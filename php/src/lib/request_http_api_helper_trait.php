<?php

declare(strict_types=1);

namespace ReticulumPhp;

// Loaded here as well as by index.php: deploy.sh renames lib/ before
// index.php, and a request between the two runs the old index.php.
require_once __DIR__ . '/empty_poll.php';

/**
 * HTTP API Helper Trait — request lifecycle and exchange orchestration.
 *
 * Reticulum-php is request-operated: every operation runs inside an HTTP
 * request/response cycle. There are no background threads, no event loop,
 * no persistent workers.
 *
 * REQUEST LIFECYCLE
 * -----------------
 * Each /v1/interfaces/exchange request follows this pattern:
 *
 *   1. PRELUDE  (runInterfaceRequestPrelude)
 *      - Rate-limited maintenance (once per 2 seconds).
 *      - Cleans stale interfaces, expired packets, orphaned paths.
 *      - See RequestMaintenanceTrait for the full cleanup logic.
 *
 *   2. EXCHANGE BODY
 *      - Authenticate the interface.
 *      - Ingest inbound packets from the client.
 *      - Fetch pending outbound packets for the client.
 *      - Process any inline delivery (local destinations, path responses).
 *
 *   3. EPILOGUE (runInterfaceRequestEpilogue)
 *      - Dispatch fire-and-forget wakes to PHP peers with pending data.
 *      - See RequestPhpWakeTrait for the wake dispatch architecture.
 *
 * CRITICAL: The epilogue runs INSIDE the request cycle. Every millisecond
 * spent in the epilogue is a millisecond the PHP process is blocked. With
 * multiple concurrent exchanges (browser + NAS + PHP peer), blocked processes
 * stack up and exhaust the shared hosting entry process limit.
 *
 * THEREFORE:
 *   - Maintenance is rate-limited to once per 2 seconds (avoids redundant
 *     DELETE locks that deadlock with concurrent INSERTs/UPDATEs).
 *   - Wake dispatch is capped at 1000ms per peer (see RequestPhpWakeTrait).
 *   - No request starts a process for a wake. The only process the node
 *     ever starts is the detached storage reclaim
 *     (RequestStorageBudgetTrait::spawnDetachedStorageReclaim), pinned by
 *     tests/only_storage_reclaim_starts_a_process_test.php.
 *
 * PERF LOGGING
 * ------------
 * The exchange endpoint logs timing breakdowns:
 *   maint  = prelude (maintenance) time
 *   ack    = acknowledge outbound batches time
 *   ingest = ingest inbound packets time
 *   fetch  = fetch outbound batch time
 *   epi    = epilogue time (wake dispatch)
 *   total  = total request time
 *
 * If `epi` exceeds 1000ms, check:
 *   - Is fireAndForgetWakeWithCurl's timeout cap still at 1000ms?
 *   - Is the peer server slow to respond?
 *
 * REGRESSION PREVENTION
 * ---------------------
 * DO NOT:
 *   - Remove the maintenance rate-limit (causes deadlocks under concurrency).
 *   - Add blocking work to the epilogue.
 *   - Increase the maintenance rate beyond once per 2 seconds.
 *   - Make wake dispatch synchronous/blocking.
 */

/**
 * The request path and the response headers, shared by HttpApi and by the
 * empty-poll shortcut (EmptyPoll), which answers before HttpApi exists and
 * must route and answer exactly as HttpApi would.
 */
final class HttpIo
{
    public static function normalizedPath(string $uri, array $server): string
    {
        $path = parse_url($uri, PHP_URL_PATH);
        $path = is_string($path) ? $path : '/';

        $scriptName = $server['SCRIPT_NAME'] ?? $server['PHP_SELF'] ?? null;
        if (is_string($scriptName) && $scriptName !== '') {
            $path = self::stripPathPrefix($path, rtrim($scriptName, '/'));

            $scriptDir = dirname($scriptName);
            if (is_string($scriptDir) && $scriptDir !== '' && $scriptDir !== '.' && $scriptDir !== DIRECTORY_SEPARATOR) {
                $path = self::stripPathPrefix($path, rtrim(str_replace('\\', '/', $scriptDir), '/'));
            }
        }

        $path = rtrim($path, '/');
        return $path === '' ? '/' : $path;
    }

    private static function stripPathPrefix(string $path, string $prefix): string
    {
        if ($prefix === '' || $prefix === '/') {
            return $path;
        }

        if ($path === $prefix) {
            return '/';
        }

        if (str_starts_with($path, $prefix . '/')) {
            return substr($path, strlen($prefix));
        }

        return $path;
    }

    public static function sendHeaders(int $statusCode): void
    {
        http_response_code($statusCode);
        header('Content-Type: application/json');
        header('Access-Control-Allow-Origin: *');
        header('Access-Control-Allow-Methods: GET, POST, OPTIONS');
        header('Access-Control-Allow-Headers: Content-Type, X-Interface-Id, X-Session-Token');
        header('Access-Control-Max-Age: 86400');
    }
}

trait RequestHttpApiHelperTrait
{
    /**
     * Exchange prelude: rate-limited maintenance run.
     *
     * Maintenance DELETEs acquire row locks. When two exchanges overlap
     * (e.g., browser client + PHP peer calling each other), concurrent
     * DELETE and INSERT/UPDATE on the same tables can deadlock.
     *
     * Rate-limiting to once per 2 seconds eliminates most deadlocks
     * without losing cleanup — stale data is caught by the next
     * eligible request. The lock file is per-host (hashed from host_url)
     * so multiple virtual hosts on the same server don't interfere.
     */
    private function runInterfaceRequestPrelude(): void
    {
        $lockFile = $this->maintenanceLockFilePath();
        $now = time();
        $lastRun = is_file($lockFile) ? (int) filemtime($lockFile) : 0;
        if ($now - $lastRun >= 2) {
            @touch($lockFile);
            $this->storage->runMaintenance(
                $this->maintenanceInt('interface_stale_after_seconds', 15),
                $this->maintenanceInt('batch_ttl_seconds', 86400),
            );
            EmptyPoll::sweep($this->config);
        }
    }

    private function maintenanceLockFilePath(): string
    {
        $tmpDir = sys_get_temp_dir();
        $hostHash = substr(hash('sha256', $this->config['host_url'] ?? 'default'), 0, 16);
        return $tmpDir . '/reticulum-php-maintenance-' . $hostHash . '.lock';
    }

    /**
     * Exchange epilogue: dispatch peer wakes.
     *
     * This runs INSIDE the request cycle and its duration is measured
     * as the `epi` metric in the perf log. Keep it fast.
     *
     * Fire-and-forget peer wakes: send a quick HTTP request to each PHP
     * peer (another PHP node, or a gateway registered as reticulum-php with
     * a peer_url) with pending outbound data, telling it to call us back.
     * Capped at 1000ms per peer (see RequestPhpWakeTrait).
     *
     * Until 2026-10-04 this also spawned a detached `php index.php
     * wake-event <id>` for every wake_events row: the wake_url path of
     * 2026-07-03, superseded by these inline wakes on 2026-07-10 and never
     * removed. Any client could register with metadata.wake_url and have
     * this node start a process and POST that URL whenever packets queued
     * for it. registerInterface() now strips wake_url.
     */
    private function runInterfaceRequestEpilogue(): void
    {
        // Fire-and-forget wakes to PHP peer nodes with pending outbound packets.
        // These MUST be non-blocking — see RequestPhpWakeTrait for the contract.
        try {
            $this->storage->dispatchWakes();
        } catch (\Throwable $error) {
            $this->log('error', 'Wake dispatch failed: ' . $error->getMessage());
        }
    }

    /**
     * The exchange or poll has been answered in full: let the client's next
     * empty poll be answered from its idle mark if nothing waits for it (see
     * EmptyPoll). A failure here costs only the shortcut, so it is logged and
     * the answer still goes out.
     */
    private function markIdleIfNothingQueued(string $interfaceId, string $sessionToken): void
    {
        try {
            $this->storage->markIdleIfNothingQueued($interfaceId, $sessionToken);
        } catch (\Throwable $error) {
            $this->log('error', 'Idle mark failed: ' . $error->getMessage());
        }
    }

    private function idleExchangeIntervalMs(): int
    {
        return (int) (
            $this->config['http']['idle_exchange_interval_ms']
                ?? 1000
        );
    }

    private function maintenanceInt(string $field, int $default): int
    {
        $maintenance = $this->config['maintenance'] ?? $this->config['worker'] ?? [];
        return (int) ($maintenance[$field] ?? $default);
    }

    private function requireInterfaceCredentials(array $body): array
    {
        return [
            $this->requireNonEmptyString($body, 'interface_id'),
            $this->requireNonEmptyString($body, 'session_token'),
        ];
    }

    private function readJsonBody(): array
    {
        $raw = file_get_contents('php://input');
        if (!is_string($raw) || $raw === '') {
            throw new ApiError(400, 'Empty request body', ['error' => 'empty request body']);
        }

        $decoded = json_decode($raw, true);
        if (!is_array($decoded)) {
            throw new ApiError(400, 'Invalid JSON', ['error' => 'invalid json']);
        }

        return $decoded;
    }

    private function normalizedPath(string $uri, array $server): string
    {
        return HttpIo::normalizedPath($uri, $server);
    }

    private function requirePacketArray(array $body, string $field, ?string $interfaceId = null): array
    {
        $packets = $body[$field] ?? null;
        if (!is_array($packets)) {
            throw new ApiError(400, $field . ' must be an array', ['error' => $field . ' must be an array']);
        }

        $maxPackets = (int) $this->config['http']['max_batch_packets'];
        if (count($packets) > $maxPackets) {
            throw new ApiError(400, 'Too many packets', ['error' => 'batch exceeds max_batch_packets']);
        }

        $maxPacketBytes = $interfaceId === null
            ? (int) $this->config['http']['max_packet_bytes']
            : $this->storage->maxPacketBytesForInterface($interfaceId);
        foreach ($packets as $index => $packet) {
            if (!is_string($packet)) {
                throw new ApiError(400, 'Packet must be a base64 string', ['error' => 'invalid packet encoding', 'index' => $index]);
            }

            $decoded = base64_decode($packet, true);
            if (!is_string($decoded)) {
                throw new ApiError(400, 'Packet is not valid base64', ['error' => 'invalid packet base64', 'index' => $index]);
            }

            if (strlen($decoded) > $maxPacketBytes) {
                throw new ApiError(400, 'Packet exceeds max_packet_bytes', ['error' => 'packet too large', 'index' => $index]);
            }
        }

        return $packets;
    }

    private function requireNonEmptyString(array $body, string $field): string
    {
        $value = $body[$field] ?? null;
        if (!is_string($value) || trim($value) === '') {
            throw new ApiError(400, $field . ' must be a non-empty string', ['error' => $field . ' must be a non-empty string']);
        }

        return $value;
    }

    private function optionalNonEmptyString(array $body, string $field): ?string
    {
        $value = $body[$field] ?? null;
        if ($value === null) {
            return null;
        }

        if (!is_string($value) || trim($value) === '') {
            throw new ApiError(400, $field . ' must be a non-empty string', ['error' => $field . ' must be a non-empty string']);
        }

        return $value;
    }

    private function requirePositiveInt(array $body, string $field): int
    {
        return $this->requirePositiveIntValue($body[$field] ?? null, $field);
    }

    private function requirePositiveIntValue(mixed $value, string $field): int
    {
        if (!is_int($value) && !(is_string($value) && ctype_digit($value))) {
            throw new ApiError(400, $field . ' must be a positive integer', ['error' => $field . ' must be a positive integer']);
        }

        $integer = (int) $value;
        if ($integer < 1) {
            throw new ApiError(400, $field . ' must be greater than zero', ['error' => $field . ' must be greater than zero']);
        }

        return $integer;
    }

    private function optionalArray(array $body, string $field): array
    {
        $value = $body[$field] ?? [];
        if (!is_array($value)) {
            throw new ApiError(400, $field . ' must be an object or array', ['error' => $field . ' must be an object or array']);
        }

        return $value;
    }

    private function optionalStringArray(array $body, string $field): array
    {
        $value = $body[$field] ?? [];
        if (!is_array($value)) {
            throw new ApiError(400, $field . ' must be an array', ['error' => $field . ' must be an array']);
        }

        foreach ($value as $entry) {
            if (!is_string($entry) || $entry === '') {
                throw new ApiError(400, $field . ' must only contain strings', ['error' => $field . ' must only contain strings']);
            }
        }

        return $value;
    }

    private function respond(int $statusCode, array $payload): never
    {
        HttpIo::sendHeaders($statusCode);
        // Strip control characters from all string values before encoding.
        // Null bytes (\x00) are stripped first with str_replace;
        // the regex handles the remaining C0 controls (\x01-\x1f) excluding
        // tab (\x09), LF (\x0a), and CR (\x0d). The regex must NOT contain
        // a literal null byte — PHP 7.3+ rejects patterns with embedded
        // null bytes as a security measure against null-byte injection.
        array_walk_recursive($payload, function(&$v) {
            if (is_string($v) && strlen($v) > 0) {
                $v = str_replace("\x00", "", $v);
                $cleaned = preg_replace("/[\x01-\x08\x0b\x0c\x0e-\x1f]/", "", $v);
                if ($cleaned !== null) { $v = $cleaned; }
            }
        });
        try {
            $encoded = json_encode($payload, JSON_THROW_ON_ERROR | JSON_PARTIAL_OUTPUT_ON_ERROR);
        } catch (\JsonException $e) {
            $msg = "json_encode threw: " . $e->getMessage() . " keys=" . implode(",", array_keys($payload));
            foreach ($payload as $k => $v) {
                if (is_string($v) && preg_match("/[\x01-\x08\x0b\x0c\x0e-\x1f]/", $v)) {
                    $msg .= " | $k has ctrl len=" . strlen($v) . " prev=" . substr($v,0,40);
                }
                if (is_array($v)) {
                    foreach ($v as $i => $sv) {
                        if (is_string($sv) && preg_match("/[\x01-\x08\x0b\x0c\x0e-\x1f]/", $sv)) {
                            $msg .= " | $k" . "[$i] has ctrl len=" . strlen($sv);
                        }
                    }
                }
            }
            $this->log("error", $msg);
            $encoded = json_encode(["error" => "internal error"]);
        }
        echo $encoded;
        exit;
    }

    private function log(string $level, string $message): void
    {
        // Only write error and warning messages to the log.
        // Debug/notice/info levels are suppressed to prevent unbounded
        // log growth from per-exchange perf metrics (500k+ lines/day).
        $allowed = ['error', 'warning'];
        if (!in_array(strtolower($level), $allowed, true)) {
            return;
        }
        $logPath = (string) ($this->config['storage']['log_path'] ?? '');
        if ($logPath === '') {
            return;
        }
        $line = sprintf("[%s] [%s] %s\n", date('Y-m-d H:i:s'), strtoupper($level), $message);
        @file_put_contents($logPath, $line, FILE_APPEND | LOCK_EX);
    }
}
