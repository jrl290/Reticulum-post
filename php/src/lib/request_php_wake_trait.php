<?php

declare(strict_types=1);

namespace ReticulumPhp;

// Loaded here as well as by index.php: deploy.sh renames lib/ before
// index.php, and a request between the two runs the old index.php.
require_once __DIR__ . '/empty_poll.php';

use PDO;

/**
 * PHP Peer Wake Trait — fire-and-forget wake dispatch for PHP-to-PHP peers.
 *
 * ARCHITECTURE
 * ------------
 * Reticulum-php is request-operated: every operation runs inside an HTTP
 * request/response cycle. There are no background threads, no event loop,
 * no persistent workers. When a client (browser, NAS, or another PHP node)
 * calls /v1/interfaces/exchange, the exchange runs synchronously and returns
 * a response.
 *
 * If a PHP peer has pending outbound packets for another PHP peer, the
 * exchange epilogue sends a "wake" HTTP request to that peer. The wake
 * tells the peer "I have packets for you — call my /v1/interfaces/exchange
 * to pull them." This is the ONLY mechanism for PHP→PHP delivery.
 *
 * CRITICAL: fire-and-forget must be NON-BLOCKING
 * ----------------------------------------------
 * Every exchange epilogue calls dispatchWakes(). If dispatchWakes() blocks
 * waiting for the peer to respond, then:
 *   - Each exchange holds a PHP process for the full round-trip time.
 *   - With multiple concurrent exchanges (browser + NAS + peer), processes
 *     stack up and exhaust the shared hosting entry process limit.
 *   - The symptom is "Resource Limit Is Reached" (LiteSpeed lsphp limit).
 *
 * THEREFORE:
 *   - fireAndForgetWakeWithSocket() is the primary path: opens a TCP+TLS
 *     socket, writes the HTTP request, and closes without reading. Returns
 *     in microseconds — truly non-blocking.
 *   - fireAndForgetWakeWithCurl() is a last-resort fallback (100ms timeout)
 *     for hosts where stream_socket_client is unavailable.
 *   - CURLOPT_RETURNTRANSFER is always true — responses must never leak
 *     to stdout and corrupt our own HTTP response to the client.
 *
 * WAKE GATING
 * -----------
 * Each peer has a last_wake_sent_at timestamp. dispatchWakes() skips peers
 * whose last wake was less than min_wake_interval_ms ago (default 1000ms).
 * This prevents wake storms when multiple exchanges happen simultaneously.
 *
 * WAKE URL CONSTRUCTION
 * ---------------------
 * fireAndForgetWake() appends /v1/wake to the peer's base URL if it doesn't
 * already contain a /v1/ path. The wake endpoint receives the waker_url
 * (our host_url) so the peer knows who to call back.
 *
 * REGRESSION PREVENTION
 * ---------------------
 * DO NOT:
 *   - Set CURLOPT_RETURNTRANSFER to false (corrupts stdout — peer responses
 *     leak into our HTTP response, causing JSON parse errors in clients).
 *   - Make the wake blocking — the raw socket approach MUST remain the
 *     primary path. cURL fallback is for compatibility only.
 *   - Add retry logic (violates DESIGN_PRINCIPLES.md Rule #1).
 *   - Remove the min_wake_interval gating.
 */

trait RequestPhpWakeTrait
{
    /**
     * Dispatch fire-and-forget wake requests to all PHP peer interfaces that
     * have pending outbound packets or pending acknowledgements.
     *
     * Called from the exchange epilogue on every request. Uses raw socket
     * writes (fireAndForgetWakeWithSocket) — returns in microseconds.
     */
    public function dispatchWakes(): void
    {
        // Removed before the look and written after it if anything is owed,
        // so idle polls stop taking the shortcut while an epilogue is due
        // (EmptyPoll, "THE WAKE MARK").
        EmptyPoll::clearWakesOwed($this->config ?? []);

        // Collect peers with pending outbound packets.
        $peers = $this->phpPeerInterfaceIdsWithPendingOutbound();

        // Also collect peers with pending acks (they need to know we received
        // their data so they can release those batches).
        $ackPeers = $this->phpPeerInterfaceIdsWithPendingAcks();
        $seen = [];
        foreach ($peers as $p) { $seen[(string)$p['interface_id']] = true; }
        foreach ($ackPeers as $p) {
            if (!isset($seen[(string)$p['interface_id']])) {
                $peers[] = $p;
                $seen[(string)$p['interface_id']] = true;
            }
        }
        if ($peers !== []) {
            EmptyPoll::noteWakesOwed($this->config ?? []);
        }

        // Gate: don't wake the same peer more than once per min_wake_interval_ms.
        // This prevents wake storms when multiple exchanges stack up.
        $minWakeInterval = (int) ($this->config['http']['min_wake_interval_ms'] ?? 1000);
        // Note: wakeTimeoutMs has a floor of 5000 in config but the cURL helper
        // caps it at 1000ms to maintain the non-blocking contract.
        $wakeTimeoutMs = max(5000, (int) ($this->config['http']['wake_timeout_ms'] ?? 500));
        $now = time();

        foreach ($peers as $peer) {
            $lastWake = isset($peer['last_wake_sent_at']) ? (int) $peer['last_wake_sent_at'] : 0;
            if (($now - $lastWake) * 1000 < $minWakeInterval) {
                continue;
            }

            $peerUrl = (string) ($peer['peer_url'] ?? '');
            if ($peerUrl === '') {
                continue;
            }

            $this->fireAndForgetWake($peerUrl, $wakeTimeoutMs);
            $this->touchPeerWakeSent((string) $peer['interface_id']);
        }
    }

    /**
     * Send a wake request to a peer. Appends /v1/wake to the peer URL if
     * it's a base URL. The wake body contains our host_url so the peer
     * knows which node to call back.
     *
     * This MUST be non-blocking. See the trait-level documentation for the
     * rationale around shared hosting resource limits.
     */
    private function fireAndForgetWake(string $peerUrl, int $timeoutMs): void
    {
        // Append /v1/wake if peerUrl is a base URL (no /v1/ path suffix).
        if (!str_ends_with($peerUrl, "/v1/wake") && !str_contains($peerUrl, "/v1/")) {
            $peerUrl = rtrim($peerUrl, "/") . "/v1/wake";
        }
        $hostUrl = $this->config['host_url'] ?? ($this->config['http']['advertise_url'] ?? null);
        if (!is_string($hostUrl) || trim($hostUrl) === '') {
            return;
        }

        $hostUrl = rtrim(trim($hostUrl), '/');
        $body = json_encode([
            'waker_url' => $hostUrl,
        ], JSON_THROW_ON_ERROR | JSON_PARTIAL_OUTPUT_ON_ERROR);

        // Prefer raw socket: truly non-blocking, returns in microseconds.
        if (function_exists('stream_socket_client')) {
            $this->fireAndForgetWakeWithSocket($peerUrl, $body);
            return;
        }

        // Fallback to cURL with ultra-short timeout if sockets unavailable.
        if (function_exists('curl_init')) {
            $this->fireAndForgetWakeWithCurl($peerUrl, $body);
        }
    }

    /**
     * Truly non-blocking fire-and-forget via raw socket.
     *
     * Opens a TCP (+TLS) connection, writes the HTTP request, and closes
     * without reading the response. Returns as soon as the bytes are written
     * to the socket buffer — typically microseconds.
     *
     * This is what "fire and forget" actually means. The peer will process
     * the wake whenever it's ready; we don't wait to find out.
     */
    private function fireAndForgetWakeWithSocket(string $url, string $body): void
    {
        $parts = parse_url($url);
        if ($parts === false || !isset($parts['host'])) {
            return;
        }

        $host = $parts['host'];
        $port = isset($parts['port'])
            ? (int) $parts['port']
            : (($parts['scheme'] ?? 'https') === 'https' ? 443 : 80);
        $isTls = ($parts['scheme'] ?? 'https') === 'https';
        $path = ($parts['path'] ?? '/') . (isset($parts['query']) ? '?' . $parts['query'] : '');

        $errno = 0;
        $errstr = '';
        $connectTimeout = 2; // seconds — just enough for TCP+TLS handshake
        $started = microtime(true);
        $fp = @stream_socket_client(
            ($isTls ? 'tls://' : 'tcp://') . $host . ':' . $port,
            $errno,
            $errstr,
            $connectTimeout,
            STREAM_CLIENT_ASYNC_CONNECT
        );

        if ($fp === false) {
            // tls:// with STREAM_CLIENT_ASYNC_CONNECT reports every failure
            // with no message and the connect's errno EINPROGRESS (115 on
            // Linux): a refusal at once, and a TCP+TLS setup still unfinished
            // when the 2 s ran out (a wake that finishes inside them leaves).
            // retichat.com logged selectiv's wakes as "connect failed:  (115)"
            // from ~10-01 (L75). How long it took is what tells them apart.
            $tookMs = (int) round((microtime(true) - $started) * 1000);
            if ($errstr === '' && $tookMs >= ($connectTimeout - 0.1) * 1000) {
                error_log("[WAKE-DROP] {$host}:{$port} did not finish connecting"
                    . ($isTls ? ' (TCP and TLS)' : '') . " within {$connectTimeout} s");
            } else {
                error_log("[WAKE-DROP] {$host}:{$port} connect failed after {$tookMs} ms: {$errstr} ({$errno})");
            }
            return;
        }

        // Complete the TLS handshake if needed.
        if ($isTls) {
            @stream_set_blocking($fp, true);
            @stream_socket_enable_crypto($fp, true, STREAM_CRYPTO_METHOD_TLSv1_2_CLIENT);
        } else {
            // STREAM_CLIENT_ASYNC_CONNECT returns while the TCP handshake is
            // still in flight, and a write before it completes fails — the
            // wake was lost with nothing said. Wait for the socket to become
            // writable (the handshake finished), bounded by the same 2 s as
            // the connect. The TLS branch already blocks through its
            // handshake, which is why https wake URLs (production) always
            // worked while the staging gateway's http://127.0.0.1:4371 lost
            // nearly every wake.
            $read = null;
            $write = [$fp];
            $except = null;
            if (@stream_select($read, $write, $except, 2) !== 1) {
                error_log("[WAKE-DROP] {$host}:{$port} did not finish connecting within 2 s");
                @fclose($fp);
                return;
            }
        }

        // HTTP/1.0 + Connection: close — the server will close after
        // responding (which we won't read).
        $request  = "POST {$path} HTTP/1.0\r\n";
        $request .= "Host: {$host}\r\n";
        $request .= "Content-Type: application/json\r\n";
        $request .= "Content-Length: " . strlen($body) . "\r\n";
        $request .= "Connection: close\r\n";
        $request .= "\r\n";
        $request .= $body;

        $written = @fwrite($fp, $request);
        @fclose($fp);
        // Never read the response. Truly fire and forget — but a wake that
        // never left says so.
        if ($written !== strlen($request)) {
            error_log("[WAKE-DROP] {$host}:{$port} write failed ("
                . var_export($written, true) . " of " . strlen($request) . " bytes)");
        }
    }

    /**
     * cURL-based wake — fallback only when stream_socket_client is unavailable.
     * Uses an ultra-short timeout (100ms) and RETURNTRANSFER to avoid stdout
     * corruption. Still blocks briefly, but only as a last resort.
     */
    private function fireAndForgetWakeWithCurl(string $url, string $body): void
    {
        $curl = curl_init($url);
        if ($curl === false) {
            return;
        }

        curl_setopt($curl, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($curl, CURLOPT_CUSTOMREQUEST, 'POST');
        curl_setopt($curl, CURLOPT_HTTPHEADER, ['Content-Type: application/json']);
        curl_setopt($curl, CURLOPT_POSTFIELDS, $body);
        curl_setopt($curl, CURLOPT_TIMEOUT_MS, 100);
        curl_setopt($curl, CURLOPT_CONNECTTIMEOUT_MS, 100);
        curl_exec($curl);
        curl_close($curl);
    }

    /**
     * Perform a PHP-to-PHP peer exchange: call the peer's /v1/interfaces/exchange
     * endpoint to deliver pending packets and collect any packets the peer has
     * for us.
     *
     * This is a SYNCHRONOUS operation — it blocks until the peer responds.
     * Its caller is the POST /v1/wake handler, inline, with the waker_url
     * from the request body.
     *
     * The peer's credentials go ONLY to the URL stored on the peer's row.
     * Until 2026-10-03 they went to $peerUrl . '/v1/interfaces/exchange',
     * the caller's own string. The row lookup compares under the table's
     * utf8mb4_unicode_ci collation on MySQL/MariaDB, which ignores case,
     * accents, fullwidth forms and trailing spaces, so a wake from
     * https://rétichat.com/reticulum (an IDN look-alike anyone can register,
     * with its own certificate) found the row for retichat.com and was sent
     * retichat.com's peer_interface_id and peer_session_token. SQLite compares
     * bytes, so no test saw it. The lookup is therefore not an identity check:
     * the caller's URL must equal the row's peer_url byte for byte after the
     * same normalisation (canonicalPeerBaseUrl), compared here in PHP, or
     * nothing is sent and nothing owed to the real peer is drained.
     * Pinned by tests/wake_exchanges_only_with_stored_peer_url_test.php.
     */
    public function exchangeWithPhpPeer(string $peerUrl): array
    {
        $peer = $this->phpPeerInterfaceByPeerUrl($peerUrl);
        if ($peer === null) {
            return ['status' => 'unknown_peer', 'peer_url' => $peerUrl];
        }

        $storedBaseUrl = self::canonicalPeerBaseUrl((string) ($peer['peer_url'] ?? ''));
        $callerBaseUrl = self::canonicalPeerBaseUrl($peerUrl);
        if ($storedBaseUrl === '' || !hash_equals($storedBaseUrl, $callerBaseUrl)) {
            // Not [WAKE-DROP]: that is a wake of ours that did not leave. This
            // is someone else's wake that the lookup matched to a peer it is
            // not. json_encode escapes non-ASCII and control characters, so
            // the look-alike shows as what it is and cannot forge a log line.
            error_log(sprintf(
                '[WAKE-REFUSED] waker_url %s matched peer row %s, whose peer_url is %s; '
                    . 'not the same bytes, so no exchange and no credentials sent',
                self::wakeLogValue($peerUrl),
                self::wakeLogValue((string) ($peer['interface_id'] ?? '')),
                self::wakeLogValue((string) ($peer['peer_url'] ?? ''))
            ));

            return ['status' => 'refused', 'reason' => 'waker_url_is_not_the_stored_peer_url', 'peer_url' => $peerUrl];
        }
        $peerUrl = $storedBaseUrl;

        $peerInterfaceId = (string) ($peer['peer_interface_id'] ?? '');
        $peerSessionToken = (string) ($peer['peer_session_token'] ?? '');
        if ($peerInterfaceId === '' || $peerSessionToken === '') {
            return ['status' => 'no_credentials', 'peer_url' => $peerUrl];
        }

        // Collect pending ack batch IDs owed to this peer.
        $ackBatchIds = $this->drainPeerAckBatchIds((string) $peer['interface_id']);

        // Call the peer's exchange endpoint: the STORED URL, never the
        // request's string (see above).
        $exchangeUrl = $storedBaseUrl . '/v1/interfaces/exchange';

        try {
            $payload = json_encode([
                'interface_id' => $peerInterfaceId,
                'session_token' => $peerSessionToken,
                'packets' => [],
                'max_packets' => (int) $this->config['http']['max_batch_packets'],
                'ack_batch_ids' => $ackBatchIds,
            ], JSON_THROW_ON_ERROR | JSON_PARTIAL_OUTPUT_ON_ERROR);
        } catch (\JsonException $e) {
            error_log('[peer] exchangeWithPhpPeer: json_encode failed: ' . $e->getMessage());
            return ['status' => 'encode_failed', 'message' => $e->getMessage(), 'peer_url' => $peerUrl];
        }

        $response = $this->httpPostJson($exchangeUrl, $payload);
        if ($response === null) {
            return ['status' => 'exchange_failed', 'peer_url' => $peerUrl];
        }

        // Touch the local interface so it shows online.
        $this->touchInterface((string) $peer['interface_id'], 'online');

        // Process delivery packets from the peer into our inbound pipeline.
        $deliveryPackets = $response['delivery_packets'] ?? [];
        $deliveryBatchId = $response['delivery_batch_id'] ?? null;

        if (is_array($deliveryPackets) && $deliveryPackets !== []) {
            $peerIfId = (string) ($peer['interface_id'] ?? '');
            $batchId = is_string($deliveryBatchId) && $deliveryBatchId !== ''
                ? $deliveryBatchId
                : 'peer-' . bin2hex(random_bytes(12));
            $this->ingestInboundBatchInline($peerIfId, $batchId, $deliveryPackets);

            // Queue ack for next exchange with this peer.
            if (is_string($deliveryBatchId) && $deliveryBatchId !== '') {
                $this->appendPeerAckBatchId($peerIfId, $deliveryBatchId);
            }
        }

        return [
            'status' => 'ok',
            'peer_url' => $peerUrl,
            'delivery_packets' => count($deliveryPackets),
            'delivery_batch_id' => $deliveryBatchId,
        ];
    }

    /**
     * A PHP peer's base URL, as both sides of the wake comparison see it:
     * trailing '/' removed, then one trailing '/v1/wake' removed (rows and
     * wakers have carried either form), then trailing '/' again. Nothing
     * else changes: no case folding, no IDN conversion, no default-port
     * removal; anything looser would only widen what a look-alike can match.
     * A legitimate waker sends its host_url, rtrim(trim(), '/'). On the node
     * it registered at, the row holds that same string (registerInterface
     * stored it). On the initiator, the row holds the initiator's own
     * [interfaces] node_url for it (connectToPeer stored it), so the two
     * configs must spell the URL with the same bytes; if they differ, say
     * only in case, that node's wakes are refused and say [WAKE-REFUSED].
     */
    private static function canonicalPeerBaseUrl(string $url): string
    {
        $url = rtrim($url, '/');
        if (str_ends_with($url, '/v1/wake')) {
            $url = rtrim(substr($url, 0, -strlen('/v1/wake')), '/');
        }

        return $url;
    }

    /** A request-supplied string made safe and bounded for one error_log line. */
    private static function wakeLogValue(string $value): string
    {
        $encoded = json_encode(
            strlen($value) > 200 ? substr($value, 0, 200) . '...' : $value,
            JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE
        );

        return is_string($encoded) ? $encoded : '"(unencodable)"';
    }

    private function drainPeerAckBatchIds(string $peerInterfaceId): array
    {
        $stmt = $this->db->prepare(
            'SELECT pending_ack_batch_ids_json FROM interfaces WHERE interface_id = :interface_id'
        );
        $stmt->bindValue(':interface_id', $peerInterfaceId, PDO::PARAM_STR);
        $stmt->execute();
        $row = $stmt->fetch(PDO::FETCH_ASSOC);

        $json = is_array($row) ? (string) ($row['pending_ack_batch_ids_json'] ?? '') : '';
        $ids = [];
        if ($json !== '') {
            try {
                $decoded = self::decodeJson($json);
                $ids = is_array($decoded) ? $decoded : [];
            } catch (\JsonException $e) {
                error_log('[peer] drainPeerAckBatchIds: decodeJson failed for ' . $peerInterfaceId . ': ' . $e->getMessage());
                $ids = [];
            }
        }

        // Clear them from the database.
        $clear = $this->db->prepare(
            'UPDATE interfaces SET pending_ack_batch_ids_json = :empty WHERE interface_id = :interface_id'
        );
        $clear->bindValue(':empty', self::encodeJson([]), PDO::PARAM_STR);
        $clear->bindValue(':interface_id', $peerInterfaceId, PDO::PARAM_STR);
        $clear->execute();

        return $ids;
    }

    private function appendPeerAckBatchId(string $peerInterfaceId, string $batchId): void
    {
        // An acknowledgement owed to a peer is a wake owed (EmptyPoll).
        EmptyPoll::noteWakesOwed($this->config ?? []);
        $stmt = $this->db->prepare(
            'SELECT pending_ack_batch_ids_json FROM interfaces WHERE interface_id = :interface_id'
        );
        $stmt->bindValue(':interface_id', $peerInterfaceId, PDO::PARAM_STR);
        $stmt->execute();
        $row = $stmt->fetch(PDO::FETCH_ASSOC);

        $ids = [];
        if (is_array($row)) {
            $json = (string) ($row['pending_ack_batch_ids_json'] ?? '');
            if ($json !== '') {
                try {
                    $decoded = self::decodeJson($json);
                    if (is_array($decoded)) {
                        $ids = $decoded;
                    }
                } catch (\JsonException $e) {
                    error_log('[peer] appendPeerAckBatchId: decodeJson failed for ' . $peerInterfaceId . ': ' . $e->getMessage());
                    $ids = [];
                }
            }
        }

        // Deduplicate: don't append if this batch ID is already pending.
        if (!in_array($batchId, $ids, true)) {
            $ids[] = $batchId;
        }

        // Keep the list bounded.
        if (count($ids) > 64) {
            $ids = array_slice($ids, -64);
        }

        $update = $this->db->prepare(
            'UPDATE interfaces SET pending_ack_batch_ids_json = :json WHERE interface_id = :interface_id'
        );
        $update->bindValue(':json', self::encodeJson($ids), PDO::PARAM_STR);
        $update->bindValue(':interface_id', $peerInterfaceId, PDO::PARAM_STR);
        $update->execute();
    }

    private function httpPostJson(string $url, string $body): ?array
    {
        if (function_exists('curl_init')) {
            return $this->httpPostJsonWithCurl($url, $body);
        }

        return $this->httpPostJsonWithStream($url, $body);
    }

    private function httpPostJsonWithCurl(string $url, string $body): ?array
    {
        $curl = curl_init($url);
        if ($curl === false) {
            return null;
        }

        curl_setopt($curl, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($curl, CURLOPT_CUSTOMREQUEST, 'POST');
        curl_setopt($curl, CURLOPT_HTTPHEADER, ['Content-Type: application/json']);
        curl_setopt($curl, CURLOPT_POSTFIELDS, $body);
        curl_setopt($curl, CURLOPT_TIMEOUT, 10);
        curl_setopt($curl, CURLOPT_CONNECTTIMEOUT, 5);

        $responseBody = curl_exec($curl);
        $statusCode = (int) curl_getinfo($curl, CURLINFO_RESPONSE_CODE);

        if ($responseBody === false || $statusCode < 200 || $statusCode >= 300) {
            return null;
        }

        try {
            $decoded = json_decode($responseBody, true, flags: JSON_THROW_ON_ERROR);
            return is_array($decoded) ? $decoded : null;
        } catch (\JsonException) {
            return null;
        }
    }

    private function httpPostJsonWithStream(string $url, string $body): ?array
    {
        $context = stream_context_create([
            'http' => [
                'method' => 'POST',
                'header' => 'Content-Type: application/json',
                'content' => $body,
                'timeout' => 10,
                'ignore_errors' => true,
            ],
        ]);

        $responseBody = @file_get_contents($url, false, $context);
        if ($responseBody === false) {
            return null;
        }

        $statusCode = 0;
        $headers = $http_response_header ?? [];
        if (isset($headers[0]) && preg_match('/\s(\d{3})\s/', $headers[0], $matches) === 1) {
            $statusCode = (int) $matches[1];
        }

        if ($statusCode < 200 || $statusCode >= 300) {
            return null;
        }

        try {
            $decoded = json_decode($responseBody, true, flags: JSON_THROW_ON_ERROR);
            return is_array($decoded) ? $decoded : null;
        } catch (\JsonException) {
            return null;
        }
    }

    /**
     * The operator's `php index.php initialize`, its only caller (runIndexCli).
     * Until 2026-10-14 it was GET /v1/initialize, open to anyone; see
     * HttpApi::handle(). The admin page's Reconnect is the same for one peer,
     * without the migration (reconnectConfiguredPeer()).
     */
    public function initializeNode(): array
    {
        $summary = [
            'status' => 'ok',
            'migrated' => false,
            'peers' => [],
        ];

        // Schema migration. Until 2026-10-14 this said migrated whatever
        // migrate() reported; its errors are the answer now.
        $migration = $this->migrate();
        $summary['migrated'] = $migration['errors'] === [];
        $summary['migration'] = $migration;

        $hostUrl = $this->configuredHostUrl();
        if ($hostUrl === null) {
            $summary['status'] = 'no_host_url';
            return $summary;
        }

        // Connect to configured peer interfaces.
        foreach ($this->configuredPeerEndpoints() as $ifaceName => $endpoint) {
            $summary['peers'][] = $this->connectToPeer($endpoint['exchange_url'], $endpoint['wake_url'], $hostUrl, (string) $ifaceName);
        }

        return $summary;
    }

    /**
     * The peers [interfaces] configures, by name: the URL to register and
     * exchange at (node_url, or peer_url) and the one to wake (wake_url, or
     * <node_url>/v1/wake). initialize, the heal in maintenance and the admin
     * page all read them here, so they cannot disagree about a URL.
     *
     * @return array<string|int, array{exchange_url: string, wake_url: string}>
     */
    private function configuredPeerEndpoints(): array
    {
        $interfaces = $this->config['interfaces'] ?? [];
        if (!is_array($interfaces)) {
            return [];
        }

        $endpoints = [];
        foreach ($interfaces as $ifaceName => $ifaceConfig) {
            if (!is_array($ifaceConfig)) {
                continue;
            }

            $exchangeUrl = $ifaceConfig['node_url'] ?? $ifaceConfig['peer_url'] ?? null;
            if (!is_string($exchangeUrl) || trim($exchangeUrl) === '') {
                continue;
            }
            $exchangeUrl = rtrim(trim($exchangeUrl), '/');

            // Wake URL: explicit config field takes precedence, otherwise
            // the standard PHP node convention (<base>/v1/wake).
            $wakeUrl = $ifaceConfig['wake_url'] ?? null;
            $endpoints[$ifaceName] = [
                'exchange_url' => $exchangeUrl,
                'wake_url' => is_string($wakeUrl) && trim($wakeUrl) !== '' ? trim($wakeUrl) : $exchangeUrl . '/v1/wake',
            ];
        }

        return $endpoints;
    }

    private function configuredHostUrl(): ?string
    {
        $hostUrl = $this->config['host_url'] ?? ($this->config['http']['advertise_url'] ?? null);
        return is_string($hostUrl) && trim($hostUrl) !== '' ? rtrim(trim($hostUrl), '/') : null;
    }

    /**
     * The configured peers and this node's row for each, for the admin page.
     * The row goes out through publicInterfaceView(), so no credential does;
     * 'rows' counts every row that names the peer, because README's rotation
     * stops when there is more than one.
     */
    public function configuredPeerStates(): array
    {
        $now = time();
        $states = [];
        foreach ($this->configuredPeerEndpoints() as $ifaceName => $endpoint) {
            $rows = $this->interfaceRowsNamingPeer($endpoint['exchange_url']);
            $row = $rows[0] ?? null;
            $states[] = [
                'name' => (string) $ifaceName,
                'node_url' => $endpoint['exchange_url'],
                'rows' => count($rows),
                'live' => self::phpPeerRowIsLive($row, $now),
                'interface' => $row === null ? null : self::publicInterfaceView($row, true),
            ];
        }

        return $states;
    }

    /**
     * The admin page's Reconnect for one configured peer: what `php index.php
     * initialize` does for it, without the migration. connectToPeer() leaves
     * a live row alone and replaces any other, so a row that is only quiet
     * gets new credentials, as a rotation would.
     */
    public function reconnectConfiguredPeer(string $name): array
    {
        $endpoint = $this->configuredPeerEndpoints()[$name] ?? null;
        $hostUrl = $this->configuredHostUrl();
        if ($endpoint === null || $hostUrl === null) {
            return ['peer' => $name, 'status' => $endpoint === null ? 'not_configured' : 'no_host_url'];
        }

        return ['peer' => $name] + $this->connectToPeer($endpoint['exchange_url'], $endpoint['wake_url'], $hostUrl, $name);
    }

    /**
     * The admin page's Rotate: README "Rotating a PHP peering's credentials"
     * step 2 as one action. This node's row for the peer is deleted, not
     * marked dead (the peer's next exchange with the old token would revive
     * a merely-offline row), so connectToPeer() finds none and registers
     * afresh: a new id and token here, and the peer re-binds its row with a
     * new token of its own. Refused, with nothing deleted, when more than one
     * row names the peer, where README's step 1 stops too.
     */
    public function rotateConfiguredPeer(string $name): array
    {
        $endpoint = $this->configuredPeerEndpoints()[$name] ?? null;
        $hostUrl = $this->configuredHostUrl();
        if ($endpoint === null || $hostUrl === null) {
            return ['peer' => $name, 'status' => $endpoint === null ? 'not_configured' : 'no_host_url'];
        }

        $rows = $this->interfaceRowsNamingPeer($endpoint['exchange_url']);
        if (count($rows) > 1) {
            return ['peer' => $name, 'peer_url' => $endpoint['exchange_url'], 'status' => 'refused_duplicate_rows', 'rows' => count($rows)];
        }

        $previous = isset($rows[0]) ? (string) $rows[0]['interface_id'] : null;
        if ($previous !== null) {
            $delete = $this->db->prepare('DELETE FROM interfaces WHERE interface_id = :id');
            $delete->bindValue(':id', $previous, PDO::PARAM_STR);
            Database::executeWithRetry($delete, 'rotatePeerRow');
            EmptyPoll::clear($this->config, $previous);
        }

        return ['peer' => $name, 'previous_interface_id' => $previous]
            + $this->connectToPeer($endpoint['exchange_url'], $endpoint['wake_url'], $hostUrl, $name);
    }

    /**
     * Every interface row whose peer_url is $exchangeUrl, as is or with
     * /v1/wake (the forms phpPeerInterfaceByPeerUrl() looks up), most recently
     * seen first, with metadata decoded for publicInterfaceView().
     */
    private function interfaceRowsNamingPeer(string $exchangeUrl): array
    {
        $stmt = $this->db->prepare(
            'SELECT interface_id, name, bitrate, mtu, status, metadata_json, peer_url,
                    created_at, last_seen_at, rx_packets, rx_bytes, tx_packets, tx_bytes
             FROM interfaces
             WHERE peer_url IN (:peer_url, :wake_url)
             ORDER BY last_seen_at DESC, created_at DESC'
        );
        $stmt->bindValue(':peer_url', $exchangeUrl, PDO::PARAM_STR);
        $stmt->bindValue(':wake_url', $exchangeUrl . '/v1/wake', PDO::PARAM_STR);
        $stmt->execute();

        $rows = [];
        while (($row = $stmt->fetch(PDO::FETCH_ASSOC)) !== false) {
            $row['metadata'] = self::decodeJson((string) ($row['metadata_json'] ?? '{}'));
            unset($row['metadata_json']);
            $rows[] = $row;
        }

        return $rows;
    }

    /**
     * Is a peer-session interface row an actual live session?
     *
     * A row merely existing is NOT connectivity. On 2026-08-17 selectiv held
     * an interfaces row for retichat.com that had been offline since 06:32;
     * connectToPeer() saw the row, said "already_connected", and refused to
     * re-register — while on the retichat side the stale-interface cleanup had
     * (correctly) pruned the dead row entirely. Result: selectiv's only route
     * to the mesh was gone for 9 hours, browsers connected to its exchange and
     * then waited forever for announces that could not arrive ("getting stuck
     * on links"), and the remedy was a manual GET /v1/initialize that nothing
     * would ever have issued on its own.
     *
     * Pure function so the boundary is testable without a database.
     */
    public static function phpPeerRowIsLive(?array $row, int $now, int $staleAfterSeconds = 900): bool
    {
        if (!is_array($row)) {
            return false;
        }
        if (($row['status'] ?? '') !== 'online') {
            return false;
        }
        $lastSeen = (int) ($row['last_seen_at'] ?? 0);

        return $lastSeen > 0 && ($now - $lastSeen) <= $staleAfterSeconds;
    }

    /**
     * Re-establish configured peer sessions that have died. Called from
     * maintenance (Phase 12), so it runs on ordinary request traffic — no
     * scheduler, per the operations-police-themselves rule. Throttled through
     * transport_state so concurrent requests do not stampede the peer.
     */
    public function ensureConfiguredPeerSessions(int $now, array &$summary): void
    {
        $endpoints = $this->configuredPeerEndpoints();
        $hostUrl = $this->configuredHostUrl();
        if ($endpoints === [] || $hostUrl === null) {
            return;
        }

        // Claim the throttle window BEFORE doing network work, so parallel
        // requests running maintenance do not each re-register.
        $key = 'peer_session_checked_at';
        $minInterval = $this->maintenanceConfigInt('peer_session_check_seconds', 300);
        $stmt = $this->db->prepare('SELECT state_value FROM transport_state WHERE state_key = :k');
        $stmt->bindValue(':k', $key, PDO::PARAM_STR);
        $stmt->execute();
        $row = $stmt->fetch(PDO::FETCH_ASSOC);
        $last = is_array($row) ? (int) $row['state_value'] : 0;
        if (($now - $last) < $minInterval) {
            return;
        }
        if (is_array($row)) {
            $up = $this->db->prepare('UPDATE transport_state SET state_value = :v, updated_at = :t WHERE state_key = :k');
        } else {
            $up = $this->db->prepare('INSERT INTO transport_state (state_key, state_value, updated_at) VALUES (:k, :v, :t)');
        }
        $up->bindValue(':k', $key, PDO::PARAM_STR);
        $up->bindValue(':v', (string) $now, PDO::PARAM_STR);
        $up->bindValue(':t', $now, PDO::PARAM_INT);
        Database::executeWithRetry($up, 'claimPeerSessionWindow');

        foreach ($endpoints as $ifaceName => $endpoint) {
            $exchangeUrl = $endpoint['exchange_url'];
            $existing = $this->phpPeerInterfaceByPeerUrl($exchangeUrl);

            // Heal on: no row at all, or a row that has been offline for a
            // long time. NOT on merely-offline: wake-based peers are
            // legitimately offline whenever no traffic has flowed for 15s
            // (Phase 1's browser-grade staleness), and healing that state
            // would re-register an idle-but-healthy peer every throttle
            // window all night — churning session credentials that in-flight
            // exchanges may still be using. An idle peer costs nothing;
            // a dead one (wakes rejected because the far side lost the
            // session) looks identical for the first hour and is healed at
            // the hour mark. The 2026-08-17 outage shapes were "no row"
            // (heals immediately) and "offline for 9 hours" (heals at +1h).
            if ($existing !== null) {
                $lastSeen = (int) ($existing['last_seen_at'] ?? 0);
                $healAfter = $this->maintenanceConfigInt('peer_session_heal_after_seconds', 3600);
                $isOnline = ($existing['status'] ?? '') === 'online';
                if ($isOnline || ($now - $lastSeen) < $healAfter) {
                    continue;
                }
            }

            $result = $this->connectToPeer($exchangeUrl, $endpoint['wake_url'], $hostUrl, (string) $ifaceName);
            $summary['peer_sessions_healed'][] = $result;
            // error_log(), as every line Storage writes: log() is HttpApi's
            // (RequestHttpApiHelperTrait), and this trait runs as Storage.
            // Until 2026-10-05 this was $this->log(), so the request whose
            // prelude had just re-registered the session died with "Call to
            // undefined method Storage::log()" and answered 500, and no entry
            // after this one was checked. Pinned by
            // tests/peer_session_heal_request_test.php; the class of bug by
            // tests/static_check_methods.php.
            error_log(sprintf(
                '[peer] session to %s was dead (%s) — re-registered: %s',
                $exchangeUrl,
                $existing === null ? 'no row' : 'row ' . ($existing['status'] ?? '?'),
                $result['status'] ?? '?'
            ));
        }
    }

    private function connectToPeer(string $exchangeUrl, string $wakeUrl, string $hostUrl, string $name): array
    {
        // Only a LIVE session counts as connected. A dead row must not block
        // re-registration — see phpPeerRowIsLive for the outage this caused.
        $existing = $this->phpPeerInterfaceByPeerUrl($exchangeUrl);
        if (self::phpPeerRowIsLive($existing, time())) {
            return [
                'peer_url' => $exchangeUrl,
                'wake_url' => $wakeUrl,
                'status' => 'already_connected',
                'interface_id' => $existing['interface_id'],
            ];
        }
        if ($existing !== null) {
            // Remove the corpse so the fresh registration below fully replaces
            // it; leaving it would keep two rows claiming the same peer_url,
            // with lookups free to return either.
            $del = $this->db->prepare('DELETE FROM interfaces WHERE interface_id = :id');
            $del->bindValue(':id', (string) $existing['interface_id'], PDO::PARAM_STR);
            Database::executeWithRetry($del, 'removeDeadPeerRow');
            EmptyPoll::clear($this->config ?? [], (string) $existing['interface_id']);
        }

        // Pre-generate credentials for the peer to call us.
        $localInterfaceId = bin2hex(random_bytes(16));
        $localSessionToken = bin2hex(random_bytes(32));

        // Register with the peer using the exchange base URL.
        // Use the local host identity as the name, not the peer config name.
        $registerUrl = $exchangeUrl . '/v1/interfaces/register';
        $localName = parse_url($hostUrl, PHP_URL_HOST) ?: $hostUrl;
        $body = json_encode([
            'name' => $localName,
            'bitrate' => 1000000,
            'mtu' => 500,
            'metadata' => [
                'client' => 'reticulum-php',
                'peer_url' => $hostUrl,
                'peer_interface_id' => $localInterfaceId,
                'peer_session_token' => $localSessionToken,
            ],
        ], JSON_THROW_ON_ERROR | JSON_PARTIAL_OUTPUT_ON_ERROR);

        $response = $this->httpPostJson($registerUrl, $body);
        if ($response === null) {
            return [
                'peer_url' => $exchangeUrl,
                'status' => 'register_failed',
            ];
        }

        $remoteInterfaceId = isset($response['interface_id']) && is_string($response['interface_id']) ? $response['interface_id'] : null;
        $remoteSessionToken = isset($response['session_token']) && is_string($response['session_token']) ? $response['session_token'] : null;
        if ($remoteInterfaceId === null || $remoteSessionToken === null) {
            return [
                'peer_url' => $exchangeUrl,
                'status' => 'register_malformed_response',
            ];
        }

        // Store the peer locally so we can queue packets and send wakes.
        // wakeUrl is the literal URL for fire-and-forget wake POSTs.
        $this->upsertConfiguredInterface(
            $localInterfaceId,
            $localName,
            $localSessionToken,
            1000000,
            500,
            ['client' => 'reticulum-php', 'peer_url' => $exchangeUrl],
            $exchangeUrl,
            $remoteInterfaceId,
            $remoteSessionToken,
        );

        return [
            'peer_url' => $exchangeUrl,
            'wake_url' => $wakeUrl,
            'status' => 'connected',
            'interface_id' => $localInterfaceId,
        ];
    }
}
