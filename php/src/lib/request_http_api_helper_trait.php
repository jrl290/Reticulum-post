<?php

declare(strict_types=1);

namespace ReticulumPhp;

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
 *      - Spawn detached wake runners for pending wake events.
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
 *   - Wake runners are spawned via exec() in the background — the spawn
 *     itself is fast (exec returns immediately), and the actual wake work
 *     happens in a separate PHP process.
 *
 * PERF LOGGING
 * ------------
 * The exchange endpoint logs timing breakdowns:
 *   maint  = prelude (maintenance) time
 *   ack    = acknowledge outbound batches time
 *   ingest = ingest inbound packets time
 *   fetch  = fetch outbound batch time
 *   epi    = epilogue time (wake dispatch + wake runner spawn)
 *   total  = total request time
 *
 * If `epi` exceeds 1000ms, check:
 *   - Is fireAndForgetWakeWithCurl's timeout cap still at 1000ms?
 *   - Is the peer server slow to respond?
 *   - Are there excessive wake events being spawned?
 *
 * REGRESSION PREVENTION
 * ---------------------
 * DO NOT:
 *   - Remove the maintenance rate-limit (causes deadlocks under concurrency).
 *   - Add blocking work to the epilogue.
 *   - Increase the maintenance rate beyond once per 2 seconds.
 *   - Make wake dispatch synchronous/blocking.
 */

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
        }
    }

    private function maintenanceLockFilePath(): string
    {
        $tmpDir = sys_get_temp_dir();
        $hostHash = substr(hash('sha256', $this->config['host_url'] ?? 'default'), 0, 16);
        return $tmpDir . '/reticulum-php-maintenance-' . $hostHash . '.lock';
    }

    /**
     * Exchange epilogue: spawn wake runners and dispatch peer wakes.
     *
     * This runs INSIDE the request cycle and its duration is measured
     * as the `epi` metric in the perf log. Keep it fast.
     *
     * Two-phase wake dispatch:
     *   1. Detached wake runners: spawn background PHP processes via exec()
     *      for each pending wake event. These run exchangeWithPhpPeer()
     *      asynchronously. The exec() call returns immediately.
     *   2. Fire-and-forget peer wakes: send a quick HTTP request to each
     *      PHP peer with pending outbound data, telling them to call us
     *      back. Capped at 1000ms per peer (see RequestPhpWakeTrait).
     */
    private function runInterfaceRequestEpilogue(): void
    {
        $wakeEventIds = $this->storage->pendingWakeEventIdsForSpawn(
            (int) ($this->config['wake']['dispatch_limit'] ?? 32),
        );

        foreach ($wakeEventIds as $wakeEventId) {
            try {
                $this->spawnDetachedWakeRunner((int) $wakeEventId);
            } catch (\Throwable $error) {
                $message = 'failed to spawn wake runner: ' . $error->getMessage();
                $this->storage->failWakeEvent((int) $wakeEventId, $message);
                $this->log('error', 'Wake runner spawn failed for wake_event_id ' . $wakeEventId . ': ' . $error->getMessage());
            }
        }

        // Fire-and-forget wakes to PHP peer nodes with pending outbound packets.
        // These MUST be non-blocking — see RequestPhpWakeTrait for the contract.
        try {
            $this->storage->dispatchWakes();
        } catch (\Throwable $error) {
            $this->log('error', 'Wake dispatch failed: ' . $error->getMessage());
        }
    }

    /**
     * Spawn a background PHP process to run exchangeWithPhpPeer().
     *
     * Uses exec() with '&' to detach. The exec() call returns immediately;
     * the actual peer exchange happens in a separate process that doesn't
     * block the current request.
     *
     * NOTE: exec() may be disabled on some shared hosting configurations.
     * If so, wake events will accumulate and fail. The fallback is that
     * the peer will eventually pull during its own idle exchange cycle.
     */
    private function spawnDetachedWakeRunner(int $wakeEventId): void
    {
        $phpBinary = PHP_BINARY !== '' ? PHP_BINARY : 'php';
        $workerScript = dirname(__DIR__) . '/index.php';
        $command = sprintf(
            '%s %s wake-event %d > /dev/null 2>&1 &',
            escapeshellarg($phpBinary),
            escapeshellarg($workerScript),
            $wakeEventId,
        );

        $output = [];
        $exitCode = 0;
        exec($command, $output, $exitCode);
        if ($exitCode !== 0) {
            throw new \RuntimeException('wake runner spawn exited with status ' . $exitCode);
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
        $path = parse_url($uri, PHP_URL_PATH);
        $path = is_string($path) ? $path : '/';

        $scriptName = $server['SCRIPT_NAME'] ?? $server['PHP_SELF'] ?? null;
        if (is_string($scriptName) && $scriptName !== '') {
            $path = $this->stripPathPrefix($path, rtrim($scriptName, '/'));

            $scriptDir = dirname($scriptName);
            if (is_string($scriptDir) && $scriptDir !== '' && $scriptDir !== '.' && $scriptDir !== DIRECTORY_SEPARATOR) {
                $path = $this->stripPathPrefix($path, rtrim(str_replace('\\', '/', $scriptDir), '/'));
            }
        }

        $path = rtrim($path, '/');
        return $path === '' ? '/' : $path;
    }

    private function stripPathPrefix(string $path, string $prefix): string
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
        http_response_code($statusCode);
        header('Content-Type: application/json');
        header('Access-Control-Allow-Origin: *');
        header('Access-Control-Allow-Methods: GET, POST, OPTIONS');
        header('Access-Control-Allow-Headers: Content-Type, X-Interface-Id, X-Session-Token');
        header('Access-Control-Max-Age: 86400');
        // Strip control characters from all string values before encoding
        array_walk_recursive($payload, function(&$v) {
            if (is_string($v) && strlen($v) > 0) { $cleaned = preg_replace("/[\x00-\x08\x0b\x0c\x0e-\x1f]/", "", str_replace("\x00", "", $v)); if ($cleaned !== null) { $v = $cleaned; } }
        });
        try {
            $encoded = json_encode($payload, JSON_THROW_ON_ERROR | JSON_PARTIAL_OUTPUT_ON_ERROR);
        } catch (\JsonException $e) {
            $msg = "json_encode threw: " . $e->getMessage() . " keys=" . implode(",", array_keys($payload));
            foreach ($payload as $k => $v) {
                if (is_string($v) && preg_match("/[\x00-\x08\x0b\x0c\x0e-\x1f]/", $v)) {
                    $msg .= " | $k has ctrl len=" . strlen($v) . " prev=" . substr($v,0,40);
                }
                if (is_array($v)) {
                    foreach ($v as $i => $sv) {
                        if (is_string($sv) && preg_match("/[\x00-\x08\x0b\x0c\x0e-\x1f]/", $sv)) {
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
        $line = sprintf("[%s] [%s] %s\n", date('Y-m-d H:i:s'), strtoupper($level), $message);
        file_put_contents((string) $this->config['storage']['log_path'], $line, FILE_APPEND | LOCK_EX);
    }

    public function renderMonitorPage(): never
    {
        $data = $this->storage->monitorData();
        $interfaces = $data['interfaces'] ?? [];
        $outbound = $data['outbound_pending'] ?? [];
        $packets = $data['recent_inbound'] ?? [];
        $outboundPkts = $data['recent_outbound'] ?? [];
        $hostUrl = $this->config['host_url'] ?? ($this->config['http']['advertise_url'] ?? '');
        $now = date('Y-m-d H:i:s');

        $peerRows = '';
        $ifaceRows = '';
        foreach ($interfaces as $iface) {
            $name = htmlspecialchars((string) ($iface['name'] ?? ''), ENT_QUOTES);
            $status = htmlspecialchars((string) ($iface['status'] ?? ''), ENT_QUOTES);
            $peer = htmlspecialchars((string) ($iface['peer_url'] ?? ''), ENT_QUOTES);
            $rx = (int) ($iface['rx_packets'] ?? 0);
            $tx = (int) ($iface['tx_packets'] ?? 0);
            $lastSeen = isset($iface['last_seen_at']) ? date('H:i:s', (int) $iface['last_seen_at']) : '-';
            $isPhpPeer = $peer !== '';

            if ($isPhpPeer) {
                $ifaceId = substr((string) ($iface['interface_id'] ?? ''), 0, 12);
                $peerRows .= "<tr><td class=\"mono\">{$ifaceId}</td><td class=\"mono\">{$peer}</td><td>{$rx}</td><td>{$tx}</td><td>{$lastSeen}</td></tr>";
            } elseif ($status === 'online') {
                $ifaceId = substr((string) ($iface['interface_id'] ?? ''), 0, 12);
                $ifaceRows .= "<tr><td class=\"mono\">{$ifaceId}</td><td>{$rx}</td><td>{$tx}</td><td>{$lastSeen}</td></tr>";
            }
        }

        $outboundRows = '';
        foreach ($outbound as $ob) {
            $name = htmlspecialchars((string) ($ob['name'] ?? ''), ENT_QUOTES);
            $pending = (int) ($ob['pending'] ?? 0);
            $oldest = isset($ob['oldest_queued_at']) ? date('H:i:s', (int) $ob['oldest_queued_at']) : '-';
            $op = htmlspecialchars((string) ($ob['peer_url'] ?? ''), ENT_QUOTES);
            $outboundRows .= "<tr><td>{$name}</td><td class=\"mono\">{$op}</td><td class=\"count\">{$pending}</td><td>{$oldest}</td></tr>";
        }

        $packetRows = '';
        $typeNames = ['DATA', 'ANNOUNCE', 'LINK', 'PROOF'];
        foreach ($packets as $pkt) {
            $pktType = (int) ($pkt['packet_type'] ?? -1);
            $typeName = $typeNames[$pktType] ?? "?{$pktType}";
            $destHash = htmlspecialchars(substr((string) ($pkt['destination_hash_hex'] ?? ''), 0, 12), ENT_QUOTES);
            $st = htmlspecialchars((string) ($pkt['filter_status'] ?? ($pkt['status'] ?? '')), ENT_QUOTES);
            $size = (int) ($pkt['packet_size'] ?? 0);
            $ts = isset($pkt['created_at']) ? date('H:i:s', (int) $pkt['created_at']) : '-';
            $packetRows .= "<tr><td class=\"mono\">{$typeName}</td><td class=\"mono\">{$destHash}</td><td>{$st}</td><td>{$size}</td><td>{$ts}</td></tr>";
        }

        $outPktRows = '';
        foreach ($outboundPkts as $pkt) {
            $destHash = htmlspecialchars(substr((string) ($pkt['destination_hash_hex'] ?? ''), 0, 12), ENT_QUOTES);
            $reason = htmlspecialchars((string) ($pkt['queue_reason'] ?? ''), ENT_QUOTES);
            $acked = ($pkt['acked_at'] ?? null) !== null ? 'acked' : 'pending';
            $ts = isset($pkt['queued_at']) ? date('H:i:s', (int) $pkt['queued_at']) : '-';
            $outPktRows .= "<tr><td class=\"mono\">{$destHash}</td><td>{$reason}</td><td>{$acked}</td><td>{$ts}</td></tr>";
        }

        $totalPending = array_sum(array_column($outbound, 'pending'));
        $ifaceCount = count($interfaces);
        $pktCount = count($packets);

        echo <<<HTML
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Reticulum-php Monitor</title>
<style>
  body { font-family: -apple-system, system-ui, sans-serif; margin: 0; padding: 16px; background: #111; color: #ddd; }
  h1 { font-size: 18px; margin: 0 0 4px; }
  .sub { color: #888; font-size: 12px; margin-bottom: 16px; }
  .grid { display: flex; gap: 12px; flex-wrap: wrap; margin-bottom: 16px; }
  .card { background: #1a1a1a; border: 1px solid #333; border-radius: 6px; padding: 10px 14px; min-width: 100px; }
  .card .val { font-size: 24px; font-weight: bold; color: #4af; }
  .card .lbl { font-size: 10px; color: #888; text-transform: uppercase; }
  table { width: 100%; border-collapse: collapse; margin-bottom: 20px; font-size: 13px; }
  th { text-align: left; padding: 6px 8px; border-bottom: 2px solid #333; color: #888; font-size: 11px; text-transform: uppercase; }
  td { padding: 5px 8px; border-bottom: 1px solid #222; }
  .mono { font-family: 'SF Mono', monospace; font-size: 12px; }
  .count { text-align: right; font-weight: bold; }
  h2 { font-size: 14px; color: #888; margin: 20px 0 8px; text-transform: uppercase; }
  .refresh { font-size: 10px; color: #555; }
  .btn-flush { background: #c44; color: #fff; border: none; border-radius: 4px; padding: 6px 14px; font-size: 12px; cursor: pointer; margin-left: 12px; }
  .btn-flush:hover { background: #d55; }
  .btn-flush:disabled { background: #555; cursor: default; }
  .flush-msg { font-size: 11px; margin-left: 12px; padding: 4px 8px; border-radius: 3px; display: inline-block; }
  .flush-msg.ok { background: #153; color: #4f8; }
  .flush-msg.err { background: #531; color: #f84; }
</style>
</head>
<body>
<h1>Reticulum-php</h1>
<div class="sub">{$hostUrl} &mdash; {$now} <span class="refresh">(auto-refresh 5s)</span><button class="btn-flush" id="btn-flush" onclick="flushStale()">Flush Stale</button><button class="btn-flush" id="btn-clear" style="background:#900" onclick="clearAll()">Clear All Data</button><span id="flush-msg"></span></div>

<div class="grid">
  <div class="card"><div class="val">{$totalPending}</div><div class="lbl">Pending Outbound</div></div>
  <div class="card"><div class="val">{$ifaceCount}</div><div class="lbl">Interfaces</div></div>
  <div class="card"><div class="val">{$pktCount}</div><div class="lbl">Recent Packets</div></div>
</div>

<h2>Connected Peers</h2>
<table><thead><tr><th>Interface ID</th><th>Peer URL</th><th>RX</th><th>TX</th><th>Last Seen</th></tr></thead><tbody>{$peerRows}</tbody></table>

<h2>Active Clients</h2>
<table><thead><tr><th>Interface ID</th><th>RX</th><th>TX</th><th>Last Seen</th></tr></thead><tbody>{$ifaceRows}</tbody></table>

<h2>Pending Outbound</h2>
<table><thead><tr><th>Interface</th><th>Peer</th><th>Pending</th><th>Oldest</th></tr></thead><tbody>{$outboundRows}</tbody></table>

<h2>Received</h2>
<table><thead><tr><th>Type</th><th>Dest Hash</th><th>Status</th><th>Size</th><th>Time</th></tr></thead><tbody>{$packetRows}</tbody></table>

<h2>Queued Outbound</h2>
<table><thead><tr><th>Dest Hash</th><th>Reason</th><th>State</th><th>Queued</th></tr></thead><tbody>{$outPktRows}</tbody></table>

<script>
var autoRefresh = setTimeout(function(){ location.reload(); }, 5000);

function flushStale() {
  var btn = document.getElementById('btn-flush');
  var msg = document.getElementById('flush-msg');
  btn.disabled = true;
  btn.textContent = 'Flushing...';
  msg.className = 'flush-msg';
  msg.textContent = '';

  clearTimeout(autoRefresh);

  fetch('/v1/maintenance/flush', { method: 'POST' })
    .then(function(r) { return r.json(); })
    .then(function(data) {
      var f = data.flushed || {};
      var parts = [];
      if (f.interfaces_marked_offline) parts.push(f.interfaces_marked_offline + ' ifaces offline');
      if (f.trimmed_outbound_packets) parts.push(f.trimmed_outbound_packets + ' pkts flushed');
      if (f.trimmed_expired_paths) parts.push(f.trimmed_expired_paths + ' paths');
      if (f.trimmed_link_transport_entries) parts.push(f.trimmed_link_transport_entries + ' links');
      if (parts.length === 0) parts.push('nothing to flush');
      msg.textContent = parts.join(', ');
      msg.className = 'flush-msg ok';
    })
    .catch(function(err) {
      msg.textContent = 'Error: ' + err.message;
      msg.className = 'flush-msg err';
    })
    .finally(function() {
      btn.disabled = false;
      btn.textContent = 'Flush Stale';
      autoRefresh = setTimeout(function(){ location.reload(); }, 3000);
    });
}

function clearAll() {
  if (!confirm('Delete ALL rows from ALL tables? This cannot be undone.')) return;
  var btn = document.getElementById('btn-clear');
  var msg = document.getElementById('flush-msg');
  btn.disabled = true; btn.textContent = 'Clearing...';
  clearTimeout(autoRefresh);
  fetch('/reticulum/v1/monitor/clear', { method: 'POST', headers: {'Content-Type':'application/json'}, body: JSON.stringify({confirm:'YES'}) })
    .then(function(r) { return r.json(); })
    .then(function(d) { msg.textContent = d.status === 'ok' ? 'All tables cleared' : (d.error || 'Failed'); msg.className = d.status === 'ok' ? 'flush-msg ok' : 'flush-msg err'; })
    .catch(function(e) { msg.textContent = 'Error: ' + e.message; msg.className = 'flush-msg err'; })
    .finally(function() { btn.disabled = false; btn.textContent = 'Clear All Data'; autoRefresh = setTimeout(function(){ location.reload(); }, 2000); });
}
</script>
</body>
</html>
HTML;

        exit;
    }
}