<?php

declare(strict_types=1);

namespace ReticulumPhp;

// Reticulum-php is request-operated. These HTTP API helpers validate and
// complete one authenticated request at a time; they do not create a separate
// background transport path.

trait RequestHttpApiHelperTrait
{
    /**
     * Run maintenance at most once per interval to keep exchange/poll calls
     * lightweight. Maintenance touches 9+ tables and causes InnoDB deadlocks
     * when two concurrent exchange requests both try to run it. A file-based
     * timestamp avoids adding DB load for the rate-limit check itself.
     */
    private function runInterfaceRequestPrelude(): void
    {
        $now = time();
        $interval = $this->maintenanceInt('maintenance_interval_seconds', 30);
        $flagFile = ($this->config['project_root'] ?? sys_get_temp_dir()) . '/var/last_maintenance_time';
        $lastRun = (int) @file_get_contents($flagFile);

        if (($now - $lastRun) >= $interval) {
            @file_put_contents($flagFile, (string) $now, LOCK_EX);
            $this->storage->runMaintenance(
                $this->maintenanceInt('interface_stale_after_seconds', 300),
                $this->maintenanceInt('batch_ttl_seconds', 86400),
            );
        }
    }

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
        try {
            $this->storage->dispatchWakes();
        } catch (\Throwable $error) {
            $this->log('error', 'Wake dispatch failed: ' . $error->getMessage());
        }
    }

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
        // Strip control characters from all string values before encoding.
        // Null byte handled separately — preg_replace rejects \x00 in regex
        // bracket expressions on some PHP builds.
        array_walk_recursive($payload, function(&$v) {
            if (is_string($v)) {
                $v = str_replace("\x00", '', $v);
                $v = preg_replace('/[\x01-\x08\x0b\x0c\x0e-\x1f]/', '', $v);
            }
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
                $peerRows .= "<tr><td>{$name}</td><td class=\"mono\">{$peer}</td><td>{$rx}</td><td>{$tx}</td><td>{$lastSeen}</td></tr>";
            } elseif ($status === 'online') {
                $ifaceRows .= "<tr><td>{$name}</td><td>{$rx}</td><td>{$tx}</td><td>{$lastSeen}</td></tr>";
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
        $ifaceOnline = count(array_filter($interfaces, fn($i) => ($i['status'] ?? '') === 'online' && ($i['peer_url'] ?? '') === ''));
        $ifaceOffline = $ifaceCount - $ifaceOnline;
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
  .btn-force { background: #a30; color: #fff; border: none; border-radius: 4px; padding: 6px 14px; font-size: 12px; cursor: pointer; margin-left: 6px; }
  .btn-force:hover { background: #c40; }
  .btn-force:disabled { background: #555; cursor: default; }
  .flush-msg { font-size: 11px; margin-left: 12px; padding: 4px 8px; border-radius: 3px; display: inline-block; }
  .flush-msg.ok { background: #153; color: #4f8; }
  .flush-msg.err { background: #531; color: #f84; }
</style>
</head>
<body>
<h1>Reticulum-php</h1>
<div class="sub">{$hostUrl} &mdash; {$now} <span class="refresh">(auto-refresh 5s)</span><button class="btn-flush" id="btn-flush" onclick="flushStale(false)">Flush Stale</button><button class="btn-force" id="btn-force" onclick="flushStale(true)">Force Flush</button><span id="flush-msg"></span></div>

<div class="grid">
  <div class="card"><div class="val">{$totalPending}</div><div class="lbl">Pending Outbound</div></div>
  <div class="card"><div class="val">{$ifaceOnline}<span style="font-size:14px;color:#888">/{$ifaceCount}</span></div><div class="lbl">Clients (online/total)</div></div>
  <div class="card"><div class="val">{$pktCount}</div><div class="lbl">Recent Packets</div></div>
</div>

<h2>Connected Peers</h2>
<table><thead><tr><th>Name</th><th>Peer URL</th><th>RX</th><th>TX</th><th>Last Seen</th></tr></thead><tbody>{$peerRows}</tbody></table>

<h2>Active Clients</h2>
<table><thead><tr><th>Name</th><th>RX</th><th>TX</th><th>Last Seen</th></tr></thead><tbody>{$ifaceRows}</tbody></table>

<h2>Pending Outbound</h2>
<table><thead><tr><th>Interface</th><th>Peer</th><th>Pending</th><th>Oldest</th></tr></thead><tbody>{$outboundRows}</tbody></table>

<h2>Received</h2>
<table><thead><tr><th>Type</th><th>Dest Hash</th><th>Status</th><th>Size</th><th>Time</th></tr></thead><tbody>{$packetRows}</tbody></table>

<h2>Queued Outbound</h2>
<table><thead><tr><th>Dest Hash</th><th>Reason</th><th>State</th><th>Queued</th></tr></thead><tbody>{$outPktRows}</tbody></table>

<script>
var autoRefresh = setTimeout(function(){ location.reload(); }, 5000);

function flushStale(force) {
  var btn = document.getElementById(force ? 'btn-force' : 'btn-flush');
  var otherBtn = document.getElementById(force ? 'btn-flush' : 'btn-force');
  var msg = document.getElementById('flush-msg');
  btn.disabled = true;
  if (otherBtn) otherBtn.disabled = true;
  btn.textContent = force ? 'Force Flushing...' : 'Flushing...';
  msg.className = 'flush-msg';
  msg.textContent = '';

  clearTimeout(autoRefresh);

  fetch('../maintenance/flush', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ force: !!force })
  })
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
      if (otherBtn) otherBtn.disabled = false;
      btn.textContent = force ? 'Force Flush' : 'Flush Stale';
      autoRefresh = setTimeout(function(){ location.reload(); }, 3000);
    });
}
</script>
</body>
</html>
HTML;

        exit;
    }
}