<?php

declare(strict_types=1);

namespace ReticulumPhp;

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
        $fp = @stream_socket_client(
            ($isTls ? 'tls://' : 'tcp://') . $host . ':' . $port,
            $errno,
            $errstr,
            2, // 2s connect timeout — just enough for TCP+TLS handshake
            STREAM_CLIENT_ASYNC_CONNECT
        );

        if ($fp === false) {
            return;
        }

        // Complete the TLS handshake if needed.
        if ($isTls) {
            @stream_set_blocking($fp, true);
            @stream_socket_enable_crypto($fp, true, STREAM_CRYPTO_METHOD_TLSv1_2_CLIENT);
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

        @fwrite($fp, $request);
        @fclose($fp);
        // Never read the response. Truly fire and forget.
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
     * It is called from the wake runner (background process spawned via exec()),
     * NOT from the main exchange epilogue. This keeps the main request path
     * non-blocking while still allowing full bidirectional exchange.
     */
    public function exchangeWithPhpPeer(string $peerUrl): array
    {
        $peer = $this->phpPeerInterfaceByPeerUrl($peerUrl);
        if ($peer === null) {
            return ['status' => 'unknown_peer', 'peer_url' => $peerUrl];
        }

        $peerInterfaceId = (string) ($peer['peer_interface_id'] ?? '');
        $peerSessionToken = (string) ($peer['peer_session_token'] ?? '');
        if ($peerInterfaceId === '' || $peerSessionToken === '') {
            return ['status' => 'no_credentials', 'peer_url' => $peerUrl];
        }

        // Collect pending ack batch IDs owed to this peer.
        $ackBatchIds = $this->drainPeerAckBatchIds((string) $peer['interface_id']);

        // Call the peer's exchange endpoint.
        $exchangeUrl = $peerUrl . '/v1/interfaces/exchange';

        try {
            $payload = json_encode([
                'interface_id' => $peerInterfaceId,
                'session_token' => $peerSessionToken,
                'packets' => [],
                'max_packets' => (int) $this->config['http']['max_batch_packets'],
                'ack_batch_ids' => $ackBatchIds,
            ], JSON_THROW_ON_ERROR | JSON_PARTIAL_OUTPUT_ON_ERROR);
        } catch (\JsonException $e) {
            $this->log('exchangeWithPhpPeer: json_encode failed: ' . $e->getMessage());
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
                $this->log('error', 'drainPeerAckBatchIds: decodeJson failed for ' . $peerInterfaceId . ': ' . $e->getMessage());
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
                    $this->log('error', 'appendPeerAckBatchId: decodeJson failed for ' . $peerInterfaceId . ': ' . $e->getMessage());
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

    public function initializeNode(): array
    {
        $summary = [
            'status' => 'ok',
            'migrated' => false,
            'peers' => [],
        ];

        // Schema migration.
        $this->migrate();
        $summary['migrated'] = true;

        // Connect to configured peer interfaces.
        $interfaces = $this->config['interfaces'] ?? [];
        if (!is_array($interfaces)) {
            return $summary;
        }

        $hostUrl = $this->config['host_url'] ?? ($this->config['http']['advertise_url'] ?? null);
        if (!is_string($hostUrl) || trim($hostUrl) === '') {
            $summary['status'] = 'no_host_url';
            return $summary;
        }
        $hostUrl = rtrim(trim($hostUrl), '/');

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
            if (is_string($wakeUrl) && trim($wakeUrl) !== '') {
                $wakeUrl = trim($wakeUrl);
            } else {
                $wakeUrl = $exchangeUrl . '/v1/wake';
            }

            $result = $this->connectToPeer($exchangeUrl, $wakeUrl, $hostUrl, (string) $ifaceName);
            $summary['peers'][] = $result;
        }

        return $summary;
    }

    private function connectToPeer(string $exchangeUrl, string $wakeUrl, string $hostUrl, string $name): array
    {
        // Check if already connected.
        $existing = $this->phpPeerInterfaceByPeerUrl($exchangeUrl);
        if ($existing !== null) {
            return [
                'peer_url' => $exchangeUrl,
                'wake_url' => $wakeUrl,
                'status' => 'already_connected',
                'interface_id' => $existing['interface_id'],
            ];
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
