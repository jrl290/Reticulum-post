<?php

declare(strict_types=1);

namespace ReticulumPhp;

use PDO;

// Reticulum-php is request-operated. PHP peer wakes are fire-and-forget HTTP
// calls that prompt a peer to call our /v1/interfaces/exchange. They do not
// carry transport data and do not form a second transport path.

trait RequestPhpWakeTrait
{
    public function dispatchWakes(): void
    {
        // Wake peers with pending outbound (primary trigger).
        $peers = $this->phpPeerInterfaceIdsWithPendingOutbound();

        // Also wake peers that have pending acks owed to them — this ensures
        // the ack cycle completes even when only one side has outbound traffic.
        $ackPeers = $this->phpPeerInterfaceIdsWithPendingAcks();
        $seen = [];
        foreach ($peers as $p) { $seen[(string)$p['interface_id']] = true; }
        foreach ($ackPeers as $p) {
            if (!isset($seen[(string)$p['interface_id']])) {
                $peers[] = $p;
                $seen[(string)$p['interface_id']] = true;
            }
        }

        $minWakeInterval = (int) ($this->config['http']['min_wake_interval_ms'] ?? 1000);
        $wakeTimeoutMs = (int) ($this->config['http']['wake_timeout_ms'] ?? 500);
        $now = time();

        foreach ($peers as $peer) {
            $peerId = (string) ($peer['interface_id'] ?? '');
            $lastWake = isset($peer['last_wake_sent_at']) ? (int) $peer['last_wake_sent_at'] : 0;
            if (($now - $lastWake) * 1000 < $minWakeInterval) {
                continue;
            }

            // Exponential backoff: after N consecutive failures, wait 2^N seconds.
            $backoffUntil = isset($peer['wake_backoff_until']) ? (int) $peer['wake_backoff_until'] : 0;
            if ($backoffUntil > 0 && $now < $backoffUntil) {
                continue;
            }

            $peerUrl = (string) ($peer['peer_url'] ?? '');
            if ($peerUrl === '') {
                continue;
            }

            $success = $this->fireAndForgetWake($peerUrl, $wakeTimeoutMs);
            if ($success) {
                $this->resetWakeBackoff($peerId);
            } else {
                $this->incrementWakeBackoff($peerId, isset($peer['wake_failure_count']) ? (int) $peer['wake_failure_count'] : 0);
            }
            $this->touchPeerWakeSent($peerId);
        }
    }

    private function resetWakeBackoff(string $interfaceId): void
    {
        $stmt = $this->db->prepare(
            'UPDATE interfaces SET wake_failure_count = 0, wake_backoff_until = NULL WHERE interface_id = :id'
        );
        $stmt->bindValue(':id', $interfaceId, PDO::PARAM_STR);
        $stmt->execute();
    }

    private function incrementWakeBackoff(string $interfaceId, int $currentFailures): void
    {
        $newCount = $currentFailures + 1;
        // Exponential backoff: 2^N seconds, uncapped.
        $delay = pow(2, $newCount);

        // After 24 hours of consecutive failures, drop the peer entirely.
        if ($delay > 86400) {
            $stmt = $this->db->prepare(
                'UPDATE interfaces SET status = :offline, wake_failure_count = 0, wake_backoff_until = NULL WHERE interface_id = :id'
            );
            $stmt->bindValue(':offline', 'offline', PDO::PARAM_STR);
            $stmt->bindValue(':id', $interfaceId, PDO::PARAM_STR);
            $stmt->execute();
            return;
        }

        $backoffUntil = time() + (int) $delay;
        $stmt = $this->db->prepare(
            'UPDATE interfaces SET wake_failure_count = :count, wake_backoff_until = :until WHERE interface_id = :id'
        );
        $stmt->bindValue(':count', $newCount, PDO::PARAM_INT);
        $stmt->bindValue(':until', $backoffUntil, PDO::PARAM_INT);
        $stmt->bindValue(':id', $interfaceId, PDO::PARAM_STR);
        $stmt->execute();
    }

    private function fireAndForgetWake(string $peerUrl, int $timeoutMs): bool
    {
        // Append /v1/wake if peerUrl is a base URL (no /v1/ path suffix).
        if (!str_ends_with($peerUrl, "/v1/wake") && !str_contains($peerUrl, "/v1/")) {
            $peerUrl = rtrim($peerUrl, "/") . "/v1/wake";
        }
        $hostUrl = $this->config['host_url'] ?? ($this->config['http']['advertise_url'] ?? null);
        if (!is_string($hostUrl) || trim($hostUrl) === '') {
            return false;
        }

        $hostUrl = rtrim(trim($hostUrl), '/');
        $body = json_encode([
            'waker_url' => $hostUrl,
        ], JSON_THROW_ON_ERROR | JSON_PARTIAL_OUTPUT_ON_ERROR);

        // Fire-and-forget: short timeout, but track success for backoff.
        if (function_exists('curl_init')) {
            return $this->fireAndForgetWakeWithCurl($peerUrl, $body, $timeoutMs);
        } else {
            return $this->fireAndForgetWakeWithStream($peerUrl, $body, $timeoutMs);
        }
    }

    private function fireAndForgetWakeWithCurl(string $url, string $body, int $timeoutMs): bool
    {
        $curl = curl_init($url);
        if ($curl === false) {
            return false;
        }

        curl_setopt($curl, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($curl, CURLOPT_CUSTOMREQUEST, 'POST');
        curl_setopt($curl, CURLOPT_HTTPHEADER, ['Content-Type: application/json']);
        curl_setopt($curl, CURLOPT_POSTFIELDS, $body);
        curl_setopt($curl, CURLOPT_TIMEOUT_MS, $timeoutMs);
        curl_setopt($curl, CURLOPT_CONNECTTIMEOUT_MS, min($timeoutMs, 500));
        // Fire and drop — but check if it got through for backoff tracking.
        $result = curl_exec($curl);
        $httpCode = curl_getinfo($curl, CURLINFO_HTTP_CODE);
        curl_close($curl);
        return $result !== false && $httpCode > 0;
    }

    private function fireAndForgetWakeWithStream(string $url, string $body, int $timeoutMs): bool
    {
        $timeoutSec = max(0.1, $timeoutMs / 1000.0);
        $context = stream_context_create([
            'http' => [
                'method' => 'POST',
                'header' => 'Content-Type: application/json',
                'content' => $body,
                'timeout' => $timeoutSec,
                'ignore_errors' => true,
            ],
        ]);

        // Fire and check — we need to know if it connected.
        $fp = @fopen($url, 'r', false, $context);
        if ($fp !== false) {
            fclose($fp);
            return true;
        }
        return false;
    }

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
        $registerUrl = $exchangeUrl . '/v1/interfaces/register';
        $body = json_encode([
            'name' => $name,
            'bitrate' => 1000000,
            'mtu' => 500,
            'metadata' => [
                'client' => 'reticulum-php',
                'peer_url' => $hostUrl . '/v1/wake',
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
            $name,
            $localSessionToken,
            1000000,
            500,
            ['client' => 'reticulum-php', 'peer_url' => $exchangeUrl],
            $wakeUrl,
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
