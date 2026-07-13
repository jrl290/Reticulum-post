<?php

declare(strict_types=1);

namespace ReticulumPhp;

use PDO;

// Reticulum-php is request-operated. This PostInterface client trait registers
// this node as an interface on a remote Reticulum-post node and exchanges
// packets during request/response cycles.  It supports both poll-driven
// exchange (no wake_url) and wake-driven exchange (wake_url present — the
// remote wakes us via POST /v1/wake, and the wake handler triggers an
// exchange).

trait RequestPostInterfaceTrait
{
    /**
     * Ensure all configured PostInterface peers are registered on their
     * respective remote nodes.  Called during request prelude.
     */
    public function ensurePostInterfacePeersRegistered(): void
    {
        $peers = $this->config['post_interface_peers'] ?? [];
        if (!is_array($peers)) {
            return;
        }

        foreach ($peers as $peerId => $peerConfig) {
            if (!is_array($peerConfig)) {
                continue;
            }

            $this->ensurePostInterfacePeerRegistered($peerId, $peerConfig);
        }
    }

    /**
     * Register (or re-register) a single PostInterface peer on its remote node
     * and create the local interface entry.
     */
    public function ensurePostInterfacePeerRegistered(string $peerId, array $peerConfig): void
    {
        $existing = $this->postInterfacePeerRow($peerId);

        // Create or update the local interface entry that represents this peer.
        $localInterfaceId = $this->postInterfaceLocalInterfaceId($peerId);
        $remoteNodeUrl = rtrim((string) ($peerConfig['node_url'] ?? ''), '/');

        $localMetadata = [
            'client' => 'reticulum-post',
            'implementation' => 'PostInterface',
            'peer_id' => $peerId,
            'remote_node_url' => $remoteNodeUrl,
        ];

        // The remote's node_url serves as its wake URL (all Reticulum-post
        // nodes expose /v1/wake).  When packets are queued for this local
        // interface, scheduleWakeEventIfNeeded reads wake_url from metadata
        // and creates a __http_wake__ event to prompt the remote to fetch.
        if ($remoteNodeUrl !== '') {
            $localMetadata['wake_url'] = $remoteNodeUrl;
        }

        $this->upsertConfiguredInterface(
            $localInterfaceId,
            'post-iface:' . $peerId,
            bin2hex(random_bytes(32)),
            (int) ($peerConfig['bitrate'] ?? 62500),
            (int) ($peerConfig['mtu'] ?? 500),
            $localMetadata,
        );

        // If already registered and session is fresh, skip re-registration.
        if (is_array($existing)
            && ($existing['status'] ?? '') === 'online'
            && !empty($existing['remote_interface_id'])
            && !empty($existing['remote_session_token'])
            && (int) ($existing['registered_at'] ?? 0) > time() - 3600
        ) {
            return;
        }

        if ($remoteNodeUrl === '') {
            $this->updatePostInterfacePeerStatus($peerId, 'error', 'node_url is required');
            return;
        }

        $localWakeUrl = null;
        $wakeUrl = $peerConfig['wake_url'] ?? null;
        if (is_string($wakeUrl) && trim($wakeUrl) !== '') {
            $localWakeUrl = rtrim(trim($wakeUrl), '/');
        }

        $metadata = [
            'client' => 'reticulum-post',
            'implementation' => 'PostInterface',
        ];

        if ($localWakeUrl !== null) {
            $metadata['wake_url'] = $localWakeUrl;
        }

        try {
            $response = $this->postInterfaceHttpPost(
                $remoteNodeUrl . '/v1/interfaces/register',
                [
                    'name' => 'PHP PostInterface (' . ($peerConfig['name'] ?? $peerId) . ')',
                    'bitrate' => (int) ($peerConfig['bitrate'] ?? 62500),
                    'mtu' => (int) ($peerConfig['mtu'] ?? 500),
                    'metadata' => $metadata,
                ],
                (int) ($peerConfig['http_timeout_seconds'] ?? 15),
                (int) ($peerConfig['connect_timeout_seconds'] ?? 5),
            );

            $remoteInterfaceId = $response['interface_id'] ?? null;
            $remoteSessionToken = $response['session_token'] ?? null;
            if (!is_string($remoteInterfaceId) || !is_string($remoteSessionToken)) {
                throw new \RuntimeException('Remote registration did not return credentials');
            }

            $this->upsertPostInterfacePeer($peerId, $peerConfig, $remoteNodeUrl, $localWakeUrl, $remoteInterfaceId, $remoteSessionToken, $response);
            $this->updatePostInterfacePeerStatus($peerId, 'online');
        } catch (\Throwable $error) {
            $this->updatePostInterfacePeerStatus($peerId, 'error', $error->getMessage());
        }
    }

    /**
     * Exchange ALL pending outbound packets with a PostInterface peer.
     *
     * PostInterface is a transport pipe between two routers — it flushes
     * every pending outbound packet across all online interfaces, sends them
     * to the remote, and processes any delivery packets that come back.
     *
     * @return array Exchange summary
     */
    public function exchangeWithPostInterfacePeer(string $peerId): array
    {
        $peer = $this->postInterfacePeerRow($peerId);
        if (!is_array($peer) || (($peer['status'] ?? '') !== 'online' && ($peer['status'] ?? '') !== 'error')) {
            return ['status' => 'skipped', 'reason' => 'peer_not_online'];
        }

        // Auto-recover from transient errors: re-register if needed.
        if (($peer['status'] ?? '') === 'error') {
            $peerConfig = $this->config['post_interface_peers'][$peerId] ?? [];
            if ($peerConfig !== []) {
                $this->ensurePostInterfacePeerRegistered($peerId, $peerConfig);
                $peer = $this->postInterfacePeerRow($peerId);
            }
        }

        if (!is_array($peer) || ($peer['status'] ?? '') !== 'online') {
            return ['status' => 'skipped', 'reason' => 'peer_not_online'];
        }

        $remoteNodeUrl = (string) ($peer['remote_node_url'] ?? '');
        $remoteInterfaceId = (string) ($peer['remote_interface_id'] ?? '');
        $remoteSessionToken = (string) ($peer['remote_session_token'] ?? '');

        if ($remoteNodeUrl === '' || $remoteInterfaceId === '' || $remoteSessionToken === '') {
            return ['status' => 'skipped', 'reason' => 'missing_credentials'];
        }

        $maxBatchPackets = (int) ($peer['remote_max_batch_packets'] ?? 64);
        $httpTimeout = (int) ($peer['http_timeout_seconds'] ?? 15);
        $connectTimeout = (int) ($peer['connect_timeout_seconds'] ?? 5);

        try {
            // Fetch ALL pending outbound packets across all online interfaces.
            // PostInterface is a transport pipe — it doesn't filter by interface.
            $allPackets = [];
            $batchesToAck = []; // interface_id => [batch_ids]

            $onlineInterfaces = $this->allOnlineInterfaceIds();
            foreach ($onlineInterfaces as $ifaceId) {
                $outbound = $this->fetchOutboundBatch($ifaceId, $maxBatchPackets - count($allPackets));
                $pkts = $outbound['packets'] ?? [];
                $batchId = $outbound['batch_id'] ?? null;

                if ($pkts !== []) {
                    $allPackets = array_merge($allPackets, $pkts);
                    if ($batchId !== null) {
                        $batchesToAck[$ifaceId][] = $batchId;
                    }
                }

                if (count($allPackets) >= $maxBatchPackets) {
                    break;
                }
            }

            $outboundPackets = array_slice($allPackets, 0, $maxBatchPackets);
            $combinedBatchId = $outboundPackets !== [] ? bin2hex(random_bytes(12)) : null;

            $body = [
                'interface_id' => $remoteInterfaceId,
                'session_token' => $remoteSessionToken,
                'max_packets' => $maxBatchPackets,
                'packets' => $outboundPackets,
                'ack_batch_ids' => [],
            ];

            if ($combinedBatchId !== null && $outboundPackets !== []) {
                $body['batch_id'] = $combinedBatchId;
            }

            $response = $this->postInterfaceHttpPost(
                $remoteNodeUrl . '/v1/interfaces/exchange',
                $body,
                $httpTimeout,
                $connectTimeout,
            );

            // Ack our original per-interface batches now that the remote accepted them.
            foreach ($batchesToAck as $ifaceId => $batchIds) {
                foreach ($batchIds as $bid) {
                    $this->acknowledgeOutboundBatches($ifaceId, [$bid]);
                }
            }

            // Also ack the delivery batch the remote sent us.
            $deliveryBatchId = $response['delivery_batch_id'] ?? null;
            if (is_string($deliveryBatchId) && $deliveryBatchId !== '') {
                foreach ($onlineInterfaces as $ifaceId) {
                    $this->acknowledgeOutboundBatches($ifaceId, [$deliveryBatchId]);
                }
            }

            // Process delivery packets as inbound on the local peer interface.
            $deliveryPackets = $response['delivery_packets'] ?? [];
            $inboundSummary = null;

            if (is_array($deliveryPackets) && $deliveryPackets !== []) {
                $localInterfaceId = $this->postInterfaceLocalInterfaceId($peerId);
                $inboundBatchId = is_string($deliveryBatchId) && $deliveryBatchId !== ''
                    ? $deliveryBatchId
                    : 'post-iface-delivery-' . bin2hex(random_bytes(8));

                $inbound = $this->ingestInboundBatchInline($localInterfaceId, $inboundBatchId, $deliveryPackets);
                $inboundSummary = $inbound['processing'] ?? null;
            }

            $this->touchPostInterfacePeerExchange($peerId);

            return [
                'status' => 'exchanged',
                'peer_id' => $peerId,
                'outbound_packets_sent' => count($outboundPackets),
                'outbound_batch_id' => $combinedBatchId,
                'delivery_packets_received' => count($deliveryPackets),
                'delivery_batch_id' => $deliveryBatchId,
                'inbound_processing' => $inboundSummary,
            ];
        } catch (\Throwable $error) {
            $this->updatePostInterfacePeerStatus($peerId, 'error', $error->getMessage());
            return [
                'status' => 'error',
                'peer_id' => $peerId,
                'error' => $error->getMessage(),
            ];
        }
    }

    /**
     * Exchange with all online PostInterface peers (poll-mode only).
     */
    public function exchangeWithAllPostInterfacePeers(): array
    {
        $peers = $this->config['post_interface_peers'] ?? [];
        if (!is_array($peers)) {
            return [];
        }

        $results = [];
        foreach ($peers as $peerId => $peerConfig) {
            if (!is_array($peerConfig)) {
                continue;
            }

            // Skip wake-mode peers — they are triggered by incoming wake.
            $wakeUrl = $peerConfig['wake_url'] ?? null;
            if (is_string($wakeUrl) && trim($wakeUrl) !== '') {
                continue;
            }

            $results[$peerId] = $this->exchangeWithPostInterfacePeer($peerId);
        }

        return $results;
    }

    /**
     * Resolve a PostInterface peer ID from a waker URL.
     */
    public function postInterfacePeerIdForWakerUrl(string $wakerUrl): ?string
    {
        $peers = $this->config['post_interface_peers'] ?? [];
        if (!is_array($peers)) {
            return null;
        }

        $wakerUrl = rtrim($wakerUrl, '/');

        foreach ($peers as $peerId => $peerConfig) {
            if (!is_array($peerConfig)) {
                continue;
            }

            $nodeUrl = rtrim((string) ($peerConfig['node_url'] ?? ''), '/');
            if ($nodeUrl !== '' && $nodeUrl === $wakerUrl) {
                return $peerId;
            }
        }

        // Also check stored peers.
        $stmt = $this->db->prepare(
            'SELECT peer_id FROM post_interface_peers WHERE remote_node_url = :remote_node_url LIMIT 1'
        );
        $stmt->bindValue(':remote_node_url', $wakerUrl, PDO::PARAM_STR);
        $stmt->execute();
        $row = $stmt->fetch(PDO::FETCH_ASSOC);

        return is_array($row) ? ($row['peer_id'] ?? null) : null;
    }

    /**
     * Queue a wake event for async exchange dispatch.
     */
    public function queuePostInterfaceWakeEvent(string $peerId, string $wakerUrl): void
    {
        $peer = $this->postInterfacePeerRow($peerId);
        $localInterfaceId = is_array($peer) ? (string) ($peer['local_interface_id'] ?? '') : '';

        $stmt = $this->db->prepare(
            'INSERT INTO wake_events (
                interface_id, wake_profile, wake_target,
                wake_data_json, queue_reason, queued_packet_count, created_at
            ) VALUES (
                :interface_id, :wake_profile, :wake_target,
                :wake_data_json, :queue_reason, :queued_packet_count, :created_at
            )'
        );
        $stmt->bindValue(':interface_id', $localInterfaceId, PDO::PARAM_STR);
        $stmt->bindValue(':wake_profile', '__post_interface_wake__', PDO::PARAM_STR);
        $stmt->bindValue(':wake_target', $peerId, PDO::PARAM_STR);
        $stmt->bindValue(':wake_data_json', self::encodeJson(['waker_url' => $wakerUrl, 'peer_id' => $peerId]), PDO::PARAM_STR);
        $stmt->bindValue(':queue_reason', 'post_interface_wake', PDO::PARAM_STR);
        $stmt->bindValue(':queued_packet_count', 0, PDO::PARAM_INT);
        $stmt->bindValue(':created_at', time(), PDO::PARAM_INT);
        $stmt->execute();
    }

    /**
     * Dispatch a PostInterface wake event from the CLI wake runner.
     */
    public function dispatchPostInterfaceWakeEvent(int $wakeEventId): ?array
    {
        $stmt = $this->db->prepare(
            'SELECT wake_event_id, wake_data_json
             FROM wake_events
             WHERE wake_event_id = :wake_event_id
               AND wake_profile = :wake_profile
               AND dispatched_at IS NULL
               AND failed_at IS NULL
               AND claimed_at IS NULL
             LIMIT 1'
        );
        $stmt->bindValue(':wake_event_id', $wakeEventId, PDO::PARAM_INT);
        $stmt->bindValue(':wake_profile', '__post_interface_wake__', PDO::PARAM_STR);
        $stmt->execute();
        $row = $stmt->fetch(PDO::FETCH_ASSOC);

        if (!is_array($row)) {
            return null;
        }

        $wakeData = self::decodeJson((string) ($row['wake_data_json'] ?? '[]'));
        $wakerUrl = (string) ($wakeData['waker_url'] ?? '');

        // Claim the event.
        $now = time();
        $pid = (int) (getmypid() ?: 0);
        $claim = $this->db->prepare(
            'UPDATE wake_events
             SET claimed_at = :claimed_at, claimed_by_pid = :claimed_by_pid
             WHERE wake_event_id = :wake_event_id
               AND dispatched_at IS NULL AND failed_at IS NULL AND claimed_by_pid IS NULL'
        );
        $claim->bindValue(':claimed_at', $now, PDO::PARAM_INT);
        $claim->bindValue(':claimed_by_pid', $pid, PDO::PARAM_INT);
        $claim->bindValue(':wake_event_id', $wakeEventId, PDO::PARAM_INT);
        $claim->execute();

        if ($claim->rowCount() !== 1) {
            return null;
        }

        try {
            $result = $this->handlePostInterfaceWake($wakerUrl);

            $stmt2 = $this->db->prepare(
                'UPDATE wake_events
                 SET dispatched_at = :dispatched_at, dispatch_result_json = :result_json
                 WHERE wake_event_id = :wake_event_id'
            );
            $stmt2->bindValue(':dispatched_at', $now, PDO::PARAM_INT);
            $stmt2->bindValue(':result_json', self::encodeJson($result), PDO::PARAM_STR);
            $stmt2->bindValue(':wake_event_id', $wakeEventId, PDO::PARAM_INT);
            $stmt2->execute();

            return [
                'status' => 'dispatched',
                'wake_event_id' => $wakeEventId,
                'post_interface_exchange' => $result,
            ];
        } catch (\Throwable $error) {
            $stmt3 = $this->db->prepare(
                'UPDATE wake_events
                 SET failed_at = :failed_at, failure_message = :msg
                 WHERE wake_event_id = :wake_event_id'
            );
            $stmt3->bindValue(':failed_at', $now, PDO::PARAM_INT);
            $stmt3->bindValue(':msg', $error->getMessage(), PDO::PARAM_STR);
            $stmt3->bindValue(':wake_event_id', $wakeEventId, PDO::PARAM_INT);
            $stmt3->execute();

            return [
                'status' => 'failed',
                'wake_event_id' => $wakeEventId,
                'error' => $error->getMessage(),
            ];
        }
    }

    /**
     * Handle a wake notification from a remote PostInterface peer.
     */
    public function handlePostInterfaceWake(string $wakerUrl): array
    {
        $wakerUrl = rtrim(trim($wakerUrl), '/');
        if ($wakerUrl === '') {
            return ['status' => 'ignored', 'reason' => 'empty_waker_url'];
        }

        $peerId = $this->postInterfacePeerIdForWakerUrl($wakerUrl);
        if ($peerId === null) {
            return ['status' => 'ignored', 'reason' => 'unknown_waker'];
        }

        return $this->exchangeWithPostInterfacePeer($peerId);
    }

    /**
     * Compute the deterministic local interface_id for a PostInterface peer.
     */
    public function postInterfaceLocalInterfaceId(string $peerId): string
    {
        return bin2hex(substr(hash('sha256', 'post-iface:' . $peerId, true), 0, 16));
    }

    // ── Health ───────────────────────────────────────────────────────────

    public function postInterfacePeerSummary(): array
    {
        $peers = [];
        $stmt = $this->db->query(
            'SELECT peer_id, name, remote_node_url, local_wake_url, status, last_exchange_at, last_error_message
             FROM post_interface_peers
             ORDER BY peer_id ASC'
        );

        while (($row = $stmt->fetch(PDO::FETCH_ASSOC)) !== false) {
            if (!is_array($row)) {
                continue;
            }

            $peers[] = [
                'peer_id' => (string) ($row['peer_id'] ?? ''),
                'name' => (string) ($row['name'] ?? ''),
                'remote_node_url' => (string) ($row['remote_node_url'] ?? ''),
                'local_wake_url' => ($row['local_wake_url'] ?? null),
                'status' => (string) ($row['status'] ?? 'unknown'),
                'last_exchange_at' => ($row['last_exchange_at'] ?? null),
                'last_error_message' => ($row['last_error_message'] ?? null),
            ];
        }

        return $peers;
    }

    // ── Internal queries ─────────────────────────────────────────────────

    /**
     * Return all currently-online interface IDs.
     */
    private function allOnlineInterfaceIds(): array
    {
        $stmt = $this->db->prepare(
            'SELECT interface_id FROM interfaces WHERE status = :status ORDER BY last_seen_at DESC'
        );
        $stmt->bindValue(':status', 'online', PDO::PARAM_STR);
        $stmt->execute();

        $ids = [];
        while (($row = $stmt->fetch(PDO::FETCH_ASSOC)) !== false) {
            if (!empty($row['interface_id'])) {
                $ids[] = (string) $row['interface_id'];
            }
        }

        return $ids;
    }

    private function postInterfacePeerRow(string $peerId): ?array
    {
        $stmt = $this->db->prepare(
            'SELECT peer_id, name, local_interface_id, remote_node_url, local_wake_url,
                    remote_interface_id, remote_session_token,
                    remote_max_batch_packets, remote_idle_exchange_interval_ms,
                    remote_max_packet_bytes, bitrate, mtu,
                    poll_interval_seconds, http_timeout_seconds, connect_timeout_seconds,
                    registered_at, last_exchange_at, last_error_message, status
             FROM post_interface_peers
             WHERE peer_id = :peer_id
             LIMIT 1'
        );
        $stmt->bindValue(':peer_id', $peerId, PDO::PARAM_STR);
        $stmt->execute();
        $row = $stmt->fetch(PDO::FETCH_ASSOC);

        return is_array($row) ? $row : null;
    }

    private function upsertPostInterfacePeer(
        string $peerId,
        array $peerConfig,
        string $remoteNodeUrl,
        ?string $localWakeUrl,
        string $remoteInterfaceId,
        string $remoteSessionToken,
        array $registrationResponse,
    ): void {
        $now = time();
        $localInterfaceId = $this->postInterfaceLocalInterfaceId($peerId);

        $stmt = $this->db->prepare(
            $this->insertOrSql(
                'INSERT OR REPLACE INTO post_interface_peers (
                    peer_id, name, local_interface_id, remote_node_url, local_wake_url,
                    remote_interface_id, remote_session_token,
                    remote_max_batch_packets, remote_idle_exchange_interval_ms,
                    remote_max_packet_bytes, bitrate, mtu,
                    poll_interval_seconds, http_timeout_seconds, connect_timeout_seconds,
                    registered_at, status
                ) VALUES (
                    :peer_id, :name, :local_interface_id, :remote_node_url, :local_wake_url,
                    :remote_interface_id, :remote_session_token,
                    :remote_max_batch_packets, :remote_idle_exchange_interval_ms,
                    :remote_max_packet_bytes, :bitrate, :mtu,
                    :poll_interval_seconds, :http_timeout_seconds, :connect_timeout_seconds,
                    :registered_at, :status
                )'
            )
        );
        $stmt->bindValue(':peer_id', $peerId, PDO::PARAM_STR);
        $stmt->bindValue(':name', (string) ($peerConfig['name'] ?? $peerId), PDO::PARAM_STR);
        $stmt->bindValue(':local_interface_id', $localInterfaceId, PDO::PARAM_STR);
        $stmt->bindValue(':remote_node_url', $remoteNodeUrl, PDO::PARAM_STR);
        $stmt->bindValue(':local_wake_url', $localWakeUrl, $localWakeUrl === null ? PDO::PARAM_NULL : PDO::PARAM_STR);
        $stmt->bindValue(':remote_interface_id', $remoteInterfaceId, PDO::PARAM_STR);
        $stmt->bindValue(':remote_session_token', $remoteSessionToken, PDO::PARAM_STR);
        $stmt->bindValue(':remote_max_batch_packets', (int) ($registrationResponse['max_batch_packets'] ?? 64), PDO::PARAM_INT);
        $stmt->bindValue(':remote_idle_exchange_interval_ms', (int) ($registrationResponse['idle_exchange_interval_ms'] ?? 1000), PDO::PARAM_INT);
        $stmt->bindValue(':remote_max_packet_bytes', (int) ($registrationResponse['max_packet_bytes'] ?? 512), PDO::PARAM_INT);
        $stmt->bindValue(':bitrate', (int) ($peerConfig['bitrate'] ?? 62500), PDO::PARAM_INT);
        $stmt->bindValue(':mtu', (int) ($peerConfig['mtu'] ?? 500), PDO::PARAM_INT);
        $stmt->bindValue(':poll_interval_seconds', isset($peerConfig['poll_interval_seconds']) ? (float) $peerConfig['poll_interval_seconds'] : null, isset($peerConfig['poll_interval_seconds']) ? PDO::PARAM_STR : PDO::PARAM_NULL);
        $stmt->bindValue(':http_timeout_seconds', (int) ($peerConfig['http_timeout_seconds'] ?? 15), PDO::PARAM_INT);
        $stmt->bindValue(':connect_timeout_seconds', (int) ($peerConfig['connect_timeout_seconds'] ?? 5), PDO::PARAM_INT);
        $stmt->bindValue(':registered_at', $now, PDO::PARAM_INT);
        $stmt->bindValue(':status', 'online', PDO::PARAM_STR);
        $stmt->execute();
    }

    private function updatePostInterfacePeerStatus(string $peerId, string $status, ?string $errorMessage = null): void
    {
        // Use UPDATE to preserve existing credentials (remote_interface_id,
        // remote_session_token) that were set by a prior successful registration.
        $stmt = $this->db->prepare(
            'UPDATE post_interface_peers
             SET status = :status,
                 last_error_message = :last_error_message
             WHERE peer_id = :peer_id'
        );
        $stmt->bindValue(':status', $status, PDO::PARAM_STR);
        $stmt->bindValue(':last_error_message', $errorMessage, $errorMessage === null ? PDO::PARAM_NULL : PDO::PARAM_STR);
        $stmt->bindValue(':peer_id', $peerId, PDO::PARAM_STR);
        $stmt->execute();

        // If no row exists yet, insert a minimal row so the error is visible.
        // Use INSERT IGNORE / INSERT OR IGNORE to avoid racing with upsertPostInterfacePeer.
        $now = time();
        $config = $this->config['post_interface_peers'][$peerId] ?? [];
        $localInterfaceId = $this->postInterfaceLocalInterfaceId($peerId);
        $remoteNodeUrl = isset($config['node_url']) ? rtrim((string) $config['node_url'], '/') : '';

        $insert = $this->db->prepare(
            $this->insertOrSql(
                'INSERT OR IGNORE INTO post_interface_peers (
                    peer_id, name, local_interface_id, remote_node_url,
                    bitrate, mtu, http_timeout_seconds, connect_timeout_seconds,
                    status, last_error_message, registered_at
                ) VALUES (
                    :peer_id, :name, :local_interface_id, :remote_node_url,
                    :bitrate, :mtu, :http_timeout_seconds, :connect_timeout_seconds,
                    :status, :last_error_message, :registered_at
                )'
            )
        );
        $insert->bindValue(':peer_id', $peerId, PDO::PARAM_STR);
        $insert->bindValue(':name', (string) ($config['name'] ?? $peerId), PDO::PARAM_STR);
        $insert->bindValue(':local_interface_id', $localInterfaceId, PDO::PARAM_STR);
        $insert->bindValue(':remote_node_url', $remoteNodeUrl, PDO::PARAM_STR);
        $insert->bindValue(':bitrate', (int) ($config['bitrate'] ?? 62500), PDO::PARAM_INT);
        $insert->bindValue(':mtu', (int) ($config['mtu'] ?? 500), PDO::PARAM_INT);
        $insert->bindValue(':http_timeout_seconds', (int) ($config['http_timeout_seconds'] ?? 15), PDO::PARAM_INT);
        $insert->bindValue(':connect_timeout_seconds', (int) ($config['connect_timeout_seconds'] ?? 5), PDO::PARAM_INT);
        $insert->bindValue(':status', $status, PDO::PARAM_STR);
        $insert->bindValue(':last_error_message', $errorMessage, $errorMessage === null ? PDO::PARAM_NULL : PDO::PARAM_STR);
        $insert->bindValue(':registered_at', $now, PDO::PARAM_INT);
        $insert->execute();
    }

    private function touchPostInterfacePeerExchange(string $peerId): void
    {
        $stmt = $this->db->prepare(
            'UPDATE post_interface_peers
             SET last_exchange_at = :last_exchange_at,
                 last_error_message = NULL
             WHERE peer_id = :peer_id'
        );
        $stmt->bindValue(':last_exchange_at', time(), PDO::PARAM_INT);
        $stmt->bindValue(':peer_id', $peerId, PDO::PARAM_STR);
        $stmt->execute();
    }

    // ── HTTP helpers ─────────────────────────────────────────────────────

    private function postInterfaceHttpPost(string $url, array $body, int $httpTimeoutSeconds, int $connectTimeoutSeconds): array
    {
        $headers = ['Content-Type: application/json'];
        $encodedBody = json_encode($body, JSON_THROW_ON_ERROR);

        if (function_exists('curl_init')) {
            return $this->postInterfaceHttpPostWithCurl($url, $headers, $encodedBody, $httpTimeoutSeconds, $connectTimeoutSeconds);
        }

        return $this->postInterfaceHttpPostWithStreams($url, $headers, $encodedBody, $httpTimeoutSeconds);
    }

    private function postInterfaceHttpPostWithCurl(string $url, array $headers, string $body, int $httpTimeoutSeconds, int $connectTimeoutSeconds): array
    {
        $curl = curl_init($url);
        if ($curl === false) {
            throw new \RuntimeException('Unable to initialise cURL for PostInterface request');
        }

        curl_setopt($curl, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($curl, CURLOPT_CUSTOMREQUEST, 'POST');
        curl_setopt($curl, CURLOPT_HTTPHEADER, $headers);
        curl_setopt($curl, CURLOPT_TIMEOUT, $httpTimeoutSeconds);
        curl_setopt($curl, CURLOPT_CONNECTTIMEOUT, $connectTimeoutSeconds);
        curl_setopt($curl, CURLOPT_POSTFIELDS, $body);

        $responseBody = curl_exec($curl);
        if ($responseBody === false) {
            $error = curl_error($curl);
            throw new \RuntimeException('PostInterface HTTP request failed: ' . $error);
        }

        $statusCode = (int) curl_getinfo($curl, CURLINFO_RESPONSE_CODE);

        if ($statusCode < 200 || $statusCode >= 300) {
            throw new \RuntimeException('PostInterface HTTP request returned ' . $statusCode . ': ' . substr($responseBody, 0, 500));
        }

        $decoded = json_decode($responseBody, true, flags: JSON_THROW_ON_ERROR);
        if (!is_array($decoded)) {
            throw new \RuntimeException('PostInterface HTTP response was not a JSON object');
        }

        return $decoded;
    }

    private function postInterfaceHttpPostWithStreams(string $url, array $headers, string $body, int $httpTimeoutSeconds): array
    {
        $context = stream_context_create([
            'http' => [
                'method' => 'POST',
                'header' => implode("\r\n", $headers),
                'content' => $body,
                'timeout' => $httpTimeoutSeconds,
                'ignore_errors' => true,
            ],
        ]);

        $responseBody = @file_get_contents($url, false, $context);
        if ($responseBody === false) {
            $error = error_get_last();
            throw new \RuntimeException('PostInterface HTTP request failed: ' . ($error['message'] ?? 'unknown error'));
        }

        $headersResponse = $http_response_header ?? [];
        $statusCode = 0;
        if (isset($headersResponse[0]) && preg_match('/\s(\d{3})\s/', $headersResponse[0], $matches) === 1) {
            $statusCode = (int) $matches[1];
        }

        if ($statusCode < 200 || $statusCode >= 300) {
            throw new \RuntimeException('PostInterface HTTP request returned ' . $statusCode . ': ' . substr($responseBody, 0, 500));
        }

        $decoded = json_decode($responseBody, true, flags: JSON_THROW_ON_ERROR);
        if (!is_array($decoded)) {
            throw new \RuntimeException('PostInterface HTTP response was not a JSON object');
        }

        return $decoded;
    }
}
