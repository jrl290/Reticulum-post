<?php

declare(strict_types=1);

namespace ReticulumPhp;

use PDO;

// Reticulum-php is request-operated. These reporting helpers expose request
// path state for /health and /debug inspection only; they do not alter packet
// flow or create a second transport mechanism.

trait RequestDebugReportTrait
{
    public function healthSummary(): array
    {
        // Storage is reported here because the cap is silent when it works.
        // storage_bytes is what the account is charged, so it includes
        // storage_database_free_bytes. When the two are close, almost nothing
        // here is live data: pruning has kept up but no reclaim has rebuilt the
        // tablespaces, and the space is recoverable by a reclaim pass.
        $footprint = $this->storageFootprint();

        return [
            'storage_bytes' => $footprint['total_bytes'],
            'storage_database_bytes' => $footprint['database_bytes'],
            'storage_database_free_bytes' => $footprint['database_free_bytes'],
            'storage_log_bytes' => $footprint['log_bytes'],
            'storage_budget_bytes' => (int) (
                ($this->config['maintenance'] ?? $this->config['worker'] ?? [])['storage_max_bytes']
                ?? 300000000
            ),
            'interfaces' => $this->countByQuery('SELECT COUNT(*) FROM interfaces'),
            'interfaces_online' => $this->countByQuery("SELECT COUNT(*) FROM interfaces WHERE status = 'online'"),
            'inbound_batches' => $this->countByQuery('SELECT COUNT(*) FROM inbound_batches'),
            'inbound_batches_pending' => $this->countByQuery('SELECT COUNT(*) FROM inbound_batches WHERE processed_at IS NULL'),
            'inbound_packets_parsed' => $this->countByQuery("SELECT COUNT(*) FROM inbound_packets WHERE status = 'parsed'"),
            'inbound_packets_failed' => $this->countByQuery("SELECT COUNT(*) FROM inbound_packets WHERE status = 'error'"),
            'inbound_packets_rejected' => $this->countByQuery("SELECT COUNT(*) FROM inbound_packets WHERE filter_status = 'rejected'"),
            'validated_announces' => $this->countByQuery("SELECT COUNT(*) FROM inbound_packets WHERE announce_status IN ('validated', 'path_updated')"),
            'announce_validation_failures' => $this->countByQuery("SELECT COUNT(*) FROM inbound_packets WHERE announce_status = 'invalid'"),
            'packet_hashes_remembered' => $this->countByQuery('SELECT COUNT(*) FROM packet_hashes'),
            'known_destinations' => $this->countByQuery('SELECT COUNT(*) FROM known_destinations'),
            'path_entries' => $this->countByQuery('SELECT COUNT(*) FROM path_entries'),
            'path_request_tags' => $this->countByQuery('SELECT COUNT(*) FROM path_request_tags'),
            'reverse_path_entries' => $this->countByQuery('SELECT COUNT(*) FROM reverse_path_entries'),
            'link_transport_entries' => $this->countByQuery('SELECT COUNT(*) FROM link_transport_entries'),
            'validated_link_transport_entries' => $this->countByQuery('SELECT COUNT(*) FROM link_transport_entries WHERE validated = 1'),
            'outbound_path_responses_pending' => $this->countByQuery("SELECT COUNT(*) FROM outbound_packets WHERE acked_at IS NULL AND queue_reason = 'path_response'"),
            'outbound_proof_relays_pending' => $this->countByQuery("SELECT COUNT(*) FROM outbound_packets WHERE acked_at IS NULL AND queue_reason = 'proof_relay'"),
            'outbound_lrproof_relays_pending' => $this->countByQuery("SELECT COUNT(*) FROM outbound_packets WHERE acked_at IS NULL AND queue_reason = 'lrproof_relay'"),
            'outbound_link_relays_pending' => $this->countByQuery("SELECT COUNT(*) FROM outbound_packets WHERE acked_at IS NULL AND queue_reason = 'link_relay'"),
            'outbound_relay_packets_pending' => $this->countByQuery("SELECT COUNT(*) FROM outbound_packets WHERE acked_at IS NULL AND queue_reason = 'relay'"),
            'outbound_packets_pending' => $this->countByQuery('SELECT COUNT(*) FROM outbound_packets WHERE acked_at IS NULL'),
            'outbound_batches_unacked' => $this->countByQuery('SELECT COUNT(*) FROM outbound_batches WHERE acked_at IS NULL'),
            'wake_events_pending' => $this->countByQuery('SELECT COUNT(*) FROM wake_events WHERE dispatched_at IS NULL AND failed_at IS NULL'),
            'wake_events_claimed' => $this->countByQuery('SELECT COUNT(*) FROM wake_events WHERE dispatched_at IS NULL AND failed_at IS NULL AND claimed_at IS NOT NULL'),
            'wake_events_dispatched' => $this->countByQuery('SELECT COUNT(*) FROM wake_events WHERE dispatched_at IS NOT NULL'),
            'wake_events_failed' => $this->countByQuery('SELECT COUNT(*) FROM wake_events WHERE failed_at IS NOT NULL'),
        ];
    }

    public function healthInterfaceRegistry(int $limit = 5): array
    {
        $limit = max(1, $limit);

        return [
            'summary' => [
                'total' => $this->countByQuery('SELECT COUNT(*) FROM interfaces'),
                'online' => $this->countByQuery("SELECT COUNT(*) FROM interfaces WHERE status = 'online'"),
                'offline' => $this->countByQuery("SELECT COUNT(*) FROM interfaces WHERE status = 'offline'"),
            ],
            // Nodes and gateways only; browsers are in the counts above.
            'recent_online' => array_map(
                static fn (array $row): array => self::publicInterfaceView($row, false),
                $this->recentNodeInterfacesByStatus('online', $limit)
            ),
            'recent_offline' => array_map(
                static fn (array $row): array => self::publicInterfaceView($row, false),
                $this->recentNodeInterfacesByStatus('offline', $limit)
            ),
        ];
    }

    /**
     * The only interface fields a public report (/health, /v1/monitor and
     * /v1/monitor/data, and /debug where debug.enabled is set) may carry. An
     * allowlist, never a denylist: a field or metadata key that is not named
     * here does not leave the node, whatever a client puts in its
     * registration. Which rows a report lists is the caller's choice: /health
     * lists only nodes and gateways (recentNodeInterfacesByStatus()).
     *
     * Until 2026-09-30 the whole metadata_json went out. For a PHP peer that
     * is its registration body, whose peer_interface_id + peer_session_token
     * are the credentials exchangeWithPhpPeer() presents to the other node's
     * /v1/interfaces/exchange, and /v1/monitor also listed the
     * peer_session_token column; for a web client it is identity_hash, the
     * key registerInterface() re-binds a browser's row by. Both production
     * nodes published a peer_session_token this way.
     *
     * Kept because something reads them: interface_id, name, rx/tx and
     * last_seen_at (staging.sh status, e2e-local/start.sh,
     * OPNS-RNS-Post-Bridge/rnsd-redeploy.sh), metadata client and mode
     * (staging.sh, the bridge check in the gateway notes). peer_url only with
     * $withPeerUrl: the monitor page labels PHP peers by it, and /debug
     * shares the view; /health never carries it.
     * Pinned by tests/health_allowlist_test.php.
     */
    public static function publicInterfaceView(array $row, bool $withPeerUrl): array
    {
        $fields = ['interface_id', 'name', 'bitrate', 'mtu', 'status', 'created_at', 'last_seen_at',
                   'rx_packets', 'rx_bytes', 'tx_packets', 'tx_bytes'];
        if ($withPeerUrl) {
            $fields[] = 'peer_url';
        }
        $view = [];
        foreach ($fields as $field) {
            if (array_key_exists($field, $row)) {
                $view[$field] = $row[$field];
            }
        }

        $metadata = is_array($row['metadata'] ?? null) ? $row['metadata'] : [];
        $publicMetadata = [];
        foreach (['client', 'implementation', 'mode', 'transport'] as $key) {
            $value = $metadata[$key] ?? null;
            if (is_string($value) || is_int($value)) {
                $publicMetadata[$key] = $value;
            }
        }
        // An object even when empty: readers call .get() on it.
        $view['metadata'] = (object) $publicMetadata;

        return $view;
    }

    public function recentInboundPackets(int $limit): array
    {
        $stmt = $this->db->prepare(
            'SELECT
                interface_id,
                batch_id,
                packet_index,
                status,
                error_message,
                packet_hash_hex,
                truncated_hash_hex,
                packet_size,
                ifac_flag,
                header_type,
                transport_type,
                destination_type,
                packet_type,
                context_flag,
                hops,
                context,
                transport_id_hex,
                destination_hash_hex,
                     filter_status,
                     filter_reason,
                     announce_status,
                     announce_reason,
                created_at
             FROM inbound_packets
             ORDER BY packet_record_id DESC
             LIMIT :limit'
        );
        $stmt->bindValue(':limit', $limit, PDO::PARAM_INT);
        $stmt->execute();

        $packets = [];
        while (($row = $stmt->fetch(PDO::FETCH_ASSOC)) !== false) {
            $packets[] = $row;
        }

        return $packets;
    }

    public function recentPathEntries(int $limit): array
    {
        $stmt = $this->db->prepare(
            'SELECT destination_hash_hex, next_hop_hex, hops, expires_at, random_blobs_json, interface_id, packet_hash_hex, announce_emitted, updated_at
             FROM path_entries
             ORDER BY updated_at DESC
             LIMIT :limit'
        );
        $stmt->bindValue(':limit', $limit, PDO::PARAM_INT);
        $stmt->execute();

        $paths = [];
        while (($row = $stmt->fetch(PDO::FETCH_ASSOC)) !== false) {
            $paths[] = $row;
        }

        return $paths;
    }

    public function recentInterfaces(int $limit): array
    {
        $stmt = $this->db->prepare(
            'SELECT
                interface_id,
                name,
                bitrate,
                mtu,
                status,
                metadata_json,
                peer_url,
                peer_interface_id,
                peer_session_token,
                created_at,
                last_seen_at,
                rx_packets,
                rx_bytes,
                tx_packets,
                tx_bytes
             FROM interfaces
             ORDER BY last_seen_at DESC, created_at DESC
             LIMIT :limit'
        );
        $stmt->bindValue(':limit', $limit, PDO::PARAM_INT);
        $stmt->execute();

        $interfaces = [];
        while (($row = $stmt->fetch(PDO::FETCH_ASSOC)) !== false) {
            if (!is_array($row)) {
                continue;
            }

            $row['metadata'] = self::decodeJson((string) ($row['metadata_json'] ?? '{}'));
            unset($row['metadata_json']);
            $interfaces[] = $row;
        }

        return $interfaces;
    }

    /**
     * The clients /health lists one row at a time: other nodes and gateways.
     * 'reticulum-php' is a PHP peer, or a gateway bridge in wake mode;
     * 'rns-post-interface' is a gateway in poll mode (Reticulum-rust and
     * python/ PostInterface register_with_remote). Browsers ('rns-js') and
     * any client not named here are only counted.
     */
    public const HEALTH_LISTED_CLIENTS = ['reticulum-php', 'rns-post-interface'];

    /**
     * The most recently seen node and gateway rows with this status. Only
     * HEALTH_LISTED_CLIENTS; browsers never appear here.
     *
     * A browser's row keeps its interface_id for as long as the identity
     * re-registers (registerInterface() re-binds by identity_hash), and
     * created_at and the rx/tx counters with it, so listing browser rows on the
     * public /health published when each Retichat identity was online, under a
     * stable pseudonym, even with identity_hash gone. Nothing reads browser
     * rows there (the consumers named at publicInterfaceView() read the bridge
     * and peer rows); the summary still counts every row. Selecting nodes in
     * SQL also stops five busy browsers from pushing the bridge out of
     * recent_online, which rnsd-redeploy.sh reads the bridge's id from.
     */
    public function recentNodeInterfacesByStatus(string $status, int $limit): array
    {
        // The LIKE only narrows the scan to poll-mode gateways; the client is
        // checked exactly below. encodeJson() writes "key":"value" with no
        // spaces, and the value holds no character LIKE or json_encode treats
        // specially.
        $stmt = $this->db->prepare(
            'SELECT
                interface_id,
                name,
                bitrate,
                mtu,
                status,
                metadata_json,
                created_at,
                last_seen_at,
                rx_packets,
                rx_bytes,
                tx_packets,
                tx_bytes
             FROM interfaces
             WHERE status = :status
               AND (peer_url IS NOT NULL OR metadata_json LIKE :poll_gateway)
             ORDER BY last_seen_at DESC, created_at DESC
             LIMIT :limit'
        );
        $stmt->bindValue(':status', $status, PDO::PARAM_STR);
        $stmt->bindValue(':poll_gateway', '%"client":"rns-post-interface"%', PDO::PARAM_STR);
        $stmt->bindValue(':limit', $limit, PDO::PARAM_INT);
        $stmt->execute();

        $interfaces = [];
        while (($row = $stmt->fetch(PDO::FETCH_ASSOC)) !== false) {
            if (!is_array($row)) {
                continue;
            }

            $row['metadata'] = self::decodeJson((string) ($row['metadata_json'] ?? '{}'));
            unset($row['metadata_json']);
            if (!in_array($row['metadata']['client'] ?? null, self::HEALTH_LISTED_CLIENTS, true)) {
                continue;
            }
            $interfaces[] = $row;
        }

        return $interfaces;
    }

    public function recentInboundBatches(int $limit): array
    {
        $stmt = $this->db->prepare(
            'SELECT
                interface_id,
                batch_id,
                packet_count,
                byte_count,
                created_at,
                processed_at,
                processing_summary_json
             FROM inbound_batches
             ORDER BY created_at DESC
             LIMIT :limit'
        );
        $stmt->bindValue(':limit', $limit, PDO::PARAM_INT);
        $stmt->execute();

        $batches = [];
        while (($row = $stmt->fetch(PDO::FETCH_ASSOC)) !== false) {
            if (!is_array($row)) {
                continue;
            }

            $row['processing_summary'] = isset($row['processing_summary_json']) && is_string($row['processing_summary_json'])
                ? self::decodeJson($row['processing_summary_json'])
                : null;
            unset($row['processing_summary_json']);
            $batches[] = $row;
        }

        return $batches;
    }

    public function recentOutboundPackets(int $limit): array
    {
        $stmt = $this->db->prepare(
            'SELECT
                packet_id,
                interface_id,
                packet_hash_hex,
                proof_destination_hash_hex,
                destination_hash_hex,
                queue_reason,
                queued_at,
                delivered_at,
                delivered_batch_id,
                acked_at,
                proofed_at
             FROM outbound_packets
             ORDER BY packet_id DESC
             LIMIT :limit'
        );
        $stmt->bindValue(':limit', $limit, PDO::PARAM_INT);
        $stmt->execute();

        $packets = [];
        while (($row = $stmt->fetch(PDO::FETCH_ASSOC)) !== false) {
            if (!is_array($row)) {
                continue;
            }

            $packets[] = $row;
        }

        return $packets;
    }

    public function recentOutboundBatches(int $limit): array
    {
        $stmt = $this->db->prepare(
            'SELECT
                interface_id,
                batch_id,
                packet_ids_json,
                created_at,
                acked_at
             FROM outbound_batches
             ORDER BY created_at DESC
             LIMIT :limit'
        );
        $stmt->bindValue(':limit', $limit, PDO::PARAM_INT);
        $stmt->execute();

        $batches = [];
        while (($row = $stmt->fetch(PDO::FETCH_ASSOC)) !== false) {
            if (!is_array($row)) {
                continue;
            }

            $row['packet_ids'] = self::decodeJson((string) ($row['packet_ids_json'] ?? '[]'));
            unset($row['packet_ids_json']);
            $batches[] = $row;
        }

        return $batches;
    }

    public function recentWakeEvents(int $limit): array
    {
        $stmt = $this->db->prepare(
            'SELECT
                wake_event_id,
                interface_id,
                wake_profile,
                wake_target,
                wake_data_json,
                queue_reason,
                queued_packet_count,
                created_at,
                dispatched_at,
                failed_at,
                failure_message
             FROM wake_events
             ORDER BY wake_event_id DESC
             LIMIT :limit'
        );
        $stmt->bindValue(':limit', $limit, PDO::PARAM_INT);
        $stmt->execute();

        $events = [];
        while (($row = $stmt->fetch(PDO::FETCH_ASSOC)) !== false) {
            if (!is_array($row)) {
                continue;
            }

            $row['wake_data'] = self::decodeJson((string) ($row['wake_data_json'] ?? '{}'));
            unset($row['wake_data_json']);
            $events[] = $row;
        }

        return $events;
    }

    public function debugReport(int $limit): array
    {
        $limit = max(1, $limit);

        // /debug is public whenever debug.enabled is set, so its interface
        // rows get the same allowlist as /health and the monitor.
        return [
            'recent_interfaces' => array_map(
                static fn (array $row): array => self::publicInterfaceView($row, true),
                $this->recentInterfaces($limit)
            ),
            'recent_inbound_batches' => $this->recentInboundBatches($limit),
            'recent_inbound_packets' => $this->recentInboundPackets($limit),
            'recent_path_entries' => $this->recentPathEntries($limit),
            'recent_outbound_packets' => $this->recentOutboundPackets($limit),
            'recent_outbound_batches' => $this->recentOutboundBatches($limit),
            'recent_wake_events' => $this->recentWakeEvents($limit),
        ];
    }

    private function countByQuery(string $query): int
    {
        $result = $this->db->query($query);
        $row = $result->fetch(PDO::FETCH_NUM);
        return (int) ($row[0] ?? 0);
    }

    public function monitorData(): array
    {
        return [
            'interfaces' => array_map(
                static fn (array $row): array => self::publicInterfaceView($row, true),
                $this->recentInterfaces(50)
            ),
            'outbound_pending' => $this->pendingOutboundByInterface(),
            'recent_inbound' => $this->recentInboundPackets(20),
            'recent_outbound' => $this->recentOutboundPackets(20),
            'recent_batches' => $this->recentInboundBatches(10),
        ];
    }

    private function pendingOutboundByInterface(): array
    {
        $stmt = $this->db->prepare(
            'SELECT i.name, i.interface_id, i.peer_url,
                    COUNT(op.packet_id) AS pending,
                    MIN(op.queued_at) AS oldest_queued_at
             FROM interfaces i
             LEFT JOIN outbound_packets op ON op.interface_id = i.interface_id AND op.acked_at IS NULL
             GROUP BY i.interface_id
             HAVING pending > 0
             ORDER BY pending DESC'
        );
        $stmt->execute();

        $rows = [];
        while (($row = $stmt->fetch(PDO::FETCH_ASSOC)) !== false) {
            if (is_array($row)) {
                $rows[] = $row;
            }
        }

        return $rows;
    }

    public function clearAllData(): void
    {
        $tables = [
            'inbound_packets', 'inbound_batches',
            'outbound_packets', 'outbound_batches',
            'packet_hashes', 'path_request_tags',
            'reverse_path_entries', 'link_transport_entries',
            'path_entries', 'known_destinations', 'local_destinations',
            'wake_events', 'php_peer_sessions', 'post_interface_peers',
            'transport_state',
            'interfaces',
        ];
        foreach ($tables as $table) {
            $this->db->exec("DELETE FROM {$table}");
        }
    }
}