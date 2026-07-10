<?php

declare(strict_types=1);

namespace ReticulumPhp;

// Reticulum-php is request-operated. These reporting helpers expose request
// path state for /health and /debug inspection only; they do not alter packet
// flow or create a second transport mechanism.

trait RequestDebugReportTrait
{
    public function healthSummary(): array
    {
        return [
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
            'recent_online' => $this->recentInterfacesByStatus('online', $limit),
            'recent_offline' => $this->recentInterfacesByStatus('offline', $limit),
        ];
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
        $stmt->bindValue(':limit', $limit, SQLITE3_INTEGER);
        $result = $stmt->execute();

        $packets = [];
        while (($row = $result->fetchArray(SQLITE3_ASSOC)) !== false) {
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
        $stmt->bindValue(':limit', $limit, SQLITE3_INTEGER);
        $result = $stmt->execute();

        $paths = [];
        while (($row = $result->fetchArray(SQLITE3_ASSOC)) !== false) {
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
        $stmt->bindValue(':limit', $limit, SQLITE3_INTEGER);
        $result = $stmt->execute();

        $interfaces = [];
        while (($row = $result->fetchArray(SQLITE3_ASSOC)) !== false) {
            if (!is_array($row)) {
                continue;
            }

            $row['metadata'] = self::decodeJson((string) ($row['metadata_json'] ?? '{}'));
            unset($row['metadata_json']);
            $interfaces[] = $row;
        }

        return $interfaces;
    }

    public function recentInterfacesByStatus(string $status, int $limit): array
    {
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
             ORDER BY last_seen_at DESC, created_at DESC
             LIMIT :limit'
        );
        $stmt->bindValue(':status', $status, SQLITE3_TEXT);
        $stmt->bindValue(':limit', $limit, SQLITE3_INTEGER);
        $result = $stmt->execute();

        $interfaces = [];
        while (($row = $result->fetchArray(SQLITE3_ASSOC)) !== false) {
            if (!is_array($row)) {
                continue;
            }

            $row['metadata'] = self::decodeJson((string) ($row['metadata_json'] ?? '{}'));
            unset($row['metadata_json']);
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
        $stmt->bindValue(':limit', $limit, SQLITE3_INTEGER);
        $result = $stmt->execute();

        $batches = [];
        while (($row = $result->fetchArray(SQLITE3_ASSOC)) !== false) {
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
        $stmt->bindValue(':limit', $limit, SQLITE3_INTEGER);
        $result = $stmt->execute();

        $packets = [];
        while (($row = $result->fetchArray(SQLITE3_ASSOC)) !== false) {
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
        $stmt->bindValue(':limit', $limit, SQLITE3_INTEGER);
        $result = $stmt->execute();

        $batches = [];
        while (($row = $result->fetchArray(SQLITE3_ASSOC)) !== false) {
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
        $stmt->bindValue(':limit', $limit, SQLITE3_INTEGER);
        $result = $stmt->execute();

        $events = [];
        while (($row = $result->fetchArray(SQLITE3_ASSOC)) !== false) {
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

        return [
            'recent_interfaces' => $this->recentInterfaces($limit),
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
        /** @var SQLite3Result $result */
        $result = $this->db->query($query);
        $row = $result->fetchArray(SQLITE3_NUM);
        return (int) ($row[0] ?? 0);
    }

    public function monitorData(): array
    {
        return [
            'interfaces' => $this->recentInterfaces(50),
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
        $result = $stmt->execute();

        $rows = [];
        while (($row = $result->fetchArray(SQLITE3_ASSOC)) !== false) {
            if (is_array($row)) {
                $rows[] = $row;
            }
        }

        return $rows;
    }
}