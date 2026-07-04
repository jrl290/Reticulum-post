<?php

declare(strict_types=1);

namespace ReticulumPhp;

// Reticulum-php is request-operated. This schema bootstrap prepares the SQLite
// state that backs request/response exchanges; it does not introduce any
// alternate transport path.

trait RequestSchemaTrait
{
    private function maintenanceInt(string $field, int $default): int
    {
        $maintenance = $this->config['maintenance'] ?? $this->config['worker'] ?? [];
        return (int) ($maintenance[$field] ?? $default);
    }

    public function migrate(): void
    {
        $this->db->exec('PRAGMA journal_mode = WAL');
        $this->db->exec('PRAGMA foreign_keys = ON');
        $this->db->exec(
            'CREATE TABLE IF NOT EXISTS interfaces (
                interface_id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                session_token TEXT NOT NULL,
                bitrate INTEGER NOT NULL,
                mtu INTEGER NOT NULL,
                status TEXT NOT NULL,
                metadata_json TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                last_seen_at INTEGER NOT NULL,
                rx_packets INTEGER NOT NULL DEFAULT 0,
                rx_bytes INTEGER NOT NULL DEFAULT 0,
                tx_packets INTEGER NOT NULL DEFAULT 0,
                tx_bytes INTEGER NOT NULL DEFAULT 0
            )'
        );
        $this->db->exec(
            'CREATE TABLE IF NOT EXISTS inbound_batches (
                interface_id TEXT NOT NULL,
                batch_id TEXT NOT NULL,
                packet_count INTEGER NOT NULL,
                byte_count INTEGER NOT NULL,
                payload_json TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                PRIMARY KEY (interface_id, batch_id),
                FOREIGN KEY (interface_id) REFERENCES interfaces(interface_id) ON DELETE CASCADE
            )'
        );
        $this->ensureColumn('inbound_batches', 'processed_at', 'INTEGER');
        $this->ensureColumn('inbound_batches', 'processing_summary_json', 'TEXT');
        $this->db->exec(
            'CREATE TABLE IF NOT EXISTS inbound_packets (
                packet_record_id INTEGER PRIMARY KEY AUTOINCREMENT,
                interface_id TEXT NOT NULL,
                batch_id TEXT NOT NULL,
                packet_index INTEGER NOT NULL,
                status TEXT NOT NULL,
                error_message TEXT,
                packet_hash_hex TEXT,
                truncated_hash_hex TEXT,
                raw_base64 TEXT NOT NULL,
                packet_size INTEGER NOT NULL,
                ifac_flag INTEGER NOT NULL,
                header_type INTEGER,
                transport_type INTEGER,
                destination_type INTEGER,
                packet_type INTEGER,
                context_flag INTEGER,
                hops INTEGER,
                context INTEGER,
                transport_id_hex TEXT,
                destination_hash_hex TEXT,
                payload_base64 TEXT,
                created_at INTEGER NOT NULL,
                UNIQUE(interface_id, batch_id, packet_index),
                FOREIGN KEY (interface_id, batch_id) REFERENCES inbound_batches(interface_id, batch_id) ON DELETE CASCADE
            )'
        );
        $this->ensureColumn('inbound_packets', 'filter_status', 'TEXT');
        $this->ensureColumn('inbound_packets', 'filter_reason', 'TEXT');
        $this->ensureColumn('inbound_packets', 'announce_status', 'TEXT');
        $this->ensureColumn('inbound_packets', 'announce_reason', 'TEXT');
        $this->db->exec('CREATE INDEX IF NOT EXISTS idx_inbound_batches_unprocessed ON inbound_batches(processed_at, created_at)');
        $this->db->exec('CREATE INDEX IF NOT EXISTS idx_inbound_packets_status ON inbound_packets(status, created_at)');

        $this->db->exec(
            'CREATE TABLE IF NOT EXISTS packet_hashes (
                packet_hash_hex TEXT PRIMARY KEY,
                first_seen_at INTEGER NOT NULL
            )'
        );
        $this->db->exec(
            'CREATE TABLE IF NOT EXISTS known_destinations (
                destination_hash_hex TEXT PRIMARY KEY,
                packet_hash_hex TEXT NOT NULL,
                public_key_hex TEXT NOT NULL,
                identity_hash_hex TEXT NOT NULL,
                app_data_base64 TEXT,
                ratchet_hex TEXT,
                updated_at INTEGER NOT NULL
            )'
        );
        $this->db->exec(
            'CREATE TABLE IF NOT EXISTS path_entries (
                destination_hash_hex TEXT PRIMARY KEY,
                next_hop_hex TEXT NOT NULL,
                hops INTEGER NOT NULL,
                expires_at INTEGER NOT NULL,
                random_blobs_json TEXT NOT NULL,
                interface_id TEXT NOT NULL,
                packet_hash_hex TEXT NOT NULL,
                announce_emitted INTEGER NOT NULL,
                updated_at INTEGER NOT NULL,
                FOREIGN KEY (interface_id) REFERENCES interfaces(interface_id) ON DELETE CASCADE
            )'
        );
        $this->db->exec('CREATE INDEX IF NOT EXISTS idx_path_entries_expires ON path_entries(expires_at)');
        $this->db->exec('CREATE INDEX IF NOT EXISTS idx_known_destinations_updated ON known_destinations(updated_at)');
        $this->db->exec(
            'CREATE TABLE IF NOT EXISTS path_request_tags (
                tag_key_hex TEXT PRIMARY KEY,
                created_at INTEGER NOT NULL
            )'
        );
        $this->db->exec(
            'CREATE TABLE IF NOT EXISTS transport_state (
                state_key TEXT PRIMARY KEY,
                state_value TEXT NOT NULL,
                updated_at INTEGER NOT NULL
            )'
        );
        $this->db->exec(
            'CREATE TABLE IF NOT EXISTS reverse_path_entries (
                truncated_hash_hex TEXT NOT NULL,
                received_interface_id TEXT NOT NULL,
                outbound_interface_id TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                PRIMARY KEY (truncated_hash_hex, outbound_interface_id),
                FOREIGN KEY (received_interface_id) REFERENCES interfaces(interface_id) ON DELETE CASCADE,
                FOREIGN KEY (outbound_interface_id) REFERENCES interfaces(interface_id) ON DELETE CASCADE
            )'
        );
        $this->db->exec('CREATE INDEX IF NOT EXISTS idx_reverse_path_entries_created_at ON reverse_path_entries(created_at)');
        $this->db->exec(
            'CREATE TABLE IF NOT EXISTS link_transport_entries (
                link_id_hex TEXT NOT NULL,
                received_interface_id TEXT NOT NULL,
                outbound_interface_id TEXT NOT NULL,
                next_hop_hex TEXT NOT NULL,
                remaining_hops INTEGER NOT NULL,
                taken_hops INTEGER NOT NULL,
                destination_hash_hex TEXT NOT NULL,
                validated INTEGER NOT NULL,
                proof_expires_at INTEGER,
                updated_at INTEGER NOT NULL,
                PRIMARY KEY (link_id_hex, outbound_interface_id),
                FOREIGN KEY (received_interface_id) REFERENCES interfaces(interface_id) ON DELETE CASCADE,
                FOREIGN KEY (outbound_interface_id) REFERENCES interfaces(interface_id) ON DELETE CASCADE
            )'
        );
        $this->ensureColumn('link_transport_entries', 'proof_expires_at', 'INTEGER');
        $this->db->exec('CREATE INDEX IF NOT EXISTS idx_link_transport_entries_updated_at ON link_transport_entries(updated_at)');
        $this->db->exec('CREATE INDEX IF NOT EXISTS idx_link_transport_entries_pending_proof_expires_at ON link_transport_entries(validated, proof_expires_at)');
        $legacyLinkTransportTtl = $this->maintenanceInt('link_transport_ttl_seconds', 900);
        $this->db->exec(
            'UPDATE link_transport_entries
             SET proof_expires_at = updated_at + ' . $legacyLinkTransportTtl . '
             WHERE validated = 0 AND proof_expires_at IS NULL'
        );
        $this->db->exec(
            'CREATE TABLE IF NOT EXISTS outbound_packets (
                packet_id INTEGER PRIMARY KEY AUTOINCREMENT,
                interface_id TEXT NOT NULL,
                packet_hash_hex TEXT,
                proof_destination_hash_hex TEXT,
                destination_hash_hex TEXT,
                destination_public_key_hex TEXT,
                packet_base64 TEXT NOT NULL,
                queued_at INTEGER NOT NULL,
                delivered_at INTEGER,
                delivered_batch_id TEXT,
                acked_at INTEGER,
                proofed_at INTEGER,
                FOREIGN KEY (interface_id) REFERENCES interfaces(interface_id) ON DELETE CASCADE
            )'
        );
        $this->ensureColumn('outbound_packets', 'packet_hash_hex', 'TEXT');
        $this->ensureColumn('outbound_packets', 'proof_destination_hash_hex', 'TEXT');
        $this->ensureColumn('outbound_packets', 'destination_hash_hex', 'TEXT');
        $this->ensureColumn('outbound_packets', 'destination_public_key_hex', 'TEXT');
        $this->ensureColumn('outbound_packets', 'queue_reason', 'TEXT');
        $this->ensureColumn('outbound_packets', 'proofed_at', 'INTEGER');
        $this->db->exec(
            'CREATE TABLE IF NOT EXISTS outbound_batches (
                interface_id TEXT NOT NULL,
                batch_id TEXT NOT NULL,
                packet_ids_json TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                acked_at INTEGER,
                PRIMARY KEY (interface_id, batch_id),
                FOREIGN KEY (interface_id) REFERENCES interfaces(interface_id) ON DELETE CASCADE
            )'
        );
        $this->db->exec(
            'CREATE TABLE IF NOT EXISTS wake_events (
                wake_event_id INTEGER PRIMARY KEY AUTOINCREMENT,
                interface_id TEXT NOT NULL,
                wake_profile TEXT NOT NULL,
                wake_target TEXT NOT NULL,
                wake_data_json TEXT NOT NULL,
                queue_reason TEXT NOT NULL,
                queued_packet_count INTEGER NOT NULL,
                created_at INTEGER NOT NULL,
                dispatched_at INTEGER,
                failed_at INTEGER,
                dispatch_result_json TEXT,
                failure_message TEXT,
                FOREIGN KEY (interface_id) REFERENCES interfaces(interface_id) ON DELETE CASCADE
            )'
        );
        $this->ensureColumn('wake_events', 'dispatch_result_json', 'TEXT');
        $this->ensureColumn('wake_events', 'claimed_at', 'INTEGER');
        $this->ensureColumn('wake_events', 'claimed_by_pid', 'INTEGER');
        $this->db->exec('CREATE INDEX IF NOT EXISTS idx_outbound_packets_pending ON outbound_packets(interface_id, delivered_at, packet_id)');
        $this->db->exec('CREATE INDEX IF NOT EXISTS idx_outbound_packets_ack_state ON outbound_packets(interface_id, acked_at, delivered_batch_id, packet_id)');
        $this->db->exec('CREATE INDEX IF NOT EXISTS idx_outbound_packets_packet_hash ON outbound_packets(packet_hash_hex)');
        $this->db->exec('CREATE INDEX IF NOT EXISTS idx_outbound_packets_proof_destination ON outbound_packets(proof_destination_hash_hex, proofed_at, packet_id)');
        $this->db->exec('CREATE INDEX IF NOT EXISTS idx_wake_events_pending ON wake_events(dispatched_at, failed_at, created_at)');
        $this->db->exec('CREATE INDEX IF NOT EXISTS idx_wake_events_claimable ON wake_events(dispatched_at, failed_at, claimed_at, created_at)');
    }

    private function ensureColumn(string $table, string $column, string $definition): void
    {
        $result = $this->db->query(sprintf('PRAGMA table_info(%s)', $table));
        while (($row = $result->fetchArray(SQLITE3_ASSOC)) !== false) {
            if (($row['name'] ?? null) === $column) {
                return;
            }
        }

        $this->db->exec(sprintf('ALTER TABLE %s ADD COLUMN %s %s', $table, $column, $definition));
    }
}