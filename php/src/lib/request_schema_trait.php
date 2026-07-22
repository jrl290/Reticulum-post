<?php

declare(strict_types=1);

namespace ReticulumPhp;

use PDO;
use PDOException;

/**
 * RequestSchemaTrait — idempotent schema migration.
 *
 * Run on every /v1/initialize. Brings the database schema up to date
 * regardless of what state it's in:
 *   1. CREATE TABLE IF NOT EXISTS for new deployments
 *   2. ALTER TABLE ADD COLUMN for columns added after initial deploy
 *   3. CREATE INDEX for deadlock-prevention covering indexes
 *
 * Every step is wrapped in try/catch so a partially-migrated database
 * doesn't block the rest of the migration.
 */

trait RequestSchemaTrait
{
    public function migrate(): array
    {
        $summary = [
            'tables_created' => 0,
            'columns_added'  => 0,
            'indexes_added'  => 0,
            'errors'         => [],
        ];

        $this->ensureTables($summary);
        $this->ensureColumns($summary);
        $this->ensureIndexes($summary);

        return $summary;
    }

    private function ensureTables(array &$summary): void
    {
        $engine = $this->backend === 'mysql'
            ? ' ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci'
            : '';

        $tables = [
            'interfaces' => "
                CREATE TABLE IF NOT EXISTS interfaces (
                    interface_id VARCHAR(64) NOT NULL,
                    name VARCHAR(255) NOT NULL,
                    session_token VARCHAR(128) DEFAULT NULL,
                    bitrate INT NOT NULL DEFAULT 0,
                    mtu INT NOT NULL DEFAULT 500,
                    status VARCHAR(16) NOT NULL DEFAULT 'online',
                    metadata_json TEXT,
                    created_at INT NOT NULL DEFAULT 0,
                    last_seen_at INT NOT NULL DEFAULT 0,
                    rx_packets BIGINT NOT NULL DEFAULT 0,
                    rx_bytes BIGINT NOT NULL DEFAULT 0,
                    tx_packets BIGINT NOT NULL DEFAULT 0,
                    tx_bytes BIGINT NOT NULL DEFAULT 0,
                    peer_url VARCHAR(512) DEFAULT NULL,
                    peer_interface_id VARCHAR(64) DEFAULT NULL,
                    peer_session_token VARCHAR(128) DEFAULT NULL,
                    last_wake_sent_at INT NOT NULL DEFAULT 0,
                    pending_ack_batch_ids_json TEXT,
                    wake_failure_count INT NOT NULL DEFAULT 0,
                    wake_backoff_until INT NOT NULL DEFAULT 0,
                    updated_at INT NOT NULL DEFAULT 0,
                    PRIMARY KEY (interface_id)
                ){$engine}",

            'inbound_batches' => "
                CREATE TABLE IF NOT EXISTS inbound_batches (
                    interface_id VARCHAR(64) NOT NULL,
                    batch_id VARCHAR(128) NOT NULL,
                    packet_count INT NOT NULL DEFAULT 0,
                    byte_count INT NOT NULL DEFAULT 0,
                    payload_json LONGTEXT,
                    created_at INT NOT NULL DEFAULT 0,
                    processed_at INT DEFAULT NULL,
                    processing_summary_json TEXT,
                    PRIMARY KEY (interface_id, batch_id)
                ){$engine}",

            'inbound_packets' => "
                CREATE TABLE IF NOT EXISTS inbound_packets (
                    packet_record_id BIGINT AUTO_INCREMENT PRIMARY KEY,
                    interface_id VARCHAR(64) NOT NULL,
                    batch_id VARCHAR(128) NOT NULL,
                    packet_index INT NOT NULL DEFAULT 0,
                    status VARCHAR(32) NOT NULL DEFAULT 'pending',
                    error_message TEXT,
                    packet_hash_hex VARCHAR(64),
                    truncated_hash_hex VARCHAR(32),
                    raw_base64 TEXT,
                    packet_size INT NOT NULL DEFAULT 0,
                    ifac_flag TINYINT NOT NULL DEFAULT 0,
                    header_type TINYINT,
                    transport_type TINYINT,
                    destination_type TINYINT,
                    packet_type TINYINT,
                    context_flag TINYINT,
                    hops INT,
                    context INT,
                    transport_id_hex VARCHAR(32),
                    destination_hash_hex VARCHAR(64),
                    payload_base64 LONGTEXT,
                    created_at INT NOT NULL DEFAULT 0,
                    filter_status VARCHAR(32),
                    filter_reason VARCHAR(128),
                    announce_status VARCHAR(32),
                    announce_reason VARCHAR(128)
                ){$engine}",

            'outbound_batches' => "
                CREATE TABLE IF NOT EXISTS outbound_batches (
                    interface_id VARCHAR(64) NOT NULL,
                    batch_id VARCHAR(128) NOT NULL,
                    packet_ids_json TEXT,
                    created_at INT NOT NULL DEFAULT 0,
                    acked_at INT DEFAULT NULL,
                    PRIMARY KEY (interface_id, batch_id)
                ){$engine}",

            'outbound_packets' => "
                CREATE TABLE IF NOT EXISTS outbound_packets (
                    packet_id BIGINT AUTO_INCREMENT PRIMARY KEY,
                    interface_id VARCHAR(64) NOT NULL,
                    packet_hash_hex VARCHAR(64),
                    proof_destination_hash_hex VARCHAR(32),
                    destination_hash_hex VARCHAR(64),
                    destination_public_key_hex VARCHAR(64),
                    packet_base64 LONGTEXT NOT NULL,
                    queued_at INT NOT NULL DEFAULT 0,
                    delivered_at INT DEFAULT NULL,
                    delivered_batch_id VARCHAR(128) DEFAULT NULL,
                    acked_at INT DEFAULT NULL,
                    proofed_at INT DEFAULT NULL,
                    queue_reason VARCHAR(64) NOT NULL DEFAULT 'unknown'
                ){$engine}",

            'packet_hashes' => "
                CREATE TABLE IF NOT EXISTS packet_hashes (
                    packet_hash_hex VARCHAR(64) NOT NULL,
                    first_seen_at INT NOT NULL DEFAULT 0,
                    PRIMARY KEY (packet_hash_hex)
                ){$engine}",

            'path_request_tags' => "
                CREATE TABLE IF NOT EXISTS path_request_tags (
                    tag_key_hex VARCHAR(32) NOT NULL,
                    created_at INT NOT NULL DEFAULT 0,
                    PRIMARY KEY (tag_key_hex)
                ){$engine}",

            'reverse_path_entries' => "
                CREATE TABLE IF NOT EXISTS reverse_path_entries (
                    truncated_hash_hex VARCHAR(32) NOT NULL,
                    received_interface_id VARCHAR(64) NOT NULL,
                    outbound_interface_id VARCHAR(64) NOT NULL,
                    created_at INT NOT NULL DEFAULT 0,
                    PRIMARY KEY (truncated_hash_hex, outbound_interface_id)
                ){$engine}",

            'link_transport_entries' => "
                CREATE TABLE IF NOT EXISTS link_transport_entries (
                    link_id_hex VARCHAR(64) NOT NULL,
                    received_interface_id VARCHAR(64) NOT NULL,
                    outbound_interface_id VARCHAR(64) NOT NULL,
                    next_hop_hex VARCHAR(32) NOT NULL,
                    remaining_hops INT NOT NULL DEFAULT 0,
                    taken_hops INT NOT NULL DEFAULT 0,
                    destination_hash_hex VARCHAR(64) NOT NULL,
                    validated TINYINT NOT NULL DEFAULT 0,
                    proof_expires_at INT DEFAULT NULL,
                    updated_at INT NOT NULL DEFAULT 0,
                    PRIMARY KEY (link_id_hex, outbound_interface_id)
                ){$engine}",

            'path_entries' => "
                CREATE TABLE IF NOT EXISTS path_entries (
                    destination_hash_hex VARCHAR(64) NOT NULL,
                    next_hop_hex VARCHAR(32) DEFAULT NULL,
                    hops INT NOT NULL DEFAULT 0,
                    expires_at INT NOT NULL DEFAULT 0,
                    random_blobs_json TEXT,
                    interface_id VARCHAR(64) NOT NULL,
                    packet_hash_hex VARCHAR(64) DEFAULT NULL,
                    announce_emitted INT NOT NULL DEFAULT 0,
                    updated_at INT NOT NULL DEFAULT 0,
                    PRIMARY KEY (destination_hash_hex, interface_id)
                ){$engine}",

            'known_destinations' => "
                CREATE TABLE IF NOT EXISTS known_destinations (
                    destination_hash_hex VARCHAR(64) NOT NULL,
                    packet_hash_hex VARCHAR(64) DEFAULT NULL,
                    public_key_hex VARCHAR(64) DEFAULT NULL,
                    identity_hash_hex VARCHAR(64) DEFAULT NULL,
                    app_data_base64 TEXT,
                    ratchet_hex VARCHAR(128) DEFAULT NULL,
                    updated_at INT NOT NULL DEFAULT 0,
                    PRIMARY KEY (destination_hash_hex)
                ){$engine}",

            'local_destinations' => "
                CREATE TABLE IF NOT EXISTS local_destinations (
                    destination_hash_hex VARCHAR(64) NOT NULL,
                    interface_id VARCHAR(64) NOT NULL,
                    registered_at INT NOT NULL DEFAULT 0,
                    PRIMARY KEY (destination_hash_hex)
                ){$engine}",

            'wake_events' => "
                CREATE TABLE IF NOT EXISTS wake_events (
                    wake_event_id BIGINT AUTO_INCREMENT PRIMARY KEY,
                    interface_id VARCHAR(64) NOT NULL DEFAULT '',
                    wake_profile VARCHAR(64) DEFAULT NULL,
                    wake_target VARCHAR(512) DEFAULT NULL,
                    wake_data_json TEXT,
                    queue_reason VARCHAR(64) DEFAULT NULL,
                    queued_packet_count INT NOT NULL DEFAULT 0,
                    created_at INT NOT NULL DEFAULT 0,
                    dispatched_at INT DEFAULT NULL,
                    failed_at INT DEFAULT NULL,
                    dispatch_result_json TEXT,
                    failure_message TEXT,
                    claimed_at INT DEFAULT NULL,
                    claimed_by_pid INT DEFAULT NULL
                ){$engine}",

            'php_peer_sessions' => "
                CREATE TABLE IF NOT EXISTS php_peer_sessions (
                    peer_name VARCHAR(128) NOT NULL DEFAULT '',
                    local_interface_id VARCHAR(64) NOT NULL,
                    local_session_token VARCHAR(128) DEFAULT NULL,
                    remote_url VARCHAR(512) NOT NULL,
                    updated_at INT NOT NULL DEFAULT 0,
                    PRIMARY KEY (local_interface_id, remote_url)
                ){$engine}",

            'post_interface_peers' => "
                CREATE TABLE IF NOT EXISTS post_interface_peers (
                    peer_id BIGINT AUTO_INCREMENT PRIMARY KEY,
                    name VARCHAR(255) NOT NULL DEFAULT '',
                    local_interface_id VARCHAR(64) NOT NULL,
                    remote_node_url VARCHAR(512) DEFAULT NULL,
                    local_wake_url VARCHAR(512) DEFAULT NULL,
                    remote_interface_id VARCHAR(64) DEFAULT NULL,
                    remote_session_token VARCHAR(128) DEFAULT NULL,
                    remote_max_batch_packets INT NOT NULL DEFAULT 64,
                    remote_idle_exchange_interval_ms INT NOT NULL DEFAULT 1000,
                    remote_max_packet_bytes INT NOT NULL DEFAULT 512,
                    bitrate INT NOT NULL DEFAULT 1000000,
                    mtu INT NOT NULL DEFAULT 500,
                    poll_interval_seconds INT NOT NULL DEFAULT 10,
                    http_timeout_seconds INT NOT NULL DEFAULT 10,
                    connect_timeout_seconds INT NOT NULL DEFAULT 5,
                    registered_at INT NOT NULL DEFAULT 0,
                    last_exchange_at INT DEFAULT NULL,
                    last_error_message TEXT,
                    status VARCHAR(32) NOT NULL DEFAULT 'offline'
                ){$engine}",

            'transport_state' => "
                CREATE TABLE IF NOT EXISTS transport_state (
                    state_key VARCHAR(128) NOT NULL,
                    state_value TEXT,
                    updated_at INT NOT NULL DEFAULT 0,
                    PRIMARY KEY (state_key)
                ){$engine}",
        ];

        foreach ($tables as $name => $sql) {
            try {
                $this->db->exec($sql);
                $summary['tables_created']++;
            } catch (PDOException $e) {
                $code = (int) ($e->errorInfo[1] ?? 0);
                if ($code !== 1050 && !str_contains($e->getMessage(), 'already exists')) {
                    $summary['errors'][] = "create_table {$name}: " . $e->getMessage();
                }
            }
        }
    }

    private function ensureColumns(array &$summary): void
    {
        $additions = [
            ['interfaces', 'updated_at', 'INT NOT NULL DEFAULT 0', 'wake_backoff_until'],
            ['interfaces', 'pending_ack_batch_ids_json', 'TEXT', 'last_wake_sent_at'],
            ['interfaces', 'wake_failure_count', 'INT NOT NULL DEFAULT 0', 'pending_ack_batch_ids_json'],
            ['interfaces', 'wake_backoff_until', 'INT NOT NULL DEFAULT 0', 'wake_failure_count'],
            ['interfaces', 'last_wake_sent_at', 'INT NOT NULL DEFAULT 0', 'tx_bytes'],
            ['interfaces', 'peer_url', 'VARCHAR(512) DEFAULT NULL', 'tx_bytes'],
            ['interfaces', 'peer_interface_id', 'VARCHAR(64) DEFAULT NULL', 'peer_url'],
            ['interfaces', 'peer_session_token', 'VARCHAR(128) DEFAULT NULL', 'peer_interface_id'],
            ['inbound_batches', 'processing_summary_json', 'TEXT', 'processed_at'],
            ['outbound_batches', 'acked_at', 'INT DEFAULT NULL', 'created_at'],
            ['outbound_packets', 'queue_reason', "VARCHAR(64) NOT NULL DEFAULT 'unknown'", 'acked_at'],
            ['outbound_packets', 'proof_destination_hash_hex', 'VARCHAR(32)', 'packet_hash_hex'],
            ['inbound_packets', 'filter_status', 'VARCHAR(32)', 'created_at'],
            ['inbound_packets', 'filter_reason', 'VARCHAR(128)', 'filter_status'],
            ['inbound_packets', 'announce_status', 'VARCHAR(32)', 'filter_reason'],
            ['inbound_packets', 'announce_reason', 'VARCHAR(128)', 'announce_status'],
        ];

        foreach ($additions as [$table, $column, $definition, $after]) {
            try {
                $sql = "ALTER TABLE `{$table}` ADD COLUMN `{$column}` {$definition}";
                if ($after !== null && $after !== '') {
                    $sql .= " AFTER `{$after}`";
                }
                $this->db->exec($sql);
                $summary['columns_added']++;
            } catch (PDOException $e) {
                $code = (int) ($e->errorInfo[1] ?? 0);
                if ($code !== 1060 && $code !== 1146) {
                    $summary['errors'][] = "add_column {$table}.{$column}: " . $e->getMessage();
                }
            }
        }
    }

    private function ensureIndexes(array &$summary): void
    {
        $indexes = [
            // Maintenance DELETE covering indexes (deadlock prevention)
            'CREATE INDEX idx_packet_hashes_seen ON packet_hashes (first_seen_at)',
            'CREATE INDEX idx_inbound_batches_created ON inbound_batches (created_at)',
            'CREATE INDEX idx_inbound_batches_unprocessed ON inbound_batches (processed_at)',
            'CREATE INDEX idx_outbound_batches_created ON outbound_batches (created_at)',
            'CREATE INDEX idx_path_request_tags_created ON path_request_tags (created_at)',
            'CREATE INDEX idx_reverse_path_created ON reverse_path_entries (created_at)',
            'CREATE INDEX idx_link_transport_updated ON link_transport_entries (updated_at)',
            'CREATE INDEX idx_wake_events_created ON wake_events (created_at)',
            // Exchange hot-path indexes
            'CREATE INDEX idx_interfaces_status ON interfaces (status, last_seen_at)',
            'CREATE INDEX idx_outbound_packets_acked ON outbound_packets (acked_at)',
            'CREATE INDEX idx_outbound_packets_delivered_batch ON outbound_packets (delivered_batch_id)',
            'CREATE INDEX idx_reverse_path_outbound ON reverse_path_entries (outbound_interface_id)',
            'CREATE INDEX idx_inbound_packets_batch ON inbound_packets (interface_id, batch_id)',
            'CREATE INDEX idx_link_transport_validated ON link_transport_entries (validated, updated_at)',
            'CREATE INDEX idx_path_entries_expires ON path_entries (expires_at)',
            'CREATE INDEX idx_interfaces_peer_url ON interfaces (peer_url)',
            'CREATE INDEX idx_known_dest_identity ON known_destinations (identity_hash_hex)',
            'CREATE INDEX idx_local_dest_iface ON local_destinations (interface_id)',
            'CREATE INDEX idx_wake_events_pending ON wake_events (status, created_at)',
            'CREATE INDEX idx_outbound_packets_queued ON outbound_packets (queued_at)',
        ];

        foreach ($indexes as $sql) {
            try {
                $this->db->exec($sql);
                $summary['indexes_added']++;
            } catch (PDOException $e) {
                $code = (int) ($e->errorInfo[1] ?? 0);
                if (!in_array($code, [1061, 1072, 1146], true)
                    && !str_contains($e->getMessage(), 'already exists')) {
                    $summary['errors'][] = "create_index: " . $e->getMessage();
                }
            }
        }
    }
}
