-- The SQLite schema 50c870b's migrate() builds: the code both live PHP nodes
-- ran when Stage 1 was built (/health's build.commit on selectiv and on
-- retichat.com, read 2026-10-14), with the version that code records, the
-- SHA-1 of its request_schema_trait.php. Made by exporting 50c870b's php/src,
-- running Storage::migrateIfNeeded() on an empty SQLite file and dumping
-- sqlite_master. schema_migration_marker_test.php migrates it with this code.
--
-- Not a test: php/tests/stubs/ holds fixtures.
CREATE TABLE interfaces (
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
                );
CREATE TABLE inbound_batches (
                    interface_id VARCHAR(64) NOT NULL,
                    batch_id VARCHAR(128) NOT NULL,
                    packet_count INT NOT NULL DEFAULT 0,
                    byte_count INT NOT NULL DEFAULT 0,
                    payload_json LONGTEXT,
                    created_at INT NOT NULL DEFAULT 0,
                    processed_at INT DEFAULT NULL,
                    processing_summary_json TEXT,
                    PRIMARY KEY (interface_id, batch_id)
                );
CREATE TABLE inbound_packets (
                    packet_record_id INTEGER PRIMARY KEY AUTOINCREMENT,
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
                );
CREATE TABLE outbound_batches (
                    interface_id VARCHAR(64) NOT NULL,
                    batch_id VARCHAR(128) NOT NULL,
                    packet_ids_json TEXT,
                    created_at INT NOT NULL DEFAULT 0,
                    acked_at INT DEFAULT NULL,
                    PRIMARY KEY (interface_id, batch_id)
                );
CREATE TABLE outbound_packets (
                    packet_id INTEGER PRIMARY KEY AUTOINCREMENT,
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
                );
CREATE TABLE packet_hashes (
                    packet_hash_hex VARCHAR(64) NOT NULL,
                    first_seen_at INT NOT NULL DEFAULT 0,
                    PRIMARY KEY (packet_hash_hex)
                );
CREATE TABLE path_request_tags (
                    tag_key_hex VARCHAR(32) NOT NULL,
                    created_at INT NOT NULL DEFAULT 0,
                    PRIMARY KEY (tag_key_hex)
                );
CREATE TABLE path_request_throttle (
                    throttle_key VARCHAR(96) NOT NULL,
                    last_requested_at INT NOT NULL DEFAULT 0,
                    PRIMARY KEY (throttle_key)
                );
CREATE TABLE reverse_path_entries (
                    truncated_hash_hex VARCHAR(32) NOT NULL,
                    received_interface_id VARCHAR(64) NOT NULL,
                    outbound_interface_id VARCHAR(64) NOT NULL,
                    created_at INT NOT NULL DEFAULT 0,
                    PRIMARY KEY (truncated_hash_hex, outbound_interface_id)
                );
CREATE TABLE link_transport_entries (
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
                    PRIMARY KEY (link_id_hex, outbound_interface_id, remaining_hops)
                );
CREATE TABLE path_entries (
                    destination_hash_hex VARCHAR(64) NOT NULL,
                    next_hop_hex VARCHAR(32) DEFAULT NULL,
                    hops INT NOT NULL DEFAULT 0,
                    expires_at INT NOT NULL DEFAULT 0,
                    random_blobs_json TEXT,
                    interface_id VARCHAR(64) NOT NULL,
                    packet_hash_hex VARCHAR(64) DEFAULT NULL,
                    announce_emitted INT NOT NULL DEFAULT 0,
                    updated_at INT NOT NULL DEFAULT 0,
                    PRIMARY KEY (destination_hash_hex)
                );
CREATE TABLE known_destinations (
                    destination_hash_hex VARCHAR(64) NOT NULL,
                    packet_hash_hex VARCHAR(64) DEFAULT NULL,
                    public_key_hex VARCHAR(64) DEFAULT NULL,
                    identity_hash_hex VARCHAR(64) DEFAULT NULL,
                    app_data_base64 TEXT,
                    ratchet_hex VARCHAR(128) DEFAULT NULL,
                    updated_at INT NOT NULL DEFAULT 0,
                    PRIMARY KEY (destination_hash_hex)
                );
CREATE TABLE local_destinations (
                    destination_hash_hex VARCHAR(64) NOT NULL,
                    interface_id VARCHAR(64) NOT NULL,
                    registered_at INT NOT NULL DEFAULT 0,
                    PRIMARY KEY (destination_hash_hex)
                );
CREATE TABLE php_peer_sessions (
                    peer_name VARCHAR(128) NOT NULL DEFAULT '',
                    local_interface_id VARCHAR(64) NOT NULL,
                    local_session_token VARCHAR(128) DEFAULT NULL,
                    remote_url VARCHAR(512) NOT NULL,
                    updated_at INT NOT NULL DEFAULT 0,
                    PRIMARY KEY (local_interface_id, remote_url)
                );
CREATE TABLE transport_state (
                    state_key VARCHAR(128) NOT NULL,
                    state_value TEXT,
                    updated_at INT NOT NULL DEFAULT 0,
                    PRIMARY KEY (state_key)
                );
CREATE TABLE schema_meta (meta_key VARCHAR(32) NOT NULL, fingerprint VARCHAR(64) NOT NULL, applied_at INT NOT NULL, PRIMARY KEY (meta_key));
CREATE INDEX idx_packet_hashes_seen ON packet_hashes (first_seen_at);
CREATE INDEX idx_inbound_batches_created ON inbound_batches (created_at);
CREATE INDEX idx_inbound_batches_unprocessed ON inbound_batches (processed_at);
CREATE INDEX idx_inbound_packets_created ON inbound_packets (created_at);
CREATE INDEX idx_outbound_batches_created ON outbound_batches (created_at);
CREATE INDEX idx_path_request_tags_created ON path_request_tags (created_at);
CREATE INDEX idx_path_request_throttle_at ON path_request_throttle (last_requested_at);
CREATE INDEX idx_path_entries_packet_hash ON path_entries (packet_hash_hex);
CREATE INDEX idx_inbound_packets_hash ON inbound_packets (packet_hash_hex, created_at);
CREATE INDEX idx_reverse_path_created ON reverse_path_entries (created_at);
CREATE INDEX idx_link_transport_updated ON link_transport_entries (updated_at);
CREATE INDEX idx_interfaces_status ON interfaces (status, last_seen_at);
CREATE INDEX idx_outbound_packets_acked ON outbound_packets (acked_at);
CREATE INDEX idx_outbound_packets_delivered_batch ON outbound_packets (delivered_batch_id);
CREATE INDEX idx_reverse_path_outbound ON reverse_path_entries (outbound_interface_id);
CREATE INDEX idx_inbound_packets_batch ON inbound_packets (interface_id, batch_id);
CREATE INDEX idx_link_transport_validated ON link_transport_entries (validated, updated_at);
CREATE INDEX idx_path_entries_expires ON path_entries (expires_at);
CREATE INDEX idx_interfaces_peer_url ON interfaces (peer_url);
CREATE INDEX idx_known_dest_identity ON known_destinations (identity_hash_hex);
CREATE INDEX idx_local_dest_iface ON local_destinations (interface_id);
CREATE INDEX idx_outbound_packets_queued ON outbound_packets (queued_at);
INSERT INTO schema_meta (meta_key, fingerprint, applied_at) VALUES ('migration', '08783e676eaffc963b06f372247408bd7503c24a', 1760400000);
