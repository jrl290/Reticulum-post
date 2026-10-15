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
 * doesn't block the rest of the migration, except a statement that waits
 * out the lock wait ceiling, which stops it (migrate()).
 */

trait RequestSchemaTrait
{
    /**
     * Run migrate() only when this code's schema version is not the one
     * recorded against this database.
     *
     * Until 2026-09-24 migrate() ran inside every request: ~20 CREATE TABLE
     * IF NOT EXISTS, 24 CREATE INDEX attempts that each fail with "duplicate
     * key" on MySQL, plus column and primary-key probes — about 60 statements
     * per request before any packet was touched, ~800 plain SELECTs a second
     * on retichat.com. The version is kept in a one-row table inside the
     * database itself, so a recreated or restored database (staging wipes
     * its SQLite file) migrates again and the check costs one SELECT. The
     * /v1/initialize path still calls migrate() unconditionally, and on the
     * hosts deploy.sh runs it before the swap (`index.php migrate`), so the
     * request that records the version finds every object built.
     */
    public function migrateIfNeeded(): array
    {
        $version = $this->schemaVersion();
        if ($this->recordedSchemaFingerprint() === $version) {
            return ['skipped' => true];
        }
        $summary = $this->migrate();
        if ($summary['errors'] === []) {
            $this->recordSchemaFingerprint($version);
        }
        return $summary;
    }

    /**
     * REGISTRATION-STAGE1.md §12: the schema version, a literal the running
     * code carries (a method, since a trait constant needs PHP 8.2 and the
     * floor is 8.1). Raise it with every change to what migrate() builds;
     * tests/schema_migration_marker_test.php pins it together with the SHA-1
     * of this file with the literal masked, so a change here without a new
     * version fails.
     *
     * Until Stage 1 the recorded value was the SHA-1 of this file on disk,
     * which old code can record: for a moment after a swap opcache may still
     * run the old compiled trait, which hashed the new file, ran its own old
     * migrate(), succeeded and recorded the new file's hash, so the new code
     * never migrated. Old code records SHA-1 values, which never equal this
     * literal, so the next request of this code migrates.
     */
    private function schemaVersion(): string
    {
        return 'seed-once-1';
    }

    private function recordedSchemaFingerprint(): ?string
    {
        try {
            $stmt = $this->db->prepare('SELECT fingerprint FROM schema_meta WHERE meta_key = :k');
            $stmt->bindValue(':k', 'migration', PDO::PARAM_STR);
            $stmt->execute();
            $row = $stmt->fetch(PDO::FETCH_ASSOC);
            return is_array($row) && isset($row['fingerprint']) ? (string) $row['fingerprint'] : null;
        } catch (PDOException $e) {
            return null; // table missing: never migrated here
        }
    }

    /** After a clean migrate(), which built schema_meta: no DDL here. */
    private function recordSchemaFingerprint(string $fingerprint): void
    {
        try {
            $sql = $this->backend === 'mysql'
                ? 'INSERT INTO schema_meta (meta_key, fingerprint, applied_at) VALUES (:k, :f, :t) ON DUPLICATE KEY UPDATE fingerprint = VALUES(fingerprint), applied_at = VALUES(applied_at)'
                : 'INSERT INTO schema_meta (meta_key, fingerprint, applied_at) VALUES (:k, :f, :t) ON CONFLICT(meta_key) DO UPDATE SET fingerprint = excluded.fingerprint, applied_at = excluded.applied_at';
            $stmt = $this->db->prepare($sql);
            $stmt->bindValue(':k', 'migration', PDO::PARAM_STR);
            $stmt->bindValue(':f', $fingerprint, PDO::PARAM_STR);
            $stmt->bindValue(':t', time(), PDO::PARAM_INT);
            $stmt->execute();
        } catch (PDOException $e) {
            error_log('ReticulumPhp: could not record schema fingerprint: ' . $e->getMessage());
        }
    }

    /**
     * Build every missing object, idempotently. 'built' lists each table,
     * column and index this run created, with how long it took, for the
     * deploy step that runs this before the swap (index.php migrate).
     *
     * On MySQL and MariaDB every DDL statement runs with the session's
     * lock_wait_timeout at 2 s, read first and put back after, since a
     * request's connection gets here too (migrateIfNeeded(), and
     * /v1/initialize). The servers' default is a day. A DDL statement
     * waiting for its table's exclusive metadata lock queues every later
     * statement on that table behind it, so an ALTER waiting behind a DML
     * statement in its 50 s row lock wait would hang the live node's
     * registrations, exchanges and polls that long. Each statement is issued
     * once, never through executeWithRetry, and the first that waits out the
     * 2 s (1205) stops the migration: 'lock_wait_timeout' names it, it is
     * among the errors, so no version is recorded, and `index.php migrate`
     * exits non-zero, so deploy.sh stops before the swap.
     */
    public function migrate(): array
    {
        $summary = [
            'tables_created' => 0,
            'columns_added'  => 0,
            'indexes_added'  => 0,
            'built'          => [],
            'errors'         => [],
        ];

        $ceiling = $this->underDdlLockCeiling($summary, function () use (&$summary): void {
            $steps = [
                $this->ensureTables(...),
                $this->ensureColumns(...),
                $this->ensureColumnTypes(...),
                $this->ensurePrimaryKeys(...),
                $this->ensureIndexes(...),
            ];
            foreach ($steps as $step) {
                if (isset($summary['lock_wait_timeout'])) {
                    break;
                }
                $step($summary);
            }
        });
        if ($ceiling && !isset($summary['lock_wait_timeout'])) {
            $this->backfillClaimedIdentityHashes($summary);
        }
        // Also when a later statement stopped the migration: the next run
        // finds the column there and does not come back here.
        if ($ceiling && isset($summary['seeded_at_added'])) {
            $this->backfillSeededInterfaces($summary);
        }

        return $summary;
    }

    /**
     * Run $ddl, on MySQL and MariaDB with the session's lock_wait_timeout at
     * 2 s, and put the value it had back after, also when $ddl throws. When
     * that value cannot be read or set, $ddl does not run: false, with the
     * reason in $summary['errors']. SQLite has no metadata locks; its
     * busy_timeout bounds a wait for the file.
     */
    private function underDdlLockCeiling(array &$summary, callable $ddl): bool
    {
        if ($this->backend !== 'mysql') {
            $ddl();

            return true;
        }
        try {
            $read = $this->db->query('SELECT @@SESSION.lock_wait_timeout');
            $previous = $read === false ? false : $read->fetchColumn();
            if ($read !== false) {
                $read->closeCursor();
            }
            if (!is_numeric($previous) || (int) $previous < 1) {
                $summary['errors'][] = 'lock_wait_timeout: could not read the session value';

                return false;
            }
            $previous = (int) $previous;
            $this->db->exec('SET SESSION lock_wait_timeout = 2');
        } catch (PDOException $e) {
            $summary['errors'][] = 'lock_wait_timeout: ' . $e->getMessage();

            return false;
        }
        try {
            $ddl();
        } finally {
            try {
                $this->db->exec('SET SESSION lock_wait_timeout = ' . $previous);
            } catch (PDOException $e) {
                $summary['errors'][] = "lock_wait_timeout: could not put back {$previous}: " . $e->getMessage();
            }
        }

        return true;
    }

    /**
     * True when $e is a DDL statement that waited out the 2 s for its
     * table's metadata lock (1205), after recording it as $what in the
     * errors and as 'lock_wait_timeout': its caller issues nothing more, and
     * migrate() stops.
     */
    private static function lockWaitTimedOut(array &$summary, PDOException $e, string $what): bool
    {
        if ((int) ($e->errorInfo[1] ?? 0) !== 1205) {
            return false;
        }
        $summary['errors'][] = "{$what}: " . $e->getMessage();
        $summary['lock_wait_timeout'] = $what;

        return true;
    }

    /** One object this run built, for $summary['built']. */
    private static function noteBuilt(array &$summary, string $object, float $startedAt): void
    {
        $summary['built'][] = ['object' => $object, 'ms' => round((microtime(true) - $startedAt) * 1000, 1)];
    }

    private function ensureTables(array &$summary): void
    {
        $engine = $this->backend === 'mysql'
            ? ' ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci'
            : '';
        // SQLite only auto-numbers an INTEGER PRIMARY KEY (the rowid alias).
        // "BIGINT AUTO_INCREMENT PRIMARY KEY" is accepted there but every
        // inserted id is NULL, so outbound packets could never be assigned
        // to a batch or acknowledged and were re-sent on every poll: the
        // 2026-09-23 replay storm on the private staging node (a browser
        // re-processing the same batch 43 times a second).
        $idColumn = $this->backend === 'mysql'
            ? 'BIGINT AUTO_INCREMENT PRIMARY KEY'
            : 'INTEGER PRIMARY KEY AUTOINCREMENT';

        // wake_events and post_interface_peers are no longer created: their
        // only readers and writers (the wake_url path and the PostInterface
        // client of [post_interface_peers]) were removed on 2026-10-04.
        // Nothing here drops them either. A database that has them (both
        // live nodes) keeps them, rows and all, and no statement in this
        // migration names them, so the changed fingerprint costs one more
        // run of the CREATE ... IF NOT EXISTS / column / index steps below.
        // RequestStorageBudgetTrait still measures them where they exist.
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
                    identity_hash VARCHAR(32) DEFAULT NULL,
                    identity_public_key VARCHAR(128) DEFAULT NULL,
                    registration_seq BIGINT NOT NULL DEFAULT 0,
                    registration_proof VARCHAR(16) NOT NULL DEFAULT 'none',
                    claimed_identity_hash VARCHAR(32) DEFAULT NULL,
                    previous_session_token_hash VARCHAR(64) DEFAULT NULL,
                    superseded_logged_hash VARCHAR(64) NOT NULL DEFAULT '',
                    refusal_logged_seq BIGINT NOT NULL DEFAULT -1,
                    seeded_at INT DEFAULT NULL,
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
                    packet_record_id {$idColumn},
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
                    packet_id {$idColumn},
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

            // Persistent stand-in for Transport.path_requests and
            // Transport.discovery_path_requests, which are in-memory dicts in
            // the Python daemon but must survive between requests here.
            'path_request_throttle' => "
                CREATE TABLE IF NOT EXISTS path_request_throttle (
                    throttle_key VARCHAR(96) NOT NULL,
                    last_requested_at INT NOT NULL DEFAULT 0,
                    PRIMARY KEY (throttle_key)
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
                    PRIMARY KEY (link_id_hex, outbound_interface_id, remaining_hops)
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
                    PRIMARY KEY (destination_hash_hex)
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

            'php_peer_sessions' => "
                CREATE TABLE IF NOT EXISTS php_peer_sessions (
                    peer_name VARCHAR(128) NOT NULL DEFAULT '',
                    local_interface_id VARCHAR(64) NOT NULL,
                    local_session_token VARCHAR(128) DEFAULT NULL,
                    remote_url VARCHAR(512) NOT NULL,
                    updated_at INT NOT NULL DEFAULT 0,
                    PRIMARY KEY (local_interface_id, remote_url)
                ){$engine}",

            'transport_state' => "
                CREATE TABLE IF NOT EXISTS transport_state (
                    state_key VARCHAR(128) NOT NULL,
                    state_value TEXT,
                    updated_at INT NOT NULL DEFAULT 0,
                    PRIMARY KEY (state_key)
                ){$engine}",

            // migrateIfNeeded()'s version, recorded after a clean run. Built
            // here, not when the version is recorded, so that every DDL
            // statement runs under migrate()'s lock wait ceiling.
            'schema_meta' => "
                CREATE TABLE IF NOT EXISTS schema_meta (
                    meta_key VARCHAR(32) NOT NULL,
                    fingerprint VARCHAR(64) NOT NULL,
                    applied_at INT NOT NULL,
                    PRIMARY KEY (meta_key)
                ){$engine}",
        ];

        $existingTables = $this->existingTables();
        foreach ($tables as $name => $sql) {
            try {
                $startedAt = microtime(true);
                $this->db->exec($sql);
                $summary['tables_created']++;
                if ($existingTables !== null && !isset($existingTables[$name])) {
                    self::noteBuilt($summary, 'table ' . $name, $startedAt);
                }
            } catch (PDOException $e) {
                if (self::lockWaitTimedOut($summary, $e, "create_table {$name}")) {
                    return;
                }
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
            // REGISTRATION-STAGE1.md §12. Appended (no AFTER), so MySQL and
            // MariaDB add each one in place, with no table rebuild.
            ['interfaces', 'identity_hash', 'VARCHAR(32) DEFAULT NULL', null],
            ['interfaces', 'identity_public_key', 'VARCHAR(128) DEFAULT NULL', null],
            ['interfaces', 'registration_seq', 'BIGINT NOT NULL DEFAULT 0', null],
            ['interfaces', 'registration_proof', "VARCHAR(16) NOT NULL DEFAULT 'none'", null],
            ['interfaces', 'claimed_identity_hash', 'VARCHAR(32) DEFAULT NULL', null],
            ['interfaces', 'previous_session_token_hash', 'VARCHAR(64) DEFAULT NULL', null],
            ['interfaces', 'superseded_logged_hash', "VARCHAR(64) NOT NULL DEFAULT ''", null],
            ['interfaces', 'refusal_logged_seq', 'BIGINT NOT NULL DEFAULT -1', null],
            // seedInterfaceIfNew()'s marker: NULL until the row is seeded.
            ['interfaces', 'seeded_at', 'INT DEFAULT NULL', null],
        ];

        // Ask each table for its columns once and add only the missing ones,
        // so a re-run takes no lock; on SQLite the MySQL-only AFTER clause
        // was also a syntax error that counted as a failure. On MySQL and
        // MariaDB one ALTER adds a table's missing columns, so it takes one
        // metadata lock, not one per column, and asks for ALGORITHM=INSTANT,
        // so a server that cannot add them in place refuses at once instead
        // of copying the table. SQLite adds one column per statement.
        $existing = [];
        $missing = [];
        foreach ($additions as [$table, $column, $definition, $after]) {
            if (!isset($existing[$table])) {
                $existing[$table] = $this->existingColumns($table);
            }
            if (isset($existing[$table][$column])) {
                continue;
            }
            $clause = "ADD COLUMN `{$column}` {$definition}";
            if ($this->backend === 'mysql' && $after !== null && $after !== '') {
                $clause .= " AFTER `{$after}`";
            }
            $missing[$table][$column] = $clause;
        }

        foreach ($missing as $table => $clauses) {
            $statements = [];
            if ($this->backend === 'mysql') {
                $statements[] = [array_keys($clauses), "ALTER TABLE `{$table}` " . implode(', ', $clauses) . ', ALGORITHM=INSTANT'];
            } else {
                foreach ($clauses as $column => $clause) {
                    $statements[] = [[$column], "ALTER TABLE `{$table}` {$clause}"];
                }
            }
            foreach ($statements as [$columns, $sql]) {
                $what = "add_column {$table}." . implode(', ', $columns);
                try {
                    $startedAt = microtime(true);
                    $this->db->exec($sql);
                    $summary['columns_added'] += count($columns);
                    if ($table === 'interfaces' && in_array('seeded_at', $columns, true)) {
                        $summary['seeded_at_added'] = true;
                    }
                    self::noteBuilt($summary, (count($columns) === 1 ? 'column ' : 'columns ') . "{$table}." . implode(', ', $columns), $startedAt);
                } catch (PDOException $e) {
                    if (self::lockWaitTimedOut($summary, $e, $what)) {
                        return;
                    }
                    $code = (int) ($e->errorInfo[1] ?? 0);
                    // 1060 = MySQL duplicate column; SQLite reports the same
                    // condition as "duplicate column name" with code 1. An
                    // ALTER adds all its columns or none, so that is
                    // harmless only when every one of them is there now.
                    $duplicate = $code === 1060 || str_contains($e->getMessage(), 'duplicate column name');
                    if ($code !== 1146 && !($duplicate && array_diff($columns, array_keys($this->existingColumns($table))) === [])) {
                        $summary['errors'][] = "{$what}: " . $e->getMessage();
                    }
                }
            }
        }
    }

    /**
     * Widen counters that older installs created as 32-bit.
     *
     * ensureTables() declares the interface byte/packet counters BIGINT, but a
     * table that already existed keeps whatever type it was created with, and
     * ensureColumns() only adds columns that are missing. Both production
     * nodes had INT counters; the bridge interface's rx_bytes sat at exactly
     * 2147483647 — MySQL clamps on overflow — so the counter had been lying
     * for weeks. MySQL only: SQLite INTEGER is already 64-bit.
     */
    /** @return array<string,true> column name => true, empty if the table is missing */
    private function existingColumns(string $table): array
    {
        $columns = [];
        try {
            if ($this->backend === 'mysql') {
                $stmt = $this->db->prepare(
                    'SELECT COLUMN_NAME FROM information_schema.COLUMNS
                     WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = :table'
                );
                $stmt->bindValue(':table', $table, PDO::PARAM_STR);
                $stmt->execute();
                while (($row = $stmt->fetch(PDO::FETCH_ASSOC)) !== false) {
                    $name = (string) ($row['COLUMN_NAME'] ?? $row['column_name'] ?? '');
                    if ($name !== '') {
                        $columns[$name] = true;
                    }
                }
            } else {
                $stmt = $this->db->query("PRAGMA table_info(`{$table}`)");
                if ($stmt !== false) {
                    while (($row = $stmt->fetch(PDO::FETCH_ASSOC)) !== false) {
                        $name = (string) ($row['name'] ?? '');
                        if ($name !== '') {
                            $columns[$name] = true;
                        }
                    }
                }
            }
        } catch (PDOException $e) {
            // Unknown table or no metadata access: fall back to the ALTER path.
        }
        return $columns;
    }

    private function ensureColumnTypes(array &$summary): void
    {
        if ($this->backend !== 'mysql') {
            return;
        }
        $wanted = [
            'interfaces' => ['rx_packets', 'tx_packets', 'rx_bytes', 'tx_bytes'],
        ];
        foreach ($wanted as $table => $columns) {
            foreach ($columns as $column) {
                try {
                    $stmt = $this->db->prepare(
                        'SELECT DATA_TYPE FROM information_schema.COLUMNS
                          WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = :t AND COLUMN_NAME = :c'
                    );
                    $stmt->execute([':t' => $table, ':c' => $column]);
                    $type = strtolower((string) ($stmt->fetchColumn() ?: ''));
                    if ($type === '' || $type === 'bigint') {
                        continue;
                    }
                    $this->db->exec("ALTER TABLE `{$table}` MODIFY `{$column}` BIGINT NOT NULL DEFAULT 0");
                    $summary['columns_widened'] = ($summary['columns_widened'] ?? 0) + 1;
                } catch (PDOException $e) {
                    if (self::lockWaitTimedOut($summary, $e, "widen_column {$table}.{$column}")) {
                        return;
                    }
                    $summary['errors'][] = "widen_column {$table}.{$column}: " . $e->getMessage();
                }
            }
        }
    }

    /**
     * A destination reachable over several concurrent paths delivers the same
     * LINKREQUEST at different hop counts. Keyed only by (link, interface) the
     * variants collapse and the last writer wins, so the LRPROOF returning on
     * any other fork fails the exact-hop check and is dropped. Keying by hop
     * count keeps each variant addressable while preserving exact matching.
     */
    private function ensurePrimaryKeys(array &$summary): void
    {
        if ($this->backend !== 'mysql') {
            // SQLite builds tables with the current keys, except for a file
            // created before 2026-09-23, whose path_entries carried the key
            // (destination_hash_hex, interface_id). The reference keeps ONE
            // path per destination and every path upsert conflicts on the
            // destination alone (production MySQL has that key), so on such
            // a file every announce failed with "ON CONFLICT clause does not
            // match any PRIMARY KEY or UNIQUE constraint". Rebuild it.
            $this->rebuildSqlitePathEntriesKey($summary);
            $this->rebuildSqliteAutoIncrementIds($summary);
            return;
        }

        try {
            $stmt = $this->db->query(
                "SELECT COUNT(*) FROM information_schema.STATISTICS
                  WHERE TABLE_SCHEMA = DATABASE()
                    AND TABLE_NAME = 'link_transport_entries'
                    AND INDEX_NAME = 'PRIMARY'
                    AND COLUMN_NAME = 'remaining_hops'"
            );
            if ($stmt === false || (int) $stmt->fetchColumn() > 0) {
                return;
            }

            $this->db->exec(
                'ALTER TABLE `link_transport_entries`
                   DROP PRIMARY KEY,
                   ADD PRIMARY KEY (link_id_hex, outbound_interface_id, remaining_hops)'
            );
            $summary['indexes_added']++;
        } catch (PDOException $e) {
            if (self::lockWaitTimedOut($summary, $e, 'primary_key link_transport_entries')) {
                return;
            }
            $code = (int) ($e->errorInfo[1] ?? 0);
            if ($code !== 1146) {
                $summary['errors'][] = 'primary_key link_transport_entries: ' . $e->getMessage();
            }
        }
    }

    private function rebuildSqlitePathEntriesKey(array &$summary): void
    {
        try {
            $stmt = $this->db->query("SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'path_entries'");
            $sql = $stmt === false ? '' : (string) $stmt->fetchColumn();
            // The open cursor holds a shared lock; the DDL below needs it gone.
            if ($stmt !== false) {
                $stmt->closeCursor();
            }
            unset($stmt);
            if ($sql === '' || !preg_match('/PRIMARY KEY\s*\(\s*destination_hash_hex\s*,\s*interface_id\s*\)/i', $sql)) {
                return;
            }
            $this->db->exec('BEGIN');
            $this->db->exec('ALTER TABLE path_entries RENAME TO path_entries_old_key');
            $this->db->exec(
                'CREATE TABLE path_entries (
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
                )'
            );
            // Keep the newest row per destination.
            $this->db->exec(
                'INSERT INTO path_entries
                 SELECT destination_hash_hex, next_hop_hex, hops, expires_at, random_blobs_json,
                        interface_id, packet_hash_hex, announce_emitted, updated_at
                   FROM path_entries_old_key o
                  WHERE updated_at = (SELECT MAX(updated_at) FROM path_entries_old_key i
                                       WHERE i.destination_hash_hex = o.destination_hash_hex)
                  GROUP BY destination_hash_hex'
            );
            $this->db->exec('DROP TABLE path_entries_old_key');
            $this->db->exec('COMMIT');
            $summary['indexes_added']++;
        } catch (PDOException $e) {
            try { $this->db->exec('ROLLBACK'); } catch (PDOException $ignored) {}
            $summary['errors'][] = 'primary_key path_entries: ' . $e->getMessage();
        }
    }

    /**
     * A SQLite file built before 2026-09-23 declared its id columns
     * "BIGINT AUTO_INCREMENT PRIMARY KEY", which SQLite does not number.
     * Rebuild each such table with INTEGER PRIMARY KEY AUTOINCREMENT, numbering
     * the existing rows by rowid.
     */
    private function rebuildSqliteAutoIncrementIds(array &$summary): void
    {
        $tables = [
            'inbound_packets' => 'packet_record_id',
            'outbound_packets' => 'packet_id',
        ];
        foreach ($tables as $table => $idColumn) {
            try {
                $stmt = $this->db->query("SELECT sql FROM sqlite_master WHERE type = 'table' AND name = '{$table}'");
                $sql = $stmt === false ? '' : (string) $stmt->fetchColumn();
                if ($stmt !== false) {
                    $stmt->closeCursor();
                }
                unset($stmt);
                if ($sql === '' || !preg_match('/' . $idColumn . '\s+BIGINT\s+AUTO_INCREMENT\s+PRIMARY\s+KEY/i', $sql)) {
                    continue;
                }
                $newSql = preg_replace('/' . $idColumn . '\s+BIGINT\s+AUTO_INCREMENT\s+PRIMARY\s+KEY/i', $idColumn . ' INTEGER PRIMARY KEY AUTOINCREMENT', $sql);
                $newSql = preg_replace('/CREATE TABLE (IF NOT EXISTS )?' . $table . '\b/i', 'CREATE TABLE ' . $table . '_rebuilt', $newSql, 1);
                $cols = $this->db->query("SELECT name FROM pragma_table_info('{$table}')")->fetchAll(PDO::FETCH_COLUMN);
                $colList = implode(', ', $cols);
                $selectList = implode(', ', array_map(fn ($c) => $c === $idColumn ? 'rowid' : $c, $cols));
                $this->db->exec('BEGIN');
                $this->db->exec($newSql);
                $this->db->exec("INSERT INTO {$table}_rebuilt ({$colList}) SELECT {$selectList} FROM {$table}");
                $this->db->exec("DROP TABLE {$table}");
                $this->db->exec("ALTER TABLE {$table}_rebuilt RENAME TO {$table}");
                $this->db->exec('COMMIT');
                $summary['indexes_added']++;
            } catch (PDOException $e) {
                try { $this->db->exec('ROLLBACK'); } catch (PDOException $ignored) {}
                $summary['errors'][] = "autoincrement {$table}: " . $e->getMessage();
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
            'CREATE INDEX idx_inbound_packets_created ON inbound_packets (created_at)',
            'CREATE INDEX idx_outbound_batches_created ON outbound_batches (created_at)',
            'CREATE INDEX idx_path_request_tags_created ON path_request_tags (created_at)',
            'CREATE INDEX idx_path_request_throttle_at ON path_request_throttle (last_requested_at)',
            // Lets the Phase 5 purge check "is this packet still a path
            // entry's cached announce?" without scanning path_entries per row.
            'CREATE INDEX idx_path_entries_packet_hash ON path_entries (packet_hash_hex)',
            // The stored copies of one announce: what a path request, a cache
            // request and Phase 5b's one-copy rule look up by packet hash,
            // until 2026-10-10 by scanning the whole inbound history.
            'CREATE INDEX idx_inbound_packets_hash ON inbound_packets (packet_hash_hex, created_at)',
            'CREATE INDEX idx_reverse_path_created ON reverse_path_entries (created_at)',
            'CREATE INDEX idx_link_transport_updated ON link_transport_entries (updated_at)',
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
            'CREATE INDEX idx_outbound_packets_queued ON outbound_packets (queued_at)',
            // REGISTRATION-STAGE1.md §12. The signed row is found only by its
            // own UNIQUE column, lower-case hex (several NULLs are allowed on
            // MySQL 8.4, MariaDB 11.4 and SQLite); a legacy claim by its own.
            'CREATE UNIQUE INDEX idx_interfaces_identity_hash ON interfaces (identity_hash)',
            'CREATE INDEX idx_interfaces_claimed_identity ON interfaces (claimed_identity_hash)',
            // §4.5's removal of legacy rows: each step a statement on an
            // index (local_destinations and outbound_batches already are).
            'CREATE INDEX idx_outbound_packets_iface ON outbound_packets (interface_id, acked_at)',
            'CREATE INDEX idx_path_entries_iface ON path_entries (interface_id)',
            'CREATE INDEX idx_reverse_path_received ON reverse_path_entries (received_interface_id)',
            'CREATE INDEX idx_link_transport_received ON link_transport_entries (received_interface_id)',
            'CREATE INDEX idx_link_transport_outbound ON link_transport_entries (outbound_interface_id)',
        ];

        // The existing indexes are read once and only the missing ones
        // created, so a re-run takes no metadata lock. When they cannot be
        // read, every CREATE is tried, and "already there" is harmless.
        $tables = [];
        foreach ($indexes as $sql) {
            if (preg_match('/\ACREATE (?:UNIQUE )?INDEX (\w+) ON (\w+) /', $sql, $m) === 1) {
                $tables[$m[2]] = true;
            }
        }
        $existing = $this->existingIndexes(array_keys($tables));

        // MySQL and MariaDB are asked to build each one in place while the
        // table takes writes, so a server that cannot refuses at once instead
        // of copying or locking the table.
        $online = $this->backend === 'mysql' ? ' ALGORITHM=INPLACE LOCK=NONE' : '';
        foreach ($indexes as $sql) {
            $name = preg_match('/\ACREATE (?:UNIQUE )?INDEX (\w+) ON (\w+) /', $sql, $m) === 1 ? $m[1] : $sql;
            if ($existing !== null && isset($m[2]) && isset($existing[$m[2] . '.' . $name])) {
                continue;
            }
            try {
                $startedAt = microtime(true);
                $this->db->exec($sql . $online);
                $summary['indexes_added']++;
                self::noteBuilt($summary, 'index ' . $name, $startedAt);
            } catch (PDOException $e) {
                if (self::lockWaitTimedOut($summary, $e, "create_index {$name}")) {
                    return;
                }
                $code = (int) ($e->errorInfo[1] ?? 0);
                if (!in_array($code, [1061, 1072, 1146], true)
                    && !str_contains($e->getMessage(), 'already exists')) {
                    $summary['errors'][] = "create_index {$name}: " . $e->getMessage();
                }
            }
        }
    }

    /**
     * Every index of these tables, as "table.index" => true, read once
     * (information_schema.STATISTICS on MySQL and MariaDB, PRAGMA index_list
     * on SQLite); null when they cannot be read.
     *
     * @param list<string> $tables
     * @return array<string, true>|null
     */
    private function existingIndexes(array $tables): ?array
    {
        $indexes = [];
        try {
            if ($this->backend === 'mysql') {
                $stmt = $this->db->prepare(
                    'SELECT TABLE_NAME, INDEX_NAME FROM information_schema.STATISTICS WHERE TABLE_SCHEMA = DATABASE()'
                );
                $stmt->execute();
                while (($row = $stmt->fetch(PDO::FETCH_ASSOC)) !== false) {
                    $table = (string) ($row['TABLE_NAME'] ?? $row['table_name'] ?? '');
                    $index = (string) ($row['INDEX_NAME'] ?? $row['index_name'] ?? '');
                    if ($table !== '' && $index !== '') {
                        $indexes[$table . '.' . $index] = true;
                    }
                }
                return $indexes;
            }
            foreach ($tables as $table) {
                if (preg_match('/\A\w+\z/', $table) !== 1) {
                    return null;
                }
                $stmt = $this->db->query("PRAGMA index_list(`{$table}`)");
                if ($stmt === false) {
                    return null;
                }
                foreach ($stmt->fetchAll(PDO::FETCH_ASSOC) as $row) {
                    $index = (string) ($row['name'] ?? '');
                    if ($index !== '') {
                        $indexes[$table . '.' . $index] = true;
                    }
                }
            }
        } catch (PDOException $e) {
            return null;
        }

        return $indexes;
    }

    /** Every table, as name => true; null when they cannot be read. */
    private function existingTables(): ?array
    {
        try {
            $stmt = $this->backend === 'mysql'
                ? $this->db->prepare('SELECT TABLE_NAME FROM information_schema.TABLES WHERE TABLE_SCHEMA = DATABASE()')
                : $this->db->prepare('SELECT name FROM sqlite_master WHERE type = :type');
            if ($this->backend !== 'mysql') {
                $stmt->bindValue(':type', 'table', PDO::PARAM_STR);
            }
            $stmt->execute();
            $tables = [];
            foreach ($stmt->fetchAll(PDO::FETCH_NUM) as $row) {
                $tables[(string) $row[0]] = true;
            }

            return $tables;
        } catch (PDOException $e) {
            return null;
        }
    }

    /**
     * REGISTRATION-STAGE1.md §12's backfill, at every migration, in PHP,
     * idempotent, with no LIKE: claimed_identity_hash for legacy rns-js rows,
     * from a top-level metadata.identity_hash of 32 lower-case hex. The key
     * itself leaves metadata_json at the row's next write.
     */
    private function backfillClaimedIdentityHashes(array &$summary): void
    {
        try {
            $stmt = $this->db->prepare(
                'SELECT interface_id, metadata_json FROM interfaces
                  WHERE claimed_identity_hash IS NULL AND identity_hash IS NULL AND registration_proof = :none'
            );
            $stmt->bindValue(':none', 'none', PDO::PARAM_STR);
            $stmt->execute();
            $claims = [];
            foreach ($stmt->fetchAll(PDO::FETCH_ASSOC) as $row) {
                $metadata = json_decode((string) ($row['metadata_json'] ?? ''), true);
                if (!is_array($metadata) || ($metadata['client'] ?? null) !== 'rns-js') {
                    continue;
                }
                $claim = $metadata['identity_hash'] ?? null;
                if (is_string($claim) && preg_match('/\A[0-9a-f]{32}\z/', $claim) === 1) {
                    $claims[(string) $row['interface_id']] = $claim;
                }
            }
            if ($claims === []) {
                return;
            }
            $fill = $this->db->prepare(
                'UPDATE interfaces SET claimed_identity_hash = :claim
                  WHERE interface_id = :interface_id AND claimed_identity_hash IS NULL AND identity_hash IS NULL'
            );
            $filled = 0;
            foreach ($claims as $interfaceId => $claim) {
                $fill->bindValue(':claim', $claim, PDO::PARAM_STR);
                $fill->bindValue(':interface_id', $interfaceId, PDO::PARAM_STR);
                Database::executeWithRetry($fill, 'claimedIdentityBackfill');
                $filled += $fill->rowCount();
            }
            $summary['claims_backfilled'] = $filled;
        } catch (\Throwable $e) {
            $summary['errors'][] = 'backfill claimed_identity_hash: ' . $e->getMessage();
        }
    }

    /**
     * The rows already there when seeded_at is added were registered under
     * the rule it replaces, which seeded them on their first exchange (or
     * found them not new): mark them seeded (0, before the marker), so the
     * first request of this code does not seed every live interface again.
     * Runs only in the migration that added the column, after the DDL
     * ceiling like the claim backfill; a row registered later starts NULL
     * and is seeded once.
     */
    private function backfillSeededInterfaces(array &$summary): void
    {
        try {
            $summary['seeded_backfilled'] = (int) $this->db->exec('UPDATE interfaces SET seeded_at = 0 WHERE seeded_at IS NULL');
        } catch (\Throwable $e) {
            $summary['errors'][] = 'backfill seeded_at: ' . $e->getMessage();
        }
    }

    /**
     * REGISTRATION-STAGE1.md §12, /health's schema_migrated: the recorded
     * version is this code's and the probe finds §12's objects. Never
     * throws: a query that fails says false.
     */
    public function schemaMigrated(): bool
    {
        try {
            return $this->recordedSchemaFingerprint() === $this->schemaVersion() && $this->schemaObjectsPresent();
        } catch (\Throwable $e) {
            return false;
        }
    }

    /**
     * §12's probe: a zero-row SELECT of the new columns (the same on all
     * three engines), and idx_interfaces_identity_hash unique on
     * identity_hash (SHOW INDEX on MySQL and MariaDB, PRAGMA index_list on
     * SQLite). Needed because ensureIndexes() treats 1061, 1072 and 1146 as
     * harmless, so migrate() can report a clean run without the index. Never
     * throws.
     */
    public function schemaObjectsPresent(): bool
    {
        try {
            $probe = $this->db->query(
                'SELECT identity_hash, identity_public_key, registration_seq, registration_proof,
                        claimed_identity_hash, previous_session_token_hash, superseded_logged_hash,
                        refusal_logged_seq
                   FROM interfaces LIMIT 0'
            );
            if ($probe === false) {
                return false;
            }
            $probe->fetchAll();
            $probe->closeCursor();

            if ($this->backend === 'mysql') {
                $rows = $this->db->query('SHOW INDEX FROM interfaces');
                if ($rows === false) {
                    return false;
                }
                foreach ($rows->fetchAll(PDO::FETCH_ASSOC) as $row) {
                    if ((string) ($row['Key_name'] ?? '') === 'idx_interfaces_identity_hash'
                        && (int) ($row['Non_unique'] ?? 1) === 0
                        && (string) ($row['Column_name'] ?? '') === 'identity_hash') {
                        return true;
                    }
                }

                return false;
            }

            $list = $this->db->query('PRAGMA index_list(interfaces)');
            if ($list === false) {
                return false;
            }
            $unique = false;
            foreach ($list->fetchAll(PDO::FETCH_ASSOC) as $row) {
                if ((string) ($row['name'] ?? '') === 'idx_interfaces_identity_hash' && (int) ($row['unique'] ?? 0) === 1) {
                    $unique = true;
                }
            }
            if (!$unique) {
                return false;
            }
            $info = $this->db->query('PRAGMA index_info(idx_interfaces_identity_hash)');
            if ($info === false) {
                return false;
            }
            $columns = array_map(static fn (array $row): string => (string) ($row['name'] ?? ''), $info->fetchAll(PDO::FETCH_ASSOC));

            return $columns === ['identity_hash'];
        } catch (\Throwable $e) {
            return false;
        }
    }
}
