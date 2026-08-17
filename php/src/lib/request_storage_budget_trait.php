<?php

declare(strict_types=1);

namespace ReticulumPhp;

use PDO;
use PDOException;
use RuntimeException;

/**
 * RequestStorageBudgetTrait — hard cap on the disk Reticulum-php may occupy.
 *
 * WHY THIS EXISTS (AND WHY packet_storage_max_bytes WAS NOT ENOUGH)
 * =================================================================
 * RequestMaintenanceTrait::trimPacketStorage() caps
 *   SUM(LENGTH(raw_base64) + LENGTH(payload_base64) + LENGTH(packet_base64))
 * across inbound_packets and outbound_packets. That is the size of the packet
 * *payloads*, not the size of the database. On retichat.com those two numbers
 * diverged by more than 7x:
 *
 *   payload bytes counted by the cap ...............   143 MB  (under the 300 MB cap)
 *   data_length + index_length actually allocated ...  1053 MB  (at the 1 GB account quota)
 *
 * The gap is everything the payload count ignores:
 *   - Secondary indexes. outbound_packets carries seven of them over
 *     varchar(255)/utf8mb4 columns — 298 MB of index for 138 MB of payload.
 *   - InnoDB row and page overhead, and pages left partly filled by deletes.
 *   - inbound_batches and outbound_batches (131 MB), path_entries (26 MB) and
 *     known_destinations (18 MB), which the payload cap never looked at.
 *
 * So the payload cap never fired once while the account filled up. This trait
 * budgets what the host actually bills for: allocated table bytes plus the log
 * files, measured from information_schema (MySQL) or the page count (SQLite).
 *
 * THE DELETE-DOES-NOT-SHRINK PROBLEM
 * ==================================
 * With innodb_file_per_table=1 a DELETE returns pages to the tablespace's free
 * list, not to the filesystem. data_length stays flat and the account quota
 * does not move until the table is rebuilt (OPTIMIZE TABLE, which for InnoDB is
 * ALTER TABLE ... FORCE). Two consequences shape the design here:
 *
 *   1. Pruning MUST NOT loop on "delete, re-measure, repeat" the way
 *      trimPacketStorage() does. The measurement does not fall as rows are
 *      removed, so that loop would delete every row in the database before it
 *      terminated. Instead each pass estimates bytes-per-row from the allocated
 *      size and deletes a bounded, computed number of rows.
 *   2. Reclamation is a separate, throttled step. It only runs from the CLI
 *      (`php index.php once`), never from a web request: rebuilding a 700 MB
 *      table takes far longer than max_execution_time, and losing the
 *      connection mid-ALTER just rolls the rebuild back after doing all the
 *      work. Run it from cron.
 *
 * CONFIG (all under [maintenance])
 * ================================
 * storage_max_bytes: Total budget for everything Reticulum-php stores —
 *   all owned tables plus the managed log files. Default 300000000 (300 MB).
 *   Set to 0 to disable the cap entirely.
 *
 * storage_log_max_bytes: Sub-budget for the log files, trimmed before the
 *   database is measured. Default 16000000 (16 MB).
 *
 * storage_check_interval_seconds: Minimum gap between footprint measurements.
 *   Maintenance runs every 2s; measuring information_schema that often is
 *   needless load. Default 60.
 *
 * storage_prune_max_rows_per_pass: Ceiling on rows removed in one pass, so a
 *   bad size estimate cannot empty a table. Default 200000.
 *
 * storage_prune_min_age_seconds: Rows younger than this are never pruned by
 *   the budget, whatever the pressure. Protects in-flight traffic. Default 300.
 *
 * outbound_pending_max_age_seconds: Absolute ceiling on an undelivered
 *   outbound packet's life. TTL expiry only removes acknowledged rows, so a
 *   peer that stops acking otherwise pins its queue forever. Default 86400.
 *
 * storage_reclaim_min_free_bytes: Rebuild a table when its data_free exceeds
 *   this. Default 64000000 (64 MB).
 *
 * storage_reclaim_min_interval_seconds: Minimum gap between rebuilds.
 *   Default 3600.
 */

trait RequestStorageBudgetTrait
{
    /**
     * Every table Reticulum-php creates. The footprint is the sum over these
     * and nothing else, so a shared database that also holds unrelated tables
     * is measured fairly.
     *
     * Keep in sync with RequestSchemaTrait::createTables().
     */
    private const STORAGE_BUDGET_TABLES = [
        'interfaces',
        'inbound_batches',
        'inbound_packets',
        'outbound_batches',
        'outbound_packets',
        'packet_hashes',
        'path_request_tags',
        'path_request_throttle',
        'reverse_path_entries',
        'link_transport_entries',
        'path_entries',
        'known_destinations',
        'local_destinations',
        'wake_events',
        'php_peer_sessions',
        'post_interface_peers',
        'transport_state',
    ];

    /**
     * Prune tiers, least valuable first. Each tier names the table, the
     * timestamp column that orders it oldest-first, and the predicate that
     * makes a row eligible.
     *
     * `min_age_key` selects which config knob supplies the retention floor;
     * null means the shared storage_prune_min_age_seconds applies.
     */
    private function storagePruneTiers(string $backend): array
    {
        $pathEntries = Database::quoteTable($backend, 'path_entries');
        $inboundPackets = Database::quoteTable($backend, 'inbound_packets');

        return [
            // 1. Inbound packet rows are parse diagnostics. Nothing reads them
            //    on the packet path — except an announce that a live path entry
            //    still points at, which processAcceptedPathRequest() re-reads to
            //    answer path requests. Dropping one of those black-holes that
            //    destination for the remaining week of the entry's life, so the
            //    same NOT EXISTS guard deleteExpiredPacketHistory() uses applies
            //    here too.
            [
                'name' => 'inbound_packets',
                'table_name' => 'inbound_packets',
                'table' => $inboundPackets,
                'time_column' => 'created_at',
                'where' => "NOT EXISTS (
                    SELECT 1 FROM {$pathEntries} pe
                     WHERE pe.packet_hash_hex = {$inboundPackets}.packet_hash_hex
                )",
                'min_age_key' => null,
            ],

            // 2. Acknowledged outbound packets are delivered history. The peer
            //    has confirmed receipt; only /debug still reads them.
            [
                'name' => 'outbound_packets_acked',
                'table_name' => 'outbound_packets',
                'table' => Database::quoteTable($backend, 'outbound_packets'),
                'time_column' => 'acked_at',
                'where' => 'acked_at IS NOT NULL',
                'min_age_key' => null,
            ],

            // 3+4. Processed batch envelopes. The packets they carried have
            //      their own rows; these are the delivery receipts.
            [
                'name' => 'inbound_batches',
                'table_name' => 'inbound_batches',
                'table' => Database::quoteTable($backend, 'inbound_batches'),
                'time_column' => 'created_at',
                'where' => 'processed_at IS NOT NULL',
                'min_age_key' => null,
            ],
            [
                'name' => 'outbound_batches',
                'table_name' => 'outbound_batches',
                'table' => Database::quoteTable($backend, 'outbound_batches'),
                'time_column' => 'created_at',
                'where' => 'acked_at IS NOT NULL',
                'min_age_key' => null,
            ],

            // 5. Undelivered outbound packets. These are real queued traffic, so
            //    they are the last packet tier and carry their own, much longer
            //    retention floor. A peer that never comes back would otherwise
            //    pin its queue forever: TTL expiry deliberately skips unacked
            //    rows, so nothing else ever removes them.
            [
                'name' => 'outbound_packets_pending',
                'table_name' => 'outbound_packets',
                'table' => Database::quoteTable($backend, 'outbound_packets'),
                'time_column' => 'queued_at',
                'where' => 'acked_at IS NULL',
                'min_age_key' => 'outbound_pending_max_age_seconds',
            ],

            // 6. Learned destination identities. Losing one costs a re-announce,
            //    not a dropped packet, so this ranks below queued traffic.
            [
                'name' => 'known_destinations',
                'table_name' => 'known_destinations',
                'table' => Database::quoteTable($backend, 'known_destinations'),
                'time_column' => 'updated_at',
                'where' => '1 = 1',
                'min_age_key' => null,
            ],

            // 7. Routing table. Pruning here provokes path requests, so it is
            //    the last resort and only touches entries already past expiry.
            [
                'name' => 'path_entries',
                'table_name' => 'path_entries',
                'table' => $pathEntries,
                'time_column' => 'updated_at',
                'where' => 'expires_at < :prune_now',
                'min_age_key' => null,
            ],
        ];
    }

    // ─── Phase 11 entry point ────────────────────────────────────────────

    /**
     * Trim logs, then measure and enforce the total budget.
     *
     * Measurement is throttled independently of maintenance. Maintenance runs
     * every 2 seconds off the request path; querying information_schema and
     * COUNT(*)-ing million-row tables at that rate would cost more than the
     * storage it saves. Sixty seconds is far tighter than the hours it takes
     * this node to move a meaningful fraction of 300 MB.
     */
    private function runStorageBudgetPhase(string $backend, bool $allowReclaim, array &$summary): void
    {
        $budgetBytes = max(0, $this->maintenanceConfigInt('storage_max_bytes', 300_000_000));
        if ($budgetBytes === 0) {
            return;
        }

        // Logs are trimmed on every pass, not on the throttled schedule: it is a
        // stat() per file and a rewrite only past the limit, so there is no
        // reason to let them run ahead between checks.
        $logMaxBytes = max(0, $this->maintenanceConfigInt('storage_log_max_bytes', 16_000_000));
        $summary['storage_log_bytes_trimmed'] = $this->trimManagedLogs($logMaxBytes);

        $checkInterval = max(0, $this->maintenanceConfigInt('storage_check_interval_seconds', 60));
        $now = time();
        $lastCheck = (int) ($this->storageStateGet('storage_budget_last_check_at') ?? 0);
        if (!$allowReclaim && $now - $lastCheck < $checkInterval) {
            return;
        }
        $this->storageStateSet('storage_budget_last_check_at', (string) $now);

        $footprint = $this->storageFootprint($backend, true);
        $this->enforceStorageBudget($budgetBytes, $footprint, $backend, $allowReclaim, $summary);
    }

    /**
     * Entry point for the detached `php index.php reclaim` process.
     *
     * The throttle window was already claimed by the parent that spawned this,
     * so it is not re-checked here — re-checking would make the child refuse
     * the very work it was spawned to do.
     */
    public function reclaimStorage(): array
    {
        $summary = ['storage_reclaimed_tables' => []];
        $footprint = $this->storageFootprint($this->backend, true);
        $summary['storage_bytes_before'] = $footprint['total_bytes'];

        $this->reclaimStorageFreeSpace($footprint, $this->backend, $summary, true);

        $after = $this->storageFootprint($this->backend, true);
        $summary['storage_bytes_after'] = $after['total_bytes'];

        return $summary;
    }

    // ─── Measurement ─────────────────────────────────────────────────────

    /**
     * Measure what Reticulum-php currently occupies.
     *
     * MySQL numbers come from information_schema. They are InnoDB's cached
     * statistics, refreshed when roughly 10% of a table's rows change, so they
     * lag reality by a little — but they are derived from allocated tablespace
     * pages, which is exactly what the hosting quota bills. innodb_stats_on_
     * metadata is off by default on 8.0+, so reading them is cheap.
     *
     * @param bool $refreshStats Recompute InnoDB statistics first. Required
     *                           before acting on the numbers — see
     *                           refreshStorageStatistics(). Callers that only
     *                           report (e.g. /health) pass false to stay cheap.
     * @return array{database_bytes:int, database_free_bytes:int, log_bytes:int, total_bytes:int, per_table:array<string,array{bytes:int, free_bytes:int}>}
     */
    public function storageFootprint(?string $backend = null, bool $refreshStats = false): array
    {
        $backend ??= $this->backend;
        $perTable = [];
        $databaseBytes = 0;
        $databaseFreeBytes = 0;

        if ($backend === 'mysql') {
            if ($refreshStats) {
                $this->refreshStorageStatistics($backend);
            }

            $placeholders = implode(',', array_fill(0, count(self::STORAGE_BUDGET_TABLES), '?'));

            // Alias every column. MySQL returns information_schema column names
            // upper-cased (TABLE_NAME, DATA_LENGTH), PHP array keys are
            // case-sensitive, and a missed key reads as 0 rather than raising —
            // which silently reports an empty database and disables the cap.
            $stmt = $this->db->prepare(
                "SELECT table_name AS budget_table,
                        data_length AS budget_data_length,
                        index_length AS budget_index_length,
                        data_free AS budget_data_free
                   FROM information_schema.TABLES
                  WHERE table_schema = DATABASE()
                    AND table_name IN ({$placeholders})"
            );
            $stmt->execute(self::STORAGE_BUDGET_TABLES);

            foreach ($this->normalizeFootprintRows($stmt->fetchAll(PDO::FETCH_ASSOC)) as $row) {
                $bytes = (int) ($row['budget_data_length'] ?? 0) + (int) ($row['budget_index_length'] ?? 0);
                $free = (int) ($row['budget_data_free'] ?? 0);
                $perTable[(string) ($row['budget_table'] ?? '')] = ['bytes' => $bytes, 'free_bytes' => $free];
                $databaseBytes += $bytes;
                $databaseFreeBytes += $free;
            }
        } else {
            // SQLite keeps every table in one file, so the file is the only
            // honest total. Per-table shares are apportioned by row count in
            // storageTableBytes() — good enough for the dev/test backend.
            $pageSize = (int) $this->db->query('PRAGMA page_size')->fetchColumn();
            $pageCount = (int) $this->db->query('PRAGMA page_count')->fetchColumn();
            $freeList = (int) $this->db->query('PRAGMA freelist_count')->fetchColumn();
            $databaseBytes = $pageSize * $pageCount;
            $databaseFreeBytes = $pageSize * $freeList;
        }

        $logBytes = 0;
        foreach ($this->managedLogPaths() as $path) {
            $size = @filesize($path);
            if ($size !== false) {
                $logBytes += (int) $size;
            }
        }

        return [
            'database_bytes' => $databaseBytes,
            'database_free_bytes' => $databaseFreeBytes,
            'log_bytes' => $logBytes,
            'total_bytes' => $databaseBytes + $logBytes,
            'per_table' => $perTable,
        ];
    }

    /**
     * Lower-case the keys of an information_schema result set.
     *
     * MySQL returns information_schema column names upper-cased — TABLE_NAME,
     * DATA_LENGTH — while PHP array keys are case-sensitive and a missed key
     * reads as null, not an error. That combination shipped a footprint of zero
     * bytes to production, which reads as "database is empty" and disables the
     * cap in the one direction nothing else would catch. The SELECT aliases the
     * columns and this normalises whatever case comes back, so neither the
     * server's choice nor a future rename can reintroduce a silent zero.
     */
    private function normalizeFootprintRows(array $rows): array
    {
        return array_map(
            static fn (array $row): array => array_change_key_case($row, CASE_LOWER),
            $rows
        );
    }

    /**
     * Recompute InnoDB's persistent statistics before reading them.
     *
     * information_schema.TABLES serves cached data-dictionary statistics, and
     * they are not merely a little stale — they can be wrong by the entire size
     * of the table. Measured on retichat.com immediately after an OPTIMIZE that
     * genuinely shrank the tablespace from 1053 MB to 16.6 MB:
     *
     *   before ANALYZE:  outbound_packets  703.9 MB   (the pre-rebuild figure)
     *   after  ANALYZE:  outbound_packets    0.2 MB   (the truth)
     *
     * Acting on the cached number would have had the budget prune every tier
     * down to its retention floor to recover space that was already free.
     * innodb_stats_on_metadata is 0 on 8.0+, so nothing refreshes these on
     * read — this must be explicit. ANALYZE samples a handful of index pages
     * per table (innodb_stats_persistent_sample_pages, 20 by default), which is
     * why it is affordable at the caller's throttled cadence and nowhere else.
     */
    private function refreshStorageStatistics(string $backend): void
    {
        if ($backend !== 'mysql') {
            return;
        }

        $tables = implode(', ', array_map(
            static fn (string $table): string => Database::quoteTable('mysql', $table),
            self::STORAGE_BUDGET_TABLES
        ));

        try {
            $statement = $this->db->query('ANALYZE TABLE ' . $tables);
            if ($statement !== false) {
                $statement->fetchAll(PDO::FETCH_ASSOC);
                $statement->closeCursor();
            }
        } catch (PDOException $e) {
            // A missing table or a lock timeout leaves the previous statistics
            // in place. Stale numbers are recoverable; aborting maintenance is
            // not, so this is a warning rather than a failure.
            error_log('ReticulumPhp: ANALYZE TABLE failed: ' . $e->getMessage());
        }
    }

    /**
     * Allocated bytes attributable to one table.
     *
     * MySQL reads it straight from the footprint. SQLite has no per-table
     * accounting without the optional dbstat module, so the file is split in
     * proportion to row counts.
     */
    private function storageTableBytes(string $tableName, array $footprint, string $backend): int
    {
        if ($backend === 'mysql') {
            return (int) ($footprint['per_table'][$tableName]['bytes'] ?? 0);
        }

        $tableRows = $this->storageCountRows(Database::quoteTable($backend, $tableName), '1 = 1', []);
        if ($tableRows === 0) {
            return 0;
        }

        $totalRows = 0;
        foreach (self::STORAGE_BUDGET_TABLES as $candidate) {
            try {
                $totalRows += $this->storageCountRows(Database::quoteTable($backend, $candidate), '1 = 1', []);
            } catch (PDOException $e) {
                // A table this deployment has not migrated yet contributes nothing.
            }
        }

        if ($totalRows === 0) {
            return 0;
        }

        return (int) round($footprint['database_bytes'] * ($tableRows / $totalRows));
    }

    // ─── Enforcement ─────────────────────────────────────────────────────

    /**
     * Bring the footprint back under budget.
     *
     * @param int    $budgetBytes  Total budget; 0 disables the cap.
     * @param array  $footprint    Result of storageFootprint(). Passed in rather
     *                             than measured here so tests can drive the
     *                             pruner with a synthetic footprint.
     * @param bool   $allowReclaim Permit table rebuilds. False on the request
     *                             path — a rebuild outlives max_execution_time.
     */
    public function enforceStorageBudget(
        int $budgetBytes,
        array $footprint,
        string $backend,
        bool $allowReclaim,
        array &$summary
    ): void {
        $summary['storage_bytes_before'] = (int) ($footprint['total_bytes'] ?? 0);
        $summary['storage_bytes_estimated_after'] = $summary['storage_bytes_before'];
        $summary['storage_budget_bytes'] = $budgetBytes;
        $summary['storage_pruned'] = [];

        if ($budgetBytes <= 0) {
            return;
        }

        $databaseBudget = $budgetBytes - (int) ($footprint['log_bytes'] ?? 0);
        $databaseBytes = (int) ($footprint['database_bytes'] ?? 0);
        $overBy = $databaseBytes - $databaseBudget;

        if ($overBy <= 0) {
            // Under budget, but pages freed by earlier pruning may still be
            // charged to the account. Reclamation is throttled and only fires
            // when there is real slack, so it is safe to offer it here too —
            // and skipping it would strand exactly the situation that follows a
            // large manual cleanup: few rows left, tablespace still at 1 GB.
            $this->requestStorageReclaim($footprint, $backend, $allowReclaim, $summary);
            return;
        }

        $now = time();
        $defaultMinAge = max(0, $this->maintenanceConfigInt('storage_prune_min_age_seconds', 300));
        $maxRows = max(1, $this->maintenanceConfigInt('storage_prune_max_rows_per_pass', 200_000));
        $rowBudget = $maxRows;

        foreach ($this->storagePruneTiers($backend) as $tier) {
            if ($overBy <= 0 || $rowBudget <= 0) {
                break;
            }

            $minAge = $tier['min_age_key'] === null
                ? $defaultMinAge
                : max(0, $this->maintenanceConfigInt($tier['min_age_key'], 86400));

            $where = $tier['where'] . ' AND ' . $tier['time_column'] . ' < :prune_cutoff';
            $params = [':prune_cutoff' => $now - $minAge];
            if (str_contains($tier['where'], ':prune_now')) {
                $params[':prune_now'] = $now;
            }

            try {
                $eligible = $this->storageCountRows($tier['table'], $where, $params);
            } catch (PDOException $e) {
                // Table absent on this deployment — skip the tier rather than
                // aborting the whole budget pass.
                continue;
            }

            if ($eligible === 0) {
                continue;
            }

            // Bytes per row is derived from the whole table, then applied to the
            // eligible subset. A row's true cost is its payload plus its share
            // of seven secondary indexes and of the partly-filled pages around
            // it; the allocated-size average captures all of that, which the
            // payload length alone never did.
            $totalRows = $this->storageCountRows($tier['table'], '1 = 1', []);
            $tableBytes = $this->storageTableBytes($tier['table_name'], $footprint, $backend);

            if ($totalRows <= 0 || $tableBytes <= 0) {
                continue;
            }

            $bytesPerRow = max(1, (int) round($tableBytes / $totalRows));
            $wantRows = (int) ceil($overBy / $bytesPerRow);
            $pruneRows = min($wantRows, $eligible, $rowBudget);
            if ($pruneRows <= 0) {
                continue;
            }

            $deleted = $this->pruneTierRows($tier, $where, $params, $pruneRows, $backend, $summary);
            if ($deleted === 0) {
                continue;
            }

            $rowBudget -= $deleted;
            $overBy -= $deleted * $bytesPerRow;
            $summary['storage_pruned'][$tier['name']] = $deleted;
            $summary['storage_bytes_estimated_after'] -= $deleted * $bytesPerRow;
        }

        if ($overBy > 0) {
            // Every tier is at its retention floor and the database is still
            // over budget. That is a capacity signal, not a bug to swallow:
            // either the traffic genuinely needs more than the budget or the
            // floors are too generous.
            $summary['storage_over_budget_bytes'] = $overBy;
            error_log(sprintf(
                'ReticulumPhp: storage still %d bytes over budget after pruning every tier ' .
                '(budget=%d, database=%d, logs=%d)',
                $overBy,
                $budgetBytes,
                $databaseBytes,
                (int) ($footprint['log_bytes'] ?? 0)
            ));
        }

        if ($summary['storage_pruned'] !== []) {
            // Re-measure before choosing what to rebuild. Reclaim targets are
            // picked by free space, and the pruning above is precisely what
            // creates it — so a footprint taken beforehand skips exactly the
            // tables that just emptied. Observed on selectivesubconscious.com:
            // a pass pruned 41,235 rows from inbound_packets and then rebuilt
            // three other tables, leaving inbound_packets allocated at 422 MB
            // with its freed pages still charged to the account.
            $footprint = $this->storageFootprint($backend, true);
        }

        $this->requestStorageReclaim($footprint, $backend, $allowReclaim, $summary);
    }

    /**
     * Reclaim inline when we can afford to block, otherwise detach.
     *
     * Only the CLI can afford to block: it has no request to hold open and no
     * max_execution_time to outlive. Everything else spawns.
     */
    private function requestStorageReclaim(
        array $footprint,
        string $backend,
        bool $allowReclaim,
        array &$summary
    ): void {
        if ($allowReclaim) {
            $this->reclaimStorageFreeSpace($footprint, $backend, $summary);
            return;
        }

        $this->spawnDetachedStorageReclaim($footprint, $summary);
    }

    /**
     * Delete the oldest $limit eligible rows.
     *
     * Deletion is by timestamp threshold rather than by primary key: two of the
     * tiers (inbound_batches, outbound_batches) have composite primary keys, and
     * a threshold works identically on both backends, uses the timestamp index,
     * and reuses the deadlock-retrying batched helper.
     *
     * The cost is that every row sharing the cutoff second goes with it, so a
     * pass can overshoot $limit — normally by a handful of rows at this node's
     * packet rate, but by the whole eligible set if the timestamps are clustered
     * (a bulk backfill, say). That is acceptable because the overshoot can only
     * ever reach rows already past their retention floor: it never touches
     * anything newer than the floor, and never removes less than asked.
     */
    private function pruneTierRows(
        array $tier,
        string $where,
        array $params,
        int $limit,
        string $backend,
        array &$summary
    ): int {
        $cutoff = $this->storageNthOldestTimestamp(
            $tier['table'],
            $tier['time_column'],
            $where,
            $params,
            $limit
        );
        if ($cutoff === null) {
            return 0;
        }

        $deleteWhere = $tier['where'] . ' AND ' . $tier['time_column'] . ' <= :prune_cutoff'
            . ' ORDER BY ' . $tier['time_column'];
        $deleteParams = [':prune_cutoff' => $cutoff];
        if (isset($params[':prune_now'])) {
            $deleteParams[':prune_now'] = $params[':prune_now'];
        }

        return $this->deleteBatched($tier['table'], $deleteWhere, $deleteParams, $backend, $summary);
    }

    /**
     * Timestamp of the $nth oldest eligible row, or null if fewer exist.
     */
    private function storageNthOldestTimestamp(
        string $table,
        string $timeColumn,
        string $where,
        array $params,
        int $n
    ): ?int {
        $stmt = $this->db->prepare(
            "SELECT {$timeColumn} FROM {$table}
              WHERE {$where}
           ORDER BY {$timeColumn} ASC
              LIMIT 1 OFFSET " . max(0, $n - 1)
        );
        foreach ($params as $name => $value) {
            $stmt->bindValue($name, $value, is_int($value) ? PDO::PARAM_INT : PDO::PARAM_STR);
        }
        $stmt->execute();
        $value = $stmt->fetchColumn();

        return $value === false ? null : (int) $value;
    }

    private function storageCountRows(string $table, string $where, array $params): int
    {
        $stmt = $this->db->prepare("SELECT COUNT(*) FROM {$table} WHERE {$where}");
        foreach ($params as $name => $value) {
            $stmt->bindValue($name, $value, is_int($value) ? PDO::PARAM_INT : PDO::PARAM_STR);
        }
        $stmt->execute();

        return (int) $stmt->fetchColumn();
    }

    // ─── Reclamation ─────────────────────────────────────────────────────

    /**
     * Return freed pages to the filesystem.
     *
     * Without this the account quota never falls: InnoDB hands deleted pages to
     * the tablespace free list, and only a rebuild shrinks the .ibd file. The
     * rebuild is expensive and long, so it is throttled, skipped unless there is
     * real slack to recover, and never reached from a web request.
     */
    private function reclaimStorageFreeSpace(
        array $footprint,
        string $backend,
        array &$summary,
        bool $throttleAlreadyClaimed = false
    ): void {
        $minFree = max(0, $this->maintenanceConfigInt('storage_reclaim_min_free_bytes', 64_000_000));
        $minInterval = max(0, $this->maintenanceConfigInt('storage_reclaim_min_interval_seconds', 3600));
        $now = time();

        if (!$throttleAlreadyClaimed) {
            $lastRun = (int) ($this->storageStateGet('storage_reclaim_last_run_at') ?? 0);
            if ($now - $lastRun < $minInterval) {
                return;
            }
        }

        $summary['storage_reclaimed_tables'] = [];

        if ($backend === 'sqlite') {
            if (($footprint['database_free_bytes'] ?? 0) < $minFree) {
                return;
            }
            $this->storageStateSet('storage_reclaim_last_run_at', (string) $now);
            $this->db->exec('VACUUM');
            $summary['storage_reclaimed_tables'][] = 'sqlite:vacuum';
            return;
        }

        $targets = $this->storageReclaimTargets($footprint, $minFree);
        if ($targets === []) {
            return;
        }

        // Stamp the throttle before rebuilding, not after. If the process is
        // killed part-way through a long ALTER, the next run must not start the
        // same rebuild immediately — MySQL rolls the partial rebuild back, so
        // retrying at once would spin without ever finishing.
        $this->storageStateSet('storage_reclaim_last_run_at', (string) $now);

        foreach ($targets as $tableName) {
            try {
                $statement = $this->db->query('OPTIMIZE TABLE ' . Database::quoteTable($backend, $tableName));
                if ($statement !== false) {
                    // OPTIMIZE returns a status result set that must be drained
                    // before the connection can be reused.
                    $statement->fetchAll(PDO::FETCH_ASSOC);
                    $statement->closeCursor();
                }
                $summary['storage_reclaimed_tables'][] = $tableName;
            } catch (PDOException $e) {
                error_log('ReticulumPhp: OPTIMIZE TABLE failed on ' . $tableName . ': ' . $e->getMessage());
            }
        }
    }

    /**
     * Units of reclaimable space, or [] when there is nothing worth rebuilding.
     *
     * MySQL reports free space per table, so each qualifying table is its own
     * target. SQLite has one file and no per-table accounting, so the whole
     * database is a single target keyed off its freelist.
     *
     * A table qualifies on either an absolute or a proportional test:
     *
     *   free >= minFree                       — worth it in its own right
     *   free >= half of what the table holds  — worth it relative to its size
     *
     * The absolute test alone leaves small-but-mostly-empty tables bloated
     * forever. Observed on selectivesubconscious.com: packet_hashes sat at
     * 61.3 MB allocated with 41 MB free — 67% waste — permanently below a
     * 64 MB threshold. The ratio test carries a floor of its own so that a
     * nearly-empty 200 KB table is not rebuilt for nothing.
     */
    private function storageReclaimTargets(array $footprint, int $minFree): array
    {
        $ratioFloor = 8_000_000;
        $qualifies = static function (int $free, int $allocated) use ($minFree, $ratioFloor): bool {
            if ($free >= $minFree) {
                return true;
            }

            return $free >= $ratioFloor && $allocated > 0 && $free * 2 >= $allocated;
        };

        if (($footprint['per_table'] ?? []) === []) {
            return $qualifies(
                (int) ($footprint['database_free_bytes'] ?? 0),
                (int) ($footprint['database_bytes'] ?? 0)
            ) ? ['sqlite:vacuum'] : [];
        }

        $targets = [];
        foreach ($footprint['per_table'] as $tableName => $stats) {
            if ($qualifies((int) ($stats['free_bytes'] ?? 0), (int) ($stats['bytes'] ?? 0))) {
                $targets[] = $tableName;
            }
        }

        return $targets;
    }

    /**
     * Hand the rebuild to a detached process instead of a scheduler.
     *
     * A rebuild cannot run inline on the request path — it outlives the request
     * — but that does not make it cron's job. The node already spawns detached
     * PHP for wake dispatch (spawnDetachedWakeRunner), and reclamation is the
     * same shape of work: triggered by the operation that noticed it was
     * needed, executed out of band, with the request returning immediately.
     *
     * The throttle is claimed *here*, in the parent, before the child is
     * spawned. Claiming it in the child would let every request that arrives
     * during the rebuild spawn another one, and concurrent ALTERs on the same
     * table serialise into a pile-up.
     *
     * If exec() is unavailable the shortfall is recorded for /health rather
     * than silently dropped: pruning still bounds row growth, but the freed
     * pages stay charged to the account until something rebuilds the table.
     */
    private function spawnDetachedStorageReclaim(array $footprint, array &$summary): void
    {
        $minFree = max(0, $this->maintenanceConfigInt('storage_reclaim_min_free_bytes', 64_000_000));
        $minInterval = max(0, $this->maintenanceConfigInt('storage_reclaim_min_interval_seconds', 3600));
        $now = time();

        if ($this->storageReclaimTargets($footprint, $minFree) === []) {
            return;
        }

        $lastRun = (int) ($this->storageStateGet('storage_reclaim_last_run_at') ?? 0);
        if ($now - $lastRun < $minInterval) {
            return;
        }

        if (!function_exists('exec')) {
            $summary['storage_reclaim_deferred'] = 'exec() unavailable';
            error_log('ReticulumPhp: storage reclaim needed but exec() is unavailable; '
                . 'freed pages stay charged until `php index.php reclaim` is run');
            return;
        }

        // Claim the window before spawning — see above.
        $this->storageStateSet('storage_reclaim_last_run_at', (string) $now);

        $command = sprintf(
            '%s %s reclaim > /dev/null 2>&1 &',
            escapeshellarg($this->reclaimPhpBinary()),
            escapeshellarg(dirname(__DIR__) . '/index.php')
        );

        $output = [];
        $exitCode = 0;
        exec($command, $output, $exitCode);
        $summary['storage_reclaim_spawned'] = $exitCode === 0;

        if ($exitCode !== 0) {
            error_log('ReticulumPhp: storage reclaim spawn exited with status ' . $exitCode);
        }
    }

    /**
     * The PHP binary to run the detached reclaim with.
     *
     * PHP_BINARY is not reliable here. Under php-fpm or CGI it names the server
     * binary, not a CLI one, and handing that a script path does not run it. The
     * configured value wins; otherwise prefer a real CLI binary on disk and fall
     * back to PHP_BINARY only when nothing better is found.
     */
    private function reclaimPhpBinary(): string
    {
        $configured = (string) (
            ($this->config['maintenance'] ?? [])['reclaim_php_binary']
            ?? ($this->config['php'] ?? [])['binary']
            ?? ''
        );
        if ($configured !== '') {
            return $configured;
        }

        if (PHP_SAPI === 'cli' && PHP_BINARY !== '') {
            return PHP_BINARY;
        }

        foreach (['/usr/local/bin/php', '/usr/bin/php'] as $candidate) {
            if (is_executable($candidate)) {
                return $candidate;
            }
        }

        return PHP_BINARY !== '' ? PHP_BINARY : 'php';
    }

    // ─── Log files ───────────────────────────────────────────────────────

    /**
     * Files this node appends to and is therefore responsible for bounding.
     *
     * storage.log_path is written with a bare file_put_contents(), so a relative
     * value resolves against the working directory — resolve it the same way
     * here rather than guessing at a project root the config never records.
     */
    private function managedLogPaths(): array
    {
        $paths = [];

        $configured = (string) ($this->config['storage']['log_path'] ?? '');
        if ($configured !== '') {
            $paths[] = $this->resolveLogPath($configured);
        }

        // PHP's own error log. On this cPanel host it is the 21 MB `error_log`
        // beside index.php, which no TTL has ever touched.
        $phpErrorLog = (string) ini_get('error_log');
        if ($phpErrorLog !== '' && $phpErrorLog !== 'syslog') {
            $paths[] = $this->resolveLogPath($phpErrorLog);
        } else {
            $paths[] = $this->resolveLogPath('error_log');
        }

        foreach ((array) ($this->config['storage']['managed_log_paths'] ?? []) as $extra) {
            if (is_string($extra) && $extra !== '') {
                $paths[] = $this->resolveLogPath($extra);
            }
        }

        return array_values(array_unique($paths));
    }

    private function resolveLogPath(string $path): string
    {
        if ($path === '' || $path[0] === '/') {
            return $path;
        }

        return rtrim((string) getcwd(), '/') . '/' . $path;
    }

    /**
     * Trim each managed log to the budget, keeping the newest half.
     *
     * Keeping half rather than trimming exactly to the limit means the rewrite
     * happens once per doubling instead of on every append past the boundary.
     * The tail is kept, not the head: recent lines are the ones worth reading.
     *
     * @return int Bytes removed.
     */
    public function trimManagedLogs(int $maxBytes): int
    {
        if ($maxBytes <= 0) {
            return 0;
        }

        $keepBytes = max(1, intdiv($maxBytes, 2));
        $removed = 0;

        foreach ($this->managedLogPaths() as $path) {
            $size = @filesize($path);
            if ($size === false || $size <= $maxBytes) {
                continue;
            }

            $handle = @fopen($path, 'r+');
            if ($handle === false) {
                continue;
            }

            try {
                if (!flock($handle, LOCK_EX)) {
                    continue;
                }

                // Re-stat under the lock: another process may have rotated it
                // between the filesize() above and the lock being granted.
                $stat = fstat($handle);
                $lockedSize = (int) ($stat['size'] ?? 0);
                if ($lockedSize <= $maxBytes) {
                    continue;
                }

                fseek($handle, $lockedSize - $keepBytes);
                // Drop the partial first line so the file starts on a boundary.
                fgets($handle);
                $tail = stream_get_contents($handle);
                if ($tail === false) {
                    continue;
                }

                ftruncate($handle, 0);
                rewind($handle);
                fwrite($handle, $tail);
                fflush($handle);
                $removed += $lockedSize - strlen($tail);
            } finally {
                flock($handle, LOCK_UN);
                fclose($handle);
            }
        }

        return $removed;
    }

    // ─── Throttle state ──────────────────────────────────────────────────

    private function storageStateGet(string $key): ?string
    {
        $table = Database::quoteTable($this->backend, 'transport_state');
        try {
            $stmt = $this->db->prepare("SELECT state_value FROM {$table} WHERE state_key = :key");
            $stmt->execute([':key' => $key]);
            $value = $stmt->fetchColumn();
        } catch (PDOException $e) {
            return null;
        }

        return $value === false ? null : (string) $value;
    }

    private function storageStateSet(string $key, string $value): void
    {
        $table = Database::quoteTable($this->backend, 'transport_state');
        $sql = $this->backend === 'mysql'
            ? "INSERT INTO {$table} (state_key, state_value, updated_at) VALUES (:key, :value, :now)
                 ON DUPLICATE KEY UPDATE state_value = VALUES(state_value), updated_at = VALUES(updated_at)"
            : "INSERT INTO {$table} (state_key, state_value, updated_at) VALUES (:key, :value, :now)
                 ON CONFLICT(state_key) DO UPDATE SET state_value = excluded.state_value, updated_at = excluded.updated_at";

        try {
            $stmt = $this->db->prepare($sql);
            $stmt->bindValue(':key', $key, PDO::PARAM_STR);
            $stmt->bindValue(':value', $value, PDO::PARAM_STR);
            $stmt->bindValue(':now', time(), PDO::PARAM_INT);
            Database::executeWithRetry($stmt, 'storageStateSet:' . $key);
        } catch (PDOException | RuntimeException $e) {
            error_log('ReticulumPhp: unable to persist ' . $key . ': ' . $e->getMessage());
        }
    }
}
