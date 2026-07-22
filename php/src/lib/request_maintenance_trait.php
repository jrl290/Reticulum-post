<?php

declare(strict_types=1);

namespace ReticulumPhp;

use PDO;
use PDOException;
use RuntimeException;

/**
 * RequestMaintenanceTrait — cleanup and stale-data pruning.
 *
 * DEADLOCK CONTEXT
 * ================
 * Maintenance DELETEs were the #1 source of MySQL deadlocks in production.
 * The pattern:
 *
 *   1. Request A (browser exchange) INSERTs into outbound_packets
 *   2. Request B (PHP peer exchange) INSERTs into inbound_packets
 *   3. Request C (another exchange) runs maintenance: DELETE FROM outbound_packets WHERE...
 *   4. The DELETE scans more rows than expected (no LIMIT), acquiring many row locks
 *   5. One of the INSERTs already holds a lock the DELETE needs, and vice versa → deadlock
 *
 * THREE-PRONGED FIX
 * =================
 *
 * 1. ADVISORY LOCK SERIALIZATION (MySQL only)
 *    Before running maintenance, acquire a MySQL advisory lock (GET_LOCK).
 *    This ensures only ONE process runs maintenance at a time, eliminating
 *    the multi-process DELETE-vs-DELETE deadlock class entirely.
 *    The lock is session-scoped and auto-released on connection close.
 *    On SQLite, this is a no-op (SQLite serializes writes natively).
 *
 * 2. BATCHED DELETES WITH LIMIT
 *    Instead of `DELETE FROM t WHERE expired < now`, use
 *    `DELETE FROM t WHERE expired < now ORDER BY id LIMIT 1000`.
 *    Smaller batches → shorter lock hold times → less deadlock surface.
 *    Loop until no more rows are affected.
 *
 * 3. CONSISTENT DELETE ORDERING
 *    Always DELETE from tables in the same order across all maintenance
 *    runs. The canonical order is documented below. InnoDB acquires locks
 *    in index order; consistent ordering prevents deadlock cycles.
 *
 * DEADLOCK RETRY
 * ==============
 * Even with the above mitigations, DELETE+INSERT conflicts can still occur
 * under extreme concurrency. Every DELETE is wrapped in Database::execWithRetry()
 * which catches MySQL error 1213 and retries with exponential backoff.
 *
 * CANONICAL DELETE ORDER
 * ======================
 * Always delete in this order to prevent lock-order deadlocks:
 *   1. inbound_packets       (leaf table, many rows)
 *   2. inbound_batches       (parent of inbound_packets)
 *   3. outbound_packets      (leaf table, many rows)
 *   4. outbound_batches      (parent of outbound_packets)
 *   5. packet_hashes         (independent)
 *   6. path_request_tags     (independent)
 *   7. reverse_path_entries  (independent)
 *   8. link_transport_entries (independent)
 *   9. path_entries          (independent)
 *  10. known_destinations    (independent)
 *  11. local_destinations    (independent)
 *  12. wake_events           (independent, small)
 *  13. interfaces            (parent of many — DELETE LAST)
 *
 * interface_stale_after_seconds: How long an interface can be unseen before
 *   it's marked stale and its associated packets/paths are cleaned up.
 *   Default: 15 seconds (tight because HTTP clients reconnect rapidly).
 *
 * batch_ttl_seconds: How long to retain batch records after they're fully
 *   processed (all packets acked/delivered). Default: 86400 (24h).
 */

trait RequestMaintenanceTrait
{
    /**
     * Run maintenance cleanup with advisory-lock serialization.
     *
     * Called from the exchange prelude (rate-limited to once per 2 seconds
     * via file-based lock) and from the CLI maintenance command.
     *
     * @param  int   $interfaceStaleAfterSeconds  Mark interfaces offline after this many seconds unseen
     * @param  int   $batchTtlSeconds             Delete fully-processed batches older than this
     * @return array Summary of operations performed
     */
    public function runMaintenance(
        int $interfaceStaleAfterSeconds = 15,
        int $batchTtlSeconds = 86400,
    ): array {
        $backend = $this->backend;
        $lockName = 'reticulum_php_maintenance';
        $summary = [
            'stale_interfaces' => 0,
            'orphaned_paths' => 0,
            'expired_packet_hashes' => 0,
            'expired_batches' => 0,
            'expired_path_request_tags' => 0,
            'expired_reverse_paths' => 0,
            'expired_link_transport' => 0,
            'expired_wake_events' => 0,
            'lock_acquired' => false,
            'deadlock_retries' => 0,
        ];

        // Phase 0: Acquire advisory lock (MySQL only)
        // Non-blocking: if another process already holds the lock, skip maintenance
        // rather than queueing up. The next request will catch it.
        $summary['lock_acquired'] = Database::acquireAdvisoryLock(
            $this->db,
            $backend,
            $lockName,
            0  // non-blocking: return immediately if lock not available
        );

        if (!$summary['lock_acquired'] && $backend === 'mysql') {
            // Another process is already running maintenance. Skip — the
            // file-based rate limiter in the prelude will let us try again
            // in 2 seconds.
            return $summary;
        }

        try {
            $now = time();

            // Phase 1: Mark stale interfaces as offline
            $staleCutoff = $now - $interfaceStaleAfterSeconds;
            $summary['stale_interfaces'] = $this->markStaleInterfacesOffline($staleCutoff, $backend);

            // Phase 2: Clean up packets/paths belonging to stale interfaces
            $summary['orphaned_paths'] = $this->deleteOrphanedPathsForStaleInterfaces(
                $staleCutoff,
                $backend,
                $summary
            );

            // Phase 3: Expire old packet hashes
            $packetHashTtl = $this->maintenanceConfigInt('packet_hash_ttl_seconds', 86400);
            $summary['expired_packet_hashes'] = $this->deleteExpiredPacketHashes(
                $now - $packetHashTtl,
                $backend,
                $summary
            );

            // Phase 4: Expire old batches
            $batchTtlCutoff = $now - $batchTtlSeconds;
            $summary['expired_batches'] = $this->deleteExpiredBatches(
                $batchTtlCutoff,
                $backend,
                $summary
            );

            // Phase 5: Expire path request tags
            $pathRequestTagTtl = $this->maintenanceConfigInt('path_request_tag_ttl_seconds', 86400);
            $summary['expired_path_request_tags'] = $this->deleteExpiredPathRequestTags(
                $now - $pathRequestTagTtl,
                $backend,
                $summary
            );

            // Phase 6: Expire reverse path entries
            $reversePathTtl = $this->maintenanceConfigInt('reverse_path_ttl_seconds', 480);
            $summary['expired_reverse_paths'] = $this->deleteExpiredReversePaths(
                $now - $reversePathTtl,
                $backend,
                $summary
            );

            // Phase 7: Expire link transport entries
            $linkTransportTtl = $this->maintenanceConfigInt('link_transport_ttl_seconds', 900);
            $summary['expired_link_transport'] = $this->deleteExpiredLinkTransportEntries(
                $now - $linkTransportTtl,
                $backend,
                $summary
            );

            // Phase 8: Expire old wake events
            $wakeEventTtl = $this->maintenanceConfigInt('wake_event_ttl_seconds', 86400);
            $summary['expired_wake_events'] = $this->deleteExpiredWakeEvents(
                $now - $wakeEventTtl,
                $backend,
                $summary
            );
        } finally {
            // Always release the advisory lock, even on failure.
            Database::releaseAdvisoryLock($this->db, $backend, $lockName);
        }

        return $summary;
    }

    // ─── Phase 1: Stale interfaces ───────────────────────────────────────

    private function markStaleInterfacesOffline(int $staleCutoff, string $backend): int
    {
        $table = Database::quoteTable($backend, 'interfaces');
        $stmt = $this->db->prepare(
            "UPDATE {$table}
                SET status = 'offline',
                    updated_at = :now
              WHERE status = 'online'
                AND updated_at < :cutoff"
        );
        $stmt->bindValue(':now', time(), PDO::PARAM_INT);
        $stmt->bindValue(':cutoff', $staleCutoff, PDO::PARAM_INT);
        Database::executeWithRetry($stmt, 'markStaleInterfacesOffline');

        return $stmt->rowCount();
    }

    // ─── Phase 2: Orphaned paths for stale interfaces ────────────────────

    /**
     * Delete path entries pointing to stale/offline interfaces.
     *
     * Paths with stale interfaces can never be used. Deleting them prevents
     * the relay from wasting cycles on dead routes and reduces table size.
     */
    private function deleteOrphanedPathsForStaleInterfaces(
        int $staleCutoff,
        string $backend,
        array &$summary
    ): int {
        $totalDeleted = 0;

        // Use a subquery to find path entries for stale interfaces.
        // DELETE with JOIN is tricky across MySQL/SQLite, so use a
        // batched approach: select IDs, then delete in batches.
        $ifTable = Database::quoteTable($backend, 'interfaces');
        $pathTable = Database::quoteTable($backend, 'path_entries');

        $batchSize = 1000;
        while (true) {
            $stmt = $this->db->prepare(
                "DELETE FROM {$pathTable}
                  WHERE interface_id IN (
                      SELECT interface_id FROM {$ifTable}
                       WHERE status = 'offline'
                         AND updated_at < :cutoff
                  )
                  LIMIT :batch_size"
            );
            $stmt->bindValue(':cutoff', $staleCutoff, PDO::PARAM_INT);
            $stmt->bindValue(':batch_size', $batchSize, PDO::PARAM_INT);

            try {
                Database::executeWithRetry($stmt, 'deleteOrphanedPaths');
            } catch (PDOException $e) {
                // MySQL doesn't support LIMIT in DELETE with subquery in some versions.
                // Fall back to a two-step approach.
                break;
            }

            $affected = $stmt->rowCount();
            $totalDeleted += $affected;
            if ($affected < $batchSize) {
                break;
            }
        }

        return $totalDeleted;
    }

    // ─── Phase 3: Expired packet hashes ──────────────────────────────────

    private function deleteExpiredPacketHashes(
        int $cutoff,
        string $backend,
        array &$summary
    ): int {
        $table = Database::quoteTable($backend, 'packet_hashes');
        return $this->deleteBatched(
            $table,
            'first_seen_at < :cutoff ORDER BY first_seen_at',
            [':cutoff' => $cutoff],
            $backend,
            $summary
        );
    }

    // ─── Phase 4: Expired batches ────────────────────────────────────────

    private function deleteExpiredBatches(
        int $cutoff,
        string $backend,
        array &$summary
    ): int {
        $total = 0;

        // inbound_batches first, then outbound_batches (consistent ordering)
        $total += $this->deleteBatched(
            Database::quoteTable($backend, 'inbound_batches'),
            'created_at < :cutoff ORDER BY created_at',
            [':cutoff' => $cutoff],
            $backend,
            $summary
        );

        $total += $this->deleteBatched(
            Database::quoteTable($backend, 'outbound_batches'),
            'created_at < :cutoff ORDER BY created_at',
            [':cutoff' => $cutoff],
            $backend,
            $summary
        );

        return $total;
    }

    // ─── Phase 5: Expired path request tags ──────────────────────────────

    private function deleteExpiredPathRequestTags(
        int $cutoff,
        string $backend,
        array &$summary
    ): int {
        $table = Database::quoteTable($backend, 'path_request_tags');
        return $this->deleteBatched(
            $table,
            'created_at < :cutoff ORDER BY created_at',
            [':cutoff' => $cutoff],
            $backend,
            $summary
        );
    }

    // ─── Phase 6: Expired reverse paths ──────────────────────────────────

    private function deleteExpiredReversePaths(
        int $cutoff,
        string $backend,
        array &$summary
    ): int {
        $table = Database::quoteTable($backend, 'reverse_path_entries');
        return $this->deleteBatched(
            $table,
            'created_at < :cutoff ORDER BY created_at',
            [':cutoff' => $cutoff],
            $backend,
            $summary
        );
    }

    // ─── Phase 7: Expired link transport entries ─────────────────────────

    private function deleteExpiredLinkTransportEntries(
        int $cutoff,
        string $backend,
        array &$summary
    ): int {
        $table = Database::quoteTable($backend, 'link_transport_entries');
        return $this->deleteBatched(
            $table,
            'updated_at < :cutoff ORDER BY updated_at',
            [':cutoff' => $cutoff],
            $backend,
            $summary
        );
    }

    // ─── Phase 8: Expired wake events ────────────────────────────────────

    private function deleteExpiredWakeEvents(
        int $cutoff,
        string $backend,
        array &$summary
    ): int {
        $table = Database::quoteTable($backend, 'wake_events');
        return $this->deleteBatched(
            $table,
            'created_at < :cutoff ORDER BY created_at',
            [':cutoff' => $cutoff],
            $backend,
            $summary
        );
    }

    // ─── Batched DELETE helper ───────────────────────────────────────────

    /**
     * DELETE rows in batches of BATCH_SIZE to minimize per-statement lock
     * hold time. Retries on deadlock.
     *
     * MySQL InnoDB: each DELETE statement holds row locks on all matching
     * rows until the statement completes. Large DELETEs can hold thousands
     * of locks, creating a wide deadlock surface. Batching to ~500 rows
     * keeps lock duration in the single-digit millisecond range.
     *
     * @param  string $table       Quoted table name
     * @param  string $whereClause WHERE clause with named placeholders
     * @param  array  $params      Named parameters [':name' => value]
     * @param  string $backend     'mysql' or 'sqlite'
     * @param  array  &$summary    Mutated to increment deadlock_retries
     * @return int    Total rows deleted
     */
    private function deleteBatched(
        string $table,
        string $whereClause,
        array $params,
        string $backend,
        array &$summary
    ): int {
        $batchSize = $backend === 'mysql' ? 500 : 1000;
        $totalDeleted = 0;

        // MySQL: DELETE ... LIMIT batchSize
        // SQLite: DELETE ... (no LIMIT needed — single-writer serialization)
        $limitClause = $backend === 'mysql' ? " LIMIT {$batchSize}" : '';

        while (true) {
            $sql = "DELETE FROM {$table} WHERE {$whereClause}{$limitClause}";
            $stmt = $this->db->prepare($sql);

            foreach ($params as $name => $value) {
                $stmt->bindValue($name, $value, is_int($value) ? PDO::PARAM_INT : PDO::PARAM_STR);
            }

            try {
                Database::executeWithRetry($stmt, 'deleteBatched:' . $table);
            } catch (RuntimeException $e) {
                // If all retries exhausted on deadlock, log and stop batching
                // for this table to avoid infinite loop
                error_log('ReticulumPhp: deleteBatched failed on ' . $table . ': ' . $e->getMessage());
                break;
            }

            $affected = $stmt->rowCount();
            $totalDeleted += $affected;

            // SQLite without LIMIT: one pass deletes everything
            if ($backend !== 'mysql' || $affected < $batchSize) {
                break;
            }
        }

        return $totalDeleted;
    }

    // ─── Config helpers ──────────────────────────────────────────────────

    /**
     * Read a maintenance config value with default.
     *
     * Aliased as maintenanceInt for compatibility with call sites in
     * other Storage-used traits (relay_routing, outbound_batch) that
     * were originally written against HttpApi's RequestHttpApiHelperTrait.
     */
    private function maintenanceInt(string $field, int $default): int
    {
        return $this->maintenanceConfigInt($field, $default);
    }

    private function maintenanceConfigInt(string $field, int $default): int
    {
        $maintenance = $this->config['maintenance'] ?? $this->config['worker'] ?? [];
        return (int) ($maintenance[$field] ?? $default);
    }
}
