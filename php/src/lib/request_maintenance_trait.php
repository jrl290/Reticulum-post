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
 *
 * inbound_packet_ttl_seconds: How long to retain parsed inbound packet
 *   diagnostics. Default: 3600 (1h).
 *
 * outbound_packet_ttl_seconds: How long to retain acknowledged outbound
 *   packet history. Default: 86400 (24h). Pending packets are never expired.
 *
 * packet_storage_max_bytes: Maximum combined *payload* storage for
 *   inbound_packets and outbound_packets — the length of the base64 columns
 *   only. Inbound and acknowledged outbound history are removed oldest-first
 *   before pending outbound queue entries. Default: 300000000 (300 MB).
 *   Set to 0 to disable.
 *
 *   This is a cheap first line of defence, not the storage cap. Payload length
 *   ignores indexes, row overhead, and the batch/path/destination tables, and
 *   on retichat.com it under-reported the real footprint by more than 7x — 143
 *   MB of counted payload against 1053 MB of allocated tables. The cap that
 *   actually bounds disk is storage_max_bytes, enforced in Phase 11 by
 *   RequestStorageBudgetTrait.
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
     * @param  bool  $allowReclaim                Permit InnoDB table rebuilds in Phase 11. Only the
     *                                            CLI passes true: rebuilding a multi-hundred-MB table
     *                                            runs far past max_execution_time, and a request that
     *                                            dies mid-ALTER just wastes the whole rebuild.
     * @return array Summary of operations performed
     */
    public function runMaintenance(
        int $interfaceStaleAfterSeconds = 15,
        int $batchTtlSeconds = 86400,
        bool $allowReclaim = false,
    ): array {
        $backend = $this->backend;
        $lockName = 'reticulum_php_maintenance';
        $summary = [
            'stale_interfaces' => 0,
            'orphaned_paths' => 0,
            'expired_packet_hashes' => 0,
            'expired_batches' => 0,
            'expired_inbound_packets' => 0,
            'expired_outbound_packets' => 0,
            'expired_path_request_tags' => 0,
            'expired_reverse_paths' => 0,
            'expired_link_transport' => 0,
            'expired_wake_events' => 0,
            'packet_storage_bytes_before' => 0,
            'packet_storage_bytes_after' => 0,
            'trimmed_inbound_packets' => 0,
            'trimmed_outbound_packets' => 0,
            'storage_bytes_before' => 0,
            'storage_bytes_estimated_after' => 0,
            'storage_budget_bytes' => 0,
            'storage_log_bytes_trimmed' => 0,
            'storage_pruned' => [],
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

            // Phase 2b: Orphaned local destinations for stale interfaces.
            // A local destination is only reachable while the interface it was
            // registered on is connected. If the row survives the interface,
            // relayTargetsForAcceptedPacket() keeps choosing local delivery
            // over the path entry and the traffic is black-holed — even after
            // the destination reappears on another node.
            $summary['orphaned_local_destinations'] = $this->deleteOrphanedLocalDestinationsForStaleInterfaces(
                $staleCutoff,
                $backend
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

            // Phase 5: Expire packet history. Inbound rows are diagnostics;
            // outbound rows are removable only after delivery acknowledgement.
            $inboundPacketTtl = $this->maintenanceConfigInt('inbound_packet_ttl_seconds', 3600);
            $outboundPacketTtl = $this->maintenanceConfigInt('outbound_packet_ttl_seconds', 86400);
            [$summary['expired_inbound_packets'], $summary['expired_outbound_packets']] =
                $this->deleteExpiredPacketHistory(
                    $now - max(0, $inboundPacketTtl),
                    $now - max(0, $outboundPacketTtl),
                    $backend,
                    $summary
                );

            // Phase 6: Expire path request tags
            $pathRequestTagTtl = $this->maintenanceConfigInt('path_request_tag_ttl_seconds', 86400);
            $summary['expired_path_request_tags'] = $this->deleteExpiredPathRequestTags(
                $now - $pathRequestTagTtl,
                $backend,
                $summary
            );

            // Phase 7: Expire reverse path entries
            $reversePathTtl = $this->maintenanceConfigInt('reverse_path_ttl_seconds', 480);
            $summary['expired_reverse_paths'] = $this->deleteExpiredReversePaths(
                $now - $reversePathTtl,
                $backend,
                $summary
            );

            // Phase 8: Expire link transport entries
            $linkTransportTtl = $this->maintenanceConfigInt('link_transport_ttl_seconds', 900);
            $summary['expired_link_transport'] = $this->deleteExpiredLinkTransportEntries(
                $now - $linkTransportTtl,
                $backend,
                $summary
            );

            // Phase 9: Expire old wake events
            $wakeEventTtl = $this->maintenanceConfigInt('wake_event_ttl_seconds', 86400);
            $summary['expired_wake_events'] = $this->deleteExpiredWakeEvents(
                $now - $wakeEventTtl,
                $backend,
                $summary
            );

            // Phase 10: Bound combined packet payload storage.
            $packetStorageMaxBytes = max(
                0,
                $this->maintenanceConfigInt('packet_storage_max_bytes', 300_000_000)
            );
            $this->trimPacketStorage($packetStorageMaxBytes, $backend, $summary);

            // Phase 11: Bound the total on-disk footprint.
            $this->runStorageBudgetPhase($backend, $allowReclaim, $summary);

            // Phase 12: Re-establish configured peer sessions that have died.
            // Peering used to be a one-shot bootstrap behind GET /v1/initialize;
            // when Phase 1/2 (correctly) reaped a dead peer interface, nothing
            // ever re-created it, and on 2026-08-17 that left selectiv with no
            // route to the mesh for 9 hours. Self-healing rides maintenance so
            // it runs on ordinary request traffic — no scheduler — and is
            // throttled through transport_state inside the call.
            $this->ensureConfiguredPeerSessions($now, $summary);
        } finally {
            // Always release the advisory lock, even on failure.
            Database::releaseAdvisoryLock($this->db, $backend, $lockName);
        }

        return $summary;
    }

    // ─── Phase 1: Stale interfaces ───────────────────────────────────────

    /**
     * `updated_at` records when the row was last marked offline, so Phase 2 can
     * apply a grace period before purging its paths. Staleness must therefore be
     * judged on `last_seen_at`, which every exchange/register path refreshes.
     *
     * NEVER compare `updated_at` here. It is written by this method alone, so an
     * actively polling interface keeps whatever value it had when it was last
     * marked offline (or 0, the column default from the migration that added
     * it). `updated_at < now - 15` is then permanently true and every online
     * interface is marked offline on the very next maintenance pass, 2 seconds
     * later. Because peekReversePath() requires BOTH the receiving and the
     * outbound interface to be status='online', every PROOF and LRPROOF that
     * lands in one of those gaps is silently dropped, and 15 seconds later
     * Phase 2 deletes the live client's path_entries and local_destinations.
     * That is the cause of the intermittent "direct proof not received in 5s",
     * the missing LRPROOF on inbound link requests, "link closed before a
     * response", and the path-request storms.
     */
    private function markStaleInterfacesOffline(int $staleCutoff, string $backend): int
    {
        $table = Database::quoteTable($backend, 'interfaces');
        $stmt = $this->db->prepare(
            "UPDATE {$table}
                SET status = 'offline',
                    updated_at = :now
              WHERE status = 'online'
                AND last_seen_at < :cutoff"
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
            // SQLite does not support LIMIT in DELETE. Use batched approach
            // like deleteBatched(): LIMIT for MySQL, no LIMIT for SQLite.
            $limitClause = $backend === 'mysql' ? " LIMIT {$batchSize}" : '';
            $sql = "DELETE FROM {$pathTable}
                  WHERE interface_id IN (
                      SELECT interface_id FROM {$ifTable}
                       WHERE status = 'offline'
                         AND updated_at < :cutoff
                  ){$limitClause}";
            $stmt = $this->db->prepare($sql);
            $stmt->bindValue(':cutoff', $staleCutoff, PDO::PARAM_INT);

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

    /**
     * Delete local_destinations rows registered on stale/offline interfaces.
     *
     * Mirrors deleteOrphanedPathsForStaleInterfaces(): a destination announced
     * by a browser is local only for as long as that browser's interface is
     * online. Once the interface disappears the row must go too, otherwise
     * relayTargetsForAcceptedPacket() keeps choosing local delivery over the
     * path entry and black-holes traffic for a destination that has since
     * moved to another node.
     */
    private function deleteOrphanedLocalDestinationsForStaleInterfaces(
        int $staleCutoff,
        string $backend
    ): int {
        $ifTable = Database::quoteTable($backend, 'interfaces');
        $localTable = Database::quoteTable($backend, 'local_destinations');

        $stmt = $this->db->prepare(
            "DELETE FROM {$localTable}
              WHERE interface_id IN (
                  SELECT interface_id FROM {$ifTable}
                   WHERE status = 'offline'
                     AND updated_at < :cutoff
              )"
        );
        $stmt->bindValue(':cutoff', $staleCutoff, PDO::PARAM_INT);
        Database::executeWithRetry($stmt, 'deleteOrphanedLocalDestinations');

        return $stmt->rowCount();
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

    // ─── Phase 5: Expired packet history ────────────────────────────────

    private function deleteExpiredPacketHistory(
        int $inboundCutoff,
        int $outboundCutoff,
        string $backend,
        array &$summary
    ): array {
        // A path entry stores only the packet_hash of the announce that taught
        // us the path, and re-reads the packet body from inbound_packets to
        // answer a path request. Path entries live ~7 days, this history only
        // an hour, so purging purely on age strands the path entry pointing at
        // a row that no longer exists. processAcceptedPathRequest() then finds
        // a known path but no announce to send, and answers nothing — for the
        // remaining week of that entry's life. Python keeps the path table and
        // its packet cache together and treats a missing packet as an error
        // (Transport.py:2845), so keep the referenced rows.
        $pathEntries = Database::quoteTable($backend, 'path_entries');
        $inboundTable = Database::quoteTable($backend, 'inbound_packets');
        $inboundDeleted = $this->deleteSingleBatch(
            $inboundTable,
            "created_at < :cutoff
               AND NOT EXISTS (
                   SELECT 1 FROM {$pathEntries} pe
                    WHERE pe.packet_hash_hex = {$inboundTable}.packet_hash_hex
               )
             ORDER BY created_at",
            [':cutoff' => $inboundCutoff],
            $backend,
        );

        $outboundDeleted = $this->deleteSingleBatch(
            Database::quoteTable($backend, 'outbound_packets'),
            'acked_at IS NOT NULL AND acked_at < :cutoff ORDER BY acked_at',
            [':cutoff' => $outboundCutoff],
            $backend,
        );

        return [$inboundDeleted, $outboundDeleted];
    }

    private function deleteSingleBatch(
        string $table,
        string $whereClause,
        array $params,
        string $backend
    ): int {
        $limitClause = $backend === 'mysql' ? ' LIMIT 1000' : '';
        if ($backend === 'sqlite') {
            $whereClause = preg_replace('/\s+ORDER\s+BY\s+\S+(\s+(ASC|DESC))?\s*$/i', '', $whereClause);
        }

        $stmt = $this->db->prepare("DELETE FROM {$table} WHERE {$whereClause}{$limitClause}");
        foreach ($params as $name => $value) {
            $stmt->bindValue($name, $value, is_int($value) ? PDO::PARAM_INT : PDO::PARAM_STR);
        }
        Database::executeWithRetry($stmt, 'deleteSingleBatch:' . $table);

        return $stmt->rowCount();
    }

    // ─── Phase 6: Expired path request tags ──────────────────────────────

    private function deleteExpiredPathRequestTags(
        int $cutoff,
        string $backend,
        array &$summary
    ): int {
        $table = Database::quoteTable($backend, 'path_request_tags');
        $deleted = $this->deleteBatched(
            $table,
            'created_at < :cutoff ORDER BY created_at',
            [':cutoff' => $cutoff],
            $backend,
            $summary
        );

        // The throttle rows only need to outlive their own interval, so the
        // tag cutoff is comfortably conservative.
        $throttleTable = Database::quoteTable($backend, 'path_request_throttle');
        $deleted += $this->deleteBatched(
            $throttleTable,
            'last_requested_at < :cutoff ORDER BY last_requested_at',
            [':cutoff' => $cutoff],
            $backend,
            $summary
        );

        return $deleted;
    }

    // ─── Phase 7: Expired reverse paths ──────────────────────────────────

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

    // ─── Phase 8: Expired link transport entries ─────────────────────────

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

    // ─── Phase 9: Expired wake events ────────────────────────────────────

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

    // ─── Phase 10: Packet storage cap ────────────────────────────────────

    private function trimPacketStorage(int $maxBytes, string $backend, array &$summary): void
    {
        $inboundTable = Database::quoteTable($backend, 'inbound_packets');
        $outboundTable = Database::quoteTable($backend, 'outbound_packets');
        $inboundBytes = "COALESCE(LENGTH(raw_base64), 0) + COALESCE(LENGTH(payload_base64), 0)";
        $outboundBytes = "COALESCE(LENGTH(packet_base64), 0)";

        $totalSql = "SELECT
            (SELECT COALESCE(SUM({$inboundBytes}), 0) FROM {$inboundTable}) +
            (SELECT COALESCE(SUM({$outboundBytes}), 0) FROM {$outboundTable})";
        $totalBytes = (int) $this->db->query($totalSql)->fetchColumn();
        $summary['packet_storage_bytes_before'] = $totalBytes;
        $summary['packet_storage_bytes_after'] = $totalBytes;

        if ($maxBytes === 0 || $totalBytes <= $maxBytes) {
            return;
        }

        $candidateBatchSize = 500;

        while ($totalBytes > $maxBytes) {
            $candidateSql = "SELECT packet_table, packet_id, stored_bytes
                FROM (
                    SELECT 'inbound' AS packet_table,
                           packet_record_id AS packet_id,
                           created_at AS stored_at,
                           0 AS prune_priority,
                           {$inboundBytes} AS stored_bytes
                      FROM {$inboundTable}
                    UNION ALL
                    SELECT 'outbound' AS packet_table,
                           packet_id,
                           queued_at AS stored_at,
                           CASE WHEN acked_at IS NULL THEN 1 ELSE 0 END AS prune_priority,
                           {$outboundBytes} AS stored_bytes
                      FROM {$outboundTable}
                ) AS packet_storage
                ORDER BY prune_priority ASC, stored_at ASC, packet_table ASC, packet_id ASC
                LIMIT {$candidateBatchSize}";
            $candidates = $this->db->query($candidateSql)->fetchAll(PDO::FETCH_ASSOC);
            if ($candidates === []) {
                break;
            }

            $inboundIds = [];
            $outboundIds = [];
            $selectedBytes = 0;
            foreach ($candidates as $candidate) {
                $packetId = (int) ($candidate['packet_id'] ?? 0);
                if ($packetId <= 0) {
                    continue;
                }

                if (($candidate['packet_table'] ?? '') === 'inbound') {
                    $inboundIds[] = $packetId;
                } else {
                    $outboundIds[] = $packetId;
                }
                $selectedBytes += (int) ($candidate['stored_bytes'] ?? 0);

                if ($selectedBytes >= $totalBytes - $maxBytes) {
                    break;
                }
            }

            $inboundDeleted = $this->deletePacketRowsByIds($inboundTable, 'packet_record_id', $inboundIds);
            $outboundDeleted = $this->deletePacketRowsByIds($outboundTable, 'packet_id', $outboundIds);
            $summary['trimmed_inbound_packets'] += $inboundDeleted;
            $summary['trimmed_outbound_packets'] += $outboundDeleted;

            if ($inboundDeleted + $outboundDeleted === 0) {
                break;
            }

            $totalBytes = (int) $this->db->query($totalSql)->fetchColumn();
            $summary['packet_storage_bytes_after'] = $totalBytes;
        }
    }

    private function deletePacketRowsByIds(string $table, string $idColumn, array $ids): int
    {
        if ($ids === []) {
            return 0;
        }

        $placeholders = implode(',', array_fill(0, count($ids), '?'));
        $stmt = $this->db->prepare("DELETE FROM {$table} WHERE {$idColumn} IN ({$placeholders})");
        foreach ($ids as $index => $id) {
            $stmt->bindValue($index + 1, $id, PDO::PARAM_INT);
        }
        Database::executeWithRetry($stmt, 'trimPacketStorage:' . $table);

        return $stmt->rowCount();
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

        // MySQL: DELETE ... ORDER BY ... LIMIT batchSize
        // SQLite: DELETE ... (no ORDER BY or LIMIT — single-writer serialization)
        $limitClause = $backend === 'mysql' ? " LIMIT {$batchSize}" : '';
        // Strip ORDER BY for SQLite — SQLite doesn't support ORDER BY in DELETE
        if ($backend === 'sqlite') {
            $whereClause = preg_replace('/\s+ORDER\s+BY\s+\S+(\s+(ASC|DESC))?\s*$/i', '', $whereClause);
        }

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
