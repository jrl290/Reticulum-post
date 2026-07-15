<?php

declare(strict_types=1);

namespace ReticulumPhp;

use PDO;

/**
 * Maintenance Trait — periodic cleanup and state reconciliation.
 *
 * Reticulum-php is request-operated: maintenance runs inline during every
 * exchange request (rate-limited to once per 2 seconds by the prelude).
 * There is no background worker or cron job.
 *
 * TWO-TIER INTERFACE STALENESS MODEL
 * ----------------------------------
 * Interfaces have a `status` column: 'online' or 'offline'. The staleness
 * threshold differs by interface type:
 *
 *   NON-PEER (browsers, clients, NAS):
 *     Controlled by: interface_stale_after_seconds (default: 15 seconds)
 *     Rationale: Clients poll frequently (every 1-5 seconds). If a client
 *     hasn't been seen in 15 seconds, it's probably disconnected. Marking
 *     it offline allows cleanup of its queued packets, path entries, and
 *     link transport state. A short TTL prevents unbounded accumulation.
 *
 *   PEER (PHP↔PHP nodes):
 *     Controlled by: peer_stale_after_seconds (default: 86400 = 24 hours)
 *     Rationale: PHP peers may go extended periods without exchanging data.
 *     Unlike browser clients, a peer can be healthy but idle. Marking a
 *     peer offline prematurely breaks the PHP→PHP relay path and prevents
 *     wake dispatch. 24 hours matches the upstream RNS path expiry default.
 *     DO NOT reduce this below 3600 (1 hour) — it caused peer disappearance
 *     from the monitor and broken relay chains.
 *
 * PEER AUTO-REPAIR
 * ----------------
 * If a peer interface was marked offline (e.g., transient network blip,
 * server restart), maintenance will auto-repair it back to 'online' as long
 * as its last_seen_at is within peer_stale_after_seconds. This means a
 * single successful exchange brings the peer back immediately.
 *
 * TTL-BASED CLEANUP (no LIMITs)
 * -----------------------------
 * All cleanup is TTL-based, not row-count-based. Previous LIMIT-based
 * approaches caused silent data loss when tables grew beyond the limit.
 * TTLs target specific queue_reason values:
 *   - 'relay_announce', 'path_request_forward', 'proof_relay',
 *     'lrproof_relay', 'link_relay', 'path_response': 30s TTL
 *     (fire-and-forget relay, only needs to survive one exchange cycle)
 *   - 'relay' (link requests, data for peers): general outbound TTL
 *     (must survive the wake/pull cycle for PHP peers)
 *   - inbound_packet_ttl_seconds: 3600s (control-plane flood prevention)
 *   - packet_hash_ttl_seconds: 30s (duplicate detection window)
 *   - path_request_tag_ttl_seconds: 30s (path discovery dedup window)
 *
 * DEADLOCK AVOIDANCE
 * ------------------
 * Maintenance DELETEs acquire row locks. When two exchanges overlap
 * (browser client + PHP peer), concurrent DELETE and INSERT/UPDATE on
 * the same tables can deadlock. Mitigations:
 *   1. Maintenance is rate-limited to once per 2 seconds (prelude).
 *   2. Offline interface IDs are pre-fetched with a non-locking SELECT
 *      before being used in DELETE queries, avoiding subquery locks.
 *
 * REGRESSION PREVENTION
 * ---------------------
 * DO NOT:
 *   - Reduce peer_stale_after_seconds below 3600.
 *   - Add LIMIT clauses to DELETE queries (use TTLs instead).
 *   - Remove the rate-limit gating in the prelude.
 *   - Add retry logic (violates DESIGN_PRINCIPLES.md Rule #1).
 */

trait RequestMaintenanceTrait
{
    /**
     * Run all maintenance tasks. Called from the exchange prelude
     * (rate-limited to once per 2 seconds).
     *
     * @param int $interfaceStaleAfterSeconds  Non-peer interface offline threshold.
     * @param int $batchTtlSeconds             Batch record retention TTL.
     * @return array                           Counts of cleaned-up rows by category.
     */
    public function runMaintenance(int $interfaceStaleAfterSeconds, int $batchTtlSeconds): array
    {
        $now = time();
        $staleBefore = $now - $interfaceStaleAfterSeconds;
        $trimBefore = $now - $batchTtlSeconds;
        $packetHashTrimBefore = $now - $this->maintenanceInt('packet_hash_ttl_seconds', 30);

        // ── Non-peer interface staleness ──────────────────────────────
        // Mark any non-peer interface offline if it hasn't been seen
        // within interface_stale_after_seconds (default 15s).
        $staleStmt = $this->db->prepare(
            "UPDATE interfaces SET status = :new_status
             WHERE status != :current_status
               AND last_seen_at < :stale_before
               AND peer_url IS NULL"
        );
        $staleStmt->bindValue(':new_status', 'offline', PDO::PARAM_STR);
        $staleStmt->bindValue(':current_status', 'offline', PDO::PARAM_STR);
        $staleStmt->bindValue(':stale_before', $staleBefore, PDO::PARAM_INT);
        $staleStmt->execute();
        $interfacesMarkedOffline = $staleStmt->rowCount();

        // ── Peer interface auto-repair ────────────────────────────────
        // Peer interfaces may have been marked offline during a transient
        // network issue or server restart. If they've been seen within
        // peer_stale_after_seconds (default 86400 = 24h), repair them
        // back to online.
        // DO NOT reduce the default below 3600 — this broke peer relay.
        $peerActiveAfter = $now - $this->maintenanceInt('peer_stale_after_seconds', 86400);
        $peerRepairStmt = $this->db->prepare(
            'UPDATE interfaces SET status = :online
             WHERE peer_url IS NOT NULL
               AND status != :online2
               AND last_seen_at >= :active_after'
        );
        $peerRepairStmt->bindValue(':online', 'online', PDO::PARAM_STR);
        $peerRepairStmt->bindValue(':online2', 'online', PDO::PARAM_STR);
        $peerRepairStmt->bindValue(':active_after', $peerActiveAfter, PDO::PARAM_INT);
        $peerRepairStmt->execute();

        // ── Peer interface staleness ──────────────────────────────────
        // Mark peer interfaces offline if they haven't been seen within
        // peer_stale_after_seconds. These are truly dead peers.
        $peerStaleStmt = $this->db->prepare(
            'UPDATE interfaces SET status = :offline
             WHERE peer_url IS NOT NULL
               AND status != :offline2
               AND last_seen_at < :stale_before'
        );
        $peerStaleStmt->bindValue(':offline', 'offline', PDO::PARAM_STR);
        $peerStaleStmt->bindValue(':offline2', 'offline', PDO::PARAM_STR);
        $peerStaleStmt->bindValue(':stale_before', $peerActiveAfter, PDO::PARAM_INT);
        $peerStaleStmt->execute();

        // ── Pre-fetch offline non-peer interface IDs ──────────────────
        // Subqueries in DELETE statements acquire shared locks on interfaces
        // that can deadlock with concurrent status updates. Fetching IDs first
        // with a non-locking SELECT avoids this. TTL-based cleanup bounds row
        // counts, so no LIMIT needed.
        $offlineIfaceIds = $this->fetchOfflineNonPeerInterfaceIds();
        $offlinePlaceholders = $offlineIfaceIds !== []
            ? implode(',', array_fill(0, count($offlineIfaceIds), '?'))
            : '';

        // ── Inbound batch TTL cleanup ─────────────────────────────────
        $deleteInboundBatches = $this->db->prepare(
            'DELETE FROM inbound_batches WHERE created_at < :trim_before'
        );
        $deleteInboundBatches->bindValue(':trim_before', $trimBefore, PDO::PARAM_INT);
        $deleteInboundBatches->execute();
        $trimmedInboundBatches = $deleteInboundBatches->rowCount();

        // ── Inbound packet TTL cleanup ────────────────────────────────
        // Control-plane packets (announces, link requests) flood the
        // inbound_packets table. Delete anything older than the TTL.
        // Default TTL is 3600s (1 hour) — long enough for debugging but
        // short enough to prevent table bloat.
        $inboundPacketTtl = $this->maintenanceInt('inbound_packet_ttl_seconds', 3600);
        $inboundTrimBefore = $now - $inboundPacketTtl;
        $deleteInboundPackets = $this->db->prepare(
            'DELETE FROM inbound_packets WHERE created_at < :ttl_before'
        );
        $deleteInboundPackets->bindValue(':ttl_before', $inboundTrimBefore, PDO::PARAM_INT);
        $deleteInboundPackets->execute();
        $trimmedInboundPackets = $deleteInboundPackets->rowCount();

        // Inbound packets for offline non-peer interfaces: dead weight, drop immediately.
        if ($offlinePlaceholders !== '') {
            $deleteOfflineInboundPackets = $this->db->prepare(
                "DELETE FROM inbound_packets
                 WHERE interface_id IN ($offlinePlaceholders)"
            );
            $deleteOfflineInboundPackets->execute($offlineIfaceIds);
            $trimmedInboundPackets += $deleteOfflineInboundPackets->rowCount();
        }

        // ── Outbound batch TTL cleanup ────────────────────────────────
        $deleteOutboundBatches = $this->db->prepare(
            'DELETE FROM outbound_batches WHERE acked_at IS NOT NULL AND acked_at < :trim_before'
        );
        $deleteOutboundBatches->bindValue(':trim_before', $trimBefore, PDO::PARAM_INT);
        $deleteOutboundBatches->execute();
        $trimmedOutboundBatches = $deleteOutboundBatches->rowCount();

        // Orphaned outbound batches for offline non-peer interfaces.
        if ($offlinePlaceholders !== '') {
            $deleteOfflineOutboundBatches = $this->db->prepare(
                "DELETE FROM outbound_batches
                 WHERE acked_at IS NULL
                   AND interface_id IN ($offlinePlaceholders)"
            );
            $deleteOfflineOutboundBatches->execute($offlineIfaceIds);
            $trimmedOutboundBatches += $deleteOfflineOutboundBatches->rowCount();
        }

        // ── Outbound packet TTL cleanup ───────────────────────────────
        $deleteOutboundPackets = $this->db->prepare(
            'DELETE FROM outbound_packets WHERE acked_at IS NOT NULL AND acked_at < :trim_before'
        );
        $deleteOutboundPackets->bindValue(':trim_before', $trimBefore, PDO::PARAM_INT);
        $deleteOutboundPackets->execute();
        $trimmedOutboundPackets = $deleteOutboundPackets->rowCount();

        // Orphaned outbound packets for offline non-peer interfaces.
        if ($offlinePlaceholders !== '') {
            $deleteOfflineOutboundPackets = $this->db->prepare(
                "DELETE FROM outbound_packets
                 WHERE acked_at IS NULL
                   AND interface_id IN ($offlinePlaceholders)"
            );
            $deleteOfflineOutboundPackets->execute($offlineIfaceIds);
            $trimmedOutboundPackets += $deleteOfflineOutboundPackets->rowCount();
        }

        // ── Stale non-peer outbound ───────────────────────────────────
        // Packets queued > max_outbound_packet_age_seconds (default 3600s)
        // for non-peer interfaces that were never delivered. Prevents
        // unbounded accumulation for interfaces that stay "online" but
        // never pull (e.g., stale browser tabs).
        $maxPacketAge = $this->maintenanceInt('max_outbound_packet_age_seconds', 3600);
        $nonPeerIfaceIds = $this->fetchNonPeerInterfaceIds();
        if ($nonPeerIfaceIds !== []) {
            $nonPeerPlaceholders = implode(',', array_fill(0, count($nonPeerIfaceIds), '?'));
            $maxAge = $now - $maxPacketAge;
            $deleteStaleOutboundPackets = $this->db->prepare(
                "DELETE FROM outbound_packets
                 WHERE acked_at IS NULL
                   AND queued_at < ?
                   AND interface_id IN ($nonPeerPlaceholders)"
            );
            $deleteStaleOutboundPackets->execute(array_merge([$maxAge], $nonPeerIfaceIds));
            $trimmedOutboundPackets += $deleteStaleOutboundPackets->rowCount();
        }

        // ── Fire-and-forget relay packet cleanup ───────────────────────
        // Relay packets (announces, path requests, proofs) are forwarded
        // once and never need to persist. Python drops them immediately
        // after relay. We keep them just long enough to survive a single
        // exchange cycle (default 30s), then delete.
        // IMPORTANT: 'relay' reason (link requests, data for peers) is
        // NOT included here — those must survive the wake/pull cycle and
        // use the general outbound TTL instead.
        $relayTtl = $this->maintenanceInt('relay_packet_ttl_seconds', 30);
        $relayTrimBefore = $now - $relayTtl;
        $deleteRelayOutbound = $this->db->prepare(
            "DELETE FROM outbound_packets
             WHERE queue_reason IN ('relay_announce', 'path_request_forward', 'proof_relay', 'lrproof_relay', 'link_relay', 'path_response')
               AND queued_at < :ttl_before"
        );
        $deleteRelayOutbound->bindValue(':ttl_before', $relayTrimBefore, PDO::PARAM_INT);
        $deleteRelayOutbound->execute();
        $trimmedOutboundPackets += $deleteRelayOutbound->rowCount();

        // ── Wake event TTL cleanup ────────────────────────────────────
        $deleteWakeEvents = $this->db->prepare(
            'DELETE FROM wake_events
             WHERE created_at < :trim_before
               AND (dispatched_at IS NOT NULL OR failed_at IS NOT NULL)'
        );
        $deleteWakeEvents->bindValue(':trim_before', $trimBefore, PDO::PARAM_INT);
        $deleteWakeEvents->execute();
        $trimmedWakeEvents = $deleteWakeEvents->rowCount();

        $failedOrphanedWakeClaims = $this->failOrphanedClaimedWakeEvents();

        // ── Packet hash TTL cleanup ──────────────────────────────────
        // Duplicate detection window. Default 30s is sufficient for the
        // announcement flood dedup window.
        $deletePacketHashes = $this->db->prepare(
            'DELETE FROM packet_hashes WHERE first_seen_at < :trim_before'
        );
        $deletePacketHashes->bindValue(':trim_before', $packetHashTrimBefore, PDO::PARAM_INT);
        $deletePacketHashes->execute();
        $trimmedPacketHashes = $deletePacketHashes->rowCount();

        // ── Expired path cleanup ─────────────────────────────────────
        $deleteExpiredPaths = $this->db->prepare(
            'DELETE FROM path_entries WHERE expires_at < :expires_before'
        );
        $deleteExpiredPaths->bindValue(':expires_before', $now, PDO::PARAM_INT);
        $deleteExpiredPaths->execute();
        $trimmedExpiredPaths = $deleteExpiredPaths->rowCount();

        // Paths through offline non-peer interfaces are dead ends — drop them.
        // Peer interfaces are wake-driven and always viable; keep their paths.
        if ($offlinePlaceholders !== '') {
            $deleteDeadInterfacePaths = $this->db->prepare(
                "DELETE FROM path_entries
                 WHERE interface_id IN ($offlinePlaceholders)"
            );
            $deleteDeadInterfacePaths->execute($offlineIfaceIds);
            $trimmedExpiredPaths += $deleteDeadInterfacePaths->rowCount();
        }

        // ── Path request tag TTL cleanup ─────────────────────────────
        $deletePathRequestTags = $this->db->prepare(
            'DELETE FROM path_request_tags WHERE created_at < :trim_before'
        );
        $deletePathRequestTags->bindValue(
            ':trim_before',
            $now - $this->maintenanceInt('path_request_tag_ttl_seconds', 30),
            PDO::PARAM_INT
        );
        $deletePathRequestTags->execute();
        $trimmedPathRequestTags = $deletePathRequestTags->rowCount();

        // ── Reverse path TTL cleanup ─────────────────────────────────
        $deleteReversePaths = $this->db->prepare(
            'DELETE FROM reverse_path_entries WHERE created_at < :trim_before'
        );
        $deleteReversePaths->bindValue(
            ':trim_before',
            $now - $this->maintenanceInt('reverse_path_ttl_seconds', 480),
            PDO::PARAM_INT
        );
        $deleteReversePaths->execute();
        $trimmedReversePaths = $deleteReversePaths->rowCount();

        // ── Reverse paths for offline interfaces ──────────────────────
        // Reverse paths through offline non-peer interfaces can never be
        // used for return routing — drop them.
        if ($offlinePlaceholders !== '') {
            $deleteOfflineReversePaths = $this->db->prepare(
                "DELETE FROM reverse_path_entries
                 WHERE received_interface_id IN ($offlinePlaceholders)
                    OR outbound_interface_id IN ($offlinePlaceholders)"
            );
            $deleteOfflineReversePaths->execute(array_merge($offlineIfaceIds, $offlineIfaceIds));
            $trimmedReversePaths += $deleteOfflineReversePaths->rowCount();
        }

        // ── Link transport for offline interfaces ─────────────────────
        // Link transport entries for offline non-peer interfaces are
        // unreachable — drop them. Peer link transport is preserved
        // (peers can come back online via auto-repair).
        if ($offlinePlaceholders !== '') {
            $deleteOfflineLinkTransport = $this->db->prepare(
                "DELETE FROM link_transport_entries
                 WHERE received_interface_id IN ($offlinePlaceholders)
                    OR outbound_interface_id IN ($offlinePlaceholders)"
            );
            $deleteOfflineLinkTransport->execute(array_merge($offlineIfaceIds, $offlineIfaceIds));
            $trimmedLinkTransport = $deleteOfflineLinkTransport->rowCount();
        } else {
            $trimmedLinkTransport = 0;
        }

        // ── Link transport validation ────────────────────────────────
        // Validate links that have received proofs, and invalidate paths
        // for links that expired without validation.
        $validatedLinkActiveAfter = $now - $this->maintenanceInt('link_transport_ttl_seconds', 900);
        $invalidatedPaths = $this->invalidatePathsForExpiredPendingLinks($now, $validatedLinkActiveAfter);

        $deleteExpiredPendingLinkTransport = $this->db->prepare(
            'DELETE FROM link_transport_entries
             WHERE validated = 0
               AND (
                    (proof_expires_at IS NOT NULL AND proof_expires_at < :now)
                 OR (proof_expires_at IS NULL AND updated_at < :active_after)
               )'
        );
        $deleteExpiredPendingLinkTransport->bindValue(':now', $now, PDO::PARAM_INT);
        $deleteExpiredPendingLinkTransport->bindValue(':active_after', $validatedLinkActiveAfter, PDO::PARAM_INT);
        $deleteExpiredPendingLinkTransport->execute();
        $trimmedLinkTransport += $deleteExpiredPendingLinkTransport->rowCount();

        $deleteInactiveValidatedLinkTransport = $this->db->prepare(
            'DELETE FROM link_transport_entries
             WHERE validated = 1
               AND updated_at < :active_after'
        );
        $deleteInactiveValidatedLinkTransport->bindValue(':active_after', $validatedLinkActiveAfter, PDO::PARAM_INT);
        $deleteInactiveValidatedLinkTransport->execute();
        $trimmedLinkTransport += $deleteInactiveValidatedLinkTransport->rowCount();

        return [
            'interfaces_marked_offline' => $interfacesMarkedOffline,
            'trimmed_inbound_batches' => $trimmedInboundBatches,
            'trimmed_inbound_packets' => $trimmedInboundPackets,
            'trimmed_outbound_batches' => $trimmedOutboundBatches,
            'trimmed_outbound_packets' => $trimmedOutboundPackets,
            'trimmed_wake_events' => $trimmedWakeEvents,
            'failed_orphaned_wake_claims' => $failedOrphanedWakeClaims,
            'trimmed_packet_hashes' => $trimmedPacketHashes,
            'trimmed_expired_paths' => $trimmedExpiredPaths,
            'invalidated_paths' => $invalidatedPaths,
            'trimmed_path_request_tags' => $trimmedPathRequestTags,
            'trimmed_reverse_paths' => $trimmedReversePaths,
            'trimmed_link_transport_entries' => $trimmedLinkTransport,
        ];
    }

    /**
     * Fetch interface_ids for offline non-peer interfaces.
     *
     * Uses a plain SELECT (no locking) instead of a subquery in DELETE
     * statements to avoid shared locks on the interfaces table that can
     * deadlock with concurrent status updates during exchange processing.
     *
     * @return string[]
     */
    private function fetchOfflineNonPeerInterfaceIds(): array
    {
        $stmt = $this->db->prepare(
            "SELECT interface_id FROM interfaces
             WHERE status != 'online' AND peer_url IS NULL"
        );
        $stmt->execute();
        $ids = [];
        while (($row = $stmt->fetch(PDO::FETCH_ASSOC)) !== false) {
            $id = (string) ($row['interface_id'] ?? '');
            if ($id !== '') {
                $ids[] = $id;
            }
        }
        return $ids;
    }

    /**
     * Fetch all non-peer interface_ids (Browser, NAS, etc.).
     *
     * @return string[]
     */
    private function fetchNonPeerInterfaceIds(): array
    {
        $stmt = $this->db->prepare(
            'SELECT interface_id FROM interfaces WHERE peer_url IS NULL'
        );
        $stmt->execute();
        $ids = [];
        while (($row = $stmt->fetch(PDO::FETCH_ASSOC)) !== false) {
            $id = (string) ($row['interface_id'] ?? '');
            if ($id !== '') {
                $ids[] = $id;
            }
        }
        return $ids;
    }

    private function failOrphanedClaimedWakeEvents(): int
    {
        $stmt = $this->db->prepare(
            'SELECT wake_event_id, claimed_by_pid
             FROM wake_events
             WHERE dispatched_at IS NULL
               AND failed_at IS NULL
               AND claimed_at IS NOT NULL
               AND claimed_by_pid IS NOT NULL'
        );
        $stmt->execute();

        $rows = [];
        while (($row = $stmt->fetch(PDO::FETCH_ASSOC)) !== false) {
            if (is_array($row)) {
                $rows[] = $row;
            }
        }

        $failedClaims = 0;
        foreach ($rows as $row) {
            $wakeEventId = (int) ($row['wake_event_id'] ?? 0);
            $claimedByPid = (int) ($row['claimed_by_pid'] ?? 0);
            if ($wakeEventId <= 0 || $claimedByPid <= 0) {
                continue;
            }

            if ($this->isWakeRunnerProcessAlive($claimedByPid)) {
                continue;
            }

            $this->markWakeEventFailed(
                $wakeEventId,
                'claimed wake runner pid ' . $claimedByPid . ' is no longer running'
            );
            $failedClaims++;
        }

        return $failedClaims;
    }

    private function isWakeRunnerProcessAlive(int $pid): bool
    {
        if ($pid <= 0) {
            return false;
        }

        $output = [];
        $exitCode = 0;
        exec('kill -0 ' . $pid . ' >/dev/null 2>&1', $output, $exitCode);
        return $exitCode === 0;
    }
}