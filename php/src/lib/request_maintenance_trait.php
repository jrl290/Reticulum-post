<?php

declare(strict_types=1);

namespace ReticulumPhp;

use PDO;

// Reticulum-php is request-operated. These maintenance helpers only prune and
// reconcile request-path state between exchanges; they do not add retries,
// polling loops, or a second transport mechanism.

trait RequestMaintenanceTrait
{
    public function runMaintenance(int $interfaceStaleAfterSeconds, int $batchTtlSeconds): array
    {
        $now = time();
        $staleBefore = $now - $interfaceStaleAfterSeconds;
        $trimBefore = $now - $batchTtlSeconds;
        $packetHashTrimBefore = $now - $this->maintenanceInt('packet_hash_ttl_seconds', $batchTtlSeconds);

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

        // Peer interfaces count as active if seen recently; repair any that drifted offline.
        // Stale peers (no activity for peer_stale_seconds) are left offline.
        $peerActiveAfter = $now - $this->maintenanceInt('peer_stale_after_seconds', 900);
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

        // Stale peers: mark offline so downstream relay excludes them.
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

        // Maintenance DELETEs use LIMIT to keep lock duration short and avoid
        // deadlocks with concurrent exchange operations. Rows beyond the limit
        // are cleaned up in the next maintenance cycle (every 30 s by default).

        // Pre-fetch offline non-peer interface IDs with a non-locking read.
        // Using subqueries in DELETE statements acquires shared locks on
        // interfaces that can deadlock with concurrent status updates in
        // exchange processing. Fetching IDs first avoids this.
        $offlineIfaceIds = $this->fetchOfflineNonPeerInterfaceIds();
        $offlinePlaceholders = $offlineIfaceIds !== []
            ? implode(',', array_fill(0, count($offlineIfaceIds), '?'))
            : '';

        $deleteInboundBatches = $this->db->prepare(
            'DELETE FROM inbound_batches WHERE created_at < :trim_before LIMIT 1000'
        );
        $deleteInboundBatches->bindValue(':trim_before', $trimBefore, PDO::PARAM_INT);
        $deleteInboundBatches->execute();
        $trimmedInboundBatches = $deleteInboundBatches->rowCount();

        // Inbound packets TTL cleanup: control-plane packets (announces, link
        // requests) flood the table; delete anything older than the TTL.
        $inboundPacketTtl = $this->maintenanceInt('inbound_packet_ttl_seconds', 3600);
        $inboundTrimBefore = $now - $inboundPacketTtl;
        $deleteInboundPackets = $this->db->prepare(
            'DELETE FROM inbound_packets WHERE created_at < :ttl_before LIMIT 1000'
        );
        $deleteInboundPackets->bindValue(':ttl_before', $inboundTrimBefore, PDO::PARAM_INT);
        $deleteInboundPackets->execute();
        $trimmedInboundPackets = $deleteInboundPackets->rowCount();

        // Inbound packets for offline non-peer interfaces: dead weight, drop immediately.
        if ($offlinePlaceholders !== '') {
            $deleteOfflineInboundPackets = $this->db->prepare(
                "DELETE FROM inbound_packets
                 WHERE interface_id IN ($offlinePlaceholders)
                 LIMIT 1000"
            );
            $deleteOfflineInboundPackets->execute($offlineIfaceIds);
            $trimmedInboundPackets += $deleteOfflineInboundPackets->rowCount();
        }

        $deleteOutboundBatches = $this->db->prepare(
            'DELETE FROM outbound_batches WHERE acked_at IS NOT NULL AND acked_at < :trim_before LIMIT 1000'
        );
        $deleteOutboundBatches->bindValue(':trim_before', $trimBefore, PDO::PARAM_INT);
        $deleteOutboundBatches->execute();
        $trimmedOutboundBatches = $deleteOutboundBatches->rowCount();

        if ($offlinePlaceholders !== '') {
            $deleteOfflineOutboundBatches = $this->db->prepare(
                "DELETE FROM outbound_batches
                 WHERE acked_at IS NULL
                   AND interface_id IN ($offlinePlaceholders)
                 LIMIT 1000"
            );
            $deleteOfflineOutboundBatches->execute($offlineIfaceIds);
            $trimmedOutboundBatches += $deleteOfflineOutboundBatches->rowCount();
        }

        $deleteOutboundPackets = $this->db->prepare(
            'DELETE FROM outbound_packets WHERE acked_at IS NOT NULL AND acked_at < :trim_before LIMIT 1000'
        );
        $deleteOutboundPackets->bindValue(':trim_before', $trimBefore, PDO::PARAM_INT);
        $deleteOutboundPackets->execute();
        $trimmedOutboundPackets = $deleteOutboundPackets->rowCount();

        if ($offlinePlaceholders !== '') {
            $deleteOfflineOutboundPackets = $this->db->prepare(
                "DELETE FROM outbound_packets
                 WHERE acked_at IS NULL
                   AND interface_id IN ($offlinePlaceholders)
                 LIMIT 1000"
            );
            $deleteOfflineOutboundPackets->execute($offlineIfaceIds);
            $trimmedOutboundPackets += $deleteOfflineOutboundPackets->rowCount();
        }

        // Stale outbound: packets queued > 1 hour ago that were never delivered.
        // Prevents unbounded accumulation for interfaces that stay "online" but never pull.
        $maxPacketAge = $this->maintenanceInt('max_outbound_packet_age_seconds', 3600);
        $nonPeerIfaceIds = $this->fetchNonPeerInterfaceIds();
        if ($nonPeerIfaceIds !== []) {
            $nonPeerPlaceholders = implode(',', array_fill(0, count($nonPeerIfaceIds), '?'));
            $maxAge = $now - $maxPacketAge;
            $deleteStaleOutboundPackets = $this->db->prepare(
                "DELETE FROM outbound_packets
                 WHERE acked_at IS NULL
                   AND queued_at < ?
                   AND interface_id IN ($nonPeerPlaceholders)
                 LIMIT 1000"
            );
            $deleteStaleOutboundPackets->execute(array_merge([$maxAge], $nonPeerIfaceIds));
            $trimmedOutboundPackets += $deleteStaleOutboundPackets->rowCount();
        }

        $deleteWakeEvents = $this->db->prepare(
            'DELETE FROM wake_events
             WHERE created_at < :trim_before
               AND (dispatched_at IS NOT NULL OR failed_at IS NOT NULL)
             LIMIT 1000'
        );
        $deleteWakeEvents->bindValue(':trim_before', $trimBefore, PDO::PARAM_INT);
        $deleteWakeEvents->execute();
        $trimmedWakeEvents = $deleteWakeEvents->rowCount();

        $failedOrphanedWakeClaims = $this->failOrphanedClaimedWakeEvents();

        $deletePacketHashes = $this->db->prepare(
            'DELETE FROM packet_hashes WHERE first_seen_at < :trim_before LIMIT 1000'
        );
        $deletePacketHashes->bindValue(':trim_before', $packetHashTrimBefore, PDO::PARAM_INT);
        $deletePacketHashes->execute();
        $trimmedPacketHashes = $deletePacketHashes->rowCount();

        $deleteExpiredPaths = $this->db->prepare(
            'DELETE FROM path_entries WHERE expires_at < :expires_before LIMIT 1000'
        );
        $deleteExpiredPaths->bindValue(':expires_before', $now, PDO::PARAM_INT);
        $deleteExpiredPaths->execute();
        $trimmedExpiredPaths = $deleteExpiredPaths->rowCount();

        // Paths through offline non-peer interfaces are dead ends — drop them.
        // Peer interfaces are wake-driven and always viable; keep their paths.
        if ($offlinePlaceholders !== '') {
            $deleteDeadInterfacePaths = $this->db->prepare(
                "DELETE FROM path_entries
                 WHERE interface_id IN ($offlinePlaceholders)
                 LIMIT 1000"
            );
            $deleteDeadInterfacePaths->execute($offlineIfaceIds);
            $trimmedExpiredPaths += $deleteDeadInterfacePaths->rowCount();
        }

        $deletePathRequestTags = $this->db->prepare(
            'DELETE FROM path_request_tags WHERE created_at < :trim_before LIMIT 1000'
        );
        $deletePathRequestTags->bindValue(
            ':trim_before',
            $now - $this->maintenanceInt('path_request_tag_ttl_seconds', $batchTtlSeconds),
            PDO::PARAM_INT
        );
        $deletePathRequestTags->execute();
        $trimmedPathRequestTags = $deletePathRequestTags->rowCount();

        $deleteReversePaths = $this->db->prepare(
            'DELETE FROM reverse_path_entries WHERE created_at < :trim_before LIMIT 1000'
        );
        $deleteReversePaths->bindValue(
            ':trim_before',
            $now - $this->maintenanceInt('reverse_path_ttl_seconds', 480),
            PDO::PARAM_INT
        );
        $deleteReversePaths->execute();
        $trimmedReversePaths = $deleteReversePaths->rowCount();

        if ($offlinePlaceholders !== '') {
            $deleteOfflineReversePaths = $this->db->prepare(
                "DELETE FROM reverse_path_entries
                 WHERE received_interface_id IN ($offlinePlaceholders)
                    OR outbound_interface_id IN ($offlinePlaceholders)
                 LIMIT 1000"
            );
            $deleteOfflineReversePaths->execute(array_merge($offlineIfaceIds, $offlineIfaceIds));
            $trimmedReversePaths += $deleteOfflineReversePaths->rowCount();
        }

        if ($offlinePlaceholders !== '') {
            $deleteOfflineLinkTransport = $this->db->prepare(
                "DELETE FROM link_transport_entries
                 WHERE received_interface_id IN ($offlinePlaceholders)
                    OR outbound_interface_id IN ($offlinePlaceholders)
                 LIMIT 1000"
            );
            $deleteOfflineLinkTransport->execute(array_merge($offlineIfaceIds, $offlineIfaceIds));
            $trimmedLinkTransport = $deleteOfflineLinkTransport->rowCount();
        } else {
            $trimmedLinkTransport = 0;
        }

        $validatedLinkActiveAfter = $now - $this->maintenanceInt('link_transport_ttl_seconds', 900);
        $invalidatedPaths = $this->invalidatePathsForExpiredPendingLinks($now, $validatedLinkActiveAfter);

        $deleteExpiredPendingLinkTransport = $this->db->prepare(
            'DELETE FROM link_transport_entries
             WHERE validated = 0
               AND (
                    (proof_expires_at IS NOT NULL AND proof_expires_at < :now)
                 OR (proof_expires_at IS NULL AND updated_at < :active_after)
               )
             LIMIT 1000'
        );
        $deleteExpiredPendingLinkTransport->bindValue(':now', $now, PDO::PARAM_INT);
        $deleteExpiredPendingLinkTransport->bindValue(':active_after', $validatedLinkActiveAfter, PDO::PARAM_INT);
        $deleteExpiredPendingLinkTransport->execute();
        $trimmedLinkTransport += $deleteExpiredPendingLinkTransport->rowCount();

        $deleteInactiveValidatedLinkTransport = $this->db->prepare(
            'DELETE FROM link_transport_entries
             WHERE validated = 1
               AND updated_at < :active_after
             LIMIT 1000'
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