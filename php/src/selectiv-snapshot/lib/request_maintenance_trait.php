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

        $deleteInbound = $this->db->prepare(
            'DELETE FROM inbound_batches WHERE created_at < :trim_before'
        );
        $deleteInbound->bindValue(':trim_before', $trimBefore, PDO::PARAM_INT);
        $deleteInbound->execute();
        $trimmedInboundBatches = $deleteInbound->rowCount();

        $deleteOutboundBatches = $this->db->prepare(
            'DELETE FROM outbound_batches WHERE acked_at IS NOT NULL AND acked_at < :trim_before'
        );
        $deleteOutboundBatches->bindValue(':trim_before', $trimBefore, PDO::PARAM_INT);
        $deleteOutboundBatches->execute();
        $trimmedOutboundBatches = $deleteOutboundBatches->rowCount();

        $deleteOfflineOutboundBatches = $this->db->prepare(
            "DELETE FROM outbound_batches
             WHERE acked_at IS NULL
               AND interface_id IN (SELECT interface_id FROM interfaces WHERE status != 'online')"
        );
        $deleteOfflineOutboundBatches->execute();
        $trimmedOutboundBatches += $deleteOfflineOutboundBatches->rowCount();

        $deleteOutboundPackets = $this->db->prepare(
            'DELETE FROM outbound_packets WHERE acked_at IS NOT NULL AND acked_at < :trim_before'
        );
        $deleteOutboundPackets->bindValue(':trim_before', $trimBefore, PDO::PARAM_INT);
        $deleteOutboundPackets->execute();
        $trimmedOutboundPackets = $deleteOutboundPackets->rowCount();

        $deleteOfflineOutboundPackets = $this->db->prepare(
            "DELETE FROM outbound_packets
             WHERE acked_at IS NULL
               AND interface_id IN (SELECT interface_id FROM interfaces WHERE status != 'online')"
        );
        $deleteOfflineOutboundPackets->execute();
        $trimmedOutboundPackets += $deleteOfflineOutboundPackets->rowCount();

        // Stale outbound: packets queued > 1 hour ago that were never delivered.\n        // Prevents unbounded accumulation for interfaces that stay \"online\" but never pull.\n        $maxPacketAge = $this->maintenanceInt('max_outbound_packet_age_seconds', 3600);\n        $deleteStaleOutboundPackets = $this->db->prepare(\n            'DELETE FROM outbound_packets\n             WHERE acked_at IS NULL\n               AND queued_at < :max_age\n               AND interface_id IN (SELECT interface_id FROM interfaces WHERE peer_url IS NULL)'\n        );\n        $deleteStaleOutboundPackets->bindValue(':max_age', $now - $maxPacketAge, PDO::PARAM_INT);\n        $deleteStaleOutboundPackets->execute();\n        $trimmedOutboundPackets += $deleteStaleOutboundPackets->rowCount();

        $deleteWakeEvents = $this->db->prepare(
            'DELETE FROM wake_events
             WHERE created_at < :trim_before
               AND (dispatched_at IS NOT NULL OR failed_at IS NOT NULL)'
        );
        $deleteWakeEvents->bindValue(':trim_before', $trimBefore, PDO::PARAM_INT);
        $deleteWakeEvents->execute();
        $trimmedWakeEvents = $deleteWakeEvents->rowCount();

        $failedOrphanedWakeClaims = $this->failOrphanedClaimedWakeEvents();

        $deletePacketHashes = $this->db->prepare(
            'DELETE FROM packet_hashes WHERE first_seen_at < :trim_before'
        );
        $deletePacketHashes->bindValue(':trim_before', $packetHashTrimBefore, PDO::PARAM_INT);
        $deletePacketHashes->execute();
        $trimmedPacketHashes = $deletePacketHashes->rowCount();

        $deleteExpiredPaths = $this->db->prepare(
            'DELETE FROM path_entries WHERE expires_at < :expires_before'
        );
        $deleteExpiredPaths->bindValue(':expires_before', $now, PDO::PARAM_INT);
        $deleteExpiredPaths->execute();
        $trimmedExpiredPaths = $deleteExpiredPaths->rowCount();

        // Paths through offline non-peer interfaces are dead ends — drop them.
        // Peer interfaces are wake-driven and always viable; keep their paths.
        $deleteDeadInterfacePaths = $this->db->prepare(
            "DELETE FROM path_entries
             WHERE interface_id IN (
                 SELECT interface_id FROM interfaces
                 WHERE status != 'online' AND peer_url IS NULL
             )"
        );
        $deleteDeadInterfacePaths->execute();
        $trimmedExpiredPaths += $deleteDeadInterfacePaths->rowCount();

        $deletePathRequestTags = $this->db->prepare(
            'DELETE FROM path_request_tags WHERE created_at < :trim_before'
        );
        $deletePathRequestTags->bindValue(
            ':trim_before',
            $now - $this->maintenanceInt('path_request_tag_ttl_seconds', $batchTtlSeconds),
            PDO::PARAM_INT
        );
        $deletePathRequestTags->execute();
        $trimmedPathRequestTags = $deletePathRequestTags->rowCount();

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

        $deleteOfflineReversePaths = $this->db->prepare(
            "DELETE FROM reverse_path_entries
             WHERE received_interface_id IN (SELECT interface_id FROM interfaces WHERE status != 'online')
                OR outbound_interface_id IN (SELECT interface_id FROM interfaces WHERE status != 'online')"
        );
        $deleteOfflineReversePaths->execute();
        $trimmedReversePaths += $deleteOfflineReversePaths->rowCount();

        $deleteOfflineLinkTransport = $this->db->prepare(
            "DELETE FROM link_transport_entries
             WHERE received_interface_id IN (SELECT interface_id FROM interfaces WHERE status != 'online')
                OR outbound_interface_id IN (SELECT interface_id FROM interfaces WHERE status != 'online')"
        );
        $deleteOfflineLinkTransport->execute();
        $trimmedLinkTransport = $deleteOfflineLinkTransport->rowCount();

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