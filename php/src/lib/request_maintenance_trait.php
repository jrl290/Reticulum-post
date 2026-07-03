<?php

declare(strict_types=1);

namespace ReticulumPhp;

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
            'UPDATE interfaces SET status = :status WHERE status != :status AND last_seen_at < :stale_before'
        );
        $staleStmt->bindValue(':status', 'offline', SQLITE3_TEXT);
        $staleStmt->bindValue(':stale_before', $staleBefore, SQLITE3_INTEGER);
        $staleStmt->execute();
        $interfacesMarkedOffline = $this->db->changes();

        $deleteInbound = $this->db->prepare(
            'DELETE FROM inbound_batches WHERE created_at < :trim_before'
        );
        $deleteInbound->bindValue(':trim_before', $trimBefore, SQLITE3_INTEGER);
        $deleteInbound->execute();
        $trimmedInboundBatches = $this->db->changes();

        $deleteOutboundBatches = $this->db->prepare(
            'DELETE FROM outbound_batches WHERE acked_at IS NOT NULL AND acked_at < :trim_before'
        );
        $deleteOutboundBatches->bindValue(':trim_before', $trimBefore, SQLITE3_INTEGER);
        $deleteOutboundBatches->execute();
        $trimmedOutboundBatches = $this->db->changes();

        $deleteOfflineOutboundBatches = $this->db->prepare(
            "DELETE FROM outbound_batches
             WHERE acked_at IS NULL
               AND interface_id IN (SELECT interface_id FROM interfaces WHERE status != 'online')"
        );
        $deleteOfflineOutboundBatches->execute();
        $trimmedOutboundBatches += $this->db->changes();

        $deleteOutboundPackets = $this->db->prepare(
            'DELETE FROM outbound_packets WHERE acked_at IS NOT NULL AND acked_at < :trim_before'
        );
        $deleteOutboundPackets->bindValue(':trim_before', $trimBefore, SQLITE3_INTEGER);
        $deleteOutboundPackets->execute();
        $trimmedOutboundPackets = $this->db->changes();

        $deleteOfflineOutboundPackets = $this->db->prepare(
            "DELETE FROM outbound_packets
             WHERE acked_at IS NULL
               AND interface_id IN (SELECT interface_id FROM interfaces WHERE status != 'online')"
        );
        $deleteOfflineOutboundPackets->execute();
        $trimmedOutboundPackets += $this->db->changes();

        $deleteWakeEvents = $this->db->prepare(
            'DELETE FROM wake_events
             WHERE created_at < :trim_before
               AND (dispatched_at IS NOT NULL OR failed_at IS NOT NULL)'
        );
        $deleteWakeEvents->bindValue(':trim_before', $trimBefore, SQLITE3_INTEGER);
        $deleteWakeEvents->execute();
        $trimmedWakeEvents = $this->db->changes();

        $failedOrphanedWakeClaims = $this->failOrphanedClaimedWakeEvents();

        $deletePacketHashes = $this->db->prepare(
            'DELETE FROM packet_hashes WHERE first_seen_at < :trim_before'
        );
        $deletePacketHashes->bindValue(':trim_before', $packetHashTrimBefore, SQLITE3_INTEGER);
        $deletePacketHashes->execute();
        $trimmedPacketHashes = $this->db->changes();

        $deleteExpiredPaths = $this->db->prepare(
            'DELETE FROM path_entries WHERE expires_at < :expires_before'
        );
        $deleteExpiredPaths->bindValue(':expires_before', $now, SQLITE3_INTEGER);
        $deleteExpiredPaths->execute();
        $trimmedExpiredPaths = $this->db->changes();

        $deletePathRequestTags = $this->db->prepare(
            'DELETE FROM path_request_tags WHERE created_at < :trim_before'
        );
        $deletePathRequestTags->bindValue(
            ':trim_before',
            $now - $this->maintenanceInt('path_request_tag_ttl_seconds', $batchTtlSeconds),
            SQLITE3_INTEGER
        );
        $deletePathRequestTags->execute();
        $trimmedPathRequestTags = $this->db->changes();

        $deleteReversePaths = $this->db->prepare(
            'DELETE FROM reverse_path_entries WHERE created_at < :trim_before'
        );
        $deleteReversePaths->bindValue(
            ':trim_before',
            $now - $this->maintenanceInt('reverse_path_ttl_seconds', 480),
            SQLITE3_INTEGER
        );
        $deleteReversePaths->execute();
        $trimmedReversePaths = $this->db->changes();

        $deleteOfflineReversePaths = $this->db->prepare(
            "DELETE FROM reverse_path_entries
             WHERE received_interface_id IN (SELECT interface_id FROM interfaces WHERE status != 'online')
                OR outbound_interface_id IN (SELECT interface_id FROM interfaces WHERE status != 'online')"
        );
        $deleteOfflineReversePaths->execute();
        $trimmedReversePaths += $this->db->changes();

        $deleteOfflineLinkTransport = $this->db->prepare(
            "DELETE FROM link_transport_entries
             WHERE received_interface_id IN (SELECT interface_id FROM interfaces WHERE status != 'online')
                OR outbound_interface_id IN (SELECT interface_id FROM interfaces WHERE status != 'online')"
        );
        $deleteOfflineLinkTransport->execute();
        $trimmedLinkTransport = $this->db->changes();

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
        $deleteExpiredPendingLinkTransport->bindValue(':now', $now, SQLITE3_INTEGER);
        $deleteExpiredPendingLinkTransport->bindValue(':active_after', $validatedLinkActiveAfter, SQLITE3_INTEGER);
        $deleteExpiredPendingLinkTransport->execute();
        $trimmedLinkTransport += $this->db->changes();

        $deleteInactiveValidatedLinkTransport = $this->db->prepare(
            'DELETE FROM link_transport_entries
             WHERE validated = 1
               AND updated_at < :active_after'
        );
        $deleteInactiveValidatedLinkTransport->bindValue(':active_after', $validatedLinkActiveAfter, SQLITE3_INTEGER);
        $deleteInactiveValidatedLinkTransport->execute();
        $trimmedLinkTransport += $this->db->changes();

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
        $result = $stmt->execute();
        $rows = [];

        while (($row = $result->fetchArray(SQLITE3_ASSOC)) !== false) {
            if (is_array($row)) {
                $rows[] = $row;
            }
        }

        if ($result instanceof SQLite3Result) {
            $result->finalize();
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