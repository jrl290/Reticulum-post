<?php

declare(strict_types=1);

namespace ReticulumPhp;

use PDO;

// Reticulum-php is request-operated. These relay and link-transport helpers
// only prepare state and batches for the next authenticated exchange; they do
// not create a second push transport path.

trait RequestRelayRoutingTrait
{
    private function shouldReverseRouteProofPacket(array $packet): bool
    {
        return (int) ($packet['packet_type'] ?? -1) === 3
            && (int) ($packet['context'] ?? -1) !== 0xFF;
    }

    private function shouldTransportLinkRequestProofPacket(array $packet): bool
    {
        return (int) ($packet['packet_type'] ?? -1) === 3
            && (int) ($packet['context'] ?? -1) === 0xFF;
    }

    private function shouldRelayLinkTransportPacket(array $packet): bool
    {
        return (int) ($packet['packet_type'] ?? -1) !== 1
            && (int) ($packet['packet_type'] ?? -1) !== 2
            && (int) ($packet['context'] ?? -1) !== 0xFF
            && $this->hasValidatedLinkTransportEntry((string) ($packet['destination_hash_hex'] ?? ''));
    }

    private function relayPacketBase64(string $rawBase64, array $packet): string
    {
        $raw = base64_decode($rawBase64, true);
        if (!is_string($raw) || strlen($raw) < 2) {
            throw new RuntimeException('Relayed packet raw payload is invalid');
        }

        $forwardedHops = max(0, min(255, ((int) ($packet['hops'] ?? 0)) + 1));
        if ((int) ($packet['packet_type'] ?? -1) === 1) {
            return base64_encode($this->transportedAnnounceRelayRaw($packet, $forwardedHops));
        }

        $forwardedRaw = $this->incrementedHopRaw($raw, $forwardedHops);
        $path = $this->usablePathEntry((string) ($packet['destination_hash_hex'] ?? ''));

        if ((int) ($packet['header_type'] ?? 0) === 1
            && (string) ($packet['transport_id_hex'] ?? '') === $this->transportIdentityHashHex()) {
            if ($path !== null) {
                $forwardedRaw = $this->rewriteTransportRelayRaw($raw, $packet, $path, $forwardedHops);
            }
        } elseif ((int) ($packet['header_type'] ?? 0) === 0 && $path !== null) {
            $forwardedRaw = $this->wrapOutboundHttpExchangeRelayRaw($raw, $packet, $path, $forwardedHops);
        }

        return base64_encode($forwardedRaw);
    }

    private function proofRelayPacketBase64(string $rawBase64, array $packet): string
    {
        $raw = base64_decode($rawBase64, true);
        if (!is_string($raw) || strlen($raw) < 2) {
            throw new RuntimeException('Relayed proof raw payload is invalid');
        }

        $forwardedHops = max(0, min(255, ((int) ($packet['hops'] ?? 0)) + 1));
        return base64_encode($this->incrementedHopRaw($raw, $forwardedHops));
    }

    private function incrementedHopRaw(string $raw, int $forwardedHops): string
    {
        return $raw[0] . chr($forwardedHops) . substr($raw, 2);
    }

    private function transportedAnnounceRelayRaw(array $packet, int $forwardedHops): string
    {
        $payload = base64_decode((string) ($packet['payload_base64'] ?? ''), true);
        $destinationHash = hex2bin((string) ($packet['destination_hash_hex'] ?? ''));
        $transportIdentity = hex2bin($this->transportIdentityHashHex());
        if (!is_string($payload) || !is_string($destinationHash) || strlen($destinationHash) !== 16) {
            throw new RuntimeException('Relayed announce payload or destination is invalid');
        }

        if (!is_string($transportIdentity) || strlen($transportIdentity) !== 16) {
            throw new RuntimeException('Transport identity hash is invalid for announce relay');
        }

        $flags = (((int) ($packet['context_flag'] ?? 0)) << 5)
            | (1 << 6)
            | (1 << 4)
            | (((int) ($packet['destination_type'] ?? 0)) << 2)
            | ((int) ($packet['packet_type'] ?? 0));

        return chr($flags)
            . chr($forwardedHops)
            . $transportIdentity
            . $destinationHash
            . chr((int) ($packet['context'] ?? 0))
            . $payload;
    }

    private function rewriteTransportRelayRaw(string $raw, array $packet, array $path, int $forwardedHops): string
    {
        $remainingHops = (int) ($path['hops'] ?? 0);
        if ($remainingHops > 1) {
            $nextHop = hex2bin((string) ($path['next_hop_hex'] ?? ''));
            if (!is_string($nextHop) || strlen($nextHop) !== 16) {
                throw new RuntimeException('Path next hop is invalid for transport relay');
            }

            return $raw[0] . chr($forwardedHops) . $nextHop . substr($raw, 18);
        }

        if ($remainingHops === 1) {
            $newFlags = chr((((int) ($packet['context_flag'] ?? 0)) << 5)
                | (((int) ($packet['destination_type'] ?? 0)) << 2)
                | ((int) ($packet['packet_type'] ?? 0)));

            return $newFlags . chr($forwardedHops) . substr($raw, 18);
        }

        return $this->incrementedHopRaw($raw, $forwardedHops);
    }

    private function wrapOutboundHttpExchangeRelayRaw(string $raw, array $packet, array $path, int $forwardedHops): string
    {
        $interfaceId = (string) ($path['interface_id'] ?? '');
        if ($interfaceId === '') {
            return $this->incrementedHopRaw($raw, $forwardedHops);
        }

        $metadata = $this->interfaceMetadata($interfaceId);
        if ((string) ($metadata['transport'] ?? '') !== 'http-exchange') {
            return $this->incrementedHopRaw($raw, $forwardedHops);
        }

        $nextHopHex = strtolower((string) ($path['next_hop_hex'] ?? ''));
        $destinationHashHex = strtolower((string) ($packet['destination_hash_hex'] ?? ''));
        $remainingHops = (int) ($path['hops'] ?? 0);
        if ($nextHopHex === '') {
            return $this->incrementedHopRaw($raw, $forwardedHops);
        }

        if ($remainingHops <= 1 && $destinationHashHex !== '' && hash_equals($nextHopHex, $destinationHashHex)) {
            return $this->incrementedHopRaw($raw, $forwardedHops);
        }

        $nextHop = hex2bin($nextHopHex);
        if (!is_string($nextHop) || strlen($nextHop) !== 16) {
            throw new RuntimeException('Path next hop is invalid for http-exchange relay');
        }

        $flags = ord($raw[0]);
        $transportFlags = ($flags & 0x20) | 0x40 | 0x10 | ($flags & 0x0F);

        return chr($transportFlags) . chr($forwardedHops) . $nextHop . substr($raw, 2);
    }

    private function rememberLinkTransportEntry(
        string $linkIdHex,
        string $receivedInterfaceId,
        string $outboundInterfaceId,
        string $nextHopHex,
        int $remainingHops,
        int $takenHops,
        string $destinationHashHex
    ): void {
        $proofExpiresAt = $this->linkRequestProofExpiresAt($receivedInterfaceId, $remainingHops);
        $sql = 'INSERT INTO link_transport_entries (
                link_id_hex,
                received_interface_id,
                outbound_interface_id,
                next_hop_hex,
                remaining_hops,
                taken_hops,
                destination_hash_hex,
                validated,
                proof_expires_at,
                updated_at
            ) VALUES (
                :link_id_hex,
                :received_interface_id,
                :outbound_interface_id,
                :next_hop_hex,
                :remaining_hops,
                :taken_hops,
                :destination_hash_hex,
                0,
                :proof_expires_at,
                :updated_at
            )
            ON CONFLICT(link_id_hex, outbound_interface_id) DO UPDATE SET
                received_interface_id = excluded.received_interface_id,
                next_hop_hex = excluded.next_hop_hex,
                remaining_hops = excluded.remaining_hops,
                taken_hops = excluded.taken_hops,
                destination_hash_hex = excluded.destination_hash_hex,
                validated = 0,
                proof_expires_at = excluded.proof_expires_at,
                updated_at = excluded.updated_at';
        $sql = Database::upsertSql($sql, $this->backend);
        $stmt = $this->db->prepare($sql);
        $stmt->bindValue(':link_id_hex', $linkIdHex, PDO::PARAM_STR);
        $stmt->bindValue(':received_interface_id', $receivedInterfaceId, PDO::PARAM_STR);
        $stmt->bindValue(':outbound_interface_id', $outboundInterfaceId, PDO::PARAM_STR);
        $stmt->bindValue(':next_hop_hex', $nextHopHex, PDO::PARAM_STR);
        $stmt->bindValue(':remaining_hops', $remainingHops, PDO::PARAM_INT);
        $stmt->bindValue(':taken_hops', $takenHops, PDO::PARAM_INT);
        $stmt->bindValue(':destination_hash_hex', $destinationHashHex, PDO::PARAM_STR);
        $stmt->bindValue(':proof_expires_at', $proofExpiresAt, PDO::PARAM_INT);
        $stmt->bindValue(':updated_at', time(), PDO::PARAM_INT);
        $stmt->execute();
    }

    private function linkTransportEntryForOutbound(string $linkIdHex, string $outboundInterfaceId): ?array
    {
        $now = time();
        $stmt = $this->db->prepare(
                        "SELECT lte.*
                         FROM link_transport_entries AS lte
                         JOIN interfaces AS received_if ON received_if.interface_id = lte.received_interface_id
                         JOIN interfaces AS outbound_if ON outbound_if.interface_id = lte.outbound_interface_id
                         WHERE lte.link_id_hex = :link_id_hex
                             AND lte.outbound_interface_id = :outbound_interface_id
                             AND lte.validated = 0
                             AND received_if.status = 'online'
                             AND outbound_if.status = 'online'
                             AND (
                                  (lte.proof_expires_at IS NOT NULL AND lte.proof_expires_at >= :now)
                               OR (lte.proof_expires_at IS NULL AND lte.updated_at >= :active_after)
                             )"
        );
        $stmt->bindValue(':link_id_hex', $linkIdHex, PDO::PARAM_STR);
        $stmt->bindValue(':outbound_interface_id', $outboundInterfaceId, PDO::PARAM_STR);
        $stmt->bindValue(':now', $now, PDO::PARAM_INT);
        $stmt->bindValue(':active_after', $this->validatedLinkTransportActiveAfter($now), PDO::PARAM_INT);
        $row = $stmt->execute(); $row = $stmt->fetch(PDO::FETCH_ASSOC);

        return is_array($row) ? $row : null;
    }

    private function linkTransportEntries(string $linkIdHex, bool $validatedOnly = false): array
    {
        $now = time();
        $query = "SELECT lte.*
                  FROM link_transport_entries AS lte
                  JOIN interfaces AS received_if ON received_if.interface_id = lte.received_interface_id
                  JOIN interfaces AS outbound_if ON outbound_if.interface_id = lte.outbound_interface_id
                  WHERE lte.link_id_hex = :link_id_hex
                    AND received_if.status = 'online'
                    AND outbound_if.status = 'online'";
        if ($validatedOnly) {
            $query .= ' AND lte.validated = 1 AND lte.updated_at >= :active_after';
        } else {
            $query .= ' AND ((lte.validated = 1 AND lte.updated_at >= :active_after)'
                . ' OR (lte.validated = 0 AND ((lte.proof_expires_at IS NOT NULL AND lte.proof_expires_at >= :now)'
                . ' OR (lte.proof_expires_at IS NULL AND lte.updated_at >= :active_after))))';
        }

        $stmt = $this->db->prepare($query);
        $stmt->bindValue(':link_id_hex', $linkIdHex, PDO::PARAM_STR);
        $stmt->bindValue(':active_after', $this->validatedLinkTransportActiveAfter($now), PDO::PARAM_INT);
        if (!$validatedOnly) {
            $stmt->bindValue(':now', $now, PDO::PARAM_INT);
        }
        $stmt->execute();

        $entries = [];
        while (($row = $stmt->fetch(PDO::FETCH_ASSOC)) !== false) {
            if (!is_array($row)) {
                continue;
            }

            $entries[] = $row;
        }

        return $entries;
    }

    private function hasValidatedLinkTransportEntry(string $linkIdHex): bool
    {
        if ($linkIdHex === '') {
            return false;
        }

        $stmt = $this->db->prepare(
            'SELECT 1
             FROM link_transport_entries
             WHERE link_id_hex = :link_id_hex
               AND validated = 1
               AND updated_at >= :active_after
             LIMIT 1'
        );
        $stmt->bindValue(':link_id_hex', $linkIdHex, PDO::PARAM_STR);
        $stmt->bindValue(':active_after', $this->validatedLinkTransportActiveAfter(), PDO::PARAM_INT);
        $row = $stmt->execute(); $row = $stmt->fetch(PDO::FETCH_NUM);

        return $row !== false;
    }

    private function touchLinkTransportEntry(string $linkIdHex, string $outboundInterfaceId, ?bool $validated = null): void
    {
        $query = 'UPDATE link_transport_entries SET updated_at = :updated_at';
        if ($validated !== null) {
            $query .= ', validated = :validated';
            if ($validated) {
                $query .= ', proof_expires_at = NULL';
            }
        }
        $query .= ' WHERE link_id_hex = :link_id_hex AND outbound_interface_id = :outbound_interface_id';

        $stmt = $this->db->prepare($query);
        $stmt->bindValue(':updated_at', time(), PDO::PARAM_INT);
        if ($validated !== null) {
            $stmt->bindValue(':validated', $validated ? 1 : 0, PDO::PARAM_INT);
        }
        $stmt->bindValue(':link_id_hex', $linkIdHex, PDO::PARAM_STR);
        $stmt->bindValue(':outbound_interface_id', $outboundInterfaceId, PDO::PARAM_STR);
        $stmt->execute();
    }

    private function deleteLinkTransportEntries(string $linkIdHex): void
    {
        $stmt = $this->db->prepare(
            'DELETE FROM link_transport_entries WHERE link_id_hex = :link_id_hex'
        );
        $stmt->bindValue(':link_id_hex', $linkIdHex, PDO::PARAM_STR);
        $stmt->execute();
    }

    private function rememberReversePath(string $truncatedHashHex, string $receivedInterfaceId, string $outboundInterfaceId): void
    {
        $sql = 'INSERT INTO reverse_path_entries (
                truncated_hash_hex,
                received_interface_id,
                outbound_interface_id,
                created_at
            ) VALUES (
                :truncated_hash_hex,
                :received_interface_id,
                :outbound_interface_id,
                :created_at
            )
            ON CONFLICT(truncated_hash_hex, outbound_interface_id) DO UPDATE SET
                received_interface_id = excluded.received_interface_id,
                created_at = excluded.created_at';
        $sql = Database::upsertSql($sql, $this->backend);
        $stmt = $this->db->prepare($sql);
        $stmt->bindValue(':truncated_hash_hex', $truncatedHashHex, PDO::PARAM_STR);
        $stmt->bindValue(':received_interface_id', $receivedInterfaceId, PDO::PARAM_STR);
        $stmt->bindValue(':outbound_interface_id', $outboundInterfaceId, PDO::PARAM_STR);
        $stmt->bindValue(':created_at', time(), PDO::PARAM_INT);
        $stmt->execute();
    }

    private function popReversePath(string $truncatedHashHex, string $outboundInterfaceId): ?array
    {
        $select = $this->db->prepare(
                        "SELECT rpe.truncated_hash_hex, rpe.received_interface_id, rpe.outbound_interface_id
                         FROM reverse_path_entries AS rpe
                         JOIN interfaces AS received_if ON received_if.interface_id = rpe.received_interface_id
                         JOIN interfaces AS outbound_if ON outbound_if.interface_id = rpe.outbound_interface_id
                         WHERE rpe.truncated_hash_hex = :truncated_hash_hex
                             AND rpe.outbound_interface_id = :outbound_interface_id
                             AND received_if.status = 'online'
                             AND outbound_if.status = 'online'"
        );
        $select->bindValue(':truncated_hash_hex', $truncatedHashHex, PDO::PARAM_STR);
        $select->bindValue(':outbound_interface_id', $outboundInterfaceId, PDO::PARAM_STR);
        $row = $select->execute(); $row = $select->fetch(PDO::FETCH_ASSOC);
        if (!is_array($row)) {
            return null;
        }

        $delete = $this->db->prepare(
            'DELETE FROM reverse_path_entries
             WHERE truncated_hash_hex = :truncated_hash_hex
               AND outbound_interface_id = :outbound_interface_id'
        );
        $delete->bindValue(':truncated_hash_hex', $truncatedHashHex, PDO::PARAM_STR);
        $delete->bindValue(':outbound_interface_id', $outboundInterfaceId, PDO::PARAM_STR);
        $delete->execute();

        return $row;
    }

    private function relayAcceptedPacket(string $sourceInterfaceId, string $rawBase64, array $packet): int
    {
        $this->queueRelayPathRequestIfNeeded($sourceInterfaceId, $packet);

        $relayPacketBase64 = $this->relayPacketBase64($rawBase64, $packet);
        $targets = $this->relayTargetsForAcceptedPacket($sourceInterfaceId, $packet);
        $queueReason = (int) ($packet['packet_type'] ?? -1) === 1 ? 'relay_announce' : 'relay';

        $queued = 0;
        foreach ($targets as $targetInterfaceId) {
            $this->queueOutboundPacket($targetInterfaceId, $relayPacketBase64, $queueReason, $sourceInterfaceId);
            if ((int) ($packet['packet_type'] ?? -1) === 2) {
                $this->rememberLinkTransportRelay($sourceInterfaceId, $targetInterfaceId, $rawBase64, $packet);
            } elseif ((int) ($packet['packet_type'] ?? -1) !== 1) {
                $this->rememberReversePath((string) $packet['truncated_hash_hex'], $sourceInterfaceId, $targetInterfaceId);
            }
            $queued++;
        }

        return $queued;
    }

    private function queueRelayPathRequestIfNeeded(string $sourceInterfaceId, array $packet): void
    {
        if ((int) ($packet['packet_type'] ?? -1) === 1) {
            return;
        }

        $destinationHashHex = (string) ($packet['destination_hash_hex'] ?? '');
        if ($destinationHashHex === '' || $this->usablePathEntry($destinationHashHex) !== null) {
            return;
        }

        $destinationHash = hex2bin($destinationHashHex);
        $controlHash = hex2bin($this->pathRequestControlHashHex());
        if (!is_string($destinationHash) || strlen($destinationHash) !== 16) {
            throw new RuntimeException('relay path request destination hash must be 16 bytes');
        }

        if (!is_string($controlHash) || strlen($controlHash) !== 16) {
            throw new RuntimeException('relay path request control hash must be 16 bytes');
        }

        $targets = $this->activePeerInterfaceIds($sourceInterfaceId);
        if ($targets === []) {
            return;
        }

        $payload = $destinationHash . random_bytes(8);
        $raw = chr(0x08) . chr(0x00) . $controlHash . chr(0x00) . $payload;
        $packetBase64 = base64_encode($raw);

        foreach ($targets as $targetInterfaceId) {
            $this->queueOutboundPacket($targetInterfaceId, $packetBase64, 'relay_path_request', $sourceInterfaceId);
        }
    }

    private function forwardPathRequestPacket(string $sourceInterfaceId, string $rawBase64, array $packet): int
    {
        $targets = $this->activePeerInterfaceIds($sourceInterfaceId);
        if ($targets === []) {
            return 0;
        }

        $relayPacketBase64 = $this->relayPacketBase64($rawBase64, $packet);
        foreach ($targets as $targetInterfaceId) {
            $this->queueOutboundPacket($targetInterfaceId, $relayPacketBase64, 'path_request_forward', $sourceInterfaceId);
        }

        return count($targets);
    }

    private function replayCachedAnnouncePacket(string $sourceInterfaceId, string $rawBase64): int
    {
        $raw = base64_decode($rawBase64, true);
        if (!is_string($raw)) {
            return 0;
        }

        $packet = PacketParser::parseRaw($raw);
        [$announceStatus, $announceReason] = $this->processAcceptedAnnounce($sourceInterfaceId, $packet);
        $packet['announce_status'] = $announceStatus;
        $packet['announce_reason'] = $announceReason;
        if ($announceStatus === 'invalid') {
            return 0;
        }

        return $this->relayAcceptedPacket($sourceInterfaceId, $rawBase64, $packet);
    }

    private function rememberLinkTransportRelay(string $sourceInterfaceId, string $targetInterfaceId, string $rawBase64, array $packet): void
    {
        $destinationHashHex = (string) ($packet['destination_hash_hex'] ?? '');
        $path = $this->usablePathEntry($destinationHashHex);
        if ($path === null) {
            return;
        }

        if ((string) ($path['interface_id'] ?? '') !== $targetInterfaceId) {
            return;
        }

        $linkIdHex = $this->linkIdHex($rawBase64, $packet);
        if ($linkIdHex === null) {
            return;
        }

        $this->rememberLinkTransportEntry(
            $linkIdHex,
            $sourceInterfaceId,
            $targetInterfaceId,
            (string) ($path['next_hop_hex'] ?? $destinationHashHex),
            max(1, ((int) ($path['hops'] ?? 0)) + 1),
            $this->transportObservedHops($packet),
            $destinationHashHex
        );
    }

    private function relayProofPacket(string $sourceInterfaceId, string $rawBase64, array $packet): int
    {
        $reversePath = $this->popReversePath((string) ($packet['destination_hash_hex'] ?? ''), $sourceInterfaceId);
        if ($reversePath === null) {
            return 0;
        }

        $relayPacketBase64 = $this->proofRelayPacketBase64($rawBase64, $packet);
        $this->queueOutboundPacket((string) $reversePath['received_interface_id'], $relayPacketBase64, 'proof_relay', $sourceInterfaceId);

        return 1;
    }

    private function relayLinkRequestProofPacket(string $sourceInterfaceId, string $rawBase64, array $packet): int
    {
        $linkIdHex = (string) ($packet['destination_hash_hex'] ?? '');
        $linkEntry = $this->linkTransportEntryForOutbound($linkIdHex, $sourceInterfaceId);
        if ($linkEntry === null) {
            return 0;
        }

        if ($this->transportObservedHops($packet) !== (int) ($linkEntry['remaining_hops'] ?? -1)) {
            return 0;
        }

        if (!$this->validateLinkRequestProof($packet, $linkEntry)) {
            return 0;
        }

        $relayPacketBase64 = $this->proofRelayPacketBase64($rawBase64, $packet);
        $this->queueOutboundPacket((string) $linkEntry['received_interface_id'], $relayPacketBase64, 'lrproof_relay', $sourceInterfaceId);
        $this->touchLinkTransportEntry($linkIdHex, $sourceInterfaceId, true);

        return 1;
    }

    private function relayLinkTransportPacket(string $sourceInterfaceId, string $rawBase64, array $packet): int
    {
        $linkIdHex = (string) ($packet['destination_hash_hex'] ?? '');
        $observedHops = $this->transportObservedHops($packet);
        $targets = [];

        foreach ($this->linkTransportEntries($linkIdHex, true) as $linkEntry) {
            $targetInterfaceId = $this->linkTransportTargetInterfaceId($sourceInterfaceId, $observedHops, $linkEntry);
            if ($targetInterfaceId === null) {
                continue;
            }

            $targets[$targetInterfaceId] = $linkEntry;
        }

        if ($targets === []) {
            return 0;
        }

        $relayPacketBase64 = $this->proofRelayPacketBase64($rawBase64, $packet);
        foreach ($targets as $targetInterfaceId => $linkEntry) {
            $this->queueOutboundPacket($targetInterfaceId, $relayPacketBase64, 'link_relay', $sourceInterfaceId);
            $this->touchLinkTransportEntry((string) $linkEntry['link_id_hex'], (string) $linkEntry['outbound_interface_id']);
        }

        if ((int) ($packet['context'] ?? -1) === 0xFC) {
            $this->deleteLinkTransportEntries($linkIdHex);
        }

        return count($targets);
    }

    private function linkTransportTargetInterfaceId(string $sourceInterfaceId, int $observedHops, array $linkEntry): ?string
    {
        $outboundInterfaceId = (string) ($linkEntry['outbound_interface_id'] ?? '');
        $receivedInterfaceId = (string) ($linkEntry['received_interface_id'] ?? '');
        $remainingHops = (int) ($linkEntry['remaining_hops'] ?? -1);
        $takenHops = (int) ($linkEntry['taken_hops'] ?? -1);

        if ($outboundInterfaceId === '' || $receivedInterfaceId === '') {
            return null;
        }

        if ($outboundInterfaceId === $receivedInterfaceId) {
            if ($observedHops === $remainingHops || $observedHops === $takenHops) {
                return $outboundInterfaceId;
            }

            return null;
        }

        if ($sourceInterfaceId === $outboundInterfaceId && $observedHops === $remainingHops) {
            return $receivedInterfaceId;
        }

        if ($sourceInterfaceId === $receivedInterfaceId && $observedHops === $takenHops) {
            return $outboundInterfaceId;
        }

        return null;
    }

    private function activePeerInterfaceIds(string $sourceInterfaceId): array
    {
        $activeAfter = time() - $this->maintenanceInt('interface_stale_after_seconds', 15);
        $stmt = $this->db->prepare(
            'SELECT interface_id
             FROM interfaces
             WHERE interface_id != :interface_id
               AND status = :status
               AND last_seen_at >= :active_after'
        );
        $stmt->bindValue(':interface_id', $sourceInterfaceId, PDO::PARAM_STR);
        $stmt->bindValue(':status', 'online', PDO::PARAM_STR);
        $stmt->bindValue(':active_after', $activeAfter, PDO::PARAM_INT);
        $stmt->execute();

        $interfaceIds = [];
        while (($row = $stmt->fetch(PDO::FETCH_ASSOC)) !== false) {
            if (!is_array($row)) {
                continue;
            }

            $targetInterfaceId = (string) ($row['interface_id'] ?? '');
            if ($targetInterfaceId === '') {
                continue;
            }

            $interfaceIds[] = $targetInterfaceId;
        }

        return $interfaceIds;
    }

    private function isInterfaceActive(string $interfaceId): bool
    {
        $activeAfter = time() - $this->maintenanceInt('interface_stale_after_seconds', 15);
        $stmt = $this->db->prepare(
            'SELECT 1
             FROM interfaces
             WHERE interface_id = :interface_id
               AND status = :status
               AND last_seen_at >= :active_after
             LIMIT 1'
        );
        $stmt->bindValue(':interface_id', $interfaceId, PDO::PARAM_STR);
        $stmt->bindValue(':status', 'online', PDO::PARAM_STR);
        $stmt->bindValue(':active_after', $activeAfter, PDO::PARAM_INT);
        $row = $stmt->execute(); $row = $stmt->fetch(PDO::FETCH_NUM);

        return $row !== false;
    }

    private function transportObservedHops(array $packet): int
    {
        return max(0, min(255, ((int) ($packet['hops'] ?? 0)) + 1));
    }

    private function linkIdHex(string $rawBase64, array $packet): ?string
    {
        $raw = base64_decode($rawBase64, true);
        $payload = base64_decode((string) ($packet['payload_base64'] ?? ''), true);
        if (!is_string($raw) || strlen($raw) < 2 || !is_string($payload) || strlen($payload) < 64) {
            return null;
        }

        $flags = ord($raw[0]);
        $hashablePart = chr($flags & 0x0F);
        if ((int) ($packet['header_type'] ?? 0) === 1) {
            $hashablePart .= substr($raw, 18);
        } else {
            $hashablePart .= substr($raw, 2);
        }

        if (strlen($payload) > 64) {
            $hashablePart = substr($hashablePart, 0, strlen($hashablePart) - (strlen($payload) - 64));
        }

        return bin2hex(substr(hash('sha256', $hashablePart, true), 0, 16));
    }

    private function validateLinkRequestProof(array $packet, array $linkEntry): bool
    {
        $payload = base64_decode((string) ($packet['payload_base64'] ?? ''), true);
        if (!is_string($payload) || (strlen($payload) !== 96 && strlen($payload) !== 99)) {
            return false;
        }

        $publicKeyHex = $this->knownDestinationPublicKey((string) ($linkEntry['destination_hash_hex'] ?? ''));
        $publicKey = $publicKeyHex === null ? false : hex2bin($publicKeyHex);
        $linkId = hex2bin((string) ($packet['destination_hash_hex'] ?? ''));
        if (!is_string($publicKey) || strlen($publicKey) !== 64 || !is_string($linkId) || strlen($linkId) !== 16) {
            return false;
        }

        $signature = substr($payload, 0, 64);
        $peerPublicKey = substr($payload, 64, 32);
        $signallingBytes = substr($payload, 96);
        $ed25519PublicKey = substr($publicKey, 32, 32);

        return sodium_crypto_sign_verify_detached(
            $signature,
            $linkId . $peerPublicKey . $ed25519PublicKey . $signallingBytes,
            $ed25519PublicKey
        );
    }

    private function validatedLinkTransportActiveAfter(?int $now = null): int
    {
        $currentTime = $now ?? time();
        return $currentTime - $this->maintenanceInt('link_transport_ttl_seconds', 900);
    }

    private function invalidatePathsForExpiredPendingLinks(int $now, int $validatedLinkActiveAfter): int
    {
        $stmt = $this->db->prepare(
            'SELECT destination_hash_hex, outbound_interface_id, taken_hops
             FROM link_transport_entries
             WHERE validated = 0
               AND destination_hash_hex != :empty_destination_hash
               AND (
                    (proof_expires_at IS NOT NULL AND proof_expires_at < :now)
                 OR (proof_expires_at IS NULL AND updated_at < :active_after)
               )'
        );
        $stmt->bindValue(':empty_destination_hash', '', PDO::PARAM_STR);
        $stmt->bindValue(':now', $now, PDO::PARAM_INT);
        $stmt->bindValue(':active_after', $validatedLinkActiveAfter, PDO::PARAM_INT);
        $stmt->execute();

        $invalidated = [];
        while (($row = $stmt->fetch(PDO::FETCH_ASSOC)) !== false) {
            if (!is_array($row)) {
                continue;
            }

            $destinationHashHex = (string) ($row['destination_hash_hex'] ?? '');
            if ($destinationHashHex === '' || isset($invalidated[$destinationHashHex])) {
                continue;
            }

            $path = $this->usablePathEntry($destinationHashHex);
            if ($path === null) {
                continue;
            }

            if ((string) ($path['interface_id'] ?? '') !== (string) ($row['outbound_interface_id'] ?? '')) {
                continue;
            }

            $takenHops = (int) ($row['taken_hops'] ?? PHP_INT_MAX);
            $pathHops = (int) ($path['hops'] ?? PHP_INT_MAX);
            if ($takenHops > 1 && $pathHops > 1) {
                continue;
            }

            $this->deletePathEntry($destinationHashHex);
            $invalidated[$destinationHashHex] = true;
        }

        return count($invalidated);
    }

    private function linkRequestProofExpiresAt(string $receivedInterfaceId, int $remainingHops): int
    {
        $now = time();
        $bitrate = $this->interfaceBitrate($receivedInterfaceId);
        $mtu = max(1, (int) ($this->config['transport']['rns_mtu'] ?? 500));
        $extraProofTimeout = 0.0;
        if ($bitrate !== null && $bitrate > 0) {
            $extraProofTimeout = ($mtu * 8) / $bitrate;
        }

        return (int) ceil(
            $now
            + $extraProofTimeout
            + (TransportConstants::DEFAULT_PER_HOP_TIMEOUT_SECONDS * max(1, $remainingHops))
        );
    }
}