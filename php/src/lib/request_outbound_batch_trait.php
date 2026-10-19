<?php

declare(strict_types=1);

namespace ReticulumPhp;

use PDO;

// Reticulum-php is request-operated. These outbound batch helpers package and
// acknowledge queued packets only within authenticated request exchanges; they
// do not create a separate delivery path.

trait RequestOutboundBatchTrait
{
    public function outboundPacketDeliveryRecord(string $packetHashHex): ?array
    {
        $stmt = $this->db->prepare(
            'SELECT
                packet_id,
                interface_id,
                packet_hash_hex,
                proof_destination_hash_hex,
                destination_hash_hex,
                destination_public_key_hex,
                queue_reason,
                queued_at,
                delivered_at,
                delivered_batch_id,
                acked_at,
                proofed_at
             FROM outbound_packets
             WHERE packet_hash_hex = :packet_hash_hex
             ORDER BY packet_id DESC
             LIMIT 1'
        );
        $stmt->bindValue(':packet_hash_hex', $packetHashHex, PDO::PARAM_STR);
        $row = $stmt->execute(); $row = $stmt->fetch(PDO::FETCH_ASSOC);

        return is_array($row) ? $row : null;
    }

    public function recordInboundProofDelivery(array $packet): ?array
    {
        if ((int) ($packet['packet_type'] ?? -1) !== 3 || (int) ($packet['context'] ?? -1) === 0xFF) {
            return null;
        }

        $proofDestinationHashHex = (string) ($packet['destination_hash_hex'] ?? '');
        if ($proofDestinationHashHex === '') {
            return null;
        }

        $payload = base64_decode((string) ($packet['payload_base64'] ?? ''), true);
        if (!is_string($payload)) {
            return null;
        }

        $proofedAt = time();
        $candidates = $this->outboundProofCandidates($proofDestinationHashHex);
        if ($candidates === []) {
            return null;
        }

        if (strlen($payload) === 96) {
            $proofHashHex = bin2hex(substr($payload, 0, 32));
            $signature = substr($payload, 32);

            foreach ($candidates as $candidate) {
                if (!hash_equals((string) ($candidate['packet_hash_hex'] ?? ''), $proofHashHex)) {
                    continue;
                }

                if (!$this->validateOutboundProofSignature($candidate, $signature)) {
                    continue;
                }

                $this->markOutboundPacketProofed((int) ($candidate['packet_id'] ?? 0), $proofedAt);
                return [
                    'packet_id' => (int) ($candidate['packet_id'] ?? 0),
                    'packet_hash_hex' => $proofHashHex,
                    'proofed_at' => $proofedAt,
                ];
            }

            return null;
        }

        if (strlen($payload) === 64) {
            foreach ($candidates as $candidate) {
                if (!$this->validateOutboundProofSignature($candidate, $payload)) {
                    continue;
                }

                $packetHashHex = (string) ($candidate['packet_hash_hex'] ?? '');
                $this->markOutboundPacketProofed((int) ($candidate['packet_id'] ?? 0), $proofedAt);
                return [
                    'packet_id' => (int) ($candidate['packet_id'] ?? 0),
                    'packet_hash_hex' => $packetHashHex,
                    'proofed_at' => $proofedAt,
                ];
            }
        }

        return null;
    }

    public function acknowledgeOutboundBatches(string $interfaceId, array $batchIds): int
    {
        $acked = 0;
        foreach ($batchIds as $batchId) {
            $select = $this->db->prepare(
                'SELECT packet_ids_json, acked_at FROM outbound_batches WHERE interface_id = :interface_id AND batch_id = :batch_id'
            );
            $select->bindValue(':interface_id', $interfaceId, PDO::PARAM_STR);
            $select->bindValue(':batch_id', $batchId, PDO::PARAM_STR);
            $select->execute();
            $batch = $select->fetch(PDO::FETCH_ASSOC);
            if (!is_array($batch) || $batch['acked_at'] !== null) {
                continue;
            }

            $packetIds = self::decodeJson((string) $batch['packet_ids_json']);
            $now = time();

            $updateBatch = $this->db->prepare(
                'UPDATE outbound_batches SET acked_at = :acked_at WHERE interface_id = :interface_id AND batch_id = :batch_id'
            );
            $updateBatch->bindValue(':acked_at', $now, PDO::PARAM_INT);
            $updateBatch->bindValue(':interface_id', $interfaceId, PDO::PARAM_STR);
            $updateBatch->bindValue(':batch_id', $batchId, PDO::PARAM_STR);
            Database::executeWithRetry($updateBatch, 'ackOutboundBatch');

            foreach ($packetIds as $packetId) {
                $updatePacket = $this->db->prepare(
                    'UPDATE outbound_packets
                     SET acked_at = :acked_at,
                         delivered_at = :delivered_at
                     WHERE packet_id = :packet_id AND interface_id = :interface_id'
                );
                $updatePacket->bindValue(':acked_at', $now, PDO::PARAM_INT);
                $updatePacket->bindValue(':delivered_at', $now, PDO::PARAM_INT);
                $updatePacket->bindValue(':packet_id', (int) $packetId, PDO::PARAM_INT);
                $updatePacket->bindValue(':interface_id', $interfaceId, PDO::PARAM_STR);
                Database::executeWithRetry($updatePacket, 'ackOutboundPackets');
            }

            $acked++;
        }

        return $acked;
    }

    public function fetchOutboundBatch(string $interfaceId, int $maxPackets): array
    {
        $existingBatch = $this->existingUnackedOutboundBatch($interfaceId);
        if ($existingBatch !== null) {
            // Abandon batches that have been unacked for too long.
            // Stale batches block delivery of new packets indefinitely.
            $staleAfter = $this->maintenanceInt('outbound_batch_stale_seconds', 300);
            if (time() - (int) ($existingBatch['created_at'] ?? 0) > $staleAfter) {
                $this->abandonOutboundBatch($interfaceId, (string) $existingBatch['batch_id']);
            } else {
                $packetIds = $this->outboundBatchPacketIds($interfaceId, (string) $existingBatch['batch_id']);
                $packets = $this->outboundPacketPayloads($interfaceId, (string) $existingBatch['batch_id']);

                if ($packetIds !== [] && $packets !== []) {
                    $this->recordOutboundBatchAttempt($interfaceId, $packets);

                    return [
                        'batch_id' => (string) $existingBatch['batch_id'],
                        'packets' => $packets,
                        'more' => $this->pendingOutboundPacketCount($interfaceId) > count($packetIds),
                    ];
                }
            }
        }

                [$packetIds, $packets] = $this->eligibleOutboundPackets($interfaceId, $maxPackets);

        if ($packetIds === []) {
            return [
                'batch_id' => null,
                'packets' => [],
                'more' => false,
            ];
        }

        $batchId = bin2hex(random_bytes(12));
        $now = time();

        $this->assignOutboundBatch($interfaceId, $batchId, $packetIds);

        $insertBatch = $this->db->prepare(
            'INSERT INTO outbound_batches (interface_id, batch_id, packet_ids_json, created_at, acked_at)
             VALUES (:interface_id, :batch_id, :packet_ids_json, :created_at, NULL)'
        );
        $insertBatch->bindValue(':interface_id', $interfaceId, PDO::PARAM_STR);
        $insertBatch->bindValue(':batch_id', $batchId, PDO::PARAM_STR);
        $insertBatch->bindValue(':packet_ids_json', self::encodeJson($packetIds), PDO::PARAM_STR);
        $insertBatch->bindValue(':created_at', $now, PDO::PARAM_INT);
        Database::executeWithRetry($insertBatch, 'storeOutboundBatch');

        $txBytes = 0;
        foreach ($packets as $packetBase64) {
            $txBytes += strlen((string) base64_decode($packetBase64, true));
        }

        $this->recordOutboundBatchAttempt($interfaceId, $packets, $now, $txBytes);

        return [
            'batch_id' => $batchId,
            'packets' => $packets,
            'more' => $this->pendingOutboundPacketCount($interfaceId) > count($packetIds),
        ];
    }

    private function eligibleOutboundPackets(string $interfaceId, int $maxPackets): array
    {
        $stmt = $this->db->prepare(
            'SELECT packet_id, packet_base64, queue_reason, destination_hash_hex
             FROM outbound_packets
             WHERE interface_id = :interface_id
               AND acked_at IS NULL
               AND delivered_batch_id IS NULL
             ORDER BY packet_id ASC'
        );
        $stmt->bindValue(':interface_id', $interfaceId, PDO::PARAM_STR);
        $stmt->execute();

        $packetIds = [];
        $packets = [];
        while (($row = $stmt->fetch(PDO::FETCH_ASSOC)) !== false) {
            if (!is_array($row) || $this->shouldDeferPathlessRelayPacket($interfaceId, $row)) {
                continue;
            }

            $packetIds[] = (int) ($row['packet_id'] ?? 0);
            $packets[] = $this->preparedOutboundPacketBase64($interfaceId, $row);

            if (count($packetIds) >= $maxPackets) {
                break;
            }
        }

        return [$packetIds, $packets];
    }

    private function shouldDeferPathlessRelayPacket(string $interfaceId, array $packetRow): bool
    {
        $metadata = $this->interfaceMetadata($interfaceId);
        if ((string) ($metadata['transport'] ?? '') !== 'http-exchange') {
            return false;
        }

        if ((string) ($packetRow['queue_reason'] ?? '') !== 'relay') {
            return false;
        }

        $destinationHashHex = (string) ($packetRow['destination_hash_hex'] ?? '');
        if ($destinationHashHex === '') {
            return false;
        }

        return $this->usablePathEntry($destinationHashHex) === null;
    }

    private function preparedOutboundPacketBase64(string $interfaceId, array $packetRow): string
    {
        $packetBase64 = (string) ($packetRow['packet_base64'] ?? '');
        if ((string) ($packetRow['queue_reason'] ?? '') !== 'relay') {
            return $packetBase64;
        }

        $metadata = $this->interfaceMetadata($interfaceId);
        if ((string) ($metadata['transport'] ?? '') !== 'http-exchange') {
            return $packetBase64;
        }

        $wrappedRaw = base64_decode($packetBase64, true);
        if (!is_string($wrappedRaw)) {
            throw new RuntimeException('Queued outbound packet base64 is invalid');
        }

        [$raw] = IfacCodec::unwrapForInterface($wrappedRaw, $this->ifacConfig($interfaceId));
        $packet = PacketParser::parseRaw($raw);
        $destinationHashHex = (string) ($packet['destination_hash_hex'] ?? '');
        if ($destinationHashHex === '') {
            return $packetBase64;
        }

        $path = $this->usablePathEntry($destinationHashHex);
        if ($path === null) {
            return $packetBase64;
        }

        $currentHops = max(0, min(255, (int) ($packet['hops'] ?? 0)));
        $rewrittenRaw = $raw;
        if ((int) ($packet['header_type'] ?? 0) === 1
            && (string) ($packet['transport_id_hex'] ?? '') === $this->transportIdentityHashHex()) {
            $rewrittenRaw = $this->rewriteTransportRelayRaw($raw, $packet, $path, $currentHops);
        } elseif ((int) ($packet['header_type'] ?? 0) === 0) {
            $rewrittenRaw = $this->wrapOutboundHttpExchangeRelayRaw($raw, $packet, $path, $currentHops);
        }

        if ($rewrittenRaw === $raw) {
            return $packetBase64;
        }

        $rewrappedPacketBase64 = base64_encode(IfacCodec::wrapForInterface($rewrittenRaw, $this->ifacConfig($interfaceId)));
        $rewrittenPacket = PacketParser::parseRaw($rewrittenRaw);
        $this->updateQueuedOutboundPacketPayload($interfaceId, (int) ($packetRow['packet_id'] ?? 0), $rewrappedPacketBase64, $rewrittenPacket);

        return $rewrappedPacketBase64;
    }

    private function updateQueuedOutboundPacketPayload(string $interfaceId, int $packetId, string $packetBase64, array $packet): void
    {
        if ($packetId <= 0) {
            return;
        }

        $destinationHashHex = (string) ($packet['destination_hash_hex'] ?? '');
        $destinationPublicKeyHex = $destinationHashHex === '' ? null : $this->knownDestinationPublicKey($destinationHashHex);

        $stmt = $this->db->prepare(
            'UPDATE outbound_packets
             SET packet_hash_hex = :packet_hash_hex,
                 proof_destination_hash_hex = :proof_destination_hash_hex,
                 destination_hash_hex = :destination_hash_hex,
                 destination_public_key_hex = :destination_public_key_hex,
                 packet_base64 = :packet_base64
             WHERE packet_id = :packet_id
               AND interface_id = :interface_id
               AND acked_at IS NULL
               AND delivered_batch_id IS NULL'
        );
        $stmt->bindValue(':packet_hash_hex', (string) ($packet['packet_hash_hex'] ?? ''), PDO::PARAM_STR);
        $stmt->bindValue(':proof_destination_hash_hex', (string) ($packet['truncated_hash_hex'] ?? ''), PDO::PARAM_STR);
        $stmt->bindValue(':destination_hash_hex', $destinationHashHex, $destinationHashHex === '' ? PDO::PARAM_NULL : PDO::PARAM_STR);
        $stmt->bindValue(':destination_public_key_hex', $destinationPublicKeyHex, $destinationPublicKeyHex === null ? PDO::PARAM_NULL : PDO::PARAM_STR);
        $stmt->bindValue(':packet_base64', $packetBase64, PDO::PARAM_STR);
        $stmt->bindValue(':packet_id', $packetId, PDO::PARAM_INT);
        $stmt->bindValue(':interface_id', $interfaceId, PDO::PARAM_STR);
        Database::executeWithRetry($stmt, 'reserveOutboundPackets');
    }

    private function existingUnackedOutboundBatch(string $interfaceId): ?array
    {
        $stmt = $this->db->prepare(
            'SELECT interface_id, batch_id, created_at
             FROM outbound_batches
             WHERE interface_id = :interface_id
               AND acked_at IS NULL
               AND EXISTS (
                    SELECT 1
                    FROM outbound_packets
                    WHERE outbound_packets.interface_id = outbound_batches.interface_id
                      AND outbound_packets.delivered_batch_id = outbound_batches.batch_id
                      AND outbound_packets.acked_at IS NULL
               )
             ORDER BY created_at ASC
             LIMIT 1'
        );
        $stmt->bindValue(':interface_id', $interfaceId, PDO::PARAM_STR);
        $row = $stmt->execute(); $row = $stmt->fetch(PDO::FETCH_ASSOC);

        return is_array($row) ? $row : null;
    }

    private function abandonOutboundBatch(string $interfaceId, string $batchId): void
    {
        // Clear the delivered_batch_id on packets so they can be picked up
        // by a new batch. The old batch is marked acked (abandoned).
        $stmt = $this->db->prepare(
            'UPDATE outbound_packets
             SET delivered_batch_id = NULL, delivered_at = NULL
             WHERE interface_id = :interface_id
               AND delivered_batch_id = :batch_id
               AND acked_at IS NULL'
        );
        $stmt->bindValue(':interface_id', $interfaceId, PDO::PARAM_STR);
        $stmt->bindValue(':batch_id', $batchId, PDO::PARAM_STR);
        Database::executeWithRetry($stmt, 'markOutboundPacketsAcked');

        $stmt2 = $this->db->prepare(
            'UPDATE outbound_batches SET acked_at = :now WHERE interface_id = :interface_id AND batch_id = :batch_id'
        );
        $stmt2->bindValue(':now', time(), PDO::PARAM_INT);
        $stmt2->bindValue(':interface_id', $interfaceId, PDO::PARAM_STR);
        $stmt2->bindValue(':batch_id', $batchId, PDO::PARAM_STR);
        Database::executeWithRetry($stmt2, 'markOutboundBatchAcked');
    }

    private function outboundBatchPacketIds(string $interfaceId, string $batchId): array
    {
        $stmt = $this->db->prepare(
            'SELECT packet_id
             FROM outbound_packets
             WHERE interface_id = :interface_id
               AND delivered_batch_id = :batch_id
               AND acked_at IS NULL
             ORDER BY packet_id ASC'
        );
        $stmt->bindValue(':interface_id', $interfaceId, PDO::PARAM_STR);
        $stmt->bindValue(':batch_id', $batchId, PDO::PARAM_STR);
        $stmt->execute();

        $packetIds = [];
        while (($row = $stmt->fetch(PDO::FETCH_ASSOC)) !== false) {
            if (!is_array($row)) {
                continue;
            }

            $packetIds[] = (int) ($row['packet_id'] ?? 0);
        }

        return $packetIds;
    }

    private function outboundPacketPayloads(string $interfaceId, string $batchId): array
    {
        $stmt = $this->db->prepare(
            'SELECT packet_base64
             FROM outbound_packets
             WHERE interface_id = :interface_id
               AND delivered_batch_id = :batch_id
               AND acked_at IS NULL
             ORDER BY packet_id ASC'
        );
        $stmt->bindValue(':interface_id', $interfaceId, PDO::PARAM_STR);
        $stmt->bindValue(':batch_id', $batchId, PDO::PARAM_STR);
        $stmt->execute();

        $packets = [];
        while (($row = $stmt->fetch(PDO::FETCH_ASSOC)) !== false) {
            if (!is_array($row)) {
                continue;
            }

            $packets[] = (string) ($row['packet_base64'] ?? '');
        }

        return $packets;
    }

    private function assignOutboundBatch(string $interfaceId, string $batchId, array $packetIds): void
    {
        // One statement for the batch (at most max_batch_packets ids), not
        // one UPDATE per packet.
        $ids = array_values(array_map('intval', $packetIds));
        if ($ids === []) {
            return;
        }
        $placeholders = implode(',', array_fill(0, count($ids), '?'));
        $update = $this->db->prepare(
            "UPDATE outbound_packets
             SET delivered_batch_id = ?
             WHERE interface_id = ?
               AND acked_at IS NULL
               AND delivered_batch_id IS NULL
               AND packet_id IN ({$placeholders})"
        );
        $update->bindValue(1, $batchId, PDO::PARAM_STR);
        $update->bindValue(2, $interfaceId, PDO::PARAM_STR);
        foreach ($ids as $i => $id) {
            $update->bindValue($i + 3, $id, PDO::PARAM_INT);
        }
        Database::executeWithRetry($update, 'requeueOutboundPackets');
    }

    private function recordOutboundBatchAttempt(string $interfaceId, array $packets, ?int $now = null, ?int $txBytes = null): void
    {
        $now ??= time();
        if ($txBytes === null) {
            $txBytes = 0;
            foreach ($packets as $packetBase64) {
                $txBytes += strlen((string) base64_decode((string) $packetBase64, true));
            }
        }

        $updateCounters = $this->db->prepare(
            'UPDATE interfaces
             SET tx_packets = tx_packets + :packet_count,
                 tx_bytes = tx_bytes + :byte_count,
                 last_seen_at = :last_seen_at,
                 status = :status
             WHERE interface_id = :interface_id'
        );
        $updateCounters->bindValue(':packet_count', count($packets), PDO::PARAM_INT);
        $updateCounters->bindValue(':byte_count', $txBytes, PDO::PARAM_INT);
        $updateCounters->bindValue(':last_seen_at', $now, PDO::PARAM_INT);
        $updateCounters->bindValue(':status', 'online', PDO::PARAM_STR);
        $updateCounters->bindValue(':interface_id', $interfaceId, PDO::PARAM_STR);
        Database::executeWithRetry($updateCounters, 'incrementInterfaceTxCounters');
    }

    private function outboundProofCandidates(string $proofDestinationHashHex): array
    {
        $stmt = $this->db->prepare(
            'SELECT
                packet_id,
                packet_hash_hex,
                destination_hash_hex,
                destination_public_key_hex
             FROM outbound_packets
             WHERE proof_destination_hash_hex = :proof_destination_hash_hex
               AND proofed_at IS NULL
             ORDER BY packet_id ASC'
        );
        $stmt->bindValue(':proof_destination_hash_hex', $proofDestinationHashHex, PDO::PARAM_STR);
        $stmt->execute();

        $candidates = [];
        while (($row = $stmt->fetch(PDO::FETCH_ASSOC)) !== false) {
            if (!is_array($row)) {
                continue;
            }

            $candidates[] = $row;
        }

        return $candidates;
    }

    private function validateOutboundProofSignature(array $candidate, string $signature): bool
    {
        if (!function_exists('sodium_crypto_sign_verify_detached')) {
            throw new RuntimeException('ext/sodium is required for outbound proof validation');
        }

        $packetHashHex = (string) ($candidate['packet_hash_hex'] ?? '');
        $packetHash = hex2bin($packetHashHex);
        if (!is_string($packetHash) || strlen($packetHash) !== 32 || strlen($signature) !== 64) {
            return false;
        }

        $destinationPublicKeyHex = $candidate['destination_public_key_hex'] ?? null;
        if (!is_string($destinationPublicKeyHex) || $destinationPublicKeyHex === '') {
            $destinationHashHex = (string) ($candidate['destination_hash_hex'] ?? '');
            $destinationPublicKeyHex = $destinationHashHex === '' ? null : $this->knownDestinationPublicKey($destinationHashHex);
        }

        if (!is_string($destinationPublicKeyHex) || $destinationPublicKeyHex === '') {
            return false;
        }

        $destinationPublicKey = hex2bin($destinationPublicKeyHex);
        if (!is_string($destinationPublicKey) || strlen($destinationPublicKey) !== 64) {
            return false;
        }

        $ed25519PublicKey = substr($destinationPublicKey, 32);
        return sodium_crypto_sign_verify_detached($signature, $packetHash, $ed25519PublicKey);
    }

    private function markOutboundPacketProofed(int $packetId, int $proofedAt): void
    {
        if ($packetId <= 0) {
            return;
        }

        $stmt = $this->db->prepare(
            'UPDATE outbound_packets
             SET proofed_at = :proofed_at
             WHERE packet_id = :packet_id
               AND proofed_at IS NULL'
        );
        $stmt->bindValue(':proofed_at', $proofedAt, PDO::PARAM_INT);
        $stmt->bindValue(':packet_id', $packetId, PDO::PARAM_INT);
        Database::executeWithRetry($stmt, 'expireOutboundPackets');
    }

    /**
     * Seed a newly-registered interface with cached announces from other
     * interfaces, once per registration, on its first exchange. PHP node
     * peering rows are never seeded. A registration that gets its old row
     * back (a reloaded tab) clears the marker, so it is seeded like a new
     * browser (2026-10-19; until then once per row, and a reload started
     * blind).
     *
     * "New" is the row's seeded_at marker, claimed by the one UPDATE that
     * finds it NULL, so of two concurrent exchanges only one seeds. Until
     * 2026-10-14 it was "no packets received and no outbound rows", and a
     * live announce relayed to the interface between its registration and
     * its first exchange gave it an outbound row: it was never seeded
     * (tests/seed_new_interface_once_test.php). If seeding throws, the
     * claim is released, so the interface's next exchange seeds it.
     */
    public function seedInterfaceIfNew(string $interfaceId): void
    {
        if ($this->isPhpPeerInterface($interfaceId)) return;
        // Read first: on SQLite an UPDATE takes the write lock even when it
        // matches nothing, and every exchange comes through here.
        $read = $this->db->prepare('SELECT seeded_at FROM interfaces WHERE interface_id = :id');
        $read->bindValue(':id', $interfaceId, PDO::PARAM_STR);
        $read->execute();
        $seededAt = $read->fetch(PDO::FETCH_NUM);
        $read->closeCursor();
        if ($seededAt === false || $seededAt[0] !== null) return;
        $claim = $this->db->prepare(
            'UPDATE interfaces SET seeded_at = :now WHERE interface_id = :id AND seeded_at IS NULL'
        );
        $claim->bindValue(':now', time(), PDO::PARAM_INT);
        $claim->bindValue(':id', $interfaceId, PDO::PARAM_STR);
        Database::executeWithRetry($claim, 'claimInterfaceSeed');
        if ($claim->rowCount() !== 1) return;
        try {
            $this->seedInterfaceWithCachedAnnounces($interfaceId);
        } catch (\Throwable $e) {
            $release = $this->db->prepare('UPDATE interfaces SET seeded_at = NULL WHERE interface_id = :id');
            $release->bindValue(':id', $interfaceId, PDO::PARAM_STR);
            Database::executeWithRetry($release, 'releaseInterfaceSeed');
            throw $e;
        }
    }

    /**
     * Replay cached announces to a newly-registered interface so it learns
     * existing destinations immediately — no need to wait for the next
     * announce cycle or page reload.
     */
    private function seedInterfaceWithCachedAnnounces(string $interfaceId): void
    {
        $queued = 0;
        foreach ($this->seedDestinations($interfaceId) as $destHex) {
            // The announce the path keeps, by the same rule as a path or cache
            // request and as maintenance keeps one copy of it; with no path,
            // or none of its copies stored, the newest copy. Either way only
            // a copy that was accepted (validated or path_updated): never one
            // the browser-row rule refused (REGISTRATION-STAGE1.md §9).
            $rawStmt = $this->db->prepare($this->seedPathAnnounceSql());
            $rawStmt->bindValue(':dest', $destHex, PDO::PARAM_STR);
            $rawStmt->bindValue(':accepted', 'accepted', PDO::PARAM_STR);
            $rawStmt->bindValue(':validated', 'validated', PDO::PARAM_STR);
            $rawStmt->bindValue(':path_updated', 'path_updated', PDO::PARAM_STR);
            $rawStmt->execute();
            $rawRow = $rawStmt->fetch(PDO::FETCH_ASSOC);
            if (!is_array($rawRow)) {
                $rawStmt = $this->db->prepare($this->seedNewestAnnounceSql());
                $rawStmt->bindValue(':dest', $destHex, PDO::PARAM_STR);
                $rawStmt->bindValue(':accepted', 'accepted', PDO::PARAM_STR);
                $rawStmt->bindValue(':validated', 'validated', PDO::PARAM_STR);
                $rawStmt->bindValue(':path_updated', 'path_updated', PDO::PARAM_STR);
                $rawStmt->execute();
                $rawRow = $rawStmt->fetch(PDO::FETCH_ASSOC);
            }

            if (!is_array($rawRow)) continue;
            $rawBase64 = (string) ($rawRow['raw_base64'] ?? '');
            if ($rawBase64 === '') continue;

            // Queue the cached announce for this interface
            $this->queueOutboundPacket($interfaceId, $rawBase64, 'relay_announce', null);
            $queued++;
        }
    }

    /**
     * The up to 64 destinations seeding replays, newest accepted announce
     * first, excluding announces that came in on this interface (echoes).
     *
     * Read newest first in chunks of 256 rows, doubling to 4096, until 64
     * destinations are found or the history ends. Until 2026-10-15 one
     * SELECT DISTINCT destination_hash_hex ... ORDER BY packet_record_id
     * did this; MySQL refuses it under ONLY_FULL_GROUP_BY (8.4's default
     * sql_mode, error 3065), so every new interface's exchange failed there.
     * GROUP BY ... ORDER BY MAX(packet_record_id) is standard but reads
     * every announce: timed 2026-10-15 on 60K rows of retichat.com's width
     * with 24K destinations, about 95 ms on SQLite and 120 ms on MySQL 8.4
     * against 0.2 and 0.5 ms this way (one chunk). With fewer than 64
     * destinations every form reads the whole history: 8 chunks, 90 ms, as
     * the DISTINCT took.
     *
     * @return list<string>
     */
    private function seedDestinations(string $interfaceId): array
    {
        $stmt = $this->db->prepare(
            'SELECT packet_record_id, destination_hash_hex
             FROM inbound_packets
             WHERE packet_type = 1
               AND filter_status = :accepted
               AND announce_status IN (:validated, :path_updated)
               AND interface_id != :self_iface
               AND packet_record_id < :before
             ORDER BY packet_record_id DESC
             LIMIT :chunk'
        );
        $destinations = [];
        $before = PHP_INT_MAX;
        $chunk = 256;
        while (true) {
            $stmt->bindValue(':accepted', 'accepted', PDO::PARAM_STR);
            $stmt->bindValue(':validated', 'validated', PDO::PARAM_STR);
            $stmt->bindValue(':path_updated', 'path_updated', PDO::PARAM_STR);
            $stmt->bindValue(':self_iface', $interfaceId, PDO::PARAM_STR);
            $stmt->bindValue(':before', $before, PDO::PARAM_INT);
            $stmt->bindValue(':chunk', $chunk, PDO::PARAM_INT);
            $stmt->execute();
            $rows = $stmt->fetchAll(PDO::FETCH_NUM);
            foreach ($rows as [$recordId, $destHex]) {
                $before = (int) $recordId;
                $destHex = (string) $destHex;
                if ($destHex === '' || isset($destinations[$destHex])) continue;
                $destinations[$destHex] = true;
                if (count($destinations) === 64) {
                    return array_keys($destinations);
                }
            }
            if (count($rows) < $chunk) {
                return array_keys($destinations);
            }
            $chunk = min($chunk * 2, 4096);
        }
    }

    /**
     * Seeding's pick for one destination with a path: the path's announce,
     * ranked by announceCopyOrderSql(). Driven from the path, so it reads one
     * path_entries row by its primary key and that announce's few copies
     * through idx_inbound_packets_hash. It runs up to 64 times inside the
     * exchange that registers an interface. Driven from inbound_packets, as
     * it was briefly on 2026-10-10, no index can give the CASE order, and
     * each destination read and sorted the whole inbound history (about 4 s
     * for 64 destinations over 61K rows on SQLite, against 1 ms this way).
     */
    private function seedPathAnnounceSql(): string
    {
        return 'SELECT ip.raw_base64
             FROM path_entries pe
             JOIN inbound_packets ip ON ip.packet_hash_hex = pe.packet_hash_hex
             WHERE pe.destination_hash_hex = :dest
               AND ip.packet_type = 1
               AND ip.filter_status = :accepted
               AND ip.announce_status IN (:validated, :path_updated)
               AND ip.raw_base64 IS NOT NULL
             ORDER BY ' . $this->announceCopyOrderSql('ip', 'pe') . '
             LIMIT 1';
    }

    /**
     * Seeding's pick for a destination with no path, or none of whose path's
     * copies is stored: its newest accepted announce, validated or
     * path_updated (until Stage 1 the newest accepted packet whatever its
     * status, so a refused copy would have been seeded). The ORDER BY on the
     * primary key with LIMIT 1 walks the history backwards and stops at the
     * first match; the destinations come from the newest rows.
     */
    private function seedNewestAnnounceSql(): string
    {
        return 'SELECT raw_base64 FROM inbound_packets
             WHERE destination_hash_hex = :dest
               AND packet_type = 1
               AND filter_status = :accepted
               AND announce_status IN (:validated, :path_updated)
               AND raw_base64 IS NOT NULL
             ORDER BY packet_record_id DESC
             LIMIT 1';
    }
}