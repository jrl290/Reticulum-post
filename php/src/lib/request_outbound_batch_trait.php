<?php

declare(strict_types=1);

namespace ReticulumPhp;

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
        $stmt->bindValue(':packet_hash_hex', $packetHashHex, SQLITE3_TEXT);
        $row = $stmt->execute()->fetchArray(SQLITE3_ASSOC);

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
            $select->bindValue(':interface_id', $interfaceId, SQLITE3_TEXT);
            $select->bindValue(':batch_id', $batchId, SQLITE3_TEXT);
            $batch = $select->execute()->fetchArray(SQLITE3_ASSOC);
            if (!is_array($batch) || $batch['acked_at'] !== null) {
                continue;
            }

            $packetIds = self::decodeJson((string) $batch['packet_ids_json']);
            $now = time();

            $updateBatch = $this->db->prepare(
                'UPDATE outbound_batches SET acked_at = :acked_at WHERE interface_id = :interface_id AND batch_id = :batch_id'
            );
            $updateBatch->bindValue(':acked_at', $now, SQLITE3_INTEGER);
            $updateBatch->bindValue(':interface_id', $interfaceId, SQLITE3_TEXT);
            $updateBatch->bindValue(':batch_id', $batchId, SQLITE3_TEXT);
            $updateBatch->execute();

            foreach ($packetIds as $packetId) {
                $updatePacket = $this->db->prepare(
                    'UPDATE outbound_packets
                     SET acked_at = :acked_at,
                         delivered_at = :delivered_at
                     WHERE packet_id = :packet_id AND interface_id = :interface_id'
                );
                $updatePacket->bindValue(':acked_at', $now, SQLITE3_INTEGER);
                $updatePacket->bindValue(':delivered_at', $now, SQLITE3_INTEGER);
                $updatePacket->bindValue(':packet_id', (int) $packetId, SQLITE3_INTEGER);
                $updatePacket->bindValue(':interface_id', $interfaceId, SQLITE3_TEXT);
                $updatePacket->execute();
            }

            $acked++;
        }

        return $acked;
    }

    public function fetchOutboundBatch(string $interfaceId, int $maxPackets): array
    {
        $existingBatch = $this->existingUnackedOutboundBatch($interfaceId);
        if ($existingBatch !== null) {
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
        $insertBatch->bindValue(':interface_id', $interfaceId, SQLITE3_TEXT);
        $insertBatch->bindValue(':batch_id', $batchId, SQLITE3_TEXT);
        $insertBatch->bindValue(':packet_ids_json', self::encodeJson($packetIds), SQLITE3_TEXT);
        $insertBatch->bindValue(':created_at', $now, SQLITE3_INTEGER);
        $insertBatch->execute();

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
        $stmt->bindValue(':interface_id', $interfaceId, SQLITE3_TEXT);
        $result = $stmt->execute();

        $packetIds = [];
        $packets = [];
        while (($row = $result->fetchArray(SQLITE3_ASSOC)) !== false) {
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
        $stmt->bindValue(':packet_hash_hex', (string) ($packet['packet_hash_hex'] ?? ''), SQLITE3_TEXT);
        $stmt->bindValue(':proof_destination_hash_hex', (string) ($packet['truncated_hash_hex'] ?? ''), SQLITE3_TEXT);
        $stmt->bindValue(':destination_hash_hex', $destinationHashHex, $destinationHashHex === '' ? SQLITE3_NULL : SQLITE3_TEXT);
        $stmt->bindValue(':destination_public_key_hex', $destinationPublicKeyHex, $destinationPublicKeyHex === null ? SQLITE3_NULL : SQLITE3_TEXT);
        $stmt->bindValue(':packet_base64', $packetBase64, SQLITE3_TEXT);
        $stmt->bindValue(':packet_id', $packetId, SQLITE3_INTEGER);
        $stmt->bindValue(':interface_id', $interfaceId, SQLITE3_TEXT);
        $stmt->execute();
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
        $stmt->bindValue(':interface_id', $interfaceId, SQLITE3_TEXT);
        $row = $stmt->execute()->fetchArray(SQLITE3_ASSOC);

        return is_array($row) ? $row : null;
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
        $stmt->bindValue(':interface_id', $interfaceId, SQLITE3_TEXT);
        $stmt->bindValue(':batch_id', $batchId, SQLITE3_TEXT);
        $result = $stmt->execute();

        $packetIds = [];
        while (($row = $result->fetchArray(SQLITE3_ASSOC)) !== false) {
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
        $stmt->bindValue(':interface_id', $interfaceId, SQLITE3_TEXT);
        $stmt->bindValue(':batch_id', $batchId, SQLITE3_TEXT);
        $result = $stmt->execute();

        $packets = [];
        while (($row = $result->fetchArray(SQLITE3_ASSOC)) !== false) {
            if (!is_array($row)) {
                continue;
            }

            $packets[] = (string) ($row['packet_base64'] ?? '');
        }

        return $packets;
    }

    private function assignOutboundBatch(string $interfaceId, string $batchId, array $packetIds): void
    {
        foreach ($packetIds as $packetId) {
            $update = $this->db->prepare(
                'UPDATE outbound_packets
                 SET delivered_batch_id = :delivered_batch_id
                 WHERE packet_id = :packet_id
                   AND interface_id = :interface_id
                   AND acked_at IS NULL
                   AND delivered_batch_id IS NULL'
            );
            $update->bindValue(':delivered_batch_id', $batchId, SQLITE3_TEXT);
            $update->bindValue(':packet_id', $packetId, SQLITE3_INTEGER);
            $update->bindValue(':interface_id', $interfaceId, SQLITE3_TEXT);
            $update->execute();
        }
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
        $updateCounters->bindValue(':packet_count', count($packets), SQLITE3_INTEGER);
        $updateCounters->bindValue(':byte_count', $txBytes, SQLITE3_INTEGER);
        $updateCounters->bindValue(':last_seen_at', $now, SQLITE3_INTEGER);
        $updateCounters->bindValue(':status', 'online', SQLITE3_TEXT);
        $updateCounters->bindValue(':interface_id', $interfaceId, SQLITE3_TEXT);
        $updateCounters->execute();
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
        $stmt->bindValue(':proof_destination_hash_hex', $proofDestinationHashHex, SQLITE3_TEXT);
        $result = $stmt->execute();

        $candidates = [];
        while (($row = $result->fetchArray(SQLITE3_ASSOC)) !== false) {
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
        $stmt->bindValue(':proofed_at', $proofedAt, SQLITE3_INTEGER);
        $stmt->bindValue(':packet_id', $packetId, SQLITE3_INTEGER);
        $stmt->execute();
    }
}