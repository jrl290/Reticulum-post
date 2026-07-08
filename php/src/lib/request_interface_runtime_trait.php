<?php

declare(strict_types=1);

namespace ReticulumPhp;

use PDO;

// Reticulum-php is request-operated. These interface/runtime helpers prepare
// queued packets and wake state for the next authenticated exchange; they do
// not form an independent background transport path.

trait RequestInterfaceRuntimeTrait
{
    private function transportIdentityHashHex(): string
    {
        $stmt = $this->db->prepare('SELECT state_value FROM transport_state WHERE state_key = :state_key');
        $stmt->bindValue(':state_key', 'identity_hash_hex', PDO::PARAM_STR);
        $row = $stmt->execute(); $row = $stmt->fetch(PDO::FETCH_ASSOC);
        if (is_array($row)) {
            return (string) $row['state_value'];
        }

        $identityHashHex = bin2hex(random_bytes(16));
        $insert = $this->db->prepare(
            'INSERT INTO transport_state (state_key, state_value, updated_at)
             VALUES (:state_key, :state_value, :updated_at)'
        );
        $insert->bindValue(':state_key', 'identity_hash_hex', PDO::PARAM_STR);
        $insert->bindValue(':state_value', $identityHashHex, PDO::PARAM_STR);
        $insert->bindValue(':updated_at', time(), PDO::PARAM_INT);
        $insert->execute();

        return $identityHashHex;
    }

    private function queueOutboundPacket(string $interfaceId, string $packetBase64, string $reason, ?string $currentExchangeInterfaceId = null): void
    {
        $packetRaw = base64_decode($packetBase64, true);
        if (!is_string($packetRaw)) {
            throw new RuntimeException('Outbound packet base64 is invalid');
        }

        $parsedPacket = PacketParser::parseRaw($packetRaw);
        $destinationHashHex = (string) ($parsedPacket['destination_hash_hex'] ?? '');
        $destinationPublicKeyHex = $destinationHashHex === '' ? null : $this->knownDestinationPublicKey($destinationHashHex);
        $wrappedPacketBase64 = base64_encode(IfacCodec::wrapForInterface($packetRaw, $this->ifacConfig($interfaceId)));
        $stmt = $this->db->prepare(
            'INSERT INTO outbound_packets (
                interface_id,
                packet_hash_hex,
                proof_destination_hash_hex,
                destination_hash_hex,
                destination_public_key_hex,
                packet_base64,
                queued_at,
                delivered_at,
                delivered_batch_id,
                acked_at,
                proofed_at,
                queue_reason
            ) VALUES (
                :interface_id,
                :packet_hash_hex,
                :proof_destination_hash_hex,
                :destination_hash_hex,
                :destination_public_key_hex,
                :packet_base64,
                :queued_at,
                NULL,
                NULL,
                NULL,
                NULL,
                :queue_reason
            )'
        );
        $stmt->bindValue(':interface_id', $interfaceId, PDO::PARAM_STR);
        $stmt->bindValue(':packet_hash_hex', (string) ($parsedPacket['packet_hash_hex'] ?? ''), PDO::PARAM_STR);
        $stmt->bindValue(':proof_destination_hash_hex', (string) ($parsedPacket['truncated_hash_hex'] ?? ''), PDO::PARAM_STR);
        $stmt->bindValue(':destination_hash_hex', $destinationHashHex, $destinationHashHex === '' ? PDO::PARAM_NULL : PDO::PARAM_STR);
        $stmt->bindValue(':destination_public_key_hex', $destinationPublicKeyHex, $destinationPublicKeyHex === null ? PDO::PARAM_NULL : PDO::PARAM_STR);
        $stmt->bindValue(':packet_base64', $wrappedPacketBase64, PDO::PARAM_STR);
        $stmt->bindValue(':queued_at', time(), PDO::PARAM_INT);
        $stmt->bindValue(':queue_reason', $reason, PDO::PARAM_STR);
        $stmt->execute();

        if ($currentExchangeInterfaceId !== null && $currentExchangeInterfaceId === $interfaceId) {
            return;
        }

        $this->scheduleWakeEventIfNeeded($interfaceId, $reason, $this->unissuedOutboundPacketCount($interfaceId));
    }

    private function pendingOutboundPacketCount(string $interfaceId): int
    {
        $stmt = $this->db->prepare(
            'SELECT COUNT(*) AS pending
             FROM outbound_packets
             WHERE interface_id = :interface_id AND acked_at IS NULL'
        );
        $stmt->bindValue(':interface_id', $interfaceId, PDO::PARAM_STR);
        $row = $stmt->execute(); $row = $stmt->fetch(PDO::FETCH_ASSOC);

        return (int) ($row['pending'] ?? 0);
    }

    private function unissuedOutboundPacketCount(string $interfaceId): int
    {
        $stmt = $this->db->prepare(
            'SELECT COUNT(*) AS pending
             FROM outbound_packets
             WHERE interface_id = :interface_id
               AND acked_at IS NULL
               AND delivered_batch_id IS NULL'
        );
        $stmt->bindValue(':interface_id', $interfaceId, PDO::PARAM_STR);
        $row = $stmt->execute(); $row = $stmt->fetch(PDO::FETCH_ASSOC);

        return (int) ($row['pending'] ?? 0);
    }

    private function scheduleWakeEventIfNeeded(string $interfaceId, string $reason, int $pendingPacketCount): void
    {
        // Create a wake event whenever there are unissued packets and no
        // existing undispatched wake event already queued for this interface.
        // This prevents wake storms (one wake per batch of packets) while
        // allowing backlog recovery after restarts or failures.
        if ($pendingPacketCount === 0) {
            return;
        }

        if ($this->hasPendingWakeEvent($interfaceId)) {
            return;
        }

        $wakeConfig = $this->wakeConfigForInterface($interfaceId);
        if ($wakeConfig === null) {
            return;
        }

        $stmt = $this->db->prepare(
            'INSERT INTO wake_events (
                interface_id,
                wake_profile,
                wake_target,
                wake_data_json,
                queue_reason,
                queued_packet_count,
                created_at,
                dispatched_at,
                failed_at,
                failure_message
            ) VALUES (
                :interface_id,
                :wake_profile,
                :wake_target,
                :wake_data_json,
                :queue_reason,
                :queued_packet_count,
                :created_at,
                NULL,
                NULL,
                NULL
            )'
        );
        $stmt->bindValue(':interface_id', $interfaceId, PDO::PARAM_STR);
        $stmt->bindValue(':wake_profile', (string) $wakeConfig['profile'], PDO::PARAM_STR);
        $stmt->bindValue(':wake_target', (string) $wakeConfig['target'], PDO::PARAM_STR);
        $stmt->bindValue(':wake_data_json', self::encodeJson((array) $wakeConfig['data']), PDO::PARAM_STR);
        $stmt->bindValue(':queue_reason', $reason, PDO::PARAM_STR);
        $stmt->bindValue(':queued_packet_count', $pendingPacketCount, PDO::PARAM_INT);
        $stmt->bindValue(':created_at', time(), PDO::PARAM_INT);
        $stmt->execute();
    }

    /**
     * Check if there's already an undispatched wake event for this interface.
     * Prevents wake storms while allowing backlog recovery.
     */
    private function hasPendingWakeEvent(string $interfaceId): bool
    {
        $stmt = $this->db->prepare(
            'SELECT 1 FROM wake_events
             WHERE interface_id = :interface_id
               AND dispatched_at IS NULL
               AND failed_at IS NULL
             LIMIT 1'
        );
        $stmt->bindValue(':interface_id', $interfaceId, PDO::PARAM_STR);
        $stmt->execute();
        return $stmt->fetch(PDO::FETCH_ASSOC) !== false;
    }

    public function maxPacketBytesForMetadata(array $metadata): int
    {
        return IfacCodec::packetSizeLimit(
            (int) $this->config['http']['max_packet_bytes'],
            IfacCodec::configFromMetadata($metadata)
        );
    }

    public function maxPacketBytesForInterface(string $interfaceId): int
    {
        return $this->maxPacketBytesForMetadata($this->interfaceMetadata($interfaceId));
    }

    public function interfaceMetadataForInterface(string $interfaceId): array
    {
        return $this->interfaceMetadata($interfaceId);
    }

    private function wakeConfigForInterface(string $interfaceId): ?array
    {
        return WakeConfig::fromMetadata($this->interfaceMetadata($interfaceId));
    }

    private function interfaceMetadata(string $interfaceId): array
    {
        $stmt = $this->db->prepare('SELECT metadata_json FROM interfaces WHERE interface_id = :interface_id');
        $stmt->bindValue(':interface_id', $interfaceId, PDO::PARAM_STR);
        $row = $stmt->execute(); $row = $stmt->fetch(PDO::FETCH_ASSOC);
        if (!is_array($row)) {
            return [];
        }

        return self::decodeJson((string) $row['metadata_json']);
    }

    private function ifacConfig(string $interfaceId): ?array
    {
        return IfacCodec::configFromMetadata($this->interfaceMetadata($interfaceId));
    }
}