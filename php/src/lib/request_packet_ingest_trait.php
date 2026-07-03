<?php

declare(strict_types=1);

namespace ReticulumPhp;

// Reticulum-php is request-operated. These inbound packet helpers classify and
// persist packets during authenticated exchanges; they do not introduce a
// second transport path outside the request/response flow.

trait RequestPacketIngestTrait
{
    private function applyPacketFilter(array $packet): array
    {
        $alwaysAcceptedContexts = [0x05, 0x01, 0x08, 0x0E];
        $destinationType = (int) $packet['destination_type'];
        $packetType = (int) $packet['packet_type'];
        $context = (int) $packet['context'];
        $hops = (int) $packet['hops'];
        $packetHashHex = (string) $packet['packet_hash_hex'];
        $transportIdHex = $packet['transport_id_hex'] === null ? null : (string) $packet['transport_id_hex'];

        if ($transportIdHex !== null && $packetType !== 1 && !hash_equals($this->transportIdentityHashHex(), $transportIdHex)) {
            return ['rejected', 'transport_id_mismatch'];
        }

        if (in_array($context, $alwaysAcceptedContexts, true)) {
            $this->rememberPacketHash($packetHashHex);
            return ['accepted', 'context_passthrough'];
        }

        if ($destinationType === 2) {
            if ($packetType !== 1) {
                if ($hops > 1) {
                    return ['rejected', 'plain_hops_exceeded'];
                }

                $this->rememberPacketHash($packetHashHex);
                return ['accepted', 'plain_local'];
            }

            return ['rejected', 'invalid_plain_announce'];
        }

        if ($destinationType === 1) {
            if ($packetType !== 1) {
                if ($hops > 1) {
                    return ['rejected', 'group_hops_exceeded'];
                }

                $this->rememberPacketHash($packetHashHex);
                return ['accepted', 'group_local'];
            }

            return ['rejected', 'invalid_group_announce'];
        }

        if (!$this->packetHashExists($packetHashHex)) {
            $this->rememberPacketHash($packetHashHex);
            return ['accepted', 'new_hash'];
        }

        if ($packetType === 1 && $destinationType === 0) {
            $this->rememberPacketHash($packetHashHex);
            return ['accepted', 'duplicate_single_announce'];
        }

        return ['rejected', 'duplicate'];
    }

    private function packetHashExists(string $packetHashHex): bool
    {
        $stmt = $this->db->prepare('SELECT 1 FROM packet_hashes WHERE packet_hash_hex = :packet_hash_hex');
        $stmt->bindValue(':packet_hash_hex', $packetHashHex, SQLITE3_TEXT);
        $row = $stmt->execute()->fetchArray(SQLITE3_NUM);

        return $row !== false;
    }

    private function rememberPacketHash(string $packetHashHex): void
    {
        $stmt = $this->db->prepare(
            'INSERT OR IGNORE INTO packet_hashes (packet_hash_hex, first_seen_at)
             VALUES (:packet_hash_hex, :first_seen_at)'
        );
        $stmt->bindValue(':packet_hash_hex', $packetHashHex, SQLITE3_TEXT);
        $stmt->bindValue(':first_seen_at', time(), SQLITE3_INTEGER);
        $stmt->execute();
    }

    private function storeInboundPacket(
        string $interfaceId,
        string $batchId,
        int $packetIndex,
        string $status,
        string $rawBase64,
        array $packet,
        ?string $errorMessage
    ): void {
        $stmt = $this->db->prepare(
            'INSERT OR REPLACE INTO inbound_packets (
                interface_id,
                batch_id,
                packet_index,
                status,
                error_message,
                packet_hash_hex,
                truncated_hash_hex,
                raw_base64,
                packet_size,
                ifac_flag,
                header_type,
                transport_type,
                destination_type,
                packet_type,
                context_flag,
                hops,
                context,
                transport_id_hex,
                destination_hash_hex,
                payload_base64,
                filter_status,
                filter_reason,
                announce_status,
                announce_reason,
                created_at
            ) VALUES (
                :interface_id,
                :batch_id,
                :packet_index,
                :status,
                :error_message,
                :packet_hash_hex,
                :truncated_hash_hex,
                :raw_base64,
                :packet_size,
                :ifac_flag,
                :header_type,
                :transport_type,
                :destination_type,
                :packet_type,
                :context_flag,
                :hops,
                :context,
                :transport_id_hex,
                :destination_hash_hex,
                :payload_base64,
                :filter_status,
                :filter_reason,
                :announce_status,
                :announce_reason,
                :created_at
            )'
        );
        $stmt->bindValue(':interface_id', $interfaceId, SQLITE3_TEXT);
        $stmt->bindValue(':batch_id', $batchId, SQLITE3_TEXT);
        $stmt->bindValue(':packet_index', $packetIndex, SQLITE3_INTEGER);
        $stmt->bindValue(':status', $status, SQLITE3_TEXT);
        $stmt->bindValue(':error_message', $errorMessage, $errorMessage === null ? SQLITE3_NULL : SQLITE3_TEXT);
        $stmt->bindValue(':packet_hash_hex', $packet['packet_hash_hex'], $packet['packet_hash_hex'] === null ? SQLITE3_NULL : SQLITE3_TEXT);
        $stmt->bindValue(':truncated_hash_hex', $packet['truncated_hash_hex'], $packet['truncated_hash_hex'] === null ? SQLITE3_NULL : SQLITE3_TEXT);
        $stmt->bindValue(':raw_base64', $rawBase64, SQLITE3_TEXT);
        $stmt->bindValue(':packet_size', (int) $packet['packet_size'], SQLITE3_INTEGER);
        $stmt->bindValue(':ifac_flag', (int) $packet['ifac_flag'], SQLITE3_INTEGER);
        $stmt->bindValue(':header_type', $packet['header_type'], $packet['header_type'] === null ? SQLITE3_NULL : SQLITE3_INTEGER);
        $stmt->bindValue(':transport_type', $packet['transport_type'], $packet['transport_type'] === null ? SQLITE3_NULL : SQLITE3_INTEGER);
        $stmt->bindValue(':destination_type', $packet['destination_type'], $packet['destination_type'] === null ? SQLITE3_NULL : SQLITE3_INTEGER);
        $stmt->bindValue(':packet_type', $packet['packet_type'], $packet['packet_type'] === null ? SQLITE3_NULL : SQLITE3_INTEGER);
        $stmt->bindValue(':context_flag', $packet['context_flag'], $packet['context_flag'] === null ? SQLITE3_NULL : SQLITE3_INTEGER);
        $stmt->bindValue(':hops', $packet['hops'], $packet['hops'] === null ? SQLITE3_NULL : SQLITE3_INTEGER);
        $stmt->bindValue(':context', $packet['context'], $packet['context'] === null ? SQLITE3_NULL : SQLITE3_INTEGER);
        $stmt->bindValue(':transport_id_hex', $packet['transport_id_hex'], $packet['transport_id_hex'] === null ? SQLITE3_NULL : SQLITE3_TEXT);
        $stmt->bindValue(':destination_hash_hex', $packet['destination_hash_hex'], $packet['destination_hash_hex'] === null ? SQLITE3_NULL : SQLITE3_TEXT);
        $stmt->bindValue(':payload_base64', $packet['payload_base64'], $packet['payload_base64'] === null ? SQLITE3_NULL : SQLITE3_TEXT);
        $stmt->bindValue(':filter_status', $packet['filter_status'], $packet['filter_status'] === null ? SQLITE3_NULL : SQLITE3_TEXT);
        $stmt->bindValue(':filter_reason', $packet['filter_reason'], $packet['filter_reason'] === null ? SQLITE3_NULL : SQLITE3_TEXT);
        $stmt->bindValue(':announce_status', $packet['announce_status'], $packet['announce_status'] === null ? SQLITE3_NULL : SQLITE3_TEXT);
        $stmt->bindValue(':announce_reason', $packet['announce_reason'], $packet['announce_reason'] === null ? SQLITE3_NULL : SQLITE3_TEXT);
        $stmt->bindValue(':created_at', time(), SQLITE3_INTEGER);
        $stmt->execute();
    }
}