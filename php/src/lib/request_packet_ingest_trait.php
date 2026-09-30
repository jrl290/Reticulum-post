<?php

declare(strict_types=1);

namespace ReticulumPhp;

use PDO;

// Reticulum-php is request-operated. These inbound packet helpers classify and
// persist packets during authenticated exchanges; they do not introduce a
// second transport path outside the request/response flow.

trait RequestPacketIngestTrait
{
    private function applyPacketFilter(array $packet): array
    {
        // RNS 1.5.2 Transport.packet_filter (Transport.py:1635-1640) accepts
        // exactly these six contexts before the packet hash list is consulted,
        // and only after the transport_id check (Transport.py:1630-1633, the
        // first block below). Keep this list equal to the reference's: not
        // Reticulum-rust's 0x01-0x07 superset, not a subset.
        //
        // KEEPALIVE and RESOURCE_REQ were missing until 2026-09-30. A
        // keepalive goes out unencrypted (Packet.py:209-212) and its hash
        // leaves out the hops byte (Packet.py:361-365), so it covers only
        // link_id + context + the one data byte: every ping on a link hashes
        // the same, and so does every pong. The first of each passed and
        // every later one was dropped here as 'duplicate' for
        // packet_hash_ttl_seconds, so idle links through this node went STALE
        // and closed. That is the 2026-09-29 staging failure of stage_sim
        // section c (channel posts to an idle web client were lost). A
        // re-sent RESOURCE_REQ can be byte-identical in the same way.
        // Pinned by tests/packet_filter_contexts_test.php.
        //
        // Known, separate divergence (not changed here): this filter
        // remembers the hash of every packet it accepts, including link-table
        // traffic; the reference adds hashes only after the filter and never
        // for link-table packets or LRPROOFs (Transport.py:1944-1961).
        $alwaysAcceptedContexts = [
            0xFA, // KEEPALIVE
            0x03, // RESOURCE_REQ
            0x05, // RESOURCE_PRF
            0x01, // RESOURCE
            0x08, // CACHE_REQUEST
            0x0E, // CHANNEL
        ];
        $destinationType = (int) $packet['destination_type'];
        $packetType = (int) $packet['packet_type'];
        $context = (int) $packet['context'];
        $hops = (int) $packet['hops'];
        $packetHashHex = (string) $packet['packet_hash_hex'];
        $transportIdHex = $packet['transport_id_hex'] === null ? null : (string) $packet['transport_id_hex'];
        $destinationHashHex = (string) ($packet['destination_hash_hex'] ?? '');

        if ($transportIdHex !== null && $packetType !== 1 && !hash_equals($this->transportIdentityHashHex(), $transportIdHex)) {
            // Last-hop delivery: some upstream transports set transport_id
            // to the destination hash when forwarding to the final node.
            // Accept these if the destination is a known local client.
            // Python reference: Transport.inbound() routes by path table
            // before the transport_id check, so last-hop packets addressed
            // directly to the destination hash are handled naturally.
            if ($destinationHashHex === '' || !hash_equals($destinationHashHex, $transportIdHex)) {
                return ['rejected', 'transport_id_mismatch'];
            }
            if ($this->localDestinationInterface($destinationHashHex) === null) {
                return ['rejected', 'transport_id_mismatch_not_local'];
            }
            // Fall through — transport_id matches destination hash
            // and destination is a known local client.
        }

        if (in_array($context, $alwaysAcceptedContexts, true)) {
            $this->rememberPacketHash($packetHashHex);
            return ['accepted', 'context_passthrough'];
        }

        if ($destinationType === 2) {
            if ($packetType !== 1) {
                // Path requests are addressed to the control hash with
                // destination_type=LINK. They must be forwarded through
                // multiple hops to reach a node that holds the announce.
                // Python reference handles path requests in inbound()
                // BEFORE the packet filter (early return), so the
                // plain_hops_exceeded gate does not apply to them.
                // See Python Transport.py inbound() path request handler,
                // Rust transport.rs:inbound() early path_request return.
                $isPathRequest = ((string) ($packet['destination_hash_hex'] ?? '')) === $this->pathRequestControlHashHex();
                if ($hops > 1 && !$isPathRequest) {
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
        $stmt->bindValue(':packet_hash_hex', $packetHashHex, PDO::PARAM_STR);
        $stmt->execute();
        $row = $stmt->fetch(PDO::FETCH_NUM);

        return $row !== false;
    }

    private function rememberPacketHash(string $packetHashHex): void
    {
        $stmt = $this->db->prepare(Database::insertOrSql($this->backend,
            'INSERT OR IGNORE INTO packet_hashes (packet_hash_hex, first_seen_at)
             VALUES (:packet_hash_hex, :first_seen_at)'
        ));
        $stmt->bindValue(':packet_hash_hex', $packetHashHex, PDO::PARAM_STR);
        $stmt->bindValue(':first_seen_at', time(), PDO::PARAM_INT);
        Database::executeWithRetry($stmt, 'rememberPacketHash');
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
        $stmt = $this->db->prepare(Database::insertOrSql($this->backend,
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
        ));
        $stmt->bindValue(':interface_id', $interfaceId, PDO::PARAM_STR);
        $stmt->bindValue(':batch_id', $batchId, PDO::PARAM_STR);
        $stmt->bindValue(':packet_index', $packetIndex, PDO::PARAM_INT);
        $stmt->bindValue(':status', $status, PDO::PARAM_STR);
        $stmt->bindValue(':error_message', $errorMessage, $errorMessage === null ? PDO::PARAM_NULL : PDO::PARAM_STR);
        $stmt->bindValue(':packet_hash_hex', $packet['packet_hash_hex'], $packet['packet_hash_hex'] === null ? PDO::PARAM_NULL : PDO::PARAM_STR);
        $stmt->bindValue(':truncated_hash_hex', $packet['truncated_hash_hex'], $packet['truncated_hash_hex'] === null ? PDO::PARAM_NULL : PDO::PARAM_STR);
        $stmt->bindValue(':raw_base64', $rawBase64, PDO::PARAM_STR);
        $stmt->bindValue(':packet_size', (int) $packet['packet_size'], PDO::PARAM_INT);
        $stmt->bindValue(':ifac_flag', (int) $packet['ifac_flag'], PDO::PARAM_INT);
        $stmt->bindValue(':header_type', $packet['header_type'], $packet['header_type'] === null ? PDO::PARAM_NULL : PDO::PARAM_INT);
        $stmt->bindValue(':transport_type', $packet['transport_type'], $packet['transport_type'] === null ? PDO::PARAM_NULL : PDO::PARAM_INT);
        $stmt->bindValue(':destination_type', $packet['destination_type'], $packet['destination_type'] === null ? PDO::PARAM_NULL : PDO::PARAM_INT);
        $stmt->bindValue(':packet_type', $packet['packet_type'], $packet['packet_type'] === null ? PDO::PARAM_NULL : PDO::PARAM_INT);
        $stmt->bindValue(':context_flag', $packet['context_flag'], $packet['context_flag'] === null ? PDO::PARAM_NULL : PDO::PARAM_INT);
        $stmt->bindValue(':hops', $packet['hops'], $packet['hops'] === null ? PDO::PARAM_NULL : PDO::PARAM_INT);
        $stmt->bindValue(':context', $packet['context'], $packet['context'] === null ? PDO::PARAM_NULL : PDO::PARAM_INT);
        $stmt->bindValue(':transport_id_hex', $packet['transport_id_hex'], $packet['transport_id_hex'] === null ? PDO::PARAM_NULL : PDO::PARAM_STR);
        $stmt->bindValue(':destination_hash_hex', $packet['destination_hash_hex'], $packet['destination_hash_hex'] === null ? PDO::PARAM_NULL : PDO::PARAM_STR);
        $stmt->bindValue(':payload_base64', $packet['payload_base64'], $packet['payload_base64'] === null ? PDO::PARAM_NULL : PDO::PARAM_STR);
        $stmt->bindValue(':filter_status', $packet['filter_status'], $packet['filter_status'] === null ? PDO::PARAM_NULL : PDO::PARAM_STR);
        $stmt->bindValue(':filter_reason', $packet['filter_reason'], $packet['filter_reason'] === null ? PDO::PARAM_NULL : PDO::PARAM_STR);
        $stmt->bindValue(':announce_status', $packet['announce_status'], $packet['announce_status'] === null ? PDO::PARAM_NULL : PDO::PARAM_STR);
        $stmt->bindValue(':announce_reason', $packet['announce_reason'], $packet['announce_reason'] === null ? PDO::PARAM_NULL : PDO::PARAM_STR);
        $stmt->bindValue(':created_at', time(), PDO::PARAM_INT);
        Database::executeWithRetry($stmt, 'storeInboundPacket');
    }
}