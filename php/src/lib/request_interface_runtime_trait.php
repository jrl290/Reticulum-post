<?php

declare(strict_types=1);

namespace ReticulumPhp;

// Loaded here as well as by index.php: deploy.sh renames lib/ before
// index.php, and a request between the two runs the old index.php.
require_once __DIR__ . '/empty_poll.php';

use PDO;

// Reticulum-php is request-operated. These interface/runtime helpers prepare
// queued packets for the next authenticated exchange; they do not form an
// independent background transport path.

trait RequestInterfaceRuntimeTrait
{
    /** @var array<string, array> In-memory cache for interfaceMetadata() — avoids
     *  repeated SELECTs for the same interface within a single request. Called
     *  per-packet in eligibleOutboundPackets (N queries for N packets). */
    private array $metadataCache = [];
    /** @var array<string,true> interfaces whose queue cap was checked in this request */
    private array $queueCapCheckedThisRequest = [];

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
        Database::executeWithRetry($insert, 'seedTransportState');

        return $identityHashHex;
    }

    /**
     * $currentExchangeInterfaceId (the interface whose request queued the
     * packet) is no longer read: it only kept the wake_url path from waking
     * the interface it was already answering, and that path is gone.
     */
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

        // Announce dedup per destination per interface: replace older announce for same dest.
        // Matches Python RNS announce_queue dedup behaviour (Transport.py ~line 1380).
        $replaced = false;
        if ($reason === 'relay_announce' && $destinationHashHex !== '') {
            $replaceStmt = $this->db->prepare(
                'UPDATE outbound_packets
                 SET packet_base64 = :packet_base64,
                     packet_hash_hex = :packet_hash_hex,
                     queued_at = :queued_at,
                     delivered_at = NULL,
                     delivered_batch_id = NULL
                 WHERE interface_id = :interface_id
                   AND destination_hash_hex = :dest_hash_hex
                   AND queue_reason = :queue_reason
                   AND acked_at IS NULL
                   AND delivered_batch_id IS NULL'
            );
            $replaceStmt->bindValue(':packet_base64', $wrappedPacketBase64, PDO::PARAM_STR);
            $replaceStmt->bindValue(':packet_hash_hex', (string) ($parsedPacket['packet_hash_hex'] ?? ''), PDO::PARAM_STR);
            $replaceStmt->bindValue(':queued_at', time(), PDO::PARAM_INT);
            $replaceStmt->bindValue(':interface_id', $interfaceId, PDO::PARAM_STR);
            $replaceStmt->bindValue(':dest_hash_hex', $destinationHashHex, PDO::PARAM_STR);
            $replaceStmt->bindValue(':queue_reason', 'relay_announce', PDO::PARAM_STR);
            Database::executeWithRetry($replaceStmt, 'replaceQueuedAnnounce');
            $replaced = $replaceStmt->rowCount() > 0;
        }

        if (!$replaced) {
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
            Database::executeWithRetry($stmt, 'queueOutboundPacket');
        }

        // The packet is committed (autocommit; the node opens no
        // transactions): the interface's next poll must take the full path.
        EmptyPoll::clear($this->config ?? [], $interfaceId);
        // A packet for a PHP peer is a wake owed, whether or not an epilogue
        // follows this request (/v1/wake has none): idle polls must stop
        // taking the shortcut until an epilogue has woken the peer.
        if ($this->isPhpPeerInterface($interfaceId)) {
            EmptyPoll::noteWakesOwed($this->config ?? []);
        }

        // Cap pending outbound per interface at 256. Drop oldest unissued entries.
        // Python RNS caps announce_queue at MAX_QUEUED_ANNOUNCES (16384).
        // The queue cap is per interface, not per packet: check it once per
        // interface per request. A request that queues 64 announces for one
        // browser used to run this block 64 times.
        //
        // Queueing never wakes anyone and never starts a process: peers are
        // woken by the request epilogue (dispatchWakes). Until 2026-10-04 any
        // row whose metadata carried a wake_url got a wake_events row here.
        if (isset($this->queueCapCheckedThisRequest[$interfaceId])) {
            return;
        }
        $this->queueCapCheckedThisRequest[$interfaceId] = true;
        $minIdStmt = $this->db->prepare(
            'SELECT packet_id FROM outbound_packets
             WHERE interface_id = :cap_iface
               AND acked_at IS NULL
               AND delivered_batch_id IS NULL
             ORDER BY packet_id DESC
             LIMIT 1 OFFSET :offset'
        );
        $minIdStmt->bindValue(':cap_iface', $interfaceId, PDO::PARAM_STR);
        $minIdStmt->bindValue(':offset', 255, PDO::PARAM_INT);
        $minIdStmt->execute();
        $minKeepId = $minIdStmt->fetchColumn();

        if ($minKeepId !== false && $minKeepId !== null) {
            // Find the rows, then delete by primary key ascending: the one
            // lock order for the packet tables (see deleteSingleBatch). This
            // range DELETE, driven by the delivered_batch_id index, was one of
            // the two partners in every `requeueOutboundPackets` deadlock -
            // and it ran bare on the request path, so an unretried 1213
            // would have failed the exchange.
            $idStmt = $this->db->prepare(
                'SELECT packet_id FROM outbound_packets
                 WHERE interface_id = :del_iface
                   AND acked_at IS NULL
                   AND delivered_batch_id IS NULL
                   AND packet_id < :min_id
                 ORDER BY packet_id'
            );
            $idStmt->bindValue(':del_iface', $interfaceId, PDO::PARAM_STR);
            $idStmt->bindValue(':min_id', (int) $minKeepId, PDO::PARAM_INT);
            $idStmt->execute();
            $dropIds = array_map('intval', $idStmt->fetchAll(PDO::FETCH_COLUMN));
            if ($dropIds !== []) {
                $placeholders = implode(',', array_fill(0, count($dropIds), '?'));
                $delStmt = $this->db->prepare("DELETE FROM outbound_packets WHERE packet_id IN ({$placeholders})");
                foreach ($dropIds as $i => $id) {
                    $delStmt->bindValue($i + 1, $id, PDO::PARAM_INT);
                }
                Database::executeWithRetry($delStmt, 'capOutboundQueue');
            }
        }
    }

    /**
     * After a full exchange or poll from $interfaceId (see EmptyPoll::markIdle).
     * A PHP peer (another node, or a gateway) gets no mark: its credentials are
     * revoked by deleting its row in SQL (README, rotating a leaked peer
     * session), which no code here sees, and the old credential must be
     * refused at the very next exchange, not when a mark runs out.
     */
    public function markIdleIfNothingQueued(string $interfaceId, string $sessionToken): void
    {
        if ($this->isPhpPeerInterface($interfaceId)) {
            return;
        }
        EmptyPoll::markIdle(
            $this->config,
            $interfaceId,
            $sessionToken,
            // Read after the mark is written, like the count: a row deleted
            // or given a new token while this request ran takes the mark away.
            fn (): int => $this->idleMarkCredentialHolds($interfaceId, $sessionToken)
                ? $this->pendingOutboundPacketCount($interfaceId)
                : 1,
            // last_seen_at was stamped at the start: the mark runs out
            // seconds() after that, not after this request's end.
            (int) ($_SERVER['REQUEST_TIME'] ?? time()),
        );
    }

    /** The interface still exists, with this token, and is not a PHP peer. */
    private function idleMarkCredentialHolds(string $interfaceId, string $sessionToken): bool
    {
        $stmt = $this->db->prepare(
            'SELECT session_token, peer_url, peer_interface_id FROM interfaces WHERE interface_id = :interface_id'
        );
        $stmt->bindValue(':interface_id', $interfaceId, PDO::PARAM_STR);
        $stmt->execute();
        $row = $stmt->fetch(PDO::FETCH_ASSOC);
        return is_array($row)
            && hash_equals((string) $row['session_token'], $sessionToken)
            && ($row['peer_url'] === null || $row['peer_interface_id'] === null);
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

    private function interfaceMetadata(string $interfaceId): array
    {
        if (array_key_exists($interfaceId, $this->metadataCache)) {
            return $this->metadataCache[$interfaceId];
        }

        $stmt = $this->db->prepare('SELECT metadata_json FROM interfaces WHERE interface_id = :interface_id');
        $stmt->bindValue(':interface_id', $interfaceId, PDO::PARAM_STR);
        $row = $stmt->execute(); $row = $stmt->fetch(PDO::FETCH_ASSOC);
        if (!is_array($row)) {
            $this->metadataCache[$interfaceId] = [];
            return [];
        }

        $metadata = self::decodeJson((string) $row['metadata_json']);
        $this->metadataCache[$interfaceId] = $metadata;
        return $metadata;
    }

    private function ifacConfig(string $interfaceId): ?array
    {
        return IfacCodec::configFromMetadata($this->interfaceMetadata($interfaceId));
    }

    private function interfaceMode(string $interfaceId): int
    {
        $metadata = $this->interfaceMetadata($interfaceId);
        return (int) ($metadata['mode'] ?? 1); // default MODE_FULL
    }
}