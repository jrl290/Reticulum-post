<?php

declare(strict_types=1);

namespace ReticulumPhp;

use PDO;

// Reticulum-php is request-operated. These path and announce state helpers
// persist routing knowledge for later authenticated exchanges; they do not
// create a second background transport channel.

trait RequestPathStateTrait
{
    private function knownDestinationPublicKey(string $destinationHashHex): ?string
    {
        $stmt = $this->db->prepare(
            'SELECT public_key_hex FROM known_destinations WHERE destination_hash_hex = :destination_hash_hex'
        );
        $stmt->bindValue(':destination_hash_hex', $destinationHashHex, PDO::PARAM_STR);
        $row = $stmt->execute(); $row = $stmt->fetch(PDO::FETCH_ASSOC);

        return is_array($row) ? (string) $row['public_key_hex'] : null;
    }

    private function rememberKnownDestination(string $destinationHashHex, string $packetHashHex, array $announce): void
    {
        $sql = 'INSERT INTO known_destinations (
                destination_hash_hex,
                packet_hash_hex,
                public_key_hex,
                identity_hash_hex,
                app_data_base64,
                ratchet_hex,
                updated_at
            ) VALUES (
                :destination_hash_hex,
                :packet_hash_hex,
                :public_key_hex,
                :identity_hash_hex,
                :app_data_base64,
                :ratchet_hex,
                :updated_at
            )
            ON CONFLICT(destination_hash_hex) DO UPDATE SET
                packet_hash_hex = excluded.packet_hash_hex,
                public_key_hex = excluded.public_key_hex,
                identity_hash_hex = excluded.identity_hash_hex,
                app_data_base64 = excluded.app_data_base64,
                ratchet_hex = excluded.ratchet_hex,
                updated_at = excluded.updated_at';
        $sql = Database::upsertSql($sql, $this->backend);
        $stmt = $this->db->prepare($sql);
        $stmt->bindValue(':destination_hash_hex', $destinationHashHex, PDO::PARAM_STR);
        $stmt->bindValue(':packet_hash_hex', $packetHashHex, PDO::PARAM_STR);
        $stmt->bindValue(':public_key_hex', (string) $announce['public_key_hex'], PDO::PARAM_STR);
        $stmt->bindValue(':identity_hash_hex', (string) $announce['identity_hash_hex'], PDO::PARAM_STR);
        $stmt->bindValue(':app_data_base64', $announce['app_data_base64'], $announce['app_data_base64'] === null ? PDO::PARAM_NULL : PDO::PARAM_STR);
        $stmt->bindValue(':ratchet_hex', $announce['ratchet_hex'], $announce['ratchet_hex'] === null ? PDO::PARAM_NULL : PDO::PARAM_STR);
        $stmt->bindValue(':updated_at', time(), PDO::PARAM_INT);
        $stmt->execute();
    }

    private function pathEntry(string $destinationHashHex): ?array
    {
        $normalized = strtolower($destinationHashHex);
        $stmt = $this->db->prepare('SELECT * FROM path_entries WHERE destination_hash_hex = :destination_hash_hex');
        $stmt->bindValue(':destination_hash_hex', $normalized, PDO::PARAM_STR);
        $stmt->execute(); $row = $stmt->fetch(PDO::FETCH_ASSOC);

        return is_array($row) ? $row : null;
    }

    private function usablePathEntry(string $destinationHashHex): ?array
    {
        $path = $this->pathEntry($destinationHashHex);
        if ($path === null) {
            return null;
        }

        if ((int) ($path['expires_at'] ?? 0) < time()) {
            return null;
        }

        $interfaceId = (string) ($path['interface_id'] ?? '');
        if ($interfaceId === '' || !$this->isInterfaceActive($interfaceId)) {
            return null;
        }

        return $path;
    }

    private function deletePathEntry(string $destinationHashHex): void
    {
        $stmt = $this->db->prepare('DELETE FROM path_entries WHERE destination_hash_hex = :destination_hash_hex');
        $stmt->bindValue(':destination_hash_hex', $destinationHashHex, PDO::PARAM_STR);
        Database::executeWithRetry($stmt, 'deletePathEntries');
    }

    private function rememberPathRequestTag(string $tagKeyHex): bool
    {
        $stmt = $this->db->prepare(Database::insertOrSql($this->backend,
            'INSERT OR IGNORE INTO path_request_tags (tag_key_hex, created_at)
             VALUES (:tag_key_hex, :created_at)'
        ));
        $stmt->bindValue(':tag_key_hex', $tagKeyHex, PDO::PARAM_STR);
        $stmt->bindValue(':created_at', time(), PDO::PARAM_INT);
        $stmt->execute();

        return $stmt->rowCount() > 0;
    }

    /**
     * Per-destination rate limit for path requests, returning true if the
     * caller may emit one now.
     *
     * The Python daemon holds this state in memory: Transport.path_requests
     * throttles automated requests to one per PATH_REQUEST_MI (Transport.py:81,
     * :490), and Transport.discovery_path_requests suppresses a repeat search
     * for a destination that already has one pending, for PATH_REQUEST_TIMEOUT
     * (Transport.py:2915-2918). This node is request-operated and keeps no
     * process memory between requests, so the same state lives in a table.
     *
     * Without it, tag deduplication is the only guard, and every retry carries
     * a fresh random tag (Transport.py:2669), so a destination with no path is
     * re-flooded to every local client on every single retry.
     */
    private function claimPathRequestSlot(string $throttleKey, int $minIntervalSeconds): bool
    {
        $now = time();

        $update = $this->db->prepare(
            'UPDATE path_request_throttle
                SET last_requested_at = :now
              WHERE throttle_key = :throttle_key
                AND last_requested_at <= :cutoff'
        );
        $update->bindValue(':now', $now, PDO::PARAM_INT);
        $update->bindValue(':throttle_key', $throttleKey, PDO::PARAM_STR);
        $update->bindValue(':cutoff', $now - $minIntervalSeconds, PDO::PARAM_INT);
        Database::executeWithRetry($update, 'updatePathRequestThrottle');

        if ($update->rowCount() > 0) {
            return true;
        }

        $insert = $this->db->prepare(Database::insertOrSql($this->backend,
            'INSERT OR IGNORE INTO path_request_throttle (throttle_key, last_requested_at)
             VALUES (:throttle_key, :now)'
        ));
        $insert->bindValue(':throttle_key', $throttleKey, PDO::PARAM_STR);
        $insert->bindValue(':now', $now, PDO::PARAM_INT);
        $insert->execute();

        return $insert->rowCount() > 0;
    }

    private function pathRequestControlHashHex(): string
    {
        $expanded = TransportConstants::APP_NAME
            . '.' . TransportConstants::PATH_REQUEST_ASPECT_1
            . '.' . TransportConstants::PATH_REQUEST_ASPECT_2;
        $nameHash = substr(hash('sha256', $expanded, true), 0, 10);

        return bin2hex(substr(hash('sha256', $nameHash, true), 0, 16));
    }

    private function announceRawByPacketHash(string $packetHashHex): ?string
    {
        $record = $this->cachedAnnounceRecordByPacketHash($packetHashHex);
        if ($record === null) {
            return null;
        }

        $raw = base64_decode((string) $record['raw_base64'], true);
        return is_string($raw) ? $raw : null;
    }

    private function cachedAnnounceRecordByPacketHash(string $packetHashHex): ?array
    {
        $stmt = $this->db->prepare(
            'SELECT interface_id AS received_interface_id, raw_base64
             FROM inbound_packets
             WHERE packet_hash_hex = :packet_hash_hex
               AND status = :status
               AND packet_type = :packet_type
             ORDER BY packet_record_id DESC
             LIMIT 1'
        );
        $stmt->bindValue(':packet_hash_hex', $packetHashHex, PDO::PARAM_STR);
        $stmt->bindValue(':status', 'parsed', PDO::PARAM_STR);
        $stmt->bindValue(':packet_type', 1, PDO::PARAM_INT);
        $row = $stmt->execute(); $row = $stmt->fetch(PDO::FETCH_ASSOC);
        return is_array($row) ? $row : null;
    }

    private function buildPathResponsePacket(string $announceRaw, string $destinationHashHex, int $hops): string
    {
        $announce = PacketParser::parseRaw($announceRaw);
        $announcePayload = base64_decode((string) $announce['payload_base64'], true);
        if (!is_string($announcePayload)) {
            throw new RuntimeException('Cached announce payload is invalid');
        }

        $originalFlags = ord($announceRaw[0]);
        $newFlags = ($originalFlags & 0x20) | 0x40 | 0x10 | ($originalFlags & 0x0F);
        $transportIdentity = hex2bin($this->transportIdentityHashHex());
        $destinationHash = hex2bin($destinationHashHex);
        if (!is_string($transportIdentity) || strlen($transportIdentity) !== 16) {
            throw new RuntimeException('Transport identity hash is invalid');
        }

        if (!is_string($destinationHash) || strlen($destinationHash) !== 16) {
            throw new RuntimeException('Destination hash is invalid for PATH_RESPONSE');
        }

        $boundedHops = max(0, min(255, $hops));
        return chr($newFlags)
            . chr($boundedHops)
            . $transportIdentity
            . $destinationHash
            . chr(0x0B)
            . $announcePayload;
    }

    private function pathExpirySeconds(string $interfaceId): int
    {
        $metadata = $this->interfaceMetadata($interfaceId);
        $mode = $metadata['mode'] ?? $metadata['interface_mode'] ?? null;
        if ($mode === 'access_point') {
            return (int) ($this->config['transport']['path_expiry_access_point_seconds'] ?? 86400);
        }

        if ($mode === 'roaming') {
            return (int) ($this->config['transport']['path_expiry_roaming_seconds'] ?? 21600);
        }

        return (int) ($this->config['transport']['path_expiry_default_seconds'] ?? 604800);
    }

    private function randomBlobTimebase(array $randomBlobs): int
    {
        // Ignore emission times beyond a small clock-skew allowance: a single
        // announce carrying a far-future timestamp would otherwise raise the
        // baseline permanently and make every subsequent announce for this
        // destination look stale.
        $ceiling = time() + 86_400;
        $max = 0;
        foreach ($randomBlobs as $blobHex) {
            if (!is_string($blobHex)) {
                continue;
            }

            $blob = hex2bin($blobHex);
            if (!is_string($blob) || strlen($blob) !== 10) {
                continue;
            }

            $emitted = unpack('J', "\x00\x00\x00" . substr($blob, 5, 5))[1];
            if ($emitted > $ceiling) {
                continue;
            }

            $max = max($max, $emitted);
        }

        return $max;
    }
}