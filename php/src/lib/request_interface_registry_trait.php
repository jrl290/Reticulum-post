<?php

declare(strict_types=1);

namespace ReticulumPhp;

// Reticulum-php is request-operated. These interface registry helpers only
// persist credentials and state for the next authenticated request exchange;
// they do not create a second transport path.

trait RequestInterfaceRegistryTrait
{
    public function registerInterface(string $name, int $bitrate, int $mtu, array $metadata): array
    {
        $now = time();
        $interfaceId = bin2hex(random_bytes(16));
        $sessionToken = bin2hex(random_bytes(32));
        $stmt = $this->db->prepare(
            'INSERT INTO interfaces (
                interface_id, name, session_token, bitrate, mtu, status,
                metadata_json, created_at, last_seen_at
            ) VALUES (:interface_id, :name, :session_token, :bitrate, :mtu, :status, :metadata_json, :created_at, :last_seen_at)'
        );
        $stmt->bindValue(':interface_id', $interfaceId, SQLITE3_TEXT);
        $stmt->bindValue(':name', $name, SQLITE3_TEXT);
        $stmt->bindValue(':session_token', $sessionToken, SQLITE3_TEXT);
        $stmt->bindValue(':bitrate', $bitrate, SQLITE3_INTEGER);
        $stmt->bindValue(':mtu', $mtu, SQLITE3_INTEGER);
        $stmt->bindValue(':status', 'online', SQLITE3_TEXT);
        $stmt->bindValue(':metadata_json', self::encodeJson($metadata), SQLITE3_TEXT);
        $stmt->bindValue(':created_at', $now, SQLITE3_INTEGER);
        $stmt->bindValue(':last_seen_at', $now, SQLITE3_INTEGER);
        $stmt->execute();

        return [
            'interface_id' => $interfaceId,
            'session_token' => $sessionToken,
        ];
    }

    public function upsertConfiguredInterface(string $interfaceId, string $name, string $sessionToken, int $bitrate, int $mtu, array $metadata): void
    {
        $now = time();
        $stmt = $this->db->prepare(
            'INSERT INTO interfaces (
                interface_id, name, session_token, bitrate, mtu, status,
                metadata_json, created_at, last_seen_at
            ) VALUES (
                :interface_id, :name, :session_token, :bitrate, :mtu, :status,
                :metadata_json, :created_at, :last_seen_at
            )
            ON CONFLICT(interface_id) DO UPDATE SET
                name = excluded.name,
                session_token = excluded.session_token,
                bitrate = excluded.bitrate,
                mtu = excluded.mtu,
                status = excluded.status,
                metadata_json = excluded.metadata_json,
                last_seen_at = excluded.last_seen_at'
        );
        $stmt->bindValue(':interface_id', $interfaceId, SQLITE3_TEXT);
        $stmt->bindValue(':name', $name, SQLITE3_TEXT);
        $stmt->bindValue(':session_token', $sessionToken, SQLITE3_TEXT);
        $stmt->bindValue(':bitrate', $bitrate, SQLITE3_INTEGER);
        $stmt->bindValue(':mtu', $mtu, SQLITE3_INTEGER);
        $stmt->bindValue(':status', 'online', SQLITE3_TEXT);
        $stmt->bindValue(':metadata_json', self::encodeJson($metadata), SQLITE3_TEXT);
        $stmt->bindValue(':created_at', $now, SQLITE3_INTEGER);
        $stmt->bindValue(':last_seen_at', $now, SQLITE3_INTEGER);
        $stmt->execute();
    }

    public function authenticateInterface(string $interfaceId, string $sessionToken): array
    {
        $stmt = $this->db->prepare(
            'SELECT interface_id, name, session_token, bitrate, mtu, status, metadata_json, created_at, last_seen_at
             FROM interfaces WHERE interface_id = :interface_id'
        );
        $stmt->bindValue(':interface_id', $interfaceId, SQLITE3_TEXT);
        $row = $stmt->execute()->fetchArray(SQLITE3_ASSOC);

        if (!is_array($row) || !hash_equals((string) $row['session_token'], $sessionToken)) {
            throw new ApiError(401, 'Invalid interface credentials', ['error' => 'unauthorized']);
        }

        $this->touchInterface($interfaceId, 'online');

        return [
            'interface_id' => (string) $row['interface_id'],
            'name' => (string) $row['name'],
            'bitrate' => (int) $row['bitrate'],
            'mtu' => (int) $row['mtu'],
            'status' => (string) $row['status'],
            'metadata' => self::decodeJson((string) $row['metadata_json']),
        ];
    }

    public function touchInterface(string $interfaceId, string $status = 'online'): void
    {
        $stmt = $this->db->prepare(
            'UPDATE interfaces SET last_seen_at = :last_seen_at, status = :status WHERE interface_id = :interface_id'
        );
        $stmt->bindValue(':last_seen_at', time(), SQLITE3_INTEGER);
        $stmt->bindValue(':status', $status, SQLITE3_TEXT);
        $stmt->bindValue(':interface_id', $interfaceId, SQLITE3_TEXT);
        $stmt->execute();
    }

    private function interfaceBitrate(string $interfaceId): ?int
    {
        $stmt = $this->db->prepare('SELECT bitrate FROM interfaces WHERE interface_id = :interface_id');
        $stmt->bindValue(':interface_id', $interfaceId, SQLITE3_TEXT);
        $row = $stmt->execute()->fetchArray(SQLITE3_ASSOC);
        if (!is_array($row)) {
            return null;
        }

        return isset($row['bitrate']) ? (int) $row['bitrate'] : null;
    }
}