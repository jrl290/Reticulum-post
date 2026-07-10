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

        $peerUrl = null;
        $peerInterfaceId = null;
        $peerSessionToken = null;
        if (($metadata['client'] ?? null) === 'reticulum-php') {
            $peerUrl = isset($metadata['peer_url']) && is_string($metadata['peer_url']) ? rtrim(trim($metadata['peer_url']), '/') : null;
            $peerInterfaceId = isset($metadata['peer_interface_id']) && is_string($metadata['peer_interface_id']) ? $metadata['peer_interface_id'] : null;
            $peerSessionToken = isset($metadata['peer_session_token']) && is_string($metadata['peer_session_token']) ? $metadata['peer_session_token'] : null;
        }

        $stmt = $this->db->prepare(
            'INSERT INTO interfaces (
                interface_id, name, session_token, bitrate, mtu, status,
                metadata_json, created_at, last_seen_at,
                peer_url, peer_interface_id, peer_session_token
            ) VALUES (
                :interface_id, :name, :session_token, :bitrate, :mtu, :status,
                :metadata_json, :created_at, :last_seen_at,
                :peer_url, :peer_interface_id, :peer_session_token
            )'
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
        $stmt->bindValue(':peer_url', $peerUrl, $peerUrl === null ? SQLITE3_NULL : SQLITE3_TEXT);
        $stmt->bindValue(':peer_interface_id', $peerInterfaceId, $peerInterfaceId === null ? SQLITE3_NULL : SQLITE3_TEXT);
        $stmt->bindValue(':peer_session_token', $peerSessionToken, $peerSessionToken === null ? SQLITE3_NULL : SQLITE3_TEXT);
        $stmt->execute();

        $response = [
            'interface_id' => $interfaceId,
            'session_token' => $sessionToken,
        ];

        if ($peerInterfaceId !== null) {
            $response['peer_interface_id'] = $peerInterfaceId;
        }
        if ($peerSessionToken !== null) {
            $response['peer_session_token'] = $peerSessionToken;
        }

        return $response;
    }

    public function upsertConfiguredInterface(string $interfaceId, string $name, string $sessionToken, int $bitrate, int $mtu, array $metadata, ?string $peerUrl = null, ?string $peerInterfaceId = null, ?string $peerSessionToken = null): void
    {
        $now = time();
        $stmt = $this->db->prepare(
            'INSERT INTO interfaces (
                interface_id, name, session_token, bitrate, mtu, status,
                metadata_json, created_at, last_seen_at,
                peer_url, peer_interface_id, peer_session_token
            ) VALUES (
                :interface_id, :name, :session_token, :bitrate, :mtu, :status,
                :metadata_json, :created_at, :last_seen_at,
                :peer_url, :peer_interface_id, :peer_session_token
            )
            ON CONFLICT(interface_id) DO UPDATE SET
                name = excluded.name,
                session_token = excluded.session_token,
                bitrate = excluded.bitrate,
                mtu = excluded.mtu,
                status = excluded.status,
                metadata_json = excluded.metadata_json,
                last_seen_at = excluded.last_seen_at,
                peer_url = excluded.peer_url,
                peer_interface_id = excluded.peer_interface_id,
                peer_session_token = excluded.peer_session_token'
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
        $stmt->bindValue(':peer_url', $peerUrl, $peerUrl === null ? SQLITE3_NULL : SQLITE3_TEXT);
        $stmt->bindValue(':peer_interface_id', $peerInterfaceId, $peerInterfaceId === null ? SQLITE3_NULL : SQLITE3_TEXT);
        $stmt->bindValue(':peer_session_token', $peerSessionToken, $peerSessionToken === null ? SQLITE3_NULL : SQLITE3_TEXT);
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

    public function phpPeerInterfaceIdsWithPendingOutbound(): array
    {
        $stmt = $this->db->prepare(
            'SELECT DISTINCT i.interface_id, i.peer_url, i.peer_interface_id, i.peer_session_token, i.last_wake_sent_at
             FROM interfaces i
             INNER JOIN outbound_packets op ON op.interface_id = i.interface_id
             WHERE i.peer_url IS NOT NULL
               AND i.peer_interface_id IS NOT NULL
               AND i.peer_session_token IS NOT NULL
               AND op.acked_at IS NULL
             ORDER BY i.interface_id'
        );
        $result = $stmt->execute();

        $rows = [];
        while (($row = $result->fetchArray(SQLITE3_ASSOC)) !== false) {
            if (!is_array($row)) {
                continue;
            }
            $rows[] = $row;
        }

        return $rows;
    }

    public function phpPeerInterfaceByPeerUrl(string $peerUrl): ?array
    {
        $stmt = $this->db->prepare(
            'SELECT interface_id, peer_url, peer_interface_id, peer_session_token
             FROM interfaces
             WHERE peer_url = :peer_url
             LIMIT 1'
        );
        $stmt->bindValue(':peer_url', $peerUrl, SQLITE3_TEXT);
        $row = $stmt->execute()->fetchArray(SQLITE3_ASSOC);

        return is_array($row) ? $row : null;
    }

    public function touchPeerWakeSent(string $interfaceId): void
    {
        $stmt = $this->db->prepare(
            'UPDATE interfaces SET last_wake_sent_at = :now WHERE interface_id = :interface_id'
        );
        $stmt->bindValue(':now', time(), SQLITE3_INTEGER);
        $stmt->bindValue(':interface_id', $interfaceId, SQLITE3_TEXT);
        $stmt->execute();
    }
}