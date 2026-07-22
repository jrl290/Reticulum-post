<?php

declare(strict_types=1);

namespace ReticulumPhp;

use PDO;

// Reticulum-php is request-operated. These interface registry helpers only
// persist credentials and state for the next authenticated request exchange;
// they do not create a second transport path.

trait RequestInterfaceRegistryTrait
{
    public function registerInterface(string $name, int $bitrate, int $mtu, array $metadata): array
    {
        $now = time();
        $sessionToken = bin2hex(random_bytes(32));

        $peerUrl = null;
        $peerInterfaceId = null;
        $peerSessionToken = null;
        if (($metadata['client'] ?? null) === 'reticulum-php') {
            $peerUrl = isset($metadata['peer_url']) && is_string($metadata['peer_url']) ? rtrim(trim($metadata['peer_url']), '/') : null;
            $peerInterfaceId = isset($metadata['peer_interface_id']) && is_string($metadata['peer_interface_id']) ? $metadata['peer_interface_id'] : null;
            $peerSessionToken = isset($metadata['peer_session_token']) && is_string($metadata['peer_session_token']) ? $metadata['peer_session_token'] : null;
        }

        // Bridge interface dedup: if a peer_url already has an interface, update it
        // instead of creating a duplicate. Matches Python RNS where interfaces are
        // singletons identified by transport object identity.
        if ($peerUrl !== null && $peerInterfaceId !== null) {
            $existing = $this->phpPeerInterfaceByPeerUrl($peerUrl);
            if ($existing !== null) {
                $interfaceId = (string) $existing['interface_id'];
                $updateStmt = $this->db->prepare(
                    'UPDATE interfaces
                     SET session_token = :session_token,
                         name = :name,
                         bitrate = :bitrate,
                         mtu = :mtu,
                         status = :status,
                         metadata_json = :metadata_json,
                         last_seen_at = :last_seen_at,
                         peer_url = :peer_url,
                         peer_interface_id = :peer_interface_id,
                         peer_session_token = :peer_session_token
                     WHERE interface_id = :interface_id'
                );
                $updateStmt->bindValue(':session_token', $sessionToken, PDO::PARAM_STR);
                $updateStmt->bindValue(':name', $name, PDO::PARAM_STR);
                $updateStmt->bindValue(':bitrate', $bitrate, PDO::PARAM_INT);
                $updateStmt->bindValue(':mtu', $mtu, PDO::PARAM_INT);
                $updateStmt->bindValue(':status', 'online', PDO::PARAM_STR);
                $updateStmt->bindValue(':metadata_json', self::encodeJson($metadata), PDO::PARAM_STR);
                $updateStmt->bindValue(':last_seen_at', $now, PDO::PARAM_INT);
                $updateStmt->bindValue(':peer_url', $peerUrl, PDO::PARAM_STR);
                $updateStmt->bindValue(':peer_interface_id', $peerInterfaceId, PDO::PARAM_STR);
                $updateStmt->bindValue(':peer_session_token', $peerSessionToken, $peerSessionToken === null ? PDO::PARAM_NULL : PDO::PARAM_STR);
                $updateStmt->bindValue(':interface_id', $interfaceId, PDO::PARAM_STR);
                $updateStmt->execute();

                return [
                    'interface_id' => $interfaceId,
                    'session_token' => $sessionToken,
                ];
            }
        }

        // RNS PostInterface dedup: match by persistent identity_hash so
        // the same browser/client across restarts reuses its interface.
        // Avoids name+client collisions where multiple different clients
        // share the same name (e.g. "Retichat Web").
        $identityHash = (string) ($metadata['identity_hash'] ?? '');
        if ($identityHash !== '') {
            $existing = $this->interfaceByIdentityHash($identityHash);
            if ($existing !== null) {
                $interfaceId = (string) $existing['interface_id'];
                $updateStmt2 = $this->db->prepare(
                    'UPDATE interfaces
                     SET session_token = :session_token,
                         bitrate = :bitrate,
                         mtu = :mtu,
                         status = :status,
                         metadata_json = :metadata_json,
                         last_seen_at = :last_seen_at
                     WHERE interface_id = :interface_id'
                );
                $updateStmt2->bindValue(':session_token', $sessionToken, PDO::PARAM_STR);
                $updateStmt2->bindValue(':bitrate', $bitrate, PDO::PARAM_INT);
                $updateStmt2->bindValue(':mtu', $mtu, PDO::PARAM_INT);
                $updateStmt2->bindValue(':status', 'online', PDO::PARAM_STR);
                $updateStmt2->bindValue(':metadata_json', self::encodeJson($metadata), PDO::PARAM_STR);
                $updateStmt2->bindValue(':last_seen_at', $now, PDO::PARAM_INT);
                $updateStmt2->bindValue(':interface_id', $interfaceId, PDO::PARAM_STR);
                $updateStmt2->execute();

                return [
                    'interface_id' => $interfaceId,
                    'session_token' => $sessionToken,
                ];
            }
        }

        $interfaceId = bin2hex(random_bytes(16));

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
        $stmt->bindValue(':interface_id', $interfaceId, PDO::PARAM_STR);
        $stmt->bindValue(':name', $name, PDO::PARAM_STR);
        $stmt->bindValue(':session_token', $sessionToken, PDO::PARAM_STR);
        $stmt->bindValue(':bitrate', $bitrate, PDO::PARAM_INT);
        $stmt->bindValue(':mtu', $mtu, PDO::PARAM_INT);
        $stmt->bindValue(':status', 'online', PDO::PARAM_STR);
        $stmt->bindValue(':metadata_json', self::encodeJson($metadata), PDO::PARAM_STR);
        $stmt->bindValue(':created_at', $now, PDO::PARAM_INT);
        $stmt->bindValue(':last_seen_at', $now, PDO::PARAM_INT);
        $stmt->bindValue(':peer_url', $peerUrl, $peerUrl === null ? PDO::PARAM_NULL : PDO::PARAM_STR);
        $stmt->bindValue(':peer_interface_id', $peerInterfaceId, $peerInterfaceId === null ? PDO::PARAM_NULL : PDO::PARAM_STR);
        $stmt->bindValue(':peer_session_token', $peerSessionToken, $peerSessionToken === null ? PDO::PARAM_NULL : PDO::PARAM_STR);
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
        $sql = Database::upsertSql(
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
                peer_session_token = excluded.peer_session_token',
            $this->backend
        );
        $stmt = $this->db->prepare($sql);
        $stmt->bindValue(':interface_id', $interfaceId, PDO::PARAM_STR);
        $stmt->bindValue(':name', $name, PDO::PARAM_STR);
        $stmt->bindValue(':session_token', $sessionToken, PDO::PARAM_STR);
        $stmt->bindValue(':bitrate', $bitrate, PDO::PARAM_INT);
        $stmt->bindValue(':mtu', $mtu, PDO::PARAM_INT);
        $stmt->bindValue(':status', 'online', PDO::PARAM_STR);
        $stmt->bindValue(':metadata_json', self::encodeJson($metadata), PDO::PARAM_STR);
        $stmt->bindValue(':created_at', $now, PDO::PARAM_INT);
        $stmt->bindValue(':last_seen_at', $now, PDO::PARAM_INT);
        $stmt->bindValue(':peer_url', $peerUrl, $peerUrl === null ? PDO::PARAM_NULL : PDO::PARAM_STR);
        $stmt->bindValue(':peer_interface_id', $peerInterfaceId, $peerInterfaceId === null ? PDO::PARAM_NULL : PDO::PARAM_STR);
        $stmt->bindValue(':peer_session_token', $peerSessionToken, $peerSessionToken === null ? PDO::PARAM_NULL : PDO::PARAM_STR);
        $stmt->execute();
    }

    public function authenticateInterface(string $interfaceId, string $sessionToken): array
    {
        $stmt = $this->db->prepare(
            'SELECT interface_id, name, session_token, bitrate, mtu, status, metadata_json, created_at, last_seen_at
             FROM interfaces WHERE interface_id = :interface_id'
        );
        $stmt->bindValue(':interface_id', $interfaceId, PDO::PARAM_STR);
        $stmt->execute(); $row = $stmt->fetch(PDO::FETCH_ASSOC);

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
        $stmt->bindValue(':last_seen_at', time(), PDO::PARAM_INT);
        $stmt->bindValue(':status', $status, PDO::PARAM_STR);
        $stmt->bindValue(':interface_id', $interfaceId, PDO::PARAM_STR);
        $stmt->execute();
    }

    private function interfaceBitrate(string $interfaceId): ?int
    {
        $stmt = $this->db->prepare('SELECT bitrate FROM interfaces WHERE interface_id = :interface_id');
        $stmt->bindValue(':interface_id', $interfaceId, PDO::PARAM_STR);
        $stmt->execute(); $row = $stmt->fetch(PDO::FETCH_ASSOC);
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
        $stmt->execute();

        $rows = [];
        while (($row = $stmt->fetch(PDO::FETCH_ASSOC)) !== false) {
            if (!is_array($row)) {
                continue;
            }
            $rows[] = $row;
        }

        return $rows;
    }

    public function phpPeerInterfaceIdsWithPendingAcks(): array
    {
        $stmt = $this->db->prepare(
            "SELECT i.interface_id, i.peer_url, i.peer_interface_id, i.peer_session_token, i.last_wake_sent_at
             FROM interfaces i
             WHERE i.peer_url IS NOT NULL
               AND i.peer_interface_id IS NOT NULL
               AND i.peer_session_token IS NOT NULL
               AND i.pending_ack_batch_ids_json IS NOT NULL
               AND i.pending_ack_batch_ids_json != '[]'
               AND i.pending_ack_batch_ids_json != ''"
        );
        $stmt->execute();

        $rows = [];
        while (($row = $stmt->fetch(PDO::FETCH_ASSOC)) !== false) {
            if (!is_array($row)) {
                continue;
            }
            $rows[] = $row;
        }

        return $rows;
    }

    public function isPhpPeerInterface(string $interfaceId): bool
    {
        $stmt = $this->db->prepare(
            'SELECT 1 FROM interfaces WHERE interface_id = :id AND peer_url IS NOT NULL AND peer_interface_id IS NOT NULL LIMIT 1'
        );
        $stmt->bindValue(':id', $interfaceId, PDO::PARAM_STR);
        $stmt->execute();
        return $stmt->fetch(PDO::FETCH_NUM) !== false;
    }

    public function phpPeerInterfaceByPeerUrl(string $peerUrl): ?array
    {
        $peerUrl = rtrim($peerUrl, '/');

        // Try exact match first.
        $stmt = $this->db->prepare(
            'SELECT interface_id, peer_url, peer_interface_id, peer_session_token
             FROM interfaces
             WHERE peer_url = :peer_url
             LIMIT 1'
        );
        $stmt->bindValue(':peer_url', $peerUrl, PDO::PARAM_STR);
        $stmt->execute(); $row = $stmt->fetch(PDO::FETCH_ASSOC);
        if (is_array($row)) {
            return $row;
        }

        // Try with /v1/wake appended.
        $stmt->bindValue(':peer_url', $peerUrl . '/v1/wake', PDO::PARAM_STR);
        $stmt->execute(); $row = $stmt->fetch(PDO::FETCH_ASSOC);
        if (is_array($row)) {
            return $row;
        }

        // Try stripping /v1/wake.
        if (str_ends_with($peerUrl, '/v1/wake')) {
            $baseUrl = substr($peerUrl, 0, -strlen('/v1/wake'));
            $stmt->bindValue(':peer_url', $baseUrl, PDO::PARAM_STR);
            $stmt->execute(); $row = $stmt->fetch(PDO::FETCH_ASSOC);
            if (is_array($row)) {
                return $row;
            }
        }

        return null;
    }

    private function interfaceByIdentityHash(string $identityHash): ?array
    {
        $stmt = $this->db->prepare(
            "SELECT interface_id, name, metadata_json
             FROM interfaces
             WHERE metadata_json LIKE :hash_pattern
             LIMIT 1"
        );
        $stmt->bindValue(':hash_pattern', '%"identity_hash":"' . $identityHash . '"%', PDO::PARAM_STR);
        $stmt->execute();
        $row = $stmt->fetch(PDO::FETCH_ASSOC);

        return is_array($row) ? $row : null;
    }

    public function touchPeerWakeSent(string $interfaceId): void
    {
        $stmt = $this->db->prepare(
            'UPDATE interfaces SET last_wake_sent_at = :now WHERE interface_id = :interface_id'
        );
        $stmt->bindValue(':now', time(), PDO::PARAM_INT);
        $stmt->bindValue(':interface_id', $interfaceId, PDO::PARAM_STR);
        $stmt->execute();
    }

    /**
     * Return online PHP peer interface IDs, excluding the given interface.
     *
     * @return list<string>
     */
    private function activePeerInterfaceIds(string $excludeInterfaceId): array
    {
        $stmt = $this->db->prepare(
            'SELECT interface_id FROM interfaces
             WHERE peer_url IS NOT NULL
               AND peer_interface_id IS NOT NULL
               AND status = :status
               AND interface_id != :exclude_id'
        );
        $stmt->bindValue(':status', 'online', PDO::PARAM_STR);
        $stmt->bindValue(':exclude_id', $excludeInterfaceId, PDO::PARAM_STR);
        $stmt->execute();

        $ids = [];
        while (($row = $stmt->fetch(PDO::FETCH_ASSOC)) !== false) {
            if (is_array($row)) {
                $id = (string) ($row['interface_id'] ?? '');
                if ($id !== '') {
                    $ids[] = $id;
                }
            }
        }

        return $ids;
    }
}