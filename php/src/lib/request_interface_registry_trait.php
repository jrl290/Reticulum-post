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
        //
        // A raw identity_hash is only an UNAUTHENTICATED ownership claim (no
        // signature yet — that is the follow-up redesign). So it is honoured
        // for row matching ONLY when it is a well-formed identity hash:
        // exactly 32 lowercase hex characters (RNS TRUNCATED_HASHLENGTH is
        // 128 bits = 16 bytes = 32 hex), which is what Retichat-js sends.
        // Anything else — a SQL LIKE wildcard like '%' or '_%', a wrong length,
        // upper-case, a value
        // carrying quotes or backslashes, or a non-string — is treated as NO
        // identity claim: the client gets a fresh row and can never re-bind,
        // let alone re-bind an arbitrary existing row. A malformed-but-present
        // claim is logged, never swallowed.
        $identityHash = self::normaliseIdentityHashClaim($metadata['identity_hash'] ?? null);
        if ($identityHash !== null) {
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
        } else {
            $rawIdentityClaim = $metadata['identity_hash'] ?? null;
            // A present-but-malformed claim must speak before it is dropped
            // (silent-failures rule). An absent claim (null or '') is the
            // normal "no identity" case and is not noise worth logging.
            if ($rawIdentityClaim !== null && $rawIdentityClaim !== '') {
                // The claim itself is attacker-controlled, so only its shape is
                // logged: enough to tell a client bug (say, upper-case) from noise.
                error_log(sprintf(
                    '[REG-BAD-IDENTITY] interface register: identity_hash claim (%s, length %d) is not 32 lowercase hex; treating as no identity (new row, no re-bind)',
                    get_debug_type($rawIdentityClaim),
                    is_string($rawIdentityClaim) ? strlen($rawIdentityClaim) : -1
                ));
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

    /**
     * The client's goodbye (POST /v1/interfaces/goodbye, sent as a beacon on
     * pagehide): the interface is marked offline now, and the local
     * destinations and paths registered through it are dropped now — exactly
     * what the stale sweep would do interface_stale_after_seconds later
     * (300 s on retichat.com), during which a closed tab kept capturing direct
     * delivery for its destinations. Idempotent; the sweep remains the backstop
     * for pages that never get to say goodbye. Returns what was dropped.
     */
    public function goodbyeInterface(string $interfaceId): array
    {
        $now = time();
        $stmt = $this->db->prepare(
            "UPDATE interfaces SET status = 'offline', updated_at = :now WHERE interface_id = :interface_id"
        );
        $stmt->bindValue(':now', $now, PDO::PARAM_INT);
        $stmt->bindValue(':interface_id', $interfaceId, PDO::PARAM_STR);
        $stmt->execute();
        $dropped = ['local_destinations' => 0, 'path_entries' => 0];
        foreach (array_keys($dropped) as $table) {
            $del = $this->db->prepare("DELETE FROM {$table} WHERE interface_id = :interface_id");
            $del->bindValue(':interface_id', $interfaceId, PDO::PARAM_STR);
            $del->execute();
            $dropped[$table] = $del->rowCount();
        }
        return $dropped;
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

    /** @var array<string,bool> per-request memo; peer status does not change mid-request */
    private array $phpPeerInterfaceCache = [];

    public function isPhpPeerInterface(string $interfaceId): bool
    {
        if (array_key_exists($interfaceId, $this->phpPeerInterfaceCache)) {
            return $this->phpPeerInterfaceCache[$interfaceId];
        }
        return $this->phpPeerInterfaceCache[$interfaceId] = $this->queryIsPhpPeerInterface($interfaceId);
    }

    private function queryIsPhpPeerInterface(string $interfaceId): bool
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

        // Try exact match first. status/last_seen_at ride along so callers can
        // judge whether the session is actually alive — connectToPeer treating
        // "a row exists" as "we are connected" is what left selectiv cut off
        // from the mesh for 9 hours on 2026-08-17.
        $stmt = $this->db->prepare(
            'SELECT interface_id, peer_url, peer_interface_id, peer_session_token,
                    status, last_seen_at
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

    /**
     * Normalise a raw identity_hash claim from registration metadata.
     *
     * Returns the claim when it is a well-formed identity hash — exactly 32
     * lowercase hex characters (16-byte RNS TRUNCATED_HASHLENGTH) — or null for
     * anything else: a non-string, the empty string, a LIKE wildcard, a wrong
     * length, upper-case, or a value carrying quotes/backslashes. Callers treat
     * null as "no identity claim", so a claim can never re-bind a row unless it
     * is a real identity hash.
     *
     * Lower-case is required, not coerced: the only browser client
     * (Retichat-js post_interface.js, from IdMgr.hash = Buffer.toString('hex'))
     * always sends lower-case, so an upper-case claim is not a legitimate
     * re-registration and is treated as no identity. If a client that emits
     * upper-case is ever added, normalise it at that boundary — not here, where
     * loosening the match is what a wildcard attack would exploit.
     */
    private static function normaliseIdentityHashClaim(mixed $claim): ?string
    {
        if (!is_string($claim)) {
            return null;
        }
        // \A and \z, not ^ and $: PCRE's $ also matches before a final "\n",
        // which would accept a 33-byte claim of 32 hex characters plus a newline.
        if (preg_match('/\A[0-9a-f]{32}\z/', $claim) !== 1) {
            return null;
        }

        return $claim;
    }

    /**
     * Find the interface row whose metadata's TOP-LEVEL identity_hash equals the
     * given (already normalised, 32 lowercase hex) claim.
     *
     * This is an EXACT match on the top-level value, never a bare LIKE. A LIKE
     * match let a claim of '%' or '_%' re-bind an arbitrary browser row with no
     * knowledge, and let a nested {"x":{"identity_hash":"…"}} in some unrelated
     * row's metadata match another client's claim. The LIKE below only narrows
     * the candidate rows; each candidate is then json_decoded and its top-level
     * metadata.identity_hash compared with hash_equals, so neither a wildcard
     * nor a nested key can ever match.
     */
    private function interfaceByIdentityHash(string $identityHash): ?array
    {
        // Narrowing filter only; the exact check is the hash_equals below.
        //
        // No ESCAPE clause, and no SQL string literal at all. MySQL and MariaDB
        // treat a backslash in a string literal as an escape (Database::connect
        // does not set NO_BACKSLASH_ESCAPES), so ESCAPE '\' is an unterminated
        // literal there: every browser registration would fail to prepare while
        // SQLite, which the tests use, accepts it. The claim reaching here is
        // already [0-9a-f]{32} (normaliseIdentityHashClaim), so the pattern
        // carries no LIKE metacharacter and no backslash on any engine; were the
        // validation ever loosened, a wildcard would only widen the candidates,
        // and hash_equals still rejects every row whose top-level value differs.
        // tests/no_backslash_in_sql_literals_test.php guards the literal.
        $pattern = '%"identity_hash":"' . $identityHash . '"%';

        $stmt = $this->db->prepare(
            'SELECT interface_id, name, metadata_json
             FROM interfaces
             WHERE metadata_json LIKE :hash_pattern'
        );
        $stmt->bindValue(':hash_pattern', $pattern, PDO::PARAM_STR);
        $stmt->execute();

        while (($row = $stmt->fetch(PDO::FETCH_ASSOC)) !== false) {
            if (!is_array($row)) {
                continue;
            }
            $metadata = self::decodeJson((string) ($row['metadata_json'] ?? ''));
            $stored = $metadata['identity_hash'] ?? null;
            if (is_string($stored) && hash_equals($stored, $identityHash)) {
                return $row;
            }
        }

        return null;
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