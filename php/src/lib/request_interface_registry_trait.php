<?php

declare(strict_types=1);

namespace ReticulumPhp;

// Loaded here as well as by index.php: deploy.sh renames lib/ before
// index.php, and a request between the two runs the old index.php.
require_once __DIR__ . '/empty_poll.php';

use PDO;

// Reticulum-php is request-operated. These interface registry helpers only
// persist credentials and state for the next authenticated request exchange;
// they do not create a second transport path.

trait RequestInterfaceRegistryTrait
{
    // registerInterface() and authenticateInterface() are
    // RequestRegistrationTrait's (REGISTRATION-STAGE1.md §4.6, §7).

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
        // The row may now hold a new session token (EmptyPoll).
        EmptyPoll::clear($this->config ?? [], $interfaceId);
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

    /**
     * $unsignedOnly: only a row no signature holds (identity_hash NULL), for
     * the unsigned re-bind by peer_url (registerInterface), which must never
     * touch a signed row.
     *
     * Of several rows with the peer_url, the one seen most recently, as
     * interfaceRowsNamingPeer() orders them. Since 2026-10-16 a signed row and
     * an unsigned one can share a peer_url: a gateway's first signed
     * registration leaves its old unsigned row beside the new one, and an
     * unsigned registration naming a signed row's peer_url gets a row of its
     * own. Without an order, SQLite's index gave the oldest row and MySQL
     * whichever interface_id sorts first. Not "signed first": a PHP node's own
     * peering row is unsigned and no address is checked, so a signed row
     * naming that peer must not shadow the row the peer keeps seen. Pinned by
     * tests/signed_peer_registration_test.php (6).
     */
    public function phpPeerInterfaceByPeerUrl(string $peerUrl, bool $unsignedOnly = false): ?array
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
             WHERE peer_url = :peer_url' . ($unsignedOnly ? ' AND identity_hash IS NULL' : '') . '
             ORDER BY last_seen_at DESC, created_at DESC
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
     * Registration metadata without a client-supplied wake_url.
     *
     * Until 2026-10-04 a wake_url stored here made this node insert a
     * wake_events row whenever packets queued for the row (every announce),
     * then start `php index.php wake-event <id>` from the next request's
     * epilogue, which POSTed <wake_url>/v1/wake: any client could make the
     * node start processes and send requests to a URL of its choosing. That
     * path (2026-07-03) was superseded on 2026-07-10 by peer_url and the
     * inline wakes of RequestPhpWakeTrait, and nothing reads wake_url now, so
     * it is not stored. A present key is logged once per registration, by
     * shape only (the value is the client's), so a client still sending it
     * can be found. Rows stored before the change keep theirs, unread.
     * Pinned by tests/wake_url_path_removed_test.php.
     */
    private static function withoutWakeUrl(array $metadata): array
    {
        if (!array_key_exists('wake_url', $metadata)) {
            return $metadata;
        }

        $claim = $metadata['wake_url'];
        error_log(sprintf(
            '[REG-WAKE-URL-IGNORED] interface register: metadata.wake_url (%s, length %d) is no longer used; not stored',
            get_debug_type($claim),
            is_string($claim) ? strlen($claim) : -1
        ));
        unset($metadata['wake_url']);

        return $metadata;
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