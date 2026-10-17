<?php

declare(strict_types=1);

namespace ReticulumPhp;

// Loaded here as well as by index.php: deploy.sh renames lib/ before
// index.php, and a request between the two runs the old index.php.
require_once __DIR__ . '/registration_protocol.php';
require_once __DIR__ . '/empty_poll.php';

use PDO;
use PDOException;

/**
 * RequestRegistrationTrait — who may hold an interface row, and how a session
 * is proven. REGISTRATION-STAGE1.md is the contract:
 *
 *   §3   the stateless challenge (issueChallenge)
 *   §4.3 a browser's signed registration, checked in order (registerSigned)
 *   §4.4 the bind: INSERT at count 0, UPDATE in place at count n
 *   §4.5 legacy rows claiming the identity are removed, never adopted
 *   §4.6 the legacy registration while the switch is off (registerInterface)
 *   §5   the session token goes back only encrypted to the identity
 *   §7   a lost session (401) against a superseded one (409)
 *        (authenticateInterface)
 *   §11  [REG-*] and [SESSION-SUPERSEDED], each refusal logged, the two
 *        legacy 403s once per row and count
 *
 * A browser (client rns-js) signs as Stage 1 has it. Since 2026-10-16 a
 * bidirectional peer (reticulum-php) and a poll-mode gateway
 * (rns-post-interface) may sign the same registration, under the rules their
 * unsigned one has; a signed peer row also holds its peer columns, and no
 * unsigned registration re-binds it. An unsigned registration runs as before,
 * apart from an identity_hash it carries, which is ignored. The announce rule
 * for browser rows (§9) is RequestAnnounceGuardTrait's.
 *
 * No log line carries a session token, signature, challenge or the node
 * secret (§11).
 */
trait RequestRegistrationTrait
{
    /** §13: [registration] enforce_signed_registration, as loaded. */
    private function enforceSignedRegistration(): bool
    {
        return ($this->config['registration']['enforce_signed_registration'] ?? false) === true;
    }

    // ── §3 The challenge ────────────────────────────────────────────────

    /**
     * POST /v1/interfaces/challenge {"public_key"|"identity_hash"} and its GET
     * twin. Stateless: no table of codes, no expiry, no sweep. The answer
     * says nothing about the identity's row: not its count, not whether it
     * exists. $post: the request was a POST, whose asks by identity_hash
     * /health counts (§12).
     */
    public function issueChallenge(array $request, bool $post = true): array
    {
        $keys = array_keys($request);
        $identityHash = null;
        if ($keys === ['public_key'] && RegistrationProtocol::isLowerHex($request['public_key'], 128)) {
            $identityHash = RegistrationProtocol::identityHash((string) hex2bin($request['public_key']));
        } elseif ($keys === ['identity_hash'] && RegistrationProtocol::isLowerHex($request['identity_hash'], 32)) {
            $identityHash = (string) hex2bin($request['identity_hash']);
        }
        if ($identityHash === null) {
            throw $this->registrationRefusal(400, 'bad_challenge_request',
                'Send exactly one of public_key (128 lower-case hex) or identity_hash (32 lower-case hex).', []);
        }

        try {
            $row = $this->signedRowByIdentityHash(bin2hex($identityHash));
            $count = $row === null ? 0 : (int) $row['registration_seq'];
            $challenge = RegistrationProtocol::mintChallenge($this->registrationSecret(true), $identityHash, $count);
        } catch (\Throwable $error) {
            error_log(sprintf('[REG-REFUSED] 500 internal client=- identity=%s %s',
                bin2hex($identityHash), get_class($error) . ': ' . $error->getMessage()));
            throw $error;
        }

        if ($post && $keys === ['identity_hash']) {
            $this->countHashOnlyChallenge();
        }

        return [
            'status' => 'challenge',
            'version' => 1,
            'identity_hash' => bin2hex($identityHash),
            'challenge' => bin2hex($challenge),
        ];
    }

    /**
     * §12: one more challenge POST by identity_hash, by one upsert. Only a
     * page with no signing identity asks that way, so a rise says an old
     * app.js is served somewhere. A count that cannot be written is logged
     * and the challenge still answered: the count is a prompt, never a gate.
     */
    private function countHashOnlyChallenge(): void
    {
        try {
            $stmt = $this->db->prepare(Database::upsertSql(
                'INSERT INTO transport_state (state_key, state_value, updated_at) VALUES (:state_key, :one, :updated_at)
                 ON CONFLICT(state_key) DO UPDATE SET state_value = state_value + 1, updated_at = excluded.updated_at',
                $this->backend
            ));
            $stmt->bindValue(':state_key', RegistrationProtocol::HASH_ONLY_CHALLENGES_STATE_KEY, PDO::PARAM_STR);
            $stmt->bindValue(':one', '1', PDO::PARAM_STR);
            $stmt->bindValue(':updated_at', time(), PDO::PARAM_INT);
            Database::executeWithRetry($stmt, 'hashOnlyChallengeCount');
        } catch (\Throwable $error) {
            error_log(sprintf('[REG-COUNT-FAILED] %s %s',
                RegistrationProtocol::HASH_ONLY_CHALLENGES_STATE_KEY, get_class($error) . ': ' . $error->getMessage()));
        }
    }

    /**
     * §3: 32 random bytes in transport_state, made on first use with
     * INSERT-or-ignore and then read back, so concurrent first requests end
     * up with one value. $create = false is the verifier's read: with no
     * secret there is no valid challenge, and nothing is written before §4.3
     * step 8. Read every time, never kept in memory: after a database reset
     * (§12) the old secret must be gone at once.
     */
    private function registrationSecret(bool $create): ?string
    {
        if ($create) {
            $insert = $this->db->prepare(Database::insertOrSql(
                $this->backend,
                'INSERT OR IGNORE INTO transport_state (state_key, state_value, updated_at) VALUES (:state_key, :state_value, :updated_at)'
            ));
            $insert->bindValue(':state_key', RegistrationProtocol::SECRET_STATE_KEY, PDO::PARAM_STR);
            $insert->bindValue(':state_value', bin2hex(random_bytes(32)), PDO::PARAM_STR);
            $insert->bindValue(':updated_at', time(), PDO::PARAM_INT);
            Database::executeWithRetry($insert, 'registrationSecretCreate');
        }
        $stmt = $this->db->prepare('SELECT state_value FROM transport_state WHERE state_key = :state_key');
        $stmt->bindValue(':state_key', RegistrationProtocol::SECRET_STATE_KEY, PDO::PARAM_STR);
        $stmt->execute();
        $value = $stmt->fetchColumn();
        $stmt->closeCursor();
        if ($value === false || $value === null) {
            if ($create) {
                throw new \RuntimeException('registration challenge secret missing after INSERT-or-ignore');
            }
            return null;
        }
        if (!RegistrationProtocol::isLowerHex($value, 64)) {
            // Never repaired here: a second writer would race the first.
            // Delete the transport_state row to rotate it (README).
            throw new \RuntimeException('transport_state ' . RegistrationProtocol::SECRET_STATE_KEY . ' is not 64 lower-case hex');
        }

        return (string) hex2bin($value);
    }

    /** The row bound to identity H: exact match on its own UNIQUE column (§4.4), or null. */
    private function signedRowByIdentityHash(string $identityHashHex): ?array
    {
        $stmt = $this->db->prepare(
            'SELECT interface_id, session_token, registration_seq, identity_public_key, registration_proof, refusal_logged_seq
             FROM interfaces WHERE identity_hash = :identity_hash'
        );
        $stmt->bindValue(':identity_hash', $identityHashHex, PDO::PARAM_STR);
        $stmt->execute();
        $row = $stmt->fetch(PDO::FETCH_ASSOC);
        $stmt->closeCursor();

        return is_array($row) ? $row : null;
    }

    // ── §4 Register ─────────────────────────────────────────────────────

    /**
     * POST /v1/interfaces/register: the whole answer for a decoded body. A
     * body with `registration` takes the signed path, any other the legacy
     * one (§4.1). Throws ApiError for every refusal, each logged
     * [REG-REFUSED]; never 401, never session_superseded (§7).
     */
    public function registerFromBody(array $body): array
    {
        $metadata = $body['metadata'] ?? null;
        $context = ['client' => is_array($metadata) ? ($metadata['client'] ?? null) : null];
        try {
            if (array_key_exists('registration', $body)) {
                return $this->registerSigned($body);
            }

            return $this->registerLegacyBody($body, $context);
        } catch (ApiError $error) {
            throw $error;
        } catch (\Throwable $error) {
            error_log(sprintf('[REG-REFUSED] 500 internal client=%s %s',
                RegistrationProtocol::logValue($context['client']), get_class($error) . ': ' . $error->getMessage()));
            throw $error;
        } finally {
            // A registration may have bound, re-bound or removed rows: what
            // §9 remembered about any of them this request is stale.
            $this->forgetRowRegistrationFacts();
        }
    }

    /** §4.3, in order. Nothing is written before step 8. */
    private function registerSigned(array $body): array
    {
        $metadata = $body['metadata'] ?? null;
        $context = ['client' => is_array($metadata) ? ($metadata['client'] ?? null) : null];

        // Step 1: shape. Values are read as decoded, before any
        // normalisation; nothing is coerced.
        if (!$this->signedBodyHasShape($body)) {
            throw $this->registrationRefusal(400, 'bad_registration',
                'The registration object or a signed field is malformed.', $context);
        }
        $registration = $body['registration'];
        /** @var array $metadata */

        // Step 2: only §4.1's metadata keys.
        foreach (array_keys($metadata) as $key) {
            if (!in_array($key, RegistrationProtocol::SIGNED_METADATA_KEYS, true)) {
                throw $this->registrationRefusal(400, 'unsigned_metadata',
                    'A signed registration may not carry metadata the signature does not cover.', $context);
            }
        }

        // Step 3: H from the key; a metadata identity_hash must be H.
        $publicKey = (string) hex2bin($registration['public_key']);
        $identityHash = RegistrationProtocol::identityHash($publicKey);
        $identityHashHex = bin2hex($identityHash);
        $context['identity'] = $identityHashHex;
        if (array_key_exists('identity_hash', $metadata)
            && !(is_string($metadata['identity_hash']) && hash_equals($identityHashHex, $metadata['identity_hash']))) {
            throw $this->registrationRefusal(400, 'identity_hash_mismatch',
                'metadata.identity_hash is not the hash of the registration key.', $context);
        }

        // Step 4: who may sign. A browser (rns-js) in an endpoint mode, with
        // no transit fields. A bidirectional peer (reticulum-php: a PHP
        // node's peering, a gateway in wake mode) or a gateway in poll mode
        // (rns-post-interface) signs its mode and its own fields under the
        // rules its unsigned registration has (registerInterface): any mode,
        // and peer columns only for reticulum-php. Anything else: 400.
        // Step 1 took the mode only as a JSON integer from 1 to 7, which the
        // signed bytes carry as one byte; it is read as the runtime reads it
        // all the same.
        $client = $metadata['client'];
        if ($client === 'rns-js') {
            if (in_array(self::metadataMode($metadata), [3, 5, 6], true)) {
                throw $this->registrationRefusal(400, 'transit_mode_not_allowed',
                    'A browser registers in mode 1, 2, 4 or 7.', $context);
            }
            foreach (['transport', 'peer_url', 'peer_interface_id', 'peer_session_token'] as $key) {
                if (is_string($metadata[$key] ?? null) && $metadata[$key] !== '') {
                    throw $this->registrationRefusal(400, 'metadata_not_allowed',
                        "A browser may not register {$key}.", $context);
                }
            }
        } elseif ($client !== 'reticulum-php' && $client !== 'rns-post-interface') {
            throw $this->registrationRefusal(400, 'unknown_client',
                'A signed registration must name the client rns-js, reticulum-php or rns-post-interface.', $context);
        }

        // Step 5: the signature, over bytes rebuilt from the body as
        // received. Before the challenge, so a request without H's private
        // key gets 403 whatever the count, and reads no row or secret.
        $signature = (string) hex2bin($registration['signature']);
        if (!sodium_crypto_sign_verify_detached($signature, RegistrationProtocol::signedBytes($body), substr($publicKey, 32, 32))) {
            throw $this->registrationRefusal(403, 'bad_registration_signature',
                'The registration signature does not verify.', $context);
        }

        // Step 6: the challenge is this PHP node's, for H, at the row's
        // current count.
        $row = $this->signedRowByIdentityHash($identityHashHex);
        $count = $row === null ? 0 : (int) $row['registration_seq'];
        $secret = $this->registrationSecret(false);
        $challenge = (string) hex2bin($registration['challenge']);
        if ($secret === null || !RegistrationProtocol::challengeVerifies($secret, $identityHash, $count, $challenge)) {
            throw $this->registrationRefusal(409, 'stale_challenge',
                'The challenge is not valid here any more. Fetch one new challenge and register once more.', $context);
        }

        // Step 7: a fresh token, encrypted to the identity. A low-order X25519
        // key cannot receive one.
        $sessionToken = bin2hex(random_bytes(32));
        try {
            $sealed = RegistrationProtocol::encryptToken($sessionToken, $publicKey, $identityHash);
        } catch (\SodiumException) {
            throw $this->registrationRefusal(400, 'bad_registration',
                'No session token can be encrypted to this key.', $context);
        }

        // Step 8: the bind (§4.4). A peer's row also holds its peer columns,
        // as the unsigned bind stores them; a field the signature reads as
        // empty (absent, null or "") is stored as none.
        $storedMetadata = $client === 'rns-js' ? $this->signedStoredMetadata($metadata) : self::signedPeerStoredMetadata($metadata);
        $values = [
            'name' => $body['name'],
            'bitrate' => $body['bitrate'],
            'mtu' => $body['mtu'],
            'metadata_json' => self::encodeJson($storedMetadata),
        ] + array_map(static fn (?string $value): ?string => $value === '' ? null : $value, self::peerColumns($metadata));
        if ($row === null) {
            $interfaceId = $this->bindSignedInsert($identityHashHex, $registration['public_key'], $sessionToken, $values, $context);
            $action = 'created';
        } else {
            $interfaceId = (string) $row['interface_id'];
            $this->bindSignedUpdate($identityHashHex, $registration['public_key'], $count, (string) ($row['session_token'] ?? ''), $sessionToken, $values, $context);
            $action = 'rebound';
        }
        error_log(sprintf('[REG-SIGNED] identity=%s interface=%s %s', $identityHashHex, substr($interfaceId, 0, 8), $action));

        // §4.5: after every bind, never adopt a legacy row claiming H;
        // remove it. A failure there is logged, and the bind still answers.
        $this->retireSquattedRows($identityHashHex);

        return [
            'status' => 'registered',
            'interface_id' => $interfaceId,
            'identity_hash' => $identityHashHex,
            'session_token_encrypted' => bin2hex($sealed),
            'idle_exchange_interval_ms' => (int) ($this->config['http']['idle_exchange_interval_ms'] ?? 1000),
            'max_batch_packets' => (int) ($this->config['http']['max_batch_packets'] ?? 64),
            'max_packet_bytes' => $this->maxPacketBytesForMetadata($storedMetadata),
        ];
    }

    /** §4.3 step 1. */
    private function signedBodyHasShape(array $body): bool
    {
        $registration = $body['registration'] ?? null;
        $metadata = $body['metadata'] ?? null;
        if (!is_array($registration) || !is_array($metadata)) {
            return false;
        }
        $keys = array_keys($registration);
        sort($keys, SORT_STRING);
        if ($keys !== RegistrationProtocol::REGISTRATION_KEYS
            || $registration['version'] !== 1
            || !RegistrationProtocol::isLowerHex($registration['public_key'], 128)
            || !RegistrationProtocol::isLowerHex($registration['challenge'], 2 * RegistrationProtocol::CHALLENGE_BYTES)
            || !RegistrationProtocol::isLowerHex($registration['signature'], 128)) {
            return false;
        }
        $name = $body['name'] ?? null;
        if (!is_string($name) || $name === '' || strlen($name) > 255 || !mb_check_encoding($name, 'UTF-8')) {
            return false;
        }
        foreach (['bitrate', 'mtu'] as $key) {
            $value = $body[$key] ?? null;
            if (!is_int($value) || $value < 1 || $value > RegistrationProtocol::MAX_INT_FIELD) {
                return false;
            }
        }
        $client = $metadata['client'] ?? null;
        if (!is_string($client) || $client === '' || strlen($client) > 64 || !mb_check_encoding($client, 'UTF-8')) {
            return false;
        }
        $mode = $metadata['mode'] ?? null;
        if (!is_int($mode) || $mode < 1 || $mode > 7) {
            return false;
        }
        foreach (['implementation' => 64, 'transport' => 64, 'peer_url' => 512, 'peer_interface_id' => 64, 'peer_session_token' => 128] as $key => $maxBytes) {
            if (!array_key_exists($key, $metadata) || $metadata[$key] === null) {
                continue;
            }
            $value = $metadata[$key];
            if (!is_string($value) || strlen($value) > $maxBytes || !mb_check_encoding($value, 'UTF-8')) {
                return false;
            }
        }

        return true;
    }

    /** §4.4: a signed row's metadata_json holds only client, implementation and mode. */
    private function signedStoredMetadata(array $metadata): array
    {
        $stored = ['client' => $metadata['client']];
        if (is_string($metadata['implementation'] ?? null) && $metadata['implementation'] !== '') {
            $stored['implementation'] = $metadata['implementation'];
        }
        $stored['mode'] = self::metadataMode($metadata);

        return $stored;
    }

    /**
     * A signed peer's or gateway's metadata_json: its metadata as signed, as
     * registerInterface() stores an unsigned one's (identity_hash, which is
     * H by step 3, lives in its own column).
     */
    private static function signedPeerStoredMetadata(array $metadata): array
    {
        unset($metadata['identity_hash']);

        return $metadata;
    }

    /**
     * §4.4, count 0: INSERT a new identity row. A unique-key conflict means
     * another registration of H won the race: look the row up only to log
     * it, and answer 409 stale_challenge. Never a second INSERT.
     */
    private function bindSignedInsert(string $identityHashHex, string $publicKeyHex, string $sessionToken, array $values, array $context): string
    {
        $now = time();
        $interfaceId = bin2hex(random_bytes(16));
        $stmt = $this->db->prepare(
            'INSERT INTO interfaces (
                interface_id, name, session_token, bitrate, mtu, status, metadata_json,
                created_at, last_seen_at, updated_at,
                identity_hash, identity_public_key, registration_seq, registration_proof,
                peer_url, peer_interface_id, peer_session_token
            ) VALUES (
                :interface_id, :name, :session_token, :bitrate, :mtu, :status, :metadata_json,
                :created_at, :last_seen_at, :updated_at,
                :identity_hash, :identity_public_key, :registration_seq, :registration_proof,
                :peer_url, :peer_interface_id, :peer_session_token
            )'
        );
        $stmt->bindValue(':interface_id', $interfaceId, PDO::PARAM_STR);
        $stmt->bindValue(':name', $values['name'], PDO::PARAM_STR);
        $stmt->bindValue(':session_token', $sessionToken, PDO::PARAM_STR);
        $stmt->bindValue(':bitrate', $values['bitrate'], PDO::PARAM_INT);
        $stmt->bindValue(':mtu', $values['mtu'], PDO::PARAM_INT);
        $stmt->bindValue(':status', 'online', PDO::PARAM_STR);
        $stmt->bindValue(':metadata_json', $values['metadata_json'], PDO::PARAM_STR);
        $stmt->bindValue(':created_at', $now, PDO::PARAM_INT);
        $stmt->bindValue(':last_seen_at', $now, PDO::PARAM_INT);
        $stmt->bindValue(':updated_at', $now, PDO::PARAM_INT);
        $stmt->bindValue(':identity_hash', $identityHashHex, PDO::PARAM_STR);
        $stmt->bindValue(':identity_public_key', $publicKeyHex, PDO::PARAM_STR);
        $stmt->bindValue(':registration_seq', 1, PDO::PARAM_INT);
        $stmt->bindValue(':registration_proof', 'signed', PDO::PARAM_STR);
        $this->bindPeerColumns($stmt, $values);
        try {
            Database::executeWithRetry($stmt, 'signedRegistrationInsert');
        } catch (PDOException $error) {
            if (!self::isUniqueViolation($error)) {
                throw $error;
            }
            $winner = $this->signedRowByIdentityHash($identityHashHex);
            $context['detail'] = 'lost_bind_race winner=' . ($winner === null ? '-' : substr((string) $winner['interface_id'], 0, 8));
            throw $this->registrationRefusal(409, 'stale_challenge',
                'Another registration of this identity landed first. Fetch one new challenge and register once more.', $context);
        }

        return $interfaceId;
    }

    /**
     * §4.4, count n > 0: update in place, matched on the count step 6 read.
     * The statement always changes registration_seq and session_token, so
     * MySQL's affected rows equal its matched rows. :old_token_sha256 is the
     * SHA-256 of the token the row held when step 6 read it (§8).
     */
    private function bindSignedUpdate(string $identityHashHex, string $publicKeyHex, int $count, string $oldToken, string $sessionToken, array $values, array $context): void
    {
        $now = time();
        $stmt = $this->db->prepare(
            "UPDATE interfaces
                SET previous_session_token_hash = :old_token_sha256, session_token = :token,
                    name = :name, bitrate = :bitrate, mtu = :mtu, status = 'online',
                    metadata_json = :metadata_json, last_seen_at = :last_seen_at,
                    updated_at = :updated_at, registration_seq = :next_count,
                    peer_url = :peer_url, peer_interface_id = :peer_interface_id, peer_session_token = :peer_session_token
              WHERE identity_hash = :h AND registration_seq = :count AND identity_public_key = :pub"
        );
        $this->bindPeerColumns($stmt, $values);
        $this->bindNullable($stmt, ':old_token_sha256', $oldToken === '' ? null : hash('sha256', $oldToken));
        $stmt->bindValue(':token', $sessionToken, PDO::PARAM_STR);
        $stmt->bindValue(':name', $values['name'], PDO::PARAM_STR);
        $stmt->bindValue(':bitrate', $values['bitrate'], PDO::PARAM_INT);
        $stmt->bindValue(':mtu', $values['mtu'], PDO::PARAM_INT);
        $stmt->bindValue(':metadata_json', $values['metadata_json'], PDO::PARAM_STR);
        $stmt->bindValue(':last_seen_at', $now, PDO::PARAM_INT);
        $stmt->bindValue(':updated_at', $now, PDO::PARAM_INT);
        $stmt->bindValue(':next_count', $count + 1, PDO::PARAM_INT);
        $stmt->bindValue(':h', $identityHashHex, PDO::PARAM_STR);
        $stmt->bindValue(':count', $count, PDO::PARAM_INT);
        $stmt->bindValue(':pub', $publicKeyHex, PDO::PARAM_STR);
        Database::executeWithRetry($stmt, 'signedRegistrationUpdate');
        if ($stmt->rowCount() !== 1) {
            $context['detail'] = 'lost_bind_race';
            throw $this->registrationRefusal(409, 'stale_challenge',
                'Another registration of this identity landed first. Fetch one new challenge and register once more.', $context);
        }
    }

    private static function isUniqueViolation(PDOException $error): bool
    {
        return (string) $error->getCode() === '23000' || (string) ($error->errorInfo[0] ?? '') === '23000';
    }

    private function bindNullable(\PDOStatement $stmt, string $placeholder, ?string $value): void
    {
        $stmt->bindValue($placeholder, $value, $value === null ? PDO::PARAM_NULL : PDO::PARAM_STR);
    }

    /** :peer_url, :peer_interface_id and :peer_session_token from $values (peerColumns()). */
    private function bindPeerColumns(\PDOStatement $stmt, array $values): void
    {
        foreach (['peer_url', 'peer_interface_id', 'peer_session_token'] as $column) {
            $this->bindNullable($stmt, ':' . $column, $values[$column] ?? null);
        }
    }

    /**
     * The peer columns a registration binds, signed or not: a reticulum-php
     * row's peer_url (trimmed, no trailing '/'), peer_interface_id and
     * peer_session_token, each as given when it is a string; none for any
     * other client.
     *
     * @return array{peer_url: ?string, peer_interface_id: ?string, peer_session_token: ?string}
     */
    private static function peerColumns(array $metadata): array
    {
        $field = static fn (string $key): ?string => isset($metadata[$key]) && is_string($metadata[$key]) ? $metadata[$key] : null;
        if (($metadata['client'] ?? null) !== 'reticulum-php') {
            return ['peer_url' => null, 'peer_interface_id' => null, 'peer_session_token' => null];
        }
        $peerUrl = $field('peer_url');

        return [
            'peer_url' => $peerUrl === null ? null : rtrim(trim($peerUrl), '/'),
            'peer_interface_id' => $field('peer_interface_id'),
            'peer_session_token' => $field('peer_session_token'),
        ];
    }

    // ── §4.5 Legacy rows claiming the identity ──────────────────────────

    /**
     * Every legacy row that claims H is removed, never adopted (A7): its
     * owner was never proven, so its local destinations, paths, links and
     * queue go with it, each step a statement on an index, then the row. With
     * no such row this costs one indexed SELECT. A database error is logged
     * [REG-RETIRE] ... failed=<table> and ends the removal; the bind has
     * succeeded, and the next bind of H runs the removal again. Returns the
     * number of rows removed.
     */
    private function retireSquattedRows(string $identityHashHex): int
    {
        $removed = 0;
        $dropped = 0;
        $failed = null;
        try {
            $stmt = $this->db->prepare(
                'SELECT interface_id FROM interfaces
                  WHERE claimed_identity_hash = :claim AND registration_proof = :none'
            );
            $stmt->bindValue(':claim', $identityHashHex, PDO::PARAM_STR);
            $stmt->bindValue(':none', 'none', PDO::PARAM_STR);
            $stmt->execute();
            $ids = array_map('strval', $stmt->fetchAll(PDO::FETCH_COLUMN));
        } catch (\Throwable $error) {
            $ids = [];
            $failed = ['interfaces', $error];
        }
        foreach ($ids as $interfaceId) {
            $failed = $this->deleteLegacyInterfaceRow($interfaceId, $dropped);
            if ($failed !== null) {
                break;
            }
            $removed++;
            // Its holder gets 401 at its next exchange, not when its idle
            // mark runs out.
            EmptyPoll::clear($this->config, $interfaceId);
        }
        if ($removed > 0) {
            error_log(sprintf('[REG-RETIRE] identity=%s rows=%d dropped=%d', $identityHashHex, $removed, $dropped));
        }
        if ($failed !== null) {
            [$table, $error] = $failed;
            error_log(sprintf('[REG-RETIRE] identity=%s failed=%s %s', $identityHashHex, $table,
                get_class($error) . ': ' . $error->getMessage()));
        }

        return $removed;
    }

    /**
     * §4.5's statements for one legacy row, in its order. Returns null when
     * the row is gone, or [table, error] for the step that failed (the
     * statements before it stand; the row stays, inert, for the next bind).
     * $dropped counts the queued packets deleted.
     *
     * @return array{0: string, 1: \Throwable}|null
     */
    private function deleteLegacyInterfaceRow(string $interfaceId, int &$dropped): ?array
    {
        $statements = [
            // 1. its local destinations
            ['local_destinations', 'DELETE FROM local_destinations WHERE interface_id = :interface_id'],
            // 2. the paths through it; reverse paths and link entries
            //    received on it, then sent out on it: one DELETE per column
            ['path_entries', 'DELETE FROM path_entries WHERE interface_id = :interface_id'],
            ['reverse_path_entries', 'DELETE FROM reverse_path_entries WHERE received_interface_id = :interface_id'],
            ['link_transport_entries', 'DELETE FROM link_transport_entries WHERE received_interface_id = :interface_id'],
            ['reverse_path_entries', 'DELETE FROM reverse_path_entries WHERE outbound_interface_id = :interface_id'],
            ['link_transport_entries', 'DELETE FROM link_transport_entries WHERE outbound_interface_id = :interface_id'],
        ];
        foreach ($statements as [$table, $sql]) {
            try {
                $stmt = $this->db->prepare($sql);
                $stmt->bindValue(':interface_id', $interfaceId, PDO::PARAM_STR);
                Database::executeWithRetry($stmt, 'retireLegacyRow:' . $table);
            } catch (\Throwable $error) {
                return [$table, $error];
            }
        }

        // 3. its queue: selected by interface_id, deleted by primary key in
        //    ascending order, then its batches.
        try {
            $select = $this->db->prepare(
                'SELECT packet_id FROM outbound_packets WHERE interface_id = :interface_id ORDER BY packet_id'
            );
            $select->bindValue(':interface_id', $interfaceId, PDO::PARAM_STR);
            $select->execute();
            $packetIds = array_map('intval', $select->fetchAll(PDO::FETCH_COLUMN));
            foreach (array_chunk($packetIds, 500) as $chunk) {
                $placeholders = implode(', ', array_fill(0, count($chunk), '?'));
                $delete = $this->db->prepare("DELETE FROM outbound_packets WHERE packet_id IN ({$placeholders})");
                foreach ($chunk as $index => $packetId) {
                    $delete->bindValue($index + 1, $packetId, PDO::PARAM_INT);
                }
                Database::executeWithRetry($delete, 'retireLegacyRow:outbound_packets');
                $dropped += $delete->rowCount();
            }
        } catch (\Throwable $error) {
            return ['outbound_packets', $error];
        }
        try {
            $stmt = $this->db->prepare('DELETE FROM outbound_batches WHERE interface_id = :interface_id');
            $stmt->bindValue(':interface_id', $interfaceId, PDO::PARAM_STR);
            Database::executeWithRetry($stmt, 'retireLegacyRow:outbound_batches');
        } catch (\Throwable $error) {
            return ['outbound_batches', $error];
        }

        // Then the row, its proof checked again: a signed row is never
        // removed here.
        try {
            $stmt = $this->db->prepare('DELETE FROM interfaces WHERE interface_id = :interface_id AND registration_proof = :none');
            $stmt->bindValue(':interface_id', $interfaceId, PDO::PARAM_STR);
            $stmt->bindValue(':none', 'none', PDO::PARAM_STR);
            Database::executeWithRetry($stmt, 'retireLegacyRow:interfaces');
        } catch (\Throwable $error) {
            return ['interfaces', $error];
        }

        return null;
    }

    // ── §4.6 The legacy registration ────────────────────────────────────

    /**
     * An unsigned body, validated as the register route always has (the same
     * checks and messages), then registerInterface(). Its answer is today's,
     * with a plaintext session token.
     */
    private function registerLegacyBody(array $body, array $context): array
    {
        $refuse = fn (string $error): ApiError => $this->registrationRefusal(400, $error, $error, $context);
        $name = $body['name'] ?? null;
        if (!is_string($name) || trim($name) === '') {
            throw $refuse('name must be a non-empty string');
        }
        $positive = static function (mixed $value, string $field): int|string {
            if (!is_int($value) && !(is_string($value) && ctype_digit($value))) {
                return $field . ' must be a positive integer';
            }
            $integer = (int) $value;

            return $integer < 1 ? $field . ' must be greater than zero' : $integer;
        };
        $bitrate = $positive($body['bitrate'] ?? null, 'bitrate');
        if (is_string($bitrate)) {
            throw $refuse($bitrate);
        }
        $mtu = $positive($body['mtu'] ?? null, 'mtu');
        if (is_string($mtu)) {
            throw $refuse($mtu);
        }
        $metadata = $body['metadata'] ?? [];
        if (!is_array($metadata)) {
            throw $refuse('metadata must be an object or array');
        }
        if (($metadata['client'] ?? null) !== 'reticulum-php') {
            try {
                $maxPacketBytes = $this->maxPacketBytesForMetadata($metadata);
            } catch (\RuntimeException $error) {
                throw $refuse($error->getMessage());
            }
        } else {
            $maxPacketBytes = $this->maxPacketBytesForMetadata($metadata);
        }

        $registration = $this->registerInterface($name, $bitrate, $mtu, $metadata);
        $response = [
            'status' => 'registered',
            'interface_id' => $registration['interface_id'],
            'session_token' => $registration['session_token'],
            'idle_exchange_interval_ms' => (int) ($this->config['http']['idle_exchange_interval_ms'] ?? 1000),
            'max_batch_packets' => (int) ($this->config['http']['max_batch_packets'] ?? 64),
            'max_packet_bytes' => $maxPacketBytes,
        ];
        if (isset($registration['peer_interface_id'])) {
            $response['peer_interface_id'] = $registration['peer_interface_id'];
        }
        if (isset($registration['peer_session_token'])) {
            $response['peer_session_token'] = $registration['peer_session_token'];
        }

        return $response;
    }

    /**
     * A legacy (unsigned) registration. A browser's (client rns-js) follows
     * §4.6. Any other client's runs as it always has: an unsigned
     * reticulum-php row is re-bound by its exact peer_url (a signed one never
     * is), anything else gets a new row. Its
     * identity_hash is ignored and logged [REG-CLAIM-IGNORED]: since Stage 1 a
     * claim is found only by claimed_identity_hash, and only browser rows
     * carry one (A8).
     */
    public function registerInterface(string $name, int $bitrate, int $mtu, array $metadata): array
    {
        $metadata = self::withoutWakeUrl($metadata);
        $client = $metadata['client'] ?? null;
        if ($client === 'rns-js') {
            return $this->registerLegacyBrowser($name, $bitrate, $mtu, $metadata);
        }
        if (array_key_exists('identity_hash', $metadata)) {
            $claim = $metadata['identity_hash'];
            if ($claim !== null && $claim !== '') {
                error_log(sprintf('[REG-CLAIM-IGNORED] client=%s', RegistrationProtocol::logValue($client)));
            }
            unset($metadata['identity_hash']);
        }
        $now = time();
        $sessionToken = bin2hex(random_bytes(32));

        ['peer_url' => $peerUrl, 'peer_interface_id' => $peerInterfaceId, 'peer_session_token' => $peerSessionToken] = self::peerColumns($metadata);

        // Bridge interface dedup: if a peer_url already has an interface, update it
        // instead of creating a duplicate. Matches Python RNS where interfaces are
        // singletons identified by transport object identity. Only an unsigned
        // row: a signed row is its key's alone, so an unsigned registration
        // naming its peer_url gets what it would get without it (the unsigned
        // row with that peer_url, re-bound, or a new row).
        if ($peerUrl !== null && $peerInterfaceId !== null) {
            $existing = $this->phpPeerInterfaceByPeerUrl($peerUrl, true);
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
                Database::executeWithRetry($updateStmt, 'legacyPeerRebind');

                return [
                    'interface_id' => $interfaceId,
                    'session_token' => $sessionToken,
                ];
            }
        }

        $interfaceId = $this->insertLegacyRow($name, $bitrate, $mtu, $metadata, $sessionToken, null,
            ['peer_url' => $peerUrl, 'peer_interface_id' => $peerInterfaceId, 'peer_session_token' => $peerSessionToken]);

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

    /** §4.6, a legacy browser registration, in its order. */
    private function registerLegacyBrowser(string $name, int $bitrate, int $mtu, array $metadata): array
    {
        $context = ['client' => 'rns-js'];
        $rawClaim = $metadata['identity_hash'] ?? null;
        $claim = self::normaliseIdentityHashClaim($rawClaim);
        // 6. never stored: the claim lives in claimed_identity_hash.
        unset($metadata['identity_hash']);

        // 1. A browser is an endpoint, signed or not. Its mode is read as
        // the runtime reads it, and stored as that integer, by the insert
        // and by the re-bind, which rewrites metadata_json: a spelling the
        // runtime reads as 3, 5 or 6 ("6.0", " 6", 6.0) is refused here.
        $mode = self::metadataMode($metadata);
        if (in_array($mode, [3, 5, 6], true)) {
            throw $this->registrationRefusal(400, 'transit_mode_not_allowed',
                'A browser registers in mode 1, 2, 4 or 7.', $context);
        }
        $metadata['mode'] = $mode;

        // 2. The switch.
        if ($this->enforceSignedRegistration()) {
            if ($claim !== null) {
                $context['identity'] = $claim;
            }
            throw $this->registrationRefusal(403, 'signature_required',
                'This PHP node accepts only signed registrations. Reload this page to connect.', $context,
                $this->legacyRefusalShouldLog($claim, $claim === null ? null : $this->signedRowByIdentityHash($claim)));
        }

        // 3. The claim: 32 lower-case hex, or none.
        if ($claim === null) {
            if ($rawClaim !== null && $rawClaim !== '') {
                // A present-but-malformed claim must speak before it is
                // dropped. The claim itself is attacker-controlled, so only
                // its shape is logged.
                error_log(sprintf(
                    '[REG-BAD-IDENTITY] interface register: identity_hash claim (%s, length %d) is not 32 lowercase hex; treating as no identity (new row, no re-bind)',
                    get_debug_type($rawClaim),
                    is_string($rawClaim) ? strlen($rawClaim) : -1
                ));
            }
        } else {
            $context['identity'] = $claim;
            // 4. A claim its identity has proven here is not for this path.
            $this->refuseClaimOfSignedIdentity($claim, $context);
        }

        // 5. Re-bind the claim's legacy row in place, or insert one. A
        // re-bind that changes no row lost its row after the read, to a
        // concurrent signed bind's §4.5. Then back to step 4, once: with the
        // signed row there, 403 identity_requires_signature; without it (the
        // row went some other way), step 5 again, which inserts a row if
        // that re-bind finds its row gone too.
        $sessionToken = bin2hex(random_bytes(32));
        $existing = $claim === null ? null : $this->legacyBrowserRowByClaim($claim);
        $rebound = $existing !== null && $this->rebindLegacyBrowserRow((string) $existing['interface_id'], $sessionToken, $bitrate, $mtu, $metadata);
        if ($claim !== null && $existing !== null && !$rebound) {
            $this->refuseClaimOfSignedIdentity($claim, $context);
            $existing = $this->legacyBrowserRowByClaim($claim);
            $rebound = $existing !== null && $this->rebindLegacyBrowserRow((string) $existing['interface_id'], $sessionToken, $bitrate, $mtu, $metadata);
        }
        if ($rebound) {
            $interfaceId = (string) $existing['interface_id'];
            $action = 'rebound';
        } else {
            $interfaceId = $this->insertLegacyRow($name, $bitrate, $mtu, $metadata, $sessionToken, $claim, null);
            $action = 'created';
        }
        error_log(sprintf('[REG-LEGACY] client=rns-js action=%s interface=%s', $action, substr($interfaceId, 0, 8)));

        return ['interface_id' => $interfaceId, 'session_token' => $sessionToken];
    }

    /** §4.6 step 4: a claim its identity has proven here is not for this path. */
    private function refuseClaimOfSignedIdentity(string $claim, array $context): void
    {
        $signed = $this->signedRowByIdentityHash($claim);
        if ($signed !== null) {
            throw $this->registrationRefusal(403, 'identity_requires_signature',
                'This identity registers with a signature on this PHP node. Reload this page to connect.', $context,
                $this->legacyRefusalShouldLog($claim, $signed));
        }
    }

    /**
     * §4.6 step 5's re-bind of a legacy browser row, in place. False when the
     * UPDATE changed no row: the row went after step 5 read it. It always
     * writes a new token, so MySQL's affected rows equal its matched rows.
     */
    private function rebindLegacyBrowserRow(string $interfaceId, string $sessionToken, int $bitrate, int $mtu, array $metadata): bool
    {
        $stmt = $this->db->prepare(
            'UPDATE interfaces
                SET session_token = :session_token, previous_session_token_hash = NULL,
                    bitrate = :bitrate, mtu = :mtu, status = :status,
                    metadata_json = :metadata_json, last_seen_at = :last_seen_at
              WHERE interface_id = :interface_id AND identity_hash IS NULL'
        );
        $stmt->bindValue(':session_token', $sessionToken, PDO::PARAM_STR);
        $stmt->bindValue(':bitrate', $bitrate, PDO::PARAM_INT);
        $stmt->bindValue(':mtu', $mtu, PDO::PARAM_INT);
        $stmt->bindValue(':status', 'online', PDO::PARAM_STR);
        $stmt->bindValue(':metadata_json', self::encodeJson($metadata), PDO::PARAM_STR);
        $stmt->bindValue(':last_seen_at', time(), PDO::PARAM_INT);
        $stmt->bindValue(':interface_id', $interfaceId, PDO::PARAM_STR);
        Database::executeWithRetry($stmt, 'legacyBrowserRebind');

        return $stmt->rowCount() === 1;
    }

    /**
     * The legacy browser row a claim re-binds: exact match on the
     * claimed_identity_hash column, never on metadata, the most recently
     * seen if a rollback left several.
     */
    private function legacyBrowserRowByClaim(string $claim): ?array
    {
        $stmt = $this->db->prepare(
            'SELECT interface_id, metadata_json, registration_seq, refusal_logged_seq FROM interfaces
              WHERE claimed_identity_hash = :claim AND registration_proof = :none AND identity_hash IS NULL
              ORDER BY last_seen_at DESC, interface_id ASC'
        );
        $stmt->bindValue(':claim', $claim, PDO::PARAM_STR);
        $stmt->bindValue(':none', 'none', PDO::PARAM_STR);
        $stmt->execute();
        $found = null;
        while (($row = $stmt->fetch(PDO::FETCH_ASSOC)) !== false) {
            if ((self::decodeJson((string) ($row['metadata_json'] ?? ''))['client'] ?? null) === 'rns-js') {
                $found = $row;
                break;
            }
        }
        $stmt->closeCursor();

        return $found;
    }

    /** A new legacy row. Its identity_hash is never written (§4.6). */
    private function insertLegacyRow(string $name, int $bitrate, int $mtu, array $metadata, string $sessionToken, ?string $claim, ?array $peer): string
    {
        $now = time();
        $interfaceId = bin2hex(random_bytes(16));
        $stmt = $this->db->prepare(
            'INSERT INTO interfaces (
                interface_id, name, session_token, bitrate, mtu, status,
                metadata_json, created_at, last_seen_at, claimed_identity_hash,
                peer_url, peer_interface_id, peer_session_token
            ) VALUES (
                :interface_id, :name, :session_token, :bitrate, :mtu, :status,
                :metadata_json, :created_at, :last_seen_at, :claimed_identity_hash,
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
        $this->bindNullable($stmt, ':claimed_identity_hash', $claim);
        $this->bindNullable($stmt, ':peer_url', $peer['peer_url'] ?? null);
        $this->bindNullable($stmt, ':peer_interface_id', $peer['peer_interface_id'] ?? null);
        $this->bindNullable($stmt, ':peer_session_token', $peer['peer_session_token'] ?? null);
        Database::executeWithRetry($stmt, 'legacyRegistrationInsert');

        return $interfaceId;
    }

    /**
     * §11: §4.6's two 403s are logged once per row and count. The claim's
     * row is the signed row ($signedRow, read by identity_hash), else the
     * newest legacy row by claimed_identity_hash; this logs only when the
     * compare-and-swap below changes it. A claim with no row, or no valid
     * claim, is logged every time.
     */
    private function legacyRefusalShouldLog(?string $claim, ?array $signedRow): bool
    {
        if ($claim === null) {
            return true;
        }
        $row = $signedRow ?? $this->legacyBrowserRowByClaim($claim);
        if ($row === null) {
            return true;
        }
        $count = (int) ($row['registration_seq'] ?? 0);
        if ((int) ($row['refusal_logged_seq'] ?? -1) === $count) {
            return false;
        }
        $stmt = $this->db->prepare(
            'UPDATE interfaces SET refusal_logged_seq = :seq
              WHERE interface_id = :id AND registration_seq = :row_seq AND refusal_logged_seq <> :logged_seq'
        );
        $stmt->bindValue(':seq', $count, PDO::PARAM_INT);
        $stmt->bindValue(':id', (string) $row['interface_id'], PDO::PARAM_STR);
        $stmt->bindValue(':row_seq', $count, PDO::PARAM_INT);
        $stmt->bindValue(':logged_seq', $count, PDO::PARAM_INT);
        Database::executeWithRetry($stmt, 'refusalLoggedSeq');

        return $stmt->rowCount() === 1;
    }

    // ── §7 Lost versus superseded ───────────────────────────────────────

    /**
     * /exchange, /tx, /poll and /goodbye, in §7's order:
     *   1. no row: 401;
     *   2. a legacy browser row while the switch is on: 401, whatever the token;
     *   3. the row's token: success, except a legacy browser row whose claim
     *      is a signed row's identity_hash: 401, with nothing written but
     *      its claim;
     *   4. any other token on a signed row: 409 session_superseded (§8);
     *   5. anything else: 401.
     */
    public function authenticateInterface(string $interfaceId, string $sessionToken): array
    {
        $stmt = $this->db->prepare(
            'SELECT i.interface_id, i.name, i.session_token, i.bitrate, i.mtu, i.status, i.metadata_json,
                    i.registration_proof, i.previous_session_token_hash, i.superseded_logged_hash,
                    i.identity_hash, i.claimed_identity_hash,
                    CASE WHEN EXISTS (SELECT 1 FROM interfaces s WHERE s.identity_hash = i.claimed_identity_hash)
                         THEN 1 ELSE 0 END AS claim_is_signed
               FROM interfaces i WHERE i.interface_id = :interface_id'
        );
        $stmt->bindValue(':interface_id', $interfaceId, PDO::PARAM_STR);
        $stmt->execute();
        $row = $stmt->fetch(PDO::FETCH_ASSOC);
        $stmt->closeCursor();

        // 1.
        if (!is_array($row)) {
            throw self::sessionUnknown();
        }
        // From here on the row's own id, never the request's string: on
        // MySQL and MariaDB's utf8mb4_unicode_ci every case variant of an id
        // finds the row.
        $interfaceId = (string) $row['interface_id'];
        $metadata = self::decodeJson((string) ($row['metadata_json'] ?? ''));
        $signed = (string) ($row['registration_proof'] ?? 'none') === 'signed';
        $legacyBrowser = !$signed && ($metadata['client'] ?? null) === 'rns-js';

        // 2.
        if ($legacyBrowser && $this->enforceSignedRegistration()) {
            throw self::sessionUnknown();
        }

        $current = (string) ($row['session_token'] ?? '');
        if ($current !== '' && hash_equals($current, $sessionToken)) {
            // 3.
            if ($legacyBrowser) {
                $claim = $row['claimed_identity_hash'] ?? null;
                $claimIsSigned = (int) ($row['claim_is_signed'] ?? 0) === 1;
                if (!is_string($claim) || $claim === '') {
                    $claimIsSigned = $this->fillLegacyClaim($interfaceId, $metadata);
                }
                if ($claimIsSigned) {
                    throw self::sessionUnknown();
                }
            }
            $this->touchInterface($interfaceId, 'online');

            return [
                'interface_id' => $interfaceId,
                'name' => (string) $row['name'],
                'bitrate' => (int) $row['bitrate'],
                'mtu' => (int) $row['mtu'],
                'status' => (string) $row['status'],
                'metadata' => $metadata,
            ];
        }

        // 4.
        if ($signed) {
            $tokenHash = hash('sha256', $sessionToken);
            $previous = (string) ($row['previous_session_token_hash'] ?? '');
            if ($previous !== '' && hash_equals($previous, $tokenHash)
                && !hash_equals((string) ($row['superseded_logged_hash'] ?? ''), $tokenHash)) {
                $this->logSupersededOnce($interfaceId, $tokenHash);
            }
            throw new ApiError(409, 'Session superseded', [
                'error' => 'session_superseded',
                'message' => 'This identity connected from another tab or device. Reload to connect here.',
            ]);
        }

        // 5.
        throw self::sessionUnknown();
    }

    /**
     * §7 step 3: a legacy browser row old code wrote (after a rollback) has
     * its claim only in metadata_json. Fill claimed_identity_hash from it,
     * so §4.5 and §9 see the claim, and say whether a signed row holds it.
     */
    private function fillLegacyClaim(string $interfaceId, array $metadata): bool
    {
        $claim = self::normaliseIdentityHashClaim($metadata['identity_hash'] ?? null);
        if ($claim === null) {
            return false;
        }
        $fill = $this->db->prepare(
            'UPDATE interfaces SET claimed_identity_hash = :claim
              WHERE interface_id = :interface_id AND identity_hash IS NULL
                AND (claimed_identity_hash IS NULL OR claimed_identity_hash = :empty)'
        );
        $fill->bindValue(':claim', $claim, PDO::PARAM_STR);
        $fill->bindValue(':interface_id', $interfaceId, PDO::PARAM_STR);
        $fill->bindValue(':empty', '', PDO::PARAM_STR);
        Database::executeWithRetry($fill, 'claimedIdentityFill');
        $this->forgetRowRegistrationFacts($interfaceId);

        return $this->signedRowByIdentityHash($claim) !== null;
    }

    private static function sessionUnknown(): ApiError
    {
        return new ApiError(401, 'Invalid interface credentials', [
            'error' => 'unauthorized',
            'message' => 'This PHP node does not know this session. Register again.',
        ]);
    }

    /**
     * §8: [SESSION-SUPERSEDED] only for the token the last signed re-bind
     * replaced, once per row per token: the compare-and-swap on the row's
     * own interface_id writes superseded_logged_hash, and only the request
     * whose write changed it logs.
     */
    private function logSupersededOnce(string $interfaceId, string $tokenHash): void
    {
        $stmt = $this->db->prepare(
            'UPDATE interfaces SET superseded_logged_hash = :new_hash
              WHERE interface_id = :id AND superseded_logged_hash <> :logged_hash'
        );
        $stmt->bindValue(':new_hash', $tokenHash, PDO::PARAM_STR);
        $stmt->bindValue(':id', $interfaceId, PDO::PARAM_STR);
        $stmt->bindValue(':logged_hash', $tokenHash, PDO::PARAM_STR);
        Database::executeWithRetry($stmt, 'supersededLogged');
        if ($stmt->rowCount() === 1) {
            error_log(sprintf('[SESSION-SUPERSEDED] interface=%s', substr($interfaceId, 0, 8)));
        }
    }

    // ── /health ─────────────────────────────────────────────────────────

    /**
     * §12's object for /health: no identity hash, token, key or browser row.
     * A query here that fails reports schema_migrated false, never a 500.
     */
    public function registrationHealth(): array
    {
        $health = [
            'version' => 1,
            'schema_migrated' => $this->schemaMigrated(),
            'enforce_signed_registration' => $this->enforceSignedRegistration(),
            'browsers_online' => ['signed' => 0, 'legacy' => 0],
            'hash_only_challenges' => 0,
        ];
        try {
            // Browsers only: since 2026-10-16 a gateway or PHP-node peer may
            // sign too, and Phase 2's gate (b) and Phase 3 read this number.
            // A signed row's client is one of three (§4.3 step 4), and JSON
            // escapes every quote inside a value, so the pattern matches
            // exactly the rns-js rows (as the debug report finds poll-mode
            // gateways).
            $signed = $this->db->prepare(
                'SELECT COUNT(*) FROM interfaces
                  WHERE status = :online AND registration_proof = :signed AND metadata_json LIKE :browser'
            );
            $signed->bindValue(':online', 'online', PDO::PARAM_STR);
            $signed->bindValue(':signed', 'signed', PDO::PARAM_STR);
            $signed->bindValue(':browser', '%"client":"rns-js"%', PDO::PARAM_STR);
            $signed->execute();
            $legacy = $this->db->prepare(
                'SELECT COUNT(*) FROM interfaces
                  WHERE status = :online AND registration_proof = :none AND claimed_identity_hash IS NOT NULL'
            );
            $legacy->bindValue(':online', 'online', PDO::PARAM_STR);
            $legacy->bindValue(':none', 'none', PDO::PARAM_STR);
            $legacy->execute();
            $count = $this->db->prepare('SELECT state_value FROM transport_state WHERE state_key = :state_key');
            $count->bindValue(':state_key', RegistrationProtocol::HASH_ONLY_CHALLENGES_STATE_KEY, PDO::PARAM_STR);
            $count->execute();
            $health['browsers_online'] = [
                'signed' => (int) $signed->fetchColumn(),
                'legacy' => (int) $legacy->fetchColumn(),
            ];
            $health['hash_only_challenges'] = (int) $count->fetchColumn();
        } catch (\Throwable $error) {
            $health['schema_migrated'] = false;
        }

        return $health;
    }

    // ── Refusals ────────────────────────────────────────────────────────

    /**
     * Every 4xx and 5xx of register and challenge: {"error", "message"},
     * logged [REG-REFUSED] (§10, §11) unless $log is false (§11's once per
     * row and count). The context carries what may be logged: the client
     * (escaped) and the identity hash. Never a token, signature, challenge
     * or the secret.
     */
    private function registrationRefusal(int $status, string $error, string $message, array $context, bool $log = true): ApiError
    {
        if ($log) {
            $line = sprintf('[REG-REFUSED] %d %s client=%s', $status, $error, RegistrationProtocol::logValue($context['client'] ?? null));
            if (isset($context['identity']) && is_string($context['identity'])) {
                $line .= ' identity=' . $context['identity'];
            }
            if (isset($context['detail']) && is_string($context['detail'])) {
                $line .= ' ' . $context['detail'];
            }
            error_log($line);
        }

        return new ApiError($status, $message, ['error' => $error, 'message' => $message]);
    }
}
