<?php

declare(strict_types=1);

namespace ReticulumPhp;

/**
 * RegistrationProtocol — the byte-level rules of a browser's signed
 * registration, as pure functions with no database.
 *
 * REGISTRATION-STAGE1.md is normative (§3 the challenge, §4.2 the signed
 * bytes, §5 the encrypted token); REGISTRATION.md is the full design, of which
 * Stage 1 builds the browser part. The byte-exact vectors are
 * php/tests/vectors/registration_vectors.json (format 6), and
 * tests/registration_vectors_test.php feeds the browser vectors through these
 * functions and through RequestRegistrationTrait. Nothing here is shared with
 * tools/check_registration_vectors.php or tools/registration_vectors.py: the
 * three implementations agree only through the vectors.
 */
final class RegistrationProtocol
{
    /** §4.2: the domain of the signed bytes, 26 ASCII bytes. */
    public const REGISTER_DOMAIN = 'reticulum-post/register/v1';

    /** §3: the domain of the challenge MAC, 27 ASCII bytes. */
    public const CHALLENGE_DOMAIN = 'reticulum-post/challenge/v1';

    /** §3: nonce(16) || HMAC-SHA256(32). */
    public const CHALLENGE_BYTES = 48;
    public const CHALLENGE_NONCE_BYTES = 16;

    /** §3: where the node secret lives, as 64 lower-case hex. */
    public const SECRET_STATE_KEY = 'registration_challenge_secret_hex';

    /** §12: the count of challenge POSTs by identity_hash, for /health. */
    public const HASH_ONLY_CHALLENGES_STATE_KEY = 'hash_only_challenges';

    /** §4.1: exactly these four keys in the registration object, sorted. */
    public const REGISTRATION_KEYS = ['challenge', 'public_key', 'signature', 'version'];

    /** §4.1: the metadata keys a signed registration may carry. */
    public const SIGNED_METADATA_KEYS = [
        'client', 'mode', 'transport', 'peer_url', 'peer_interface_id', 'peer_session_token',
        'implementation', 'identity_hash',
    ];

    /** §4.3 step 1: what today's INT columns hold. */
    public const MAX_INT_FIELD = 2147483647;

    /** §4.2: lp(x) = u16be(len(x)) || x. */
    public static function lp(string $x): string
    {
        if (strlen($x) > 0xFFFF) {
            throw new \LengthException('lp field longer than 65535 bytes');
        }

        return pack('n', strlen($x)) . $x;
    }

    /** Unsigned 64-bit big-endian, for the count and the bitrate. */
    public static function u64be(int $value): string
    {
        return pack('J', $value);
    }

    /** True when $value is a string of exactly $length lower-case hex characters. */
    public static function isLowerHex(mixed $value, int $length): bool
    {
        // \A and \z: PCRE's $ would also accept a trailing "\n".
        return is_string($value) && strlen($value) === $length && preg_match('/\A[0-9a-f]+\z/', $value) === 1;
    }

    /** RNS identity hash: SHA-256(x25519_pub || ed25519_pub)[:16], raw bytes. */
    public static function identityHash(string $publicKey): string
    {
        return substr(hash('sha256', $publicKey, true), 0, 16);
    }

    /** §3: HMAC-SHA256(node_secret, domain || H(16) || u64be(count) || nonce(16)), raw bytes. */
    public static function challengeMac(string $nodeSecret, string $identityHash, int $count, string $nonce): string
    {
        return hash_hmac('sha256', self::CHALLENGE_DOMAIN . $identityHash . self::u64be($count) . $nonce, $nodeSecret, true);
    }

    /** §3: nonce || mac, 48 raw bytes. $nonce is for the pinned vectors only. */
    public static function mintChallenge(string $nodeSecret, string $identityHash, int $count, ?string $nonce = null): string
    {
        $nonce ??= random_bytes(self::CHALLENGE_NONCE_BYTES);

        return $nonce . self::challengeMac($nodeSecret, $identityHash, $count, $nonce);
    }

    /** §4.3 step 6: does this 48-byte challenge carry this node's MAC for H at count? Constant time. */
    public static function challengeVerifies(string $nodeSecret, string $identityHash, int $count, string $challenge): bool
    {
        if (strlen($challenge) !== self::CHALLENGE_BYTES) {
            return false;
        }
        $nonce = substr($challenge, 0, self::CHALLENGE_NONCE_BYTES);
        $mac = substr($challenge, self::CHALLENGE_NONCE_BYTES);

        return hash_equals(self::challengeMac($nodeSecret, $identityHash, $count, $nonce), $mac);
    }

    /**
     * §4.2: the twelve signed fields, built from the decoded JSON body before
     * any normalisation. The caller has already checked the body's shape
     * (§4.3 step 1), so every value has the type the layout needs. An
     * optional field that is absent, null or "" encodes as lp("").
     */
    public static function signedBytes(array $body): string
    {
        $registration = $body['registration'];
        $metadata = $body['metadata'];
        $optional = static fn (string $key): string => is_string($metadata[$key] ?? null) ? $metadata[$key] : '';

        return self::lp(self::REGISTER_DOMAIN)
            . self::lp((string) hex2bin($registration['challenge']))
            . self::lp((string) hex2bin($registration['public_key']))
            . self::lp($body['name'])
            . self::lp(self::u64be($body['bitrate']))
            . self::lp(pack('N', $body['mtu']))
            . self::lp($metadata['client'])
            . self::lp(chr($metadata['mode']))
            . self::lp($optional('transport'))
            . self::lp($optional('peer_url'))
            . self::lp($optional('peer_interface_id'))
            . self::lp($optional('peer_session_token'));
    }

    /**
     * §5: RNS Identity.encrypt(plaintext) to a 64-byte public key, with no
     * ratchet. The HKDF salt is the identity hash. Returns the raw blob
     * eph_public(32) || iv(16) || AES-256-CBC(PKCS7) || HMAC-SHA256(iv || ct).
     *
     * $ephemeralPrivate and $iv are for the pinned vectors only; the PHP node
     * passes neither. Throws SodiumException when the X25519 result is all
     * zeros (a low-order key), which §4.3 step 7 turns into 400.
     */
    public static function encryptToken(string $plaintext, string $publicKey, string $identityHash, ?string $ephemeralPrivate = null, ?string $iv = null): string
    {
        if (strlen($publicKey) !== 64 || strlen($identityHash) !== 16) {
            throw new \InvalidArgumentException('public key must be 64 bytes and identity hash 16');
        }
        $ephemeralPrivate ??= random_bytes(SODIUM_CRYPTO_SCALARMULT_SCALARBYTES);
        $iv ??= random_bytes(16);
        $ephemeralPublic = sodium_crypto_scalarmult_base($ephemeralPrivate);
        $shared = sodium_crypto_scalarmult($ephemeralPrivate, substr($publicKey, 0, 32));
        if (hash_equals(str_repeat("\0", 32), $shared)) {
            throw new \SodiumException('X25519 result is all zeros');
        }
        $derived = hash_hkdf('sha256', $shared, 64, '', $identityHash);
        $ciphertext = openssl_encrypt($plaintext, 'aes-256-cbc', substr($derived, 32, 32), OPENSSL_RAW_DATA, $iv);
        if (!is_string($ciphertext)) {
            throw new \RuntimeException('AES-256-CBC encryption failed');
        }
        $signedParts = $iv . $ciphertext;

        return $ephemeralPublic . $signedParts . hash_hmac('sha256', $signedParts, substr($derived, 0, 32), true);
    }

    /**
     * A request-controlled value as it may appear in a log line. A plain
     * token (letters, digits, '.', '_', '-', up to 64) is written as it is;
     * anything else goes through JSON, which escapes control characters and
     * non-ASCII, so it cannot forge a line, cut to 64 bytes.
     */
    public static function logValue(mixed $value): string
    {
        if ($value === null) {
            return '-';
        }
        if (is_string($value) && preg_match('/\A[A-Za-z0-9._-]{1,64}\z/', $value) === 1) {
            return $value;
        }
        $text = is_string($value) ? $value : get_debug_type($value);
        if (strlen($text) > 64) {
            $text = substr($text, 0, 64) . '…';
        }
        $encoded = json_encode($text, JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE);

        return is_string($encoded) ? $encoded : '"?"';
    }
}
