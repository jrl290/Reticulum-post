<?php
/**
 * Test-side browser for Stage 1's signed registration (REGISTRATION-STAGE1.md
 * §3 to §5): an RNS identity, the twelve signed fields, the signature and the
 * token decryption, written here independently of php/src, so a test that
 * signs with it checks the PHP node rather than agreeing with itself. The
 * vectors (registration_vectors_test.php) pin both sides byte for byte.
 *
 * Not a test: php/tests/stubs/ holds fixtures, and deploy.sh runs only
 * php/tests/*.php.
 */
declare(strict_types=1);

final class RegFixture
{
    public const VECTORS = __DIR__ . '/../vectors/registration_vectors.json';

    /** @return array<string, mixed> the vector file, decoded */
    public static function vectors(): array
    {
        static $doc = null;
        $doc ??= json_decode((string) file_get_contents(self::VECTORS), true, 512, JSON_THROW_ON_ERROR);

        return $doc;
    }

    /**
     * An identity: a fresh one, or a vector's by name.
     *
     * @return array{x_prv: ?string, public_key: string, public_key_hex: string, ed_sk: string, hash: string, hash_hex: string}
     */
    public static function identity(?string $vectorName = null): array
    {
        if ($vectorName !== null) {
            $v = self::vectors()['identities'][$vectorName];
            $edKeypair = sodium_crypto_sign_seed_keypair((string) hex2bin($v['ed25519_private_seed_hex']));
            $xPrv = $v['x25519_private_hex'] === null ? null : (string) hex2bin($v['x25519_private_hex']);
            $publicKey = (string) hex2bin($v['public_key_hex']);
        } else {
            $edKeypair = sodium_crypto_sign_keypair();
            $xPrv = random_bytes(32);
            $publicKey = sodium_crypto_scalarmult_base($xPrv) . sodium_crypto_sign_publickey($edKeypair);
        }
        $hash = substr(hash('sha256', $publicKey, true), 0, 16);

        return [
            'x_prv' => $xPrv,
            'public_key' => $publicKey,
            'public_key_hex' => bin2hex($publicKey),
            'ed_sk' => sodium_crypto_sign_secretkey($edKeypair),
            'hash' => $hash,
            'hash_hex' => bin2hex($hash),
        ];
    }

    private static function lp(string $x): string
    {
        return pack('n', strlen($x)) . $x;
    }

    /** §4.2, built from the body the browser is about to send. */
    public static function signedBytes(array $body): string
    {
        $md = $body['metadata'];
        $opt = static fn (string $k): string => isset($md[$k]) && is_string($md[$k]) ? $md[$k] : '';

        return self::lp('reticulum-post/register/v1')
            . self::lp((string) hex2bin($body['registration']['challenge']))
            . self::lp((string) hex2bin($body['registration']['public_key']))
            . self::lp($body['name'])
            . self::lp(pack('J', $body['bitrate']))
            . self::lp(pack('N', $body['mtu']))
            . self::lp($md['client'])
            . self::lp(chr($md['mode']))
            . self::lp($opt('transport'))
            . self::lp($opt('peer_url'))
            . self::lp($opt('peer_interface_id'))
            . self::lp($opt('peer_session_token'));
    }

    /** A complete signed register body for $identity over $challengeHex (§4.1). */
    public static function body(array $identity, string $challengeHex, array $metadata, string $name = 'Retichat Web', int $bitrate = 1000000, int $mtu = 500): array
    {
        $body = [
            'name' => $name,
            'bitrate' => $bitrate,
            'mtu' => $mtu,
            'metadata' => $metadata,
            'registration' => [
                'version' => 1,
                'public_key' => $identity['public_key_hex'],
                'challenge' => $challengeHex,
                'signature' => str_repeat('0', 128),
            ],
        ];

        return self::resign($body, $identity);
    }

    /** Sign $body again after a test changed it (so only the change under test is wrong). */
    public static function resign(array $body, array $identity): array
    {
        $body['registration']['signature'] = bin2hex(sodium_crypto_sign_detached(self::signedBytes($body), $identity['ed_sk']));

        return $body;
    }

    public static function browserMetadata(): array
    {
        return ['client' => 'rns-js', 'implementation' => 'PostInterface', 'mode' => 1];
    }

    /** A gateway in poll mode, as post_interface.rs and PostInterface.py register. */
    public static function pollGatewayMetadata(): array
    {
        return ['client' => 'rns-post-interface', 'implementation' => 'PostInterface', 'mode' => 6, 'transport' => 'tcp-backbone-gateway'];
    }

    /** A PHP node registering at another (connectToPeer). */
    public static function phpPeerMetadata(string $peerUrl = 'https://peer.example/reticulum'): array
    {
        return [
            'client' => 'reticulum-php', 'peer_url' => $peerUrl,
            'peer_interface_id' => bin2hex(random_bytes(16)), 'peer_session_token' => bin2hex(random_bytes(32)),
        ];
    }

    /** RNS Identity.decrypt of session_token_encrypted; null on any failure. */
    public static function decrypt(string $blobHex, array $identity): ?string
    {
        $blob = hex2bin($blobHex);
        if (!is_string($blob) || strlen($blob) < 32 + 16 + 16 + 32 || $identity['x_prv'] === null) {
            return null;
        }
        $shared = sodium_crypto_scalarmult($identity['x_prv'], substr($blob, 0, 32));
        $derived = hash_hkdf('sha256', $shared, 64, '', $identity['hash']);
        $token = substr($blob, 32);
        $signedParts = substr($token, 0, -32);
        if (!hash_equals(hash_hmac('sha256', $signedParts, substr($derived, 0, 32), true), substr($token, -32))) {
            return null;
        }
        $plain = openssl_decrypt(substr($signedParts, 16), 'aes-256-cbc', substr($derived, 32, 32), OPENSSL_RAW_DATA, substr($signedParts, 0, 16));

        return is_string($plain) ? $plain : null;
    }

    /** A Storage on SQLite (in memory, or a file a second process can share), migrated. */
    public static function storage(array $registration = [], ?string $path = null): ReticulumPhp\Storage
    {
        $storage = new ReticulumPhp\Storage(self::config($registration, $path));
        $storage->migrateIfNeeded();

        return $storage;
    }

    public static function config(array $registration = [], ?string $path = null): array
    {
        return [
            'storage' => ['backend' => 'sqlite', 'sqlite_path' => $path ?? ':memory:'],
            'http' => ['max_batch_packets' => 64, 'max_packet_bytes' => 500, 'idle_exchange_interval_ms' => 1000],
            'registration' => $registration,
        ];
    }

    public static function db(ReticulumPhp\Storage $storage): PDO
    {
        return (new ReflectionProperty($storage, 'db'))->getValue($storage);
    }

    /** The node secret as the PHP node stored it (raw bytes), or '' if it has none yet. */
    public static function secret(ReticulumPhp\Storage $storage): string
    {
        $st = self::db($storage)->prepare('SELECT state_value FROM transport_state WHERE state_key = :k');
        $st->execute([':k' => 'registration_challenge_secret_hex']);

        return (string) hex2bin((string) $st->fetchColumn());
    }

    /** A challenge through the real code, by key (as a browser asks). */
    public static function challenge(ReticulumPhp\Storage $storage, array $identity): string
    {
        return $storage->issueChallenge(['public_key' => $identity['public_key_hex']])['challenge'];
    }

    /** Register signed through the real code: challenge, sign, register. */
    public static function register(ReticulumPhp\Storage $storage, array $identity, ?array $metadata = null, string $name = 'Retichat Web'): array
    {
        return $storage->registerFromBody(self::body($identity, self::challenge($storage, $identity), $metadata ?? self::browserMetadata(), $name));
    }

    /** Register signed and return [answer, the decrypted session token]. */
    public static function connect(ReticulumPhp\Storage $storage, array $identity, string $name = 'Retichat Web'): array
    {
        $answer = self::register($storage, $identity, null, $name);

        return [$answer, (string) self::decrypt((string) $answer['session_token_encrypted'], $identity)];
    }

    /** Run $fn and return [result or ApiError, the error_log lines it wrote]. */
    public static function capture(callable $fn): array
    {
        static $logFile = null;
        if ($logFile === null) {
            $logFile = tempnam(sys_get_temp_dir(), 'reg-fixture-log-');
            ini_set('error_log', $logFile);
            ini_set('log_errors', '1');
            register_shutdown_function(static fn () => @unlink($logFile));
        }
        clearstatcache(true, $logFile);
        $offset = (int) filesize($logFile);
        try {
            $result = $fn();
        } catch (ReticulumPhp\ApiError $error) {
            $result = $error;
        }
        clearstatcache(true, $logFile);
        $log = (string) file_get_contents($logFile, false, null, $offset);

        return [$result, $log];
    }

    /** [status, error] of a refusal, or [200, null] for an answer. */
    public static function outcome(mixed $result): array
    {
        if ($result instanceof ReticulumPhp\ApiError) {
            return [$result->statusCode, $result->payload['error'] ?? null];
        }

        return [200, null];
    }
}

// Route error_log to the capture file from the start, so lines written
// outside capture() do not land on the test's output.
RegFixture::capture(static fn () => null);
