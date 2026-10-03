<?php
/**
 * Independent check of php/tests/vectors/registration_vectors.json with the
 * primitives the relay uses: ext/sodium (Ed25519, X25519), hash_hmac,
 * hash_hkdf and ext/openssl (AES-256-CBC). REGISTRATION.md is the normative
 * protocol; tools/registration_vectors.py generated the file from RNS 1.5.2.
 *
 *     php Reticulum-post/tools/check_registration_vectors.php
 *
 * It re-derives every key, identity hash, challenge MAC, signed byte string
 * and encrypted session token from the vector inputs, verifies every
 * signature, and runs a REFERENCE verifier (REGISTRATION.md section 4.3,
 * in its normative order) over every positive and negative vector, comparing
 * the HTTP status and error code. The reference verifier is deliberately
 * self-contained: it is not the relay's code, it is what the relay's code must
 * agree with. When the relay implementation lands, its own test should feed
 * these same vectors through registerInterface().
 *
 * Exit 0 = every check passed.
 */

declare(strict_types=1);

const REGISTER_DOMAIN = 'reticulum-post/register/v1';
const CHALLENGE_DOMAIN = 'reticulum-post/challenge/v1';
const SIGNED_METADATA_KEYS = ['client', 'mode', 'transport', 'peer_url', 'peer_interface_id', 'peer_session_token'];
const ALLOWED_METADATA_KEYS = ['client', 'implementation', 'mode', 'transport', 'peer_url', 'peer_interface_id', 'peer_session_token', 'identity_hash'];
const MAX_SAFE_INTEGER = 9007199254740991; // 2^53 - 1

foreach (['sodium_crypto_sign_verify_detached', 'sodium_crypto_scalarmult', 'hash_hkdf', 'openssl_encrypt'] as $fn) {
    if (!function_exists($fn)) {
        fwrite(STDERR, "SKIP: {$fn} is not available\n");
        exit(2);
    }
}

$path = $argv[1] ?? (__DIR__ . '/../php/tests/vectors/registration_vectors.json');
$doc = json_decode((string) file_get_contents($path), true, 512, JSON_THROW_ON_ERROR);

$failures = [];
$checks = 0;
$expect = static function (bool $ok, string $what) use (&$failures, &$checks): void {
    $checks++;
    if (!$ok) {
        $failures[] = $what;
    }
};

function lp(string $x): string
{
    if (strlen($x) > 0xFFFF) {
        throw new RuntimeException('lp field too long');
    }
    return pack('n', strlen($x)) . $x;
}

function u64(int $v): string
{
    return pack('J', $v);
}

/** The twelve signed fields, read from the decoded body before any normalisation. */
function signedBytes(array $body): string
{
    $md = $body['metadata'];
    $opt = static fn (string $k): string => isset($md[$k]) ? (string) $md[$k] : '';
    return lp(REGISTER_DOMAIN)
        . lp((string) hex2bin($body['registration']['challenge']))
        . lp((string) hex2bin($body['registration']['public_key']))
        . lp($body['name'])
        . lp(u64($body['bitrate']))
        . lp(pack('N', $body['mtu']))
        . lp($md['client'])
        . lp(chr($md['mode']))
        . lp($opt('transport'))
        . lp($opt('peer_url'))
        . lp($opt('peer_interface_id'))
        . lp($opt('peer_session_token'));
}

function challengeMac(string $relaySecret, string $identityHash, int $seq, string $nonce): string
{
    return hash_hmac('sha256', CHALLENGE_DOMAIN . $identityHash . u64($seq) . $nonce, $relaySecret, true);
}

function isLowerHex(mixed $v, int $len): bool
{
    return is_string($v) && strlen($v) === $len && preg_match('/\A[0-9a-f]+\z/', $v) === 1;
}

function optionalString(array $md, string $key, int $maxBytes): bool
{
    if (!array_key_exists($key, $md)) {
        return true;
    }
    $v = $md[$key];
    // Absent, null and "" all sign as lp("") and are stored as absent.
    return $v === null || (is_string($v) && strlen($v) <= $maxBytes && mb_check_encoding($v, 'UTF-8'));
}

/**
 * Reference verifier: REGISTRATION.md section 4.3, steps 1-7 (step 8, the
 * atomic bind, is a database property and is modelled by $rowSeq only).
 *
 * @param int $rowSeq the signed row's registration_seq for the derived identity, 0 = none
 * @return array{status:int, error?:string, identity_hash?:string, registration_seq?:int}
 */
function verifySigned(array $body, string $relaySecret, int $rowSeq): array
{
    $bad = static fn (int $status, string $error): array => ['status' => $status, 'error' => $error];

    // 1. Shape.
    $reg = $body['registration'] ?? null;
    $md = $body['metadata'] ?? null;
    if (!is_array($reg) || !is_array($md)
        || array_diff(array_keys($reg), ['version', 'public_key', 'challenge', 'signature']) !== []
        || ($reg['version'] ?? null) !== 1
        || !isLowerHex($reg['public_key'] ?? null, 128)
        || !isLowerHex($reg['challenge'] ?? null, 112)
        || !isLowerHex($reg['signature'] ?? null, 128)
        || !is_string($body['name'] ?? null) || trim($body['name']) === '' || strlen($body['name']) > 255 || !mb_check_encoding($body['name'], 'UTF-8')
        || !is_int($body['bitrate'] ?? null) || $body['bitrate'] < 1 || $body['bitrate'] > MAX_SAFE_INTEGER
        || !is_int($body['mtu'] ?? null) || $body['mtu'] < 1 || $body['mtu'] > 0xFFFFFFFF
        || !is_string($md['client'] ?? null) || $md['client'] === '' || strlen($md['client']) > 64
        || !optionalString($md, 'implementation', 64)
        || !is_int($md['mode'] ?? null) || $md['mode'] < 1 || $md['mode'] > 7
        || !optionalString($md, 'transport', 64)
        || !optionalString($md, 'peer_url', 512)
        || !optionalString($md, 'peer_interface_id', 64)
        || !optionalString($md, 'peer_session_token', 128)
    ) {
        return $bad(400, 'bad_registration');
    }

    // 2. Only signed (or informational) metadata keys.
    foreach (array_keys($md) as $key) {
        if (!in_array($key, ALLOWED_METADATA_KEYS, true)) {
            return $bad(400, 'unsigned_metadata');
        }
    }

    $publicKey = (string) hex2bin($reg['public_key']);
    $identityHash = substr(hash('sha256', $publicKey, true), 0, 16);

    // 3. A metadata identity_hash, if sent, must be the key's own hash.
    if (array_key_exists('identity_hash', $md)
        && !(is_string($md['identity_hash']) && hash_equals(bin2hex($identityHash), $md['identity_hash']))) {
        return $bad(400, 'identity_hash_mismatch');
    }

    // 4. Client policy: a browser is an endpoint.
    if ($md['client'] === 'rns-js' && in_array($md['mode'], [3, 5, 6], true)) {
        return $bad(400, 'transit_mode_not_allowed');
    }

    // 5. The challenge is this relay's, for this identity.
    $challenge = (string) hex2bin($reg['challenge']);
    $nonce = substr($challenge, 0, 16);
    $seq = unpack('J', substr($challenge, 16, 8))[1];
    $mac = substr($challenge, 24, 32);
    if ($seq < 0 || $seq >= MAX_SAFE_INTEGER
        || !hash_equals(challengeMac($relaySecret, $identityHash, $seq, $nonce), $mac)) {
        return $bad(409, 'stale_challenge');
    }

    // 6. The challenge is for the row's current seq.
    if ($seq !== $rowSeq) {
        return $bad(409, 'stale_challenge');
    }

    // 7. The signature.
    $signature = (string) hex2bin($reg['signature']);
    if (!sodium_crypto_sign_verify_detached($signature, signedBytes($body), substr($publicKey, 32, 32))) {
        return $bad(403, 'bad_registration_signature');
    }

    return ['status' => 200, 'identity_hash' => bin2hex($identityHash), 'registration_seq' => $seq + 1];
}

/** RNS Identity.encrypt with a pinned ephemeral key and IV (request_lxmf_handoff_trait.php's derivation). */
function encryptTokenPinned(string $plaintext, string $x25519Public, string $identityHash, string $ephPrivate, string $iv): string
{
    $ephPublic = sodium_crypto_scalarmult_base($ephPrivate);
    $shared = sodium_crypto_scalarmult($ephPrivate, $x25519Public);
    $derived = hash_hkdf('sha256', $shared, 64, '', $identityHash);
    $ct = openssl_encrypt($plaintext, 'aes-256-cbc', substr($derived, 32, 32), OPENSSL_RAW_DATA, $iv);
    $signedParts = $iv . $ct;
    return $ephPublic . $signedParts . hash_hmac('sha256', $signedParts, substr($derived, 0, 32), true);
}

/** RNS Identity.decrypt; null when the HMAC or padding fails. */
function decryptToken(string $blob, string $x25519Private, string $identityHash): ?string
{
    if (strlen($blob) < 32 + 16 + 16 + 32) {
        return null;
    }
    $shared = sodium_crypto_scalarmult($x25519Private, substr($blob, 0, 32));
    $derived = hash_hkdf('sha256', $shared, 64, '', $identityHash);
    $token = substr($blob, 32);
    $signedParts = substr($token, 0, -32);
    if (!hash_equals(hash_hmac('sha256', $signedParts, substr($derived, 0, 32), true), substr($token, -32))) {
        return null;
    }
    $pt = openssl_decrypt(substr($signedParts, 16), 'aes-256-cbc', substr($derived, 32, 32), OPENSSL_RAW_DATA, substr($signedParts, 0, 16));
    return is_string($pt) ? $pt : null;
}

// ── Constants and lp ───────────────────────────────────────────────────────
$expect($doc['constants']['register_domain'] === REGISTER_DOMAIN, 'register domain');
$expect($doc['constants']['challenge_domain'] === CHALLENGE_DOMAIN, 'challenge domain');
foreach ($doc['lp_examples'] as $ex) {
    $in = isset($ex['input_utf8']) ? $ex['input_utf8'] : (string) hex2bin($ex['input_hex']);
    $expect(bin2hex(lp($in)) === $ex['output_hex'], 'lp example ' . $ex['output_hex']);
}

// ── Identities ─────────────────────────────────────────────────────────────
$ids = [];
foreach ($doc['identities'] as $name => $id) {
    $xPrv = (string) hex2bin($id['x25519_private_hex']);
    $seed = (string) hex2bin($id['ed25519_private_seed_hex']);
    $xPub = sodium_crypto_scalarmult_base($xPrv);
    $edPub = sodium_crypto_sign_publickey(sodium_crypto_sign_seed_keypair($seed));
    $pub = $xPub . $edPub;
    $expect(bin2hex($pub) === $id['public_key_hex'], "identity {$name}: public key from private key");
    $expect($id['private_key_hex'] === $id['x25519_private_hex'] . $id['ed25519_private_seed_hex'], "identity {$name}: private key layout");
    $expect(bin2hex(substr(hash('sha256', $pub, true), 0, 16)) === $id['identity_hash_hex'], "identity {$name}: identity hash");
    $ids[$name] = [
        'x_prv' => $xPrv,
        'x_pub' => $xPub,
        'ed_sk' => sodium_crypto_sign_secretkey(sodium_crypto_sign_seed_keypair($seed)),
        'hash' => (string) hex2bin($id['identity_hash_hex']),
    ];
}

// ── Challenges ─────────────────────────────────────────────────────────────
$secrets = [];
foreach ($doc['relays'] as $r => $relay) {
    $secrets[$r] = (string) hex2bin($relay['relay_secret_hex']);
}
foreach ($doc['challenges'] as $c) {
    $h = (string) hex2bin($c['identity_hash_hex']);
    $nonce = (string) hex2bin($c['nonce_hex']);
    $input = CHALLENGE_DOMAIN . $h . u64($c['registration_seq']) . $nonce;
    $mac = challengeMac($secrets[$c['minted_by_relay']], $h, $c['registration_seq'], $nonce);
    $expect(bin2hex($input) === $c['mac_input_hex'], "challenge {$c['id']}: MAC input");
    $expect(bin2hex($mac) === $c['mac_hex'], "challenge {$c['id']}: MAC");
    $expect(bin2hex($nonce . u64($c['registration_seq']) . $mac) === $c['challenge_hex'], "challenge {$c['id']}: layout");
    $expect($h === $ids[$c['for_identity']]['hash'], "challenge {$c['id']}: identity");
}

// ── Positive registrations ─────────────────────────────────────────────────
foreach ($doc['registrations'] as $v) {
    $id = $v['id'];
    $body = $v['request_body'];
    $msg = signedBytes($body);
    $expect(bin2hex($msg) === $v['signed_bytes_hex'], "{$id}: signed bytes rebuilt from the body");
    $joined = '';
    foreach ($v['signed_fields'] as $f) {
        $expect(bin2hex(lp((string) hex2bin($f['value_hex']))) === $f['lp_hex'], "{$id}: lp of {$f['name']}");
        $joined .= (string) hex2bin($f['lp_hex']);
    }
    $expect($joined === $msg, "{$id}: signed_fields concatenate to the signed bytes");
    $sig = (string) hex2bin($v['signature_hex']);
    $expect(bin2hex(sodium_crypto_sign_detached($msg, $ids[$v['identity']]['ed_sk'])) === $v['signature_hex'], "{$id}: deterministic Ed25519 signature reproduced by sodium");

    $result = verifySigned($body, $secrets[$v['relay']], $v['relay_state_before']['row_registration_seq']);
    $expect($result['status'] === 200, "{$id}: reference verifier accepts (got " . json_encode($result) . ')');
    $expect(($result['identity_hash'] ?? '') === $v['expected']['identity_hash'], "{$id}: derived identity hash");
    $expect(($result['registration_seq'] ?? -1) === $v['expected']['registration_seq'], "{$id}: new seq");

    $t = $v['encrypted_token'];
    $blob = encryptTokenPinned(
        $t['plaintext_utf8'],
        $ids[$v['identity']]['x_pub'],
        $ids[$v['identity']]['hash'],
        (string) hex2bin($t['ephemeral_private_hex']),
        (string) hex2bin($t['iv_hex']),
    );
    $expect(bin2hex($blob) === $t['session_token_encrypted_hex'], "{$id}: encrypted token reproduced with sodium + hkdf + openssl");
    $expect($v['response_example']['session_token_encrypted'] === $t['session_token_encrypted_hex'], "{$id}: response example carries the token");
    $expect(!array_key_exists('session_token', $v['response_example']), "{$id}: response example carries no plaintext token");
    $pt = decryptToken((string) hex2bin($t['session_token_encrypted_hex']), $ids[$v['identity']]['x_prv'], $ids[$v['identity']]['hash']);
    $expect($pt === $t['plaintext_utf8'] && preg_match('/\A[0-9a-f]{64}\z/', (string) $pt) === 1, "{$id}: token decrypts to a 64-hex session token");
}

// ── Negative registrations ─────────────────────────────────────────────────
foreach ($doc['negative'] as $v) {
    $result = verifySigned($v['request_body'], $secrets[$v['relay']], $v['relay_state_before']['row_registration_seq']);
    $expect(
        $result['status'] === $v['expected']['status'] && ($result['error'] ?? null) === $v['expected']['error'],
        "negative {$v['id']}: expected {$v['expected']['status']} {$v['expected']['error']}, got " . json_encode($result)
    );
}

// ── Token negatives ────────────────────────────────────────────────────────
foreach ($doc['tokens_negative'] as $v) {
    $pt = decryptToken((string) hex2bin($v['session_token_encrypted_hex']), $ids[$v['identity']]['x_prv'], $ids[$v['identity']]['hash']);
    $expect($pt === null, "token negative {$v['id']}: must not decrypt");
}

if ($failures !== []) {
    fwrite(STDERR, "FAIL: " . count($failures) . " of {$checks} checks\n");
    foreach ($failures as $f) {
        fwrite(STDERR, "  - {$f}\n");
    }
    exit(1);
}

printf("PASS: %d checks (%d registrations, %d negative, %d token negatives) with PHP %s sodium/openssl\n",
    $checks, count($doc['registrations']), count($doc['negative']), count($doc['tokens_negative']), PHP_VERSION);
exit(0);
