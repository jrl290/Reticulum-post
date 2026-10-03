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
 * signature, re-derives every canonical peer URL and audience, and runs a
 * REFERENCE verifier (REGISTRATION.md section 4.3, in its normative order)
 * over every positive and negative vector, comparing the HTTP status, the
 * error code and the step that fails. The reference verifier is deliberately
 * self-contained: it is not the relay's code, and it shares no code with the
 * Python generator; it is what the relay's code must agree with. When the
 * relay implementation lands, its own test should feed these same vectors
 * through registerInterface().
 *
 * Exit 0 = every check passed.
 */

declare(strict_types=1);

const REGISTER_DOMAIN = 'reticulum-post/register/v1';
const CHALLENGE_DOMAIN = 'reticulum-post/challenge/v1';
const CHALLENGE_BYTES = 48;
const REGISTRATION_KEYS = ['version', 'audience', 'public_key', 'challenge', 'signature'];
const ALLOWED_METADATA_KEYS = ['client', 'implementation', 'mode', 'transport', 'peer_url', 'peer_interface_id', 'peer_session_token', 'identity_hash'];
const KNOWN_CLIENTS = ['rns-js', 'reticulum-php', 'rns-post-interface'];
const TRANSIT_CLIENTS = ['reticulum-php', 'rns-post-interface'];
const AUDIENCE_PATTERN = '/\A(\[[0-9a-f:.]+\]|[a-z0-9.-]+)(:[0-9]{1,5})?\z/';
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

/** The thirteen signed fields, read from the decoded body before any normalisation. */
function signedBytes(array $body): string
{
    $md = $body['metadata'];
    $opt = static fn (string $k): string => isset($md[$k]) ? (string) $md[$k] : '';
    return lp(REGISTER_DOMAIN)
        . lp((string) hex2bin($body['registration']['challenge']))
        . lp($body['registration']['audience'])
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

function present(array $md, string $key): bool
{
    return isset($md[$key]) && is_string($md[$key]) && $md[$key] !== '';
}

/**
 * REGISTRATION.md section 10.1: [canonical, null] or [null, reason].
 *
 * @return array{0: ?string, 1: ?string}
 */
function canonicalPeerUrl(mixed $u): array
{
    if (!is_string($u) || $u === '') {
        return [null, 'empty'];
    }
    if (preg_match('/[^\x00-\x7E]/', $u) === 1) {
        return [null, 'not_ascii'];
    }
    if (preg_match('/[\x00-\x20]/', $u) === 1) {
        return [null, 'whitespace_or_control'];
    }
    if (str_contains($u, '?') || str_contains($u, '#')) {
        return [null, 'query_or_fragment'];
    }
    if (preg_match('#\A([A-Za-z][A-Za-z0-9+.-]*)://([^/]*)(.*)\z#', $u, $m) !== 1) {
        return [null, 'not_absolute'];
    }
    $scheme = strtolower($m[1]);
    $authority = $m[2];
    $path = $m[3];
    if ($scheme !== 'http' && $scheme !== 'https') {
        return [null, 'scheme'];
    }
    if (str_contains($authority, '@')) {
        return [null, 'userinfo'];
    }
    if (preg_match('/\A(\[[0-9A-Fa-f:.]+\]|[A-Za-z0-9.-]+)(?::([0-9]{1,5}))?\z/', $authority, $hm) !== 1) {
        return [null, 'host'];
    }
    $host = strtolower($hm[1]);
    $port = '';
    if (isset($hm[2]) && $hm[2] !== '') {
        $p = (int) $hm[2];
        if ($p < 1 || $p > 65535) {
            return [null, 'port'];
        }
        $isDefault = ($scheme === 'https' && $p === 443) || ($scheme === 'http' && $p === 80);
        $port = $isDefault ? '' : ':' . $p;
    }
    $path = rtrim($path, '/');
    if (str_ends_with($path, '/v1/wake')) {
        $path = rtrim(substr($path, 0, -strlen('/v1/wake')), '/');
    }
    return [$scheme . '://' . $host . $port . $path, null];
}

/** What a client signs: the host part of its canonical base URL. */
function audienceFromBaseUrl(string $u): ?string
{
    [$canonical] = canonicalPeerUrl($u);
    if ($canonical === null) {
        return null;
    }
    $rest = explode('://', $canonical, 2)[1];
    return explode('/', $rest, 2)[0];
}

/** What a relay compares with: its received Host header, lower-cased, default port dropped. */
function audienceFromHostHeader(string $hostHeader, string $scheme): string
{
    $h = strtolower($hostHeader);
    if (preg_match('/\A(\[[^\]]*\]|[^:\[\]]*):([0-9]{1,5})\z/', $h, $m) === 1) {
        $p = (int) $m[2];
        if (($scheme === 'https' && $p === 443) || ($scheme === 'http' && $p === 80)) {
            $h = $m[1];
        }
    }
    return $h;
}

/**
 * Reference verifier: REGISTRATION.md section 4.3, steps 1-10 (step 11, the
 * atomic bind, is a database property and is modelled by the row's seq).
 *
 * @param array{secret:string, host:string, transit_identities:list<string>} $relay
 * @param array{row_registration_seq:int, at_capacity:bool} $state
 * @return array{status:int, error?:string, step?:string, identity_hash?:string, registration_seq?:int}
 */
function verifySigned(array $body, array $relay, array $state): array
{
    $bad = static fn (int $status, string $error, string $step): array => ['status' => $status, 'error' => $error, 'step' => $step];

    // 1. Shape.
    $reg = $body['registration'] ?? null;
    $md = $body['metadata'] ?? null;
    if (!is_array($reg) || !is_array($md)) {
        return $bad(400, 'bad_registration', 'shape');
    }
    $regKeys = array_keys($reg);
    sort($regKeys);
    $wantKeys = REGISTRATION_KEYS;
    sort($wantKeys);
    if ($regKeys !== $wantKeys
        || ($reg['version'] ?? null) !== 1
        || !is_string($reg['audience'] ?? null) || strlen($reg['audience']) > 255 || preg_match(AUDIENCE_PATTERN, $reg['audience']) !== 1
        || !isLowerHex($reg['public_key'] ?? null, 128)
        || !isLowerHex($reg['challenge'] ?? null, 2 * CHALLENGE_BYTES)
        || !isLowerHex($reg['signature'] ?? null, 128)
        || !is_string($body['name'] ?? null) || $body['name'] === '' || strlen($body['name']) > 255 || !mb_check_encoding($body['name'], 'UTF-8')
        || !is_int($body['bitrate'] ?? null) || $body['bitrate'] < 1 || $body['bitrate'] > MAX_SAFE_INTEGER
        || !is_int($body['mtu'] ?? null) || $body['mtu'] < 1 || $body['mtu'] > 0xFFFFFFFF
        || !is_string($md['client'] ?? null) || $md['client'] === '' || strlen($md['client']) > 64 || !mb_check_encoding($md['client'], 'UTF-8')
        || !optionalString($md, 'implementation', 64)
        || !is_int($md['mode'] ?? null) || $md['mode'] < 1 || $md['mode'] > 7
        || !optionalString($md, 'transport', 64)
        || !optionalString($md, 'peer_url', 512)
        || !optionalString($md, 'peer_interface_id', 64)
        || !optionalString($md, 'peer_session_token', 128)
    ) {
        return $bad(400, 'bad_registration', 'shape');
    }

    // 2. Only signed (or informational) metadata keys.
    foreach (array_keys($md) as $key) {
        if (!in_array($key, ALLOWED_METADATA_KEYS, true)) {
            return $bad(400, 'unsigned_metadata', 'metadata_keys');
        }
    }

    $publicKey = (string) hex2bin($reg['public_key']);
    $identityHash = substr(hash('sha256', $publicKey, true), 0, 16);

    // 3. A metadata identity_hash, if sent, must be the key's own hash.
    if (array_key_exists('identity_hash', $md)
        && !(is_string($md['identity_hash']) && hash_equals(bin2hex($identityHash), $md['identity_hash']))) {
        return $bad(400, 'identity_hash_mismatch', 'metadata_identity_hash');
    }

    // 4. Client policy (section 4.3.1).
    $client = $md['client'];
    if (!in_array($client, KNOWN_CLIENTS, true)) {
        return $bad(400, 'unknown_client', 'client_policy');
    }
    if ($client === 'rns-js') {
        if (in_array($md['mode'], [3, 5, 6], true)) {
            return $bad(400, 'transit_mode_not_allowed', 'client_policy');
        }
        foreach (['transport', 'peer_url', 'peer_interface_id', 'peer_session_token'] as $k) {
            if (present($md, $k)) {
                return $bad(400, 'metadata_not_allowed', 'client_policy');
            }
        }
    } elseif ($client === 'rns-post-interface') {
        foreach (['peer_url', 'peer_interface_id', 'peer_session_token'] as $k) {
            if (present($md, $k)) {
                return $bad(400, 'metadata_not_allowed', 'client_policy');
            }
        }
    } else { // reticulum-php: a wake-mode gateway
        if (present($md, 'transport')) {
            return $bad(400, 'metadata_not_allowed', 'client_policy');
        }
        foreach (['peer_url', 'peer_interface_id', 'peer_session_token'] as $k) {
            if (!present($md, $k)) {
                return $bad(400, 'peer_fields_required', 'client_policy');
            }
        }
        if (canonicalPeerUrl($md['peer_url'])[0] === null) {
            return $bad(400, 'peer_url_not_allowed', 'client_policy');
        }
    }

    // 5. The audience is the host this relay was reached at.
    if ($reg['audience'] !== $relay['host']) {
        return $bad(403, 'audience_mismatch', 'audience');
    }

    // 6. The challenge is this relay's, for this identity, at the row's current seq.
    $challenge = (string) hex2bin($reg['challenge']);
    if (!hash_equals(challengeMac($relay['secret'], $identityHash, $state['row_registration_seq'], substr($challenge, 0, 16)), substr($challenge, 16))) {
        return $bad(409, 'stale_challenge', 'challenge');
    }

    // 7. The signature.
    if (!sodium_crypto_sign_verify_detached((string) hex2bin($reg['signature']), signedBytes($body), substr($publicKey, 32, 32))) {
        return $bad(403, 'bad_registration_signature', 'signature');
    }

    // 8. Transit permission.
    if (in_array($client, TRANSIT_CLIENTS, true) && !in_array(bin2hex($identityHash), $relay['transit_identities'], true)) {
        return $bad(403, 'transit_identity_not_allowed', 'transit_identity');
    }

    // 9. Capacity, for a new row only.
    if ($state['row_registration_seq'] === 0 && $state['at_capacity']) {
        return $bad(503, 'registration_capacity', 'capacity');
    }

    // 10. A token must be encryptable to the X25519 half: sodium refuses an
    //     all-zero shared secret (a low-order point) by throwing.
    try {
        $shared = sodium_crypto_scalarmult(random_bytes(32), substr($publicKey, 0, 32));
        if ($shared === str_repeat("\0", 32)) {
            throw new RuntimeException('all-zero shared secret');
        }
    } catch (\Throwable) {
        return $bad(400, 'bad_registration', 'token_encryption');
    }

    return ['status' => 200, 'identity_hash' => bin2hex($identityHash), 'registration_seq' => $state['row_registration_seq'] + 1];
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
$expect($doc['constants']['challenge_length'] === CHALLENGE_BYTES, 'challenge length');
$expect(count($doc['constants']['signed_field_order']) === 13, 'thirteen signed fields');
foreach ($doc['lp_examples'] as $ex) {
    $in = isset($ex['input_utf8']) ? $ex['input_utf8'] : (string) hex2bin($ex['input_hex']);
    $expect(bin2hex(lp($in)) === $ex['output_hex'], 'lp example ' . $ex['output_hex']);
}

// ── Identities ─────────────────────────────────────────────────────────────
$ids = [];
foreach ($doc['identities'] as $name => $id) {
    $seed = (string) hex2bin($id['ed25519_private_seed_hex']);
    $edKeypair = sodium_crypto_sign_seed_keypair($seed);
    $edPub = sodium_crypto_sign_publickey($edKeypair);
    if ($id['x25519_private_hex'] === null) {
        // The low-order identity: an all-zero X25519 half and no private X25519 key.
        $xPrv = null;
        $xPub = str_repeat("\0", 32);
        $expect($id['x25519_public_hex'] === bin2hex($xPub), "identity {$name}: all-zero X25519 half");
    } else {
        $xPrv = (string) hex2bin($id['x25519_private_hex']);
        $xPub = sodium_crypto_scalarmult_base($xPrv);
        $expect($id['private_key_hex'] === $id['x25519_private_hex'] . $id['ed25519_private_seed_hex'], "identity {$name}: private key layout");
    }
    $pub = $xPub . $edPub;
    $expect(bin2hex($pub) === $id['public_key_hex'], "identity {$name}: public key from private key");
    $expect(bin2hex(substr(hash('sha256', $pub, true), 0, 16)) === $id['identity_hash_hex'], "identity {$name}: identity hash");
    $ids[$name] = [
        'x_prv' => $xPrv,
        'x_pub' => $xPub,
        'ed_sk' => sodium_crypto_sign_secretkey($edKeypair),
        'hash' => (string) hex2bin($id['identity_hash_hex']),
    ];
}

// ── Relays ─────────────────────────────────────────────────────────────────
$relays = [];
foreach ($doc['relays'] as $r => $relay) {
    $relays[$r] = [
        'secret' => (string) hex2bin($relay['relay_secret_hex']),
        'host' => $relay['host'],
        'transit_identities' => $relay['transit_identities'],
    ];
    $expect(preg_match(AUDIENCE_PATTERN, $relay['host']) === 1, "relay {$r}: host is a valid audience");
}
$expect(in_array(bin2hex($ids['gateway']['hash']), $relays['A']['transit_identities'], true), 'relay A lists the gateway');

// ── Challenges ─────────────────────────────────────────────────────────────
foreach ($doc['challenges'] as $c) {
    $h = (string) hex2bin($c['identity_hash_hex']);
    $nonce = (string) hex2bin($c['nonce_hex']);
    $input = CHALLENGE_DOMAIN . $h . u64($c['registration_seq_bound']) . $nonce;
    $mac = challengeMac($relays[$c['minted_by_relay']]['secret'], $h, $c['registration_seq_bound'], $nonce);
    $expect(bin2hex($input) === $c['mac_input_hex'], "challenge {$c['id']}: MAC input");
    $expect(bin2hex($mac) === $c['mac_hex'], "challenge {$c['id']}: MAC");
    $expect(bin2hex($nonce . $mac) === $c['challenge_hex'], "challenge {$c['id']}: layout nonce || mac (48 bytes)");
    $expect($h === $ids[$c['for_identity']]['hash'], "challenge {$c['id']}: identity");
    $expect(!array_key_exists('registration_seq', $c['challenge_response']), "challenge {$c['id']}: the response does not reveal the seq");
    $expect($c['challenge_response']['challenge'] === $c['challenge_hex'], "challenge {$c['id']}: response carries the challenge");
}

// ── Positive registrations ─────────────────────────────────────────────────
foreach ($doc['registrations'] as $v) {
    $id = $v['id'];
    $body = $v['request_body'];
    $msg = signedBytes($body);
    $expect(bin2hex($msg) === $v['signed_bytes_hex'], "{$id}: signed bytes rebuilt from the body");
    $joined = '';
    $names = [];
    foreach ($v['signed_fields'] as $f) {
        $expect(bin2hex(lp((string) hex2bin($f['value_hex']))) === $f['lp_hex'], "{$id}: lp of {$f['name']}");
        $joined .= (string) hex2bin($f['lp_hex']);
        $names[] = $f['name'];
    }
    $expect($names === $doc['constants']['signed_field_order'], "{$id}: signed field order");
    $expect($joined === $msg, "{$id}: signed_fields concatenate to the signed bytes");
    $expect(bin2hex(sodium_crypto_sign_detached($msg, $ids[$v['identity']]['ed_sk'])) === $v['signature_hex'], "{$id}: deterministic Ed25519 signature reproduced by sodium");

    $result = verifySigned($body, $relays[$v['relay']], $v['relay_state_before']);
    $expect($result['status'] === 200, "{$id}: reference verifier accepts (got " . json_encode($result) . ')');
    $expect(($result['identity_hash'] ?? '') === $v['expected']['identity_hash'], "{$id}: derived identity hash");
    $expect(($result['registration_seq'] ?? -1) === $v['expected']['relay_state_after']['row_registration_seq'], "{$id}: new seq");

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
    foreach (['session_token', 'peer_interface_id', 'peer_session_token', 'registration_seq'] as $k) {
        $expect(!array_key_exists($k, $v['response_example']), "{$id}: response example carries no {$k}");
    }
    $pt = decryptToken((string) hex2bin($t['session_token_encrypted_hex']), $ids[$v['identity']]['x_prv'], $ids[$v['identity']]['hash']);
    $expect($pt === $t['plaintext_utf8'] && preg_match('/\A[0-9a-f]{64}\z/', (string) $pt) === 1, "{$id}: token decrypts to a 64-hex session token");
}

// ── Negative registrations ─────────────────────────────────────────────────
foreach ($doc['negative'] as $v) {
    $result = verifySigned($v['request_body'], $relays[$v['relay']], $v['relay_state_before']);
    $expect(
        $result['status'] === $v['expected']['status']
            && ($result['error'] ?? null) === $v['expected']['error']
            && ($result['step'] ?? null) === $v['fails_check'],
        "negative {$v['id']}: expected {$v['expected']['status']} {$v['expected']['error']} at {$v['fails_check']}, got " . json_encode($result)
    );
}

// ── Token negatives ────────────────────────────────────────────────────────
foreach ($doc['tokens_negative'] as $v) {
    $pt = decryptToken((string) hex2bin($v['session_token_encrypted_hex']), $ids[$v['identity']]['x_prv'], $ids[$v['identity']]['hash']);
    $expect($pt === null, "token negative {$v['id']}: must not decrypt");
}

// ── Canonical peer URLs and audiences ──────────────────────────────────────
foreach ($doc['url_canonical'] as $u) {
    [$canonical, $reason] = canonicalPeerUrl($u['input']);
    $expect($canonical === $u['canonical'] && $reason === $u['refused'], 'url ' . json_encode($u['input']) . ': got ' . json_encode([$canonical, $reason]));
    $key = $canonical === null ? null : hash('sha256', $canonical);
    $expect($key === $u['peer_url_key'], 'url ' . json_encode($u['input']) . ': peer_url_key');
}
foreach ($doc['audience_client'] as $a) {
    $expect(audienceFromBaseUrl($a['client_base_url']) === $a['audience'], 'client audience for ' . $a['client_base_url']);
}
foreach ($doc['audience_relay'] as $a) {
    $expect(audienceFromHostHeader($a['host_header'], $a['scheme']) === $a['audience'], 'relay audience for ' . $a['host_header']);
}

if ($failures !== []) {
    fwrite(STDERR, "FAIL: " . count($failures) . " of {$checks} checks\n");
    foreach ($failures as $f) {
        fwrite(STDERR, "  - {$f}\n");
    }
    exit(1);
}

printf("PASS: %d checks (%d registrations, %d negative, %d token negatives, %d URLs, %d audiences) with PHP %s sodium/openssl\n",
    $checks, count($doc['registrations']), count($doc['negative']), count($doc['tokens_negative']),
    count($doc['url_canonical']), count($doc['audience_client']) + count($doc['audience_relay']), PHP_VERSION);
exit(0);
