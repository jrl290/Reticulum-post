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
 * signature, re-derives every canonical peer URL, checks the gateway
 * wake-URL confirm (section 9.8) with its own gateway handler and relay
 * answer verifier, checks the PHP relay peer (section 10: identity file,
 * token decryption as the PHP client does it, confirm handler, link order),
 * and runs a
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
const REGISTRATION_KEYS = ['version', 'public_key', 'challenge', 'signature'];
const ALLOWED_METADATA_KEYS = ['client', 'implementation', 'mode', 'transport', 'peer_url', 'peer_interface_id', 'peer_session_token', 'identity_hash'];
const KNOWN_CLIENTS = ['rns-js', 'reticulum-php', 'rns-post-interface'];
const MAX_SAFE_INTEGER = 9007199254740991; // 2^53 - 1
const GATEWAY_CONFIRM_DOMAIN = 'reticulum-post/gateway-confirm/v1';
const GATEWAY_CONFIRM_PATH = '/v1/gateway/confirm';
const GATEWAY_CONFIRM_KEYS = ['version', 'nonce', 'identity_hash', 'relay_url', 'peer_url'];

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

/**
 * Reference verifier: REGISTRATION.md section 4.3, steps 1-8 (step 9, the
 * atomic bind, is a database property and is modelled by the row's seq).
 *
 * @param array{secret:string} $relay
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

    // 5. The challenge is this relay's, for this identity, at the row's current seq.
    $challenge = (string) hex2bin($reg['challenge']);
    if (!hash_equals(challengeMac($relay['secret'], $identityHash, $state['row_registration_seq'], substr($challenge, 0, 16)), substr($challenge, 16))) {
        return $bad(409, 'stale_challenge', 'challenge');
    }

    // 6. The signature.
    if (!sodium_crypto_sign_verify_detached((string) hex2bin($reg['signature']), signedBytes($body), substr($publicKey, 32, 32))) {
        return $bad(403, 'bad_registration_signature', 'signature');
    }

    // 7. Capacity, for a new row only.
    if ($state['row_registration_seq'] === 0 && $state['at_capacity']) {
        return $bad(503, 'registration_capacity', 'capacity');
    }

    // 8. A token must be encryptable to the X25519 half: sodium refuses an
    //    all-zero shared secret (a low-order point) by throwing.
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

/** Section 9.8: the five signed values of a gateway confirm, from the body as received. */
function gatewayConfirmBytes(array $body): string
{
    return lp(GATEWAY_CONFIRM_DOMAIN)
        . lp((string) hex2bin($body['nonce']))
        . lp((string) hex2bin($body['identity_hash']))
        . lp($body['relay_url'])
        . lp($body['peer_url']);
}

function boundedUtf8(mixed $v, int $maxBytes): bool
{
    return is_string($v) && $v !== '' && strlen($v) <= $maxBytes && mb_check_encoding($v, 'UTF-8');
}

/**
 * Section 9.8, the gateway's handler.
 *
 * @param array{node_url:string, wake_url:string} $cfg the gateway's config as written
 * @return array{status:int, error?:string, signature?:string}
 */
function gatewayHandleConfirm(mixed $body, string $ownHash, string $edSecretKey, array $cfg): array
{
    return handleConfirm($body, $ownHash, $edSecretKey, [canonicalPeerUrl($cfg['node_url'])[0]], canonicalPeerUrl($cfg['wake_url'])[0]);
}

/**
 * Section 10, a PHP relay's handler: it registers at every relay in its [interfaces].
 *
 * @param array{host_url:string, interfaces_node_urls:list<string>} $cfg
 * @return array{status:int, error?:string, signature?:string}
 */
function phpRelayHandleConfirm(mixed $body, string $ownHash, string $edSecretKey, array $cfg): array
{
    $relays = [];
    foreach ($cfg['interfaces_node_urls'] as $u) {
        [$c] = canonicalPeerUrl($u);
        if ($c !== null) {
            $relays[] = $c;
        }
    }
    return handleConfirm($body, $ownHash, $edSecretKey, $relays, canonicalPeerUrl($cfg['host_url'])[0]);
}

/**
 * Section 9.8's checks, in their normative order.
 *
 * @param list<string> $relayUrls canonical URLs of the relays this node registers at
 * @return array{status:int, error?:string, signature?:string}
 */
function handleConfirm(mixed $body, string $ownHash, string $edSecretKey, array $relayUrls, ?string $ownUrl): array
{
    if (!is_array($body)) {
        return ['status' => 400, 'error' => 'bad_confirm_request'];
    }
    $keys = array_keys($body);
    sort($keys);
    $want = GATEWAY_CONFIRM_KEYS;
    sort($want);
    if ($keys !== $want
        || ($body['version'] ?? null) !== 1
        || !isLowerHex($body['nonce'] ?? null, 32)
        || !isLowerHex($body['identity_hash'] ?? null, 32)
        || !boundedUtf8($body['relay_url'] ?? null, 512)
        || !boundedUtf8($body['peer_url'] ?? null, 512)
    ) {
        return ['status' => 400, 'error' => 'bad_confirm_request'];
    }
    if (!hash_equals(bin2hex($ownHash), $body['identity_hash'])) {
        return ['status' => 403, 'error' => 'not_my_identity'];
    }
    [$relay] = canonicalPeerUrl($body['relay_url']);
    if ($relay === null || !in_array($relay, $relayUrls, true)) {
        return ['status' => 403, 'error' => 'unknown_relay'];
    }
    [$peer] = canonicalPeerUrl($body['peer_url']);
    if ($peer === null || $ownUrl === null || $peer !== $ownUrl) {
        return ['status' => 403, 'error' => 'not_my_wake_url'];
    }
    return ['status' => 200, 'signature' => bin2hex(sodium_crypto_sign_detached(gatewayConfirmBytes($body), $edSecretKey))];
}

/**
 * Section 9.8, the relay's runner after its POST.
 *
 * @return array{result:string, reason?:string}
 */
function relayVerifyConfirmAnswer(array $sent, int $status, mixed $answer, string $publicKey): array
{
    if ($status !== 200) {
        return ['result' => 'bad_answer', 'reason' => 'status'];
    }
    if (!is_array($answer) || array_keys($answer) !== ['signature'] || !isLowerHex($answer['signature'], 128)) {
        return ['result' => 'bad_answer', 'reason' => 'shape'];
    }
    if (!sodium_crypto_sign_verify_detached((string) hex2bin($answer['signature']), gatewayConfirmBytes($sent), substr($publicKey, 32, 32))) {
        return ['result' => 'bad_signature'];
    }
    return ['result' => 'confirmed'];
}

/**
 * Section 10.4: the PHP client's decrypt of session_token_encrypted, with the
 * reason it refuses. sodium X25519 (an all-zero result throws), hash_hkdf,
 * HMAC-SHA256 checked with hash_equals before decrypting, openssl AES-256-CBC.
 *
 * @return array{result:string, session_token?:string}
 */
function clientDecrypt(string $blob, string $x25519Private, string $identityHash): array
{
    $ctLen = strlen($blob) - 32 - 16 - 32;
    if ($ctLen < 16 || $ctLen % 16 !== 0) {
        return ['result' => 'malformed'];
    }
    try {
        $shared = sodium_crypto_scalarmult($x25519Private, substr($blob, 0, 32));
    } catch (\SodiumException) {
        return ['result' => 'zero_shared_secret'];
    }
    if (hash_equals(str_repeat("\0", 32), $shared)) {
        return ['result' => 'zero_shared_secret'];
    }
    $derived = hash_hkdf('sha256', $shared, 64, '', $identityHash);
    $iv = substr($blob, 32, 16);
    $ct = substr($blob, 48, $ctLen);
    if (!hash_equals(hash_hmac('sha256', $iv . $ct, substr($derived, 0, 32), true), substr($blob, -32))) {
        return ['result' => 'hmac'];
    }
    $pt = openssl_decrypt($ct, 'aes-256-cbc', substr($derived, 32, 32), OPENSSL_RAW_DATA, $iv);
    if (!is_string($pt)) {
        return ['result' => 'padding'];
    }
    if (preg_match('/\A[0-9a-f]{64}\z/', $pt) !== 1) {
        return ['result' => 'not_a_token'];
    }
    return ['result' => 'ok', 'session_token' => $pt];
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
$expect($doc['format_version'] === 5, 'format 5 (revision 3: no audience; revision 4: the gateway confirm; revision 6: the PHP relay peer)');
$expect($doc['constants']['signed_field_order'] === ['domain', 'challenge', 'public_key', 'name', 'bitrate', 'mtu', 'client', 'mode', 'transport', 'peer_url', 'peer_interface_id', 'peer_session_token'], 'the twelve signed fields, in order');
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
    $relays[$r] = ['secret' => (string) hex2bin($relay['relay_secret_hex'])];
    // Revision 3: a relay is configured by its secret alone. No host to bind
    // (no audience) and no list of transit identities (peering is open).
    $expect(array_keys($relay) === ['relay_secret_hex', 'description'], "relay {$r}: carries only its secret");
}

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

// ── Canonical peer URLs ────────────────────────────────────────────────────
foreach ($doc['url_canonical'] as $u) {
    [$canonical, $reason] = canonicalPeerUrl($u['input']);
    $expect($canonical === $u['canonical'] && $reason === $u['refused'], 'url ' . json_encode($u['input']) . ': got ' . json_encode([$canonical, $reason]));
    $key = $canonical === null ? null : hash('sha256', $canonical);
    $expect($key === $u['peer_url_key'], 'url ' . json_encode($u['input']) . ': peer_url_key');
}
// ── The gateway wake-URL confirm (section 9.8) ─────────────────────────────
$gc = $doc['gateway_confirm'] ?? null;
$expect(is_array($gc), 'gateway confirm: section present');
if (is_array($gc)) {
    $expect($gc['domain'] === GATEWAY_CONFIRM_DOMAIN && $gc['domain_hex'] === bin2hex(GATEWAY_CONFIRM_DOMAIN), 'gateway confirm: domain');
    $expect($gc['path'] === GATEWAY_CONFIRM_PATH && !str_starts_with($gc['path'], '/v1/wake'), 'gateway confirm: path, not under /v1/wake');
    $expect($gc['signed_field_order'] === ['domain', 'nonce', 'identity_hash', 'relay_url', 'peer_url'], 'gateway confirm: the five signed fields, in order');
    $gwName = $gc['gateway']['identity'];
    $gwCfg = $gc['gateway']['config'];
    $gwPub = (string) hex2bin($doc['identities'][$gwName]['public_key_hex']);
    $pos = $gc['positive'];
    $sent = $pos['request_body'];
    // The URL confirmed is the one the gateway-wake row stores, and the confirm goes there and nowhere else.
    $wakeRow = null;
    foreach ($doc['registrations'] as $v) {
        if ($v['id'] === 'gateway-wake') {
            $wakeRow = $v;
        }
    }
    [$storedPeerUrl] = canonicalPeerUrl($wakeRow['request_body']['metadata']['peer_url'] ?? null);
    $expect($storedPeerUrl !== null && $pos['row']['peer_url'] === $storedPeerUrl && $sent['peer_url'] === $storedPeerUrl, 'gateway confirm: names the stored canonical peer_url');
    $expect($pos['row']['peer_url_key'] === hash('sha256', (string) $storedPeerUrl), 'gateway confirm: the row key');
    $expect($pos['request_url'] === $storedPeerUrl . GATEWAY_CONFIRM_PATH, 'gateway confirm: sent only to the stored URL');
    $expect($sent['identity_hash'] === bin2hex($ids[$gwName]['hash']) && $sent['relay_url'] === $gc['relay_url'], 'gateway confirm: identity and relay');
    $msg = gatewayConfirmBytes($sent);
    $expect(bin2hex($msg) === $pos['signed_bytes_hex'], 'gateway confirm: signed bytes rebuilt from the body');
    $joined = '';
    $names = [];
    foreach ($pos['signed_fields'] as $f) {
        $expect(bin2hex(lp((string) hex2bin($f['value_hex']))) === $f['lp_hex'], "gateway confirm: lp of {$f['name']}");
        $joined .= (string) hex2bin($f['lp_hex']);
        $names[] = $f['name'];
    }
    $expect($names === $gc['signed_field_order'] && $joined === $msg, 'gateway confirm: signed_fields concatenate to the signed bytes');
    $handled = gatewayHandleConfirm($sent, $ids[$gwName]['hash'], $ids[$gwName]['ed_sk'], $gwCfg);
    $expect($handled === ['status' => 200, 'signature' => $pos['signature_hex']], 'gateway confirm: the reference gateway signs it, reproduced by sodium (got ' . json_encode($handled) . ')');
    $expect($pos['response_body'] === ['signature' => $pos['signature_hex']], 'gateway confirm: response body');
    $expect(relayVerifyConfirmAnswer($sent, 200, $pos['response_body'], $gwPub) === $pos['expected_relay'], 'gateway confirm: the relay accepts the answer');
    foreach ($gc['gateway_refusals'] as $r) {
        $got = gatewayHandleConfirm($r['request_body'], $ids[$gwName]['hash'], $ids[$gwName]['ed_sk'], $gwCfg);
        $expect($got === $r['expected'], "gateway refusal {$r['id']}: expected " . json_encode($r['expected']) . ', got ' . json_encode($got));
    }
    foreach ($gc['answer_negative'] as $a) {
        $got = relayVerifyConfirmAnswer($sent, $a['answer_status'], $a['answer_body'], $gwPub);
        $expect($got === $a['expected'], "confirm answer {$a['id']}: expected " . json_encode($a['expected']) . ', got ' . json_encode($got));
    }
}

// ── The PHP relay peer (section 10) ────────────────────────────────────────
$pr = $doc['php_relay_peer'] ?? null;
$expect(is_array($pr), 'php relay peer: section present');
if (is_array($pr)) {
    $rbName = $pr['identity'];
    $file = (string) hex2bin($pr['identity_file_hex']);
    $expect(strlen($file) === 64, 'php relay peer: the identity file is 64 bytes');
    $rbXPrv = substr($file, 0, 32);
    $rbKeypair = sodium_crypto_sign_seed_keypair(substr($file, 32, 32));
    $rbPub = sodium_crypto_scalarmult_base($rbXPrv) . sodium_crypto_sign_publickey($rbKeypair);
    $rbHash = substr(hash('sha256', $rbPub, true), 0, 16);
    $expect(bin2hex($rbHash) === $pr['identity_hash_hex'] && $doc['identities'][$rbName]['public_key_hex'] === bin2hex($rbPub), 'php relay peer: identity file -> public key -> identity hash');
    $rbReg = null;
    foreach ($doc['registrations'] as $v) {
        if ($v['id'] === $pr['registration_id']) {
            $rbReg = $v;
        }
    }
    $expect(is_array($rbReg) && $rbReg['identity'] === $rbName, 'php relay peer: its registration vector exists');
    if (is_array($rbReg)) {
        $md = $rbReg['request_body']['metadata'];
        [$hostCanon] = canonicalPeerUrl($pr['config']['host_url']);
        $expect($md['client'] === 'reticulum-php' && $md['mode'] === 1 && $md['peer_url'] === $hostCanon, 'php relay peer: registers as reticulum-php, mode 1, peer_url = its canonical host_url');
        $expect(($rbReg['request_body']['registration']['public_key'] ?? '') === bin2hex($rbPub), 'php relay peer: signs with the identity file\'s key');
    }
    $dw = $pr['decrypt'];
    $blob = (string) hex2bin($dw['session_token_encrypted_hex']);
    $expect(bin2hex(substr($blob, 0, 32)) === $dw['ephemeral_public_hex'] && bin2hex(substr($blob, 32, 16)) === $dw['iv_hex']
        && bin2hex(substr($blob, 48, -32)) === $dw['ciphertext_hex'] && bin2hex(substr($blob, -32)) === $dw['hmac_hex'], 'php relay peer: blob layout');
    $shared = sodium_crypto_scalarmult($rbXPrv, substr($blob, 0, 32));
    $derived = hash_hkdf('sha256', $shared, 64, '', $rbHash);
    $expect(bin2hex($shared) === $dw['shared_key_hex'] && bin2hex($derived) === $dw['derived_key_hex']
        && bin2hex(substr($derived, 0, 32)) === $dw['hmac_key_hex'] && bin2hex(substr($derived, 32)) === $dw['aes_key_hex']
        && $dw['hkdf_salt_hex'] === bin2hex($rbHash), 'php relay peer: shared, derived, HMAC and AES keys');
    $expect(clientDecrypt($blob, $rbXPrv, $rbHash) === $dw['expected'], 'php relay peer: the PHP client decrypts its token');
    foreach ($pr['decrypt_negative'] as $d) {
        $got = clientDecrypt((string) hex2bin($d['session_token_encrypted_hex']), $rbXPrv, $rbHash);
        $expect($got === $d['expected'], "php relay decrypt {$d['id']}: expected " . json_encode($d['expected']) . ', got ' . json_encode($got));
    }
    $c = $pr['confirm'];
    $expect($c['request_url'] === $hostCanon . GATEWAY_CONFIRM_PATH && $c['request_body']['peer_url'] === $hostCanon, 'php relay confirm: sent only to its canonical host_url');
    $cmsg = gatewayConfirmBytes($c['request_body']);
    $expect(bin2hex($cmsg) === $c['signed_bytes_hex'], 'php relay confirm: signed bytes');
    $joined = '';
    foreach ($c['signed_fields'] as $f) {
        $joined .= (string) hex2bin($f['lp_hex']);
    }
    $expect($joined === $cmsg, 'php relay confirm: signed_fields concatenate to the signed bytes');
    $rbSk = sodium_crypto_sign_secretkey($rbKeypair);
    $expect(phpRelayHandleConfirm($c['request_body'], $rbHash, $rbSk, $pr['config']) === ['status' => 200, 'signature' => $c['signature_hex']], 'php relay confirm: its handler signs it');
    $expect(relayVerifyConfirmAnswer($c['request_body'], 200, $c['response_body'], $rbPub) === $c['expected_relay'], 'php relay confirm: the relay accepts the answer');
    foreach ($pr['confirm_refusals'] as $r) {
        $got = phpRelayHandleConfirm($r['request_body'], $rbHash, $rbSk, $pr['config']);
        $expect($got === $r['expected'], "php relay refusal {$r['id']}: expected " . json_encode($r['expected']) . ', got ' . json_encode($got));
    }
    foreach ($pr['confirm_answer_negative'] as $a) {
        $got = relayVerifyConfirmAnswer($c['request_body'], $a['answer_status'], $a['answer_body'], $rbPub);
        $expect($got === $a['expected'], "php relay answer {$a['id']}: expected " . json_encode($a['expected']) . ', got ' . json_encode($got));
    }
    foreach ($pr['link_order'] as $l) {
        [$c1] = canonicalPeerUrl($l['relay_1']);
        [$c2] = canonicalPeerUrl($l['relay_2']);
        $first = strcmp((string) $c1, (string) $c2) < 0 ? $c1 : $c2;
        $second = $first === $c1 ? $c2 : $c1;
        $expect($c1 === $l['canonical_1'] && $c2 === $l['canonical_2'] && $l['link_is_registration_of'] === $first && $l['stands_down'] === $second,
            'php relay link order: ' . $l['note']);
    }
}

// Revision 3: nothing in the file carries an audience.
$expect(!str_contains((string) file_get_contents($path), 'audience'), 'no vector carries an audience');

if ($failures !== []) {
    fwrite(STDERR, "FAIL: " . count($failures) . " of {$checks} checks\n");
    foreach ($failures as $f) {
        fwrite(STDERR, "  - {$f}\n");
    }
    exit(1);
}

printf("PASS: %d checks (%d registrations, %d negative, %d token negatives, %d URLs, gateway confirm: 1 positive, %d refusals, %d answer negatives; php relay peer: %d decrypt negatives, %d confirm refusals, %d link orders) with PHP %s sodium/openssl\n",
    $checks, count($doc['registrations']), count($doc['negative']), count($doc['tokens_negative']),
    count($doc['url_canonical']), count($gc['gateway_refusals'] ?? []), count($gc['answer_negative'] ?? []),
    count($pr['decrypt_negative'] ?? []), count($pr['confirm_refusals'] ?? []), count($pr['link_order'] ?? []), PHP_VERSION);
exit(0);
