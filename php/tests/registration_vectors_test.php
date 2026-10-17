<?php
/**
 * REGISTRATION-STAGE1.md §15: the browser vectors, through the PHP node's own
 * code.
 *
 * php/tests/vectors/registration_vectors.json (format 6) is made by
 * tools/registration_vectors.py from RNS 1.5.2 and checked by
 * tools/check_registration_vectors.php, each with its own reference verifier.
 * Those prove the file. This proves the PHP node: each Stage 1 registration
 * and negative vector goes through Storage::registerFromBody(), the function
 * POST /v1/interfaces/register calls, with node A's secret in
 * transport_state and the identity's signed row at the vector's count; each
 * challenge through the MAC the challenge route mints and §4.3 step 6
 * checks; each pinned token through the real encryption, byte for byte.
 * Stage 2's vectors (the gateway and PHP-node registrations and negatives,
 * registration-capacity, url_canonical, gateway_confirm, php_relay_peer) are
 * skipped, each by name; since 2026-10-16 the gateway and PHP-node
 * registrations and their negatives run in signed_peer_registration_test.php.
 *
 * Before Stage 1 none of this exists: registerInterface() takes the body's
 * metadata on trust and answers every negative 200 with a plaintext token.
 *
 * Run: php php/tests/registration_vectors_test.php
 */
declare(strict_types=1);

require_once dirname(__DIR__) . '/src/index.php';
require_once __DIR__ . '/stubs/registration_fixture.php';

use ReticulumPhp\ApiError;
use ReticulumPhp\RegistrationProtocol as P;
use ReticulumPhp\Storage;

const VECTORS_SHA256 = '7d2bcfee1742a6421a05e2b212c04182cc94247d53128ad91d35139fb07304ef';

// §15: what Stage 1 pins. Everything else in the file is Stage 2's.
const STAGE1_IDENTITIES = ['browser', 'other', 'lowx', 'gateway'];
const STAGE1_CHALLENGE_IDENTITIES = ['browser', 'other', 'lowx'];
const STAGE1_REGISTRATIONS = ['browser-first', 'browser-reregister'];
const STAGE1_NEGATIVES = [
    'tampered-name', 'tampered-bitrate', 'wrong-key-signature', 'replay-after-success', 'other-relay-mac',
    'challenge-for-other-identity', 'altered-challenge-nonce', 'identity-hash-mismatch', 'unsigned-metadata',
    'uppercase-public-key', 'browser-transit-mode', 'browser-with-peer-url', 'unknown-client', 'low-order-x25519-key',
];

$pass = 0;
$fail = 0;
function check(string $label, bool $ok, string $detail = ''): void
{
    global $pass, $fail;
    if ($ok) {
        $pass++;
        echo "  ok   $label\n";
    } else {
        $fail++;
        echo "  FAIL $label" . ($detail !== '' ? "\n         $detail" : '') . "\n";
    }
}

function skipped(string $what): void
{
    echo "  skip $what (Stage 2)\n";
}

check('the vector file is the pinned one (format 6, SHA-256 ' . substr(VECTORS_SHA256, 0, 12) . '…)',
    hash_file('sha256', RegFixture::VECTORS) === VECTORS_SHA256 && (RegFixture::vectors()['format_version'] ?? null) === 6);
$doc = RegFixture::vectors();
$secretA = (string) hex2bin($doc['relays']['A']['relay_secret_hex']);
$secrets = ['A' => $secretA, 'B' => (string) hex2bin($doc['relays']['B']['relay_secret_hex'])];

/**
 * Node A as a vector's relay_state_before describes it: its secret, and the
 * identity's signed row at the given count.
 */
function nodeA(array $state, array $body, string $secretA): Storage
{
    $storage = RegFixture::storage();
    $db = RegFixture::db($storage);
    $db->prepare('INSERT INTO transport_state (state_key, state_value, updated_at) VALUES (:k, :v, 0)')
        ->execute([':k' => 'registration_challenge_secret_hex', ':v' => bin2hex($secretA)]);
    if ($state['signed_row_exists']) {
        $pub = strtolower((string) $body['registration']['public_key']);
        $db->prepare(
            "INSERT INTO interfaces (interface_id, name, session_token, bitrate, mtu, status, metadata_json, created_at, last_seen_at,
                                     identity_hash, identity_public_key, registration_seq, registration_proof)
             VALUES (:id, 'seeded', :token, 1000000, 500, 'online', :md, 1, 1, :h, :pub, :seq, 'signed')"
        )->execute([
            ':id' => 'seeded' . str_repeat('0', 26), ':token' => 'seeded-token-' . bin2hex(random_bytes(26)),
            ':md' => '{"client":"rns-js","implementation":"PostInterface","mode":1}',
            ':h' => bin2hex(P::identityHash((string) hex2bin($pub))), ':pub' => $pub, ':seq' => $state['row_registration_seq'],
        ]);
    }

    return $storage;
}

/** Every row of every table a registration touches, for "nothing was written". */
function snapshot(Storage $storage): string
{
    $db = RegFixture::db($storage);
    $out = [];
    foreach (['interfaces', 'transport_state', 'local_destinations', 'path_entries', 'outbound_packets'] as $table) {
        $out[$table] = $db->query("SELECT * FROM {$table} ORDER BY 1")->fetchAll(PDO::FETCH_ASSOC);
    }

    return json_encode($out);
}

function rowFor(Storage $storage, string $identityHashHex): ?array
{
    $st = RegFixture::db($storage)->prepare('SELECT * FROM interfaces WHERE identity_hash = :h');
    $st->execute([':h' => $identityHashHex]);
    $row = $st->fetch(PDO::FETCH_ASSOC);

    return is_array($row) ? $row : null;
}

echo "(1) lp, identities and challenges\n";
foreach ($doc['lp_examples'] as $ex) {
    $in = isset($ex['input_utf8']) ? $ex['input_utf8'] : (string) hex2bin($ex['input_hex']);
    check('lp example ' . $ex['output_hex'], bin2hex(P::lp($in)) === $ex['output_hex']);
}
foreach ($doc['identities'] as $name => $id) {
    if (!in_array($name, STAGE1_IDENTITIES, true)) {
        skipped("identity $name");
        continue;
    }
    check("identity $name: identity hash from the public key",
        bin2hex(P::identityHash((string) hex2bin($id['public_key_hex']))) === $id['identity_hash_hex']);
}
foreach ($doc['challenges'] as $c) {
    if (!in_array($c['for_identity'], STAGE1_CHALLENGE_IDENTITIES, true)) {
        skipped("challenge {$c['id']}");
        continue;
    }
    $h = (string) hex2bin($c['identity_hash_hex']);
    $nonce = (string) hex2bin($c['nonce_hex']);
    $secret = $secrets[$c['minted_by_relay']];
    check("challenge {$c['id']}: MAC", bin2hex(P::challengeMac($secret, $h, $c['registration_seq_bound'], $nonce)) === $c['mac_hex']);
    check("challenge {$c['id']}: nonce || MAC", bin2hex(P::mintChallenge($secret, $h, $c['registration_seq_bound'], $nonce)) === $c['challenge_hex']);
    check("challenge {$c['id']}: checks out at A exactly when A made it at that count",
        P::challengeVerifies($secretA, $h, $c['registration_seq_bound'], (string) hex2bin($c['challenge_hex'])) === ($c['minted_by_relay'] === 'A'));
    check("challenge {$c['id']}: fails at any other count",
        !P::challengeVerifies($secretA, $h, $c['registration_seq_bound'] + 1, (string) hex2bin($c['challenge_hex'])));
}

echo "\n(2) the challenge route (Storage::issueChallenge)\n";
foreach ($doc['challenges'] as $c) {
    // One per node-A identity and count; the longer ids repeat these for a negative.
    if ($c['minted_by_relay'] !== 'A' || substr_count($c['id'], '/') > 2 || !in_array($c['for_identity'], STAGE1_CHALLENGE_IDENTITIES, true)) {
        continue;
    }
    $identity = $doc['identities'][$c['for_identity']];
    $state = ['signed_row_exists' => $c['registration_seq_bound'] > 0, 'row_registration_seq' => $c['registration_seq_bound']];
    $storage = nodeA($state, ['registration' => ['public_key' => $identity['public_key_hex']]], $secretA);
    foreach (['public_key' => $identity['public_key_hex'], 'identity_hash' => $identity['identity_hash_hex']] as $field => $value) {
        $answer = $storage->issueChallenge([$field => $value]);
        check("[{$c['id']} by $field] the answer has exactly status, version, identity_hash, challenge (no count)",
            array_keys($answer) === array_keys($c['challenge_response']) && $answer['status'] === 'challenge' && $answer['version'] === 1,
            json_encode($answer));
        check("[{$c['id']} by $field] identity_hash is the identity's", $answer['identity_hash'] === $identity['identity_hash_hex']);
        check("[{$c['id']} by $field] the challenge is 48 bytes and binds the row's count ({$c['registration_seq_bound']})",
            P::isLowerHex($answer['challenge'], 96)
            && P::challengeVerifies($secretA, (string) hex2bin($identity['identity_hash_hex']), $c['registration_seq_bound'], (string) hex2bin($answer['challenge'])));
    }
}

echo "\n(3) the browser registrations, through registerFromBody()\n";
$seen = [];
foreach ($doc['registrations'] as $v) {
    $id = $v['id'];
    if (!in_array($id, STAGE1_REGISTRATIONS, true)) {
        skipped("registration $id");
        continue;
    }
    $seen[] = $id;
    $body = $v['request_body'];
    $identity = RegFixture::identity($v['identity']);
    check("[$id] signed bytes rebuilt by RegistrationProtocol::signedBytes", bin2hex(P::signedBytes($body)) === $v['signed_bytes_hex']);
    $joined = '';
    foreach ($v['signed_fields'] as $f) {
        $joined .= P::lp((string) hex2bin($f['value_hex']));
    }
    check("[$id] the field-by-field lp breakdown concatenates to them", bin2hex($joined) === $v['signed_bytes_hex']);
    check("[$id] the signature verifies over them with the identity's Ed25519 key",
        sodium_crypto_sign_verify_detached((string) hex2bin($v['signature_hex']), (string) hex2bin($v['signed_bytes_hex']), substr($identity['public_key'], 32, 32)));
    $t = $v['encrypted_token'];
    $pinned = P::encryptToken($t['plaintext_utf8'], $identity['public_key'], $identity['hash'],
        (string) hex2bin($t['ephemeral_private_hex']), (string) hex2bin($t['iv_hex']));
    check("[$id] the pinned encrypted token is reproduced byte for byte by RegistrationProtocol::encryptToken",
        bin2hex($pinned) === $t['session_token_encrypted_hex'] && strlen($pinned) === $t['length']);

    $storage = nodeA($v['relay_state_before'], $body, $secretA);
    $before = rowFor($storage, $v['expected']['identity_hash']);
    [$answer, $log] = RegFixture::capture(static fn () => $storage->registerFromBody($body));
    check("[$id] answered 200", is_array($answer), $answer instanceof ApiError ? json_encode($answer->payload) : '');
    if (!is_array($answer)) {
        continue;
    }
    check("[$id] the answer has exactly the keys of response_example, in order", array_keys($answer) === array_keys($v['response_example']),
        implode(',', array_keys($answer)));
    foreach (['session_token', 'registration_seq', 'peer_interface_id', 'peer_session_token'] as $k) {
        check("[$id] the answer carries no $k", !array_key_exists($k, $answer));
    }
    check("[$id] status, identity_hash and limits as the example", $answer['status'] === 'registered'
        && $answer['identity_hash'] === $v['expected']['identity_hash']
        && $answer['idle_exchange_interval_ms'] === $v['response_example']['idle_exchange_interval_ms']
        && $answer['max_batch_packets'] === $v['response_example']['max_batch_packets']
        && $answer['max_packet_bytes'] === $v['response_example']['max_packet_bytes'], json_encode($answer));
    check("[$id] session_token_encrypted is as long as the pinned one ({$t['length']} bytes)",
        strlen((string) hex2bin($answer['session_token_encrypted'])) === $t['length']);
    $after = rowFor($storage, $v['expected']['identity_hash']);
    check("[$id] the row's count is now {$v['expected']['relay_state_after']['row_registration_seq']}",
        (int) ($after['registration_seq'] ?? -1) === $v['expected']['relay_state_after']['row_registration_seq']);
    check("[$id] " . ($before === null ? 'a new row (INSERT)' : 're-bound in place: same interface_id, the old token\'s hash kept'),
        $before === null ? $after !== null && $after['previous_session_token_hash'] === null
            : $after['interface_id'] === $before['interface_id'] && $after['previous_session_token_hash'] === hash('sha256', $before['session_token']));
    check("[$id] the row is signed, keyed by H, with the registration's public key, and claims nothing",
        ($after['registration_proof'] ?? '') === 'signed' && ($after['identity_public_key'] ?? '') === $body['registration']['public_key']
        && $after['claimed_identity_hash'] === null);
    $token = RegFixture::decrypt($answer['session_token_encrypted'], $identity);
    check("[$id] session_token_encrypted decrypts, with the identity, to the row's 64-hex session token",
        is_string($token) && preg_match('/\A[0-9a-f]{64}\z/', $token) === 1 && hash_equals((string) $after['session_token'], $token));
    check("[$id] it decrypts to nothing for another identity", RegFixture::decrypt($answer['session_token_encrypted'], RegFixture::identity('other')) === null);
    $stored = json_decode((string) $after['metadata_json'], true);
    $want = array_intersect_key($body['metadata'], array_flip(['client', 'implementation', 'mode']));
    ksort($stored);
    ksort($want);
    check("[$id] metadata_json holds only client, implementation and mode", $stored === $want, (string) $after['metadata_json']);
    check("[$id] logged [REG-SIGNED] with H, and no token, challenge or signature",
        str_contains($log, '[REG-SIGNED] identity=' . $v['expected']['identity_hash'])
        && !str_contains($log, $token ?? 'no-token') && !str_contains($log, $body['registration']['signature'])
        && !str_contains($log, substr($body['registration']['challenge'], 0, 32)), trim($log));
    // The same body again: its challenge died when the count moved (§3).
    [$replay] = RegFixture::capture(static fn () => $storage->registerFromBody($body));
    check("[$id] the same body a second time is 409 stale_challenge (single use)", RegFixture::outcome($replay) === [409, 'stale_challenge']);
}
check('both browser registrations were found and run', $seen === STAGE1_REGISTRATIONS, implode(',', $seen));

echo "\n(4) the fourteen browser negatives, through registerFromBody(): each answer, and nothing written\n";
$codesByStep = [
    'shape' => 'bad_registration', 'metadata_keys' => 'unsigned_metadata', 'metadata_identity_hash' => 'identity_hash_mismatch',
    'challenge' => 'stale_challenge', 'signature' => 'bad_registration_signature', 'token_encryption' => 'bad_registration',
];
$seen = [];
foreach ($doc['negative'] as $v) {
    if (!in_array($v['id'], STAGE1_NEGATIVES, true)) {
        skipped("negative {$v['id']}");
        continue;
    }
    $seen[] = $v['id'];
    $storage = nodeA($v['relay_state_before'], $v['request_body'], $secretA);
    $before = snapshot($storage);
    [$answer, $log] = RegFixture::capture(static fn () => $storage->registerFromBody($v['request_body']));
    $got = RegFixture::outcome($answer);
    check("[{$v['id']}] {$v['expected']['status']} {$v['expected']['error']} (fails {$v['fails_check']})",
        $got === [$v['expected']['status'], $v['expected']['error']], json_encode($got));
    if (isset($codesByStep[$v['fails_check']])) {
        check("[{$v['id']}] the code is the one its step gives", $v['expected']['error'] === $codesByStep[$v['fails_check']]);
    }
    check("[{$v['id']}] nothing was written", snapshot($storage) === $before);
    check("[{$v['id']}] the body is {\"error\", \"message\"}", $answer instanceof ApiError && array_keys($answer->payload) === ['error', 'message']);
    check("[{$v['id']}] logged [REG-REFUSED] {$v['expected']['status']} {$v['expected']['error']}, and no signature or challenge",
        str_contains($log, "[REG-REFUSED] {$v['expected']['status']} {$v['expected']['error']} ")
        && !str_contains($log, (string) ($v['request_body']['registration']['signature'] ?? 'no-signature'))
        && !str_contains($log, substr((string) ($v['request_body']['registration']['challenge'] ?? 'no-challenge'), 0, 32)), trim($log));
}
sort($seen);
$want = STAGE1_NEGATIVES;
sort($want);
check('all fourteen were found and run', $seen === $want, implode(',', array_diff($want, $seen)));

echo "\n(5) token negatives: neither decrypts\n";
foreach ($doc['tokens_negative'] as $v) {
    check("token negative {$v['id']}", RegFixture::decrypt($v['session_token_encrypted_hex'], RegFixture::identity($v['identity'])) === null);
}

echo "\n(6) Stage 2's sections\n";
foreach (['url_canonical', 'gateway_confirm', 'php_relay_peer'] as $section) {
    if (array_key_exists($section, $doc)) {
        skipped("section $section");
    }
}

echo "\n$pass passed, $fail failed\n";
exit($fail === 0 ? 0 : 1);
