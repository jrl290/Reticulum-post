<?php
/**
 * A bidirectional peer and a poll-mode gateway sign the registration every
 * client already sends. James, 2026-10-16: "The gateway should use the same
 * negotiation as any other bidirectional peer."
 *
 * Stage 1 (REGISTRATION-STAGE1.md) let only a browser (client rns-js) sign: a
 * signed reticulum-php or rns-post-interface got 400 unknown_client, and an
 * unsigned registration naming a peer's peer_url took over that peer's row
 * (registerInterface's re-bind by peer_url). Here, against the real Storage
 * (SQLite):
 *
 *   (1) the vectors gateway-wake (reticulum-php, mode 6, its row at count 5),
 *       php-relay-peer and gateway-poll (rns-post-interface, its transport)
 *       through registerFromBody(): 200, the token only encrypted, the row
 *       signed and keyed by H; a reticulum-php row holds peer_url,
 *       peer_interface_id and peer_session_token, a poll-mode row none; the
 *       peer negatives (a tampered peer_url or peer_session_token 403, an old
 *       challenge 409) and client "x" (400 unknown_client) write nothing
 *   (2) the rules each client's unsigned registration has today, no more:
 *       a signed reticulum-php without peer fields and a signed
 *       rns-post-interface with a peer_url are accepted as their unsigned
 *       registrations are (REGISTRATION.md's peer_fields_required and its
 *       poll-mode metadata_not_allowed are not adopted); rns-js's rules are
 *       unchanged; any other client is 400 unknown_client
 *   (3) a signed peer row is woken and exchanged exactly like an unsigned
 *       one: its token authenticates, it is a PHP peer, the lookup by
 *       peer_url finds its credentials, it carries other identities'
 *       announces, dispatchWakes() wakes it, exchangeWithPhpPeer() sends its
 *       peer credentials to its peer_url
 *   (4) an unsigned registration naming a signed row's peer_url gets what it
 *       would get if no signed row had that peer_url: a row of its own (or
 *       the unsigned row with that peer_url, re-bound), 200 and a plaintext
 *       token. The signed row is not touched.
 *   (5) the signed peer re-registers with its own key: its own row, re-bound
 *       in place with the fields it signed
 *   (6) a gateway's first signed registration removes its old unsigned row
 *       (the unsigned rows at its peer_url, in either stored form) with its
 *       queue, and nothing at another peer_url; its next signed
 *       registration removes one made since; the lookup and
 *       exchangeWithPhpPeer() then take the signed row
 *   (6b) two rows with one peer_url (an unsigned one made after the signed
 *       bind): phpPeerInterfaceByPeerUrl() takes the row seen most
 *       recently, not "signed first", so a signed registration naming a PHP
 *       peer's URL does not shadow the peer's own, more recently seen, row
 *   (7) /health's browsers_online counts browsers only: signed gateways and
 *       peers online leave it at 0, a signed browser makes it 1
 *
 * Nothing leaves the process: curl and sockets are recorded, not sent.
 *
 * Run: php php/tests/signed_peer_registration_test.php
 */
declare(strict_types=1);

namespace ReticulumPhp;

require_once dirname(__DIR__) . '/src/index.php';
require_once __DIR__ . '/stubs/registration_fixture.php';
require_once __DIR__ . '/stubs/announce_fixture.php';

use PDO;
use RegFixture;
use AnnounceFixture;

// ── Every way out of the process, recorded and not sent ─────────────────

final class Sent
{
    /** @var list<array{via: string, url: string, body: string}> */
    public static array $requests = [];

    /** What a peer answers to an exchange: nothing to deliver. */
    public const EXCHANGE_ANSWER = '{"status":"ok","delivery_packets":[],"delivery_batch_id":null}';
}

function curl_init(?string $url = null): \stdClass
{
    $handle = new \stdClass();
    $handle->url = (string) $url;
    $handle->body = '';

    return $handle;
}

function curl_setopt(\stdClass $handle, int $option, mixed $value): bool
{
    if ($option === \CURLOPT_POSTFIELDS) {
        $handle->body = (string) $value;
    }

    return true;
}

function curl_exec(\stdClass $handle): string
{
    Sent::$requests[] = ['via' => 'curl', 'url' => $handle->url, 'body' => $handle->body];

    return Sent::EXCHANGE_ANSWER;
}

function curl_getinfo(\stdClass $handle, ?int $option = null): mixed
{
    return 200;
}

function curl_close(\stdClass $handle): void
{
}

/** @return resource|false */
function stream_socket_client(string $address, &$errorCode = null, &$errorMessage = null, ?float $timeout = null, int $flags = 0, mixed $context = null): mixed
{
    Sent::$requests[] = ['via' => 'socket', 'url' => $address, 'body' => ''];
    $errorCode = 0;
    $errorMessage = 'recorded by the test, not sent';

    return false;
}

// ── Helpers ─────────────────────────────────────────────────────────────

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

/** A PHP node that can wake (dispatchWakes needs its own host_url). */
function node(): Storage
{
    $storage = new Storage(RegFixture::config() + ['host_url' => 'https://node-a.example/reticulum']);
    $storage->migrateIfNeeded();

    return $storage;
}

function rowById(Storage $s, string $id): ?array
{
    $st = RegFixture::db($s)->prepare('SELECT * FROM interfaces WHERE interface_id = :i');
    $st->execute([':i' => $id]);
    $row = $st->fetch(PDO::FETCH_ASSOC);

    return is_array($row) ? $row : null;
}

function rowFor(Storage $s, string $identityHashHex): ?array
{
    $st = RegFixture::db($s)->prepare('SELECT * FROM interfaces WHERE identity_hash = :h');
    $st->execute([':h' => $identityHashHex]);
    $row = $st->fetch(PDO::FETCH_ASSOC);

    return is_array($row) ? $row : null;
}

/** Every row of every table, for "nothing was written". */
function everything(Storage $s): string
{
    $db = RegFixture::db($s);
    $out = [];
    foreach ($db->query("SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%' ORDER BY name")->fetchAll(PDO::FETCH_COLUMN) as $t) {
        $out[$t] = $db->query("SELECT * FROM {$t} ORDER BY 1")->fetchAll(PDO::FETCH_ASSOC);
    }

    return (string) json_encode($out);
}

function authenticates(Storage $s, string $id, string $token): array
{
    try {
        $s->authenticateInterface($id, $token);

        return [200, null];
    } catch (ApiError $error) {
        return RegFixture::outcome($error);
    }
}

/** The peer columns of a row, as the wake and exchange code reads them. */
function peerColumns(?array $row): array
{
    return [$row['peer_url'] ?? null, $row['peer_interface_id'] ?? null, $row['peer_session_token'] ?? null];
}

/**
 * Node A as a vector's relay_state_before says: A's secret in
 * transport_state, and, at the vector's count, the identity's signed row as
 * its last registration left it: client reticulum-php, mode 6, its old peer
 * credentials.
 */
function nodeA(array $state, string $publicKeyHex): Storage
{
    $storage = node();
    $db = RegFixture::db($storage);
    $db->prepare('INSERT INTO transport_state (state_key, state_value, updated_at) VALUES (:k, :v, 0)')
        ->execute([':k' => 'registration_challenge_secret_hex', ':v' => RegFixture::vectors()['relays']['A']['relay_secret_hex']]);
    if ($state['signed_row_exists']) {
        $db->prepare(
            "INSERT INTO interfaces (interface_id, name, session_token, bitrate, mtu, status, metadata_json, created_at, last_seen_at,
                                     identity_hash, identity_public_key, registration_seq, registration_proof,
                                     peer_url, peer_interface_id, peer_session_token)
             VALUES (:id, 'seeded', :token, 10000000, 500, 'online', :md, 1, 1, :h, :pub, :seq, 'signed', :peer_url, :peer_id, :peer_token)"
        )->execute([
            ':id' => 'seeded' . str_repeat('0', 26), ':token' => 'seeded-token-' . bin2hex(random_bytes(26)),
            ':md' => '{"client":"reticulum-php","implementation":"PostInterface","mode":6}',
            ':h' => bin2hex(RegistrationProtocol::identityHash((string) hex2bin($publicKeyHex))), ':pub' => $publicKeyHex,
            ':seq' => $state['row_registration_seq'],
            ':peer_url' => 'http://gateway.example.net:4371', ':peer_id' => 'old-peer-interface-id', ':peer_token' => 'old-peer-session-token',
        ]);
    }

    return $storage;
}

/** The vector with this id, from any list. */
function vector(string $id): array
{
    foreach (['registrations', 'negative'] as $list) {
        foreach (RegFixture::vectors()[$list] as $v) {
            if ($v['id'] === $id) {
                return $v;
            }
        }
    }
    throw new \RuntimeException("no vector $id");
}

/** Register $body at $s, expecting a refusal, and check that nothing was written. */
function refused(Storage $s, string $label, array $body, int $status, string $error): void
{
    $before = everything($s);
    [$r, $log] = RegFixture::capture(static fn () => $s->registerFromBody($body));
    check("$label -> $status $error, logged, nothing written",
        RegFixture::outcome($r) === [$status, $error] && str_contains($log, "[REG-REFUSED] $status $error ") && everything($s) === $before,
        json_encode(RegFixture::outcome($r)) . ' ' . trim($log));
}

$doc = RegFixture::vectors();

echo "(1) the signed peer and gateway vectors, through registerFromBody()\n";
foreach (['gateway-wake', 'php-relay-peer', 'gateway-poll'] as $id) {
    $v = vector($id);
    $body = $v['request_body'];
    $identity = RegFixture::identity($v['identity']);
    $node = nodeA($v['relay_state_before'], $body['registration']['public_key']);
    $before = rowFor($node, $v['expected']['identity_hash']);
    [$answer, $log] = RegFixture::capture(static fn () => $node->registerFromBody($body));
    check("[$id] {$body['metadata']['client']} in mode {$body['metadata']['mode']}, signed: 200",
        is_array($answer), $answer instanceof ApiError ? json_encode($answer->payload) : '');
    if (!is_array($answer)) {
        continue;
    }
    check("[$id] the answer is the browser's: exactly the keys of response_example, no plaintext token",
        array_keys($answer) === array_keys($v['response_example']) && !array_key_exists('session_token', $answer)
        && $answer['identity_hash'] === $v['expected']['identity_hash'], implode(',', array_keys($answer)));
    $after = rowFor($node, $v['expected']['identity_hash']);
    check("[$id] the row is signed, keyed by H, with the registration's key, at count {$v['expected']['relay_state_after']['row_registration_seq']}",
        ($after['registration_proof'] ?? '') === 'signed' && ($after['identity_public_key'] ?? '') === $body['registration']['public_key']
        && (int) $after['registration_seq'] === $v['expected']['relay_state_after']['row_registration_seq']
        && ($after['interface_id'] ?? '') === $answer['interface_id']);
    check("[$id] " . ($before === null ? 'a new row (INSERT)' : 're-bound in place: the same interface_id, the old token\'s hash kept'),
        $before === null ? $after['previous_session_token_hash'] === null
            : $after['interface_id'] === $before['interface_id'] && $after['previous_session_token_hash'] === hash('sha256', $before['session_token']));
    $token = RegFixture::decrypt($answer['session_token_encrypted'], $identity);
    check("[$id] the token decrypts with the identity to the row's, and authenticates",
        is_string($token) && hash_equals((string) $after['session_token'], $token) && authenticates($node, $answer['interface_id'], $token) === [200, null]);
    $md = $body['metadata'];
    $peer = $md['client'] === 'reticulum-php' ? [$md['peer_url'], $md['peer_interface_id'], $md['peer_session_token']] : [null, null, null];
    check("[$id] peer_url, peer_interface_id, peer_session_token: " . ($md['client'] === 'reticulum-php' ? 'the signed ones' : 'none (a poll-mode gateway is no PHP peer)'),
        peerColumns($after) === $peer, json_encode(peerColumns($after)));
    check("[$id] metadata_json is the signed metadata, as the unsigned registration stores it (transport included)",
        json_decode((string) $after['metadata_json'], true) === $md, (string) $after['metadata_json']);
    check("[$id] logged [REG-SIGNED] with H", str_contains($log, '[REG-SIGNED] identity=' . $v['expected']['identity_hash']), trim($log));
    [$replay] = RegFixture::capture(static fn () => $node->registerFromBody($body));
    check("[$id] the same body again: 409 stale_challenge (single use)", RegFixture::outcome($replay) === [409, 'stale_challenge']);
}

foreach (['tampered-peer-url', 'tampered-peer-session-token', 'old-challenge-lower-seq', 'unknown-client'] as $id) {
    $v = vector($id);
    $node = nodeA($v['relay_state_before'], $v['request_body']['registration']['public_key']);
    refused($node, "[$id]", $v['request_body'], $v['expected']['status'], $v['expected']['error']);
}

echo "\n(2) the rules each client's unsigned registration has today, no more\n";
// REGISTRATION.md (rev 10) would refuse these two; its unsigned twin is
// accepted today, so the signed one is too.
foreach (['wake-gateway-without-peer-fields' => [null, null, null], 'poll-gateway-with-peer-url' => [null, null, null]] as $id => $wantPeer) {
    $v = vector($id);
    $node = nodeA($v['relay_state_before'], $v['request_body']['registration']['public_key']);
    [$answer] = RegFixture::capture(static fn () => $node->registerFromBody($v['request_body']));
    $after = rowFor($node, bin2hex(RegistrationProtocol::identityHash((string) hex2bin($v['request_body']['registration']['public_key']))));
    check("[$id] accepted (200), as its unsigned twin is", is_array($answer), json_encode(RegFixture::outcome($answer)));
    check("[$id] the row binds no peer columns, as its unsigned twin's would not",
        peerColumns($after) === $wantPeer && $after !== null && !$node->isPhpPeerInterface((string) $after['interface_id']), json_encode(peerColumns($after)));
}

$node = node();
foreach ([1, 2, 3, 4, 5, 6, 7] as $mode) {
    $who = RegFixture::identity();
    [$answer] = RegFixture::capture(static fn () => RegFixture::register($node, $who, ['client' => 'reticulum-php', 'mode' => $mode,
        'peer_url' => "https://mode-$mode.example", 'peer_interface_id' => bin2hex(random_bytes(16)), 'peer_session_token' => bin2hex(random_bytes(32))]));
    $gateway = RegFixture::identity();
    [$poll] = RegFixture::capture(static fn () => RegFixture::register($node, $gateway, ['client' => 'rns-post-interface', 'mode' => $mode, 'transport' => 'http-exchange']));
    check("a signed reticulum-php and a signed rns-post-interface in mode $mode: 200, as unsigned",
        is_array($answer) && is_array($poll), json_encode([RegFixture::outcome($answer), RegFixture::outcome($poll)]));
}

$browser = RegFixture::identity();
$fresh = RegFixture::challenge($node, $browser);
refused($node, 'rns-js signed in mode 6', RegFixture::body($browser, $fresh, ['client' => 'rns-js', 'mode' => 6]), 400, 'transit_mode_not_allowed');
refused($node, 'rns-js signed with a peer_url', RegFixture::body($browser, $fresh, RegFixture::browserMetadata() + ['peer_url' => 'https://x.example']), 400, 'metadata_not_allowed');
refused($node, 'rns-js signed with a peer_session_token', RegFixture::body($browser, $fresh, RegFixture::browserMetadata() + ['peer_session_token' => 'x']), 400, 'metadata_not_allowed');
refused($node, 'rns-js signed with a transport', RegFixture::body($browser, $fresh, RegFixture::browserMetadata() + ['transport' => 'http-exchange']), 400, 'metadata_not_allowed');
[$answer] = RegFixture::capture(static fn () => $node->registerFromBody(RegFixture::body($browser, $fresh, ['implementation' => 'Retichat'] + RegFixture::browserMetadata())));
$browserRow = is_array($answer) ? rowById($node, $answer['interface_id']) : null;
check('rns-js signed: 200, its metadata_json only client, implementation and mode, no peer columns',
    $browserRow !== null && json_decode((string) $browserRow['metadata_json'], true) === ['client' => 'rns-js', 'implementation' => 'Retichat', 'mode' => 1]
    && peerColumns($browserRow) === [null, null, null], json_encode(RegFixture::outcome($answer)));
foreach (['x', 'RNS-JS', 'reticulum-php ', 'Reticulum-PHP', 'rns-post-interface-2', 'reticulum-post'] as $client) {
    $who = RegFixture::identity();
    refused($node, 'a signed client ' . json_encode($client), RegFixture::body($who, RegFixture::challenge($node, $who), ['client' => $client, 'mode' => 1]), 400, 'unknown_client');
}

echo "\n(3) a signed peer row is woken and exchanged exactly like an unsigned one\n";
$node = $wakeNode = node();
$db = RegFixture::db($node);
$gatewayIdentity = RegFixture::identity();
$peers = [];
$signedMetadata = ['client' => 'reticulum-php', 'implementation' => 'PostInterface', 'mode' => 6, 'peer_url' => 'http://signed-gateway.example:4371',
    'peer_interface_id' => bin2hex(random_bytes(16)), 'peer_session_token' => bin2hex(random_bytes(32))];
[$answer] = RegFixture::capture(static fn () => RegFixture::register($node, $gatewayIdentity, $signedMetadata, 'signed gateway'));
check('the signed gateway registers (200)', is_array($answer), json_encode(RegFixture::outcome($answer)));
if (is_array($answer)) {
    $peers['signed'] = [$answer['interface_id'], (string) RegFixture::decrypt($answer['session_token_encrypted'], $gatewayIdentity), $signedMetadata];
}
$unsignedMetadata = ['client' => 'reticulum-php', 'implementation' => 'PostInterface', 'mode' => 6, 'peer_url' => 'http://unsigned-gateway.example:4371',
    'peer_interface_id' => bin2hex(random_bytes(16)), 'peer_session_token' => bin2hex(random_bytes(32))];
[$answer] = RegFixture::capture(static fn () => $node->registerFromBody(['name' => 'unsigned gateway', 'bitrate' => 10000000, 'mtu' => 500, 'metadata' => $unsignedMetadata]));
check('the unsigned gateway registers (200)', is_array($answer), json_encode(RegFixture::outcome($answer)));
$peers['unsigned'] = [$answer['interface_id'], $answer['session_token'], $unsignedMetadata];

$seen = [];
foreach ($peers as $kind => [$id, $token, $md]) {
    $auth = $node->authenticateInterface($id, $token);
    $lookup = $node->phpPeerInterfaceByPeerUrl($md['peer_url']);
    $announcer = RegFixture::identity();
    $announce = AnnounceFixture::announce($announcer, 'lxmf.delivery', 1);
    [, $log] = RegFixture::capture(static fn () => AnnounceFixture::ingest($node, $id, $announce['raw']));
    $verdict = $db->query('SELECT announce_status FROM inbound_packets WHERE packet_hash_hex = ' . $db->quote($announce['packet_hash_hex']))->fetchColumn();
    $path = $db->query('SELECT interface_id FROM path_entries WHERE destination_hash_hex = ' . $db->quote($announce['dest_hex']))->fetchColumn();
    $seen[$kind] = [
        'authenticates as mode 6 reticulum-php' => ($auth['metadata']['client'] ?? null) === 'reticulum-php' && (int) ($auth['metadata']['mode'] ?? 0) === 6,
        'is a PHP peer' => $node->isPhpPeerInterface($id),
        'found by its peer_url, with its peer credentials' => is_array($lookup) && $lookup['interface_id'] === $id
            && $lookup['peer_interface_id'] === $md['peer_interface_id'] && $lookup['peer_session_token'] === $md['peer_session_token'],
        'carries another identity\'s announce: ' . $verdict => $verdict === 'path_updated' && !str_contains($log, '[ANNOUNCE-'),
        'the path goes through it' => $path === $id,
    ];
}
foreach ($seen['signed'] ?? [] as $what => $ok) {
    check("signed peer row: $what (unsigned: " . (($seen['unsigned'][$what] ?? null) === true ? 'yes' : 'no') . ')',
        $ok && ($seen['unsigned'][$what] ?? null) === true);
}
check('every property the unsigned peer row has, the signed one has', isset($seen['signed']) && $seen['signed'] === $seen['unsigned'],
    json_encode($seen));

// Something owed to each: dispatchWakes() wakes both, each at its peer_url.
foreach ($peers as [$id]) {
    $db->prepare("INSERT INTO outbound_packets (interface_id, packet_base64, queued_at, queue_reason) VALUES (?, 'AAAA', ?, 'relay')")->execute([$id, time()]);
}
$pending = array_column($node->phpPeerInterfaceIdsWithPendingOutbound(), 'interface_id');
check('dispatchWakes() selects both rows (pending outbound)', isset($peers['signed']) && in_array($peers['signed'][0], $pending, true)
    && in_array($peers['unsigned'][0], $pending, true), json_encode($pending));
Sent::$requests = [];
RegFixture::capture(static fn () => $node->dispatchWakes());
$woken = array_column(array_filter(Sent::$requests, static fn (array $r): bool => $r['via'] === 'socket'), 'url');
sort($woken);
check('dispatchWakes() wakes both, each at its own peer_url', $woken === ['tcp://signed-gateway.example:4371', 'tcp://unsigned-gateway.example:4371'],
    json_encode($woken));

// The wake handler's exchange: the peer's own credentials, to its own URL.
foreach ($peers as $kind => [$id, , $md]) {
    Sent::$requests = [];
    [$result] = RegFixture::capture(static fn () => $node->exchangeWithPhpPeer($md['peer_url']));
    $sent = Sent::$requests[0] ?? ['url' => '', 'body' => ''];
    $payload = json_decode($sent['body'], true);
    check("$kind peer row: exchangeWithPhpPeer() posts its peer_interface_id and peer_session_token to its peer_url, status ok",
        is_array($result) && ($result['status'] ?? null) === 'ok' && count(Sent::$requests) === 1
        && $sent['url'] === $md['peer_url'] . '/v1/interfaces/exchange'
        && ($payload['interface_id'] ?? null) === $md['peer_interface_id'] && ($payload['session_token'] ?? null) === $md['peer_session_token'],
        json_encode([$result, Sent::$requests]));
}

echo "\n(4) an unsigned registration naming a signed row's peer_url does not take it over\n";
// The gateway-wake vector's row: seeded signed at count 5, then re-bound by
// the vector through the real code (where a peer may sign).
$v = vector('gateway-wake');
$node = nodeA($v['relay_state_before'], $v['request_body']['registration']['public_key']);
$db = RegFixture::db($node);
[$answer] = RegFixture::capture(static fn () => $node->registerFromBody($v['request_body']));
$signedBefore = rowFor($node, $v['expected']['identity_hash']);
$signedId = (string) $signedBefore['interface_id'];
$signedToken = (string) $signedBefore['session_token'];
$signedUrl = (string) $signedBefore['peer_url'];
$squatters = [];
foreach (['the same peer_url' => $signedUrl, 'with a trailing /' => $signedUrl . '/',
          'with /v1/wake' => $signedUrl . '/v1/wake', 'the same peer_url again' => $signedUrl] as $label => $url) {
    $squat = ['client' => 'reticulum-php', 'implementation' => 'PostInterface', 'mode' => 6, 'peer_url' => $url,
        'peer_interface_id' => 'squatter-' . bin2hex(random_bytes(4)), 'peer_session_token' => 'squatter-token-' . bin2hex(random_bytes(8))];
    [$answer] = RegFixture::capture(static fn () => $node->registerFromBody(['name' => 'squatter', 'bitrate' => 1, 'mtu' => 500, 'metadata' => $squat]));
    check("unsigned, $label: 200 with a plaintext token, as today", is_array($answer) && is_string($answer['session_token'] ?? null),
        json_encode(RegFixture::outcome($answer)));
    if (!is_array($answer)) {
        continue;
    }
    $squatters[$label] = $answer['interface_id'];
    $row = rowById($node, $answer['interface_id']);
    check("unsigned, $label: a row of its own, unsigned, holding what it sent",
        $answer['interface_id'] !== $signedId && ($row['registration_proof'] ?? '') === 'none' && $row['identity_hash'] === null
        && $row['peer_interface_id'] === $squat['peer_interface_id'] && hash_equals((string) $row['session_token'], $answer['session_token']));
    check("unsigned, $label: the signed row is untouched, byte for byte", rowFor($node, $v['expected']['identity_hash']) === $signedBefore);
    check("unsigned, $label: the signed peer's token still authenticates", authenticates($node, $signedId, $signedToken) === [200, null]);
}
// Among themselves the unsigned registrations still re-bind by peer_url, as
// today (phpPeerInterfaceByPeerUrl's three forms): all four share one row.
check('unsigned registrations by that peer_url re-bind one unsigned row among themselves, as today',
    count($squatters) === 4 && count(array_unique($squatters)) === 1, json_encode($squatters));
$byUrl = $db->prepare('SELECT COUNT(*) FROM interfaces WHERE peer_url = :u AND identity_hash IS NULL');
$byUrl->execute([':u' => $signedUrl]);
check('one unsigned row holds the signed row\'s peer_url beside it', (int) $byUrl->fetchColumn() === 1);

echo "\n(5) the signed peer re-registers with its own key: its own row, re-bound\n";
check('(3)\'s signed peer row exists', isset($peers['signed']));
$node = $wakeNode;
$db = RegFixture::db($node);
if (isset($peers['signed'])) {
    [$signedId, $signedToken, $signedMd] = $peers['signed'];
    $squatRows = $db->query("SELECT * FROM interfaces WHERE registration_proof = 'none' ORDER BY interface_id")->fetchAll(PDO::FETCH_ASSOC);
    $again = ['peer_interface_id' => bin2hex(random_bytes(16)), 'peer_session_token' => bin2hex(random_bytes(32))] + $signedMetadata;
    [$answer] = RegFixture::capture(static fn () => RegFixture::register($node, $gatewayIdentity, $again, 'signed gateway, restarted'));
    check('200', is_array($answer), json_encode(RegFixture::outcome($answer)));
    $row = rowById($node, $signedId);
    $token = is_array($answer) ? (string) RegFixture::decrypt($answer['session_token_encrypted'], $gatewayIdentity) : '';
    check('the same interface_id, count 2, a new token, the old one\'s hash kept',
        is_array($answer) && $answer['interface_id'] === $signedId && (int) $row['registration_seq'] === 2
        && hash_equals((string) $row['session_token'], $token) && $token !== $signedToken
        && $row['previous_session_token_hash'] === hash('sha256', $signedToken));
    check('the row holds the newly signed peer credentials', peerColumns($row) === [$again['peer_url'], $again['peer_interface_id'], $again['peer_session_token']]);
    check('the new token authenticates; the replaced one is 409 session_superseded, as on every signed row',
        authenticates($node, $signedId, $token) === [200, null] && authenticates($node, $signedId, $signedToken) === [409, 'session_superseded']);
    check('the unsigned rows are untouched by the signed re-bind',
        $db->query("SELECT * FROM interfaces WHERE registration_proof = 'none' ORDER BY interface_id")->fetchAll(PDO::FETCH_ASSOC) === $squatRows);
    check('exactly one signed row', (int) $db->query("SELECT COUNT(*) FROM interfaces WHERE registration_proof = 'signed'")->fetchColumn() === 1);
}

echo "\n(6) a gateway's first signed registration removes its old unsigned row\n";
// The old row, last seen before the restart and offline since, would
// otherwise stay a routing target (a peer row is one whether online or not)
// and keep waking the gateway for what it queues, for good. Staging showed it
// 2026-10-16: path requests and announces queued on the offline old row, and
// a wake each second while they were pending. Its stored peer_url in either
// form the lookup matches.
$gatewayUrl = 'http://switching-gateway.example:4371';
foreach (['as the gateway sends it' => $gatewayUrl, 'with /v1/wake' => $gatewayUrl . '/v1/wake'] as $formLabel => $storedUrl) {
    $node = node();
    $db = RegFixture::db($node);
    $oldMd = ['client' => 'reticulum-php', 'implementation' => 'PostInterface', 'mode' => 6, 'peer_url' => $storedUrl,
        'peer_interface_id' => 'old-' . bin2hex(random_bytes(14)), 'peer_session_token' => 'old-' . bin2hex(random_bytes(30))];
    [$old] = RegFixture::capture(static fn () => $node->registerFromBody(['name' => 'gateway, unsigned', 'bitrate' => 10000000, 'mtu' => 500, 'metadata' => $oldMd]));
    $otherMd = ['client' => 'reticulum-php', 'implementation' => 'PostInterface', 'mode' => 6, 'peer_url' => 'http://other-gateway.example:4371',
        'peer_interface_id' => bin2hex(random_bytes(16)), 'peer_session_token' => bin2hex(random_bytes(32))];
    [$other] = RegFixture::capture(static fn () => $node->registerFromBody(['name' => 'another gateway', 'bitrate' => 10000000, 'mtu' => 500, 'metadata' => $otherMd]));
    check("[$formLabel] the gateway and another one register unsigned, as before the upgrade (200)", is_array($old) && is_array($other),
        json_encode([RegFixture::outcome($old), RegFixture::outcome($other)]));
    if (!is_array($old) || !is_array($other)) {
        continue;
    }
    $db->prepare("UPDATE interfaces SET status = 'offline', last_seen_at = :t WHERE interface_id = :i")
        ->execute([':t' => time() - 600, ':i' => $old['interface_id']]);
    foreach ([$old['interface_id'], $old['interface_id'], $other['interface_id']] as $queuedOn) {
        $db->prepare("INSERT INTO outbound_packets (interface_id, packet_base64, queued_at, queue_reason) VALUES (?, 'AAAA', 1, 'relay_announce')")->execute([$queuedOn]);
    }
    $otherRow = rowById($node, $other['interface_id']);
    $switchIdentity = RegFixture::identity();
    $newMd = ['peer_interface_id' => 'new-' . bin2hex(random_bytes(14)), 'peer_session_token' => 'new-' . bin2hex(random_bytes(30))]
        + ['peer_url' => $gatewayUrl] + $oldMd;
    [$new, $log] = RegFixture::capture(static fn () => RegFixture::register($node, $switchIdentity, $newMd, 'gateway, signed'));
    check("[$formLabel] restarted on a signing build, it registers signed (200), a row of its own",
        is_array($new) && $new['interface_id'] !== $old['interface_id'], json_encode(RegFixture::outcome($new)));
    if (!is_array($new)) {
        continue;
    }
    $queued = static function (string $id) use ($db): int {
        $st = $db->prepare('SELECT COUNT(*) FROM outbound_packets WHERE interface_id = :i');
        $st->execute([':i' => $id]);

        return (int) $st->fetchColumn();
    };
    check("[$formLabel] the old unsigned row is gone, its queue with it",
        rowById($node, $old['interface_id']) === null && $queued($old['interface_id']) === 0);
    check("[$formLabel] logged [REG-RETIRE] identity=H rows=1 dropped=2",
        str_contains($log, '[REG-RETIRE] identity=' . $switchIdentity['hash_hex'] . ' rows=1 dropped=2'), trim($log));
    check("[$formLabel] another peer_url's row and queue are untouched",
        rowById($node, $other['interface_id']) === $otherRow && $queued($other['interface_id']) === 1);
    foreach ([$gatewayUrl, $gatewayUrl . '/', $gatewayUrl . '/v1/wake'] as $form) {
        $lookup = $node->phpPeerInterfaceByPeerUrl($form);
        check("[$formLabel] phpPeerInterfaceByPeerUrl(" . json_encode($form) . '): the signed row, with its credentials',
            ($lookup['interface_id'] ?? null) === $new['interface_id'] && ($lookup['peer_interface_id'] ?? null) === $newMd['peer_interface_id'],
            json_encode($lookup));
    }
    Sent::$requests = [];
    [$result] = RegFixture::capture(static fn () => $node->exchangeWithPhpPeer($gatewayUrl));
    $payload = json_decode((Sent::$requests[0] ?? ['body' => ''])['body'], true);
    check("[$formLabel] exchangeWithPhpPeer() posts the signed row's peer credentials",
        ($result['status'] ?? null) === 'ok' && ($payload['interface_id'] ?? null) === $newMd['peer_interface_id']
        && ($payload['session_token'] ?? null) === $newMd['peer_session_token'], json_encode([$result, Sent::$requests]));
}

// An unsigned row made at that peer_url after the signed bind (§(4): a
// registration naming it gets a row of its own) goes at the gateway's next
// signed registration, its restart: the re-bind removes it as the first
// bind did.
$squatMd = ['client' => 'reticulum-php', 'implementation' => 'PostInterface', 'mode' => 6, 'peer_url' => $gatewayUrl,
    'peer_interface_id' => 'squat-' . bin2hex(random_bytes(13)), 'peer_session_token' => 'squat-' . bin2hex(random_bytes(29))];
[$squat] = RegFixture::capture(static fn () => $node->registerFromBody(['name' => 'squatter', 'bitrate' => 1, 'mtu' => 500, 'metadata' => $squatMd]));
check('after the signed bind, an unsigned registration at that peer_url gets a row of its own (200)',
    is_array($squat) && is_array($new ?? null) && $squat['interface_id'] !== $new['interface_id'], json_encode(RegFixture::outcome($squat)));
[$again, $log] = RegFixture::capture(static fn () => RegFixture::register($node, $switchIdentity, $newMd, 'gateway, restarted'));
check('the gateway\'s next signed registration re-binds its row and removes that one: [REG-RETIRE] rows=1',
    is_array($again) && is_array($squat) && $again['interface_id'] === $new['interface_id'] && rowById($node, $squat['interface_id']) === null
    && str_contains($log, '[REG-RETIRE] identity=' . $switchIdentity['hash_hex'] . ' rows=1'), trim($log));
check('a signed bind with no unsigned row at its peer_url logs no [REG-RETIRE]',
    !str_contains(RegFixture::capture(static fn () => RegFixture::register($node, $switchIdentity, $newMd, 'gateway, again'))[1], '[REG-RETIRE]'));

echo "\n(6b) two rows with one peer_url: the lookup takes the one seen most recently\n";
// A PHP node's own peering row is unsigned (connectToPeer does not sign) and
// no address is checked. A signed registration naming that peer's URL removes
// the peer's row, as an unsigned registration naming it re-binds it today;
// the peer's next registration (the peering heal, on finding no row) makes a
// row of its own beside the signed one. Not "signed first": the row the peer
// itself keeps seen is the one found.
$node = node();
$db = RegFixture::db($node);
$peerUrl = 'https://configured-peer.example/reticulum';
$peerMd = ['client' => 'reticulum-php', 'mode' => 1, 'peer_url' => $peerUrl,
    'peer_interface_id' => bin2hex(random_bytes(16)), 'peer_session_token' => bin2hex(random_bytes(32))];
[$peerRow] = RegFixture::capture(static fn () => $node->registerFromBody(['name' => 'configured-peer.example', 'bitrate' => 1000000, 'mtu' => 500, 'metadata' => $peerMd]));
$namerMd = ['peer_interface_id' => bin2hex(random_bytes(16)), 'peer_session_token' => bin2hex(random_bytes(32))] + $peerMd;
[$namer] = RegFixture::capture(static fn () => RegFixture::register($node, RegFixture::identity(), $namerMd, 'names the peer'));
check('a signed registration naming the PHP peer\'s peer_url: 200, a row of its own; the peer\'s row is removed',
    is_array($peerRow) && is_array($namer) && $namer['interface_id'] !== $peerRow['interface_id'] && rowById($node, $peerRow['interface_id']) === null,
    json_encode([RegFixture::outcome($peerRow), RegFixture::outcome($namer)]));
$peerMd = ['peer_interface_id' => bin2hex(random_bytes(16)), 'peer_session_token' => bin2hex(random_bytes(32))] + $peerMd;
[$peerRow] = RegFixture::capture(static fn () => $node->registerFromBody(['name' => 'configured-peer.example', 'bitrate' => 1000000, 'mtu' => 500, 'metadata' => $peerMd]));
check('the peer registers again: a row of its own beside the signed one (200)',
    is_array($peerRow) && is_array($namer) && $peerRow['interface_id'] !== $namer['interface_id'] && rowById($node, $namer['interface_id']) !== null,
    json_encode(RegFixture::outcome($peerRow)));
if (is_array($peerRow) && is_array($namer)) {
    // The signed row was last seen a minute ago; the peer exchanges now.
    $db->prepare('UPDATE interfaces SET last_seen_at = :t WHERE interface_id = :i')->execute([':t' => time() - 60, ':i' => $namer['interface_id']]);
    $node->touchInterface($peerRow['interface_id']);
    check('the lookup takes the peer\'s own row, seen more recently, over the signed one',
        ($node->phpPeerInterfaceByPeerUrl($peerUrl)['interface_id'] ?? null) === $peerRow['interface_id']);
    $node->touchInterface($namer['interface_id']);
    $db->prepare('UPDATE interfaces SET last_seen_at = :t WHERE interface_id = :i')->execute([':t' => time() - 60, ':i' => $peerRow['interface_id']]);
    check('...and the signed row when it was seen more recently',
        ($node->phpPeerInterfaceByPeerUrl($peerUrl)['interface_id'] ?? null) === $namer['interface_id']);
}

echo "\n(7) /health's browsers_online counts browsers: a signed gateway or peer is none\n";
$node = node();
foreach (['a signed gateway in wake mode' => $signedMetadata, 'a signed gateway in poll mode' => RegFixture::pollGatewayMetadata(),
          'a signed PHP-node peer' => ['client' => 'reticulum-php', 'mode' => 1] + RegFixture::phpPeerMetadata()] as $what => $md) {
    [$answer] = RegFixture::capture(static fn () => RegFixture::register($node, RegFixture::identity(), $md, $what));
    check("$what registers (200), online", is_array($answer) && (rowById($node, $answer['interface_id'])['status'] ?? null) === 'online',
        json_encode(RegFixture::outcome($answer)));
}
$health = $node->registrationHealth();
check('three signed rows online, none a browser: browsers_online {signed 0, legacy 0}',
    ($health['browsers_online'] ?? null) === ['signed' => 0, 'legacy' => 0], json_encode($health));
RegFixture::capture(static fn () => RegFixture::register($node, RegFixture::identity()));
check('a signed browser joins them: browsers_online {signed 1, legacy 0}',
    ($node->registrationHealth()['browsers_online'] ?? null) === ['signed' => 1, 'legacy' => 0], json_encode($node->registrationHealth()));

echo "\n$pass passed, $fail failed\n";
exit($fail === 0 ? 0 : 1);
