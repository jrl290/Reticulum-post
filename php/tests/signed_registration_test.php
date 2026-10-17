<?php
/**
 * REGISTRATION-STAGE1.md §3 to §5: a browser's signed registration, against
 * the real Storage (SQLite).
 *
 * Before Stage 1 a body's metadata was taken on trust: anyone who knew a
 * browser's identity hash (every lxmf.delivery announce reveals it) re-bound
 * its row and rotated its token (A1). Here the row of identity H is reachable
 * only by a signature from H's key over a challenge this PHP node made for H
 * at the row's current count, and the session token goes back only encrypted
 * to that key.
 *
 * Covered: the challenge (no count, nothing about a row, its 400s); an INSERT
 * at count 0 and a re-bind in place (same interface_id, a new token, the old
 * one's hash kept); a replay, the other node's challenge and a lost bind race
 * 409, each race leaving one row; a tampered field 403; a body without a
 * valid signature over a challenge whose count has since moved 403, not 409;
 * an audience key, a low-order key, bitrate 2^31, a 65-byte or numeric
 * implementation and a transport of 5: 400 bad_registration; a signed client
 * other than rns-js, reticulum-php and rns-post-interface 400 unknown_client
 * (a signed peer or gateway: signed_peer_registration_test.php); no refusal writes
 * anything, not even the node secret; the answer has no plaintext token or
 * count; a bind whose §4.5 removal fails still answers its encrypted token
 * and logs failed=.
 *
 * Before Stage 1 there is no challenge, and a body with `registration` gets
 * a plaintext token.
 *
 * Run: php php/tests/signed_registration_test.php
 */
declare(strict_types=1);

require_once dirname(__DIR__) . '/src/index.php';
require_once __DIR__ . '/stubs/registration_fixture.php';

use ReticulumPhp\ApiError;
use ReticulumPhp\RegistrationProtocol as P;
use ReticulumPhp\Storage;

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

function rows(Storage $s): array
{
    return RegFixture::db($s)->query('SELECT * FROM interfaces ORDER BY created_at, interface_id')->fetchAll(PDO::FETCH_ASSOC);
}

function rowById(Storage $s, string $id): ?array
{
    $st = RegFixture::db($s)->prepare('SELECT * FROM interfaces WHERE interface_id = :i');
    $st->execute([':i' => $id]);
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

    return json_encode($out);
}

function authenticates(Storage $s, string $id, string $token): bool
{
    try {
        $s->authenticateInterface($id, $token);

        return true;
    } catch (ApiError) {
        return false;
    }
}

/** Refuse $body at $s and check the answer, the log line, and that nothing was written. */
function refused(Storage $s, string $label, array $body, int $status, string $error): void
{
    $before = everything($s);
    [$r, $log] = RegFixture::capture(static fn () => $s->registerFromBody($body));
    check("$label -> $status $error", RegFixture::outcome($r) === [$status, $error], json_encode(RegFixture::outcome($r)));
    check('...{"error", "message"}, logged [REG-REFUSED], nothing written',
        $r instanceof ApiError && array_keys($r->payload) === ['error', 'message']
        && str_contains($log, "[REG-REFUSED] $status $error ") && everything($s) === $before, trim($log));
}

$tmp = sys_get_temp_dir() . '/signed-registration-test-' . bin2hex(random_bytes(4));
mkdir($tmp, 0775, true);
register_shutdown_function(static fn () => exec('rm -rf ' . escapeshellarg($tmp)));

echo "(1) the challenge: no count, nothing about a row, and its 400s\n";
$node = RegFixture::storage();
$browser = RegFixture::identity();
$noRow = RegFixture::identity();
$challenge = $node->issueChallenge(['public_key' => $browser['public_key_hex']]);
check('the answer is status, version, identity_hash, challenge: no count, nothing about a row',
    array_keys($challenge) === ['status', 'version', 'identity_hash', 'challenge'] && $challenge['status'] === 'challenge'
    && $challenge['version'] === 1 && $challenge['identity_hash'] === $browser['hash_hex'] && !str_contains(json_encode($challenge), 'seq'));
check('the challenge is 48 bytes, made by this node for H at count 0',
    P::isLowerHex($challenge['challenge'], 96) && P::challengeVerifies(RegFixture::secret($node), $browser['hash'], 0, (string) hex2bin($challenge['challenge'])));
$byHash = $node->issueChallenge(['identity_hash' => $noRow['hash_hex']]);
check('asked by identity_hash it is shaped the same, for that hash',
    array_keys($byHash) === array_keys($challenge) && $byHash['identity_hash'] === $noRow['hash_hex']
    && P::challengeVerifies(RegFixture::secret($node), $noRow['hash'], 0, (string) hex2bin($byHash['challenge'])));
check('two challenges for one identity differ (a fresh nonce each time)',
    $node->issueChallenge(['identity_hash' => $noRow['hash_hex']])['challenge'] !== $byHash['challenge']);
foreach ([
    'nothing' => [],
    'both' => ['public_key' => $browser['public_key_hex'], 'identity_hash' => $browser['hash_hex']],
    'an upper-case public_key' => ['public_key' => strtoupper($browser['public_key_hex'])],
    'a short identity_hash' => ['identity_hash' => substr($browser['hash_hex'], 0, 31)],
    'an identity_hash and a newline' => ['identity_hash' => $browser['hash_hex'] . "\n"],
    'a list' => ['public_key' => [$browser['public_key_hex']]],
    'an extra key' => ['public_key' => $browser['public_key_hex'], 'seq' => 1],
] as $label => $request) {
    $before = everything($node);
    [$r, $log] = RegFixture::capture(static fn () => $node->issueChallenge($request));
    check("$label -> 400 bad_challenge_request {error, message}, logged, nothing written",
        RegFixture::outcome($r) === [400, 'bad_challenge_request'] && $r instanceof ApiError && array_keys($r->payload) === ['error', 'message']
        && str_contains($log, '[REG-REFUSED] 400 bad_challenge_request') && everything($node) === $before, trim($log));
}

echo "\n(2) an INSERT at count 0, then a re-bind in place\n";
$body = RegFixture::body($browser, $challenge['challenge'], RegFixture::browserMetadata());
[$first, $log] = RegFixture::capture(static fn () => $node->registerFromBody($body));
check('a first signed registration answers 200', is_array($first), $first instanceof ApiError ? json_encode($first->payload) : '');
$row = rowById($node, $first['interface_id'] ?? '');
check('it INSERTs one row: count 1, proof signed, identity_hash H, its public key, online, no claim',
    count(rows($node)) === 1 && (int) $row['registration_seq'] === 1 && $row['registration_proof'] === 'signed'
    && $row['identity_hash'] === $browser['hash_hex'] && $row['identity_public_key'] === $browser['public_key_hex']
    && $row['status'] === 'online' && $row['claimed_identity_hash'] === null && $row['previous_session_token_hash'] === null);
check('the answer is exactly §5\'s keys: no session_token, no count',
    array_keys($first) === ['status', 'interface_id', 'identity_hash', 'session_token_encrypted', 'idle_exchange_interval_ms', 'max_batch_packets', 'max_packet_bytes']
    && $first['status'] === 'registered' && $first['identity_hash'] === $browser['hash_hex'], implode(',', array_keys($first)));
$token1 = RegFixture::decrypt($first['session_token_encrypted'], $browser);
check('session_token_encrypted (160 bytes) decrypts with the identity to the row\'s 64-hex token',
    is_string($token1) && $token1 === $row['session_token'] && preg_match('/\A[0-9a-f]{64}\z/', $token1) === 1
    && strlen($first['session_token_encrypted']) === 320);
check('the plaintext token appears nowhere in the answer, and no count does', !str_contains(json_encode($first), (string) $token1)
    && !str_contains(json_encode($first), 'registration_seq'));
check('metadata_json holds only client, implementation and mode', json_decode($row['metadata_json'], true) === RegFixture::browserMetadata(), $row['metadata_json']);
check('logged [REG-SIGNED] identity=H interface=<id8> created',
    str_contains($log, '[REG-SIGNED] identity=' . $browser['hash_hex'] . ' interface=' . substr($first['interface_id'], 0, 8) . ' created'), trim($log));
check('the session token authenticates', authenticates($node, $first['interface_id'], (string) $token1));

$challenge2 = $node->issueChallenge(['public_key' => $browser['public_key_hex']]);
check('the next challenge binds the row\'s count (1)', P::challengeVerifies(RegFixture::secret($node), $browser['hash'], 1, (string) hex2bin($challenge2['challenge'])));
$md = RegFixture::browserMetadata() + ['identity_hash' => $browser['hash_hex']];
[$second, $log] = RegFixture::capture(static fn () => $node->registerFromBody(RegFixture::body($browser, $challenge2['challenge'], $md, 'Retichat Web — Zoë', 2000000, 400)));
$row2 = rowById($node, $first['interface_id']);
$token2 = is_array($second) ? RegFixture::decrypt($second['session_token_encrypted'], $browser) : null;
check('a re-registration re-binds in place: same interface_id, count 2, one row',
    is_array($second) && $second['interface_id'] === $first['interface_id'] && (int) $row2['registration_seq'] === 2 && count(rows($node)) === 1);
check('...with a new token, and the old one remembered by its SHA-256',
    is_string($token2) && $token2 !== $token1 && $row2['session_token'] === $token2 && $row2['previous_session_token_hash'] === hash('sha256', (string) $token1));
check('...name, bitrate and mtu as signed', $row2['name'] === 'Retichat Web — Zoë' && (int) $row2['bitrate'] === 2000000 && (int) $row2['mtu'] === 400);
check('...metadata.identity_hash equal to H accepted and never stored', !str_contains((string) $row2['metadata_json'], 'identity_hash'));
check('...logged [REG-SIGNED] ... rebound', str_contains($log, '[REG-SIGNED] identity=' . $browser['hash_hex'] . ' interface=' . substr($first['interface_id'], 0, 8) . ' rebound'), trim($log));
check('the new token authenticates', authenticates($node, $first['interface_id'], (string) $token2));
$fresh = $node->issueChallenge(['public_key' => $browser['public_key_hex']])['challenge'];
$changed = RegFixture::body($browser, $fresh, RegFixture::browserMetadata());
$changed['metadata']['implementation'] = 'Changed after signing';
[$r] = RegFixture::capture(static fn () => $node->registerFromBody($changed));
check('implementation is not signed and never acted on: changed after signing, still 200', is_array($r));

echo "\n(3) refused: a replay, the other node's challenge, tampering, malformed fields, other clients\n";
refused($node, 'replaying the first body (its count has moved)', $body, 409, 'stale_challenge');
$fresh = $node->issueChallenge(['public_key' => $browser['public_key_hex']])['challenge'];
$nodeB = RegFixture::storage();
$fromB = $nodeB->issueChallenge(['public_key' => $browser['public_key_hex']])['challenge'];
refused($node, "node B's challenge, validly signed", RegFixture::body($browser, $fromB, RegFixture::browserMetadata()), 409, 'stale_challenge');
foreach (['name' => 'Someone else', 'bitrate' => 5, 'mtu' => 1000] as $field => $value) {
    $tampered = RegFixture::body($browser, $fresh, RegFixture::browserMetadata());
    $tampered[$field] = $value;
    refused($node, "a tampered $field", $tampered, 403, 'bad_registration_signature');
}
$tampered = RegFixture::body($browser, $fresh, RegFixture::browserMetadata());
$tampered['metadata']['mode'] = 2;
refused($node, 'a tampered mode', $tampered, 403, 'bad_registration_signature');
$stale = $body;
$stale['name'] = 'Tampered';
refused($node, 'a body without a valid signature over a challenge whose count has since moved: 403, not 409', $stale, 403, 'bad_registration_signature');
$other = RegFixture::identity();
$wrongKey = RegFixture::body($browser, $fresh, RegFixture::browserMetadata());
$wrongKey['registration']['signature'] = RegFixture::resign($wrongKey, $other)['registration']['signature'];
refused($node, 'signed by another key', $wrongKey, 403, 'bad_registration_signature');

$audience = RegFixture::body($browser, $fresh, RegFixture::browserMetadata());
$audience['registration']['audience'] = 'relay-a.example.org';
refused($node, "revision 2's audience key", $audience, 400, 'bad_registration');
$version = RegFixture::body($browser, $fresh, RegFixture::browserMetadata());
$version['registration']['version'] = 2;
refused($node, 'registration.version 2', $version, 400, 'bad_registration');
foreach (['challenge', 'signature', 'public_key'] as $field) {
    $upper = RegFixture::body($browser, $fresh, RegFixture::browserMetadata());
    $upper['registration'][$field] = strtoupper($upper['registration'][$field]);
    refused($node, "an upper-case $field", $upper, 400, 'bad_registration');
}
foreach (['bitrate 2^31' => ['bitrate', 2147483648], 'bitrate as a string' => ['bitrate', '1000000'], 'bitrate as a float' => ['bitrate', 1000000.0],
          'mtu 0' => ['mtu', 0], 'mtu 2^31' => ['mtu', 2147483648], 'an empty name' => ['name', ''], 'a name of 256 bytes' => ['name', str_repeat('n', 256)],
          'a name that is not UTF-8' => ['name', "Retichat \xff"]] as $label => [$field, $value]) {
    $bad = RegFixture::body($browser, $fresh, RegFixture::browserMetadata());
    $bad[$field] = $value;
    refused($node, "$label (nothing is coerced)", $bad, 400, 'bad_registration');
}
foreach (['an implementation of 65 bytes' => ['implementation', str_repeat('i', 65)], 'a numeric implementation' => ['implementation', 7],
          'a transport of 5' => ['transport', 5], 'mode as a string' => ['mode', '1'], 'mode 8' => ['mode', 8], 'mode 0' => ['mode', 0],
          'a client of 65 bytes' => ['client', str_repeat('c', 65)], 'an empty client' => ['client', ''],
          'a peer_url of 513 bytes' => ['peer_url', 'https://' . str_repeat('p', 505)]] as $label => [$field, $value]) {
    // The shape fails before the signature is looked at, so the field is
    // changed after signing.
    $bad = RegFixture::body($browser, $fresh, RegFixture::browserMetadata());
    $bad['metadata'][$field] = $value;
    refused($node, $label, $bad, 400, 'bad_registration');
}
refused($node, 'metadata with wake_url', RegFixture::body($browser, $fresh, RegFixture::browserMetadata() + ['wake_url' => 'https://x.example/wake']), 400, 'unsigned_metadata');
refused($node, 'metadata.identity_hash of another identity',
    RegFixture::body($browser, $fresh, RegFixture::browserMetadata() + ['identity_hash' => $other['hash_hex']]), 400, 'identity_hash_mismatch');
refused($node, 'a signed client "x"', RegFixture::body($browser, $fresh, ['client' => 'x', 'implementation' => 'PostInterface', 'mode' => 1]), 400, 'unknown_client');
refused($node, 'a signed client "RNS-JS"', RegFixture::body($browser, $fresh, ['client' => 'RNS-JS', 'mode' => 1]), 400, 'unknown_client');
refused($node, 'a signed browser in mode 6', RegFixture::body($browser, $fresh, ['client' => 'rns-js', 'mode' => 6]), 400, 'transit_mode_not_allowed');
refused($node, 'a signed browser with a transport', RegFixture::body($browser, $fresh, RegFixture::browserMetadata() + ['transport' => 'tcp']), 400, 'metadata_not_allowed');
$lowx = RegFixture::identity('lowx');
$lowChallenge = $node->issueChallenge(['public_key' => $lowx['public_key_hex']])['challenge'];
refused($node, 'a low-order X25519 key, validly signed over a valid challenge', RegFixture::body($lowx, $lowChallenge, RegFixture::browserMetadata()), 400, 'bad_registration');
check('none of these moved the row: count 3, the token from (2)\'s change still current',
    (int) rowById($node, $first['interface_id'])['registration_seq'] === 3 && count(rows($node)) === 1);
$edge = RegFixture::storage();
[$r] = RegFixture::capture(static fn () => $edge->registerFromBody(RegFixture::body($browser,
    RegFixture::challenge($edge, $browser), RegFixture::browserMetadata(), str_repeat('n', 255), 2147483647, 2147483647)));
check('bitrate and mtu 2^31 - 1 and a name of 255 bytes are accepted', is_array($r), $r instanceof ApiError ? json_encode($r->payload) : '');

echo "\n(4) no refusal writes anything, not even the node secret\n";
$virgin = RegFixture::storage();
$empty = everything($virgin);
$forgedChallenge = bin2hex(random_bytes(48));
foreach ([
    'a forged challenge (409)' => [RegFixture::body($browser, $forgedChallenge, RegFixture::browserMetadata()), [409, 'stale_challenge']],
    'a bad signature (403)' => [(static function () use ($browser, $forgedChallenge): array {
        $b = RegFixture::body($browser, $forgedChallenge, RegFixture::browserMetadata());
        $b['name'] = 'x';

        return $b;
    })(), [403, 'bad_registration_signature']],
    'a malformed body (400)' => [['registration' => ['version' => 1]], [400, 'bad_registration']],
    'an unknown client (400)' => [RegFixture::body($browser, $forgedChallenge, ['client' => 'x', 'mode' => 1]), [400, 'unknown_client']],
    'a low-order key (409 first: no challenge here)' => [RegFixture::body($lowx, $forgedChallenge, RegFixture::browserMetadata()), [409, 'stale_challenge']],
] as $label => [$refusedBody, $want]) {
    [$r] = RegFixture::capture(static fn () => $virgin->registerFromBody($refusedBody));
    check("$label: refused as expected, and the node still has no secret and no row",
        RegFixture::outcome($r) === $want && everything($virgin) === $empty && RegFixture::secret($virgin) === '', json_encode(RegFixture::outcome($r)));
}

echo "\n(5) two registrations of one identity race: one row, the loser 409\n";
/**
 * A PDO that, the moment the bind statement is prepared, lets a competing
 * registration of the same identity run to completion through a second
 * connection to the same file: the window between step 6's read and step
 * 8's write, made deterministic.
 */
final class RacingPdo extends PDO
{
    /** @var (callable(): void)|null */
    public $competitor = null;
    public string $trigger = '';

    public function prepare(string $query, array $options = []): PDOStatement|false
    {
        if ($this->competitor !== null && str_contains($query, $this->trigger)) {
            $run = $this->competitor;
            $this->competitor = null;
            $run();
        }

        return parent::prepare($query, $options);
    }
}
function racingStorage(string $path, string $trigger, callable $competitor): Storage
{
    $storage = RegFixture::storage([], $path);
    $pdo = new RacingPdo('sqlite:' . $path, null, null, [
        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION, PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC, PDO::ATTR_EMULATE_PREPARES => false,
    ]);
    $pdo->exec('PRAGMA busy_timeout = 5000');
    $pdo->exec('PRAGMA journal_mode = WAL');
    $pdo->trigger = $trigger;
    $pdo->competitor = $competitor;
    (new ReflectionProperty($storage, 'db'))->setValue($storage, $pdo);

    return $storage;
}
$insertPath = $tmp . '/insert-race.sqlite';
$racer = RegFixture::identity();
$seed = RegFixture::storage([], $insertPath);
$raceChallenge = RegFixture::challenge($seed, $racer);
$bodyA = RegFixture::body($racer, $raceChallenge, RegFixture::browserMetadata(), 'tab A');
$bodyB = RegFixture::body($racer, $raceChallenge, RegFixture::browserMetadata(), 'tab B');
$winner = null;
$loserNode = racingStorage($insertPath, 'identity_hash, identity_public_key, registration_seq, registration_proof', static function () use ($insertPath, $bodyB, &$winner): void {
    $winner = RegFixture::storage([], $insertPath)->registerFromBody($bodyB);
});
[$loser, $log] = RegFixture::capture(static fn () => $loserNode->registerFromBody($bodyA));
$raceRows = RegFixture::db($seed)->query('SELECT interface_id, name, registration_seq FROM interfaces')->fetchAll(PDO::FETCH_ASSOC);
check('count 0, both bodies valid: the competitor wins the INSERT (200)', is_array($winner));
check('the loser meets the UNIQUE identity_hash index: 409 stale_challenge, and one row, the winner\'s',
    RegFixture::outcome($loser) === [409, 'stale_challenge'] && count($raceRows) === 1 && $raceRows[0]['name'] === 'tab B', json_encode($raceRows));
check('...logged with the winner\'s id, looked up only to log it',
    str_contains($log, '[REG-REFUSED] 409 stale_challenge client=rns-js identity=' . $racer['hash_hex'] . ' lost_bind_race winner=' . substr((string) ($winner['interface_id'] ?? '?'), 0, 8)), trim($log));

$updatePath = $tmp . '/update-race.sqlite';
$seed = RegFixture::storage([], $updatePath);
RegFixture::register($seed, $racer, RegFixture::browserMetadata(), 'tab 0');
$raceChallenge = RegFixture::challenge($seed, $racer);
$bodyA = RegFixture::body($racer, $raceChallenge, RegFixture::browserMetadata(), 'tab A');
$bodyB = RegFixture::body($racer, $raceChallenge, RegFixture::browserMetadata(), 'tab B');
$winner = null;
$loserNode = racingStorage($updatePath, 'SET previous_session_token_hash = :old_token_sha256', static function () use ($updatePath, $bodyB, &$winner): void {
    $winner = RegFixture::storage([], $updatePath)->registerFromBody($bodyB);
});
[$loser, $log] = RegFixture::capture(static fn () => $loserNode->registerFromBody($bodyA));
$raceRows = RegFixture::db($seed)->query('SELECT name, registration_seq, session_token FROM interfaces')->fetchAll(PDO::FETCH_ASSOC);
check('count 1: the competitor re-binds first (200)', is_array($winner));
check('the loser\'s count-matched UPDATE matches no row: 409 stale_challenge, and the winner\'s bind stands',
    RegFixture::outcome($loser) === [409, 'stale_challenge'] && count($raceRows) === 1 && $raceRows[0]['name'] === 'tab B'
    && (int) $raceRows[0]['registration_seq'] === 2 && $raceRows[0]['session_token'] === RegFixture::decrypt((string) ($winner['session_token_encrypted'] ?? ''), $racer),
    json_encode($raceRows));
check('...logged lost_bind_race', str_contains($log, '[REG-REFUSED] 409 stale_challenge client=rns-js identity=' . $racer['hash_hex'] . ' lost_bind_race'), trim($log));

// The same race between two real processes on one SQLite file: whichever
// way the scheduler interleaves them, one row and one 409.
$processPath = $tmp . '/process-race.sqlite';
$seed = RegFixture::storage([], $processPath);
$racer2 = RegFixture::identity();
$raceChallenge = RegFixture::challenge($seed, $racer2);
$go = $tmp . '/go';
$script = $tmp . '/racer.php';
file_put_contents($script, '<?php
require ' . var_export(dirname(__DIR__) . '/src/index.php', true) . ';
require ' . var_export(__DIR__ . '/stubs/registration_fixture.php', true) . ';
$body = json_decode($argv[1], true);
// Both start together; the bound only turns a missing go-file into a failure.
for ($i = 0; $i < 500 && !file_exists(' . var_export($go, true) . '); $i++) { usleep(2000); }
try { RegFixture::storage([], ' . var_export($processPath, true) . ')->registerFromBody($body); echo "200"; }
catch (ReticulumPhp\ApiError $e) { echo $e->statusCode . " " . $e->payload["error"]; }
');
$procs = [];
$pipes = [];
foreach (['process A', 'process B'] as $name) {
    $procs[$name] = proc_open([PHP_BINARY, $script, json_encode(RegFixture::body($racer2, $raceChallenge, RegFixture::browserMetadata(), $name))],
        [0 => ['file', '/dev/null', 'r'], 1 => ['pipe', 'w'], 2 => ['file', '/dev/null', 'w']], $pipes[$name]);
}
touch($go);
$answers = [];
foreach ($procs as $name => $proc) {
    $answers[] = trim((string) stream_get_contents($pipes[$name][1]));
    proc_close($proc);
}
sort($answers);
$count = (int) RegFixture::db($seed)->query('SELECT COUNT(*) FROM interfaces')->fetchColumn();
check('two processes: one 200, one 409 stale_challenge, one row', $answers === ['200', '409 stale_challenge'] && $count === 1, json_encode($answers) . " rows=$count");

echo "\n(6) a bind whose §4.5 removal fails still answers, and logs failed=\n";
$squatted = RegFixture::storage();
$sdb = RegFixture::db($squatted);
$victim = RegFixture::identity();
$legacy = $squatted->registerInterface('old tab', 1000000, 500, ['client' => 'rns-js', 'mode' => 1, 'identity_hash' => $victim['hash_hex']]);
$sdb->prepare('INSERT INTO local_destinations (destination_hash_hex, interface_id, registered_at) VALUES (:d, :i, 1)')
    ->execute([':d' => bin2hex(random_bytes(16)), ':i' => $legacy['interface_id']]);
$sdb->exec("CREATE TRIGGER keep_local_destinations BEFORE DELETE ON local_destinations
            BEGIN SELECT RAISE(ABORT, 'local_destinations is kept by this test'); END");
[$bound, $log] = RegFixture::capture(static fn () => RegFixture::register($squatted, $victim));
check('the signed bind answers 200 with its encrypted token', is_array($bound)
    && preg_match('/\A[0-9a-f]{64}\z/', (string) RegFixture::decrypt((string) ($bound['session_token_encrypted'] ?? ''), $victim)) === 1,
    $bound instanceof ApiError ? json_encode($bound->payload) : '');
check('...logged [REG-RETIRE] identity=H failed=local_destinations with the error',
    str_contains($log, '[REG-RETIRE] identity=' . $victim['hash_hex'] . ' failed=local_destinations ') && str_contains($log, 'kept by this test')
    && !str_contains($log, 'rows='), trim($log));
check('...and the legacy row is still there, inert (its holder gets 401)',
    rowById($squatted, $legacy['interface_id']) !== null && !authenticates($squatted, $legacy['interface_id'], $legacy['session_token']));
$sdb->exec('DROP TRIGGER keep_local_destinations');
[$again, $log] = RegFixture::capture(static fn () => RegFixture::register($squatted, $victim));
check('the next bind of H runs the removal again: [REG-RETIRE] rows=1, the row and its local destination gone',
    is_array($again) && str_contains($log, '[REG-RETIRE] identity=' . $victim['hash_hex'] . ' rows=1 dropped=0')
    && rowById($squatted, $legacy['interface_id']) === null
    && (int) $sdb->query('SELECT COUNT(*) FROM local_destinations')->fetchColumn() === 0, trim($log));

echo "\n$pass passed, $fail failed\n";
exit($fail === 0 ? 0 : 1);
