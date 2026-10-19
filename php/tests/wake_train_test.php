<?php
/**
 * A wake is a ping. One is outstanding at a time, and the peer's exchange
 * answers it (James, 2026-10-19: "there should be a queue with a limit of
 * one behind the active wake response ... another train should just come
 * up directly behind it. No need to resend the wake", and "if there are
 * packets still waiting after idle for more than 5 seconds, it can ping
 * again. After that, exponential backoff").
 *
 * Until 2026-10-19 dispatchWakes() woke a peer at most once per
 * min_wake_interval_ms, comparing whole seconds of time(). A packet queued
 * just after the peer's exchange had collected the rest, in the same second
 * as the last wake, got no wake, and waited for whatever request next ran a
 * wake pass on this node: on a quiet node, for good.
 *
 * Node A holds a row for peer B (a PHP peer row, as connectToPeer makes it).
 * (a) Packets for B: one ping. More packets while it is outstanding: no
 *     ping; they go with the exchange the ping brings.
 * (b) B's exchange authenticates: the ping is answered. A packet queued
 *     after it gets its own ping at once, whatever the clock says (the old
 *     gate is made to say "too soon" here).
 * (c) No exchange: no second ping before 5 s. After 5 s with packets still
 *     waiting, one ping again ([WAKE-AGAIN]); then 10 s, 20 s, ... doubling
 *     up to 5 min. B's exchange resets it.
 * (d) Packets B's exchange took wait for B to confirm them in its next
 *     exchange: they ping only once B has been idle 5 s, then 10 s, ...
 *     A packet not yet handed out still pings at once. Acknowledgements A
 *     owes B ping nothing: they go only in A's call to B's exchange, which
 *     B's own ping brings. (Pinging for both at once cost two to six pings
 *     a packet on the private staging run, 2026-10-19.)
 * (e) The empty-poll shortcut's wake mark carries the time the next ping
 *     is due, so idle browser polls take the full path once it is.
 * (f) Source: nothing reads min_wake_interval_ms or last_wake_sent_at.
 *
 * On 525db7b every part from (a) on fails, at the first read of the new
 * columns. With only the columns added, (b) still fails (the gate skips
 * the ping), and so do (c) and (e): there is no backoff and no due time.
 *
 * Run: php php/tests/wake_train_test.php
 * On MySQL (a database that holds no peer row bbbb...; the test migrates it):
 *   WAKE_TEST_MYSQL=user:pass@127.0.0.1:3306/dbname php php/tests/wake_train_test.php
 */
declare(strict_types=1);

namespace ReticulumPhp;

require_once dirname(__DIR__) . '/src/index.php';
require_once __DIR__ . '/stubs/registration_fixture.php';

use PDO;
use RegFixture;

final class Pinged
{
    /** @var list<string> */
    public static array $to = [];
}

/** Every wake is recorded here and never sent. */
function stream_socket_client(string $address, &$errorCode = null, &$errorMessage = null, ?float $timeout = null, int $flags = 0, mixed $context = null): mixed
{
    Pinged::$to[] = $address;
    $errorCode = 0;
    $errorMessage = 'recorded by the test, not sent';

    return false;
}

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

$config = RegFixture::config() + ['host_url' => 'https://node-a.example/reticulum'];
$mysql = getenv('WAKE_TEST_MYSQL') ?: null;
if ($mysql !== null) {
    $u = parse_url('mysql://' . $mysql);
    $config['storage'] = [
        'backend' => 'mysql', 'mysql_host' => $u['host'] ?? '127.0.0.1', 'mysql_port' => $u['port'] ?? 3306,
        'mysql_dbname' => ltrim($u['path'] ?? '', '/'), 'mysql_user' => rawurldecode($u['user'] ?? 'root'), 'mysql_pass' => rawurldecode($u['pass'] ?? ''),
    ];
    echo 'MySQL ' . $config['storage']['mysql_host'] . ':' . $config['storage']['mysql_port'] . '/' . $config['storage']['mysql_dbname'] . "\n";
}
$node = new Storage($config);
$migrated = $node->migrateIfNeeded();
if (($migrated['errors'] ?? []) !== []) {
    echo 'migration failed: ' . json_encode($migrated['errors']) . "\n";
    exit(1);
}
$db = RegFixture::db($node);

$peerId = str_repeat('b', 32);
$peerToken = str_repeat('c', 64);
$db->prepare("INSERT INTO interfaces (interface_id, name, session_token, status, metadata_json, created_at, last_seen_at,
                                      peer_url, peer_interface_id, peer_session_token)
              VALUES (:id, 'node-b.example', :tok, 'online', '{\"client\":\"reticulum-php\"}', :created, :seen,
                      'https://node-b.example/reticulum', :pid, :ptok)")
    ->execute([':id' => $peerId, ':tok' => $peerToken, ':created' => time(), ':seen' => time(), ':pid' => str_repeat('d', 32), ':ptok' => str_repeat('e', 64)]);

function queuePacket(PDO $db, string $id): void
{
    $db->prepare("INSERT INTO outbound_packets (interface_id, packet_base64, queued_at, queue_reason) VALUES (?, 'AAAA', ?, 'relay')")
        ->execute([$id, time()]);
}
function ackAll(PDO $db, string $id): void
{
    $db->prepare('UPDATE outbound_packets SET acked_at = ? WHERE interface_id = ? AND acked_at IS NULL')->execute([time(), $id]);
}
/** @return array{0: int, 1: string} the pings this pass sent, and what it logged */
function pass(Storage $node): array
{
    Pinged::$to = [];
    [, $log] = RegFixture::capture(static fn () => $node->dispatchWakes());

    return [count(Pinged::$to), $log];
}
function wakeState(PDO $db, string $id): array
{
    $st = $db->prepare('SELECT wake_sent_at_ms, wake_backoff_ms FROM interfaces WHERE interface_id = ?');
    $st->execute([$id]);

    return array_map('intval', $st->fetch(PDO::FETCH_ASSOC) ?: ['wake_sent_at_ms' => -1, 'wake_backoff_ms' => -1]);
}
/** Moves the outstanding ping $ms into the past, as if that long had passed. */
function age(PDO $db, string $id, int $ms): void
{
    $db->prepare('UPDATE interfaces SET wake_sent_at_ms = wake_sent_at_ms - ? WHERE interface_id = ?')->execute([$ms, $id]);
}
/** The old gate's clock, set so it would say "too soon" for a long while. */
function oldGateSaysTooSoon(PDO $db, string $id): void
{
    try {
        $db->prepare('UPDATE interfaces SET last_wake_sent_at = ? WHERE interface_id = ?')->execute([time() + 3600, $id]);
    } catch (\Throwable) {
    }
}

echo "(a) one ping; packets queued while it is out ride the train it brings\n";
queuePacket($db, $peerId);
try {
    [$n] = pass($node);
    check('packets for B: one ping', $n === 1, "pings=$n");
    check('it goes to B\'s address', (Pinged::$to[0] ?? '') === 'tls://node-b.example:443', json_encode(Pinged::$to));
    oldGateSaysTooSoon($db, $peerId);
    queuePacket($db, $peerId);
    [$n] = pass($node);
    check('more packets while it is outstanding: no ping', $n === 0, "pings=$n");
    $state = wakeState($db, $peerId);
    check('the ping is recorded, with a 5 s wait before another', $state['wake_sent_at_ms'] > 0 && $state['wake_backoff_ms'] === 5000, json_encode($state));
} catch (\Throwable $e) {
    check('(a) runs', false, $e->getMessage());
}

echo "(b) B's exchange answers the ping; what misses that train gets the next one at once\n";
try {
    $node->authenticateInterface($peerId, $peerToken);
    check('B\'s exchange clears the ping', wakeState($db, $peerId) === ['wake_sent_at_ms' => 0, 'wake_backoff_ms' => 0], json_encode(wakeState($db, $peerId)));
    ackAll($db, $peerId);
    queuePacket($db, $peerId);
    oldGateSaysTooSoon($db, $peerId);
    [$n] = pass($node);
    check('a packet queued after the train left: a ping at once', $n === 1, "pings=$n");
} catch (\Throwable $e) {
    check('(b) runs', false, $e->getMessage());
}

echo "(c) unanswered: again after 5 s, then doubling to 5 min; an exchange resets it\n";
try {
    [$n] = pass($node);
    check('no exchange yet, under 5 s: no ping', $n === 0, "pings=$n");
    age($db, $peerId, 4900);
    [$n] = pass($node);
    check('4.9 s: still none', $n === 0, "pings=$n");
    age($db, $peerId, 200);
    [$n, $log] = pass($node);
    check('past 5 s with packets waiting: one ping again', $n === 1, "pings=$n");
    check('it says so: [WAKE-AGAIN] with the wait that follows', str_contains($log, '[WAKE-AGAIN] interface=bbbbbbbb') && str_contains($log, 'next_after_ms=10000'), $log);
    check('the next wait is 10 s', wakeState($db, $peerId)['wake_backoff_ms'] === 10000, json_encode(wakeState($db, $peerId)));
    age($db, $peerId, 9900);
    [$n] = pass($node);
    check('9.9 s into it: none', $n === 0, "pings=$n");
    age($db, $peerId, 200);
    [$n] = pass($node);
    check('past 10 s: one, and then 20 s', $n === 1 && wakeState($db, $peerId)['wake_backoff_ms'] === 20000, json_encode(wakeState($db, $peerId)));
    $db->prepare('UPDATE interfaces SET wake_backoff_ms = 300000 WHERE interface_id = ?')->execute([$peerId]);
    age($db, $peerId, 300001);
    [$n] = pass($node);
    check('at the 5 min cap it stays 5 min', $n === 1 && wakeState($db, $peerId)['wake_backoff_ms'] === 300000, json_encode(wakeState($db, $peerId)));
    $node->authenticateInterface($peerId, $peerToken);
    check('B\'s exchange resets the backoff', wakeState($db, $peerId) === ['wake_sent_at_ms' => 0, 'wake_backoff_ms' => 0], json_encode(wakeState($db, $peerId)));
    [$n] = pass($node);
    check('and the next ping goes at once, with 5 s again', $n === 1 && wakeState($db, $peerId)['wake_backoff_ms'] === 5000, json_encode(wakeState($db, $peerId)));
} catch (\Throwable $e) {
    check('(c) runs', false, $e->getMessage());
}

echo "(d) what the train took waits for B's next exchange; acknowledgements we owe ping nothing\n";
try {
    $node->authenticateInterface($peerId, $peerToken);
    ackAll($db, $peerId);
    [$n] = pass($node);
    check('nothing waiting: no ping', $n === 0, "pings=$n");
    $db->prepare("UPDATE interfaces SET pending_ack_batch_ids_json = '[\"batch-1\"]' WHERE interface_id = ?")->execute([$peerId]);
    [$n] = pass($node);
    check('an acknowledgement we owe B: no ping (it goes in our call to B, which B\'s ping brings)', $n === 0, "pings=$n");
    $db->prepare("UPDATE interfaces SET pending_ack_batch_ids_json = NULL WHERE interface_id = ?")->execute([$peerId]);

    // B's exchange took a packet and has not confirmed it.
    queuePacket($db, $peerId);
    $db->prepare("UPDATE outbound_packets SET delivered_batch_id = 'batch-x', delivered_at = ? WHERE interface_id = ? AND acked_at IS NULL")->execute([time(), $peerId]);
    $node->authenticateInterface($peerId, $peerToken);
    [$n] = pass($node);
    check('collected, not yet confirmed, B seen just now: no ping', $n === 0, "pings=$n");
    $db->prepare('UPDATE interfaces SET last_seen_at = ? WHERE interface_id = ?')->execute([time() - 4, $peerId]);
    [$n] = pass($node);
    check('B idle 4 s: still none', $n === 0, "pings=$n");
    $db->prepare('UPDATE interfaces SET last_seen_at = ? WHERE interface_id = ?')->execute([time() - 6, $peerId]);
    [$n, $log] = pass($node);
    check('B idle over 5 s: one ping, then the 10 s wait', $n === 1 && wakeState($db, $peerId)['wake_backoff_ms'] === 10000, "pings=$n " . json_encode(wakeState($db, $peerId)));
    check('it says so: [WAKE-AGAIN] unconfirmed_idle_ms', str_contains($log, '[WAKE-AGAIN] interface=bbbbbbbb unconfirmed_idle_ms='), $log);
    queuePacket($db, $peerId);
    [$n] = pass($node);
    check('a new packet while that ping is out: it rides the train, no ping', $n === 0, "pings=$n");

    // Confirmation still owed, ping answered, then a new packet: it missed the train.
    $node->authenticateInterface($peerId, $peerToken);
    [$n] = pass($node);
    check('a packet not yet handed out, no ping out: a ping at once, whatever else waits', $n === 1 && wakeState($db, $peerId)['wake_backoff_ms'] === 5000, "pings=$n " . json_encode(wakeState($db, $peerId)));
    ackAll($db, $peerId);
} catch (\Throwable $e) {
    check('(d) runs', false, $e->getMessage());
}

echo "(e) the empty-poll mark says when the next ping is due\n";
try {
    $node->authenticateInterface($peerId, $peerToken);
    queuePacket($db, $peerId);
    pass($node);
    $mark = (string) (new \ReflectionMethod(EmptyPoll::class, 'dir'))->invoke(null, $config) . '/wakes-owed';
    clearstatcache();
    $state = wakeState($db, $peerId);
    $due = (int) ceil(($state['wake_sent_at_ms'] + $state['wake_backoff_ms']) / 1000);
    check('wakes-owed is dated when the unanswered ping may go again', is_file($mark) && filemtime($mark) === $due,
        'mtime=' . (is_file($mark) ? filemtime($mark) : 'none') . " due=$due");
    $node->authenticateInterface($peerId, $peerToken);
    ackAll($db, $peerId);
    pass($node);
    clearstatcache();
    check('nothing waiting: no mark', !is_file($mark));
} catch (\Throwable $e) {
    check('(e) runs', false, $e->getMessage());
}

echo "(f) source\n";
/** A file's code without its comments. */
function code(string $file): string
{
    $out = '';
    foreach (token_get_all((string) file_get_contents($file)) as $token) {
        if (is_array($token) && in_array($token[0], [T_COMMENT, T_DOC_COMMENT], true)) {
            continue;
        }
        $out .= is_array($token) ? $token[1] : $token;
    }

    return $out;
}
$src = '';
foreach (array_merge([dirname(__DIR__) . '/src/index.php'], glob(dirname(__DIR__) . '/src/lib/*.php') ?: []) as $file) {
    $src .= code($file);
}
check('nothing reads min_wake_interval_ms', !str_contains($src, 'min_wake_interval_ms'));
check('nothing reads last_wake_sent_at outside the schema', preg_match_all('/last_wake_sent_at/', $src) === preg_match_all('/last_wake_sent_at/', code(dirname(__DIR__) . '/src/lib/request_schema_trait.php')));

echo "\n$pass passed, $fail failed\n";
exit($fail === 0 ? 0 : 1);
