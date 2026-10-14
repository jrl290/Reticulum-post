<?php
/**
 * REGISTRATION-STAGE1.md §7 and §8: a lost session (401) and a superseded
 * one (409 session_superseded) are different answers, and the newest signed
 * registration wins.
 *
 * Before Stage 1 every token a row no longer held got 401. Two tabs of one
 * identity each answered their 401 by registering again, which replaced the
 * other's token, every exchange: the eviction loop. Now a signed row's token
 * changes only by a signed re-bind, which keeps the replaced token's SHA-256,
 * so any token on a signed row but its current one gets 409 with §8's
 * message, which a Stage 1 page stops on. Legacy rows keep today's 401, since
 * a client that does not know 409 would stay down.
 *
 * Covered: after a signed re-bind the old token gets 409 with §8's message,
 * and so do tokens two and three re-binds old and a random token on that row;
 * only the immediately previous token is logged, once per row per token, also
 * under seven case variants of the id with a case-folding collation. A legacy
 * browser re-bind gives the replaced token 401, stores no previous hash, and
 * the replaced holder's next legacy registration takes the row back; a
 * gateway's legacy re-bind still 401; an unknown interface 401. The switch on:
 * a legacy browser row 401, a signed row unaffected.
 *
 * Run: php php/tests/session_superseded_test.php
 */
declare(strict_types=1);

require_once dirname(__DIR__) . '/src/index.php';
require_once __DIR__ . '/stubs/registration_fixture.php';

use ReticulumPhp\ApiError;
use ReticulumPhp\Storage;

const SUPERSEDED_MESSAGE = 'This identity connected from another tab or device. Reload to connect here.';

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

/** @return array{0: int, 1: ?string, 2: string, 3: ?array} status, error, log, the refusal's body */
function auth(Storage $s, string $id, string $token): array
{
    [$r, $log] = RegFixture::capture(static fn () => $s->authenticateInterface($id, $token));
    [$status, $error] = RegFixture::outcome($r);

    return [$status, $error, $log, $r instanceof ApiError ? $r->payload : null];
}

function rowOf(Storage $s, string $id): array
{
    $st = RegFixture::db($s)->prepare('SELECT * FROM interfaces WHERE interface_id = :i');
    $st->execute([':i' => $id]);

    return $st->fetch(PDO::FETCH_ASSOC) ?: [];
}

echo "(1) signed: the newest registration wins, every older holder is told why\n";
$node = RegFixture::storage();
$id = RegFixture::identity();
[$first, $t1] = RegFixture::connect($node, $id);
[, $t2] = RegFixture::connect($node, $id);
$rowId = $first['interface_id'];
[$status, $error, $log, $payload] = auth($node, $rowId, $t1);
check('the first tab\'s token after the second tab registered -> 409 session_superseded', [$status, $error] === [409, 'session_superseded'], "$status $error");
check('...with §8\'s body, exactly', $payload === ['error' => 'session_superseded', 'message' => SUPERSEDED_MESSAGE], json_encode($payload));
check('...logged [SESSION-SUPERSEDED] interface=<id8>, without the token',
    str_contains($log, '[SESSION-SUPERSEDED] interface=' . substr($rowId, 0, 8)) && !str_contains($log, $t1), trim($log));
check('...the row keeps the logged hash, set on its own id', rowOf($node, $rowId)['superseded_logged_hash'] === hash('sha256', $t1));
[$status, , $log] = auth($node, $rowId, $t1);
check('the same old token again: 409 again, not logged again (an old tab repeating it cannot fill the log)',
    $status === 409 && !str_contains($log, '[SESSION-SUPERSEDED]'));
check('the newest token works', auth($node, $rowId, $t2)[0] === 200);

[, $t3] = RegFixture::connect($node, $id);
[$status, , $log] = auth($node, $rowId, $t2);
check('a third registration supersedes the second: 409, logged once for this token', $status === 409 && substr_count($log, '[SESSION-SUPERSEDED]') === 1);
[, $t4] = RegFixture::connect($node, $id);
[$status, $error, $log, $payload] = auth($node, $rowId, $t1);
check('a token three re-binds old -> 409 session_superseded with §8\'s message, no line (only the previous token is logged)',
    [$status, $error] === [409, 'session_superseded'] && ($payload['message'] ?? null) === SUPERSEDED_MESSAGE && !str_contains($log, '[SESSION-SUPERSEDED]'));
[$status, $error, $log] = auth($node, $rowId, $t2);
check('a token two re-binds old -> 409 session_superseded, no line', [$status, $error] === [409, 'session_superseded'] && !str_contains($log, '[SESSION-SUPERSEDED]'));
[$status, $error, $log] = auth($node, $rowId, bin2hex(random_bytes(32)));
check('a random token on the signed row -> 409 session_superseded, no line', [$status, $error] === [409, 'session_superseded'] && !str_contains($log, '[SESSION-SUPERSEDED]'));
[$status, $error] = auth($node, $rowId, '');
check('an empty token on the signed row -> 409 too, and never authenticates', [$status, $error] === [409, 'session_superseded']);
[$status, , $log] = auth($node, $rowId, $t3);
check('the immediately previous token (the third) -> 409, logged once', $status === 409 && substr_count($log, '[SESSION-SUPERSEDED]') === 1);
check('the current token still works', auth($node, $rowId, $t4)[0] === 200);
[$status, $error, , $payload] = auth($node, bin2hex(random_bytes(16)), $t4);
check('an unknown interface -> 401 unauthorized {error, message}', [$status, $error] === [401, 'unauthorized'] && array_keys((array) $payload) === ['error', 'message']);

echo "\n(2) legacy rows keep today's 401\n";
$claim = bin2hex(random_bytes(16));
$meta = ['client' => 'rns-js', 'mode' => 1, 'identity_hash' => $claim];
[$a] = RegFixture::capture(static fn () => $node->registerInterface('Retichat Web', 1000000, 500, $meta));
[$b] = RegFixture::capture(static fn () => $node->registerInterface('Retichat Web', 1000000, 500, $meta));
check('a second legacy browser with the claim re-binds the same row', $a['interface_id'] === $b['interface_id']);
[$status, $error] = auth($node, $a['interface_id'], $a['session_token']);
check('the replaced legacy token -> 401 unauthorized, never 409', [$status, $error] === [401, 'unauthorized'], "$status $error");
check('...and the row stores no previous hash', rowOf($node, $a['interface_id'])['previous_session_token_hash'] === null);
check('the newer legacy token works', auth($node, $b['interface_id'], $b['session_token'])[0] === 200);
[$back] = RegFixture::capture(static fn () => $node->registerInterface('Retichat Web', 1000000, 500, $meta));
check('the replaced holder registers again (as its 401 makes it): it takes the row back',
    $back['interface_id'] === $a['interface_id'] && auth($node, $back['interface_id'], $back['session_token'])[0] === 200
    && auth($node, $b['interface_id'], $b['session_token'])[0] === 401 && rowOf($node, $a['interface_id'])['previous_session_token_hash'] === null);
[$status, $error] = auth($node, $a['interface_id'], bin2hex(random_bytes(32)));
check('a random token on a legacy row -> 401', [$status, $error] === [401, 'unauthorized']);
$peerMeta = ['client' => 'reticulum-php', 'peer_url' => 'https://peer.example.org/reticulum', 'peer_interface_id' => str_repeat('a', 32), 'peer_session_token' => str_repeat('b', 64)];
[$p1] = RegFixture::capture(static fn () => $node->registerInterface('peer', 1000000, 500, $peerMeta));
[$p2] = RegFixture::capture(static fn () => $node->registerInterface('peer', 1000000, 500, $peerMeta));
check('a gateway\'s legacy re-bind (a PHP node by its peer_url): the replaced token still -> 401',
    $p1['interface_id'] === $p2['interface_id'] && auth($node, $p1['interface_id'], $p1['session_token'])[0] === 401
    && auth($node, $p2['interface_id'], $p2['session_token'])[0] === 200 && rowOf($node, $p1['interface_id'])['previous_session_token_hash'] === null);

echo "\n(3) the switch on: a legacy browser row 401, a signed row unaffected\n";
$path = sys_get_temp_dir() . '/session-superseded-' . bin2hex(random_bytes(4)) . '.sqlite';
register_shutdown_function(static function () use ($path): void {
    foreach (['', '-wal', '-shm'] as $suffix) {
        @unlink($path . $suffix);
    }
});
$open = RegFixture::storage([], $path);
[$browserRow] = RegFixture::capture(static fn () => $open->registerInterface('Retichat Web', 1000000, 500, ['client' => 'rns-js', 'mode' => 1, 'identity_hash' => bin2hex(random_bytes(16))]));
[$bareRow] = RegFixture::capture(static fn () => $open->registerInterface('Retichat Web', 1000000, 500, ['client' => 'rns-js', 'mode' => 1]));
[$peerRow] = RegFixture::capture(static fn () => $open->registerInterface('peer', 1000000, 500, $peerMeta));
[$pollRow] = RegFixture::capture(static fn () => $open->registerInterface('poll', 1000000, 500, RegFixture::pollGatewayMetadata()));
[$otherRow] = RegFixture::capture(static fn () => $open->registerInterface('x', 1000000, 500, ['client' => 'some-other-client']));
$signedId = RegFixture::identity();
[$signed, $signedToken] = RegFixture::connect($open, $signedId);
$all = ['legacy browser with a claim' => $browserRow, 'legacy browser without one' => $bareRow, 'reticulum-php' => $peerRow,
        'rns-post-interface' => $pollRow, 'another client' => $otherRow];
foreach ($all as $what => $row) {
    check("switch off: the $what row authenticates", auth($open, $row['interface_id'], $row['session_token'])[0] === 200);
}
$enforcing = RegFixture::storage(['enforce_signed_registration' => true], $path);
foreach ($all as $what => $row) {
    $want = str_starts_with($what, 'legacy browser') ? 401 : 200;
    check("switch on: the $what row -> $want", auth($enforcing, $row['interface_id'], $row['session_token'])[0] === $want);
}
check('switch on: the signed row still authenticates', auth($enforcing, $signed['interface_id'], $signedToken)[0] === 200);
[$status, $error] = auth($enforcing, $signed['interface_id'], bin2hex(random_bytes(32)));
check('switch on: another token on the signed row is still 409', [$status, $error] === [409, 'session_superseded']);

echo "\n(4) once per token, keyed on the row's own id, not the request's spelling of it\n";
/**
 * MySQL and MariaDB's utf8mb4_unicode_ci ignores case, so every case variant
 * of an interface_id finds the row there. SQLite compares bytes; COLLATE
 * NOCASE on interfaces.interface_id gives it that behaviour for this column.
 * The compare-and-swap that logs is on the row's own interface_id (§8), so
 * the variants share one row and one logged hash.
 */
function nocaseInterfaceIds(PDO $db): void
{
    $table = (string) $db->query("SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'interfaces'")->fetchColumn();
    $indexes = $db->query("SELECT sql FROM sqlite_master WHERE type = 'index' AND tbl_name = 'interfaces' AND sql IS NOT NULL")->fetchAll(PDO::FETCH_COLUMN);
    $nocase = preg_replace('/CREATE TABLE interfaces \(\s*interface_id VARCHAR\(64\) NOT NULL,/', 'CREATE TABLE interfaces_nocase (interface_id VARCHAR(64) NOT NULL COLLATE NOCASE,', $table, 1, $count);
    if ($count !== 1) {
        throw new RuntimeException('interfaces schema changed: ' . $table);
    }
    $db->exec('PRAGMA foreign_keys = OFF');
    $db->exec((string) $nocase);
    $db->exec('INSERT INTO interfaces_nocase SELECT * FROM interfaces');
    $db->exec('DROP TABLE interfaces');
    $db->exec('ALTER TABLE interfaces_nocase RENAME TO interfaces');
    foreach ($indexes as $index) {
        $db->exec((string) $index);
    }
}
$ci = RegFixture::storage();
nocaseInterfaceIds(RegFixture::db($ci));
// An id with at least six letters, so seven case variants of it exist.
do {
    $ciIdentity = RegFixture::identity();
    [$ciFirst, $ciOld] = RegFixture::connect($ci, $ciIdentity);
    $ciRowId = (string) $ciFirst['interface_id'];
} while (preg_match_all('/[a-f]/', $ciRowId) < 6);
check('the case-folding table finds the row under another spelling, as MySQL would', auth($ci, strtoupper($ciRowId), $ciOld)[0] === 200);
RegFixture::connect($ci, $ciIdentity);
$variants = [strtoupper($ciRowId)];
foreach (array_keys(array_filter(str_split($ciRowId), static fn (string $c): bool => ctype_alpha($c))) as $position) {
    $variants[] = substr_replace($ciRowId, strtoupper($ciRowId[$position]), $position, 1);
}
$variants = array_slice(array_values(array_unique($variants)), 0, 7);
$statuses = [];
$lines = 0;
foreach (array_merge($variants, [$ciRowId]) as $spelling) {
    [$status, $error, $log] = auth($ci, $spelling, $ciOld);
    $statuses[] = "$status $error";
    $lines += substr_count($log, '[SESSION-SUPERSEDED]');
}
check('seven case variants of the id, and the id itself, all find the row and get 409 session_superseded',
    count($variants) === 7 && array_unique($statuses) === ['409 session_superseded'], json_encode($statuses));
check('...but [SESSION-SUPERSEDED] is logged once for that token, not once per spelling', $lines === 1, "lines: $lines");
$stateKeys = RegFixture::db($ci)->query("SELECT state_key FROM transport_state WHERE state_key LIKE 'session_superseded%'")->fetchAll(PDO::FETCH_COLUMN);
check('...the logged hash is on the row itself; transport_state holds no entry per token',
    rowOf($ci, $ciRowId)['superseded_logged_hash'] === hash('sha256', $ciOld) && $stateKeys === [], json_encode($stateKeys));

echo "\n$pass passed, $fail failed\n";
exit($fail === 0 ? 0 : 1);
