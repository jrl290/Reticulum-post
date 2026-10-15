<?php
/**
 * A newly registered interface is seeded with the cached announces once, on
 * its first exchange, whatever was queued for it before that exchange.
 *
 * Until 2026-10-14 seedInterfaceIfNew() took "no outbound rows yet and no
 * packets received" for "new". A live announce relayed to the browser
 * between its registration and its first exchange (queueOutboundPacket,
 * relay_announce) gave it an outbound row, so it was never seeded: it heard
 * only announces made after it registered, and could not reach a cached
 * destination until that destination announced again. Seen on a selectiv
 * test node the same day (SQLite, a gateway sending one announce per
 * exchange and N browsers starting at once): under the Swoole entry 1 of 4
 * browsers at par=5 and 2 of 8 at par=9 got only the live announces; plain
 * PHP has the same window and lost the race less often.
 *
 * Runs the real Storage on a SQLite file, with the exchange route's storage
 * steps in its order (seedInterfaceIfNew, then fetchOutboundBatch; the
 * route itself answers through respond(), which exits):
 *   (a) a browser registered after a gateway's announces were cached, sent
 *       a live announce before its first exchange, gets every cached
 *       announce and the live one on that exchange;
 *   (b) it is seeded once: its next exchange, and another request's (a
 *       second Storage on the same file), queue nothing more, nor does an
 *       exchange after its delivered rows are pruned;
 *   (c) a browser with nothing queued before its first exchange is seeded,
 *       as before;
 *   (d) a PHP node peering row is never seeded;
 *   (e) the 64 cap holds, and takes the destinations announced last;
 *   (f) a row that was there before the marker column (the schema the live
 *       nodes' code built) is not seeded by the migration's first request,
 *       while a row registered after it is;
 *   (g) one destination whose accepted announces fill the newest 768
 *       rows and more is seeded once, with the 63 destinations before it.
 *
 * On MySQL with ONLY_FULL_GROUP_BY in sql_mode (8.4's default) the seeding
 * query was a SELECT DISTINCT ordered by a column it did not select, error
 * 3065, until 2026-10-15; run this there with that mode to check it.
 *
 * Run: php tests/seed_new_interface_once_test.php
 * On MySQL (every table in the database is dropped first):
 *   SEED_TEST_MYSQL=user:pass@127.0.0.1:3306/dbname php tests/seed_new_interface_once_test.php
 * There (f) starts from this code's schema with seeded_at dropped and the
 * version before it recorded, the stage1-1 schema, since the 50c870b stub
 * is SQLite.
 */
declare(strict_types=1);

require_once dirname(__DIR__) . '/src/index.php';
require_once __DIR__ . '/stubs/registration_fixture.php';
require_once __DIR__ . '/stubs/announce_fixture.php';

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
        echo "  FAIL $label" . ($detail !== '' ? " — $detail" : '') . "\n";
    }
}

$dir = sys_get_temp_dir() . '/reticulum-php-seed-once-' . bin2hex(random_bytes(4));
mkdir($dir, 0775, true);
register_shutdown_function(static function () use ($dir): void {
    foreach ((array) glob($dir . '/*') as $file) {
        @unlink((string) $file);
    }
    @rmdir($dir);
});

function row(Storage $s, array $metadata, string $name): string
{
    [$answer] = RegFixture::capture(static fn () => $s->registerInterface($name, 1000000, 500, $metadata));
    if (!is_array($answer)) {
        throw new RuntimeException('registration refused: ' . json_encode(RegFixture::outcome($answer)));
    }

    return (string) $answer['interface_id'];
}

/** A browser row: signed where this code has signed registration, legacy otherwise. */
function browserRow(Storage $s): string
{
    if (method_exists($s, 'issueChallenge')) {
        [$answer] = RegFixture::capture(static fn () => RegFixture::register($s, RegFixture::identity()));
        if (is_array($answer)) {
            return (string) $answer['interface_id'];
        }
    }

    return row($s, ['client' => 'rns-js', 'mode' => 1], 'browser');
}

/** $n announces from fresh identities, fed through $gateway; their packet hashes. */
function announceThrough(Storage $s, string $gateway, int $n): array
{
    $hashes = [];
    for ($i = 0; $i < $n; $i++) {
        $a = AnnounceFixture::announce(RegFixture::identity(), 'lxmf.delivery');
        RegFixture::capture(static fn () => AnnounceFixture::ingest($s, $gateway, $a['raw']));
        $hashes[] = $a['packet_hash_hex'];
    }

    return $hashes;
}

/** The packet hashes of the announces queued for $row, every row of them. */
function queuedAnnounces(PDO $db, string $row): array
{
    $st = $db->prepare("SELECT packet_hash_hex FROM outbound_packets WHERE interface_id = :i AND queue_reason = 'relay_announce' ORDER BY packet_id");
    $st->execute([':i' => $row]);

    return array_map('strval', $st->fetchAll(PDO::FETCH_COLUMN));
}

/** The exchange route's storage steps: seed, then the outbound batch it answers with. */
function firstExchange(Storage $s, string $row): array
{
    $s->seedInterfaceIfNew($row);
    $batch = $s->fetchOutboundBatch($row, 64);

    return $batch;
}

function sameSet(array $a, array $b): bool
{
    sort($a);
    sort($b);

    return $a === $b;
}

$mysql = getenv('SEED_TEST_MYSQL') ?: null;
if ($mysql !== null) {
    $u = parse_url('mysql://' . $mysql);
    $mysql = [
        'backend' => 'mysql', 'mysql_host' => $u['host'] ?? '127.0.0.1', 'mysql_port' => $u['port'] ?? 3306,
        'mysql_dbname' => ltrim($u['path'] ?? '', '/'), 'mysql_user' => rawurldecode($u['user'] ?? 'root'), 'mysql_pass' => rawurldecode($u['pass'] ?? ''),
    ];
    echo 'MySQL ' . $mysql['mysql_host'] . ':' . $mysql['mysql_port'] . '/' . $mysql['mysql_dbname'] . "\n";
}

/** A migrated Storage on the SQLite file $path, or on the MySQL database. */
function storageAt(string $path): Storage
{
    global $mysql;
    $config = RegFixture::config([], $path);
    if ($mysql !== null) {
        $config['storage'] = $mysql;
    }
    $storage = new Storage($config);
    $summary = $storage->migrateIfNeeded();
    if (($summary['errors'] ?? []) !== []) {
        throw new RuntimeException('migration failed: ' . json_encode($summary['errors']));
    }

    return $storage;
}

/** MySQL: an empty database. */
function dropAllTables(): void
{
    global $mysql;
    $pdo = new PDO(sprintf('mysql:host=%s;port=%d;dbname=%s', $mysql['mysql_host'], $mysql['mysql_port'], $mysql['mysql_dbname']),
        $mysql['mysql_user'], $mysql['mysql_pass'], [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]);
    echo '  sql_mode: ' . $pdo->query('SELECT @@SESSION.sql_mode')->fetchColumn() . "\n";
    $pdo->exec('SET FOREIGN_KEY_CHECKS = 0');
    foreach ($pdo->query('SHOW TABLES')->fetchAll(PDO::FETCH_COLUMN) as $table) {
        $pdo->exec("DROP TABLE `{$table}`");
    }
}

$path = $dir . '/node.sqlite';
if ($mysql !== null) {
    dropAllTables();
}
$node = storageAt($path);
$db = RegFixture::db($node);
$gateway = row($node, RegFixture::pollGatewayMetadata(), 'gateway');

echo "\n(a) a live announce queued before the first exchange does not stop the seed\n";
$cached = announceThrough($node, $gateway, 3);
$browser = browserRow($node);
$live = announceThrough($node, $gateway, 1);
check('(precondition) the live announce was relayed to the browser before its first exchange',
    queuedAnnounces($db, $browser) === $live, json_encode(queuedAnnounces($db, $browser)));
firstExchange($node, $browser);
check('its first exchange queues every cached announce and keeps the live one',
    sameSet(queuedAnnounces($db, $browser), array_merge($cached, $live)), json_encode(queuedAnnounces($db, $browser)));

echo "\n(b) seeded once\n";
$before = queuedAnnounces($db, $browser);
firstExchange($node, $browser);
check('its next exchange queues nothing more', queuedAnnounces($db, $browser) === $before, json_encode(queuedAnnounces($db, $browser)));
$other = storageAt($path);
$other->seedInterfaceIfNew($browser);
check("another request's exchange queues nothing more", queuedAnnounces($db, $browser) === $before, json_encode(queuedAnnounces($db, $browser)));
// Its rows gone, as maintenance prunes them once acked, it still has had
// its seed: the old rule ("no outbound rows") seeded it a second time here.
$db->prepare('DELETE FROM outbound_packets WHERE interface_id = :i')->execute([':i' => $browser]);
firstExchange($node, $browser);
check('with its rows pruned, its next exchange queues nothing', queuedAnnounces($db, $browser) === [], json_encode(queuedAnnounces($db, $browser)));

echo "\n(c) a browser with nothing queued is seeded\n";
$quiet = browserRow($node);
check('(precondition) nothing is queued for it', queuedAnnounces($db, $quiet) === []);
firstExchange($node, $quiet);
check('its first exchange queues every cached announce', sameSet(queuedAnnounces($db, $quiet), array_merge($cached, $live)), json_encode(queuedAnnounces($db, $quiet)));

echo "\n(d) a PHP node peering row is not seeded\n";
$peer = row($node, RegFixture::phpPeerMetadata(), 'peer');
$node->seedInterfaceIfNew($peer);
check('no announce is queued for it', queuedAnnounces($db, $peer) === [], json_encode(queuedAnnounces($db, $peer)));

echo "\n(e) the 64 cap\n";
$newest = announceThrough($node, $gateway, 70);
$crowded = browserRow($node);
firstExchange($node, $crowded);
$count = count(queuedAnnounces($db, $crowded));
check('with 74 destinations cached, a new browser gets 64', $count === 64, (string) $count);
check('the 64 whose announces are newest', sameSet(queuedAnnounces($db, $crowded), array_slice($newest, -64)));

echo "\n(g) one destination announcing 900 times does not crowd out the others\n";
$chatty = RegFixture::identity();
$chattyHash = '';
for ($i = 0; $i < 900; $i++) {
    $a = AnnounceFixture::announce($chatty, 'lxmf.delivery');
    RegFixture::capture(static fn () => AnnounceFixture::ingest($node, $gateway, $a['raw']));
    $chattyHash = $a['packet_hash_hex'];
}
$accepted = (int) $db->query("SELECT COUNT(*) FROM inbound_packets WHERE packet_type = 1 AND destination_hash_hex = '" . bin2hex(substr(hash('sha256', substr(hash('sha256', 'lxmf.delivery', true), 0, 10) . $chatty['hash'], true), 0, 16)) . "' AND announce_status IN ('validated', 'path_updated')")->fetchColumn();
check('(precondition) its newest accepted announces fill the first chunks (' . $accepted . ' rows)', $accepted > 256 + 512);
$behind = browserRow($node);
firstExchange($node, $behind);
$queued = queuedAnnounces($db, $behind);
check('a new browser gets it once and the 63 destinations announced before it',
    count($queued) === 64 && sameSet(array_diff($queued, array_slice($newest, -63)), [$chattyHash]) && count(array_unique($queued)) === 64,
    count($queued) . ' ' . json_encode(array_values(array_diff($queued, array_slice($newest, -63)))));

echo "\n(f) rows from before the marker\n";
$oldPath = $dir . '/live.sqlite';
if ($mysql === null) {
    $oldDb = new PDO('sqlite:' . $oldPath);
    $oldDb->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    $oldDb->exec((string) file_get_contents(__DIR__ . '/stubs/50c870b_schema.sql'));
} else {
    unset($node, $other, $db);
    dropAllTables();
    $oldDb = RegFixture::db(storageAt($oldPath));
    $oldDb->exec('ALTER TABLE interfaces DROP COLUMN seeded_at');
    $oldDb->exec("UPDATE schema_meta SET fingerprint = 'stage1-1' WHERE meta_key = 'migration'");
}
$oldBrowser = bin2hex(random_bytes(16));
$oldDb->prepare("INSERT INTO interfaces (interface_id, name, session_token, status, metadata_json, created_at, last_seen_at)
                 VALUES (:i, 'browser', :t, 'online', :m, :created, :seen)")
    ->execute([':i' => $oldBrowser, ':t' => bin2hex(random_bytes(32)), ':m' => json_encode(['client' => 'rns-js', 'mode' => 1]), ':created' => time(), ':seen' => time()]);
$migrated = storageAt($oldPath);
$migratedDb = RegFixture::db($migrated);
$oldGateway = row($migrated, RegFixture::pollGatewayMetadata(), 'gateway');
$oldCached = announceThrough($migrated, $oldGateway, 3);
$migratedDb->exec('DELETE FROM outbound_packets');
$migrated->seedInterfaceIfNew($oldBrowser);
check('a row from before the marker is not seeded after the migration', queuedAnnounces($migratedDb, $oldBrowser) === [], json_encode(queuedAnnounces($migratedDb, $oldBrowser)));
$newBrowser = browserRow($migrated);
$migrated->seedInterfaceIfNew($newBrowser);
check('a row registered after the migration is', sameSet(queuedAnnounces($migratedDb, $newBrowser), $oldCached), json_encode(queuedAnnounces($migratedDb, $newBrowser)));

echo "\n$pass passed, $fail failed\n";
exit($fail === 0 ? 0 : 1);
