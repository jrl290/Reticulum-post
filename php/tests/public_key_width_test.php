<?php
/**
 * A public key is 128 hex characters, and the columns that hold one take it
 * whole; keys a VARCHAR(64) column cut short are repaired by the migration.
 *
 * Until 2026-10-15 a fresh install declared known_destinations.public_key_hex
 * and outbound_packets.destination_public_key_hex VARCHAR(64). On MySQL in
 * strict mode every announce was then refused (1406, data too long), and with
 * an empty sql_mode its key was cut to 64 characters, after which every later
 * announce of that destination was refused: "ANNOUNCE public key conflicts
 * with previously known destination key". A queued packet's cut key failed
 * its proof. retichat.com's tables, built by older code, have VARCHAR(255);
 * selectiv's (MariaDB 11.4) were never checked.
 *
 * Runs the real Storage and real signed announces fed to the real inbound
 * path:
 *   (a) a fresh schema declares both columns VARCHAR(128) (on MySQL, read
 *       from information_schema);
 *   (b) with keys cut to 64 characters as MySQL left them, a destination's
 *       next announce is refused (the bug, as the precondition);
 *   (c) the migration repairs a cut key from the destination's stored
 *       announce, drops a known destination whose announce is gone or does
 *       not give its hash, clears a queued packet's cut key, and leaves a
 *       whole key alone; on MySQL it first widens both columns to 128;
 *   (d) afterwards the destinations' announces are accepted again, and the
 *       dropped ones are known again with their whole key;
 *   (e) another migration finds nothing to repair.
 *
 * Run: php tests/public_key_width_test.php
 * On MySQL (every table in the database is dropped first; there (b) narrows
 * both columns back to VARCHAR(64), as a fresh install of older code had,
 * and stores keys under an empty sql_mode, which cuts them; (c) to (e) run
 * under the server's own sql_mode):
 *   KEY_WIDTH_TEST_MYSQL=user:pass@127.0.0.1:3306/dbname php tests/public_key_width_test.php
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

$dir = sys_get_temp_dir() . '/reticulum-php-key-width-' . bin2hex(random_bytes(4));
mkdir($dir, 0775, true);
register_shutdown_function(static function () use ($dir): void {
    foreach ((array) glob($dir . '/*') as $file) {
        @unlink((string) $file);
    }
    @rmdir($dir);
});

$mysql = getenv('KEY_WIDTH_TEST_MYSQL') ?: null;
if ($mysql !== null) {
    $u = parse_url('mysql://' . $mysql);
    $mysql = [
        'backend' => 'mysql', 'mysql_host' => $u['host'] ?? '127.0.0.1', 'mysql_port' => $u['port'] ?? 3306,
        'mysql_dbname' => ltrim($u['path'] ?? '', '/'), 'mysql_user' => rawurldecode($u['user'] ?? 'root'), 'mysql_pass' => rawurldecode($u['pass'] ?? ''),
    ];
    echo 'MySQL ' . $mysql['mysql_host'] . ':' . $mysql['mysql_port'] . '/' . $mysql['mysql_dbname'] . "\n";
    $admin = new PDO(sprintf('mysql:host=%s;port=%d;dbname=%s', $mysql['mysql_host'], $mysql['mysql_port'], $mysql['mysql_dbname']),
        $mysql['mysql_user'], $mysql['mysql_pass'], [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]);
    echo '  sql_mode: ' . $admin->query('SELECT @@SESSION.sql_mode')->fetchColumn() . "\n";
    foreach ($admin->query('SHOW TABLES')->fetchAll(PDO::FETCH_COLUMN) as $table) {
        $admin->exec("DROP TABLE `{$table}`");
    }
}

$path = $dir . '/node.sqlite';
/** A Storage on the test's database, and its migration's summary. */
function storage(): array
{
    global $mysql, $path;
    $config = RegFixture::config([], $path);
    if ($mysql !== null) {
        $config['storage'] = $mysql;
    }
    $storage = new Storage($config);

    return [$storage, $storage->migrateIfNeeded()];
}

/** @return array<string, string> column => declared type, for the two key columns */
function keyColumnTypes(PDO $db): array
{
    global $mysql;
    $types = [];
    foreach ([['known_destinations', 'public_key_hex'], ['outbound_packets', 'destination_public_key_hex']] as [$table, $column]) {
        if ($mysql !== null) {
            $st = $db->prepare('SELECT COLUMN_TYPE FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = ? AND COLUMN_NAME = ?');
            $st->execute([$table, $column]);
            $types["{$table}.{$column}"] = strtoupper((string) $st->fetchColumn());
        } else {
            $st = $db->prepare('SELECT type FROM pragma_table_info(?) WHERE name = ?');
            $st->execute([$table, $column]);
            $types["{$table}.{$column}"] = strtoupper((string) $st->fetchColumn());
        }
    }

    return $types;
}

function row(Storage $s, array $metadata, string $name): string
{
    [$answer] = RegFixture::capture(static fn () => $s->registerInterface($name, 1000000, 500, $metadata));

    return (string) $answer['interface_id'];
}

/** Feed one announce through $iface; its stored verdict [status, reason]. */
function announce(Storage $s, PDO $db, string $iface, array $identity): array
{
    $a = AnnounceFixture::announce($identity, 'lxmf.delivery');
    RegFixture::capture(static fn () => AnnounceFixture::ingest($s, $iface, $a['raw']));
    $st = $db->prepare('SELECT announce_status, announce_reason FROM inbound_packets WHERE packet_hash_hex = ? ORDER BY packet_record_id DESC LIMIT 1');
    $st->execute([$a['packet_hash_hex']]);
    $row = $st->fetch(PDO::FETCH_NUM) ?: ['?', '?'];

    return ['status' => (string) $row[0], 'reason' => (string) $row[1], 'dest' => $a['dest_hex'], 'hash' => $a['packet_hash_hex']];
}

function knownKey(PDO $db, string $dest): string|false|null
{
    $st = $db->prepare('SELECT public_key_hex FROM known_destinations WHERE destination_hash_hex = ?');
    $st->execute([$dest]);
    $row = $st->fetch(PDO::FETCH_NUM);

    return $row === false ? false : $row[0];
}

function accepted(array $verdict): bool
{
    return in_array($verdict['status'], ['validated', 'path_updated'], true);
}

echo "\n(a) a fresh schema\n";
[$node, $summary] = storage();
$db = RegFixture::db($node);
check('declares both key columns VARCHAR(128)',
    keyColumnTypes($db) === ['known_destinations.public_key_hex' => 'VARCHAR(128)', 'outbound_packets.destination_public_key_hex' => 'VARCHAR(128)'],
    json_encode(keyColumnTypes($db)));

echo "\n(b) keys cut to 64 characters\n";
// On MySQL, the fresh install of older code, under an empty sql_mode (a
// strict one refuses the keys instead): every key it stores is cut, the
// "whole" one too.
function cutting(PDO $db): void
{
    global $mysql;
    if ($mysql !== null) {
        $db->exec("SET SESSION sql_mode = ''");
    }
}
if ($mysql !== null) {
    $db->exec('ALTER TABLE known_destinations MODIFY public_key_hex VARCHAR(64) DEFAULT NULL');
    $db->exec('ALTER TABLE outbound_packets MODIFY destination_public_key_hex VARCHAR(64) DEFAULT NULL');
    cutting($db);
}
$gateway = row($node, RegFixture::pollGatewayMetadata(), 'gateway');
$browser = row($node, ['client' => 'rns-js', 'mode' => 1], 'browser');
$ids = ['repairable' => RegFixture::identity(), 'announce gone' => RegFixture::identity(), 'announce foreign' => RegFixture::identity(), 'whole' => RegFixture::identity()];
$first = [];
foreach ($ids as $who => $identity) {
    $first[$who] = announce($node, $db, $gateway, $identity);
}
check('(precondition) each first announce is accepted', array_filter($first, static fn (array $v): bool => !accepted($v)) === [], json_encode($first));
// What MySQL left: the first 64 characters of each key but the whole one.
$cut = $db->prepare('UPDATE known_destinations SET public_key_hex = SUBSTR(public_key_hex, 1, 64) WHERE destination_hash_hex = ?');
foreach (['repairable', 'announce gone', 'announce foreign'] as $who) {
    $cut->execute([$first[$who]['dest']]);
}
$db->prepare("DELETE FROM inbound_packets WHERE destination_hash_hex = ?")->execute([$first['announce gone']['dest']]);
$db->prepare('UPDATE known_destinations SET packet_hash_hex = ? WHERE destination_hash_hex = ?')
    ->execute([$first['repairable']['hash'], $first['announce foreign']['dest']]);
$db->prepare('UPDATE outbound_packets SET destination_public_key_hex = SUBSTR(destination_public_key_hex, 1, 64) WHERE destination_hash_hex = ?')
    ->execute([$first['repairable']['dest']]);
$cutQueued = (int) $db->query('SELECT COUNT(*) FROM outbound_packets WHERE LENGTH(destination_public_key_hex) = 64')->fetchColumn();
check('(precondition) a packet queued for the browser carries a cut key', $cutQueued >= 1, (string) $cutQueued);
// A new request: the Storage that fed the first announces keeps their keys in a cache.
unset($node, $db);
[$node] = storage();
$db = RegFixture::db($node);
cutting($db);
$refused = announce($node, $db, $gateway, $ids['repairable']);
check('(precondition) the next announce of a destination with a cut key is refused',
    $refused['status'] === 'invalid' && str_contains($refused['reason'], 'conflicts with previously known destination key'), json_encode($refused));

echo "\n(c) the migration\n";
$db->exec("UPDATE schema_meta SET fingerprint = 'seed-once-1' WHERE meta_key = 'migration'");
unset($node, $db);
[$node, $summary] = storage();
$db = RegFixture::db($node);
check('runs with no error', ($summary['errors'] ?? ['?']) === [], json_encode($summary['errors'] ?? null));
if ($mysql !== null) {
    check('widens both columns to VARCHAR(128)',
        keyColumnTypes($db) === ['known_destinations.public_key_hex' => 'VARCHAR(128)', 'outbound_packets.destination_public_key_hex' => 'VARCHAR(128)'],
        json_encode(keyColumnTypes($db)));
}
$cutRepairable = $mysql === null ? 1 : 2;
check("repairs {$cutRepairable} key(s), drops two known destinations, clears the queued cut keys",
    ($summary['public_keys'] ?? null) === ['repaired' => $cutRepairable, 'dropped' => 2, 'cleared' => $cutQueued], json_encode($summary['public_keys'] ?? null));
check("the repaired key is the destination's whole key", knownKey($db, $first['repairable']['dest']) === $ids['repairable']['public_key_hex'],
    (string) knownKey($db, $first['repairable']['dest']));
check('the known destination whose announce is gone is dropped', knownKey($db, $first['announce gone']['dest']) === false);
check("the one whose stored announce is another destination's is dropped", knownKey($db, $first['announce foreign']['dest']) === false);
check($mysql === null ? 'a whole key is left alone' : 'the key MySQL cut on its way in is whole again', knownKey($db, $first['whole']['dest']) === $ids['whole']['public_key_hex']);
check('no queued packet carries a cut key',
    (int) $db->query('SELECT COUNT(*) FROM outbound_packets WHERE destination_public_key_hex IS NOT NULL AND LENGTH(destination_public_key_hex) <> 128')->fetchColumn() === 0);

echo "\n(d) afterwards\n";
foreach ($ids as $who => $identity) {
    $v = announce($node, $db, $gateway, $identity);
    check("the {$who} destination's next announce is accepted", accepted($v), json_encode($v));
    check("and its known key is whole", knownKey($db, $v['dest']) === $identity['public_key_hex'], (string) knownKey($db, $v['dest']));
}

echo "\n(e) another migration\n";
$again = $node->migrate();
check('finds nothing to repair or widen', ($again['errors'] ?? ['?']) === [] && !isset($again['public_keys']) && !isset($again['columns_widened']),
    json_encode(['errors' => $again['errors'] ?? null, 'public_keys' => $again['public_keys'] ?? null, 'widened' => $again['columns_widened'] ?? null]));

echo "\n$pass passed, $fail failed\n";
exit($fail === 0 ? 0 : 1);
