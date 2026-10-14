<?php
declare(strict_types=1);

/**
 * The storage reclaim's OPTIMIZE TABLE must not stall the live node on
 * metadata locks. For InnoDB it is a rebuild (ALTER TABLE ... FORCE), and on
 * MySQL and MariaDB one waiting for its table's exclusive metadata lock
 * queues every later statement on that table behind it, for as long as
 * lock_wait_timeout allows: a day by default.
 *
 * The suite has no MySQL server, so the reclaim runs here with backend mysql
 * on stubs/mysql_stand_in.php's recording connection, over a SQLite file the
 * current code built, with the sizes storageFootprint() reads put in
 * stand_in_table_sizes: inbound_packets and outbound_packets qualify for a
 * rebuild, packet_hashes does not. It proves:
 *  (a) `index.php reclaim` (reclaimStorage()) reads the session's
 *      lock_wait_timeout, sets it to 2 before the first OPTIMIZE, runs each
 *      OPTIMIZE once at 2 and puts the value back after the last; ANALYZE
 *      TABLE runs at the session's own value; both tables are reported
 *      reclaimed and nothing is logged;
 *  (b) a table whose OPTIMIZE waits out the 2 s, answered as MySQL answers
 *      it (an error row, then status "Operation failed"), is logged naming
 *      the table and the 2 s wait, is not reported reclaimed and is not
 *      retried; the next table is still rebuilt, and the value is put back;
 *  (c) the same when the wait comes back as an error of the statement (1205);
 *  (d) any other failure is logged as reclaim logged its failures before,
 *      with the server's words, and is not reported reclaimed;
 *  (e) when the session's value cannot be read, no OPTIMIZE runs, and each
 *      table is logged as not run;
 *  (f) `index.php once` reaches the same rebuilds through
 *      enforceStorageBudget(), under the same 2 s;
 *  (g) on SQLite the reclaim is a VACUUM, with no lock_wait_timeout.
 */

$root = dirname(__DIR__);
require_once $root . '/src/lib/database.php';
require_once $root . '/src/index.php';
require_once __DIR__ . '/stubs/mysql_stand_in.php';

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

const RECLAIMED = ['inbound_packets', 'outbound_packets'];
const LOCK_WAIT_ROWS = [
    ['note', 'Table does not support optimize, doing recreate + analyze instead'],
    ['error', 'Lock wait timeout exceeded; try restarting transaction'],
    ['status', 'Operation failed'],
];

/** A database the current code built, with the table sizes the footprint reads. */
function nodeDatabase(string $path): void
{
    foreach (['', '-wal', '-shm'] as $suffix) {
        @unlink($path . $suffix);
    }
    $built = new ReticulumPhp\Storage(['storage' => ['backend' => 'sqlite', 'sqlite_path' => $path, 'log_path' => dirname($path) . '/router.log']]);
    $built->migrateIfNeeded();
    unset($built);
    $pdo = new PDO('sqlite:' . $path);
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    $pdo->exec('CREATE TABLE stand_in_table_sizes (table_name TEXT, data_length INTEGER, index_length INTEGER, data_free INTEGER)');
    $insert = $pdo->prepare('INSERT INTO stand_in_table_sizes VALUES (?, ?, ?, ?)');
    foreach (['inbound_packets' => 300_000_000, 'outbound_packets' => 90_000_000, 'packet_hashes' => 1_000_000] as $table => $free) {
        $insert->execute([$table, 20_000_000, 2_000_000, $free]);
    }
}

/** @return array{0: MysqlStandInPdo, 1: ReticulumPhp\Storage} */
function node(string $path, string $backend = 'mysql', array $config = []): array
{
    nodeDatabase($path);
    $pdo = new MysqlStandInPdo($path);

    return [$pdo, standInStorage($path, $pdo, $backend, $config)];
}

/** @return list<int> the positions in $log of the statements matching $regex */
function positions(array $log, string $regex): array
{
    return array_keys(array_filter(array_column($log, 'sql'), static fn (string $sql): bool => preg_match($regex, $sql) === 1));
}

/** @return list<array{sql: string, via: string, lock_wait: int}> */
function entries(array $log, string $regex): array
{
    return array_values(array_filter($log, static fn (array $entry): bool => preg_match($regex, $entry['sql']) === 1));
}

/** What error_log() wrote since the last call. */
function logged(): string
{
    $path = (string) ini_get('error_log');
    $text = (string) @file_get_contents($path);
    @file_put_contents($path, '');

    return $text;
}

/** The statements of one reclaim, from the session's read to the value put back, in order. */
function ceilingOrder(array $log): array
{
    $read = positions($log, '/\ASELECT @@SESSION\.lock_wait_timeout\z/');
    $set = positions($log, '/\ASET SESSION lock_wait_timeout = 2\z/');
    $back = positions($log, '/\ASET SESSION lock_wait_timeout = 86400\z/');
    $optimize = positions($log, '/\AOPTIMIZE TABLE /');

    return ['read' => $read, 'set' => $set, 'optimize' => $optimize, 'back' => $back];
}

function ceilingHolds(array $log): bool
{
    $o = ceilingOrder($log);
    if (count($o['read']) !== 1 || count($o['set']) !== 1 || count($o['back']) !== 1 || $o['optimize'] === []) {
        return false;
    }

    return $o['read'][0] < $o['set'][0] && $o['set'][0] < min($o['optimize']) && max($o['optimize']) < $o['back'][0]
        && array_unique(array_column(entries($log, '/\AOPTIMIZE TABLE /'), 'lock_wait')) === [2];
}

$dir = sys_get_temp_dir() . '/reticulum-php-reclaim-lock-wait-test-' . bin2hex(random_bytes(4));
mkdir($dir, 0775, true);
register_shutdown_function(static function () use ($dir): void {
    foreach (glob($dir . '/*') ?: [] as $file) {
        @unlink($file);
    }
    @rmdir($dir);
});
ini_set('error_log', $dir . '/php-error.log');
ini_set('log_errors', '1');

echo "(a) `index.php reclaim` rebuilds each table once, at a 2 s lock wait, and puts the session's value back\n";
[$pdo, $storage] = node($dir . '/a.sqlite');
logged();
$summary = $storage->reclaimStorage();
$log = logged();
check('both qualifying tables are rebuilt and reported, packet_hashes is not',
    $summary['storage_reclaimed_tables'] === RECLAIMED, json_encode($summary['storage_reclaimed_tables']));
check('the value is read, set to 2 before the first OPTIMIZE, and put back after the last; each OPTIMIZE runs at 2',
    ceilingHolds($pdo->log), json_encode(ceilingOrder($pdo->log)));
check('each OPTIMIZE is issued once, by query()',
    array_column(entries($pdo->log, '/\AOPTIMIZE TABLE /'), 'sql') === ['OPTIMIZE TABLE `inbound_packets`', 'OPTIMIZE TABLE `outbound_packets`']
    && array_unique(array_column(entries($pdo->log, '/\AOPTIMIZE TABLE /'), 'via')) === ['query'],
    json_encode(entries($pdo->log, '/\AOPTIMIZE TABLE /')));
check('ANALYZE TABLE and the footprint reads run at the session\'s own value',
    entries($pdo->log, '/\AANALYZE TABLE /') !== []
    && array_unique(array_column(entries($pdo->log, '/\AANALYZE TABLE |information_schema/'), 'lock_wait')) === [86400],
    json_encode(entries($pdo->log, '/\AANALYZE TABLE /')));
check('the session ends at its own value, and nothing is logged', $pdo->lockWait === 86400 && trim($log) === '', $log);

echo "(b) an OPTIMIZE that waits out the 2 s, answered as rows, is logged and not retried; the next table is rebuilt\n";
[$pdo, $storage] = node($dir . '/b.sqlite');
$pdo->optimizeAnswers['inbound_packets'] = LOCK_WAIT_ROWS;
logged();
$summary = $storage->reclaimStorage();
$log = logged();
check('logged as reclaim logs a failure, naming the table and the 2 s wait',
    str_contains($log, "ReticulumPhp: OPTIMIZE TABLE failed on inbound_packets: it waited 2 s for the table's metadata lock and gave up, so the table was not rebuilt (Lock wait timeout exceeded; try restarting transaction)"),
    $log);
check('...not reported reclaimed; outbound_packets still is', $summary['storage_reclaimed_tables'] === ['outbound_packets'],
    json_encode($summary['storage_reclaimed_tables']));
check('...its OPTIMIZE issued once, never retried',
    count(positions($pdo->log, '/\AOPTIMIZE TABLE `inbound_packets`\z/')) === 1, json_encode(array_column($pdo->log, 'sql')));
check('...and the value is put back after the last OPTIMIZE', ceilingHolds($pdo->log) && $pdo->lockWait === 86400,
    json_encode(ceilingOrder($pdo->log)));

echo "(c) the same when the wait comes back as an error of the statement (1205)\n";
[$pdo, $storage] = node($dir . '/c.sqlite');
$pdo->timeOut = '/\AOPTIMIZE TABLE `outbound_packets`\z/';
logged();
$summary = $storage->reclaimStorage();
$log = logged();
check('logged naming the table and the 2 s wait',
    str_contains($log, "ReticulumPhp: OPTIMIZE TABLE failed on outbound_packets: it waited 2 s for the table's metadata lock and gave up, so the table was not rebuilt (SQLSTATE[HY000]: General error: 1205 Lock wait timeout exceeded; try restarting transaction)"),
    $log);
check('...not reported reclaimed; inbound_packets is', $summary['storage_reclaimed_tables'] === ['inbound_packets'],
    json_encode($summary['storage_reclaimed_tables']));
check('...issued once, and the value is put back',
    count(positions($pdo->log, '/\AOPTIMIZE TABLE `outbound_packets`\z/')) === 1 && ceilingHolds($pdo->log) && $pdo->lockWait === 86400,
    json_encode(ceilingOrder($pdo->log)));

echo "(d) any other failure is logged with the server's words, and not reported reclaimed\n";
[$pdo, $storage] = node($dir . '/d.sqlite');
$pdo->optimizeAnswers['inbound_packets'] = [['Error', "Table 'node.inbound_packets' doesn't exist"], ['status', 'Operation failed']];
logged();
$summary = $storage->reclaimStorage();
$log = logged();
check('logged as before: "OPTIMIZE TABLE failed on <table>: <the server\'s words>", with no 2 s wait in it',
    str_contains($log, "ReticulumPhp: OPTIMIZE TABLE failed on inbound_packets: Table 'node.inbound_packets' doesn't exist\n")
    && !str_contains($log, '2 s'), $log);
check('...not reported reclaimed', $summary['storage_reclaimed_tables'] === ['outbound_packets'],
    json_encode($summary['storage_reclaimed_tables']));

echo "(e) when the session's value cannot be read, no OPTIMIZE runs\n";
[$pdo, $storage] = node($dir . '/e.sqlite');
$pdo->unreadable = true;
logged();
$summary = $storage->reclaimStorage();
$log = logged();
check('no OPTIMIZE and no SET', positions($pdo->log, '/\AOPTIMIZE TABLE |\ASET SESSION /') === [],
    json_encode(array_column($pdo->log, 'sql')));
check('nothing reported reclaimed, each table logged as not run',
    $summary['storage_reclaimed_tables'] === []
    && str_contains($log, 'ReticulumPhp: OPTIMIZE TABLE failed on inbound_packets: not run, lock_wait_timeout: ')
    && str_contains($log, 'ReticulumPhp: OPTIMIZE TABLE failed on outbound_packets: not run, lock_wait_timeout: '), $log);

echo "(f) `index.php once` reaches the same rebuilds through enforceStorageBudget(), under the same 2 s\n";
[$pdo, $storage] = node($dir . '/f.sqlite');
$summary = [];
$storage->enforceStorageBudget(PHP_INT_MAX, $storage->storageFootprint('mysql', true), 'mysql', true, $summary);
check('both tables rebuilt, each once at 2, the value put back',
    ($summary['storage_reclaimed_tables'] ?? null) === RECLAIMED && ceilingHolds($pdo->log) && $pdo->lockWait === 86400,
    json_encode([$summary['storage_reclaimed_tables'] ?? null, ceilingOrder($pdo->log)]));

echo "(g) on SQLite the reclaim is a VACUUM, with no lock_wait_timeout\n";
[$pdo, $storage] = node($dir . '/g.sqlite', 'sqlite', ['maintenance' => ['storage_reclaim_min_free_bytes' => 0]]);
$summary = $storage->reclaimStorage();
check('VACUUM, and no lock_wait_timeout read or set',
    $summary['storage_reclaimed_tables'] === ['sqlite:vacuum'] && positions($pdo->log, '/\AVACUUM\z/') !== []
    && positions($pdo->log, '/lock_wait_timeout|\AOPTIMIZE /') === [], json_encode(array_column($pdo->log, 'sql')));

echo "\n$pass passed, $fail failed\n";
exit($fail === 0 ? 0 : 1);
