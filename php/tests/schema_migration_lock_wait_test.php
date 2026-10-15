<?php
declare(strict_types=1);

/**
 * migrate() must not stall the live node on metadata locks. On MySQL and
 * MariaDB a DDL statement waiting for its table's exclusive metadata lock
 * queues every later statement on that table behind it, for as long as
 * lock_wait_timeout allows: a day by default.
 *
 * The suite has no MySQL server, so migrate() runs here with backend mysql
 * on a recording connection: a SQLite file as 50c870b built it
 * (stubs/50c870b_schema.sql, the live nodes' code when Stage 1 was built),
 * behind stubs/mysql_stand_in.php's PDO, which answers the MySQL-only
 * statements migrate() issues (@@SESSION.lock_wait_timeout, SET SESSION,
 * information_schema, SHOW INDEX, ON DUPLICATE KEY, the ENGINE, ALGORITHM
 * and LOCK clauses, an ALTER adding several columns) as MySQL would. It
 * records every statement as issued, with the session's lock_wait_timeout
 * at that moment, and can fail one statement with 1205, MySQL's lock wait
 * timeout. It proves:
 *  (a) the session's value is read, then set to 2, before the first DDL
 *      statement; every DDL statement runs at 2, issued with exec() (none
 *      is prepared, so none can go through executeWithRetry); the value read
 *      is put back after the last one, before the backfill;
 *  (b) interfaces' nine new columns (eight §12, and seeded_at) are added
 *      by one ALTER asking for
 *      ALGORITHM=INSTANT, and each of the seven §12 indexes by a CREATE
 *      [UNIQUE] INDEX asking for ALGORITHM=INPLACE LOCK=NONE; the database
 *      ends with every one of them, and no error;
 *  (c) a re-run issues no ALTER and no CREATE INDEX, and migrateIfNeeded()
 *      then records the version;
 *  (d) a statement that waits out the 2 s (1205) is issued once and stops
 *      the migration: nothing follows it but the value put back, the error
 *      is recorded, no version is recorded, and `index.php migrate`'s report
 *      (runIndexMigrateOn) exits 1, saying the live node keeps its code and
 *      the deploy can be run again; the next run builds the rest;
 *  (e) when the session's value cannot be read, no DDL runs;
 *  (f) on SQLite: no lock_wait_timeout, one ADD COLUMN per statement, and
 *      no MySQL clause;
 *  (g) a DDL statement that fails some other way: an exception other than
 *      PDOException leaves migrate() as before, thrown, through `index.php
 *      migrate` and a request's migrateIfNeeded() alike, and the session's
 *      value is put back on its way out; a PDOException with another code
 *      (1846, no INSTANT for this ALTER) is recorded as before, the run goes
 *      on, `index.php migrate` exits 1 without "stopped at", and the value is
 *      put back after the last DDL statement.
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

/** A SQLite file with the schema (and recorded version) 50c870b's code built. */
function liveDatabase(string $path): PDO
{
    @unlink($path);
    $pdo = new PDO('sqlite:' . $path);
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    $pdo->exec((string) file_get_contents(__DIR__ . '/stubs/50c870b_schema.sql'));
    $pdo->exec("INSERT INTO interfaces (interface_id, name, session_token, metadata_json)
                VALUES ('browser', 'Retichat Web', 't', '{\"client\":\"rns-js\",\"identity_hash\":\"00112233445566778899aabbccddeeff\"}')");

    return $pdo;
}

function isDdl(string $sql): bool
{
    return preg_match('/\A(CREATE|ALTER|DROP|RENAME|TRUNCATE|OPTIMIZE)\b/i', $sql) === 1;
}

/** @return list<int> the positions in $log of the statements matching $regex */
function positions(array $log, string $regex): array
{
    return array_keys(array_filter(array_column($log, 'sql'), static fn (string $sql): bool => preg_match($regex, $sql) === 1));
}

/** @return list<string> */
function statements(array $log, string $regex): array
{
    return array_values(array_filter(array_column($log, 'sql'), static fn (string $sql): bool => preg_match($regex, $sql) === 1));
}

function recordedVersion(PDO $pdo): mixed
{
    return $pdo->query("SELECT fingerprint FROM schema_meta WHERE meta_key = 'migration'")->fetchColumn();
}

/** @return array{0: int, 1: string, 2: string} runIndexMigrateOn()'s exit code, output and errors */
function report(ReticulumPhp\Storage $storage): array
{
    $out = fopen('php://memory', 'w+');
    $err = fopen('php://memory', 'w+');
    $code = ReticulumPhp\runIndexMigrateOn($storage, $out, $err);
    rewind($out);
    rewind($err);

    return [$code, (string) stream_get_contents($out), (string) stream_get_contents($err)];
}

const STAGE1_COLUMNS = ['identity_hash', 'identity_public_key', 'registration_seq', 'registration_proof',
    'claimed_identity_hash', 'previous_session_token_hash', 'superseded_logged_hash', 'refusal_logged_seq',
    // Not §12: seedInterfaceIfNew()'s marker (2026-10-14), also new to a 50c870b database.
    'seeded_at'];
const STAGE1_INDEXES = ['idx_interfaces_identity_hash', 'idx_interfaces_claimed_identity', 'idx_outbound_packets_iface',
    'idx_path_entries_iface', 'idx_reverse_path_received', 'idx_link_transport_received', 'idx_link_transport_outbound'];
const LIVE_VERSION = '08783e676eaffc963b06f372247408bd7503c24a';

/** @return list<string> the §12 columns and indexes the file lacks */
function missingObjects(PDO $pdo): array
{
    $columns = array_column($pdo->query('PRAGMA table_info(interfaces)')->fetchAll(PDO::FETCH_ASSOC), 'name');
    $indexes = array_column($pdo->query("SELECT il.name FROM sqlite_master AS m, pragma_index_list(m.name) AS il WHERE m.type = 'table'")->fetchAll(PDO::FETCH_ASSOC), 'name');

    return array_values(array_merge(array_diff(STAGE1_COLUMNS, $columns), array_diff(STAGE1_INDEXES, $indexes)));
}

$dir = sys_get_temp_dir() . '/reticulum-php-lock-wait-test-' . bin2hex(random_bytes(4));
mkdir($dir, 0775, true);
ini_set('error_log', $dir . '/php-error.log');
ini_set('log_errors', '1');

$version = (new ReflectionMethod(ReticulumPhp\Storage::class, 'schemaVersion'))->invoke(standInStorage($dir . '/v.sqlite', new MysqlStandInPdo($dir . '/v.sqlite')));

// ── (a) the ceiling ──────────────────────────────────────────────────────
echo "(a) every DDL statement runs with lock_wait_timeout at 2 s, put back after\n";
$pathA = $dir . '/a.sqlite';
$plainA = liveDatabase($pathA);
$pdoA = new MysqlStandInPdo($pathA);
$summaryA = standInStorage($pathA, $pdoA)->migrate();
$logA = $pdoA->log;
$ddlA = array_keys(array_filter(array_column($logA, 'sql'), 'isDdl'));
$readA = positions($logA, '/\ASELECT @@SESSION\.lock_wait_timeout\z/');
$setsA = positions($logA, '/\ASET SESSION lock_wait_timeout = /');
check('the session\'s value is read, then set to 2, before the first DDL statement',
    count($readA) === 1 && count($setsA) === 2 && $ddlA !== [] && $logA[$setsA[0]]['sql'] === 'SET SESSION lock_wait_timeout = 2'
    && $readA[0] < $setsA[0] && $setsA[0] < $ddlA[0],
    json_encode(['read' => $readA, 'sets' => $setsA, 'first_ddl' => $ddlA[0] ?? null]));
$atTwo = array_filter($ddlA, static fn (int $i): bool => $logA[$i]['lock_wait'] === 2);
check('every DDL statement (' . count($ddlA) . ') runs at 2 s', $ddlA !== [] && count($atTwo) === count($ddlA),
    json_encode(array_map(static fn (int $i): array => $logA[$i], array_diff($ddlA, array_keys($atTwo)))));
$viaExec = array_filter($ddlA, static fn (int $i): bool => $logA[$i]['via'] === 'exec');
check('each is issued with exec(): none is prepared, so none can go through executeWithRetry', count($viaExec) === count($ddlA));
check('the value read is put back after the last one',
    isset($setsA[1]) && $logA[$setsA[1]]['sql'] === 'SET SESSION lock_wait_timeout = 86400' && $setsA[1] > max($ddlA) && $pdoA->lockWait === 86400,
    json_encode(['sets' => $setsA, 'last_ddl' => max($ddlA)]));
$backfillA = positions($logA, '/\AUPDATE interfaces SET claimed_identity_hash = /');
check('and before the backfill, whose UPDATE runs at the session\'s own value',
    count($backfillA) === 1 && $backfillA[0] > $setsA[1] && $logA[$backfillA[0]]['lock_wait'] === 86400 && ($summaryA['claims_backfilled'] ?? 0) === 1,
    json_encode(['backfill' => $backfillA, 'claims_backfilled' => $summaryA['claims_backfilled'] ?? null]));

// ── (b) one ALTER, and the online algorithms asked for ───────────────────
echo "(b) one ALTER for interfaces' columns; ALGORITHM=INSTANT and INPLACE LOCK=NONE asked for\n";
$altersA = statements($logA, '/\AALTER TABLE /');
$adds = preg_match_all('/ADD COLUMN `(\w+)`/', $altersA[0] ?? '', $added) === false ? [] : $added[1];
check('one ALTER adds interfaces\' nine new columns',
    count($altersA) === 1 && str_starts_with($altersA[0], 'ALTER TABLE `interfaces` ') && $adds === STAGE1_COLUMNS,
    json_encode($altersA));
check('asking for ALGORITHM=INSTANT', str_ends_with($altersA[0] ?? '', ', ALGORITHM=INSTANT'), (string) ($altersA[0] ?? ''));
$indexesA = statements($logA, '/\ACREATE (UNIQUE )?INDEX /');
$indexNames = array_map(static fn (string $sql): string => preg_match('/\ACREATE (?:UNIQUE )?INDEX (\w+) /', $sql, $m) === 1 ? $m[1] : $sql, $indexesA);
$online = array_filter($indexesA, static fn (string $sql): bool => str_ends_with($sql, ') ALGORITHM=INPLACE LOCK=NONE'));
check('each of the seven §12 indexes is one CREATE INDEX asking for ALGORITHM=INPLACE LOCK=NONE',
    $indexNames === STAGE1_INDEXES && count($online) === count($indexesA), json_encode($indexesA));
check('the UNIQUE one too',
    in_array('CREATE UNIQUE INDEX idx_interfaces_identity_hash ON interfaces (identity_hash) ALGORITHM=INPLACE LOCK=NONE', $indexesA, true));
$builtA = array_column($summaryA['built'] ?? [], 'object');
check('no error; the summary counts nine columns and names each object built',
    ($summaryA['errors'] ?? ['?']) === [] && ($summaryA['columns_added'] ?? 0) === 9
    && $builtA === array_merge(['columns interfaces.' . implode(', ', STAGE1_COLUMNS)], array_map(static fn (string $i): string => "index {$i}", STAGE1_INDEXES)),
    json_encode(['errors' => $summaryA['errors'] ?? null, 'built' => $builtA]));
check('the database has every §12 column and index', missingObjects($plainA) === [], json_encode(missingObjects($plainA)));

// ── (c) a re-run takes no lock ───────────────────────────────────────────
echo "(c) a re-run issues no ALTER and no CREATE INDEX\n";
$pdoC = new MysqlStandInPdo($pathA);
$storageC = standInStorage($pathA, $pdoC);
$again = $storageC->migrate();
check('a re-run issues no ALTER and no CREATE INDEX, and builds nothing',
    statements($pdoC->log, '/\A(ALTER |CREATE (UNIQUE )?INDEX )/') === [] && ($again['errors'] ?? ['?']) === [] && ($again['built'] ?? ['?']) === [],
    json_encode(['statements' => statements($pdoC->log, '/\A(ALTER |CREATE (UNIQUE )?INDEX )/'), 'errors' => $again['errors'] ?? null]));
$ddlC = array_keys(array_filter(array_column($pdoC->log, 'sql'), 'isDdl'));
check('only the CREATE TABLE IF NOT EXISTS statements, at 2 s',
    $ddlC !== [] && count(statements($pdoC->log, '/\ACREATE TABLE IF NOT EXISTS /')) === count($ddlC)
    && array_filter($ddlC, static fn (int $i): bool => $pdoC->log[$i]['lock_wait'] !== 2) === [] && $pdoC->lockWait === 86400);
$pdoC->log = [];
$needed = $storageC->migrateIfNeeded();
check('migrateIfNeeded() then records the version',
    !isset($needed['skipped']) && ($needed['errors'] ?? ['?']) === [] && recordedVersion($plainA) === $version,
    json_encode(['recorded' => recordedVersion($plainA), 'errors' => $needed['errors'] ?? null]));
unset($storageC, $pdoC, $pdoA, $plainA);

// ── (d) a statement that waits out the 2 s stops the migration ──────────
echo "(d) a 1205 is issued once and stops the migration; the report says the deploy can be run again\n";
$pathD = $dir . '/d.sqlite';
$plainD = liveDatabase($pathD);
$pdoD = new MysqlStandInPdo($pathD);
$pdoD->timeOut = '/\AALTER TABLE `interfaces` /';
[$codeD, $outD, $errD] = report(standInStorage($pathD, $pdoD));
$alterD = positions($pdoD->log, '/\AALTER TABLE `interfaces` /');
check('the ALTER that waits out the 2 s is issued once, not again', count($alterD) === 1, json_encode($alterD));
$afterD = array_column(array_slice($pdoD->log, ($alterD[0] ?? 0) + 1), 'sql');
check('nothing follows it but the value put back: no other DDL, no index, no backfill',
    $afterD === ['SET SESSION lock_wait_timeout = 86400'] && $pdoD->lockWait === 86400, json_encode($afterD));
check('`index.php migrate`\'s report exits 1 and names the error',
    $codeD === 1 && str_contains($errD, 'migrate error: add_column interfaces.' . implode(', ', STAGE1_COLUMNS) . ': SQLSTATE[HY000]: General error: 1205 ')
    && str_contains($errD, 'migrate: FAILED with 1 error(s); no version recorded'),
    trim($errD));
check('and says where it stopped, that the live node keeps its code, and that the deploy can be run again',
    str_contains($errD, 'migrate: stopped at add_column interfaces.identity_hash, ')
    && str_contains($errD, 'the live node keeps its code, and the deploy can be run again'), trim($errD));
check('nothing was built', count(missingObjects($plainD)) === 16 && !str_contains($outD, 'built '), trim($outD));

$pdoD2 = new MysqlStandInPdo($pathD);
$pdoD2->timeOut = '/\ACREATE UNIQUE INDEX idx_interfaces_identity_hash /';
$stoppedD = standInStorage($pathD, $pdoD2)->migrateIfNeeded();
$uniqueD = positions($pdoD2->log, '/\ACREATE UNIQUE INDEX idx_interfaces_identity_hash /');
check('at the UNIQUE index, a request\'s migrateIfNeeded(): issued once, and no index after it',
    count($uniqueD) === 1 && statements(array_slice($pdoD2->log, $uniqueD[0] + 1), '/\ACREATE /') === [],
    json_encode(array_column(array_slice($pdoD2->log, ($uniqueD[0] ?? 0) + 1), 'sql')));
check('\'lock_wait_timeout\' names it, the error is recorded, the session\'s value put back',
    ($stoppedD['lock_wait_timeout'] ?? null) === 'create_index idx_interfaces_identity_hash' && count($stoppedD['errors'] ?? []) === 1
    && str_contains((string) ($stoppedD['errors'][0] ?? ''), '1205') && $pdoD2->lockWait === 86400,
    json_encode(['lock_wait_timeout' => $stoppedD['lock_wait_timeout'] ?? null, 'errors' => $stoppedD['errors'] ?? null]));
check('and no version is recorded', recordedVersion($plainD) === LIVE_VERSION, (string) recordedVersion($plainD));

$pdoD3 = new MysqlStandInPdo($pathD);
[$codeD3, $outD3, $errD3] = report(standInStorage($pathD, $pdoD3));
preg_match_all('/^built (.+) in [0-9.]+ ms$/m', $outD3, $builtD3);
check('the deploy run again builds the rest and passes the probe',
    $codeD3 === 0 && $builtD3[1] === array_map(static fn (string $i): string => "index {$i}", STAGE1_INDEXES)
    && str_contains($outD3, 'probe passed') && missingObjects($plainD) === [],
    trim($outD3 . ' ' . $errD3));
unset($pdoD, $pdoD2, $pdoD3, $plainD);

// ── (e) no ceiling, no DDL ───────────────────────────────────────────────
echo "(e) when the session's value cannot be read, no DDL runs\n";
$pathE = $dir . '/e.sqlite';
$plainE = liveDatabase($pathE);
$pdoE = new MysqlStandInPdo($pathE);
$pdoE->unreadable = true;
$summaryE = standInStorage($pathE, $pdoE)->migrate();
check('no DDL statement, no SET, no backfill; the migration fails',
    array_filter(array_column($pdoE->log, 'sql'), 'isDdl') === [] && positions($pdoE->log, '/\A(SET |UPDATE )/') === []
    && count($summaryE['errors'] ?? []) === 1 && str_starts_with((string) ($summaryE['errors'][0] ?? ''), 'lock_wait_timeout: '),
    json_encode(['log' => array_column($pdoE->log, 'sql'), 'errors' => $summaryE['errors'] ?? null]));
unset($pdoE, $plainE);

// ── (f) SQLite ───────────────────────────────────────────────────────────
echo "(f) SQLite: no lock_wait_timeout, one ADD COLUMN per statement, no MySQL clause\n";
$pathF = $dir . '/f.sqlite';
$plainF = liveDatabase($pathF);
$pdoF = new MysqlStandInPdo($pathF);
$summaryF = standInStorage($pathF, $pdoF, 'sqlite')->migrate();
check('no lock_wait_timeout read or set', positions($pdoF->log, '/lock_wait_timeout/') === []);
$altersF = statements($pdoF->log, '/\AALTER TABLE /');
$single = array_filter($altersF, static fn (string $sql): bool => substr_count($sql, 'ADD COLUMN') === 1 && !str_contains($sql, 'ALGORITHM') && !str_contains($sql, ' AFTER '));
check('nine ALTERs, one ADD COLUMN each, with no AFTER or ALGORITHM', count($altersF) === 9 && count($single) === 9, json_encode($altersF));
check('no CREATE INDEX carries ALGORITHM or LOCK',
    statements($pdoF->log, '/\ACREATE (UNIQUE )?INDEX .*(ALGORITHM|LOCK)/') === [] && count(statements($pdoF->log, '/\ACREATE (UNIQUE )?INDEX /')) === 7);
check('and it builds the same objects, one column per entry, with no error',
    ($summaryF['errors'] ?? ['?']) === [] && count($summaryF['built'] ?? []) === 16 && missingObjects($plainF) === [],
    json_encode(['errors' => $summaryF['errors'] ?? null, 'built' => array_column($summaryF['built'] ?? [], 'object')]));
unset($pdoF, $plainF);

// ── (g) a DDL statement that fails some other way ───────────────────────
echo "(g) any other failure out of a DDL statement surfaces as before, and the session's value is put back\n";
/** @return Throwable|null what $run threw */
function thrownBy(callable $run): ?Throwable
{
    try {
        $run();
    } catch (Throwable $e) {
        return $e;
    }

    return null;
}
$pathG = $dir . '/g.sqlite';
$plainG = liveDatabase($pathG);
$pdoG = new MysqlStandInPdo($pathG);
$pdoG->throwOn = '/\AALTER TABLE `interfaces` /';
$pdoG->throw = new RuntimeException('stand-in: not a PDOException');
$thrownG = thrownBy(static fn () => standInStorage($pathG, $pdoG)->migrate());
$alterG = positions($pdoG->log, '/\AALTER TABLE `interfaces` /');
check('a RuntimeException out of the interfaces ALTER leaves migrate() as before: the same exception, thrown',
    $thrownG instanceof RuntimeException && $thrownG->getMessage() === 'stand-in: not a PDOException',
    $thrownG === null ? 'nothing thrown' : get_class($thrownG) . ': ' . $thrownG->getMessage());
check('...and on its way out the session\'s value is put back: the one statement after the failed ALTER',
    count($alterG) === 1 && array_column(array_slice($pdoG->log, $alterG[0] + 1), 'sql') === ['SET SESSION lock_wait_timeout = 86400']
    && $pdoG->lockWait === 86400,
    json_encode(['after' => array_column(array_slice($pdoG->log, ($alterG[0] ?? 0) + 1), 'sql'), 'lock_wait' => $pdoG->lockWait]));

// The ALTER runs this time; the UNIQUE index throws.
$pdoG2 = new MysqlStandInPdo($pathG);
$pdoG2->throwOn = '/\ACREATE UNIQUE INDEX idx_interfaces_identity_hash /';
$pdoG2->throw = new RuntimeException('stand-in: not a PDOException');
$thrownG2 = thrownBy(static fn () => standInStorage($pathG, $pdoG2)->migrateIfNeeded());
check('through a request\'s migrateIfNeeded() (an index this time): thrown, the value put back, no version recorded',
    $thrownG2 instanceof RuntimeException && $pdoG2->lockWait === 86400
    && ($pdoG2->log[count($pdoG2->log) - 1]['sql'] ?? '') === 'SET SESSION lock_wait_timeout = 86400'
    && recordedVersion($plainG) === LIVE_VERSION,
    json_encode(['thrown' => $thrownG2?->getMessage(), 'last' => $pdoG2->log[count($pdoG2->log) - 1]['sql'] ?? null, 'recorded' => recordedVersion($plainG)]));

// A later index throws, through `index.php migrate`.
$pdoG3 = new MysqlStandInPdo($pathG);
$pdoG3->throwOn = '/\ACREATE INDEX idx_outbound_packets_iface /';
$pdoG3->throw = new RuntimeException('stand-in: not a PDOException');
$thrownG3 = thrownBy(static fn () => report(standInStorage($pathG, $pdoG3)));
check('through `index.php migrate`: thrown out of the report, the value put back',
    $thrownG3 instanceof RuntimeException && $pdoG3->lockWait === 86400
    && ($pdoG3->log[count($pdoG3->log) - 1]['sql'] ?? '') === 'SET SESSION lock_wait_timeout = 86400',
    json_encode(['thrown' => $thrownG3?->getMessage(), 'last' => $pdoG3->log[count($pdoG3->log) - 1]['sql'] ?? null]));
unset($pdoG, $pdoG2, $pdoG3, $plainG);

$pathG4 = $dir . '/g4.sqlite';
$plainG4 = liveDatabase($pathG4);
$pdoG4 = new MysqlStandInPdo($pathG4);
$pdoG4->throwOn = '/\AALTER TABLE `interfaces` /';
$noInstant = new PDOException('SQLSTATE[0A000]: Feature not supported: 1846 ALGORITHM=INSTANT is not supported. Try ALGORITHM=COPY/INPLACE.');
$noInstant->errorInfo = ['0A000', 1846, 'ALGORITHM=INSTANT is not supported. Try ALGORITHM=COPY/INPLACE.'];
$pdoG4->throw = $noInstant;
[$codeG4, $outG4, $errG4] = report(standInStorage($pathG4, $pdoG4));
check('a PDOException with another code (1846) is recorded as before: `index.php migrate` exits 1 naming it, not "stopped at"',
    $codeG4 === 1 && str_contains($errG4, 'migrate error: add_column interfaces.' . implode(', ', STAGE1_COLUMNS) . ': SQLSTATE[0A000]: Feature not supported: 1846 ')
    && str_contains($errG4, 'migrate: FAILED with ') && !str_contains($errG4, 'stopped at'), trim($errG4));
$ddlG4 = array_keys(array_filter(array_column($pdoG4->log, 'sql'), 'isDdl'));
$setsG4 = positions($pdoG4->log, '/\ASET SESSION lock_wait_timeout = /');
check('...the run goes on to the indexes as before, and the value is put back after its last DDL statement',
    statements($pdoG4->log, '/\ACREATE (UNIQUE )?INDEX /') !== [] && count($setsG4) === 2
    && $pdoG4->log[$setsG4[1]]['sql'] === 'SET SESSION lock_wait_timeout = 86400' && $setsG4[1] > max($ddlG4) && $pdoG4->lockWait === 86400,
    json_encode(['sets' => $setsG4, 'last_ddl' => $ddlG4 === [] ? null : max($ddlG4)]));
unset($pdoG4, $plainG4);

array_map('unlink', glob($dir . '/*') ?: []);
@rmdir($dir);

echo "\n$pass passed, $fail failed\n";
exit($fail === 0 ? 0 : 1);
