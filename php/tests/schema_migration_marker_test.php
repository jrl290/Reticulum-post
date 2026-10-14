<?php
declare(strict_types=1);

/**
 * migrateIfNeeded() must run the schema migration once per (schema version,
 * database) and then skip it: until 2026-09-24 migrate() ran on every
 * request, ~60 statements before any packet was touched.
 *
 * Stage 1 (REGISTRATION-STAGE1.md §12, §13) adds, each on a database as
 * 50c870b's code built it (stubs/50c870b_schema.sql: the commit both live
 * nodes' /health named when Stage 1 was built; the spec's c37b08f is one
 * index older):
 *  (e) §12's objects, the UNIQUE index enforced, the migration clean;
 *  (f) the claim backfill (rns-js only, top-level 32 lower-case hex,
 *      idempotent);
 *  (g) the version is a literal: with schema_meta holding the SHA-1 of the
 *      deployed trait file (what old cached code records after a swap)
 *      migrateIfNeeded() still builds §12's objects; an older version
 *      recorded migrates, its own skips;
 *  (h) schema_migrated: false before, true after, and false after one
 *      failed statement or with the UNIQUE index missing;
 *  (i) `php index.php migrate --project-root <dir>` builds every object and
 *      records nothing, and a migrate() after it adds nothing;
 *  (j) the guard: the pair (version, SHA-1 of the trait with the literal
 *      masked) is pinned, so a change to the trait without a new version
 *      fails.
 */

$root = dirname(__DIR__);
require_once $root . '/src/lib/database.php';
require_once $root . '/src/index.php';

// (j)'s pinned pair. A change to request_schema_trait.php changes the hash:
// if the change alters what migrate() builds, raise schemaVersion() too, so
// every database that recorded the old version migrates again; then pin the
// new pair here.
const PINNED_SCHEMA_VERSION = 'stage1-1';
const PINNED_SCHEMA_TRAIT_MASKED_SHA1 = 'bbf57ccac703771695c0cbf3414f389fb022a163';

$dir = sys_get_temp_dir() . '/reticulum-php-marker-test-' . bin2hex(random_bytes(4));
mkdir($dir, 0775, true);
$queryLog = $dir . '/queries.jsonl';
putenv('RETICULUM_PHP_QUERY_LOG=' . $queryLog);
ini_set('error_log', $dir . '/php-error.log');
ini_set('log_errors', '1');

$config = [
    'storage' => [
        'backend'     => 'sqlite',
        'sqlite_path' => $dir . '/node.sqlite',
        'log_path'    => $dir . '/router.log',
    ],
];

function schemaStatements(): int
{
    $n = 0;
    foreach (ReticulumPhp\CountingPdo::$counts as $sql => $count) {
        if (preg_match('/^(CREATE|ALTER)\b/i', $sql)) {
            $n += $count;
        }
    }
    return $n;
}

$failures = 0;
$check = static function (bool $ok, string $what) use (&$failures): void {
    echo ($ok ? 'ok   ' : 'FAIL ') . $what . "\n";
    if (!$ok) {
        $failures++;
    }
};

// First bootstrap on a fresh database: the migration runs and leaves a marker.
$storage = new ReticulumPhp\Storage($config);
$first = $storage->migrateIfNeeded();
$created = schemaStatements();
$check(!isset($first['skipped']), 'first bootstrap runs the migration');
$check($created >= 20, "first bootstrap issued schema statements ($created)");
$pdo = new PDO('sqlite:' . $config['storage']['sqlite_path']);
$recorded = $pdo->query("SELECT fingerprint FROM schema_meta WHERE meta_key = 'migration'")->fetchColumn();
$check($recorded === PINNED_SCHEMA_VERSION, 'the schema version was recorded inside the database: ' . var_export($recorded, true));

// Second bootstrap (a new request): nothing but the marker read.
ReticulumPhp\CountingPdo::$counts = [];
ReticulumPhp\CountingPdo::$total = 0;
$storage2 = new ReticulumPhp\Storage($config);
$second = $storage2->migrateIfNeeded();
$check(($second['skipped'] ?? false) === true, 'second bootstrap skips the migration');
$check(schemaStatements() === 0, 'second bootstrap issued no schema statements');
$check(ReticulumPhp\CountingPdo::$total <= 6, 'second bootstrap issued only the connection pragmas and one lookup (' . ReticulumPhp\CountingPdo::$total . ')');

// A stale fingerprint (schema source changed) runs the migration again.
$pdo->exec("UPDATE schema_meta SET fingerprint = 'stale' WHERE meta_key = 'migration'");
ReticulumPhp\CountingPdo::$counts = [];
$storage3 = new ReticulumPhp\Storage($config);
$third = $storage3->migrateIfNeeded();
$check(!isset($third['skipped']), 'a stale fingerprint runs the migration again');
$check($pdo->query("SELECT fingerprint FROM schema_meta WHERE meta_key = 'migration'")->fetchColumn() !== 'stale', 'and rewrites the fingerprint');

// A recreated database (staging wipes its SQLite file) migrates again.
unset($storage, $storage2, $storage3, $pdo);
unlink($config['storage']['sqlite_path']);
$storage4 = new ReticulumPhp\Storage($config);
$fourth = $storage4->migrateIfNeeded();
$check(!isset($fourth['skipped']), 'a recreated database runs the migration again');

// Explicit migrate() is untouched (the initialize path forces it).
$forced = $storage4->migrate();
$check(isset($forced['tables_created']), 'migrate() still runs unconditionally when called directly');
unset($storage4);

// ── Stage 1 ───────────────────────────────────────────────────────────────

/** A SQLite file with the schema (and recorded version) the live nodes' code, 50c870b, built. */
function liveDatabase(string $path): PDO
{
    @unlink($path);
    $pdo = new PDO('sqlite:' . $path);
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    $pdo->exec((string) file_get_contents(__DIR__ . '/stubs/50c870b_schema.sql'));

    return $pdo;
}

function storageOn(string $path): ReticulumPhp\Storage
{
    return new ReticulumPhp\Storage(['storage' => ['backend' => 'sqlite', 'sqlite_path' => $path, 'log_path' => dirname($path) . '/router.log']]);
}

function recordedVersion(PDO $pdo): mixed
{
    return $pdo->query("SELECT fingerprint FROM schema_meta WHERE meta_key = 'migration'")->fetchColumn();
}

/** @return array<string, array{type: string, notnull: int, dflt_value: mixed}> */
function columnsOf(PDO $pdo, string $table): array
{
    $columns = [];
    foreach ($pdo->query("PRAGMA table_info({$table})")->fetchAll(PDO::FETCH_ASSOC) as $row) {
        $columns[$row['name']] = ['type' => strtoupper((string) $row['type']), 'notnull' => (int) $row['notnull'], 'dflt_value' => $row['dflt_value']];
    }
    return $columns;
}

/** @return array{unique: int, columns: list<string>}|null */
function indexOf(PDO $pdo, string $table, string $index): ?array
{
    foreach ($pdo->query("PRAGMA index_list({$table})")->fetchAll(PDO::FETCH_ASSOC) as $row) {
        if ($row['name'] === $index) {
            $columns = array_column($pdo->query("PRAGMA index_info({$index})")->fetchAll(PDO::FETCH_ASSOC), 'name');
            return ['unique' => (int) $row['unique'], 'columns' => $columns];
        }
    }
    return null;
}

$stage1Columns = [
    'identity_hash'               => ['VARCHAR(32)', 0, 'NULL'],
    'identity_public_key'         => ['VARCHAR(128)', 0, 'NULL'],
    'registration_seq'            => ['BIGINT', 1, '0'],
    'registration_proof'          => ['VARCHAR(16)', 1, "'none'"],
    'claimed_identity_hash'       => ['VARCHAR(32)', 0, 'NULL'],
    'previous_session_token_hash' => ['VARCHAR(64)', 0, 'NULL'],
    'superseded_logged_hash'      => ['VARCHAR(64)', 1, "''"],
    'refusal_logged_seq'          => ['BIGINT', 1, '-1'],
];
$stage1Indexes = [
    'idx_interfaces_identity_hash'    => ['interfaces', 1, ['identity_hash']],
    'idx_interfaces_claimed_identity' => ['interfaces', 0, ['claimed_identity_hash']],
    'idx_outbound_packets_iface'      => ['outbound_packets', 0, ['interface_id', 'acked_at']],
    'idx_path_entries_iface'          => ['path_entries', 0, ['interface_id']],
    'idx_reverse_path_received'       => ['reverse_path_entries', 0, ['received_interface_id']],
    'idx_link_transport_received'     => ['link_transport_entries', 0, ['received_interface_id']],
    'idx_link_transport_outbound'     => ['link_transport_entries', 0, ['outbound_interface_id']],
];
$stage1Built = array_merge(
    array_map(static fn (string $c): string => "column interfaces.{$c}", array_keys($stage1Columns)),
    array_map(static fn (string $i): string => "index {$i}", array_keys($stage1Indexes))
);
$objectsPresent = static function (PDO $pdo) use ($stage1Columns, $stage1Indexes): array {
    $missing = [];
    $columns = columnsOf($pdo, 'interfaces');
    foreach ($stage1Columns as $name => [$type, $notnull, $default]) {
        $have = $columns[$name] ?? null;
        if ($have === null || $have['type'] !== $type || $have['notnull'] !== $notnull || strtoupper((string) ($have['dflt_value'] ?? 'NULL')) !== strtoupper($default)) {
            $missing[] = "column {$name} " . json_encode($have);
        }
    }
    foreach ($stage1Indexes as $name => [$table, $unique, $cols]) {
        $have = indexOf($pdo, $table, $name);
        if ($have === null || $have['unique'] !== $unique || $have['columns'] !== $cols) {
            $missing[] = "index {$name} " . json_encode($have);
        }
    }
    return $missing;
};

// ── (e) §12's objects on the live nodes' database ────────────────────────
echo "(e) a 50c870b database gets §12's objects, cleanly\n";
$livePath = $dir . '/50c870b.sqlite';
$live = liveDatabase($livePath);
$liveVersion = recordedVersion($live);
$check(is_string($liveVersion) && preg_match('/\A[0-9a-f]{40}\z/', $liveVersion) === 1, 'the 50c870b database records the SHA-1 its code recorded');
$check(indexOf($live, 'inbound_packets', 'idx_inbound_packets_hash') !== null, 'it already has bdb65f7\'s idx_inbound_packets_hash, as the live nodes do');
$claim = 'deadbeefcafef00d0123456789abcdef';
$oldRows = [
    'browser'          => '{"client":"rns-js","implementation":"PostInterface","mode":1,"identity_hash":"' . $claim . '"}',
    'browser-upper'    => '{"client":"rns-js","mode":1,"identity_hash":"' . strtoupper($claim) . '"}',
    'browser-short'    => '{"client":"rns-js","mode":1,"identity_hash":"' . substr($claim, 0, 31) . '"}',
    'browser-nested'   => '{"client":"rns-js","wrap":{"identity_hash":"' . $claim . '"}}',
    'browser-none'     => '{"client":"rns-js","mode":1}',
    'gateway-claims'   => '{"client":"rns-post-interface","mode":6,"identity_hash":"' . $claim . '"}',
    'peer'             => '{"client":"reticulum-php","peer_url":"https://peer.example/reticulum"}',
    'not-json'         => 'not json',
];
$insert = $live->prepare("INSERT INTO interfaces (interface_id, name, session_token, bitrate, mtu, status, metadata_json, created_at, last_seen_at)
                          VALUES (?, ?, ?, 1000000, 500, 'online', ?, 1, 1)");
foreach ($oldRows as $id => $metadata) {
    $insert->execute([$id, $id, 'token-' . $id, $metadata]);
}
$check($objectsPresent($live) !== [], 'before: none of §12\'s objects is there');
$migrated = storageOn($livePath);
$check($migrated->schemaMigrated() === false, '(h) schema_migrated is false before the migration');
$summary = $migrated->migrateIfNeeded();
$check(!isset($summary['skipped']) && ($summary['errors'] ?? ['?']) === [], 'the migration of a 50c870b database has no errors: ' . json_encode($summary['errors'] ?? null));
$missing = $objectsPresent($live);
$check($missing === [], 'every §12 object is there, with its type, default and index columns: ' . implode('; ', $missing));
$built = array_column($summary['built'] ?? [], 'object');
$check($built === $stage1Built, 'it builds exactly §12\'s objects, each listed in the summary, and nothing else: ' . implode(', ', $built));
$check(recordedVersion($live) === PINNED_SCHEMA_VERSION, 'and records this code\'s version');
$check($migrated->schemaMigrated() === true, '(h) schema_migrated is true after it');
$rows = $live->query('SELECT interface_id, registration_proof, registration_seq, refusal_logged_seq, superseded_logged_hash, identity_hash, metadata_json FROM interfaces ORDER BY interface_id')->fetchAll(PDO::FETCH_ASSOC);
$check(count($rows) === count($oldRows), 'every row survives');
$check(array_unique(array_column($rows, 'registration_proof')) === ['none'], 'every existing row is registration_proof none');
$check(array_unique(array_map('intval', array_column($rows, 'registration_seq'))) === [0]
    && array_unique(array_map('intval', array_column($rows, 'refusal_logged_seq'))) === [-1]
    && array_unique(array_column($rows, 'superseded_logged_hash')) === ['']
    && array_unique(array_column($rows, 'identity_hash')) === [null], 'with count 0, refusal_logged_seq -1, no superseded hash, no identity_hash');
$live->exec("UPDATE interfaces SET identity_hash = '{$claim}' WHERE interface_id = 'browser'");
try {
    $live->exec("UPDATE interfaces SET identity_hash = '{$claim}' WHERE interface_id = 'peer'");
    $check(false, 'the UNIQUE index refuses a second row with one identity_hash');
} catch (PDOException $e) {
    $check(str_contains($e->getMessage(), 'UNIQUE'), 'the UNIQUE index refuses a second row with one identity_hash');
}
$live->exec("UPDATE interfaces SET identity_hash = NULL WHERE interface_id = 'browser'");
$check((int) $live->query('SELECT COUNT(*) FROM interfaces WHERE identity_hash IS NULL')->fetchColumn() === count($oldRows), 'and allows every legacy row its NULL');

// ── (f) the backfill, and the claim filled at first authentication ──────
echo "(f) the claim backfill: rns-js only, exact shape, idempotent\n";
$claims = $live->query('SELECT interface_id, claimed_identity_hash FROM interfaces')->fetchAll(PDO::FETCH_KEY_PAIR);
$check($claims['browser'] === $claim, 'an rns-js row\'s top-level 32-hex identity_hash becomes its claim');
$check($claims['browser-upper'] === null && $claims['browser-short'] === null, 'a malformed claim is no claim');
$check($claims['browser-nested'] === null && $claims['browser-none'] === null, 'a nested or absent identity_hash is no claim');
$check($claims['gateway-claims'] === null && $claims['peer'] === null && $claims['not-json'] === null, 'only rns-js rows get a claim (A8)');
$check(($summary['claims_backfilled'] ?? null) === 1, 'the summary counts the backfill: ' . json_encode($summary['claims_backfilled'] ?? null));
$check(str_contains((string) $live->query("SELECT metadata_json FROM interfaces WHERE interface_id = 'browser'")->fetchColumn(), $claim),
    'the backfill leaves metadata_json for the row\'s next write');
$snapshot = json_encode($live->query('SELECT * FROM interfaces ORDER BY interface_id')->fetchAll(PDO::FETCH_ASSOC));
$again = storageOn($livePath)->migrate();
$check(($again['errors'] ?? ['?']) === [], 'a second migration has no errors');
$check(($again['built'] ?? ['?']) === [] && ($again['claims_backfilled'] ?? 0) === 0, 'and builds and fills nothing: ' . json_encode($again['built'] ?? null));
$check(json_encode($live->query('SELECT * FROM interfaces ORDER BY interface_id')->fetchAll(PDO::FETCH_ASSOC)) === $snapshot, 'and changes no row');

unset($migrated);

// ── (g) the version is a literal ─────────────────────────────────────────
echo "(g) only this code's own version skips the migration\n";
$traitFile = $root . '/src/lib/request_schema_trait.php';
$cachedPath = $dir . '/old-cached-code.sqlite';
$cached = liveDatabase($cachedPath);
$cached->prepare("UPDATE schema_meta SET fingerprint = :f WHERE meta_key = 'migration'")->execute([':f' => sha1_file($traitFile)]);
$afterSwap = storageOn($cachedPath)->migrateIfNeeded();
$check(!isset($afterSwap['skipped']) && $objectsPresent($cached) === [],
    'with schema_meta holding the SHA-1 of the deployed trait file (old cached code after a swap), migrateIfNeeded() still builds §12\'s objects');
$check(recordedVersion($cached) === PINNED_SCHEMA_VERSION, 'and records the version');
$cached->exec("UPDATE schema_meta SET fingerprint = 'stage1-0' WHERE meta_key = 'migration'");
$older = storageOn($cachedPath)->migrateIfNeeded();
$check(!isset($older['skipped']) && recordedVersion($cached) === PINNED_SCHEMA_VERSION, 'an older version recorded migrates');
$own = storageOn($cachedPath)->migrateIfNeeded();
$check(($own['skipped'] ?? false) === true, 'its own version skips');
unset($cached);

// ── (h) schema_migrated after a failed statement, or without the index ──
echo "(h) schema_migrated is false after one failed statement, or with the UNIQUE index missing\n";
$failPath = $dir . '/one-failed-statement.sqlite';
$failing = liveDatabase($failPath);
$failing->exec('CREATE TABLE idx_path_entries_iface (x INT)');   // takes the name one CREATE INDEX needs
$failedStorage = storageOn($failPath);
$failed = $failedStorage->migrateIfNeeded();
$check(count($failed['errors'] ?? []) === 1, 'one statement fails: ' . json_encode($failed['errors'] ?? null));
$check(recordedVersion($failing) === $liveVersion, 'no version is recorded');
$check($failedStorage->schemaObjectsPresent() === true && $failedStorage->schemaMigrated() === false,
    'schema_migrated is false, though the probe\'s own objects are there');
$failing->exec('DROP TABLE idx_path_entries_iface');
$check(storageOn($failPath)->migrateIfNeeded()['errors'] === [] && $failedStorage->schemaMigrated() === true, 'the next request\'s migration finishes, and it is true');
$failing->exec('DROP INDEX idx_interfaces_identity_hash');
$check($failedStorage->schemaMigrated() === false, 'without the UNIQUE index (the version still recorded) it is false');
$failing->exec('CREATE INDEX idx_interfaces_identity_hash ON interfaces (identity_hash)');
$check($failedStorage->schemaMigrated() === false, 'and false with a non-unique index of that name');
$failing->exec('DROP INDEX idx_interfaces_identity_hash');
$failing->exec('CREATE UNIQUE INDEX idx_interfaces_identity_hash ON interfaces (claimed_identity_hash)');
$check($failedStorage->schemaMigrated() === false, 'and false with a unique index of that name on another column');
$failing->exec('DROP INDEX idx_interfaces_identity_hash');
$check($failedStorage->migrate()['errors'] === [] && $failedStorage->schemaMigrated() === true, 'a forced migrate() (the deploy step) builds it again');
unset($failing, $failedStorage);

// ── (i) the CLI migrate mode ─────────────────────────────────────────────
echo "(i) `php index.php migrate` builds every object and records nothing\n";
$projectRoot = $dir . '/project-root';
mkdir($projectRoot);
$cliPath = $dir . '/cli.sqlite';
file_put_contents($projectRoot . '/config.toml', implode("\n", [
    '[storage]',
    'backend = "sqlite"',
    'sqlite_path = "' . $cliPath . '"',
    'log_path = "' . $dir . '/cli-router.log"',
]) . "\n");
$cliDb = liveDatabase($cliPath);
$cliDb->exec("INSERT INTO interfaces (interface_id, name, session_token, metadata_json) VALUES ('browser', 'Retichat Web', 't', '{\"client\":\"rns-js\",\"identity_hash\":\"{$claim}\"}')");
$cli = static function (array $args) use ($root): array {
    $proc = proc_open(array_merge([PHP_BINARY, $root . '/src/index.php', 'migrate'], $args),
        [0 => ['file', '/dev/null', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes);
    $out = (string) stream_get_contents($pipes[1]);
    $err = (string) stream_get_contents($pipes[2]);
    fclose($pipes[1]);
    fclose($pipes[2]);
    return [proc_close($proc), $out, $err];
};
[$code, $out, $err] = $cli(['--project-root', $projectRoot]);
$ok = $code === 0 && str_contains($out, 'migrate: ok');
$check($ok, 'it succeeds' . ($ok ? '' : ": exit {$code} " . trim($out . ' ' . $err)));
preg_match_all('/^built (.+) in [0-9.]+ ms$/m', $out, $builtLines);
$check($builtLines[1] === $stage1Built, 'it names each object it built, with its time: exactly §12\'s on a 50c870b database: ' . implode(', ', $builtLines[1]));
$check(str_contains($out, 'backfilled claimed_identity_hash on 1 row(s)'), 'and the backfill');
$check($objectsPresent($cliDb) === [], 'every §12 object is there');
$check(recordedVersion($cliDb) === $liveVersion, 'and no version is recorded');
$cliStorage = storageOn($cliPath);
$after = $cliStorage->migrate();
$check(($after['errors'] ?? ['?']) === [] && ($after['built'] ?? ['?']) === [], 'a migrate() after it adds nothing: ' . json_encode($after['built'] ?? null));
$next = $cliStorage->migrateIfNeeded();
$check(!isset($next['skipped']) && ($next['built'] ?? ['?']) === [] && recordedVersion($cliDb) === PINNED_SCHEMA_VERSION,
    'the first request after the swap builds nothing and records the version');
[$code, , $err] = $cli(['--project-root', $dir . '/no-such-dir']);
$check($code === 1 && str_contains($err, 'existing directory'), 'a missing project root is refused');
mkdir($dir . '/empty-root');
[$code, , $err] = $cli(['--project-root', $dir . '/empty-root']);
$check($code === 1 && str_contains($err, 'no config file'), 'a project root without a config is refused, nothing done');
$cliDb->exec('DROP INDEX idx_link_transport_outbound');
$cliDb->exec('CREATE TABLE idx_link_transport_outbound (x INT)');   // takes the index's name
[$code, $out, $err] = $cli(['--project-root', $projectRoot]);
$ok = $code === 1 && str_contains($err, 'FAILED');
$check($ok, 'a failing statement exits 1, so deploy.sh stops before the swap' . ($ok ? '' : ": exit {$code} " . trim($out . ' ' . $err)));
$check(recordedVersion($cliDb) === PINNED_SCHEMA_VERSION, 'and changes no recorded version');
unset($cliDb, $cliStorage);

// ── (j) the guard ────────────────────────────────────────────────────────
echo "(j) the schema version moves with the schema code\n";
$source = (string) file_get_contents($traitFile);
$pattern = "/(private function schemaVersion\\(\\): string\\s*\\{\\s*return ')([^']*)(';)/";
$found = preg_match_all($pattern, $source, $m);
$check($found === 1, 'schemaVersion() returns one literal');
$version = $m[2][0] ?? null;
$masked = sha1((string) preg_replace($pattern, '$1<version>$3', $source));
$check($version === PINNED_SCHEMA_VERSION && $masked === PINNED_SCHEMA_TRAIT_MASKED_SHA1,
    "the pinned pair (version, masked SHA-1) matches request_schema_trait.php: found ({$version}, {$masked}). "
    . 'A change to what migrate() builds needs a new schemaVersion(); then pin the new pair in this test');

array_map('unlink', glob($dir . '/*.*') ?: []);
foreach (['project-root/config.toml'] as $file) {
    @unlink($dir . '/' . $file);
}
@rmdir($dir . '/project-root');
@rmdir($dir . '/empty-root');
array_map('unlink', glob($dir . '/*') ?: []);
rmdir($dir);
exit($failures === 0 ? 0 : 1);
