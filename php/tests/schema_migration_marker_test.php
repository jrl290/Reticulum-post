<?php
declare(strict_types=1);

/**
 * migrateIfNeeded() must run the schema migration once per (schema source,
 * database) and then skip it: until 2026-09-24 migrate() ran on every
 * request, ~60 statements before any packet was touched.
 */

$root = dirname(__DIR__);
require_once $root . '/src/lib/database.php';
require_once $root . '/src/index.php';

$dir = sys_get_temp_dir() . '/reticulum-php-marker-test-' . bin2hex(random_bytes(4));
mkdir($dir, 0775, true);
$queryLog = $dir . '/queries.jsonl';
putenv('RETICULUM_PHP_QUERY_LOG=' . $queryLog);

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
$check(is_string($recorded) && strlen($recorded) === 40, 'the fingerprint was recorded inside the database');

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

array_map('unlink', glob($dir . '/*') ?: []);
rmdir($dir);
exit($failures === 0 ? 0 : 1);
