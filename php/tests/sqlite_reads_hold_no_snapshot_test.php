<?php
/**
 * A finished read must not leave its SQLite snapshot open.
 *
 * selectiv ran on SQLite until July 2026 and moved to MySQL (6dc8486) after
 * concurrent exchanges answered "database is locked". Reproduced 2026-10-14:
 * 12% of exchanges at nine interfaces, each failing at once although
 * busy_timeout is 5 s. The node reads one row with fetch() and moves on, so
 * the statement stays open and keeps its WAL snapshot; the next write on that
 * connection must upgrade the snapshot to a write lock, and SQLite refuses the
 * upgrade outright when another process committed in between (waiting cannot
 * make a stale snapshot current). acknowledgeOutboundBatches() and the seeding
 * of a new interface both did exactly that.
 *
 * This opens two connections to one file the way two requests would, leaves a
 * read half-consumed on A, commits on B, then writes on A. It also pins the
 * fetch behaviour the node relies on, since SQLite reads are now finished at
 * execute().
 *
 * Run: php tests/sqlite_reads_hold_no_snapshot_test.php
 */
declare(strict_types=1);

require_once __DIR__ . '/../src/lib/database.php';

use ReticulumPhp\Database;

$failures = 0;
function check(bool $ok, string $what): void
{
    global $failures;
    echo ($ok ? 'ok   ' : 'FAIL ') . $what . PHP_EOL;
    if (!$ok) {
        $failures++;
    }
}

function writeSucceeds(PDO $db, string $sql): string
{
    $t = microtime(true);
    try {
        $db->exec($sql);
        return sprintf('ok in %.0f ms', (microtime(true) - $t) * 1000);
    } catch (PDOException $e) {
        return sprintf('%s after %.0f ms', $e->getMessage(), (microtime(true) - $t) * 1000);
    }
}

function runScenarios(string $label, array $config): void
{
    $a = Database::connect($config);
    $b = Database::connect($config);
    $a->exec('CREATE TABLE IF NOT EXISTS t (id INTEGER PRIMARY KEY, v INTEGER NOT NULL)');
    $a->exec('DELETE FROM t');
    $a->exec('INSERT INTO t (id, v) VALUES (1, 10), (2, 20), (3, 30)');

    // The July failure: one row taken with fetch(), another process commits,
    // this connection writes.
    $select = $a->prepare('SELECT id, v FROM t WHERE id >= :min ORDER BY id');
    $select->bindValue(':min', 1, PDO::PARAM_INT);
    $select->execute();
    $first = $select->fetch(PDO::FETCH_ASSOC);
    $b->exec('UPDATE t SET v = v + 1 WHERE id = 3');
    $result = writeSucceeds($a, 'UPDATE t SET v = 0 WHERE id = 1');
    check(str_starts_with($result, 'ok'), "$label: write after a half-read prepared statement ($result)");
    check($first === ['id' => 1, 'v' => 10], "$label: the half-read statement returned its first row");
    // The rest of that result is still the result of the original read.
    check($select->fetch(PDO::FETCH_ASSOC) === ['id' => 2, 'v' => 20], "$label: the half-read statement continues where it stopped");

    // The same through query() + fetchColumn(), as the node's counts do.
    $count = $a->query('SELECT COUNT(*) FROM t');
    $n = $count->fetchColumn();
    $b->exec('UPDATE t SET v = v + 1 WHERE id = 2');
    $result = writeSucceeds($a, 'UPDATE t SET v = 5 WHERE id = 2');
    check(str_starts_with($result, 'ok'), "$label: write after query() + fetchColumn() ($result)");
    check($n === 3, "$label: fetchColumn() keeps the integer type");

    // Fetch behaviour the node relies on.
    $a->exec('DELETE FROM t');
    $a->exec('INSERT INTO t (id, v) VALUES (1, 10), (2, 20), (3, 30)');
    $s = $a->prepare('SELECT id, v FROM t ORDER BY id');
    $s->execute();
    $rows = [];
    while (($row = $s->fetch(PDO::FETCH_ASSOC)) !== false) {
        $rows[] = $row;
    }
    check($rows === [['id' => 1, 'v' => 10], ['id' => 2, 'v' => 20], ['id' => 3, 'v' => 30]], "$label: fetch() loop returns every row in order, then false");
    check($s->fetch(PDO::FETCH_ASSOC) === false, "$label: fetch() past the end stays false");

    $s->execute();
    check($s->fetch(PDO::FETCH_NUM) === [1, 10], "$label: re-execute starts over; FETCH_NUM");
    check($s->fetchColumn(1) === 20, "$label: fetchColumn(1) takes the next row's second column");
    check($s->fetchAll(PDO::FETCH_ASSOC) === [['id' => 3, 'v' => 30]], "$label: fetchAll() returns the remaining rows");
    check($s->fetchColumn() === false, "$label: fetchColumn() past the end is false");

    $s->execute();
    check($s->fetchAll(PDO::FETCH_COLUMN) === [1, 2, 3], "$label: fetchAll(FETCH_COLUMN)");
    $s->execute();
    check($s->fetchAll(PDO::FETCH_COLUMN, 1) === [10, 20, 30], "$label: fetchAll(FETCH_COLUMN, 1)");
    $s->execute();
    check($s->fetchAll(PDO::FETCH_NUM) === [[1, 10], [2, 20], [3, 30]], "$label: fetchAll(FETCH_NUM)");
    $s->execute();
    check($s->fetchAll() === [['id' => 1, 'v' => 10], ['id' => 2, 'v' => 20], ['id' => 3, 'v' => 30]], "$label: fetchAll() uses the connection's FETCH_ASSOC default");
    $s->execute();
    check($s->fetch() === ['id' => 1, 'v' => 10], "$label: fetch() uses the connection's FETCH_ASSOC default");
    check($s->closeCursor() && $s->fetch(PDO::FETCH_ASSOC) === false, "$label: closeCursor() ends the result");

    $s->execute();
    $seen = [];
    foreach ($s as $row) {
        $seen[] = $row['id'];
    }
    check($seen === [1, 2, 3], "$label: foreach over a statement");

    $dup = $a->query('SELECT 1 AS x, 2 AS x');
    check($dup->fetch(PDO::FETCH_ASSOC) === ['x' => 2], "$label: duplicate column names keep the last value, as PDO does");

    $empty = $a->prepare('SELECT id FROM t WHERE id > :id');
    $empty->execute([':id' => 99]);
    check($empty->fetch(PDO::FETCH_ASSOC) === false, "$label: empty result: fetch() is false");
    $empty->execute([':id' => 99]);
    check($empty->fetchAll(PDO::FETCH_ASSOC) === [], "$label: empty result: fetchAll() is []");
    $empty->execute([':id' => 99]);
    check($empty->fetchColumn() === false, "$label: empty result: fetchColumn() is false");

    $update = $a->prepare('UPDATE t SET v = v + 1 WHERE id <= :id');
    $update->execute([':id' => 2]);
    check($update->rowCount() === 2, "$label: rowCount() of a write");
    $insert = $a->prepare('INSERT INTO t (id, v) VALUES (:id, :v)');
    $insert->bindValue(':id', 4, PDO::PARAM_INT);
    $insert->bindValue(':v', 40, PDO::PARAM_INT);
    check($insert->execute() === true && $insert->rowCount() === 1, "$label: a prepared insert with bound values");

    $threw = false;
    try {
        $s->execute();
        $s->fetch(PDO::FETCH_OBJ);
    } catch (\LogicException $e) {
        $threw = true;
    }
    check($threw, "$label: an unsupported fetch mode is refused, not answered wrongly");
}

$dir = sys_get_temp_dir() . '/reticulum-php-snapshot-test-' . getmypid();
@mkdir($dir);
$base = ['storage' => ['backend' => 'sqlite', 'sqlite_path' => $dir . '/plain.sqlite']];
runScenarios('PDO', $base);
$counting = ['storage' => ['backend' => 'sqlite', 'sqlite_path' => $dir . '/counting.sqlite', 'query_log_path' => $dir . '/query.log']];
runScenarios('CountingPdo', $counting);

foreach (glob($dir . '/*') ?: [] as $file) {
    @unlink($file);
}
@rmdir($dir);

echo $failures === 0 ? "PASS\n" : "FAILED: $failures\n";
exit($failures === 0 ? 0 : 1);
