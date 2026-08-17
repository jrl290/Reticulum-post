<?php

declare(strict_types=1);

/**
 * Every write on the hot request path must go through the deadlock helper.
 *
 * WHAT THIS EXISTS TO PREVENT
 * ===========================
 * Database::executeWithRetry() has existed for months, and database.php's own
 * header describes the deadlock it defends against. It was applied to
 * request_packet_ingest_trait.php and nowhere else. Meanwhile 19 write
 * statements across the inbound batch, outbound batch, path state and relay
 * routing traits called $stmt->execute() directly.
 *
 * The result, measured on retichat.com on 2026-08-17: eight HTTP 500s that day
 * and one roughly every hour for days before it, each logged as
 *
 *   [ERROR] Unhandled HTTP exception: SQLSTATE[40001]: Serialization failure:
 *   1213 Deadlock found when trying to get lock; try restarting transaction
 *
 * Note the shape of that line — it is the raw PDO message, not the wrapper's
 * "Database deadlock after 3 retries [label]". That is how you can tell the
 * statement never went through the helper at all. Every one of those 500s was
 * a browser's exchange POST dropped outright: packets not delivered, no retry
 * at the protocol layer, and nothing in the log naming the query responsible.
 *
 * A mitigation that exists but is not applied is worse than none, because the
 * header comment in database.php reads as though the problem is handled. This
 * test makes the coverage checkable instead of assumed.
 *
 * Scope note: read-only SELECTs do not need the helper — they take no locks
 * that deadlock in READ COMMITTED. Only INSERT/UPDATE/DELETE are required to
 * be wrapped.
 */

$root = dirname(__DIR__) . '/src/lib';

/** Traits that serve HTTP requests and write to contended tables. */
$hotPathTraits = [
    'request_inbound_batch_trait.php',
    'request_outbound_batch_trait.php',
    'request_path_state_trait.php',
    'request_relay_routing_trait.php',
    'request_packet_ingest_trait.php',
];

$failures = [];
$checked = 0;
$wrapped = 0;

foreach ($hotPathTraits as $file) {
    $path = $root . '/' . $file;
    if (!is_file($path)) {
        $failures[] = "{$file}: missing — update this test if the trait was renamed";
        continue;
    }

    $source = file_get_contents($path);

    // Resolve each execution site back to the prepare() that produced its
    // statement, rather than walking lines statefully — bindValue() runs
    // between them, prepare() bodies span many lines, and a state machine that
    // loses track silently reports success, which is the one outcome a test
    // like this must never produce.
    //
    // $offset is the position of the execution call; the statement variable
    // names the prepare to look back for.
    $sites = [];

    if (preg_match_all('/\$(\w+)->execute\s*\(\s*\)\s*;/', $source, $m, PREG_OFFSET_CAPTURE | PREG_SET_ORDER)) {
        foreach ($m as $match) {
            $sites[] = ['var' => $match[1][0], 'offset' => $match[0][1], 'wrapped' => false];
        }
    }
    if (preg_match_all('/Database::exec(?:ute)?WithRetry\s*\(\s*\$(\w+)/', $source, $m, PREG_OFFSET_CAPTURE | PREG_SET_ORDER)) {
        foreach ($m as $match) {
            $sites[] = ['var' => $match[1][0], 'offset' => $match[0][1], 'wrapped' => true];
        }
    }

    foreach ($sites as $site) {
        // The prepare that created this statement is the last assignment to
        // the variable before the execution point.
        $before = substr($source, 0, $site['offset']);
        $assignPos = strrpos($before, '$' . $site['var'] . ' = ');
        if ($assignPos === false) {
            continue; // not a prepared statement we can attribute
        }
        $prepareBody = substr($source, $assignPos, $site['offset'] - $assignPos);
        if (!str_contains($prepareBody, 'prepare(')) {
            continue;
        }
        // Note the anchoring: a trailing \b after "UPDATE\s+\w" can never match,
        // because \w consumes a word character and the next one is a word
        // character too. An earlier draft of this test had exactly that bug and
        // therefore passed while writes went unwrapped — a green test that
        // cannot fail is the worst possible outcome here, so each keyword
        // anchors itself.
        if (!preg_match('/\b(INSERT\s+INTO\b|UPDATE\s+\w+|DELETE\s+FROM\b)/i', $prepareBody)) {
            continue; // read-only statement; no locks to deadlock on
        }

        $checked++;
        if ($site['wrapped']) {
            $wrapped++;
            continue;
        }

        $lineNo = substr_count(substr($source, 0, $site['offset']), "\n") + 1;
        $failures[] = sprintf(
            '%s:%d: $%s->execute() on a write statement — use '
            . 'Database::executeWithRetry($%s, \'label\') so a deadlock does '
            . 'not become an HTTP 500',
            $file,
            $lineNo,
            $site['var'],
            $site['var']
        );
    }
}

// Every wrapped call must carry a label: an unlabelled deadlock in the log is
// the unactionable state this whole change exists to leave behind.
foreach ($hotPathTraits as $file) {
    $path = $root . '/' . $file;
    if (!is_file($path)) {
        continue;
    }
    $source = file_get_contents($path);
    if (preg_match_all('/Database::exec(?:ute)?WithRetry\s*\(([^)]*)\)/', $source, $m)) {
        foreach ($m[1] as $args) {
            if (!str_contains($args, ',')) {
                $failures[] = sprintf(
                    '%s: Database::executeWithRetry(%s) has no label — the log '
                    . 'entry would not say which statement deadlocked',
                    $file,
                    trim($args)
                );
            }
        }
    }
}

// The helper must actually log, or a survived retry stays invisible.
$dbSource = file_get_contents(dirname(__DIR__) . '/src/lib/database.php');
if (!str_contains($dbSource, 'logDeadlock')) {
    $failures[] = 'database.php: no logDeadlock() — deadlocks must name their '
        . 'statement or the ordering conflict cannot be found';
}
if (!preg_match('/deadlock retry %d\/%d/', $dbSource)) {
    $failures[] = 'database.php: survived retries must be logged too; they '
        . 'never surface as errors and are otherwise invisible';
}

if ($failures !== []) {
    fwrite(STDERR, "FAIL: unwrapped writes on the hot request path\n\n");
    foreach ($failures as $f) {
        fwrite(STDERR, "  - {$f}\n");
    }
    fwrite(STDERR, "\n");
    exit(1);
}

printf("PASS: %d hot-path write statements, all using the deadlock helper\n", $wrapped);
exit(0);
