<?php

declare(strict_types=1);

/**
 * Every endpoint that ingests packets must run the maintenance prelude.
 *
 * WHAT THIS EXISTS TO PREVENT
 * ===========================
 * Reticulum-php has no scheduler by design: maintenance rides the request path
 * through runInterfaceRequestPrelude(). That works only for as long as every
 * endpoint carrying traffic actually calls it.
 *
 * On 2026-08-30 one did not. /v1/wake went straight into exchangeWithPhpPeer()
 * — pulling packets from the peer, writing rows, appending to error_log — with
 * no prelude anywhere in the handler. selectivesubconscious.com serves wakes and
 * nothing else (8,662 wakes and zero exchanges in the live access log), so it
 * ran no maintenance at all for 12.8 days: no TTL expiry, no log trim, no budget
 * check, no reclaim. It finished with 1,026 MB of freed-but-unrebuilt InnoDB
 * pages against a 1 GB account quota and a 93 MB error_log, while its own budget
 * cheerfully reported 135 MB of 300 MB.
 *
 * The node was not idle, which is why this went unnoticed — it was busy on the
 * one endpoint nobody had wired up. That is a whole class of bug, not one miss,
 * so this test asserts the invariant over every ingest endpoint rather than
 * over the one that broke.
 *
 * /v1/interfaces/register is deliberately excluded: it creates an interface row
 * and ingests no packets, so a node receiving only registrations accumulates
 * nothing to police, and the prelude's DELETEs have no business in the hot path
 * a browser client hits to connect.
 */

$root = dirname(__DIR__);
$indexPath = $root . '/src/index.php';

$failures = [];

$source = @file_get_contents($indexPath);
if ($source === false) {
    fwrite(STDERR, "FAIL: cannot read {$indexPath}\n");
    exit(1);
}

// Endpoints that move packets into or out of this node's tables.
$ingestRoutes = [
    "/v1/interfaces/exchange",
    "/v1/interfaces/poll",
    "/v1/wake",
];

$lines = explode("\n", $source);

/**
 * The body of a route handler: from the `if ($method === ...)` line that names
 * $route to the closing brace at the same indentation.
 */
$handlerBody = static function (string $route) use ($lines): ?string {
    $start = null;
    $indent = 0;
    foreach ($lines as $i => $line) {
        if (!str_contains($line, '$method ===') || !str_contains($line, "'" . $route . "'")) {
            continue;
        }
        $start = $i;
        $indent = strlen($line) - strlen(ltrim($line));
        break;
    }

    if ($start === null) {
        return null;
    }

    $closing = str_repeat(' ', $indent) . '}';
    $body = [];
    for ($i = $start + 1, $n = count($lines); $i < $n; $i++) {
        if (rtrim($lines[$i]) === $closing) {
            return implode("\n", $body);
        }
        $body[] = $lines[$i];
    }

    return null;
};

foreach ($ingestRoutes as $route) {
    $body = $handlerBody($route);

    if ($body === null) {
        $failures[] = "{$route}: no handler found in index.php — if the route was "
            . 'renamed, rename it here too rather than deleting the assertion';
        continue;
    }

    if (!str_contains($body, 'runInterfaceRequestPrelude()')) {
        $failures[] = "{$route}: handler does not call runInterfaceRequestPrelude(). "
            . 'This node has no cron; a traffic endpoint without the prelude is a '
            . 'node that never expires a row, never trims a log and never measures '
            . 'its own footprint.';
    }
}

// The prelude is only as good as the maintenance it invokes.
$preludePath = $root . '/src/lib/request_http_api_helper_trait.php';
$prelude = @file_get_contents($preludePath);
if ($prelude === false) {
    $failures[] = 'cannot read request_http_api_helper_trait.php';
} elseif (!str_contains($prelude, 'runMaintenance(')) {
    $failures[] = 'runInterfaceRequestPrelude() no longer calls runMaintenance() — '
        . 'the prelude is the only thing standing between this node and unbounded growth';
}

// ...and maintenance is only as good as the budget phase it reaches.
$maintenancePath = $root . '/src/lib/request_maintenance_trait.php';
$maintenance = @file_get_contents($maintenancePath);
if ($maintenance === false) {
    $failures[] = 'cannot read request_maintenance_trait.php';
} elseif (!str_contains($maintenance, 'runStorageBudgetPhase(')) {
    $failures[] = 'runMaintenance() no longer runs the storage budget phase';
}

if ($failures !== []) {
    fwrite(STDERR, "FAIL: maintenance does not ride every ingest endpoint\n\n");
    foreach ($failures as $f) {
        fwrite(STDERR, "  - {$f}\n");
    }
    fwrite(STDERR, "\n");
    exit(1);
}

printf("PASS: all %d ingest endpoints run the maintenance prelude\n", count($ingestRoutes));
exit(0);
