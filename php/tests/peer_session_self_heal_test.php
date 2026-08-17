<?php

declare(strict_types=1);

/**
 * Peer sessions must self-heal, and a dead row must never pass as connected.
 *
 * WHAT THIS EXISTS TO PREVENT
 * ===========================
 * On 2026-08-17 selectivesubconscious.com spent ~9 hours with no route to the
 * rest of the network. Its only mesh connection is the PHP-to-PHP peer session
 * with retichat.com, and that session was a one-shot bootstrap: established by
 * a manual GET /v1/initialize, maintained by nothing.
 *
 * Two defects compounded:
 *
 *   1. connectToPeer() treated ANY interfaces row with the peer's URL as
 *      "already_connected" — including a row that had been offline since
 *      06:32. Re-running /v1/initialize on selectiv would have done nothing.
 *   2. On the retichat side, maintenance Phase 1/2 (correctly) reaped the
 *      dead peer row — and nothing ever re-created it. The stale-interface
 *      cleanup, one of the fixes this repo is proudest of, silently
 *      guaranteed the peering could never come back on its own.
 *
 * The visible symptom was indirect, which is why it read as a client
 * regression: browsers connected to selectiv's exchange fine ("online",
 * registered) and then hung forever on link establishment, because the
 * announces that name every service could not reach selectiv's node at all.
 * "Stuck on links" on one URL and healthy on the other is what a dead peer
 * session looks like from the outside.
 *
 * The fix: phpPeerRowIsLive() is the single boundary for "is this session
 * real" (status online AND recently seen), connectToPeer() replaces dead rows
 * instead of deferring to them, and maintenance Phase 12 re-registers dead
 * configured peers on ordinary request traffic — no scheduler, throttled
 * through transport_state (operations police themselves).
 */

$root = dirname(__DIR__) . '/src/lib';

// ── The liveness boundary, as a pure function ────────────────────────────
// Extract phpPeerRowIsLive from the trait and run it standalone: the trait
// has database dependencies, the function deliberately has none.
$source = file_get_contents($root . '/request_php_wake_trait.php');
if (!preg_match(
    '/public static function phpPeerRowIsLive\(.*?\n    \}/s',
    $source,
    $m
)) {
    fwrite(STDERR, "FAIL: phpPeerRowIsLive missing from request_php_wake_trait.php\n");
    exit(1);
}
eval('class PeerLivenessProbe { ' . $m[0] . ' }');

$now = 1_786_990_000;
$cases = [
    // [expected, row, label]
    [false, null, 'no row at all'],
    [false, ['status' => 'offline', 'last_seen_at' => $now - 10],
        'offline row, recently seen — THE selectiv corpse: existed, blocked reconnection, carried no traffic'],
    [false, ['status' => 'online', 'last_seen_at' => $now - 3600],
        'online row not seen for an hour — the peer stopped answering and nothing marked it yet'],
    [false, ['status' => 'online'],
        'online row with no last_seen_at'],
    [true,  ['status' => 'online', 'last_seen_at' => $now - 30],
        'online and recently seen'],
    [true,  ['status' => 'online', 'last_seen_at' => $now - 899],
        'online, just inside the stale window'],
    [false, ['status' => 'online', 'last_seen_at' => $now - 901],
        'online, just outside the stale window'],
];

$failures = [];
foreach ($cases as [$expected, $row, $label]) {
    $got = PeerLivenessProbe::phpPeerRowIsLive($row, $now);
    if ($got !== $expected) {
        $failures[] = sprintf('%s: expected %s, got %s',
            $label, var_export($expected, true), var_export($got, true));
    }
}

// ── Structural guarantees ────────────────────────────────────────────────
// connectToPeer must consult the liveness boundary, not bare row existence.
$connectStart = strpos($source, 'private function connectToPeer(');
$connectBody = substr($source, $connectStart, 1500);
if (!str_contains($connectBody, 'phpPeerRowIsLive(')) {
    $failures[] = 'connectToPeer() no longer consults phpPeerRowIsLive — a dead '
        . 'row will again satisfy "already_connected" and block reconnection forever';
}
if (preg_match('/if \(\$existing !== null\) \{\s*return \[/', $connectBody)) {
    $failures[] = 'connectToPeer() has regressed to treating bare row existence '
        . 'as connectivity';
}

// Maintenance must actually run the self-healing phase.
$maint = file_get_contents($root . '/request_maintenance_trait.php');
if (!str_contains($maint, 'ensureConfiguredPeerSessions(')) {
    $failures[] = 'runMaintenance() no longer calls ensureConfiguredPeerSessions — '
        . 'peering is back to being a one-shot bootstrap that dies permanently '
        . 'the first time a session drops';
}

// The self-healer must claim its throttle window before network work.
$healStart = strpos($source, 'public function ensureConfiguredPeerSessions(');
$healBody = substr($source, $healStart, 3000);
$claimPos = strpos($healBody, 'claimPeerSessionWindow');
$connectPos = strpos($healBody, 'connectToPeer(');
if ($claimPos === false || $connectPos === false || $claimPos > $connectPos) {
    $failures[] = 'ensureConfiguredPeerSessions must claim the transport_state '
        . 'window BEFORE calling connectToPeer, or concurrent requests stampede '
        . 'the peer with duplicate registrations';
}

if ($failures !== []) {
    fwrite(STDERR, "FAIL: peer session self-healing regressed\n\n");
    foreach ($failures as $f) {
        fwrite(STDERR, "  - {$f}\n");
    }
    fwrite(STDERR, "\n");
    exit(1);
}

printf("PASS: %d liveness cases + structural guards (dead rows never count as connected)\n", count($cases));
exit(0);
