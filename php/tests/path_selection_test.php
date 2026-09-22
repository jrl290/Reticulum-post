<?php

declare(strict_types=1);

/**
 * Regression test: path-selection logic in upsertPathFromAnnounce.
 *
 * Verifies the "shorter_path_replaced" branch (added 2026-08-08) that
 * prevents the relay from getting stuck on a longer path when the same
 * announce (same random blob) arrives via two different routes.
 *
 * Observed failure: retichat.com kept a 6-hop gateway path to a
 * selectiv-local destination instead of the 2-hop direct peer, because:
 *   1. The gateway path (6 hops) arrived first → blob recorded.
 *   2. The peer path (2 hops) arrived later → blob already seen →
 *      $isNewerAnnounce=false → existing logic dropped it.
 *   3. Messages routed via gateway (6 hops) instead of peer (2 hops),
 *      breaking direct retichat→selectiv delivery.
 *
 * Run with: php tests/path_selection_test.php
 */

require_once __DIR__ . '/path_selection_test_fixture.php';

function assertEq(string $label, $expected, $actual): void
{
    global $pass, $fail;
    if ($expected === $actual) {
        $pass++;
        echo "  \033[32m✓\033[0m $label\n";
    } else {
        $fail++;
        echo "  \033[31m✗\033[0m $label\n";
        echo "    expected: " . var_export($expected, true) . "\n";
        echo "    actual:   " . var_export($actual, true) . "\n";
    }
}

function assertTrue(string $label, bool $condition): void
{
    global $pass, $fail;
    if ($condition) {
        $pass++;
        echo "  \033[32m✓\033[0m $label\n";
    } else {
        $fail++;
        echo "  \033[31m✗\033[0m $label (expected true)\n";
    }
}

// ══════════════════════════════════════════════════════════════════════════
// Test 1: Shorter path replaces longer (blob already seen) — THE REGRESSION
// ══════════════════════════════════════════════════════════════════════════

echo "\n── Test 1: Shorter path replaces longer (blob seen) ──\n";

$r1 = new PathSelectionMockRouter();
$destHex = '1762c055000000000000000000000000';
$blobHex = 'aaaa11112222333344445555';

// Pre-seed: current path = 6 hops via gateway interface, blob already seen.
seedPath($r1, $destHex, 6, '05fea3e6gateway00000000000000', $blobHex);

// Now an announce arrives via the direct peer interface with 2 hops, same blob.
$packet = mkPacket([
    'hops' => 2,
    'destination_hash_hex' => $destHex,
]);
$announce = mkAnnounce([
    'random_hash_hex' => $blobHex,
]);

[$status, $reason] = $r1->test_upsertPathFromAnnounce('e06a36b2peer0000000000000000', $packet, $announce);

assertEq('status = path_updated', 'path_updated', $status);
assertEq('reason = shorter_path_replaced', 'shorter_path_replaced', $reason);

// Verify the DB was updated: hops should now be 2, interface should be the peer.
$row = $r1->test_pathEntry($destHex);
assertTrue('path row exists', $row !== null);
assertEq('hops updated to 2', 2, (int) ($row['hops'] ?? -1));
assertEq('interface updated to peer', 'e06a36b2peer0000000000000000', (string) ($row['interface_id'] ?? ''));

// ══════════════════════════════════════════════════════════════════════════
// Test 2: Longer path does NOT replace shorter (blob already seen)
// ══════════════════════════════════════════════════════════════════════════

echo "\n── Test 2: Longer path does NOT replace shorter (blob seen) ──\n";

$r2 = new PathSelectionMockRouter();
$destHex = '1762c055000000000000000000000000';
$blobHex = 'aaaa11112222333344445555';

// Pre-seed: current path = 2 hops via peer (GOOD path), blob already seen.
seedPath($r2, $destHex, 2, 'e06a36b2peer0000000000000000', $blobHex);

// Now the SAME announce arrives via the gateway with 6 hops (worse path).
$packet = mkPacket([
    'hops' => 6,
    'destination_hash_hex' => $destHex,
]);
$announce = mkAnnounce([
    'random_hash_hex' => $blobHex,
]);

[$status, $reason] = $r2->test_upsertPathFromAnnounce('05fea3e6gateway00000000000000', $packet, $announce);

assertEq('status = validated', 'validated', $status);
assertEq('reason = announce_ignored', 'announce_ignored', $reason);

// Verify the DB was NOT changed: hops still 2, interface still peer.
$row = $r2->test_pathEntry($destHex);
assertTrue('path row still exists', $row !== null);
assertEq('hops unchanged at 2', 2, (int) ($row['hops'] ?? -1));
assertEq('interface unchanged (peer)', 'e06a36b2peer0000000000000000', (string) ($row['interface_id'] ?? ''));

// ══════════════════════════════════════════════════════════════════════════
// Test 3: Shorter path wins even if gateway path recorded first
//         (simulates the exact production race condition)
// ══════════════════════════════════════════════════════════════════════════

echo "\n── Test 3: Shorter path wins (gateway-first race) ──\n";

// Simulate: the gateway path (6 hops) arrives first and is recorded.
$r3 = new PathSelectionMockRouter();
$destHex = '1762c055000000000000000000000000';
$blobHex = 'aaaa11112222333344445555';

seedPath($r3, $destHex, 6, '05fea3e6gateway00000000000000', $blobHex);
$row = $r3->test_pathEntry($destHex);
assertTrue('initial: gateway path seeded', $row !== null && (int) $row['hops'] === 6);

// Now the peer path (2 hops, same blob) arrives — this is the fix.
$packet = mkPacket([
    'hops' => 2,
    'destination_hash_hex' => $destHex,
]);
$announce = mkAnnounce([
    'random_hash_hex' => $blobHex,
]);

[$status, $reason] = $r3->test_upsertPathFromAnnounce('e06a36b2peer0000000000000000', $packet, $announce);

assertEq('status = path_updated', 'path_updated', $status);
assertEq('reason = shorter_path_replaced', 'shorter_path_replaced', $reason);

// Verify the gateway path was replaced with the shorter peer path.
$row = $r3->test_pathEntry($destHex);
assertTrue('path row exists', $row !== null);
assertEq('hops corrected to 2', 2, (int) ($row['hops'] ?? -1));
assertEq('interface corrected to peer', 'e06a36b2peer0000000000000000', (string) ($row['interface_id'] ?? ''));

// ══════════════════════════════════════════════════════════════════════════
// Test 4: New destination (no existing path)
// ══════════════════════════════════════════════════════════════════════════

echo "\n── Test 4: New destination ──\n";

$r4 = new PathSelectionMockRouter();
$destHex = 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb';
$blobHex = 'bbbb11112222333344445555';

$packet = mkPacket([
    'hops' => 3,
    'destination_hash_hex' => $destHex,
]);
$announce = mkAnnounce([
    'random_hash_hex' => $blobHex,
]);

[$status, $reason] = $r4->test_upsertPathFromAnnounce('iface_new', $packet, $announce);

assertEq('status = path_updated', 'path_updated', $status);
assertEq('reason = new_destination', 'new_destination', $reason);

$row = $r4->test_pathEntry($destHex);
assertTrue('path row created', $row !== null);
assertEq('hops = 3', 3, (int) ($row['hops'] ?? -1));

// ══════════════════════════════════════════════════════════════════════════
// Test 5: Equal hops + newer announce (blob NOT seen) → refresh
// ══════════════════════════════════════════════════════════════════════════

echo "\n── Test 5: Equal hops + newer announce → refresh ──\n";

$r5 = new PathSelectionMockRouter();
$destHex = 'cccccccccccccccccccccccccccccccc';
$oldBlob = 'cccc11112222333344445555';
$newBlob = 'dddd11112222333344445555';

$oldEmitted = time() - 120;
$newEmitted = time() - 30;  // newer than old

// Pre-seed with old blob at old emitted time.
seedPath($r5, $destHex, 3, 'iface_a', $oldBlob, $oldEmitted);

// New announce: equal hops, new blob, newer emitted.
$packet = mkPacket([
    'hops' => 3,
    'destination_hash_hex' => $destHex,
]);
$announce = mkAnnounce([
    'random_hash_hex' => $newBlob,
    'announce_emitted' => $newEmitted,
]);

[$status, $reason] = $r5->test_upsertPathFromAnnounce('iface_a', $packet, $announce);

assertEq('status = path_updated', 'path_updated', $status);
assertEq('reason = better_or_equal_hops_newer_announce', 'better_or_equal_hops_newer_announce', $reason);

// ══════════════════════════════════════════════════════════════════════════
// Test 6: Equal hops + blob already seen → ignored (no refresh)
// ══════════════════════════════════════════════════════════════════════════

echo "\n── Test 6: Equal hops + blob seen → ignored ──\n";

$r6 = new PathSelectionMockRouter();
$destHex = 'dddddddddddddddddddddddddddddddd';
$blobHex = 'eeee11112222333344445555';

seedPath($r6, $destHex, 3, 'iface_a', $blobHex);

// Same blob, same hops, different interface → should be ignored.
$packet = mkPacket([
    'hops' => 3,
    'destination_hash_hex' => $destHex,
]);
$announce = mkAnnounce([
    'random_hash_hex' => $blobHex,
]);

[$status, $reason] = $r6->test_upsertPathFromAnnounce('iface_b', $packet, $announce);

assertEq('status = validated', 'validated', $status);
assertEq('reason = announce_ignored', 'announce_ignored', $reason);

// ══════════════════════════════════════════════════════════════════════════
// Test 7: Hops exceed pathfinder_max_hops → rejected
// ══════════════════════════════════════════════════════════════════════════

echo "\n── Test 7: Hops exceed max → rejected ──\n";

$r7 = new PathSelectionMockRouter();
$r7->config['transport']['pathfinder_max_hops'] = 16;

$packet = mkPacket([
    'hops' => 20,
    'destination_hash_hex' => 'eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee',
]);
$announce = mkAnnounce();

[$status, $reason] = $r7->test_upsertPathFromAnnounce('iface_x', $packet, $announce);

assertEq('status = validated', 'validated', $status);
assertEq('reason = announce_hops_exceeded', 'announce_hops_exceeded', $reason);

// ══════════════════════════════════════════════════════════════════════════
// Report
// ══════════════════════════════════════════════════════════════════════════

echo "\n" . str_repeat('=', 50) . "\n";
echo "Results: $pass passed, $fail failed\n";
echo str_repeat('=', 50) . "\n";

exit($fail > 0 ? 1 : 0);
