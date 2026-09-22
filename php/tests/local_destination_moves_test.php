<?php
/**
 * A destination that announces again from another node stops being "local".
 *
 * On 2026-09-22 a browser identity that had been on retichat.com re-attached to
 * selectiv. Its new announce reached retichat.com over the peer link, the path
 * table updated, but local_destinations still mapped it to the dead browser
 * interface (status stays 'online' for interface_stale_after_seconds, 300 s
 * on retichat.com). deliverLocallyIfKnown() runs before the path table, so a
 * message for it was queued as local_delivery to that interface and never
 * relayed. RNS: the newer announce wins (Transport.py:2229-2252).
 *
 * Run: php tests/local_destination_moves_test.php
 */
declare(strict_types=1);
require_once __DIR__ . '/path_selection_test_fixture.php';

$pass = 0; $fail = 0;
function check(string $label, bool $ok): void { global $pass, $fail; if ($ok) { $pass++; echo "  ok   $label\n"; } else { $fail++; echo "  FAIL $label\n"; } }

$dest = 'b42714bda794d70a05dd70ce6140f59a';
$browser = 'iface_browser';
$peer = 'iface_peer';

function seedLocal(PathSelectionMockRouter $r, string $dest, string $iface): void {
    $r->db->prepare('INSERT OR REPLACE INTO local_destinations VALUES (:d, :i, :t)')->execute([':d' => $dest, ':i' => $iface, ':t' => time() - 120]);
}
function localIface(PathSelectionMockRouter $r, string $dest): ?string {
    $st = $r->db->prepare('SELECT interface_id FROM local_destinations WHERE destination_hash_hex = :d'); $st->execute([':d' => $dest]);
    $row = $st->fetch(PDO::FETCH_ASSOC); return is_array($row) ? $row['interface_id'] : null;
}

echo "── a newer announce via the peer evicts the stale local registration ──\n";
$r = new PathSelectionMockRouter();
$t0 = time() - 60;
seedPath($r, $dest, 1, $browser, 'aaaa11112222333344445555', $t0);
seedLocal($r, $dest, $browser);
[$status, $reason] = $r->test_upsertPathFromAnnounce($peer,
    mkPacket(['destination_hash_hex' => $dest, 'hops' => 2]),
    mkAnnounce(['random_hash_hex' => 'bbbb11112222333344445555', 'announce_emitted' => $t0 + 30]));
check("path accepted the newer announce ($reason)", $status === 'path_updated');
check('local registration on the dead browser interface is gone', localIface($r, $dest) === null);

echo "── an echo of the browser's own announce (same random hash) keeps it local ──\n";
$r = new PathSelectionMockRouter();
seedPath($r, $dest, 1, $browser, 'aaaa11112222333344445555', $t0);
seedLocal($r, $dest, $browser);
$r->test_upsertPathFromAnnounce($peer,
    mkPacket(['destination_hash_hex' => $dest, 'hops' => 3]),
    mkAnnounce(['random_hash_hex' => 'aaaa11112222333344445555', 'announce_emitted' => $t0]));
check('echo does not evict the local registration', localIface($r, $dest) === $browser);

echo "── an older announce from elsewhere keeps it local ──\n";
$r = new PathSelectionMockRouter();
seedPath($r, $dest, 1, $browser, 'aaaa11112222333344445555', $t0);
seedLocal($r, $dest, $browser);
$r->test_upsertPathFromAnnounce($peer,
    mkPacket(['destination_hash_hex' => $dest, 'hops' => 2]),
    mkAnnounce(['random_hash_hex' => 'cccc11112222333344445555', 'announce_emitted' => $t0 - 30]));
check('older announce does not evict', localIface($r, $dest) === $browser);

echo "── the browser re-announcing on its own interface keeps it local ──\n";
$r = new PathSelectionMockRouter();
seedPath($r, $dest, 1, $browser, 'aaaa11112222333344445555', $t0);
seedLocal($r, $dest, $browser);
$r->test_upsertPathFromAnnounce($browser,
    mkPacket(['destination_hash_hex' => $dest, 'hops' => 1]),
    mkAnnounce(['random_hash_hex' => 'dddd11112222333344445555', 'announce_emitted' => $t0 + 30]));
check('same interface keeps the local registration', localIface($r, $dest) === $browser);

echo "\nResults: $pass passed, $fail failed\n";
exit($fail > 0 ? 1 : 0);
