<?php
/**
 * REGISTRATION-STAGE1.md §4.5, §4.6, §7 step 3, §11 and §12: who may re-bind
 * which row, and what a legacy registration can no longer do. Against the
 * real Storage (SQLite).
 *
 * Before Stage 1 an unsigned body re-bound any browser row by naming its
 * identity hash (A1), and found it by a LIKE on metadata_json, so a client of
 * any kind could do it (A8); a browser could register in a transit mode; the
 * first real registration inherited whatever a squatter had bound (A7).
 *
 * Covered: a legacy claim of a signed identity, '%' and '_%' never touch the
 * signed row (A1); a legacy rns-post-interface registration naming a
 * browser's identity hash makes its own row (A8); no identity field in
 * metadata_json; legacy rows claiming an identity that signs are removed with
 * their traffic; legacy mode 3, 5 or 6 400; the switch refuses legacy
 * browsers only. With the switch off, a legacy row claiming a signed identity
 * (written as old code writes it, with H only in metadata_json, and with the
 * claim filled) gets 401 with its own token, with nothing written but the
 * claim, and the next signed registration removes it; a legacy row of an
 * identity that never signed still gets 200. N legacy registrations claiming
 * a signed identity log one [REG-REFUSED] line and write once; a new signed
 * registration allows one more; with the switch on, one per legacy row. No
 * SQL in php/src compares metadata_json with a value from a request: the one
 * comparison allowed is recentNodeInterfacesByStatus's LIKE :poll_gateway,
 * bound to a constant.
 *
 * Before Stage 1: A8 re-binds the browser's row; mode 6 is accepted; the
 * old-code row gets 200; every refusal is logged; the scan finds
 * interfaceByIdentityHash's LIKE :hash_pattern.
 *
 * Run: php php/tests/registration_rebind_rules_test.php
 */
declare(strict_types=1);

require_once dirname(__DIR__) . '/src/index.php';
require_once __DIR__ . '/stubs/registration_fixture.php';

use ReticulumPhp\ApiError;
use ReticulumPhp\Storage;

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

function row(Storage $s, string $id): ?array
{
    $st = RegFixture::db($s)->prepare('SELECT * FROM interfaces WHERE interface_id = :i');
    $st->execute([':i' => $id]);
    $r = $st->fetch(PDO::FETCH_ASSOC);

    return is_array($r) ? $r : null;
}

/**
 * The row as a re-bind would change it: all but last_seen_at, which its
 * holder's own authentication refreshes, and refusal_logged_seq, which a
 * refused legacy claim of it sets once per count (§11) and which binds
 * nothing.
 */
function owned(Storage $s, string $id): ?array
{
    $r = row($s, $id);
    if ($r !== null) {
        unset($r['last_seen_at'], $r['refusal_logged_seq']);
    }

    return $r;
}

function count_rows(Storage $s, string $table, string $where = '1 = 1', array $bind = []): int
{
    $st = RegFixture::db($s)->prepare("SELECT COUNT(*) FROM {$table} WHERE {$where}");
    $st->execute($bind);

    return (int) $st->fetchColumn();
}

/** @return array{0: array|ApiError, 1: string} */
function legacy(Storage $s, array $metadata, string $name = 'legacy'): array
{
    return RegFixture::capture(static fn () => $s->registerFromBody(['name' => $name, 'bitrate' => 1000000, 'mtu' => 500, 'metadata' => $metadata]));
}

function authStatus(Storage $s, string $id, string $token): int
{
    try {
        $s->authenticateInterface($id, $token);

        return 200;
    } catch (ApiError $e) {
        return $e->statusCode;
    }
}

/** Rows this connection has changed since it opened (SQLite's total_changes()). */
function changes(Storage $s): int
{
    return (int) RegFixture::db($s)->query('SELECT total_changes()')->fetchColumn();
}

/** Everything a row can own, planted for it: what §4.5 must delete. */
function plantDependents(Storage $s, string $id, string $dest): void
{
    $db = RegFixture::db($s);
    $db->prepare('INSERT INTO local_destinations (destination_hash_hex, interface_id, registered_at) VALUES (?, ?, 1)')->execute([$dest, $id]);
    $db->prepare("INSERT INTO path_entries (destination_hash_hex, next_hop_hex, hops, expires_at, random_blobs_json, interface_id, updated_at) VALUES (?, ?, 1, 9999999999, '[]', ?, 1)")
        ->execute([$dest . 'p', $dest, $id]);
    $db->prepare('INSERT INTO reverse_path_entries (truncated_hash_hex, received_interface_id, outbound_interface_id, created_at) VALUES (?, ?, ?, 1)')
        ->execute([$dest . 'r1', $id, 'elsewhere']);
    $db->prepare('INSERT INTO reverse_path_entries (truncated_hash_hex, received_interface_id, outbound_interface_id, created_at) VALUES (?, ?, ?, 1)')
        ->execute([$dest . 'r2', 'elsewhere', $id]);
    $db->prepare("INSERT INTO link_transport_entries (link_id_hex, received_interface_id, outbound_interface_id, next_hop_hex, destination_hash_hex, updated_at) VALUES (?, ?, 'elsewhere', 'nh', ?, 1)")
        ->execute([$dest . 'l1', $id, $dest]);
    $db->prepare("INSERT INTO link_transport_entries (link_id_hex, received_interface_id, outbound_interface_id, next_hop_hex, destination_hash_hex, updated_at) VALUES (?, 'elsewhere', ?, 'nh', ?, 1)")
        ->execute([$dest . 'l2', $id, $dest]);
    $db->prepare("INSERT INTO outbound_packets (interface_id, packet_base64, queued_at, queue_reason) VALUES (?, 'AAAA', 1, 'relay')")->execute([$id]);
    $db->prepare("INSERT INTO outbound_packets (interface_id, packet_base64, queued_at, queue_reason) VALUES (?, 'BBBB', 2, 'relay')")->execute([$id]);
    $db->prepare("INSERT INTO outbound_batches (interface_id, batch_id, packet_ids_json, created_at) VALUES (?, 'b1', '[]', 1)")->execute([$id]);
}

/** @return array<string,int> what is left that belongs to $id */
function dependents(Storage $s, string $id): array
{
    return [
        'interfaces' => count_rows($s, 'interfaces', 'interface_id = ?', [$id]),
        'local_destinations' => count_rows($s, 'local_destinations', 'interface_id = ?', [$id]),
        'path_entries' => count_rows($s, 'path_entries', 'interface_id = ?', [$id]),
        'reverse_path_entries' => count_rows($s, 'reverse_path_entries', 'received_interface_id = ? OR outbound_interface_id = ?', [$id, $id]),
        'link_transport_entries' => count_rows($s, 'link_transport_entries', 'received_interface_id = ? OR outbound_interface_id = ?', [$id, $id]),
        'outbound_packets' => count_rows($s, 'outbound_packets', 'interface_id = ?', [$id]),
        'outbound_batches' => count_rows($s, 'outbound_batches', 'interface_id = ?', [$id]),
    ];
}

/** A legacy browser row as code before Stage 1 writes it: the claim only in metadata_json. */
function oldCodeRow(Storage $s, string $claim): array
{
    $id = bin2hex(random_bytes(16));
    $token = bin2hex(random_bytes(32));
    RegFixture::db($s)->prepare("INSERT INTO interfaces (interface_id, name, session_token, bitrate, mtu, status, metadata_json, created_at, last_seen_at)
                                 VALUES (:i, 'Retichat Web', :t, 1000000, 500, 'online', :m, 1, 1)")
        ->execute([':i' => $id, ':t' => $token, ':m' => json_encode(['client' => 'rns-js', 'mode' => 1, 'identity_hash' => $claim])]);

    return ['interface_id' => $id, 'session_token' => $token];
}

echo "(1) A1 against a signed row: a legacy claim neither finds nor re-binds it\n";
$node = RegFixture::storage();
$victimId = RegFixture::identity();
[$victim, $victimToken] = RegFixture::connect($node, $victimId);
$victimBefore = owned($node, $victim['interface_id']);
foreach (["the victim's own hash" => $victimId['hash_hex'], "the wildcard '%'" => '%', "the wildcard '_%'" => '_%',
          'the hash in upper case' => strtoupper($victimId['hash_hex'])] as $label => $claim) {
    [$r, $log] = legacy($node, ['client' => 'rns-js', 'mode' => 1, 'identity_hash' => $claim], 'Retichat Web');
    if ($claim === $victimId['hash_hex']) {
        check("[$label] -> 403 identity_requires_signature, logged", RegFixture::outcome($r) === [403, 'identity_requires_signature']
            && str_contains($log, '[REG-REFUSED] 403 identity_requires_signature client=rns-js identity=' . $claim), trim($log));
        check("[$label] ...whose message says to reload", $r instanceof ApiError && str_contains((string) $r->payload['message'], 'Reload'));
    } else {
        check("[$label] is no claim: a fresh row of its own, claiming nothing, logged [REG-BAD-IDENTITY]",
            is_array($r) && $r['interface_id'] !== $victim['interface_id'] && row($node, $r['interface_id'])['claimed_identity_hash'] === null
            && str_contains($log, '[REG-BAD-IDENTITY]'), trim($log));
    }
    check("[$label] the victim's row is unchanged", owned($node, $victim['interface_id']) === $victimBefore,
        json_encode(array_diff_assoc((array) owned($node, $victim['interface_id']), (array) $victimBefore)));
    check("[$label] the victim's token still authenticates", authStatus($node, $victim['interface_id'], $victimToken) === 200);
}

echo "\n(2) A8: another client naming a browser's identity hash makes its own row\n";
$browserClaim = bin2hex(random_bytes(16));
[$browserRow] = legacy($node, ['client' => 'rns-js', 'mode' => 1, 'identity_hash' => $browserClaim], 'Retichat Web');
$browserBefore = owned($node, $browserRow['interface_id']);
foreach (['a legacy browser\'s claim' => [$browserClaim, $browserRow, $browserBefore], 'a signed browser\'s hash' => [$victimId['hash_hex'], $victim, $victimBefore]] as $label => [$hash, $target, $targetBefore]) {
    [$poll, $log] = legacy($node, ['client' => 'rns-post-interface', 'mode' => 6, 'transport' => 'tcp-backbone-gateway', 'identity_hash' => $hash], 'RNS PostInterface');
    check("[$label] a legacy rns-post-interface naming it gets a new row of its own", is_array($poll) && $poll['interface_id'] !== $target['interface_id']);
    check("[$label] ...the browser's row is unchanged, and its claim is not the gateway's",
        owned($node, $target['interface_id']) === $targetBefore && row($node, $poll['interface_id'])['claimed_identity_hash'] === null);
    check("[$label] ...logged [REG-CLAIM-IGNORED] client=rns-post-interface", str_contains($log, '[REG-CLAIM-IGNORED] client=rns-post-interface'), trim($log));
}
[$php, $log] = legacy($node, RegFixture::phpPeerMetadata() + ['identity_hash' => $browserClaim], 'peer');
check('a legacy reticulum-php naming it: a row of its own too, logged [REG-CLAIM-IGNORED] client=reticulum-php',
    is_array($php) && $php['interface_id'] !== $browserRow['interface_id'] && owned($node, $browserRow['interface_id']) === $browserBefore
    && str_contains($log, '[REG-CLAIM-IGNORED] client=reticulum-php'));
check('the browser\'s token still authenticates', authStatus($node, $browserRow['interface_id'], $browserRow['session_token']) === 200);

echo "\n(3) the legacy browser path: re-binds only its own claim's legacy row; no transit mode\n";
$claim = bin2hex(random_bytes(16));
[$l1] = legacy($node, ['client' => 'rns-js', 'mode' => 1, 'identity_hash' => $claim]);
[$l2, $log] = legacy($node, ['client' => 'rns-js', 'mode' => 1, 'identity_hash' => $claim]);
$r = row($node, $l1['interface_id']);
check('a legacy rns-js claim re-binds its own legacy row in place', $l1['interface_id'] === $l2['interface_id']
    && $r['claimed_identity_hash'] === $claim && $r['registration_proof'] === 'none');
check('...writing no identity column', $r['identity_hash'] === null && $r['identity_public_key'] === null && (int) $r['registration_seq'] === 0);
check('...logged [REG-LEGACY] client=rns-js action=rebound interface=<id8>',
    str_contains($log, '[REG-LEGACY] client=rns-js action=rebound interface=' . substr($l1['interface_id'], 0, 8)), trim($log));
[$n1] = legacy($node, ['client' => 'rns-js', 'mode' => 1]);
[$n2] = legacy($node, ['client' => 'rns-js', 'mode' => 1]);
check('no claim: a new row every time', $n1['interface_id'] !== $n2['interface_id']);
$c2 = bin2hex(random_bytes(16));
RegFixture::db($node)->prepare("INSERT INTO interfaces (interface_id, name, session_token, status, metadata_json, claimed_identity_hash) VALUES ('notbrowser', 'n', 't', 'online', '{\"client\":\"mystery\"}', ?)")
    ->execute([$c2]);
[$l3] = legacy($node, ['client' => 'rns-js', 'mode' => 1, 'identity_hash' => $c2]);
check('a claim never re-binds a row of another client holding the same claim', is_array($l3) && $l3['interface_id'] !== 'notbrowser');
foreach ([3, 5, 6, '6'] as $mode) {
    $before = count_rows($node, 'interfaces');
    [$r, $log] = legacy($node, ['client' => 'rns-js', 'mode' => $mode, 'identity_hash' => bin2hex(random_bytes(16))]);
    check('legacy rns-js mode ' . var_export($mode, true) . ' -> 400 transit_mode_not_allowed, logged, no row',
        RegFixture::outcome($r) === [400, 'transit_mode_not_allowed'] && str_contains($log, '[REG-REFUSED] 400 transit_mode_not_allowed client=rns-js')
        && count_rows($node, 'interfaces') === $before);
}
foreach ([1, 2, 4, 7] as $mode) {
    [$r] = legacy($node, ['client' => 'rns-js', 'mode' => $mode]);
    check("legacy rns-js mode $mode is accepted", is_array($r));
}

echo "\n(4) no identity field reaches metadata_json, on any path\n";
$poison = ['identity_hash' => bin2hex(random_bytes(16)), 'wake_url' => 'https://wake.example.org/v1/wake'];
$written = [
    'legacy rns-js' => legacy($node, ['client' => 'rns-js', 'mode' => 1] + $poison)[0],
    'legacy reticulum-php' => legacy($node, RegFixture::phpPeerMetadata('https://poison.example.org') + $poison)[0],
    'legacy rns-post-interface' => legacy($node, RegFixture::pollGatewayMetadata() + $poison)[0],
    'legacy other client' => legacy($node, ['client' => 'mystery'] + $poison)[0],
    'legacy with no client' => legacy($node, $poison)[0],
];
foreach ($written as $what => $r) {
    $md = json_decode((string) row($node, $r['interface_id'])['metadata_json'], true);
    check("$what: no identity_hash and no wake_url stored", is_array($md) && array_intersect_key($md, $poison) === [], json_encode($md));
}
$stored = json_decode((string) row($node, $victim['interface_id'])['metadata_json'], true);
check('signed: only client, implementation and mode', array_keys($stored) === ['client', 'implementation', 'mode'], json_encode($stored));

echo "\n(5) legacy rows claiming an identity that signs are removed with their traffic (§4.5)\n";
$owner = RegFixture::identity();
[$squat] = legacy($node, ['client' => 'rns-js', 'mode' => 1, 'identity_hash' => $owner['hash_hex']], 'squatter');
plantDependents($node, $squat['interface_id'], 'aa');
[$bystander] = legacy($node, ['client' => 'rns-js', 'mode' => 1, 'identity_hash' => bin2hex(random_bytes(16))], 'bystander');
plantDependents($node, $bystander['interface_id'], 'bb');
[$real, $log] = RegFixture::capture(static fn () => RegFixture::register($node, $owner));
check('the owner\'s first signed registration gets a NEW row, not the squatter\'s', is_array($real) && $real['interface_id'] !== $squat['interface_id']);
check('the squatter\'s row and everything it held, routed and queued are gone',
    array_sum(dependents($node, $squat['interface_id'])) === 0, json_encode(dependents($node, $squat['interface_id'])));
check('the bystander keeps its row and the nine things planted for it', array_sum(dependents($node, $bystander['interface_id'])) === 10, json_encode(dependents($node, $bystander['interface_id'])));
check('logged [REG-RETIRE] identity=H rows=1 dropped=2', str_contains($log, '[REG-RETIRE] identity=' . $owner['hash_hex'] . ' rows=1 dropped=2'), trim($log));
check('nothing passed to the signed row: it holds no local destination and no queue',
    count_rows($node, 'local_destinations', 'interface_id = ?', [$real['interface_id']]) === 0
    && count_rows($node, 'outbound_packets', 'interface_id = ?', [$real['interface_id']]) === 0);
check('the squatter\'s token now gets 401', authStatus($node, $squat['interface_id'], $squat['session_token']) === 401);
check('and its legacy registration claiming H gets 403 identity_requires_signature',
    RegFixture::outcome(legacy($node, ['client' => 'rns-js', 'mode' => 1, 'identity_hash' => $owner['hash_hex']])[0]) === [403, 'identity_requires_signature']);
RegFixture::db($node)->prepare("INSERT INTO interfaces (interface_id, name, session_token, status, metadata_json, claimed_identity_hash) VALUES ('racedin', 'r', 't', 'offline', '{\"client\":\"rns-js\"}', ?)")
    ->execute([$owner['hash_hex']]);
[$again, $log] = RegFixture::capture(static fn () => RegFixture::register($node, $owner));
check('a legacy row that raced in after the signed row is removed by the next signed re-bind',
    is_array($again) && row($node, 'racedin') === null && str_contains($log, '[REG-RETIRE] identity=' . $owner['hash_hex'] . ' rows=1'), trim($log));
check('a re-bind with nothing to remove logs no [REG-RETIRE]', !str_contains(RegFixture::capture(static fn () => RegFixture::register($node, $owner))[1], '[REG-RETIRE]'));

echo "\n(6) the switch refuses legacy browsers only\n";
$on = RegFixture::storage(['enforce_signed_registration' => true]);
$cases = [
    'rns-js with a claim' => ['client' => 'rns-js', 'mode' => 1, 'identity_hash' => bin2hex(random_bytes(16))],
    'rns-js without one' => ['client' => 'rns-js', 'mode' => 1],
    'reticulum-php' => RegFixture::phpPeerMetadata('https://switch.example.org'),
    'rns-post-interface' => RegFixture::pollGatewayMetadata(),
    'another client' => ['client' => 'mystery'],
    'no client' => [],
];
foreach ($cases as $what => $metadata) {
    $rowsBefore = count_rows($on, 'interfaces');
    [$r, $log] = legacy($on, $metadata);
    if (str_starts_with($what, 'rns-js')) {
        check("switch on: legacy $what -> 403 signature_required, saying to reload, logged, no row", RegFixture::outcome($r) === [403, 'signature_required']
            && $r instanceof ApiError && str_contains((string) $r->payload['message'], 'Reload')
            && str_contains($log, '[REG-REFUSED] 403 signature_required client=rns-js') && count_rows($on, 'interfaces') === $rowsBefore, trim($log));
    } else {
        check("switch on: legacy $what still accepted", is_array($r));
    }
}
check('switch on: legacy rns-js in mode 6 is still 400 transit_mode_not_allowed (step 1 first)',
    RegFixture::outcome(legacy($on, ['client' => 'rns-js', 'mode' => 6])[0]) === [400, 'transit_mode_not_allowed']);
[$s] = RegFixture::capture(static fn () => RegFixture::register($on, RegFixture::identity()));
check('switch on: a signed registration is unaffected', is_array($s));

echo "\n(7) the switch off: a legacy row claiming a signed identity gets 401 with its own token\n";
$path = sys_get_temp_dir() . '/rebind-rules-' . bin2hex(random_bytes(4)) . '.sqlite';
register_shutdown_function(static function () use ($path): void {
    foreach (['', '-wal', '-shm'] as $suffix) {
        @unlink($path . $suffix);
    }
});
$off = RegFixture::storage([], $path);
$signer = RegFixture::identity();
RegFixture::connect($off, $signer);
$oldRow = oldCodeRow($off, $signer['hash_hex']);
$before = row($off, $oldRow['interface_id']);
$changesBefore = changes($off);
check('[as old code writes it: H only in metadata_json] -> 401 with its own token',
    authStatus($off, $oldRow['interface_id'], $oldRow['session_token']) === 401);
$after = row($off, $oldRow['interface_id']);
$expected = $before;
$expected['claimed_identity_hash'] = $signer['hash_hex'];
check('...with nothing written but the claim (one row changed, last_seen_at untouched)', $after === $expected && changes($off) - $changesBefore === 1,
    json_encode(array_diff_assoc((array) $after, (array) $before)));
check('...and 401 again, writing nothing more', authStatus($off, $oldRow['interface_id'], $oldRow['session_token']) === 401 && changes($off) - $changesBefore === 1);
[$rebound, $log] = RegFixture::capture(static fn () => RegFixture::register($off, $signer));
check('the next signed registration removes it: [REG-RETIRE] rows=1', is_array($rebound) && row($off, $oldRow['interface_id']) === null
    && str_contains($log, '[REG-RETIRE] identity=' . $signer['hash_hex'] . ' rows=1'), trim($log));
RegFixture::db($off)->prepare("INSERT INTO interfaces (interface_id, name, session_token, status, metadata_json, claimed_identity_hash, created_at, last_seen_at)
                               VALUES ('filled', 'Retichat Web', 'filled-token', 'online', '{\"client\":\"rns-js\",\"mode\":1}', :h, 1, 1)")
    ->execute([':h' => $signer['hash_hex']]);
$before = row($off, 'filled');
$changesBefore = changes($off);
check('[with the claim filled] -> 401 with its own token, nothing written',
    authStatus($off, 'filled', 'filled-token') === 401 && row($off, 'filled') === $before && changes($off) === $changesBefore);
[$rebound, $log] = RegFixture::capture(static fn () => RegFixture::register($off, $signer));
check('...the next signed registration removes it: [REG-RETIRE] rows=1', is_array($rebound) && row($off, 'filled') === null
    && str_contains($log, '[REG-RETIRE] identity=' . $signer['hash_hex'] . ' rows=1'), trim($log));
$neverSigned = bin2hex(random_bytes(16));
$plain = oldCodeRow($off, $neverSigned);
check('a legacy row of an identity that never signed still gets 200', authStatus($off, $plain['interface_id'], $plain['session_token']) === 200);
check('...and its claim is filled from metadata_json, for §4.5 and §9', row($off, $plain['interface_id'])['claimed_identity_hash'] === $neverSigned);
[$claimant] = legacy($off, ['client' => 'rns-js', 'mode' => 1, 'identity_hash' => bin2hex(random_bytes(16))]);
check('a legacy row registered under Stage 1, whose identity never signed, gets 200', authStatus($off, $claimant['interface_id'], $claimant['session_token']) === 200);
$enforcingOff = RegFixture::storage(['enforce_signed_registration' => true], $path);
check('...and 401 once the switch is on', authStatus($enforcingOff, $claimant['interface_id'], $claimant['session_token']) === 401);

echo "\n(8) the two legacy 403s are logged once per row and count\n";
$quiet = RegFixture::storage([], $path);
$loud = RegFixture::identity();
RegFixture::connect($quiet, $loud);
$lines = 0;
$changesBefore = changes($quiet);
for ($i = 0; $i < 6; $i++) {
    [$r, $log] = legacy($quiet, ['client' => 'rns-js', 'mode' => 1, 'identity_hash' => $loud['hash_hex']]);
    $lines += substr_count($log, '[REG-REFUSED]');
    check('legacy registration ' . ($i + 1) . ' claiming a signed identity -> 403 identity_requires_signature', RegFixture::outcome($r) === [403, 'identity_requires_signature']);
}
check('six of them log one [REG-REFUSED] line, and write once', $lines === 1 && changes($quiet) - $changesBefore === 1, "lines=$lines writes=" . (changes($quiet) - $changesBefore));
RegFixture::connect($quiet, $loud);
$lines = 0;
for ($i = 0; $i < 4; $i++) {
    [, $log] = legacy($quiet, ['client' => 'rns-js', 'mode' => 1, 'identity_hash' => $loud['hash_hex']]);
    $lines += substr_count($log, '[REG-REFUSED] 403 identity_requires_signature client=rns-js identity=' . $loud['hash_hex']);
}
check('a new signed registration (the count moved) allows one more line', $lines === 1, "lines=$lines");
$c1 = bin2hex(random_bytes(16));
$c2 = bin2hex(random_bytes(16));
legacy($quiet, ['client' => 'rns-js', 'mode' => 1, 'identity_hash' => $c1]);
legacy($quiet, ['client' => 'rns-js', 'mode' => 1, 'identity_hash' => $c2]);
$switched = RegFixture::storage(['enforce_signed_registration' => true], $path);
foreach (['a legacy row\'s claim' => $c1, 'another legacy row\'s claim' => $c2] as $what => $c) {
    $lines = 0;
    for ($i = 0; $i < 4; $i++) {
        [$r, $log] = legacy($switched, ['client' => 'rns-js', 'mode' => 1, 'identity_hash' => $c]);
        $lines += substr_count($log, '[REG-REFUSED] 403 signature_required');
    }
    check("switch on, $what: four refusals, one line (one per legacy row)", $lines === 1 && RegFixture::outcome($r) === [403, 'signature_required'], "lines=$lines");
}
foreach (['no claim' => [], 'a claim with no row' => ['identity_hash' => bin2hex(random_bytes(16))]] as $what => $extra) {
    $lines = 0;
    for ($i = 0; $i < 3; $i++) {
        [, $log] = legacy($switched, ['client' => 'rns-js', 'mode' => 1] + $extra);
        $lines += substr_count($log, '[REG-REFUSED] 403 signature_required');
    }
    check("switch on, $what: logged every time (three lines)", $lines === 3, "lines=$lines");
}

echo "\n(9) no SQL in php/src compares metadata_json with a value from a request (§12)\n";
/**
 * Every comparison on metadata_json in $code: LIKE, =, <>, IN, REGEXP and
 * the like with metadata_json on either side, any JSON function or operator
 * applied to it, and a literal that ends at metadata_json in a WHERE (an
 * operator concatenated in). An assignment in a SET clause is not one.
 *
 * @return list<array{line: int, function: ?string, operator: string, placeholder: ?string}>
 */
function metadataJsonComparisons(string $code): array
{
    $found = [];
    $depth = 0;
    $function = null;
    $functionDepth = null;
    $pending = null;
    $tokens = token_get_all($code);
    foreach ($tokens as $i => $token) {
        if (is_array($token) && $token[0] === T_FUNCTION) {
            for ($j = $i + 1; isset($tokens[$j]) && is_array($tokens[$j]) && in_array($tokens[$j][0], [T_WHITESPACE, T_COMMENT], true); $j++) {
            }
            if (isset($tokens[$j]) && is_array($tokens[$j]) && $tokens[$j][0] === T_STRING && $function === null) {
                $pending = $tokens[$j][1];
            }
            continue;
        }
        if ($token === ';' && $pending !== null && $functionDepth === null) {
            $pending = null;
        }
        if ($token === '{' || (is_array($token) && in_array($token[0], [T_CURLY_OPEN, T_DOLLAR_OPEN_CURLY_BRACES], true))) {
            if ($pending !== null && $functionDepth === null) {
                $function = $pending;
                $functionDepth = $depth;
                $pending = null;
            }
            $depth++;
            continue;
        }
        if ($token === '}') {
            $depth--;
            if ($functionDepth !== null && $depth === $functionDepth) {
                $function = null;
                $functionDepth = null;
            }
            continue;
        }
        if (!is_array($token) || !in_array($token[0], [T_CONSTANT_ENCAPSED_STRING, T_ENCAPSED_AND_WHITESPACE], true)) {
            continue;
        }
        $text = $token[0] === T_CONSTANT_ENCAPSED_STRING ? substr($token[1], 1, -1) : $token[1];
        if (preg_match_all('/(?:\b\w+\.)?\bmetadata_json\b/i', $text, $matches, PREG_OFFSET_CAPTURE) === 0) {
            continue;
        }
        foreach ($matches[0] as [$word, $offset]) {
            $before = substr($text, 0, $offset);
            $after = substr($text, $offset + strlen($word));
            preg_match_all('/\b(SET|WHERE|AND|OR|ON|HAVING|WHEN|SELECT|VALUES|NOT)\b/i', $before, $keywords);
            $keyword = strtoupper((string) (end($keywords[1]) ?: ''));
            $operator = null;
            if (preg_match('/\b(json_\w+)\s*\(\s*\z/i', $before, $m) === 1) {
                $operator = strtoupper($m[1]);
            } elseif (preg_match('/\A\s*(->>?)/', $after, $m) === 1) {
                $operator = $m[1];
            } elseif (preg_match('/\A\s*(?:(NOT\s+LIKE|LIKE|NOT\s+IN|IN|REGEXP|RLIKE|GLOB)\b|(<=>|<>|!=|=))/i', $after, $m) === 1) {
                $operator = strtoupper(preg_replace('/\s+/', ' ', $m[1] !== '' ? $m[1] : $m[2]));
                if ($operator === '=' && $keyword === 'SET') {
                    $operator = null; // an assignment
                }
            } elseif (preg_match('/(NOT\s+LIKE|LIKE|<=>|<>|!=|=|\bIN\s*\()\s*\z/i', $before, $m) === 1 && $keyword !== 'SET') {
                $operator = strtoupper(preg_replace('/\s+/', ' ', $m[1])) . ' (right side)';
            } elseif (trim($after) === '' && in_array($keyword, ['WHERE', 'AND', 'OR', 'ON', 'HAVING', 'WHEN', 'NOT'], true)) {
                $operator = 'concatenated';
            }
            if ($operator === null) {
                continue;
            }
            preg_match('/\A\s*(?:NOT\s+LIKE|LIKE|NOT\s+IN|IN|<=>|<>|!=|=)\s*\(?\s*(:\w+)/i', $after, $p);
            $found[] = [
                'line' => $token[2] + substr_count($before, "\n"),
                'function' => $function,
                'operator' => $operator,
                'placeholder' => $p[1] ?? null,
            ];
        }
    }

    return $found;
}

/** Whether $function in $code binds $placeholder with bindValue to one string literal, and nothing else. */
function boundToConstant(string $code, string $function, string $placeholder): bool
{
    $tokens = array_values(array_filter(token_get_all($code), static fn ($t): bool => !is_array($t) || !in_array($t[0], [T_WHITESPACE, T_COMMENT, T_DOC_COMMENT], true)));
    $inside = false;
    $depth = 0;
    $start = null;
    $constant = 0;
    $other = 0;
    foreach ($tokens as $i => $t) {
        if (!$inside && is_array($t) && $t[0] === T_FUNCTION && is_array($tokens[$i + 1] ?? null) && $tokens[$i + 1][1] === $function) {
            $inside = true;
            $start = null;
            continue;
        }
        if (!$inside) {
            continue;
        }
        if ($t === '{') {
            $depth++;
            $start ??= $i;
        } elseif ($t === '}') {
            $depth--;
            if ($depth === 0) {
                break;
            }
        }
        if (is_array($t) && $t[0] === T_STRING && in_array($t[1], ['bindValue', 'bindParam'], true) && ($tokens[$i + 1] ?? null) === '('
            && is_array($tokens[$i + 2] ?? null) && $tokens[$i + 2][0] === T_CONSTANT_ENCAPSED_STRING && substr($tokens[$i + 2][1], 1, -1) === $placeholder) {
            $value = $tokens[$i + 4] ?? null;
            $next = $tokens[$i + 5] ?? null;
            if ($t[1] === 'bindValue' && ($tokens[$i + 3] ?? null) === ',' && is_array($value) && $value[0] === T_CONSTANT_ENCAPSED_STRING && ($next === ',' || $next === ')')) {
                $constant++;
            } else {
                $other++;
            }
        }
    }

    return $constant === 1 && $other === 0;
}

$selfTests = [
    'interfaceByIdentityHash\'s LIKE :hash_pattern (on main)' => ['<?php function interfaceByIdentityHash() { $s = $this->db->prepare(\'SELECT interface_id FROM interfaces
             WHERE metadata_json LIKE :hash_pattern\'); }', 1],
    'a JSON function' => ['<?php function f() { $this->db->prepare("SELECT 1 FROM interfaces i WHERE JSON_EXTRACT(i.metadata_json, \'$.identity_hash\') = :h"); }', 1],
    'IN with an alias' => ['<?php function f() { $this->db->prepare(\'SELECT 1 FROM interfaces i WHERE i.metadata_json IN (:a, :b)\'); }', 1],
    'the value on the right' => ['<?php function f() { $this->db->prepare(\'SELECT 1 FROM interfaces WHERE :m = metadata_json\'); }', 1],
    'an operator concatenated in' => ['<?php function f($op) { $this->db->prepare(\'SELECT 1 FROM interfaces WHERE status = :s AND metadata_json \' . $op . \' :x\'); }', 1],
    'a JSON operator' => ['<?php function f() { $this->db->prepare("SELECT 1 FROM interfaces WHERE metadata_json->>\'$.client\' = :c"); }', 1],
    'an assignment in SET, and an upsert\'s' => ['<?php function f() { $this->db->prepare(\'UPDATE interfaces SET name = :name, metadata_json = :metadata_json WHERE interface_id = :id\');
        $this->db->prepare(\'INSERT INTO interfaces (metadata_json) VALUES (:m) ON CONFLICT(interface_id) DO UPDATE SET metadata_json = excluded.metadata_json\'); }', 0],
    'a column read' => ['<?php function f() { $this->db->prepare(\'SELECT interface_id, metadata_json FROM interfaces WHERE interface_id = :id\'); }', 0],
];
foreach ($selfTests as $label => [$code, $want]) {
    $got = metadataJsonComparisons($code);
    check("scanner self-test: $label -> $want comparison" . ($want === 1 ? '' : 's'), count($got) === $want, json_encode($got));
}
$requestBound = '<?php function recentNodeInterfacesByStatus($p) { $s = $this->db->prepare(\'SELECT 1 FROM interfaces WHERE metadata_json LIKE :poll_gateway\');
    $s->bindValue(\':poll_gateway\', $p, PDO::PARAM_STR); }';
check('scanner self-test: the allowed comparison bound to a request value is not allowed', !boundToConstant($requestBound, 'recentNodeInterfacesByStatus', ':poll_gateway'));
$constantBound = '<?php function recentNodeInterfacesByStatus() { $s = $this->db->prepare(\'SELECT 1 FROM interfaces WHERE metadata_json LIKE :poll_gateway\');
    $s->bindValue(\':poll_gateway\', \'%"client":"rns-post-interface"%\', PDO::PARAM_STR); }';
check('scanner self-test: ...and bound to a constant it is', boundToConstant($constantBound, 'recentNodeInterfacesByStatus', ':poll_gateway'));

$src = dirname(__DIR__) . '/src';
$all = [];
$files = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($src, FilesystemIterator::SKIP_DOTS));
$scanned = 0;
foreach ($files as $file) {
    if ($file->getExtension() !== 'php') {
        continue;
    }
    $scanned++;
    $code = (string) file_get_contents($file->getPathname());
    foreach (metadataJsonComparisons($code) as $hit) {
        $hit['file'] = substr($file->getPathname(), strlen($src) + 1);
        $hit['bound_to_constant'] = $hit['function'] !== null && $hit['placeholder'] !== null && boundToConstant($code, $hit['function'], $hit['placeholder']);
        $all[] = $hit;
    }
}
$allowed = array_values(array_filter($all, static fn (array $h): bool => $h['file'] === 'lib/request_debug_report_trait.php'
    && $h['function'] === 'recentNodeInterfacesByStatus' && $h['operator'] === 'LIKE' && $h['placeholder'] === ':poll_gateway' && $h['bound_to_constant']));
$others = array_values(array_filter($all, static fn (array $h): bool => !in_array($h, $allowed, true)));
check("php/src ($scanned files): exactly one comparison on metadata_json, recentNodeInterfacesByStatus's LIKE :poll_gateway, bound to a constant",
    count($allowed) === 1 && count($all) === 1, json_encode($all));
foreach ($others as $hit) {
    check("no other comparison: {$hit['file']}:{$hit['line']} in {$hit['function']}() ({$hit['operator']} {$hit['placeholder']})", false);
}

echo "\n$pass passed, $fail failed\n";
exit($fail === 0 ? 0 : 1);
