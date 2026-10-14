<?php
/**
 * A copy of an announce whose random blob this node has already heard may
 * move the path, but it is not relayed again as a path update.
 *
 * The gateway can hand the node two copies of one emission, the second with
 * fewer hops. upsertPathFromAnnounce() keeps the second for routing
 * ('shorter_path_replaced'; see path_selection_test.php for why), and until
 * this test it also answered 'path_updated' for it, so shouldRelayAcceptedPacket()
 * relayed the same emission to every client a second time. RNS 1.5.2 does not
 * re-add a heard random blob on hop count (Transport.py:2236-2251, 2267-2275),
 * and so does not rebroadcast it. Such a copy now answers 'validated': the
 * once-per-announce_refresh_seconds refresh rule decides whether it goes out,
 * and the path's updated_at, which is that rule's clock, is left as it was.
 *
 * Runs the real Storage on in-memory SQLite and feeds signed announces through
 * ingestInboundBatchInline(), the path every exchange takes, then reads what
 * the relay queued in outbound_packets:
 *   (1) the first copy of an emission is relayed to each client;
 *   (2) a second copy, same blob, fewer hops, moves the path and is not relayed,
 *       and does not restart the refresh clock;
 *   (3) a new blob is relayed;
 *   (4) a seen-blob copy that moves the path is still relayed as a refresh once
 *       announce_refresh_seconds have passed, like any 'validated' announce;
 *   (5) a seen-blob copy that replaces an unusable path (its interface went
 *       offline) moves the path and is not relayed;
 *   (6) a new blob arriving the same way is relayed.
 *
 * Run: php tests/announce_relay_seen_blob_test.php
 */
declare(strict_types=1);

$root = dirname(__DIR__);
require_once $root . '/src/lib/database.php';
require_once $root . '/src/index.php';

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
        echo "  FAIL $label" . ($detail !== '' ? " — $detail" : '') . "\n";
    }
}

// ── A signed announce, as RNS Destination.announce() builds it ────────────
// public key = X25519 (32) + Ed25519 (32); payload = public key, name hash
// (10), random hash (10: 5 random bytes + 5-byte big-endian emission time),
// signature (64) over destination hash + public key + name hash + random hash
// + app data, then app data.

$edKeypair = sodium_crypto_sign_keypair();
$edSecret = sodium_crypto_sign_secretkey($edKeypair);
$publicKey = random_bytes(32) . sodium_crypto_sign_publickey($edKeypair);
$nameHash = substr(hash('sha256', 'lxmf.delivery', true), 0, 10);
$identityHash = substr(hash('sha256', $publicKey, true), 0, 16);
$destinationHash = substr(hash('sha256', $nameHash . $identityHash, true), 0, 16);
$destinationHex = bin2hex($destinationHash);
$appData = 'seen-blob test';

function randomBlob(int $emitted): string
{
    return random_bytes(5) . substr(pack('J', $emitted), 3, 5);
}

/** HEADER_2, in transport from $transportId, SINGLE, ANNOUNCE, context NONE. */
function announceRaw(string $randomBlob, int $wireHops, string $transportId): string
{
    global $edSecret, $publicKey, $nameHash, $destinationHash, $appData;
    $signature = sodium_crypto_sign_detached($destinationHash . $publicKey . $nameHash . $randomBlob . $appData, $edSecret);
    $flags = (1 << 6) | (1 << 4) | (0 << 2) | 1;
    return chr($flags) . chr($wireHops) . $transportId . $destinationHash . chr(0x00)
        . $publicKey . $nameHash . $randomBlob . $signature . $appData;
}

// ── The node: one gateway bridge, a second gateway, two browsers ──────────

$storage = new Storage(['storage' => ['backend' => 'sqlite', 'sqlite_path' => ':memory:']]);
$storage->migrateIfNeeded();
$db = (new ReflectionProperty($storage, 'db'))->getValue($storage);

$gateway = str_repeat('a', 32);
$gateway2 = str_repeat('d', 32);
$browser1 = str_repeat('b', 32);
$browser2 = str_repeat('c', 32);
$browsers = [$browser1, $browser2];
$bridgeMeta = json_encode(['client' => 'rns-post-interface', 'mode' => 6]);
$browserMeta = json_encode(['client' => 'rns-js']);
foreach ([$gateway => $bridgeMeta, $gateway2 => $bridgeMeta, $browser1 => $browserMeta, $browser2 => $browserMeta] as $iface => $meta) {
    $db->prepare("INSERT INTO interfaces (interface_id, name, session_token, bitrate, mtu, status, metadata_json, created_at, last_seen_at)
                  VALUES (:i, 'test', 'tok', 1000000, 500, 'online', :m, 1, :t)")
        ->execute([':i' => $iface, ':m' => $meta, ':t' => time()]);
}
$gatewayTransportId = random_bytes(16);
$gateway2TransportId = random_bytes(16);

/**
 * Deliver one announce from $iface as an exchange would, after marking every
 * packet queued so far as fetched and acknowledged (so a relay of this copy
 * shows as a new row instead of replacing an undelivered one). Returns the
 * relay count from the processing summary, the relay_announce rows it queued
 * per interface, and the status the node recorded for the copy.
 */
function deliver(string $iface, string $raw): array
{
    global $storage, $db;
    static $batch = 0;
    $db->exec('UPDATE outbound_packets SET delivered_at = 1, delivered_batch_id = \'fetched\', acked_at = 1 WHERE acked_at IS NULL');
    $result = $storage->ingestInboundBatchInline($iface, 'batch-' . (++$batch), [base64_encode($raw)]);
    $rows = [];
    foreach ($db->query("SELECT interface_id, COUNT(*) n FROM outbound_packets
                          WHERE acked_at IS NULL AND queue_reason = 'relay_announce' GROUP BY interface_id") as $row) {
        $rows[(string) $row['interface_id']] = (int) $row['n'];
    }
    $last = $db->query('SELECT filter_status, announce_status, announce_reason FROM inbound_packets ORDER BY packet_record_id DESC LIMIT 1')
        ->fetch(PDO::FETCH_ASSOC);
    return [
        'relayed' => (int) ($result['processing']['relay_packets_queued'] ?? -1),
        'rows' => $rows,
        'status' => (string) ($last['announce_status'] ?? ''),
        'reason' => (string) ($last['announce_reason'] ?? ''),
        'filter' => (string) ($last['filter_status'] ?? ''),
    ];
}

function path(): array
{
    global $db, $destinationHex;
    $stmt = $db->prepare('SELECT hops, interface_id, updated_at, random_blobs_json FROM path_entries WHERE destination_hash_hex = :d');
    $stmt->execute([':d' => $destinationHex]);
    $row = $stmt->fetch(PDO::FETCH_ASSOC);
    return is_array($row) ? $row : [];
}

function setPathUpdatedAt(int $at): void
{
    global $db, $destinationHex;
    $db->prepare('UPDATE path_entries SET updated_at = :u WHERE destination_hash_hex = :d')->execute([':u' => $at, ':d' => $destinationHex]);
}

function relayedToEachBrowser(array $r): bool
{
    global $browsers;
    return $r['relayed'] === 2 && $r['rows'] === array_fill_keys($browsers, 1);
}

$now = time();
$blobX = randomBlob($now - 60);
$blobY = randomBlob($now - 30);
$blobZ = randomBlob($now - 10);

// ── (1) first copy of an emission ─────────────────────────────────────────
echo "(1) the first copy of an emission is relayed\n";
$r = deliver($gateway, announceRaw($blobX, 3, $gatewayTransportId));
check('accepted by the filter', $r['filter'] === 'accepted', $r['filter']);
check('path_updated / new_destination', [$r['status'], $r['reason']] === ['path_updated', 'new_destination'], "{$r['status']} / {$r['reason']}");
check('relayed once to each browser, not to the other gateway', relayedToEachBrowser($r), json_encode($r));
check('path is 4 hops via the gateway', (int) (path()['hops'] ?? -1) === 4 && (path()['interface_id'] ?? '') === $gateway, json_encode(path()));

// ── (2) same blob, fewer hops ─────────────────────────────────────────────
echo "(2) a second copy, same blob and fewer hops, moves the path and is not relayed\n";
$clock = $now - 100; // the last relay, inside announce_refresh_seconds (300)
setPathUpdatedAt($clock);
$r = deliver($gateway, announceRaw($blobX, 1, $gatewayTransportId));
check('accepted by the filter (duplicate single announce)', $r['filter'] === 'accepted', $r['filter']);
check('validated / shorter_path_replaced', [$r['status'], $r['reason']] === ['validated', 'shorter_path_replaced'], "{$r['status']} / {$r['reason']}");
check('path moved to 2 hops', (int) (path()['hops'] ?? -1) === 2, json_encode(path()));
check('nothing relayed', $r['relayed'] === 0 && $r['rows'] === [], json_encode($r));
check('the refresh clock is not restarted', (int) (path()['updated_at'] ?? -1) === $clock, json_encode(path()));

// ── (3) a new blob ────────────────────────────────────────────────────────
echo "(3) a new emission is relayed\n";
$r = deliver($gateway, announceRaw($blobY, 1, $gatewayTransportId));
check('path_updated / better_or_equal_hops_newer_announce', [$r['status'], $r['reason']] === ['path_updated', 'better_or_equal_hops_newer_announce'], "{$r['status']} / {$r['reason']}");
check('relayed once to each browser', relayedToEachBrowser($r), json_encode($r));
check('the relay restarts the refresh clock', (int) (path()['updated_at'] ?? -1) >= $now, json_encode(path()));

// ── (4) the refresh rule still applies to a seen-blob path update ─────────
echo "(4) a seen-blob copy that moves the path is relayed as a refresh after 300 s\n";
setPathUpdatedAt($now - 301);
$r = deliver($gateway, announceRaw($blobY, 0, $gatewayTransportId));
check('validated / shorter_path_replaced', [$r['status'], $r['reason']] === ['validated', 'shorter_path_replaced'], "{$r['status']} / {$r['reason']}");
check('path moved to 1 hop', (int) (path()['hops'] ?? -1) === 1, json_encode(path()));
check('relayed once to each browser as the refresh', relayedToEachBrowser($r), json_encode($r));
check('the refresh restarts the clock', (int) (path()['updated_at'] ?? -1) >= $now, json_encode(path()));

// ── (5) seen blob replacing an unusable path ──────────────────────────────
echo "(5) a seen-blob copy that replaces an unusable path is not relayed\n";
$db->prepare("UPDATE interfaces SET status = 'offline' WHERE interface_id = :i")->execute([':i' => $gateway]);
$clock = (int) (path()['updated_at'] ?? 0);
$r = deliver($gateway2, announceRaw($blobY, 2, $gateway2TransportId));
check('validated / unusable_path_replaced', [$r['status'], $r['reason']] === ['validated', 'unusable_path_replaced'], "{$r['status']} / {$r['reason']}");
check('path moved to the second gateway, 3 hops', (path()['interface_id'] ?? '') === $gateway2 && (int) (path()['hops'] ?? -1) === 3, json_encode(path()));
check('nothing relayed', $r['relayed'] === 0 && $r['rows'] === [], json_encode($r));
check('the refresh clock is not restarted', (int) (path()['updated_at'] ?? -1) === $clock, json_encode(path()));

// ── (6) a new blob the same way ───────────────────────────────────────────
echo "(6) a new emission through the second gateway is relayed\n";
$r = deliver($gateway2, announceRaw($blobZ, 2, $gateway2TransportId));
check('path_updated', $r['status'] === 'path_updated', "{$r['status']} / {$r['reason']}");
check('relayed once to each browser', relayedToEachBrowser($r), json_encode($r));
check('all three emissions are on record', count(json_decode((string) (path()['random_blobs_json'] ?? '[]'), true)) === 3, json_encode(path()));

echo "\n$pass passed, $fail failed\n";
exit($fail === 0 ? 0 : 1);
