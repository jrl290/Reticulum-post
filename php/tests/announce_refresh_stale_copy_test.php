<?php
/**
 * The announce refresh never spreads a copy the node chose not to use.
 *
 * shouldRelayAcceptedPacket() relays a 'validated' announce once per
 * announce_refresh_seconds per destination, and the relay re-sends THAT copy
 * (relayPacketBase64 rebuilds it from the copy's own payload and hop count),
 * not the announce the path keeps. A private staging run caught it refreshing
 * looped copies at hops 69-128 ('announce_ignored', longer than the path) and
 * one at hops 129 ('announce_hops_exceeded') to browsers 358-666 s after the
 * first relay. RNS 1.5.2 does not consider an announce past PATHFINDER_M
 * (Transport.py:2211) and retransmits only an announce it adds to its path
 * table (Transport.py:2298, 2351-2373).
 *
 * Runs the real Storage on in-memory SQLite and feeds signed announces through
 * ingestInboundBatchInline(), the path every exchange takes, with the refresh
 * clock (path_entries.updated_at) already past 300 s for each copy:
 *   (1) a copy past the hop limit is not relayed and leaves the clock alone,
 *       whether its blob is known or new;
 *   (2) a longer copy of the emission the path keeps is not relayed;
 *   (3) an older emission at the same hop count is not relayed;
 *   (4) the copy the path keeps, at its hop count, is still relayed as the
 *       refresh, once;
 *   (5) a cache request for a stored copy past the hop limit does not replay
 *       it, while one for a stored copy within the limit does.
 *
 * Run: php tests/announce_refresh_stale_copy_test.php
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
$edKeypair = sodium_crypto_sign_keypair();
$edSecret = sodium_crypto_sign_secretkey($edKeypair);
$publicKey = random_bytes(32) . sodium_crypto_sign_publickey($edKeypair);
$nameHash = substr(hash('sha256', 'lxmf.delivery', true), 0, 10);
$destinationHash = substr(hash('sha256', $nameHash . substr(hash('sha256', $publicKey, true), 0, 16), true), 0, 16);
$destinationHex = bin2hex($destinationHash);

function randomBlob(int $emitted): string
{
    return random_bytes(5) . substr(pack('J', $emitted), 3, 5);
}

/** HEADER_2, in transport from $transportId, SINGLE, ANNOUNCE, context NONE. */
function announceRaw(string $randomBlob, int $wireHops, string $transportId): string
{
    global $edSecret, $publicKey, $nameHash, $destinationHash;
    $appData = 'stale copy test';
    $signature = sodium_crypto_sign_detached($destinationHash . $publicKey . $nameHash . $randomBlob . $appData, $edSecret);
    return chr((1 << 6) | (1 << 4) | 1) . chr($wireHops) . $transportId . $destinationHash . chr(0x00)
        . $publicKey . $nameHash . $randomBlob . $signature . $appData;
}

/** HEADER_1 DATA to the destination, context CACHE_REQUEST, asking for a packet hash. */
function cacheRequestRaw(string $packetHash): string
{
    global $destinationHash;
    return chr(0) . chr(0) . $destinationHash . chr(0x08) . $packetHash;
}

// ── The node: a gateway bridge and two browsers ───────────────────────────
$storage = new Storage(['storage' => ['backend' => 'sqlite', 'sqlite_path' => ':memory:']]);
$storage->migrateIfNeeded();
$db = (new ReflectionProperty($storage, 'db'))->getValue($storage);

$gateway = str_repeat('a', 32);
$browser1 = str_repeat('b', 32);
$browser2 = str_repeat('c', 32);
$browsers = [$browser1, $browser2];
foreach ([$gateway => ['client' => 'rns-post-interface', 'mode' => 6], $browser1 => ['client' => 'rns-js'], $browser2 => ['client' => 'rns-js']] as $iface => $meta) {
    $db->prepare("INSERT INTO interfaces (interface_id, name, session_token, bitrate, mtu, status, metadata_json, created_at, last_seen_at)
                  VALUES (:i, 'test', 'tok', 1000000, 500, 'online', :m, 1, :t)")
        ->execute([':i' => $iface, ':m' => json_encode($meta), ':t' => time()]);
}
$gatewayTransportId = random_bytes(16);

/**
 * Deliver one packet from $iface as an exchange would, after marking every
 * packet queued so far as fetched and acknowledged, so a relay shows as a new
 * row. Returns the processing summary, the relay_announce rows queued per
 * interface, and what the node recorded for the packet.
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
    $last = $db->query('SELECT announce_status, announce_reason, packet_hash_hex FROM inbound_packets ORDER BY packet_record_id DESC LIMIT 1')
        ->fetch(PDO::FETCH_ASSOC);
    return [
        'summary' => $result['processing'] ?? [],
        'rows' => $rows,
        'status' => (string) ($last['announce_status'] ?? ''),
        'reason' => (string) ($last['announce_reason'] ?? ''),
        'hash' => (string) ($last['packet_hash_hex'] ?? ''),
    ];
}

function path(): array
{
    global $db, $destinationHex;
    $stmt = $db->prepare('SELECT hops, updated_at, packet_hash_hex FROM path_entries WHERE destination_hash_hex = :d');
    $stmt->execute([':d' => $destinationHex]);
    $row = $stmt->fetch(PDO::FETCH_ASSOC);
    return is_array($row) ? $row : [];
}

/** Put the last relay 301 s back, past announce_refresh_seconds (300). */
function clockPastRefresh(): int
{
    global $db, $destinationHex;
    $at = time() - 301;
    $db->prepare('UPDATE path_entries SET updated_at = :u WHERE destination_hash_hex = :d')->execute([':u' => $at, ':d' => $destinationHex]);
    return $at;
}

function notRelayed(array $r): bool
{
    return ($r['summary']['relay_packets_queued'] ?? -1) === 0 && $r['rows'] === [];
}

function relayedToEachBrowser(array $r): bool
{
    global $browsers;
    return $r['rows'] === array_fill_keys($browsers, 1);
}

$now = time();
$blobX = randomBlob($now - 60);   // the emission the path keeps
$blobY = randomBlob($now - 30);   // a newer emission that only ever arrives past the limit
$blobW = randomBlob($now - 600);  // an older emission

echo "(0) the first copy of an emission is relayed\n";
$r = deliver($gateway, announceRaw($blobX, 3, $gatewayTransportId));
$hashX = $r['hash'];
check('path_updated, relayed once to each browser', $r['status'] === 'path_updated' && relayedToEachBrowser($r), json_encode($r));
check('path is 4 hops and keeps this emission', (int) (path()['hops'] ?? -1) === 4 && (path()['packet_hash_hex'] ?? '') === $hashX, json_encode(path()));

// ── (1) past the hop limit ───────────────────────────────────────────────
echo "(1) a copy past the hop limit is not relayed, refresh clock or not\n";
$clock = clockPastRefresh();
$r = deliver($gateway, announceRaw($blobX, 128, $gatewayTransportId)); // 129 hops here
check('known emission at 129 hops: validated / announce_hops_exceeded', [$r['status'], $r['reason']] === ['validated', 'announce_hops_exceeded'], "{$r['status']} / {$r['reason']}");
check('known emission at 129 hops: not relayed', notRelayed($r), json_encode($r));
check('known emission at 129 hops: refresh clock untouched', (int) (path()['updated_at'] ?? -1) === $clock, json_encode(path()));
$clock = clockPastRefresh();
$r = deliver($gateway, announceRaw($blobY, 129, $gatewayTransportId)); // 130 hops here
$hashY = $r['hash'];
check('new emission at 130 hops: validated / announce_hops_exceeded', [$r['status'], $r['reason']] === ['validated', 'announce_hops_exceeded'], "{$r['status']} / {$r['reason']}");
check('new emission at 130 hops: not relayed', notRelayed($r), json_encode($r));
check('new emission at 130 hops: path and refresh clock untouched',
    (int) (path()['updated_at'] ?? -1) === $clock && (path()['packet_hash_hex'] ?? '') === $hashX && (int) (path()['hops'] ?? -1) === 4, json_encode(path()));

// ── (2) a longer copy of the kept emission ───────────────────────────────
echo "(2) a longer copy of the emission the path keeps is not relayed\n";
$clock = clockPastRefresh();
$r = deliver($gateway, announceRaw($blobX, 69, $gatewayTransportId)); // 70 hops here
check('validated / announce_ignored', [$r['status'], $r['reason']] === ['validated', 'announce_ignored'], "{$r['status']} / {$r['reason']}");
check('not relayed', notRelayed($r), json_encode($r));
check('refresh clock untouched', (int) (path()['updated_at'] ?? -1) === $clock, json_encode(path()));

// ── (3) an older emission ────────────────────────────────────────────────
echo "(3) an older emission at the path's hop count is not relayed\n";
$clock = clockPastRefresh();
$r = deliver($gateway, announceRaw($blobW, 3, $gatewayTransportId)); // 4 hops here
check('validated / announce_ignored', [$r['status'], $r['reason']] === ['validated', 'announce_ignored'], "{$r['status']} / {$r['reason']}");
check('not relayed', notRelayed($r), json_encode($r));
check('refresh clock untouched', (int) (path()['updated_at'] ?? -1) === $clock, json_encode(path()));

// ── (4) the kept copy still refreshes ────────────────────────────────────
echo "(4) the copy the path keeps, at its hop count, is relayed as the refresh\n";
clockPastRefresh();
$r = deliver($gateway, announceRaw($blobX, 3, $gatewayTransportId)); // 4 hops here
check('validated / announce_ignored', [$r['status'], $r['reason']] === ['validated', 'announce_ignored'], "{$r['status']} / {$r['reason']}");
check('relayed once to each browser', relayedToEachBrowser($r), json_encode($r));
check('the refresh restarts the clock', (int) (path()['updated_at'] ?? -1) >= $now, json_encode(path()));
$r = deliver($gateway, announceRaw($blobX, 3, $gatewayTransportId));
check('the next copy inside 300 s is not relayed', notRelayed($r), json_encode($r));

// ── (5) cache requests ───────────────────────────────────────────────────
echo "(5) a cache request replays a stored copy only if it is within the hop limit\n";
$r = deliver($browser1, cacheRequestRaw(hex2bin($hashY)));
check('the copy past the limit is not replayed', ($r['summary']['cache_requests_replayed'] ?? -1) === 0 && $r['rows'] === [], json_encode($r));
$r = deliver($browser1, cacheRequestRaw(hex2bin($hashX)));
check('a copy within the limit is replayed (the request works)', ($r['summary']['cache_requests_replayed'] ?? -1) === 1 && $r['rows'] !== [], json_encode($r));

echo "\n$pass passed, $fail failed\n";
exit($fail === 0 ? 0 : 1);
