<?php
/**
 * Past the inbound TTL the node keeps ONE stored copy of each announce a path
 * points at: the copy a path request, a cache request and seeding would use.
 *
 * deleteExpiredPacketHistory() spares inbound rows whose packet_hash_hex a
 * path entry holds, so the path can answer path requests (Transport.py:2845
 * keeps the path table and its packet cache together). The hash leaves out
 * the hop count and the transport id, so every copy of one emission, over
 * every route and every retry, carries it and was spared: on retichat.com on
 * 2026-10-10, 61,354 rows held 26,108 announces, 206 MB of a 306 MB database,
 * and the storage budget could not get under its cap. RNS caches one packet
 * per hash.
 *
 * Runs the real Storage on in-memory SQLite, feeds signed announces through
 * ingestInboundBatchInline(), ages rows past the TTL and runs maintenance:
 *   (a) three old copies of one referenced emission (a longer route, plus a
 *       same-hops retry) leave one row: the path's copy, at the path's hop
 *       count, the newest of those;
 *   (b) after pruning a path request is answered at the path's hops with that
 *       announce, and a cache request replays it; while copies remain, a cache
 *       request and seeding pick the path's copy, not the newest copy;
 *   (c) copies younger than the TTL are untouched;
 *   (d) old rows no path points at are deleted by the TTL as before;
 *   (e) the work per run is bounded: 1,200 old copies of one announce, and 700
 *       announces with two old copies each, drain over several runs;
 *   (f) two referenced announces are each kept once.
 *
 * Run: php tests/inbound_one_copy_test.php
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

// ── Signed announces, as RNS Destination.announce() builds them ──────────

function identity(string $appData): array
{
    $keypair = sodium_crypto_sign_keypair();
    $publicKey = random_bytes(32) . sodium_crypto_sign_publickey($keypair);
    $nameHash = substr(hash('sha256', 'lxmf.delivery', true), 0, 10);
    return [
        'secret' => sodium_crypto_sign_secretkey($keypair),
        'public_key' => $publicKey,
        'name_hash' => $nameHash,
        'destination' => substr(hash('sha256', $nameHash . substr(hash('sha256', $publicKey, true), 0, 16), true), 0, 16),
        'app_data' => $appData,
    ];
}

function randomBlob(int $emitted): string
{
    return random_bytes(5) . substr(pack('J', $emitted), 3, 5);
}

/** HEADER_2, in transport from $transportId, SINGLE, ANNOUNCE, context NONE. */
function announceRaw(array $id, string $randomBlob, int $wireHops, string $transportId): string
{
    $signature = sodium_crypto_sign_detached(
        $id['destination'] . $id['public_key'] . $id['name_hash'] . $randomBlob . $id['app_data'],
        $id['secret']
    );
    return chr((1 << 6) | (1 << 4) | 1) . chr($wireHops) . $transportId . $id['destination'] . chr(0x00)
        . $id['public_key'] . $id['name_hash'] . $randomBlob . $signature . $id['app_data'];
}

/** The announce body: everything after a HEADER_2 header (2 + 16 + 16 + 1 bytes). */
function announceBody(string $raw): string
{
    return substr($raw, 35);
}

/** HEADER_1 DATA to the destination, context CACHE_REQUEST, asking for a packet hash. */
function cacheRequestRaw(array $id, string $packetHash): string
{
    return chr(0) . chr(0) . $id['destination'] . chr(0x08) . $packetHash;
}

/** HEADER_1 DATA to rnstransport.path.request (PLAIN): destination + tag. */
function pathRequestRaw(Storage $storage, string $destination): string
{
    $control = hex2bin((new ReflectionMethod($storage, 'pathRequestControlHashHex'))->invoke($storage));
    return chr(2 << 2) . chr(0) . $control . chr(0x00) . $destination . random_bytes(16);
}

// ── A node: two bridges into the mesh and two browsers ───────────────────

const GATEWAY = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';
const GATEWAY2 = 'dddddddddddddddddddddddddddddddd';
const BROWSER1 = 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb';
const BROWSER2 = 'cccccccccccccccccccccccccccccccc';
const BROWSER3 = 'eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee';

function node(): array
{
    $storage = new Storage(['storage' => ['backend' => 'sqlite', 'sqlite_path' => ':memory:']]);
    $storage->migrateIfNeeded();
    $db = (new ReflectionProperty($storage, 'db'))->getValue($storage);
    $bridge = ['client' => 'rns-post-interface', 'mode' => 6];
    foreach ([GATEWAY => $bridge, GATEWAY2 => $bridge, BROWSER1 => ['client' => 'rns-js'], BROWSER2 => ['client' => 'rns-js']] as $iface => $meta) {
        addInterface($db, $iface, $meta);
    }
    return [$storage, $db];
}

function addInterface(PDO $db, string $iface, array $meta): void
{
    $db->prepare("INSERT INTO interfaces (interface_id, name, session_token, bitrate, mtu, status, metadata_json, created_at, last_seen_at)
                  VALUES (:i, 'test', 'tok', 1000000, 500, 'online', :m, 1, :t)")
        ->execute([':i' => $iface, ':m' => json_encode($meta), ':t' => time()]);
}

/**
 * Deliver one packet from $iface as an exchange would, after marking every
 * packet queued so far as fetched and acknowledged, so what this one queues
 * shows as new rows. Returns the processing summary and the stored row.
 */
function deliver(Storage $storage, PDO $db, string $iface, string $raw): array
{
    static $batch = 0;
    $db->exec("UPDATE outbound_packets SET delivered_at = 1, delivered_batch_id = 'fetched', acked_at = 1 WHERE acked_at IS NULL");
    $result = $storage->ingestInboundBatchInline($iface, 'batch-' . (++$batch), [base64_encode($raw)]);
    $row = $db->query('SELECT packet_record_id, packet_hash_hex, hops, announce_status, announce_reason
                         FROM inbound_packets ORDER BY packet_record_id DESC LIMIT 1')->fetch(PDO::FETCH_ASSOC);
    return [
        'summary' => $result['processing'] ?? [],
        'id' => (int) $row['packet_record_id'],
        'hash' => (string) $row['packet_hash_hex'],
        'hops' => (int) $row['hops'],
        'status' => (string) $row['announce_status'],
    ];
}

/** Outbound packets queued since the last deliver(), as [interface, reason, raw]. */
function queued(PDO $db): array
{
    $rows = [];
    foreach ($db->query('SELECT interface_id, queue_reason, packet_base64 FROM outbound_packets WHERE acked_at IS NULL ORDER BY packet_id') as $row) {
        $rows[] = [(string) $row['interface_id'], (string) $row['queue_reason'], (string) base64_decode((string) $row['packet_base64'], true)];
    }
    return $rows;
}

/** Record ids of the stored copies of one announce. */
function copies(PDO $db, string $hashHex): array
{
    $stmt = $db->prepare('SELECT packet_record_id FROM inbound_packets WHERE packet_hash_hex = :h ORDER BY packet_record_id');
    $stmt->execute([':h' => $hashHex]);
    return array_map('intval', $stmt->fetchAll(PDO::FETCH_COLUMN));
}

/** Put rows two hours back, past inbound_packet_ttl_seconds (3600). */
function age(PDO $db, array $ids): void
{
    $stmt = $db->prepare('UPDATE inbound_packets SET created_at = created_at - 7200 WHERE packet_record_id = :id');
    foreach ($ids as $id) {
        $stmt->execute([':id' => $id]);
    }
}

function pathOf(PDO $db, array $id): array
{
    $stmt = $db->prepare('SELECT hops, packet_hash_hex, interface_id FROM path_entries WHERE destination_hash_hex = :d');
    $stmt->execute([':d' => bin2hex($id['destination'])]);
    $row = $stmt->fetch(PDO::FETCH_ASSOC);
    return is_array($row) ? $row : [];
}

function maintain(Storage $storage): array
{
    return $storage->runMaintenance(300, 86400);
}

$now = time();
$gatewayTid = random_bytes(16);
$gateway2Tid = random_bytes(16);
[$storage, $db] = node();

// ── The announces ────────────────────────────────────────────────────────
// Wire hops w are stored, and kept by the path, as w + 1 (this node's hop).

// A: three copies, all to be aged. The path is the first, 4 hops via the
// gateway; a same-hops retry follows, then the newest copy, over a longer
// route. The copy to keep is the retry: the path's hops, the newest of those.
$idA = identity('one copy A');
$blobA = randomBlob($now - 60);
$a1 = deliver($storage, $db, GATEWAY, announceRaw($idA, $blobA, 3, $gatewayTid));
$a2 = deliver($storage, $db, GATEWAY, announceRaw($idA, $blobA, 3, $gatewayTid));
$a3 = deliver($storage, $db, GATEWAY2, announceRaw($idA, $blobA, 5, $gateway2Tid));
$hashA = $a1['hash'];

// F: a second referenced announce, its copies in another shape: the path is
// 2 hops via the gateway, the same hops arrive again over the other bridge,
// then a 3-hop copy. The copy to keep is the second.
$idF = identity('one copy F');
$blobF = randomBlob($now - 50);
$f1 = deliver($storage, $db, GATEWAY, announceRaw($idF, $blobF, 1, $gatewayTid));
$f2 = deliver($storage, $db, GATEWAY2, announceRaw($idF, $blobF, 1, $gateway2Tid));
$f3 = deliver($storage, $db, GATEWAY, announceRaw($idF, $blobF, 2, $gatewayTid));
$hashF = $f1['hash'];

// C: two old copies (the path's, then a longer one) and two young ones (the
// path's hops again, then the newest, longer again).
$idC = identity('one copy C');
$blobC = randomBlob($now - 40);
$c1 = deliver($storage, $db, GATEWAY, announceRaw($idC, $blobC, 3, $gatewayTid));
$c2 = deliver($storage, $db, GATEWAY2, announceRaw($idC, $blobC, 5, $gateway2Tid));
$c3 = deliver($storage, $db, GATEWAY, announceRaw($idC, $blobC, 3, $gatewayTid));
$c4 = deliver($storage, $db, GATEWAY2, announceRaw($idC, $blobC, 5, $gateway2Tid));
$hashC = $c1['hash'];

// D: an older emission with two copies, then a newer one the path moves to.
$idD = identity('one copy D');
$d1 = deliver($storage, $db, GATEWAY, announceRaw($idD, $blobOld = randomBlob($now - 600), 2, $gatewayTid));
$d2 = deliver($storage, $db, GATEWAY2, announceRaw($idD, $blobOld, 2, $gateway2Tid));
$d3 = deliver($storage, $db, GATEWAY, announceRaw($idD, randomBlob($now - 30), 2, $gatewayTid));

echo "(setup) the copies landed as intended\n";
check('A: path is 4 hops via the gateway, on this announce', pathOf($db, $idA) === ['hops' => 4, 'packet_hash_hex' => $hashA, 'interface_id' => GATEWAY], json_encode(pathOf($db, $idA)));
check('A: copies at 4, 4, 6 hops share one hash', [$a1['hops'], $a2['hops'], $a3['hops']] === [4, 4, 6] && $a2['hash'] === $hashA && $a3['hash'] === $hashA);
check('F: path is 2 hops via the gateway; copies at 2, 2, 3 hops', (int) (pathOf($db, $idF)['hops'] ?? -1) === 2 && (pathOf($db, $idF)['packet_hash_hex'] ?? '') === $hashF && [$f1['hops'], $f2['hops'], $f3['hops']] === [2, 2, 3] && $f3['hash'] === $hashF);
check('C: path is 4 hops; copies at 4, 6, 4, 6 hops', (int) (pathOf($db, $idC)['hops'] ?? -1) === 4 && (pathOf($db, $idC)['packet_hash_hex'] ?? '') === $hashC && [$c1['hops'], $c2['hops'], $c3['hops'], $c4['hops']] === [4, 6, 4, 6]);
check('D: the path moved to the newer emission', (pathOf($db, $idD)['packet_hash_hex'] ?? '') === $d3['hash'] && $d1['hash'] === $d2['hash'] && $d1['hash'] !== $d3['hash'], json_encode(pathOf($db, $idD)));

// ── (b, before) the readers pick the path's copy while copies remain ─────
echo "(b) while copies remain, seeding and a cache request use the path's copy, not the newest\n";
addInterface($db, BROWSER3, ['client' => 'rns-js']);
$db->exec("UPDATE outbound_packets SET delivered_at = 1, delivered_batch_id = 'fetched', acked_at = 1 WHERE acked_at IS NULL");
$storage->seedInterfaceIfNew(BROWSER3);
$seeded = [];
foreach (queued($db) as [$iface, $reason, $raw]) {
    if ($iface === BROWSER3 && $reason === 'relay_announce') {
        $seeded[bin2hex(substr($raw, 18, 16))] = ord($raw[1]);
    }
}
check('seeding sends C at the path\'s wire hops (3), not the newest copy (5)', ($seeded[bin2hex($idC['destination'])] ?? -1) === 3, json_encode($seeded));
check('seeding sends A at the path\'s wire hops (3), not the newest copy (5)', ($seeded[bin2hex($idA['destination'])] ?? -1) === 3, json_encode($seeded));

// ── (a, c, d, f) one maintenance run ─────────────────────────────────────
age($db, [$a1['id'], $a2['id'], $a3['id'], $f1['id'], $f2['id'], $f3['id'], $c1['id'], $c2['id'], $d1['id'], $d2['id'], $d3['id']]);
$summary = maintain($storage);

echo "(a) three old copies of one referenced announce leave one: the path's\n";
check('A keeps only the same-hops retry', copies($db, $hashA) === [$a2['id']], json_encode(copies($db, $hashA)));
echo "(f) two referenced announces are each kept once\n";
check('F keeps only the second 2-hop copy', copies($db, $hashF) === [$f2['id']], json_encode(copies($db, $hashF)));
echo "(c) copies younger than the TTL are untouched\n";
check('C keeps its old path copy and both young copies', copies($db, $hashC) === [$c1['id'], $c3['id'], $c4['id']], json_encode(copies($db, $hashC)));
echo "(d) old rows no path points at still expire\n";
check('D: the older emission is gone, the path\'s kept', copies($db, $d1['hash']) === [] && copies($db, $d3['hash']) === [$d3['id']], json_encode([copies($db, $d1['hash']), copies($db, $d3['hash'])]));
check('the TTL counted the two unreferenced rows', ($summary['expired_inbound_packets'] ?? -1) === 2, json_encode($summary['expired_inbound_packets'] ?? null));
echo "(speaks) the deletion is counted\n";
check('expired_inbound_duplicate_copies = 2 (A) + 2 (F) + 1 (C)', ($summary['expired_inbound_duplicate_copies'] ?? -1) === 5, json_encode($summary['expired_inbound_duplicate_copies'] ?? null));
$again = maintain($storage);
check('the next run finds nothing more', ($again['expired_inbound_duplicate_copies'] ?? -1) === 0 && copies($db, $hashA) === [$a2['id']] && copies($db, $hashC) === [$c1['id'], $c3['id'], $c4['id']], json_encode($again['expired_inbound_duplicate_copies'] ?? null));

// ── (b, after) the pruned announce still answers ─────────────────────────
echo "(b) after pruning, a path request is answered at the path's hops, and a cache request replays\n";
$r = deliver($storage, $db, BROWSER1, pathRequestRaw($storage, $idA['destination']));
$responses = array_values(array_filter(queued($db), static fn (array $q): bool => $q[0] === BROWSER1 && $q[1] === 'path_response'));
check('one path response to the asker', ($r['summary']['path_responses_queued'] ?? -1) === 1 && count($responses) === 1, json_encode($r['summary']));
$response = $responses[0][2] ?? '';
check('at the path\'s 4 hops', $response !== '' && ord($response[1]) === 4, $response === '' ? 'none' : (string) ord($response[1]));
check('carrying the announce', $response !== '' && announceBody($response) === announceBody(announceRaw($idA, $blobA, 3, $gatewayTid)) && substr($response, 18, 16) === $idA['destination']);

$r = deliver($storage, $db, BROWSER1, cacheRequestRaw($idA, hex2bin($hashA)));
check('a cache request for A replays the kept copy', ($r['summary']['cache_requests_replayed'] ?? -1) === 1 && queued($db) !== [], json_encode($r['summary']));
$r = deliver($storage, $db, BROWSER1, cacheRequestRaw($idC, hex2bin($hashC)));
$replayHops = array_values(array_unique(array_map(static fn (array $q): int => ord($q[2][1]), array_filter(queued($db), static fn (array $q): bool => $q[1] === 'relay_announce'))));
$replayTargets = array_values(array_unique(array_map(static fn (array $q): string => $q[0], queued($db))));
check('a cache request for C replays the gateway\'s 4-hop copy, not the newest 6-hop one',
    ($r['summary']['cache_requests_replayed'] ?? -1) === 1 && $replayHops === [3] && !in_array(GATEWAY, $replayTargets, true),
    json_encode(['hops' => $replayHops, 'to' => $replayTargets]));

// ── (e) bounded per run ──────────────────────────────────────────────────
echo "(e) the work per run is bounded and drains over several runs\n";
[$storage, $db] = node();
$idE = identity('one copy E');
$e = deliver($storage, $db, GATEWAY, announceRaw($idE, randomBlob($now - 20), 3, $gatewayTid));
// 1,200 newer copies over a longer route, the path's copy the oldest.
$db->exec("WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i + 1 FROM n WHERE i < 1200)
           INSERT INTO inbound_packets (interface_id, batch_id, packet_index, status, packet_hash_hex, raw_base64, packet_type, hops, destination_hash_hex, filter_status, announce_status, created_at)
           SELECT '" . GATEWAY2 . "', 'clone', i, 'parsed', packet_hash_hex, raw_base64, 1, 6, destination_hash_hex, 'accepted', 'validated', created_at
             FROM inbound_packets, n WHERE packet_record_id = " . $e['id']);
$db->exec('UPDATE inbound_packets SET created_at = created_at - 7200');
$runs = [];
for ($i = 0; $i < 6; $i++) {
    $runs[] = (int) (maintain($storage)['expired_inbound_duplicate_copies'] ?? -1);
}
check('1,200 copies of one announce: 500, 500, 200, then nothing', $runs === [500, 500, 200, 0, 0, 0], json_encode($runs));
check('the path\'s copy is the one left', copies($db, $e['hash']) === [$e['id']], json_encode(count(copies($db, $e['hash']))));

[$storage, $db] = node();
// 700 announces a path points at, each with an old copy at the path's hops
// and an older one a hop longer: 1,400 rows, 700 to delete.
$db->exec("WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i + 1 FROM n WHERE i < 700)
           INSERT INTO path_entries (destination_hash_hex, next_hop_hex, hops, expires_at, random_blobs_json, interface_id, packet_hash_hex, announce_emitted, updated_at)
           SELECT printf('%032x', i), 'ab', 2, " . ($now + 86400) . ", '[]', '" . GATEWAY . "', printf('%064x', i), 0, " . $now . " FROM n");
$db->exec("WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i + 1 FROM n WHERE i < 700), c(h) AS (SELECT 3 UNION ALL SELECT 2)
           INSERT INTO inbound_packets (interface_id, batch_id, packet_index, status, packet_hash_hex, raw_base64, packet_type, hops, destination_hash_hex, created_at)
           SELECT '" . GATEWAY . "', 'many', i, 'parsed', printf('%064x', i), 'x', 1, h, printf('%032x', i), " . ($now - 7200) . "
             FROM n, c ORDER BY i, h DESC");
$runs = [];
for ($i = 0; $i < 6; $i++) {
    $runs[] = (int) (maintain($storage)['expired_inbound_duplicate_copies'] ?? -1);
}
// A run reads 500 rows past the TTL (250 announces here) and settles those.
check('700 announces x 2 copies: 250, 250, 200, then nothing', $runs === [250, 250, 200, 0, 0, 0], json_encode($runs));
$left = $db->query('SELECT COUNT(*), MIN(hops), MAX(hops) FROM inbound_packets')->fetch(PDO::FETCH_NUM);
check('each keeps its copy at the path\'s hops', array_map('intval', $left) === [700, 2, 2], json_encode($left));

echo "(e) a cursor past the cutoff (the clock went back) walks again from the start\n";
[$storage, $db] = node();
$idG = identity('one copy G');
$blobG = randomBlob($now - 10);
$g1 = deliver($storage, $db, GATEWAY, announceRaw($idG, $blobG, 3, $gatewayTid));
$g2 = deliver($storage, $db, GATEWAY2, announceRaw($idG, $blobG, 5, $gateway2Tid));
age($db, [$g1['id'], $g2['id']]);
$db->prepare("INSERT INTO transport_state (state_key, state_value, updated_at) VALUES ('inbound_copy_cursor', :v, 0)")
    ->execute([':v' => ($now + 86400) . ':999999']);
$runs = [(int) (maintain($storage)['expired_inbound_duplicate_copies'] ?? -1)];
check('the copy is still found and deleted', $runs === [1] && copies($db, $g1['hash']) === [$g1['id']], json_encode([$runs, copies($db, $g1['hash'])]));

echo "\n$pass passed, $fail failed\n";
exit($fail === 0 ? 0 : 1);
