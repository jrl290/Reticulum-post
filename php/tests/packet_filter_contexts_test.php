<?php
/**
 * The packet filter's always-accepted contexts, on the real trait and schema.
 *
 * RNS 1.5.2 Transport.packet_filter (Transport.py:1624-1640) first drops a
 * packet in transport for another instance (1630-1633), then accepts six
 * contexts outright, before the packet hash list is consulted: KEEPALIVE,
 * RESOURCE_REQ, RESOURCE_PRF, RESOURCE, CACHE_REQUEST and CHANNEL
 * (1635-1640). Everything else addressed to a link is de-duplicated by hash.
 *
 * 2026-09-29, staging, stage_sim section c ("Channel Display Names both
 * ways"): a web client idle past its keepalive lost a live channel post.
 * This node's list had only four of the six. A keepalive is sent unencrypted
 * (Packet.py:209-212) and its hash leaves out the hops byte
 * (Packet.py:361-365), so every 0xFF ping on one link hashes the same, and so
 * does every 0xFE pong. The first ping passed; the second was rejected here
 * as 'duplicate' (inbound_packets 'rejected|duplicate', context 250), the
 * link went STALE and closed, and rfed's push to the web client went
 * unanswered. Both existing relay tests stub applyPacketFilter, so the list
 * itself had never been asserted.
 *
 * This drives the real Storage (every trait, the real schema) on an
 * in-memory SQLite and parses real packet bytes with the real PacketParser:
 *   (a) a byte-identical repeat with each of the six contexts is accepted as
 *       context passthrough;
 *   (b) a byte-identical repeat of a link DATA packet with context 0x00 is
 *       still rejected as a duplicate;
 *   (c) a foreign transport_id is rejected before the context bypass;
 *   (d) over all 256 contexts, exactly the reference's six bypass the hash
 *       list (checked against the installed RNS 1.5.2 source when present);
 *   (e) end to end through the inbound batch path, a second identical ping on
 *       a validated link is relayed to the far side, as the first was.
 *
 * Run: php tests/packet_filter_contexts_test.php
 */
declare(strict_types=1);

$root = dirname(__DIR__);
require_once $root . '/src/lib/database.php';
require_once $root . '/src/index.php';

use ReticulumPhp\PacketParser;
use ReticulumPhp\Storage;

// RNS 1.5.2 Transport.py:1635-1640, in the reference's order.
const REFERENCE_ALWAYS_ACCEPTED = [
    'KEEPALIVE'     => 0xFA,
    'RESOURCE_REQ'  => 0x03,
    'RESOURCE_PRF'  => 0x05,
    'RESOURCE'      => 0x01,
    'CACHE_REQUEST' => 0x08,
    'CHANNEL'       => 0x0E,
];

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

function call(object $obj, string $method, mixed ...$args): mixed
{
    $m = new ReflectionMethod($obj, $method);
    return $m->invoke($obj, ...$args);
}

/**
 * Raw bytes of a packet addressed to a link (destination type LINK).
 * HEADER_1 unless a transport id is given, which makes it HEADER_2 in
 * transport; flags as RNS Packet.get_packed_flags.
 */
function linkPacketRaw(string $linkId, int $context, string $data, int $packetType = 0, ?string $transportId = null, int $hops = 0): string
{
    $headerType = $transportId === null ? 0 : 1;
    $transportType = $transportId === null ? 0 : 1;
    $flags = ($headerType << 6) | ($transportType << 4) | (3 << 2) | $packetType;
    return chr($flags) . chr($hops) . ($transportId ?? '') . $linkId . chr($context) . $data;
}

/** What processInboundBatchRow() hands the filter: parsed, hops +1. */
function inbound(string $raw): array
{
    $packet = PacketParser::parseRaw($raw);
    $packet['hops'] = ($packet['hops'] ?? 0) + 1;
    return $packet;
}

function filter(Storage $s, string $raw): array
{
    return call($s, 'applyPacketFilter', inbound($raw));
}

function freshStorage(): Storage
{
    $storage = new Storage(['storage' => ['backend' => 'sqlite', 'sqlite_path' => ':memory:']]);
    $storage->migrateIfNeeded();
    return $storage;
}

$storage = freshStorage();
$ownTransportId = hex2bin(call($storage, 'transportIdentityHashHex'));

// Data a real sender would put in each context: a keepalive carries one byte
// (0xFF ping, 0xFE pong); a resource proof is a PROOF packet (Packet.py:214).
$sample = [
    0xFA => [0, "\xFF"],
    0x03 => [0, random_bytes(48)],
    0x05 => [3, random_bytes(48)],
    0x01 => [0, random_bytes(64)],
    0x08 => [0, random_bytes(16)],
    0x0E => [0, random_bytes(40)],
];

// ── (a) a byte-identical repeat of each always-accepted context passes ────
echo "(a) byte-identical repeats of the six always-accepted contexts\n";
foreach (REFERENCE_ALWAYS_ACCEPTED as $name => $context) {
    [$packetType, $data] = $sample[$context];
    $raw = linkPacketRaw(random_bytes(16), $context, $data, $packetType);
    $first = filter($storage, $raw);
    $second = filter($storage, $raw);
    check(sprintf('%s 0x%02X first copy accepted', $name, $context),
        $first === ['accepted', 'context_passthrough'], json_encode($first));
    check(sprintf('%s 0x%02X identical second copy accepted', $name, $context),
        $second === ['accepted', 'context_passthrough'], json_encode($second));
}

// A keepalive in transport through this node (HEADER_2, our transport id),
// and one that arrives with a different hop count: same hash, still passes.
$linkId = random_bytes(16);
$ping = linkPacketRaw($linkId, 0xFA, "\xFF", 0, $ownTransportId);
filter($storage, $ping);
check('KEEPALIVE in transport for this node: identical second copy accepted',
    filter($storage, $ping) === ['accepted', 'context_passthrough']);
$pong = linkPacketRaw($linkId, 0xFA, "\xFE");
$pongLater = linkPacketRaw($linkId, 0xFA, "\xFE", 0, null, 3);
check('a pong seen again with other hops has the same packet hash',
    inbound($pong)['packet_hash_hex'] === inbound($pongLater)['packet_hash_hex']);
filter($storage, $pong);
check('KEEPALIVE pong seen again with other hops: accepted',
    filter($storage, $pongLater) === ['accepted', 'context_passthrough']);

// ── (b) ordinary link data is still de-duplicated ─────────────────────────
echo "(b) link DATA with context 0x00 is still de-duplicated\n";
$data = linkPacketRaw(random_bytes(16), 0x00, random_bytes(80));
$first = filter($storage, $data);
$second = filter($storage, $data);
check('first copy accepted as a new hash', $first === ['accepted', 'new_hash'], json_encode($first));
check('identical second copy rejected as a duplicate', $second === ['rejected', 'duplicate'], json_encode($second));

// ── (c) the transport_id check comes before the context bypass ───────────
echo "(c) a foreign transport_id is rejected before the bypass\n";
do {
    $foreign = random_bytes(16);
} while ($foreign === $ownTransportId);
foreach (REFERENCE_ALWAYS_ACCEPTED as $name => $context) {
    [$packetType, $bytes] = $sample[$context];
    $raw = linkPacketRaw(random_bytes(16), $context, $bytes, $packetType, $foreign);
    $result = filter($storage, $raw);
    check(sprintf('%s 0x%02X for another transport instance rejected', $name, $context),
        $result === ['rejected', 'transport_id_mismatch'], json_encode($result));
}

// ── (d) exactly the reference's six bypass the hash list ─────────────────
echo "(d) the always-accepted set equals RNS 1.5.2's six\n";
$bypassing = [];
for ($context = 0; $context <= 0xFF; $context++) {
    $raw = linkPacketRaw(random_bytes(16), $context, random_bytes(24));
    filter($storage, $raw);
    if (filter($storage, $raw) === ['accepted', 'context_passthrough']) {
        $bypassing[] = $context;
    }
}
$expected = array_values(REFERENCE_ALWAYS_ACCEPTED);
sort($expected);
check('contexts whose identical repeat passes = {' . implode(', ', array_map(static fn (int $c): string => sprintf('0x%02X', $c), $expected)) . '}',
    $bypassing === $expected,
    'got {' . implode(', ', array_map(static fn (int $c): string => sprintf('0x%02X', $c), $bypassing)) . '}');

// Cross-check the list above against the reference source itself when the
// workspace venv has RNS 1.5.2 installed (it does on the deploy machine).
$referenceDir = null;
foreach (glob(dirname($root, 2) . '/.venv/lib/python3*/site-packages/RNS') ?: [] as $dir) {
    $version = @file_get_contents($dir . '/_version.py');
    if (is_string($version) && preg_match('/__version__\s*=\s*"1\.5\.2"/', $version) === 1) {
        $referenceDir = $dir;
        break;
    }
}
if ($referenceDir === null) {
    echo "  skip RNS 1.5.2 source not found under the workspace .venv; the list above is the check\n";
} else {
    $transport = (string) file_get_contents($referenceDir . '/Transport.py');
    $packetPy = (string) file_get_contents($referenceDir . '/Packet.py');
    $filterBody = preg_match('/def packet_filter\(packet\):(.*?)\n    @staticmethod/s', $transport, $m) === 1 ? $m[1] : '';
    preg_match_all('/if packet\.context == RNS\.Packet\.([A-Z_]+):\s*return True/', $filterBody, $names);
    $fromSource = [];
    foreach ($names[1] as $constName) {
        if (preg_match('/^\s*' . $constName . '\s*=\s*0x([0-9A-Fa-f]{2})/m', $packetPy, $c) === 1) {
            $fromSource[$constName] = hexdec($c[1]);
        }
    }
    check('the test\'s list matches Transport.packet_filter in ' . $referenceDir,
        $fromSource === REFERENCE_ALWAYS_ACCEPTED, json_encode($fromSource));
}

// ── (e) end to end: the second ping on a link is relayed, not dropped ────
echo "(e) through the inbound batch path, repeat pings on a link are relayed\n";
$e2e = freshStorage();
$db = (new ReflectionProperty($e2e, 'db'))->getValue($e2e);
$browser = str_repeat('b', 32);
$gateway = str_repeat('c', 32);
foreach ([$browser, $gateway] as $iface) {
    $db->prepare("INSERT INTO interfaces (interface_id, name, session_token, bitrate, mtu, status, metadata_json, created_at, last_seen_at)
                  VALUES (:i, 'test', 'tok', 1000000, 500, 'online', '{}', 1, :t)")
        ->execute([':i' => $iface, ':t' => time()]);
}
// A validated link whose LINKREQUEST came in from the browser (one hop) and
// went out to the gateway, as the relay records it once the LRPROOF passes.
$linkId = random_bytes(16);
$db->prepare('INSERT INTO link_transport_entries (link_id_hex, received_interface_id, outbound_interface_id, next_hop_hex,
              remaining_hops, taken_hops, destination_hash_hex, validated, proof_expires_at, updated_at)
              VALUES (:l, :r, :o, :n, 2, 1, :d, 1, NULL, :t)')
    ->execute([':l' => bin2hex($linkId), ':r' => $browser, ':o' => $gateway, ':n' => bin2hex(random_bytes(16)),
               ':d' => bin2hex(random_bytes(16)), ':t' => time()]);
$pingRaw = linkPacketRaw($linkId, 0xFA, "\xFF");
$summary = ['batches_processed' => 0, 'packets_parsed' => 0, 'packet_errors' => 0, 'packets_rejected' => 0,
            'announces_validated' => 0, 'announce_paths_updated' => 0, 'announce_validation_failures' => 0,
            'path_requests_seen' => 0, 'path_responses_queued' => 0, 'path_requests_forwarded' => 0,
            'path_requests_ignored' => 0, 'relay_packets_queued' => 0, 'cache_requests_seen' => 0,
            'cache_requests_replayed' => 0, 'cache_requests_ignored' => 0, 'outbound_proofs_marked' => 0,
            'local_deliveries' => 0];
foreach (['batch-1', 'batch-2'] as $batchId) {
    $row = ['interface_id' => $browser, 'batch_id' => $batchId, 'payload_json' => json_encode([base64_encode($pingRaw)])];
    $args = [$row, &$summary];
    (new ReflectionMethod($e2e, 'processInboundBatchRow'))->invokeArgs($e2e, $args);
}
$relayed = (int) $db->query("SELECT COUNT(*) FROM outbound_packets WHERE interface_id = '$gateway' AND queue_reason = 'link_relay'")->fetchColumn();
$rejected = (int) $db->query("SELECT COUNT(*) FROM inbound_packets WHERE context = 250 AND filter_status = 'rejected'")->fetchColumn();
check('both pings relayed to the gateway side of the link', $relayed === 2, "relayed $relayed");
check('no keepalive recorded as rejected', $rejected === 0, "rejected $rejected");
check('the summary counts no rejection', $summary['packets_rejected'] === 0, (string) $summary['packets_rejected']);

echo "\n$pass passed, $fail failed\n";
exit($fail === 0 ? 0 : 1);
