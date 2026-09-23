<?php
/**
 * A link initiated from OUTSIDE to a browser on this node, on the real SQL.
 *
 * The LINKREQUEST is delivered locally and its link entry carries
 * remaining_hops = 1: the browser is a directly attached client, so its
 * LRPROOF arrives observed 1 and must match exactly, the same gate a transit
 * entry gets (the reference link_table has no "don't check" mode).
 *
 * 2026-09-22, retichat.com: an Android app opened a link to a browser here.
 * The entry was then recorded with a -1 "no expectation" sentinel (88ec642),
 * which the exact `remaining_hops = 1` lookup could never match, so the
 * browser's LRPROOF fell to the reverse-path fallback: the proof went out, but
 * a SECOND row (taken_hops = 1) was written and the original never validated.
 * The phone's LRRTT and LXMF data (observed 7) then failed the taken-hops check
 * on the fallback row and were dropped without a trace. hops_test.php's mock
 * had hidden the filter; this test uses the trait's own queries on an
 * in-memory SQLite so the SQL itself is what is asserted.
 *
 * 2026-09-23: the relay now follows RNS 1.5.2 Transport.py:2608-2672 exactly:
 * no reverse-path fallback, the proof signature is checked against the real
 * known_destinations lookup (a real Ed25519 key below), a signed hop mismatch
 * on a pending entry rebalances remaining_hops and the path hops, and the
 * exact hop + next-hop-interface gate follows.
 *
 * Also 2026-09-23: link packets reach a local browser only through the
 * validated link table entry, as in Transport.py:2121-2166. No
 * local_destinations row is written for a link (it used to be, under the
 * LINKREQUEST's truncated hash, and relayTargetsForAcceptedPacket() fell back
 * to it with no hop check); a link packet with no validated entry is dropped
 * without a path request; a LINKCLOSE no longer deletes the entry, which ages
 * out instead. Sections 13-16 run the real dispatch
 * (relayAcceptedInboundPacket) and the real path-request code.
 *
 * Run: php tests/local_link_relay_sql_test.php
 */
declare(strict_types=1);

require_once __DIR__ . '/../src/lib/database.php';
require_once __DIR__ . '/../src/lib/request_relay_routing_trait.php';
require_once __DIR__ . '/../src/lib/request_inbound_batch_trait.php';
require_once __DIR__ . '/../src/lib/request_control_plane_trait.php';
require_once __DIR__ . '/../src/lib/request_path_state_trait.php';
require_once __DIR__ . '/../src/lib/request_json_codec_trait.php';

if (!class_exists('ReticulumPhp\\TransportConstants')) {
    final class TransportConstantsStubForLinkTest
    {
        public const APP_NAME = 'rnstransport';
        public const PATH_REQUEST_ASPECT_1 = 'path';
        public const PATH_REQUEST_ASPECT_2 = 'request';
        public const DEFAULT_PER_HOP_TIMEOUT_SECONDS = 6;
        public const PATH_REQUEST_MI = 20;
        public const PATH_REQUEST_TIMEOUT = 15;
    }
    class_alias('TransportConstantsStubForLinkTest', 'ReticulumPhp\\TransportConstants');
}

final class SqlLinkRouter
{
    use \ReticulumPhp\RequestControlPlaneTrait;
    use \ReticulumPhp\RequestPathStateTrait;
    use \ReticulumPhp\RequestJsonCodecTrait;
    use \ReticulumPhp\RequestRelayRoutingTrait;
    use \ReticulumPhp\RequestInboundBatchTrait;

    public \PDO $db;
    public string $backend = 'sqlite';
    public array $config = ['transport' => ['rns_mtu' => 500, 'pathfinder_max_hops' => 128, 'path_expiry_default_seconds' => 604800, 'max_random_blobs' => 64]];
    /** @var array<int, array{interface_id: string, reason: string, raw: string}> */
    public array $queued = [];

    public function __construct()
    {
        $this->db = new \PDO('sqlite::memory:', options: [\PDO::ATTR_ERRMODE => \PDO::ERRMODE_EXCEPTION]);
        $this->db->exec('CREATE TABLE interfaces (interface_id TEXT PRIMARY KEY, status TEXT NOT NULL, peer_url TEXT, peer_interface_id TEXT, bitrate INTEGER)');
        $this->db->exec('CREATE TABLE local_destinations (destination_hash_hex TEXT PRIMARY KEY, interface_id TEXT NOT NULL, registered_at INTEGER NOT NULL)');
        $this->db->exec('CREATE TABLE known_destinations (destination_hash_hex TEXT PRIMARY KEY, identity_hash_hex TEXT, public_key_hex TEXT)');
        $this->db->exec('CREATE TABLE path_entries (destination_hash_hex TEXT PRIMARY KEY, next_hop_hex TEXT NOT NULL, hops INTEGER NOT NULL, expires_at INTEGER NOT NULL, random_blobs_json TEXT NOT NULL DEFAULT \'[]\', interface_id TEXT NOT NULL, packet_hash_hex TEXT NOT NULL, announce_emitted INTEGER NOT NULL, updated_at INTEGER NOT NULL)');
        // Same shape and PRIMARY KEY as request_schema_trait.php.
        $this->db->exec('CREATE TABLE link_transport_entries (
            link_id_hex TEXT NOT NULL, received_interface_id TEXT NOT NULL, outbound_interface_id TEXT NOT NULL,
            next_hop_hex TEXT NOT NULL, remaining_hops INTEGER NOT NULL DEFAULT 0, taken_hops INTEGER NOT NULL DEFAULT 0,
            destination_hash_hex TEXT NOT NULL, validated INTEGER NOT NULL DEFAULT 0, proof_expires_at INTEGER DEFAULT NULL,
            updated_at INTEGER NOT NULL DEFAULT 0, PRIMARY KEY (link_id_hex, outbound_interface_id, remaining_hops))');
        $this->db->exec('CREATE TABLE path_request_throttle (throttle_key TEXT PRIMARY KEY, last_requested_at INTEGER NOT NULL DEFAULT 0)');
        $this->db->exec('CREATE TABLE reverse_path_entries (truncated_hash_hex TEXT NOT NULL, received_interface_id TEXT NOT NULL, outbound_interface_id TEXT NOT NULL, created_at INTEGER NOT NULL DEFAULT 0, PRIMARY KEY (truncated_hash_hex, outbound_interface_id))');
    }

    public function addInterface(string $id): void
    {
        $this->db->prepare('INSERT INTO interfaces (interface_id, status) VALUES (:i, \'online\')')->execute([':i' => $id]);
    }

    public function addLocalDestination(string $dest, string $iface): void
    {
        $this->db->prepare('INSERT INTO local_destinations VALUES (:d, :i, :t)')->execute([':d' => $dest, ':i' => $iface, ':t' => time()]);
    }

    /** The destination's 64-byte public key: X25519 (32) . Ed25519 (32). */
    public function addKnownDestination(string $dest, string $ed25519Public): void
    {
        $this->db->prepare('INSERT INTO known_destinations (destination_hash_hex, identity_hash_hex, public_key_hex) VALUES (:d, :i, :p)')
            ->execute([':d' => $dest, ':i' => bin2hex(random_bytes(16)), ':p' => bin2hex(random_bytes(32) . $ed25519Public)]);
    }

    public function addPath(string $dest, string $iface, int $hops): void
    {
        $this->db->prepare('INSERT INTO path_entries (destination_hash_hex, next_hop_hex, hops, expires_at, interface_id, packet_hash_hex, announce_emitted, updated_at)
            VALUES (:d, :n, :h, :e, :i, :p, 0, :u)')
            ->execute([':d' => $dest, ':n' => $dest, ':h' => $hops, ':e' => time() + 3600, ':i' => $iface, ':p' => bin2hex(random_bytes(16)), ':u' => time()]);
    }

    public function pathHops(string $dest): ?int
    {
        $st = $this->db->prepare('SELECT hops FROM path_entries WHERE destination_hash_hex = :d');
        $st->execute([':d' => $dest]);
        $v = $st->fetchColumn();
        return $v === false ? null : (int) $v;
    }

    public function countWhere(string $table, string $column, string $value): int
    {
        $st = $this->db->prepare("SELECT COUNT(*) FROM $table WHERE $column = :v");
        $st->execute([':v' => $value]);
        return (int) $st->fetchColumn();
    }

    public function linkRows(string $linkIdHex): array
    {
        $st = $this->db->prepare('SELECT * FROM link_transport_entries WHERE link_id_hex = :l ORDER BY remaining_hops');
        $st->execute([':l' => $linkIdHex]);
        return $st->fetchAll(\PDO::FETCH_ASSOC);
    }

    // ── Overrides: everything outside the link relay itself ───────────
    private function queueOutboundPacket(string $interfaceId, string $packetBase64, string $reason, ?string $currentExchangeInterfaceId = null): void
    {
        $this->queued[] = ['interface_id' => $interfaceId, 'reason' => $reason, 'raw' => $packetBase64];
    }
    private function interfaceMetadata(string $interfaceId): array { return []; }
    private function isInterfaceActive(string $interfaceId): bool { return true; }
    private function interfaceBitrate(string $interfaceId): ?int { return null; }
    private function ifacConfig(string $interfaceId): array { return []; }
    private function maintenanceInt(string $field, int $default): int { return $default; }
    public function rememberKnownDestination(string $destHashHex, string $packetHashHex, array $announce): void {}
    public function registerLocalDestinationIfOwnInterface(string $destHashHex, string $interfaceId): void {}
    private function rememberPacketHash(string $hex): void {}
    private function packetHashExists(string $hex): bool { return false; }
    private function transportIdentityHashHex(): string { return str_repeat('ab', 16); }

    // ── Entry points ──────────────────────────────────────────────────
    public function t_deliverLocally(string $src, string $raw, array $pkt): bool { return $this->deliverLocallyIfKnown($src, $raw, $pkt); }
    public function t_lrproof(string $src, string $raw, array $pkt): int { return $this->relayLinkRequestProofPacket($src, $raw, $pkt); }
    public function t_shouldRelayLink(array $pkt): bool { return $this->shouldRelayLinkTransportPacket($pkt); }
    public function t_relayLink(string $src, string $raw, array $pkt): int { return $this->relayLinkTransportPacket($src, $raw, $pkt); }
    public function t_linkIdHex(string $raw, array $pkt): ?string { return $this->linkIdHex($raw, $pkt); }
    /** The inbound dispatch for an accepted packet that was not delivered locally. */
    public function t_relayAccepted(string $src, string $raw, array $pkt): int { return $this->relayAcceptedInboundPacket($src, $raw, $pkt, false); }
    public function t_relayTargets(string $src, array $pkt): array { return $this->relayTargetsForAcceptedPacket($src, $pkt); }
    /** What relayAcceptedPacket() records for a LINKREQUEST it forwards: a link entry, no reverse path. */
    public function t_forwardLinkRequest(string $src, string $target, string $raw, array $pkt): void
    {
        $this->rememberLinkTransportRelay($src, $target, $raw, $pkt);
    }
    /** A reverse path under the LINKREQUEST's hash, as the code before 2026-09-23 wrote one. */
    public function t_legacyReversePath(string $src, string $target, array $pkt): void
    {
        $this->rememberReversePath((string) $pkt['truncated_hash_hex'], $src, $target);
    }
}

$pass = 0; $fail = 0;
function check(string $label, bool $ok, string $detail = ''): void
{
    global $pass, $fail;
    if ($ok) { $pass++; echo "  ok   $label\n"; }
    else { $fail++; echo "  FAIL $label" . ($detail !== '' ? " — $detail" : '') . "\n"; }
}

/** A packet array plus matching raw bytes (HEADER_1); payload is random bytes of that length, or the given bytes. */
function pkt(array $o, int|string $payload): array
{
    $p = array_merge([
        'packet_type' => 0, 'context' => 0x00, 'context_flag' => 0, 'header_type' => 0,
        'destination_type' => 0, 'transport_type' => 0, 'hops' => 0,
        'destination_hash_hex' => str_repeat('0', 32), 'transport_id_hex' => null,
        'truncated_hash_hex' => null, 'packet_hash_hex' => bin2hex(random_bytes(16)),
    ], $o);
    if (is_int($payload)) {
        $payload = random_bytes($payload);
    }
    $p['payload_base64'] = base64_encode($payload);
    $flags = ($p['context_flag'] << 5) | ($p['header_type'] << 6) | ($p['transport_type'] << 4) | ($p['destination_type'] << 2) | $p['packet_type'];
    $raw = chr($flags) . chr($p['hops']) . hex2bin($p['destination_hash_hex']) . chr($p['context']) . $payload;
    // RNS packet hash: SHA-256 of the hashable part (low flag nibble . raw[2:]), truncated.
    $p['truncated_hash_hex'] ??= bin2hex(substr(hash('sha256', chr($flags & 0x0F) . substr($raw, 2), true), 0, 16));
    return [$p, base64_encode($raw)];
}

/**
 * An LRPROOF payload as RNS.Link.prove() builds it:
 * signature(64) . peer X25519 pub(32) . signalling(0 or 3), where the
 * signature covers link_id . peer_pub . destination Ed25519 pub . signalling.
 */
function proofPayload(string $linkIdHex, string $signalling, string $secretKey, string $ed25519Public, bool $corrupt = false): string
{
    $peerPub = random_bytes(32);
    $sig = sodium_crypto_sign_detached(hex2bin($linkIdHex) . $peerPub . $ed25519Public . $signalling, $secretKey);
    if ($corrupt) {
        $sig[10] = chr(ord($sig[10]) ^ 0x01);
    }
    return $sig . $peerPub . $signalling;
}

function lrproof(string $linkIdHex, int $hops, string $payload): array
{
    return pkt(['packet_type' => 3, 'context' => 0xFF, 'destination_type' => 3, 'hops' => $hops, 'destination_hash_hex' => $linkIdHex], $payload);
}

$keys = sodium_crypto_sign_keypair();
$edPub = sodium_crypto_sign_publickey($keys);
$edSec = sodium_crypto_sign_secretkey($keys);
$SIG3 = "\x21\xf4\x00";   // 3 signalling bytes (MTU/mode), as in a 67-byte LINKREQUEST

$GATEWAY = 'iface_gateway';
$BROWSER = 'iface_browser';
$dest = 'b42714bda794d70a05dd70ce6140f59a';

/** A router with the local browser destination, optionally with its identity known. */
function localRouter(string $dest, string $edPub, bool $knownIdentity = true): SqlLinkRouter
{
    $r = new SqlLinkRouter();
    $r->addInterface('iface_gateway');
    $r->addInterface('iface_browser');
    $r->addLocalDestination($dest, 'iface_browser');
    if ($knownIdentity) {
        $r->addKnownDestination($dest, $edPub);
    }
    return $r;
}

$r = localRouter($dest, $edPub);

echo "── 1. LINKREQUEST from the gateway (7 hops) to a local browser ──\n";
// 64 bytes of keys + 3 signalling bytes (RNS ≥ 0.9): the link id is NOT the
// packet's truncated hash.
[$lr, $lrRaw] = pkt(['packet_type' => 2, 'hops' => 7, 'destination_hash_hex' => $dest], 67);
$linkId = $r->t_linkIdHex($lrRaw, $lr);
check('link id derived', is_string($linkId) && strlen($linkId) === 32);
check('link id differs from the packet truncated hash (signalling bytes)', $linkId !== $lr['truncated_hash_hex']);
check('delivered locally', $r->t_deliverLocally($GATEWAY, $lrRaw, $lr) === true);
check('LINKREQUEST queued to the browser as local_delivery', ($r->queued[0]['interface_id'] ?? '') === $BROWSER && ($r->queued[0]['reason'] ?? '') === 'local_delivery');
$rows = $r->linkRows($linkId);
check('one link entry', count($rows) === 1, json_encode($rows));
check('entry: remaining_hops = 1, taken_hops = 7, gateway -> browser',
    (int) $rows[0]['remaining_hops'] === 1 && (int) $rows[0]['taken_hops'] === 7
    && $rows[0]['received_interface_id'] === $GATEWAY && $rows[0]['outbound_interface_id'] === $BROWSER, json_encode($rows));

echo "── 2. (case 1) valid signed LRPROOF from the browser (1 hop, signalling bytes) ──\n";
$r->queued = [];
[$pf, $pfRaw] = lrproof($linkId, 1, proofPayload($linkId, $SIG3, $edSec, $edPub));
check('LRPROOF relayed', $r->t_lrproof($BROWSER, $pfRaw, $pf) === 1);
check('LRPROOF went to the gateway via the link entry (lrproof_relay)',
    count($r->queued) === 1 && ($r->queued[0]['interface_id'] ?? '') === $GATEWAY && ($r->queued[0]['reason'] ?? '') === 'lrproof_relay', json_encode($r->queued));
check('relayed proof carries the observed hop count (1)', ord(base64_decode($r->queued[0]['raw'] ?? '')[1] ?? "\xff") === 1);
$rows = $r->linkRows($linkId);
check('exactly one link entry', count($rows) === 1, json_encode($rows));
check('the entry is validated', (int) ($rows[0]['validated'] ?? 0) === 1, json_encode($rows));

echo "── 3. LRRTT and LXMF data from the gateway (7 hops) reach the browser ──\n";
foreach ([0xFE => 'LRRTT', 0x00 => 'data'] as $ctx => $what) {
    $r->queued = [];
    [$d, $dRaw] = pkt(['packet_type' => 0, 'destination_type' => 3, 'context' => $ctx, 'hops' => 7, 'destination_hash_hex' => $linkId], 200);
    check("$what is routed as a link transport packet", $r->t_shouldRelayLink($d));
    check("$what relayed", $r->t_relayLink($GATEWAY, $dRaw, $d) === 1);
    check("$what reached the browser as link_relay", ($r->queued[0]['interface_id'] ?? '') === $BROWSER && ($r->queued[0]['reason'] ?? '') === 'link_relay', json_encode($r->queued));
}

echo "── 4. the browser's reply (1 hop) reaches the gateway ──\n";
$r->queued = [];
[$d, $dRaw] = pkt(['packet_type' => 0, 'destination_type' => 3, 'context' => 0x00, 'hops' => 1, 'destination_hash_hex' => $linkId], 200);
check('reply relayed', $r->t_relayLink($BROWSER, $dRaw, $d) === 1);
check('reply reached the gateway', ($r->queued[0]['interface_id'] ?? '') === $GATEWAY, json_encode($r->queued));

echo "── 5. a wrong-hop LRRTT from the gateway side is still dropped ──\n";
$r->queued = [];
[$d, $dRaw] = pkt(['packet_type' => 0, 'destination_type' => 3, 'context' => 0xFE, 'hops' => 3, 'destination_hash_hex' => $linkId], 200);
check('3-hop packet on a 7-hop link is not relayed', $r->t_relayLink($GATEWAY, $dRaw, $d) === 0 && $r->queued === []);

echo "── 6. (case 2) browser-initiated 64-byte LINKREQUEST (Retichat-js), valid proof ──\n";
// Link id == the packet's truncated hash: relayAcceptedPacket used to record a
// reverse path under that same hash, exactly the case the removed fallback
// used to catch and duplicate. (It records none now: section 13.)
$remote = 'c0ffee00c0ffee00c0ffee00c0ffee00';
$rj = localRouter($dest, $edPub);
$rj->addKnownDestination($remote, $edPub);
$rj->addPath($remote, $GATEWAY, 2);
[$jlr, $jlrRaw] = pkt(['packet_type' => 2, 'hops' => 1, 'destination_hash_hex' => $remote], 64);
$jLinkId = $rj->t_linkIdHex($jlrRaw, $jlr);
check('64-byte LINKREQUEST: link id == truncated hash', $jLinkId === $jlr['truncated_hash_hex']);
$rj->t_forwardLinkRequest($BROWSER, $GATEWAY, $jlrRaw, $jlr);
$rows = $rj->linkRows($jLinkId);
check('entry: remaining_hops = 2 (path), taken_hops = 1, browser -> gateway',
    count($rows) === 1 && (int) $rows[0]['remaining_hops'] === 2 && (int) $rows[0]['taken_hops'] === 1
    && $rows[0]['received_interface_id'] === $BROWSER && $rows[0]['outbound_interface_id'] === $GATEWAY, json_encode($rows));
[$pf, $pfRaw] = lrproof($jLinkId, 2, proofPayload($jLinkId, '', $edSec, $edPub));
check('LRPROOF relayed', $rj->t_lrproof($GATEWAY, $pfRaw, $pf) === 1);
check('to the browser as lrproof_relay', count($rj->queued) === 1 && $rj->queued[0]['interface_id'] === $BROWSER && $rj->queued[0]['reason'] === 'lrproof_relay', json_encode($rj->queued));
$rows = $rj->linkRows($jLinkId);
check('exactly one row, validated (no fallback duplicate)', count($rows) === 1 && (int) $rows[0]['validated'] === 1, json_encode($rows));

echo "── 7. (case 3) bad signature on a local entry → dropped ──\n";
$rb = localRouter($dest, $edPub);
check('delivered locally', $rb->t_deliverLocally($GATEWAY, $lrRaw, $lr) === true);
$rb->queued = [];
[$pf, $pfRaw] = lrproof($linkId, 1, proofPayload($linkId, $SIG3, $edSec, $edPub, true));
check('bad-signature LRPROOF is dropped, nothing queued', $rb->t_lrproof($BROWSER, $pfRaw, $pf) === 0 && $rb->queued === [], json_encode($rb->queued));
$rows = $rb->linkRows($linkId);
check('the entry stays unvalidated and alone', count($rows) === 1 && (int) $rows[0]['validated'] === 0, json_encode($rows));
// A 2-hop proof with a bad signature: no rebalance, and the exact gate drops it.
[$pf, $pfRaw] = lrproof($linkId, 2, proofPayload($linkId, $SIG3, $edSec, $edPub, true));
check('2-hop bad-signature LRPROOF on a remaining=1 local entry is dropped', $rb->t_lrproof($BROWSER, $pfRaw, $pf) === 0 && $rb->queued === []);
$rows = $rb->linkRows($linkId);
check('local entry unchanged (remaining 1, unvalidated)', count($rows) === 1 && (int) $rows[0]['remaining_hops'] === 1 && (int) $rows[0]['validated'] === 0, json_encode($rows));

echo "── 8. (case 4) unknown identity → dropped ──\n";
$ru = localRouter($dest, $edPub, false);
check('delivered locally', $ru->t_deliverLocally($GATEWAY, $lrRaw, $lr) === true);
$ru->queued = [];
[$pf, $pfRaw] = lrproof($linkId, 1, proofPayload($linkId, $SIG3, $edSec, $edPub));
check('validly signed LRPROOF for an unknown identity is dropped', $ru->t_lrproof($BROWSER, $pfRaw, $pf) === 0 && $ru->queued === []);
$rows = $ru->linkRows($linkId);
check('the entry stays unvalidated', count($rows) === 1 && (int) $rows[0]['validated'] === 0, json_encode($rows));

echo "── 9. (case 5) signed hop mismatch on a pending TRANSIT entry → rebalanced ──\n";
function transitRouter(string $dest, string $edPub, string $linkId): SqlLinkRouter
{
    $r2 = new SqlLinkRouter();
    $r2->addInterface('iface_a'); $r2->addInterface('iface_b');
    $r2->addKnownDestination($dest, $edPub);
    $r2->addPath($dest, 'iface_b', 2);
    $r2->db->prepare('INSERT INTO link_transport_entries VALUES (:l, :ri, :oi, :nh, 2, 1, :d, 0, :pe, :u)')
        ->execute([':l' => $linkId, ':ri' => 'iface_a', ':oi' => 'iface_b', ':nh' => $dest, ':d' => $dest, ':pe' => time() + 60, ':u' => time()]);
    return $r2;
}
$transitId = bin2hex(random_bytes(16));
$r2 = transitRouter($dest, $edPub, $transitId);
[$pf, $pfRaw] = lrproof($transitId, 3, proofPayload($transitId, '', $edSec, $edPub));
check('LRPROOF with 3 hops on a remaining=2 entry is relayed', $r2->t_lrproof('iface_b', $pfRaw, $pf) === 1);
check('relayed to iface_a as lrproof_relay', count($r2->queued) === 1 && $r2->queued[0]['interface_id'] === 'iface_a' && $r2->queued[0]['reason'] === 'lrproof_relay', json_encode($r2->queued));
$rows = $r2->linkRows($transitId);
check('one row, remaining_hops = 3, validated', count($rows) === 1 && (int) $rows[0]['remaining_hops'] === 3 && (int) $rows[0]['validated'] === 1, json_encode($rows));
check('path hops rebalanced to 3', $r2->pathHops($dest) === 3);

echo "── 10. (case 6) unsigned hop mismatch on a pending TRANSIT entry → dropped ──\n";
$r3 = transitRouter($dest, $edPub, $transitId);
[$pf, $pfRaw] = lrproof($transitId, 3, proofPayload($transitId, '', $edSec, $edPub, true));
check('bad-signature 3-hop LRPROOF is dropped', $r3->t_lrproof('iface_b', $pfRaw, $pf) === 0 && $r3->queued === []);
$rows = $r3->linkRows($transitId);
check('row unchanged (remaining 2, unvalidated)', count($rows) === 1 && (int) $rows[0]['remaining_hops'] === 2 && (int) $rows[0]['validated'] === 0, json_encode($rows));
check('path hops unchanged (2)', $r3->pathHops($dest) === 2);
[$pf, $pfRaw] = lrproof($transitId, 2, proofPayload($transitId, '', $edSec, $edPub));
check('then the exact 2-hop signed proof is relayed and validates', $r3->t_lrproof('iface_b', $pfRaw, $pf) === 1 && (int) $r3->linkRows($transitId)[0]['validated'] === 1);

echo "── 11. (case 7) proof after proof_expires_at → dropped, no second row ──\n";
$re = localRouter($dest, $edPub);
$re->addKnownDestination($remote, $edPub);
$re->addPath($remote, $GATEWAY, 2);
$re->t_forwardLinkRequest($BROWSER, $GATEWAY, $jlrRaw, $jlr);
$re->t_legacyReversePath($BROWSER, $GATEWAY, $jlr);
$re->db->prepare('UPDATE link_transport_entries SET proof_expires_at = :t WHERE link_id_hex = :l')->execute([':t' => time() - 1, ':l' => $jLinkId]);
[$pf, $pfRaw] = lrproof($jLinkId, 2, proofPayload($jLinkId, '', $edSec, $edPub));
check('expired-entry LRPROOF is dropped even though a reverse path exists', $re->t_lrproof($GATEWAY, $pfRaw, $pf) === 0 && $re->queued === [], json_encode($re->queued));
$rows = $re->linkRows($jLinkId);
check('still one row, unvalidated', count($rows) === 1 && (int) $rows[0]['validated'] === 0, json_encode($rows));

echo "── 12. (case 8) proof on the wrong (received) interface → dropped ──\n";
$rw = localRouter($dest, $edPub);
check('delivered locally', $rw->t_deliverLocally($GATEWAY, $lrRaw, $lr) === true);
$rw->queued = [];
[$pf, $pfRaw] = lrproof($linkId, 1, proofPayload($linkId, $SIG3, $edSec, $edPub));
check('valid LRPROOF arriving from the gateway (the received side) is dropped', $rw->t_lrproof($GATEWAY, $pfRaw, $pf) === 0 && $rw->queued === []);
$rows = $rw->linkRows($linkId);
check('one row, unvalidated', count($rows) === 1 && (int) $rows[0]['validated'] === 0, json_encode($rows));

echo "── 13. a locally delivered LINKREQUEST registers no local destination and no reverse path ──\n";
$ra = localRouter($dest, $edPub);
check('67-byte LINKREQUEST delivered locally', $ra->t_deliverLocally($GATEWAY, $lrRaw, $lr) === true);
check('no local_destinations row for the link id', $ra->countWhere('local_destinations', 'destination_hash_hex', $linkId) === 0);
check('no local_destinations row for the packet truncated hash', $ra->countWhere('local_destinations', 'destination_hash_hex', $lr['truncated_hash_hex']) === 0);
check('no reverse path for the LINKREQUEST', $ra->countWhere('reverse_path_entries', 'truncated_hash_hex', $lr['truncated_hash_hex']) === 0);
check('only the browser destination is local', (int) $ra->db->query('SELECT COUNT(*) FROM local_destinations')->fetchColumn() === 1);
// 64 bytes (Retichat-js): link id == truncated hash, the one case the old row matched.
[$lr64, $lr64Raw] = pkt(['packet_type' => 2, 'hops' => 3, 'destination_hash_hex' => $dest], 64);
$link64 = $ra->t_linkIdHex($lr64Raw, $lr64);
check('64-byte LINKREQUEST delivered locally', $ra->t_deliverLocally($GATEWAY, $lr64Raw, $lr64) === true);
check('no local_destinations row for the 64-byte link id', $ra->countWhere('local_destinations', 'destination_hash_hex', $link64) === 0);
check('no reverse path for the 64-byte LINKREQUEST', $ra->countWhere('reverse_path_entries', 'truncated_hash_hex', $link64) === 0);
check('the link entry was still created', count($ra->linkRows($link64)) === 1);
// A DATA packet delivered locally still records its reverse path (regular proofs need it).
[$dp, $dpRaw] = pkt(['packet_type' => 0, 'hops' => 2, 'destination_hash_hex' => $dest], 40);
check('DATA delivered locally', $ra->t_deliverLocally($GATEWAY, $dpRaw, $dp) === true);
check('DATA still records a reverse path', $ra->countWhere('reverse_path_entries', 'truncated_hash_hex', $dp['truncated_hash_hex']) === 1);

echo "── 14. a link packet arriving before the LRPROOF is dropped ──\n";
$rp = localRouter($dest, $edPub);
check('LINKREQUEST delivered locally', $rp->t_deliverLocally($GATEWAY, $lrRaw, $lr) === true);
$rp->queued = [];
foreach ([[$GATEWAY, 7, 'from the initiator'], [$BROWSER, 1, 'from the browser']] as [$from, $hops, $side]) {
    [$d, $dRaw] = pkt(['packet_type' => 0, 'destination_type' => 3, 'context' => 0x00, 'hops' => $hops, 'destination_hash_hex' => $linkId], 100);
    check("pre-validation packet $side is link traffic", $rp->t_shouldRelayLink($d));
    check("pre-validation packet $side is dropped", $rp->t_relayAccepted($from, $dRaw, $d) === 0);
}
check('nothing queued before validation (no relay, no path request)', $rp->queued === [], json_encode($rp->queued));
check('the entry stays pending', count($rp->linkRows($linkId)) === 1 && (int) $rp->linkRows($linkId)[0]['validated'] === 0);

echo "── 15. a LINKCLOSE leaves the entry to age out; later packets still pass ──\n";
$rc = localRouter($dest, $edPub);
check('LINKREQUEST delivered locally', $rc->t_deliverLocally($GATEWAY, $lrRaw, $lr) === true);
[$pf, $pfRaw] = lrproof($linkId, 1, proofPayload($linkId, $SIG3, $edSec, $edPub));
check('LRPROOF relayed and validates', $rc->t_lrproof($BROWSER, $pfRaw, $pf) === 1 && (int) $rc->linkRows($linkId)[0]['validated'] === 1);
$rc->queued = [];
[$close, $closeRaw] = pkt(['packet_type' => 0, 'destination_type' => 3, 'context' => 0xFC, 'hops' => 7, 'destination_hash_hex' => $linkId], 48);
check('LINKCLOSE from the initiator is relayed to the browser', $rc->t_relayAccepted($GATEWAY, $closeRaw, $close) === 1
    && ($rc->queued[0]['interface_id'] ?? '') === $BROWSER && ($rc->queued[0]['reason'] ?? '') === 'link_relay', json_encode($rc->queued));
$rows = $rc->linkRows($linkId);
check('the link entry still exists, validated', count($rows) === 1 && (int) $rows[0]['validated'] === 1, json_encode($rows));
$rc->queued = [];
[$d, $dRaw] = pkt(['packet_type' => 0, 'destination_type' => 3, 'context' => 0x00, 'hops' => 1, 'destination_hash_hex' => $linkId], 100);
check('a later packet from the browser is still relayed to the initiator', $rc->t_relayAccepted($BROWSER, $dRaw, $d) === 1
    && ($rc->queued[0]['interface_id'] ?? '') === $GATEWAY, json_encode($rc->queued));
// Past the TTL the maintenance delete is what removes it; a stale row is also
// no longer "active", so the packet is dropped as unknown.
$rc->db->exec('UPDATE link_transport_entries SET updated_at = 0');
$rc->queued = [];
check('after the TTL the link is unknown and the packet is dropped', $rc->t_relayAccepted($BROWSER, $dRaw, $d) === 0 && $rc->queued === []);

echo "── 16. a link packet for an unknown link id is dropped, with no path request ──\n";
$rn = localRouter($dest, $edPub);
// Control: the harness does emit a path request for an unknown DATA destination.
$unknownDest = bin2hex(random_bytes(16));
[$d, $dRaw] = pkt(['packet_type' => 0, 'destination_type' => 0, 'hops' => 1, 'destination_hash_hex' => $unknownDest], 40);
$rn->t_relayAccepted($BROWSER, $dRaw, $d);
check('control: DATA to an unknown destination queues a path request',
    count(array_filter($rn->queued, fn ($q) => $q['reason'] === 'relay_path_request')) === 1, json_encode(array_column($rn->queued, 'reason')));
$rn->queued = [];
$unknownLink = bin2hex(random_bytes(16));
// A stale row left in local_destinations by the old code must not matter.
$rn->addLocalDestination($unknownLink, $BROWSER);
foreach ([[0x00, 0, 'data'], [0xFE, 0, 'LRRTT'], [0x00, 3, 'link proof']] as [$ctx, $type, $what]) {
    [$d, $dRaw] = pkt(['packet_type' => $type, 'destination_type' => 3, 'context' => $ctx, 'hops' => 7, 'destination_hash_hex' => $unknownLink], 80);
    check("unknown-link $what is link traffic", $rn->t_shouldRelayLink($d));
    check("unknown-link $what is dropped", $rn->t_relayAccepted($GATEWAY, $dRaw, $d) === 0);
    check("path table routing gives it no target either", $rn->t_relayTargets($GATEWAY, $d) === []);
}
check('nothing queued: no relay to the browser and no path request', $rn->queued === [], json_encode($rn->queued));
check('no path request throttle slot was claimed for the link id', $rn->countWhere('path_request_throttle', 'throttle_key', 'auto:' . $unknownLink) === 0);

echo "\nResults: $pass passed, $fail failed\n";
exit($fail > 0 ? 1 : 0);
