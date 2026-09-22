<?php
/**
 * A link initiated from OUTSIDE to a browser on this node, on the real SQL.
 *
 * 2026-09-22, retichat.com: an Android app opened a link to a browser here.
 * The LINKREQUEST (observed 7 hops) was delivered locally and recorded with
 * remaining_hops = -1 ("no expectation", commit 88ec642). The browser's LRPROOF
 * (observed 1) was looked up with `remaining_hops = 1`, which a -1 row can
 * never satisfy, so it fell to the reverse-path fallback: the proof went out,
 * but a SECOND row (taken_hops = 1) was written and the original never
 * validated. The phone's LRRTT and LXMF data (observed 7) then failed the
 * taken-hops check on the fallback row and were dropped without a trace.
 * hops_test.php's mock had hidden the filter; this test uses the trait's own
 * queries on an in-memory SQLite so the SQL itself is what is asserted.
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
    public function knownDestinationPublicKey(string $destHashHex): ?string { return null; }
    private function rememberPacketHash(string $hex): void {}
    private function packetHashExists(string $hex): bool { return false; }

    // ── Entry points ──────────────────────────────────────────────────
    public function t_deliverLocally(string $src, string $raw, array $pkt): bool { return $this->deliverLocallyIfKnown($src, $raw, $pkt); }
    public function t_lrproof(string $src, string $raw, array $pkt): int { return $this->relayLinkRequestProofPacket($src, $raw, $pkt); }
    public function t_shouldRelayLink(array $pkt): bool { return $this->shouldRelayLinkTransportPacket($pkt); }
    public function t_relayLink(string $src, string $raw, array $pkt): int { return $this->relayLinkTransportPacket($src, $raw, $pkt); }
    public function t_linkIdHex(string $raw, array $pkt): ?string { return $this->linkIdHex($raw, $pkt); }
}

$pass = 0; $fail = 0;
function check(string $label, bool $ok, string $detail = ''): void
{
    global $pass, $fail;
    if ($ok) { $pass++; echo "  ok   $label\n"; }
    else { $fail++; echo "  FAIL $label" . ($detail !== '' ? " — $detail" : '') . "\n"; }
}

/** A packet array plus matching raw bytes (HEADER_1), payload of $payloadLen bytes. */
function pkt(array $o, int $payloadLen): array
{
    $p = array_merge([
        'packet_type' => 0, 'context' => 0x00, 'context_flag' => 0, 'header_type' => 0,
        'destination_type' => 0, 'transport_type' => 0, 'hops' => 0,
        'destination_hash_hex' => str_repeat('0', 32), 'transport_id_hex' => null,
        'truncated_hash_hex' => null, 'packet_hash_hex' => bin2hex(random_bytes(16)),
    ], $o);
    $payload = random_bytes($payloadLen);
    $p['payload_base64'] = base64_encode($payload);
    $flags = ($p['context_flag'] << 5) | ($p['header_type'] << 6) | ($p['transport_type'] << 4) | ($p['destination_type'] << 2) | $p['packet_type'];
    $raw = chr($flags) . chr($p['hops']) . hex2bin($p['destination_hash_hex']) . chr($p['context']) . $payload;
    $p['truncated_hash_hex'] ??= bin2hex(substr(hash('sha256', $raw, true), 0, 16));
    return [$p, base64_encode($raw)];
}

$GATEWAY = 'iface_gateway';
$BROWSER = 'iface_browser';
$dest = 'b42714bda794d70a05dd70ce6140f59a';

$r = new SqlLinkRouter();
$r->addInterface($GATEWAY);
$r->addInterface($BROWSER);
$r->addLocalDestination($dest, $BROWSER);

echo "── 1. LINKREQUEST from the gateway (7 hops) to a local browser ──\n";
// 64 bytes of keys + 3 signalling bytes (RNS ≥ 0.9): the link id is NOT the
// packet's truncated hash, so the reverse-path fallback could not rescue it.
[$lr, $lrRaw] = pkt(['packet_type' => 2, 'hops' => 7, 'destination_hash_hex' => $dest], 67);
$linkId = $r->t_linkIdHex($lrRaw, $lr);
check('link id derived', is_string($linkId) && strlen($linkId) === 32);
check('link id differs from the packet truncated hash (signalling bytes)', $linkId !== $lr['truncated_hash_hex']);
check('delivered locally', $r->t_deliverLocally($GATEWAY, $lrRaw, $lr) === true);
check('LINKREQUEST queued to the browser as local_delivery', ($r->queued[0]['interface_id'] ?? '') === $BROWSER && ($r->queued[0]['reason'] ?? '') === 'local_delivery');
$rows = $r->linkRows($linkId);
check('one link entry', count($rows) === 1, json_encode($rows));
check('entry: remaining_hops = -1, taken_hops = 7, gateway -> browser',
    (int) $rows[0]['remaining_hops'] === -1 && (int) $rows[0]['taken_hops'] === 7
    && $rows[0]['received_interface_id'] === $GATEWAY && $rows[0]['outbound_interface_id'] === $BROWSER, json_encode($rows));

echo "── 2. LRPROOF from the browser (1 hop) ──\n";
$r->queued = [];
[$pf, $pfRaw] = pkt(['packet_type' => 3, 'context' => 0xFF, 'destination_type' => 2, 'hops' => 1, 'destination_hash_hex' => $linkId], 99);
check('LRPROOF relayed', $r->t_lrproof($BROWSER, $pfRaw, $pf) === 1);
check('LRPROOF went to the gateway via the link entry (lrproof_relay)',
    ($r->queued[0]['interface_id'] ?? '') === $GATEWAY && ($r->queued[0]['reason'] ?? '') === 'lrproof_relay', json_encode($r->queued));
$rows = $r->linkRows($linkId);
check('still one link entry (no fallback duplicate)', count($rows) === 1, json_encode($rows));
check('the entry is validated', (int) ($rows[0]['validated'] ?? 0) === 1, json_encode($rows));

echo "── 3. LRRTT and LXMF data from the gateway (7 hops) reach the browser ──\n";
foreach ([0xFE => 'LRRTT', 0x00 => 'data'] as $ctx => $what) {
    $r->queued = [];
    [$d, $dRaw] = pkt(['packet_type' => 0, 'destination_type' => 2, 'context' => $ctx, 'hops' => 7, 'destination_hash_hex' => $linkId], 200);
    check("$what is routed as a link transport packet", $r->t_shouldRelayLink($d));
    check("$what relayed", $r->t_relayLink($GATEWAY, $dRaw, $d) === 1);
    check("$what reached the browser as link_relay", ($r->queued[0]['interface_id'] ?? '') === $BROWSER && ($r->queued[0]['reason'] ?? '') === 'link_relay', json_encode($r->queued));
}

echo "── 4. the browser's reply (1 hop) reaches the gateway ──\n";
$r->queued = [];
[$d, $dRaw] = pkt(['packet_type' => 0, 'destination_type' => 2, 'context' => 0x00, 'hops' => 1, 'destination_hash_hex' => $linkId], 200);
check('reply relayed', $r->t_relayLink($BROWSER, $dRaw, $d) === 1);
check('reply reached the gateway', ($r->queued[0]['interface_id'] ?? '') === $GATEWAY, json_encode($r->queued));

echo "── 5. a wrong-hop LRRTT from the gateway side is still dropped ──\n";
$r->queued = [];
[$d, $dRaw] = pkt(['packet_type' => 0, 'destination_type' => 2, 'context' => 0xFE, 'hops' => 3, 'destination_hash_hex' => $linkId], 200);
check('3-hop packet on a 7-hop link is not relayed', $r->t_relayLink($GATEWAY, $dRaw, $d) === 0 && $r->queued === []);

echo "── 6. a transit entry keeps the exact LRPROOF hop gate ──\n";
$r2 = new SqlLinkRouter();
$r2->addInterface('iface_a'); $r2->addInterface('iface_b');
$transitId = bin2hex(random_bytes(16));
$r2->db->prepare('INSERT INTO link_transport_entries VALUES (:l, :ri, :oi, :nh, 2, 1, :d, 0, :pe, :u)')
    ->execute([':l' => $transitId, ':ri' => 'iface_a', ':oi' => 'iface_b', ':nh' => $dest, ':d' => $dest, ':pe' => time() + 60, ':u' => time()]);
[$pf, $pfRaw] = pkt(['packet_type' => 3, 'context' => 0xFF, 'destination_type' => 2, 'hops' => 3, 'destination_hash_hex' => $transitId], 99);
check('LRPROOF with 3 hops on a remaining=2 transit entry is dropped', $r2->t_lrproof('iface_b', $pfRaw, $pf) === 0 && $r2->queued === []);
[$pf, $pfRaw] = pkt(['packet_type' => 3, 'context' => 0xFF, 'destination_type' => 2, 'hops' => 2, 'destination_hash_hex' => $transitId], 99);
check('LRPROOF with 2 hops is relayed and validates', $r2->t_lrproof('iface_b', $pfRaw, $pf) === 1 && (int) $r2->linkRows($transitId)[0]['validated'] === 1);

echo "\nResults: $pass passed, $fail failed\n";
exit($fail > 0 ? 1 : 0);
