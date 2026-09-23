<?php
/**
 * The SQLite schema must accept every upsert the node runs.
 *
 * On 2026-09-23 the private staging chain (a local PHP node on SQLite) rejected
 * every announce with "ON CONFLICT clause does not match any PRIMARY KEY or
 * UNIQUE constraint": ensureTables() built path_entries with the key
 * (destination_hash_hex, interface_id) while the path upsert conflicts on
 * destination_hash_hex alone, which is production MySQL's key and the
 * reference's one-path-per-destination rule. MySQL never noticed (ON DUPLICATE
 * KEY). This builds the real schema on an in-memory SQLite, runs the path
 * upsert twice, and checks that a file built with the old key is rebuilt.
 *
 * Run: php tests/sqlite_schema_upsert_test.php
 */
declare(strict_types=1);

require_once __DIR__ . '/../src/lib/database.php';
require_once __DIR__ . '/../src/lib/request_schema_trait.php';
require_once __DIR__ . '/../src/lib/request_control_plane_trait.php';
require_once __DIR__ . '/../src/lib/request_path_state_trait.php';
require_once __DIR__ . '/../src/lib/request_json_codec_trait.php';
require_once __DIR__ . '/../src/lib/request_relay_routing_trait.php';

if (!class_exists('ReticulumPhp\\TransportConstants')) {
    final class TransportConstantsStubForSchemaTest
    {
        public const APP_NAME = 'rnstransport';
        public const PATH_REQUEST_ASPECT_1 = 'path';
        public const PATH_REQUEST_ASPECT_2 = 'request';
        public const DEFAULT_PER_HOP_TIMEOUT_SECONDS = 6;
        public const PATH_REQUEST_MI = 20;
        public const PATH_REQUEST_TIMEOUT = 15;
    }
    class_alias('TransportConstantsStubForSchemaTest', 'ReticulumPhp\\TransportConstants');
}

final class SchemaRouter
{
    use \ReticulumPhp\RequestSchemaTrait;
    use \ReticulumPhp\RequestControlPlaneTrait;
    use \ReticulumPhp\RequestPathStateTrait;
    use \ReticulumPhp\RequestJsonCodecTrait;
    use \ReticulumPhp\RequestRelayRoutingTrait;

    public \PDO $db;
    public string $backend = 'sqlite';
    public array $config = ['transport' => ['pathfinder_max_hops' => 128, 'path_expiry_default_seconds' => 604800, 'max_random_blobs' => 64]];

    public function __construct(?string $preexisting = null)
    {
        $this->db = new \PDO('sqlite::memory:', options: [\PDO::ATTR_ERRMODE => \PDO::ERRMODE_EXCEPTION]);
        if ($preexisting !== null) {
            $this->db->exec($preexisting);
        }
        $summary = $this->migrate();
        // ensureColumns() retries MySQL-only ALTERs on SQLite and records the
        // noise; only a path_entries error is a failure here.
        $relevant = array_values(array_filter($summary['errors'] ?? [], fn ($e) => str_contains((string) $e, 'path_entries') || str_contains((string) $e, 'autoincrement')));
        if ($relevant !== []) {
            throw new RuntimeException('schema errors: ' . json_encode($relevant));
        }
    }

    private function interfaceMetadata(string $interfaceId): array { return []; }
    private function isInterfaceActive(string $interfaceId): bool { return true; }
    public function rememberKnownDestination(string $destHashHex, string $packetHashHex, array $announce): void {}
    public function registerLocalDestinationIfOwnInterface(string $destHashHex, string $interfaceId): void {}
    public function knownDestinationPublicKey(string $destHashHex): ?string { return null; }
    public function t_upsert(string $iface, array $packet, array $announce): array { return $this->upsertPathFromAnnounce($iface, $packet, $announce); }
    public function pathKeySql(): string
    {
        return (string) $this->db->query("SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'path_entries'")->fetchColumn();
    }
}

$pass = 0; $fail = 0;
function check(string $label, bool $ok, string $detail = ''): void
{
    global $pass, $fail;
    if ($ok) { $pass++; echo "  ok   $label\n"; } else { $fail++; echo "  FAIL $label" . ($detail !== '' ? " — $detail" : '') . "\n"; }
}
function packet(string $dest, int $hops): array
{
    return ['packet_type' => 1, 'context' => 0, 'context_flag' => 0, 'header_type' => 0, 'destination_type' => 0,
        'transport_type' => 0, 'hops' => $hops, 'destination_hash_hex' => $dest, 'transport_id_hex' => null,
        'payload_base64' => 'AAAA', 'normalized_raw_base64' => null, 'truncated_hash_hex' => null,
        'packet_hash_hex' => bin2hex(random_bytes(16))];
}
function announce(int $emitted): array
{
    return ['random_hash_hex' => bin2hex(random_bytes(10)), 'announce_emitted' => $emitted,
        'identity_hash_hex' => str_repeat('e', 32), 'public_key_hex' => null];
}

echo "── a fresh schema accepts the path upsert, twice ──\n";
$r = new SchemaRouter();
check('path_entries is keyed by the destination alone', (bool) preg_match('/PRIMARY KEY\s*\(\s*destination_hash_hex\s*\)/i', $r->pathKeySql()), $r->pathKeySql());
$dest = str_repeat('a', 32);
[$s1] = $r->t_upsert('iface_one', packet($dest, 2), announce(time() - 60));
[$s2] = $r->t_upsert('iface_two', packet($dest, 1), announce(time() - 30));
check('first announce accepted', in_array($s1, ['validated', 'path_updated'], true), $s1);
check('second announce (fewer hops, other interface) accepted', in_array($s2, ['validated', 'path_updated'], true), $s2);
$rows = $r->db->query("SELECT interface_id, hops FROM path_entries WHERE destination_hash_hex = '$dest'")->fetchAll(PDO::FETCH_ASSOC);
check('one path per destination, the newer one', count($rows) === 1 && $rows[0]['interface_id'] === 'iface_two' && (int) $rows[0]['hops'] === 1, json_encode($rows));

echo "── id columns are numbered on SQLite ──\n";
$r->db->exec("INSERT INTO outbound_packets (interface_id, packet_base64, queued_at, queue_reason) VALUES ('i', 'AAAA', 1, 'relay')");
$r->db->exec("INSERT INTO outbound_packets (interface_id, packet_base64, queued_at, queue_reason) VALUES ('i', 'AAAA', 1, 'relay')");
$ids = $r->db->query('SELECT packet_id FROM outbound_packets ORDER BY packet_id')->fetchAll(PDO::FETCH_COLUMN);
check('outbound packet ids are 1, 2 (not NULL)', array_map('intval', $ids) === [1, 2], json_encode($ids));
$r->db->exec("INSERT INTO inbound_packets (interface_id, batch_id, packet_index, status, created_at) VALUES ('i', 'b', 0, 'parsed', 1)");
$rid = $r->db->query('SELECT packet_record_id FROM inbound_packets')->fetchColumn();
check('inbound packet record ids are numbered', (int) $rid === 1, (string) $rid);

echo "── a file with BIGINT AUTO_INCREMENT ids is rebuilt, rows renumbered ──\n";
$oldIds = "CREATE TABLE outbound_packets (
    packet_id BIGINT AUTO_INCREMENT PRIMARY KEY, interface_id VARCHAR(64) NOT NULL, packet_hash_hex VARCHAR(64),
    proof_destination_hash_hex VARCHAR(64), destination_hash_hex VARCHAR(64), destination_public_key_hex TEXT,
    packet_base64 TEXT NOT NULL, queued_at INT NOT NULL DEFAULT 0, delivered_at INT DEFAULT NULL,
    delivered_batch_id VARCHAR(64) DEFAULT NULL, acked_at INT DEFAULT NULL, proofed_at INT DEFAULT NULL,
    queue_reason VARCHAR(32) NOT NULL DEFAULT 'relay');
INSERT INTO outbound_packets (interface_id, packet_base64, queued_at) VALUES ('i', 'AAAA', 1);
INSERT INTO outbound_packets (interface_id, packet_base64, queued_at) VALUES ('i', 'BBBB', 2);";
$r3 = new SchemaRouter($oldIds);
$rows = $r3->db->query('SELECT packet_id, packet_base64 FROM outbound_packets ORDER BY packet_id')->fetchAll(PDO::FETCH_ASSOC);
check('existing rows got ids from their rowid', count($rows) === 2 && (int) $rows[0]['packet_id'] === 1 && (int) $rows[1]['packet_id'] === 2, json_encode($rows));
$r3->db->exec("INSERT INTO outbound_packets (interface_id, packet_base64, queued_at) VALUES ('i', 'CCCC', 3)");
$next = $r3->db->query('SELECT MAX(packet_id) FROM outbound_packets')->fetchColumn();
check('new rows keep numbering', (int) $next === 3, (string) $next);

echo "── a file built with the old two-column key is rebuilt ──\n";
$old = 'CREATE TABLE path_entries (
    destination_hash_hex VARCHAR(64) NOT NULL, next_hop_hex VARCHAR(32) DEFAULT NULL, hops INT NOT NULL DEFAULT 0,
    expires_at INT NOT NULL DEFAULT 0, random_blobs_json TEXT, interface_id VARCHAR(64) NOT NULL,
    packet_hash_hex VARCHAR(64) DEFAULT NULL, announce_emitted INT NOT NULL DEFAULT 0, updated_at INT NOT NULL DEFAULT 0,
    PRIMARY KEY (destination_hash_hex, interface_id));
INSERT INTO path_entries VALUES ("' . $dest . '", "' . $dest . '", 3, ' . (time() + 3600) . ', "[]", "iface_old", "p1", 1, 100);
INSERT INTO path_entries VALUES ("' . $dest . '", "' . $dest . '", 2, ' . (time() + 3600) . ', "[]", "iface_new", "p2", 2, 200);';
$r2 = new SchemaRouter($old);
check('old key replaced', (bool) preg_match('/PRIMARY KEY\s*\(\s*destination_hash_hex\s*\)/i', $r2->pathKeySql()), $r2->pathKeySql());
$rows = $r2->db->query("SELECT interface_id, hops FROM path_entries")->fetchAll(PDO::FETCH_ASSOC);
check('the newest row per destination survives the rebuild', count($rows) === 1 && $rows[0]['interface_id'] === 'iface_new', json_encode($rows));
[$s3] = $r2->t_upsert('iface_three', packet($dest, 1), announce(time()));
check('the upsert works on the rebuilt table', in_array($s3, ['validated', 'path_updated'], true), $s3);

echo "\nResults: $pass passed, $fail failed\n";
exit($fail > 0 ? 1 : 0);
