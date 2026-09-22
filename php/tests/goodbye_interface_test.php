<?php
/**
 * POST /v1/interfaces/goodbye releases a browser's registration at once.
 *
 * Before 2026-09-22 nothing told the node a tab had closed; the interface
 * stayed 'online' — and its local destinations kept capturing direct
 * delivery — until the stale sweep (interface_stale_after_seconds, 300 s on
 * retichat.com). goodbyeInterface() does immediately what the sweep does
 * later. Run: php tests/goodbye_interface_test.php
 */
declare(strict_types=1);
require_once __DIR__ . '/../src/lib/database.php';
require_once __DIR__ . '/../src/lib/request_interface_registry_trait.php';

final class GoodbyeHarness
{
    use \ReticulumPhp\RequestInterfaceRegistryTrait;
    public \PDO $db;
    public string $backend = 'sqlite';
    public function __construct()
    {
        $this->db = new \PDO('sqlite::memory:', options: [\PDO::ATTR_ERRMODE => \PDO::ERRMODE_EXCEPTION]);
        $this->db->exec("CREATE TABLE interfaces (interface_id TEXT PRIMARY KEY, name TEXT, session_token TEXT, bitrate INTEGER, mtu INTEGER, status TEXT, metadata_json TEXT, created_at INTEGER, last_seen_at INTEGER, updated_at INTEGER, peer_url TEXT, peer_interface_id TEXT, peer_session_token TEXT)");
        $this->db->exec("CREATE TABLE local_destinations (destination_hash_hex TEXT PRIMARY KEY, interface_id TEXT NOT NULL, registered_at INTEGER NOT NULL)");
        $this->db->exec("CREATE TABLE path_entries (destination_hash_hex TEXT PRIMARY KEY, next_hop_hex TEXT, hops INTEGER, expires_at INTEGER, random_blobs_json TEXT, interface_id TEXT NOT NULL, packet_hash_hex TEXT, announce_emitted INTEGER, updated_at INTEGER)");
    }
    public function iface(string $id, string $status = 'online'): void
    {
        $this->db->prepare("INSERT INTO interfaces (interface_id, name, session_token, status, last_seen_at, updated_at) VALUES (?, ?, 'tok', ?, ?, ?)")
            ->execute([$id, "if-$id", $status, time(), time() - 100]);
    }
    public function local(string $dest, string $iface): void
    {
        $this->db->prepare("INSERT INTO local_destinations VALUES (?, ?, ?)")->execute([$dest, $iface, time()]);
    }
    public function path(string $dest, string $iface): void
    {
        $this->db->prepare("INSERT INTO path_entries (destination_hash_hex, next_hop_hex, hops, expires_at, random_blobs_json, interface_id, packet_hash_hex, announce_emitted, updated_at) VALUES (?, ?, 1, ?, '[]', ?, 'ph', ?, ?)")
            ->execute([$dest, $dest, time() + 3600, $iface, time(), time()]);
    }
    public function status(string $id): array
    {
        $st = $this->db->prepare("SELECT status, updated_at FROM interfaces WHERE interface_id = ?"); $st->execute([$id]);
        return $st->fetch(\PDO::FETCH_ASSOC);
    }
    public function count(string $table, string $iface): int
    {
        $st = $this->db->prepare("SELECT COUNT(*) FROM $table WHERE interface_id = ?"); $st->execute([$iface]);
        return (int) $st->fetchColumn();
    }
}

$pass = 0; $fail = 0;
function check(string $label, bool $ok): void { global $pass, $fail; if ($ok) { $pass++; echo "  ok   $label\n"; } else { $fail++; echo "  FAIL $label\n"; } }

$h = new GoodbyeHarness();
$h->iface('browser'); $h->iface('other');
$h->local('d1', 'browser'); $h->local('d2', 'browser'); $h->local('d3', 'other');
$h->path('d1', 'browser'); $h->path('d3', 'other');

$dropped = $h->goodbyeInterface('browser');
$row = $h->status('browser');
check("interface is offline at once", $row['status'] === 'offline');
check("updated_at is now (the sweep's cutoff clock)", (int) $row['updated_at'] >= time() - 2);
check("its local destinations are gone", $h->count('local_destinations', 'browser') === 0);
check("its path entries are gone", $h->count('path_entries', 'browser') === 0);
check("the other interface is untouched", $h->status('other')['status'] === 'online' && $h->count('local_destinations', 'other') === 1 && $h->count('path_entries', 'other') === 1);
check("the response counts what was dropped", $dropped === ['local_destinations' => 2, 'path_entries' => 1]);
$again = $h->goodbyeInterface('browser');
check("goodbye is idempotent", $again === ['local_destinations' => 0, 'path_entries' => 0] && $h->status('browser')['status'] === 'offline');

echo "\nResults: $pass passed, $fail failed\n";
exit($fail > 0 ? 1 : 0);
