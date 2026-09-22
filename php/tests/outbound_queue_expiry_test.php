<?php
/**
 * outbound_queue_expiry_test.php — packets nobody will ever collect do not stay.
 *
 * Until 2026-09-22 Phase 5 expired only ACKED outbound packets. A packet
 * queued for an interface that went offline and never returned — a closed
 * browser tab, a replaced bridge — was never acked, so it was never expired:
 * retichat.com held 512 of them for offline interfaces, 7 hours old, and 5
 * for interfaces maintenance had already deleted. Both classes now go: unacked
 * rows after the same outbound TTL, orphans (no interface row) at once.
 *
 * Run: php tests/outbound_queue_expiry_test.php
 */
declare(strict_types=1);

require_once __DIR__ . '/../src/lib/database.php';
require_once __DIR__ . '/../src/lib/request_maintenance_trait.php';

final class OutboundExpiryHarness
{
    use \ReticulumPhp\RequestMaintenanceTrait;

    private PDO $db;
    private string $backend = 'sqlite';
    private array $config = [];

    public function __construct()
    {
        $this->db = new PDO('sqlite::memory:');
        $this->db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        $this->db->exec("CREATE TABLE interfaces (interface_id TEXT PRIMARY KEY, status TEXT NOT NULL DEFAULT 'online')");
        $this->db->exec("CREATE TABLE inbound_packets (packet_record_id INTEGER PRIMARY KEY, packet_hash_hex TEXT, created_at INTEGER NOT NULL)");
        $this->db->exec("CREATE TABLE path_entries (destination_hash_hex TEXT PRIMARY KEY, packet_hash_hex TEXT)");
        $this->db->exec("CREATE TABLE outbound_packets (
            packet_id INTEGER PRIMARY KEY, interface_id TEXT NOT NULL,
            queued_at INTEGER NOT NULL, delivered_at INTEGER, acked_at INTEGER)");
        $this->db->exec("INSERT INTO interfaces VALUES ('alive','online'), ('gone-offline','offline')");
    }

    public function queue(string $label, string $iface, int $queuedAt, ?int $ackedAt): void
    {
        $s = $this->db->prepare('INSERT INTO outbound_packets (interface_id, queued_at, delivered_at, acked_at) VALUES (:i, :q, :d, :a)');
        $s->execute([':i' => $iface, ':q' => $queuedAt, ':d' => $ackedAt, ':a' => $ackedAt]);
        $this->labels[(int) $this->db->lastInsertId()] = $label;
    }
    private array $labels = [];

    public function expire(int $now, int $ttl): int
    {
        $summary = [];
        [, $outbound] = $this->deleteExpiredPacketHistory($now - 3600, $now - $ttl, $this->backend, $summary);
        return $outbound;
    }

    public function remaining(): array
    {
        $ids = $this->db->query('SELECT packet_id FROM outbound_packets ORDER BY packet_id')->fetchAll(PDO::FETCH_COLUMN);
        return array_map(fn($id) => $this->labels[(int) $id], $ids);
    }
}

$pass = 0; $fail = 0;
function check(string $label, bool $ok): void {
    global $pass, $fail;
    if ($ok) { $pass++; echo "  \033[32m✓\033[0m $label\n"; }
    else     { $fail++; echo "  \033[31m✗\033[0m $label\n"; }
}

$now = 1_000_000; $ttl = 86400;
$h = new OutboundExpiryHarness();
$h->queue('acked-old',        'alive',        $now - 2 * $ttl, $now - 2 * $ttl);  // acked, past TTL   → gone
$h->queue('acked-fresh',      'alive',        $now - 10,       $now - 10);        // acked, fresh      → stays
$h->queue('unacked-old',      'gone-offline', $now - 2 * $ttl, null);             // never acked, old  → gone (the leak)
$h->queue('unacked-fresh',    'alive',        $now - 10,       null);             // pending, fresh    → stays
$h->queue('orphan-fresh',     'deleted-iface', $now - 10,      null);             // no interface row  → gone regardless

$deleted = $h->expire($now, $ttl);
$left = $h->remaining();

check('three rows deleted', $deleted === 3);
check('acked packet past the TTL is gone',              !in_array('acked-old', $left, true));
check('never-acked packet past the TTL is gone',        !in_array('unacked-old', $left, true));
check('packet for a deleted interface is gone at once', !in_array('orphan-fresh', $left, true));
check('fresh acked packet stays',                        in_array('acked-fresh', $left, true));
check('fresh pending packet for a live interface stays', in_array('unacked-fresh', $left, true));

echo "\nResults: $pass passed, $fail failed\n";
exit($fail > 0 ? 1 : 0);
