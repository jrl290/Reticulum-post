<?php

declare(strict_types=1);

/**
 * Regression test for interface staleness detection.
 *
 * markStaleInterfacesOffline() must judge staleness on last_seen_at. It used to
 * compare updated_at, which only that method ever writes, so an actively
 * polling interface was marked offline on the next maintenance pass. Everything
 * downstream then broke: peekReversePath() requires both interfaces to be
 * online, so PROOF/LRPROOF packets landing in the gap were dropped, and Phase 2
 * deleted the live client's path_entries.
 *
 * Run with: php tests/stale_interface_test.php
 */

require_once __DIR__ . '/../src/lib/database.php';
require_once __DIR__ . '/../src/lib/request_maintenance_trait.php';

final class StaleInterfaceHarness
{
    use \ReticulumPhp\RequestMaintenanceTrait;

    private PDO $db;
    private string $backend = 'sqlite';
    private array $config = [];

    public function __construct()
    {
        $this->db = new PDO('sqlite::memory:');
        $this->db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        $this->db->exec(
            "CREATE TABLE interfaces (
                interface_id TEXT PRIMARY KEY,
                status TEXT NOT NULL DEFAULT 'offline',
                last_seen_at INTEGER NOT NULL,
                updated_at INTEGER NOT NULL DEFAULT 0
            )"
        );
        $this->db->exec(
            'CREATE TABLE path_entries (
                destination_hash_hex TEXT PRIMARY KEY,
                interface_id TEXT NOT NULL
            )'
        );
    }

    public function addInterface(string $id, string $status, int $lastSeenAt, int $updatedAt): void
    {
        $stmt = $this->db->prepare(
            'INSERT INTO interfaces (interface_id, status, last_seen_at, updated_at) VALUES (?, ?, ?, ?)'
        );
        $stmt->execute([$id, $status, $lastSeenAt, $updatedAt]);
    }

    public function addPath(string $dest, string $interfaceId): void
    {
        $stmt = $this->db->prepare('INSERT INTO path_entries (destination_hash_hex, interface_id) VALUES (?, ?)');
        $stmt->execute([$dest, $interfaceId]);
    }

    public function markStale(int $staleCutoff): int
    {
        return $this->markStaleInterfacesOffline($staleCutoff, $this->backend);
    }

    public function purgePaths(int $staleCutoff): int
    {
        $summary = ['deadlock_retries' => 0];
        return $this->deleteOrphanedPathsForStaleInterfaces($staleCutoff, $this->backend, $summary);
    }

    public function statusOf(string $id): string
    {
        $stmt = $this->db->prepare('SELECT status FROM interfaces WHERE interface_id = ?');
        $stmt->execute([$id]);
        return (string) $stmt->fetchColumn();
    }

    public function pathCount(): int
    {
        return (int) $this->db->query('SELECT COUNT(*) FROM path_entries')->fetchColumn();
    }
}

function assertSameValue(mixed $expected, mixed $actual, string $message): void
{
    if ($expected !== $actual) {
        fwrite(STDERR, "FAIL: {$message}\nExpected: " . var_export($expected, true) . "\nActual: " . var_export($actual, true) . "\n");
        exit(1);
    }
}

$now = 1_000_000;
$staleAfter = 15;
$cutoff = $now - $staleAfter;

$h = new StaleInterfaceHarness();
// The regression shape: seen this instant, but updated_at still holds the
// migration default. This is every browser and peer interface in production.
$h->addInterface('live-default-updated-at', 'online', $now, 0);
// Seen this instant, updated_at left over from an earlier offline marking.
$h->addInterface('live-stale-updated-at', 'online', $now, $now - 900);
// Genuinely gone.
$h->addInterface('abandoned', 'online', $now - 60, 0);

$marked = $h->markStale($cutoff);

assertSameValue('online', $h->statusOf('live-default-updated-at'), 'an interface seen now stays online despite updated_at=0');
assertSameValue('online', $h->statusOf('live-stale-updated-at'), 'an interface seen now stays online despite a stale updated_at');
assertSameValue('offline', $h->statusOf('abandoned'), 'an interface unseen past the cutoff goes offline');
assertSameValue(1, $marked, 'exactly one interface is marked stale');

// Phase 2 must not touch paths belonging to interfaces that are still online.
$p = new StaleInterfaceHarness();
$p->addInterface('live', 'online', $now, 0);
$p->addPath('aa', 'live');
$p->markStale($cutoff);
$p->purgePaths($cutoff);
assertSameValue(1, $p->pathCount(), 'paths for a live interface survive the maintenance pass');

echo "stale_interface_test: OK\n";
