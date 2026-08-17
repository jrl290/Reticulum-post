<?php

declare(strict_types=1);

/**
 * Regression test for the total storage budget (RequestStorageBudgetTrait).
 *
 * The budget is driven by a measured footprint rather than by payload length,
 * so the harness injects a synthetic footprint. That is the whole point of
 * enforceStorageBudget() taking the footprint as an argument: on MySQL the
 * numbers come from information_schema and cannot be staged from a test.
 *
 * Run with: php tests/storage_budget_test.php
 */

require_once __DIR__ . '/../src/lib/database.php';
require_once __DIR__ . '/../src/lib/request_maintenance_trait.php';
require_once __DIR__ . '/../src/lib/request_storage_budget_trait.php';

final class StorageBudgetHarness
{
    use \ReticulumPhp\RequestMaintenanceTrait;
    use \ReticulumPhp\RequestStorageBudgetTrait;

    private PDO $db;
    private string $backend = 'sqlite';
    private array $config;

    public function __construct(array $maintenanceConfig = [])
    {
        $this->config = ['maintenance' => $maintenanceConfig, 'storage' => ['log_path' => '']];
        $this->db = new PDO('sqlite::memory:');
        $this->db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        $this->db->exec(
            'CREATE TABLE inbound_packets (
                packet_record_id INTEGER PRIMARY KEY,
                packet_hash_hex TEXT,
                created_at INTEGER NOT NULL
            )'
        );
        $this->db->exec(
            'CREATE TABLE outbound_packets (
                packet_id INTEGER PRIMARY KEY,
                queued_at INTEGER NOT NULL,
                acked_at INTEGER
            )'
        );
        $this->db->exec(
            'CREATE TABLE inbound_batches (
                batch_id TEXT PRIMARY KEY,
                created_at INTEGER NOT NULL,
                processed_at INTEGER
            )'
        );
        $this->db->exec(
            'CREATE TABLE outbound_batches (
                batch_id TEXT PRIMARY KEY,
                created_at INTEGER NOT NULL,
                acked_at INTEGER
            )'
        );
        $this->db->exec(
            'CREATE TABLE path_entries (
                destination_hash_hex TEXT PRIMARY KEY,
                packet_hash_hex TEXT,
                expires_at INTEGER NOT NULL DEFAULT 0,
                updated_at INTEGER NOT NULL DEFAULT 0
            )'
        );
        $this->db->exec(
            'CREATE TABLE known_destinations (
                destination_hash_hex TEXT PRIMARY KEY,
                updated_at INTEGER NOT NULL DEFAULT 0
            )'
        );
        $this->db->exec(
            'CREATE TABLE transport_state (
                state_key TEXT PRIMARY KEY,
                state_value TEXT,
                updated_at INTEGER NOT NULL DEFAULT 0
            )'
        );
    }

    public function insertInbound(int $id, int $createdAt, string $packetHashHex = ''): void
    {
        $stmt = $this->db->prepare(
            'INSERT INTO inbound_packets (packet_record_id, packet_hash_hex, created_at) VALUES (?, ?, ?)'
        );
        $stmt->execute([$id, $packetHashHex !== '' ? $packetHashHex : 'hash' . $id, $createdAt]);
    }

    public function insertOutbound(int $id, int $queuedAt, ?int $ackedAt): void
    {
        $stmt = $this->db->prepare(
            'INSERT INTO outbound_packets (packet_id, queued_at, acked_at) VALUES (?, ?, ?)'
        );
        $stmt->execute([$id, $queuedAt, $ackedAt]);
    }

    public function addPathEntry(string $destHashHex, string $packetHashHex, int $expiresAt): void
    {
        $stmt = $this->db->prepare(
            'INSERT INTO path_entries (destination_hash_hex, packet_hash_hex, expires_at, updated_at)
             VALUES (?, ?, ?, 0)'
        );
        $stmt->execute([$destHashHex, $packetHashHex, $expiresAt]);
    }

    /** Drive the pruner with a footprint the SQLite file could never produce. */
    public function enforce(int $budgetBytes, array $footprint): array
    {
        $summary = [];
        $this->enforceStorageBudget($budgetBytes, $footprint, $this->backend, false, $summary);
        return $summary;
    }

    public function reclaimTargets(array $footprint, int $minFree): array
    {
        return $this->storageReclaimTargets($footprint, $minFree);
    }

    public function normalizeRows(array $rows): array
    {
        return $this->normalizeFootprintRows($rows);
    }

    public function ids(string $table, string $idColumn): array
    {
        return array_map(
            'intval',
            $this->db->query("SELECT {$idColumn} FROM {$table} ORDER BY {$idColumn}")->fetchAll(PDO::FETCH_COLUMN)
        );
    }

    public function count(string $table): int
    {
        return (int) $this->db->query("SELECT COUNT(*) FROM {$table}")->fetchColumn();
    }
}

$failures = 0;
function check(mixed $expected, mixed $actual, string $message): void
{
    global $failures;
    if ($expected !== $actual) {
        $failures++;
        fwrite(STDERR, "FAIL: {$message}\n  expected: " . var_export($expected, true)
            . "\n  actual:   " . var_export($actual, true) . "\n");
    }
}

/** A footprint whose per-table numbers the SQLite harness will read directly. */
function footprint(int $databaseBytes, int $logBytes = 0, int $freeBytes = 0): array
{
    return [
        'database_bytes' => $databaseBytes,
        'database_free_bytes' => $freeBytes,
        'log_bytes' => $logBytes,
        'total_bytes' => $databaseBytes + $logBytes,
        'per_table' => [],
    ];
}

$now = time();
$old = $now - 86_400 * 2;   // safely past every retention floor
$recent = $now - 10;        // inside the 300s floor

// ── 1. Under budget: nothing is touched ────────────────────────────────
$harness = new StorageBudgetHarness();
$harness->insertInbound(1, $old);
$harness->insertOutbound(1, $old, $old);
$summary = $harness->enforce(1_000_000, footprint(500_000));
check([], $summary['storage_pruned'], 'a footprint under budget prunes nothing');
check(1, $harness->count('inbound_packets'), 'inbound rows survive when under budget');
check(1, $harness->count('outbound_packets'), 'outbound rows survive when under budget');

// ── 2. Budget of 0 disables the cap ────────────────────────────────────
$harness = new StorageBudgetHarness();
$harness->insertInbound(1, $old);
$summary = $harness->enforce(0, footprint(999_000_000));
check([], $summary['storage_pruned'], 'a zero budget disables the cap');
check(1, $harness->count('inbound_packets'), 'a zero budget preserves rows');

// ── 3. Log bytes come out of the same budget ───────────────────────────
// 400k of database plus 700k of logs exceeds a 1M budget even though the
// database alone does not. Counting only the database would miss this.
$harness = new StorageBudgetHarness();
for ($id = 1; $id <= 100; $id++) {
    $harness->insertInbound($id, $old + $id);
}
$summary = $harness->enforce(1_000_000, footprint(400_000, 700_000));
check(true, ($summary['storage_pruned']['inbound_packets'] ?? 0) > 0, 'log bytes count against the budget');

// ── 4. Tier order: diagnostics go before queued traffic ────────────────
// 100 inbound rows and 100 unacked outbound rows share an over-budget
// database. Inbound is tier 1 and must absorb the whole overage alone.
$harness = new StorageBudgetHarness();
for ($id = 1; $id <= 100; $id++) {
    $harness->insertInbound($id, $old + $id);
    $harness->insertOutbound($id, $old + $id, null);
}
$summary = $harness->enforce(500_000, footprint(1_000_000));
check(true, ($summary['storage_pruned']['inbound_packets'] ?? 0) > 0, 'inbound diagnostics are pruned first');
check(0, $summary['storage_pruned']['outbound_packets_pending'] ?? 0, 'pending outbound survives while cheaper tiers can pay');
check(100, $harness->count('outbound_packets'), 'no pending outbound row is removed');

// ── 5. Acknowledged outbound is pruned before pending outbound ─────────
// Both tiers are eligible — the pending rows are older than their 24h ceiling
// too — but the overage is small enough for tier 2 to cover alone, so tier 5
// must never be reached.
$harness = new StorageBudgetHarness();
for ($id = 1; $id <= 100; $id++) {
    $harness->insertOutbound($id, $old, $old);              // acked
    $harness->insertOutbound(1000 + $id, $old, null);       // pending
}
$summary = $harness->enforce(900_000, footprint(1_000_000));
check(true, ($summary['storage_pruned']['outbound_packets_acked'] ?? 0) > 0, 'acked outbound is pruned');
check(0, $summary['storage_pruned']['outbound_packets_pending'] ?? 0, 'pending outbound outranks acked history');
check(
    100,
    count(array_filter($harness->ids('outbound_packets', 'packet_id'), static fn (int $id): bool => $id > 1000)),
    'every pending row survives while acked history can pay the overage'
);

// ── 6. The retention floor holds under maximum pressure ────────────────
// Every row is younger than storage_prune_min_age_seconds. A budget of 1 byte
// against a 1 GB footprint must still not touch in-flight traffic.
$harness = new StorageBudgetHarness();
for ($id = 1; $id <= 50; $id++) {
    $harness->insertInbound($id, $recent);
    $harness->insertOutbound($id, $recent, $recent);
}
$summary = $harness->enforce(1, footprint(1_000_000_000));
check(50, $harness->count('inbound_packets'), 'rows inside the age floor are never pruned');
check(50, $harness->count('outbound_packets'), 'recent outbound is never pruned');
check(true, ($summary['storage_over_budget_bytes'] ?? 0) > 0, 'an unsatisfiable budget is reported, not silently ignored');

// ── 7. Pending outbound has its own, much longer floor ─────────────────
// Older than the 300s default floor but inside outbound_pending_max_age_seconds,
// so tier 5 must still refuse it even when it is the only tier with rows.
$harness = new StorageBudgetHarness(['storage_prune_min_age_seconds' => 60]);
for ($id = 1; $id <= 50; $id++) {
    $harness->insertOutbound($id, $now - 3600, null);
}
$harness->enforce(1, footprint(1_000_000_000));
check(50, $harness->count('outbound_packets'), 'pending outbound inside its 24h ceiling survives');

// ...and is pruned once it passes that ceiling. Nothing else ever removes an
// unacked row, so a peer that stops acking would otherwise pin its queue.
$harness = new StorageBudgetHarness();
for ($id = 1; $id <= 50; $id++) {
    $harness->insertOutbound($id, $now - 86_400 * 3, null);
}
$harness->enforce(1, footprint(1_000_000_000));
check(0, $harness->count('outbound_packets'), 'pending outbound past its ceiling is finally released');

// ── 8. An announce a live path entry points at is never pruned ─────────
// path_entries stores only the announce's packet_hash and re-reads the body
// from inbound_packets to answer path requests. Pruning it black-holes that
// destination for the rest of the entry's week-long life.
$harness = new StorageBudgetHarness();
$harness->insertInbound(1, $old, 'cached_announce');
for ($id = 2; $id <= 60; $id++) {
    $harness->insertInbound($id, $old, 'unreferenced' . $id);
}
$harness->addPathEntry('deadbeefdeadbeefdeadbeefdeadbeef', 'cached_announce', $now + 604_800);
$harness->enforce(1, footprint(1_000_000_000));
check([1], $harness->ids('inbound_packets', 'packet_record_id'), 'the referenced announce survives a total purge');

// ── 9. path_entries is last resort and only touches expired routes ─────
$harness = new StorageBudgetHarness();
$harness->addPathEntry('aaaa', 'h1', $now - 10);       // expired
$harness->addPathEntry('bbbb', 'h2', $now + 604_800);  // live
$harness->enforce(1, footprint(1_000_000_000));
check(1, $harness->count('path_entries'), 'only the expired path entry is pruned');

// ── 10. A pass cannot exceed its row ceiling ───────────────────────────
$harness = new StorageBudgetHarness(['storage_prune_max_rows_per_pass' => 10]);
for ($id = 1; $id <= 100; $id++) {
    $harness->insertInbound($id, $old + $id);
}
$harness->enforce(1, footprint(1_000_000_000));
$remaining = $harness->count('inbound_packets');
check(true, $remaining >= 90, 'storage_prune_max_rows_per_pass bounds a single pass');

// ── 11. Reclaim targeting on both backends ─────────────────────────────
// MySQL reports free space per table; SQLite has one file and an empty
// per_table map. Reading only per_table would silently never reclaim on
// SQLite, and the budget would report success while the file stayed huge.
$harness = new StorageBudgetHarness();
check(
    ['outbound_packets'],
    $harness->reclaimTargets([
        'database_free_bytes' => 0,
        'per_table' => [
            'outbound_packets' => ['bytes' => 700_000_000, 'free_bytes' => 100_000_000],
            'inbound_packets' => ['bytes' => 10_000_000, 'free_bytes' => 1_000_000],
        ],
    ], 64_000_000),
    'only tables with real slack are rebuilt'
);
check(
    ['sqlite:vacuum'],
    $harness->reclaimTargets(['database_free_bytes' => 120_000_000, 'per_table' => []], 64_000_000),
    'a per_table-less footprint reclaims the whole file'
);
check(
    [],
    $harness->reclaimTargets(['database_free_bytes' => 1_000, 'database_bytes' => 500_000_000, 'per_table' => []], 64_000_000),
    'nothing is rebuilt when there is no slack to recover'
);

// A table well under the absolute threshold but mostly empty must still be
// rebuilt, or it stays bloated forever. packet_hashes sat at 61.3 MB with
// 41 MB free — 67% waste — permanently invisible to a 64 MB test.
check(
    ['packet_hashes'],
    $harness->reclaimTargets([
        'database_free_bytes' => 0,
        'per_table' => [
            'packet_hashes' => ['bytes' => 64_270_336, 'free_bytes' => 42_991_616],
            'path_entries' => ['bytes' => 26_738_688, 'free_bytes' => 6_291_456],
        ],
    ], 64_000_000),
    'a mostly-empty table qualifies on ratio even under the absolute threshold'
);

// ...but a tiny table is not worth a rebuild however empty it looks.
check(
    [],
    $harness->reclaimTargets([
        'database_free_bytes' => 0,
        'per_table' => ['wake_events' => ['bytes' => 200_000, 'free_bytes' => 180_000]],
    ], 64_000_000),
    'the ratio test has a floor so trivial tables are left alone'
);

// ── 12. information_schema column case ─────────────────────────────────
// MySQL returns these column names upper-cased; PHP array keys are
// case-sensitive and a missed key reads as null, not an error. That shipped a
// footprint of zero bytes to production once — which reads as "database is
// empty" and quietly disables the cap. Reading must not depend on the case the
// server happens to choose.
$harness = new StorageBudgetHarness();
$mysqlShaped = [[
    'BUDGET_TABLE' => 'outbound_packets',
    'BUDGET_DATA_LENGTH' => '425721856',
    'BUDGET_INDEX_LENGTH' => '312934400',
    'BUDGET_DATA_FREE' => '7340032',
]];
$normalized = $harness->normalizeRows($mysqlShaped)[0];
check('outbound_packets', $normalized['budget_table'] ?? null, 'upper-cased table name is readable');
check(
    738656256,
    (int) ($normalized['budget_data_length'] ?? 0) + (int) ($normalized['budget_index_length'] ?? 0),
    'upper-cased size columns sum correctly instead of reading as zero'
);
check(
    ['budget_table' => 'x', 'budget_data_length' => 1],
    $harness->normalizeRows([['budget_table' => 'x', 'budget_data_length' => 1]])[0],
    'already-lower-cased rows pass through unchanged'
);

if ($failures > 0) {
    fwrite(STDERR, "\n{$failures} failed\n");
    exit(1);
}

fwrite(STDOUT, "PASS: total storage budget\n");
