<?php

declare(strict_types=1);

/**
 * Regression test for the combined inbound/outbound packet storage cap.
 *
 * Run with: php tests/packet_storage_cap_test.php
 */

require_once __DIR__ . '/../src/lib/database.php';
require_once __DIR__ . '/../src/lib/request_maintenance_trait.php';

final class PacketStorageCapHarness
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
            'CREATE TABLE inbound_packets (
                packet_record_id INTEGER PRIMARY KEY,
                raw_base64 TEXT,
                payload_base64 TEXT,
                packet_hash_hex TEXT,
                created_at INTEGER NOT NULL
            )'
        );
        $this->db->exec(
            'CREATE TABLE outbound_packets (
                packet_id INTEGER PRIMARY KEY,
                packet_base64 TEXT,
                queued_at INTEGER NOT NULL,
                acked_at INTEGER
            )'
        );
        // Expiry must not orphan the announce a live path entry points at.
        $this->db->exec(
            'CREATE TABLE path_entries (
                destination_hash_hex TEXT PRIMARY KEY,
                packet_hash_hex TEXT NOT NULL
            )'
        );
    }

    public function addPathEntry(string $destHashHex, string $packetHashHex): void
    {
        $stmt = $this->db->prepare(
            'INSERT INTO path_entries (destination_hash_hex, packet_hash_hex) VALUES (?, ?)'
        );
        $stmt->execute([$destHashHex, $packetHashHex]);
    }

    public function insertInbound(int $id, int $createdAt, int $rawBytes, int $payloadBytes, string $packetHashHex = ''): void
    {
        $stmt = $this->db->prepare(
            'INSERT INTO inbound_packets (packet_record_id, raw_base64, payload_base64, packet_hash_hex, created_at)
             VALUES (?, ?, ?, ?, ?)'
        );
        $stmt->execute([
            $id,
            str_repeat('r', $rawBytes),
            str_repeat('p', $payloadBytes),
            $packetHashHex !== '' ? $packetHashHex : 'hash' . $id,
            $createdAt,
        ]);
    }

    public function insertOutbound(int $id, int $queuedAt, int $bytes, bool $acked = true): void
    {
        $stmt = $this->db->prepare(
            'INSERT INTO outbound_packets (packet_id, packet_base64, queued_at, acked_at) VALUES (?, ?, ?, ?)'
        );
        $stmt->execute([$id, str_repeat('o', $bytes), $queuedAt, $acked ? $queuedAt + 1 : null]);
    }

    public function trimTo(int $maxBytes): array
    {
        $summary = [
            'packet_storage_bytes_before' => 0,
            'packet_storage_bytes_after' => 0,
            'trimmed_inbound_packets' => 0,
            'trimmed_outbound_packets' => 0,
        ];
        $this->trimPacketStorage($maxBytes, $this->backend, $summary);
        return $summary;
    }

    public function expireHistory(int $inboundCutoff, int $outboundCutoff): array
    {
        $summary = ['deadlock_retries' => 0];
        return $this->deleteExpiredPacketHistory(
            $inboundCutoff,
            $outboundCutoff,
            $this->backend,
            $summary
        );
    }

    public function ids(string $table, string $idColumn): array
    {
        return array_map(
            'intval',
            $this->db->query("SELECT {$idColumn} FROM {$table} ORDER BY {$idColumn}")->fetchAll(PDO::FETCH_COLUMN)
        );
    }
}

function assertSameValue(mixed $expected, mixed $actual, string $message): void
{
    if ($expected !== $actual) {
        fwrite(STDERR, "FAIL: {$message}\nExpected: " . var_export($expected, true) . "\nActual: " . var_export($actual, true) . "\n");
        exit(1);
    }
}

$harness = new PacketStorageCapHarness();
$harness->insertInbound(1, 100, 8, 2);
$harness->insertOutbound(1, 200, 10);
$harness->insertInbound(2, 300, 8, 2);
$harness->insertOutbound(2, 400, 10);

$summary = $harness->trimTo(25);

assertSameValue(40, $summary['packet_storage_bytes_before'], 'combined byte count includes both packet tables');
assertSameValue(20, $summary['packet_storage_bytes_after'], 'storage is reduced below the configured cap');
assertSameValue(1, $summary['trimmed_inbound_packets'], 'one inbound packet is trimmed');
assertSameValue(1, $summary['trimmed_outbound_packets'], 'one outbound packet is trimmed');
assertSameValue([2], $harness->ids('inbound_packets', 'packet_record_id'), 'oldest inbound packet is removed');
assertSameValue([2], $harness->ids('outbound_packets', 'packet_id'), 'oldest outbound packet is removed');

$pendingHarness = new PacketStorageCapHarness();
$pendingHarness->insertOutbound(1, 100, 10, false);
$pendingHarness->insertInbound(1, 200, 10, 10);
$pendingSummary = $pendingHarness->trimTo(10);
assertSameValue([1], $pendingHarness->ids('outbound_packets', 'packet_id'), 'pending outbound survives while historical rows can satisfy the cap');
assertSameValue(1, $pendingSummary['trimmed_inbound_packets'], 'inbound history is pruned before pending outbound');
assertSameValue(0, $pendingSummary['trimmed_outbound_packets'], 'pending outbound is not pruned unnecessarily');

$disabledHarness = new PacketStorageCapHarness();
$disabledHarness->insertInbound(1, 100, 10, 10);
$disabledSummary = $disabledHarness->trimTo(0);
assertSameValue(20, $disabledSummary['packet_storage_bytes_after'], 'zero disables the storage cap');
assertSameValue([1], $disabledHarness->ids('inbound_packets', 'packet_record_id'), 'disabled cap preserves rows');

$multiBatchHarness = new PacketStorageCapHarness();
for ($id = 1; $id <= 500; $id++) {
    $multiBatchHarness->insertInbound($id, $id, 0, 0);
}
$multiBatchHarness->insertInbound(501, 501, 10, 10);
$multiBatchSummary = $multiBatchHarness->trimTo(10);
assertSameValue(501, $multiBatchSummary['trimmed_inbound_packets'], 'pruning continues past a zero-byte candidate batch');
assertSameValue(0, $multiBatchSummary['packet_storage_bytes_after'], 'multi-batch pruning reaches or undershoots the cap');

$historyHarness = new PacketStorageCapHarness();
$historyHarness->insertInbound(1, 100, 5, 5);
$historyHarness->insertInbound(2, 300, 5, 5);
$historyHarness->insertOutbound(1, 100, 10, true);
$historyHarness->insertOutbound(2, 100, 10, false);
$historyHarness->insertOutbound(3, 300, 10, true);
[$expiredInbound, $expiredOutbound] = $historyHarness->expireHistory(200, 200);
assertSameValue(1, $expiredInbound, 'expired inbound diagnostic history is removed');
assertSameValue(1, $expiredOutbound, 'only acknowledged outbound history is expired');
assertSameValue([2], $historyHarness->ids('inbound_packets', 'packet_record_id'), 'new inbound history remains');
assertSameValue([2, 3], $historyHarness->ids('outbound_packets', 'packet_id'), 'pending and new acknowledged outbound rows remain');

// A path entry keeps only the packet_hash of the announce that taught it the
// path and re-reads the body to answer path requests. Path entries outlive this
// history by days, so expiring a referenced row leaves the entry pointing at
// nothing and silently black-holes path requests for that destination.
$referencedHarness = new PacketStorageCapHarness();
$referencedHarness->insertInbound(1, 100, 5, 5, 'cached_announce');
$referencedHarness->insertInbound(2, 100, 5, 5, 'unreferenced');
$referencedHarness->addPathEntry('deadbeefdeadbeefdeadbeefdeadbeef', 'cached_announce');
[$expiredInbound] = $referencedHarness->expireHistory(200, 200);
assertSameValue(1, $expiredInbound, 'only the unreferenced announce expires');
assertSameValue(
    [1],
    $referencedHarness->ids('inbound_packets', 'packet_record_id'),
    'an announce referenced by a live path entry survives expiry'
);

fwrite(STDOUT, "PASS: combined packet storage cap\n");