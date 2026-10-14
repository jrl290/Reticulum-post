<?php
/**
 * A batch posted twice is answered as a duplicate from its stored row, and
 * its packets are processed once.
 *
 * recordInboundBatch() and ingestInboundBatchInline() look the batch up by
 * (interface_id, batch_id) before inserting it. From July 2026 both copies
 * tested execute()'s bool instead of the fetched row, so the check never
 * fired: a repeat went on to the INSERT, failed on the primary key, and the
 * catch answered it with the repeat's own counts and without the
 * 'processing' key HttpApi::handle()'s exchange route reads, a PHP
 * "Undefined array key" warning on every repeated exchange.
 *
 * Runs the real Storage on in-memory SQLite and posts a batch of two signed
 * announces through ingestInboundBatchInline(), the path every exchange
 * takes, then posts it again:
 *   (a) the repeat is answered from the stored row: duplicate_batch, the
 *       stored packet and byte counts, processing null, and no INSERT;
 *   (b) its packets are processed once: no second stored copy, no second
 *       relay, and the interface's rx counters count the batch once;
 *   (c) the batch id posted with fewer packets is answered with what was
 *       stored under it, not with the count that came this time;
 *   (d) recordInboundBatch() answers a repeat from the stored row too;
 *   (e) when another request stores the batch between the check and the
 *       INSERT, the race the duplicate-key catch is for, the loser is
 *       answered as a duplicate with processing null too, and the batch is
 *       processed once, by the request that won.
 *
 * Run: php tests/repeated_batch_is_a_duplicate_test.php
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

/**
 * Counts the INSERTs into inbound_batches the node attempts, failed ones too,
 * and can run a racing request just before the next one.
 */
final class CountingStatement extends PDOStatement
{
    public static int $batchInserts = 0;
    public static ?Closure $beforeNextBatchInsert = null;

    protected function __construct()
    {
    }

    public function execute(?array $params = null): bool
    {
        if (preg_match('/^\s*INSERT\s+INTO\s+inbound_batches\b/i', $this->queryString) === 1) {
            self::$batchInserts++;
            $race = self::$beforeNextBatchInsert;
            self::$beforeNextBatchInsert = null;
            if ($race !== null) {
                $race();
            }
        }
        return parent::execute($params);
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

/** HEADER_2, in transport from $transportId, SINGLE, ANNOUNCE, context NONE. */
function announceRaw(array $id, int $wireHops, string $transportId): string
{
    $randomBlob = random_bytes(5) . substr(pack('J', time()), 3, 5);
    $signature = sodium_crypto_sign_detached(
        $id['destination'] . $id['public_key'] . $id['name_hash'] . $randomBlob . $id['app_data'],
        $id['secret']
    );
    return chr((1 << 6) | (1 << 4) | 1) . chr($wireHops) . $transportId . $id['destination'] . chr(0x00)
        . $id['public_key'] . $id['name_hash'] . $randomBlob . $signature . $id['app_data'];
}

// ── A node: a bridge into the mesh and two browsers ──────────────────────

const GATEWAY = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';
const BROWSER1 = 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb';
const BROWSER2 = 'cccccccccccccccccccccccccccccccc';

$storage = new Storage(['storage' => ['backend' => 'sqlite', 'sqlite_path' => ':memory:']]);
$storage->migrateIfNeeded();
$db = (new ReflectionProperty($storage, 'db'))->getValue($storage);
$db->setAttribute(PDO::ATTR_STATEMENT_CLASS, [CountingStatement::class, []]);
foreach ([GATEWAY => ['client' => 'rns-post-interface', 'mode' => 6], BROWSER1 => ['client' => 'rns-js'], BROWSER2 => ['client' => 'rns-js']] as $iface => $meta) {
    $db->prepare("INSERT INTO interfaces (interface_id, name, session_token, bitrate, mtu, status, metadata_json, created_at, last_seen_at)
                  VALUES (:i, 'test', 'tok', 1000000, 500, 'online', :m, 1, :t)")
        ->execute([':i' => $iface, ':m' => json_encode($meta), ':t' => time()]);
}

/** What processing a batch leaves behind: stored copies, queued relays, the bridge's rx counters. */
function processed(PDO $db): array
{
    $count = static fn (string $table): int => (int) $db->query("SELECT COUNT(*) FROM $table")->fetchColumn();
    $rx = $db->query("SELECT rx_packets, rx_bytes FROM interfaces WHERE interface_id = '" . GATEWAY . "'")->fetch(PDO::FETCH_ASSOC);
    return [
        'stored' => $count('inbound_packets'),
        'queued' => $count('outbound_packets'),
        'batches' => $count('inbound_batches'),
        'rx_packets' => (int) $rx['rx_packets'],
        'rx_bytes' => (int) $rx['rx_bytes'],
    ];
}

/** The inbound_batches row stored for a batch id, as the duplicate answer should report it. */
function storedBatch(PDO $db, string $batchId): array
{
    $stmt = $db->prepare('SELECT packet_count, byte_count FROM inbound_batches WHERE interface_id = :i AND batch_id = :b');
    $stmt->execute([':i' => GATEWAY, ':b' => $batchId]);
    $row = $stmt->fetch(PDO::FETCH_ASSOC);
    return is_array($row) ? ['packets' => (int) $row['packet_count'], 'bytes' => (int) $row['byte_count']] : [];
}

/** Posts a batch, returning the answer and how many INSERTs into inbound_batches it attempted. */
function post(callable $ingest, string $batchId, array $packets): array
{
    $before = CountingStatement::$batchInserts;
    $answer = $ingest(GATEWAY, $batchId, $packets);
    return [$answer, CountingStatement::$batchInserts - $before];
}

$packets = [];
foreach (['one', 'two'] as $appData) {
    $packets[] = base64_encode(announceRaw(identity($appData), 1, random_bytes(16)));
}
$inline = [$storage, 'ingestInboundBatchInline'];

echo "A batch posted twice\n";
[$first, $firstInserts] = post($inline, 'batch-1', $packets);
$afterFirst = processed($db);
$stored = storedBatch($db, 'batch-1');
check('the first post is accepted and processed inline',
    ($first['duplicate_batch'] ?? null) === false && ($first['accepted_packets'] ?? null) === 2
        && is_array($first['processing'] ?? null) && $firstInserts === 1,
    json_encode($first) . ", $firstInserts INSERT(s)");
check('...its packets are stored, relayed and counted',
    $afterFirst['stored'] === 2 && $afterFirst['queued'] > 0 && $afterFirst['rx_packets'] === 2
        && $stored === ['packets' => 2, 'bytes' => $afterFirst['rx_bytes']],
    json_encode($afterFirst) . ' stored ' . json_encode($stored));

$duplicate = [
    'duplicate_batch' => true,
    'accepted_packets' => $stored['packets'] ?? -1,
    'accepted_bytes' => $stored['bytes'] ?? -1,
    'processing' => null,
];

[$repeat, $repeatInserts] = post($inline, 'batch-1', $packets);
check('(a) the repeat is answered as a duplicate from the stored row, processing null',
    $repeat === $duplicate, json_encode($repeat) . ' vs ' . json_encode($duplicate));
check('(a) ...by the duplicate check, before any INSERT', $repeatInserts === 0, "$repeatInserts INSERT(s) attempted");
check('(b) its packets are processed once: nothing stored, queued or counted again',
    processed($db) === $afterFirst, json_encode(processed($db)) . ' vs ' . json_encode($afterFirst));

[$fewer, $fewerInserts] = post($inline, 'batch-1', [$packets[0]]);
check('(c) the batch id with fewer packets is answered with what was stored under it',
    $fewer === $duplicate && $fewerInserts === 0,
    json_encode($fewer) . ", $fewerInserts INSERT(s)");

echo "\nrecordInboundBatch()\n";
$record = [$storage, 'recordInboundBatch'];
[$queuedFirst] = post($record, 'batch-2', $packets);
$queuedStored = storedBatch($db, 'batch-2');
[$queuedRepeat, $queuedRepeatInserts] = post($record, 'batch-2', $packets);
check('(d) a repeat is answered from the stored row, before any INSERT',
    ($queuedFirst['duplicate_batch'] ?? null) === false
        && $queuedRepeat === ['duplicate_batch' => true, 'accepted_packets' => $queuedStored['packets'] ?? -1, 'accepted_bytes' => $queuedStored['bytes'] ?? -1]
        && $queuedRepeatInserts === 0,
    json_encode($queuedRepeat) . ", $queuedRepeatInserts INSERT(s)");

echo "\nA race: another request stores the batch between the check and the INSERT\n";
$racePackets = [];
foreach (['three', 'four'] as $appData) {
    $racePackets[] = base64_encode(announceRaw(identity($appData), 1, random_bytes(16)));
}
$beforeRace = processed($db);
CountingStatement::$beforeNextBatchInsert = static function () use ($storage, $racePackets): void {
    $storage->ingestInboundBatchInline(GATEWAY, 'batch-3', $racePackets);
};
[$lost, $raceInserts] = post($inline, 'batch-3', $racePackets);
$raceStored = storedBatch($db, 'batch-3');
$afterRace = processed($db);
check('(e) the request that loses the race is answered as a duplicate, processing null',
    $lost === ['duplicate_batch' => true, 'accepted_packets' => $raceStored['packets'] ?? -1, 'accepted_bytes' => $raceStored['bytes'] ?? -1, 'processing' => null]
        && $raceInserts === 2,
    json_encode($lost) . ", $raceInserts INSERT(s), both requests should reach theirs");
check('(e) ...and the batch is processed once, by the request that won',
    $afterRace['stored'] - $beforeRace['stored'] === 2 && $afterRace['rx_packets'] - $beforeRace['rx_packets'] === 2
        && $afterRace['batches'] - $beforeRace['batches'] === 1,
    json_encode($afterRace) . ' vs ' . json_encode($beforeRace));

echo "\n$pass passed, $fail failed\n";
exit($fail === 0 ? 0 : 1);
