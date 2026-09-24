<?php
declare(strict_types=1);

/**
 * Per-packet database work must not repeat per-interface work.
 *
 * Until 2026-09-24 every packet queued for an interface re-ran the queue-cap
 * check and the wake decision (a pending count plus a pending-wake lookup),
 * assignOutboundBatch issued one UPDATE per packet, and the peer and
 * public-key lookups were repeated for every packet of a request. This pins
 * the once-per-request shape by counting statements through CountingPdo.
 */

$root = dirname(__DIR__);
require_once $root . '/src/lib/database.php';
require_once $root . '/src/index.php';

$dir = sys_get_temp_dir() . '/reticulum-php-budget-test-' . bin2hex(random_bytes(4));
mkdir($dir, 0775, true);
putenv('RETICULUM_PHP_QUERY_LOG=' . $dir . '/queries.jsonl');
$config = ['storage' => ['backend' => 'sqlite', 'sqlite_path' => $dir . '/node.sqlite', 'log_path' => $dir . '/router.log']];

$storage = new ReticulumPhp\Storage($config);
$storage->migrateIfNeeded();
$pdo = new PDO('sqlite:' . $config['storage']['sqlite_path']);
$pdo->exec("INSERT INTO interfaces (interface_id, name, session_token, bitrate, mtu, status, metadata_json, created_at, last_seen_at)
            VALUES ('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 'browser', 'tok', 1000000, 500, 'online', '{}', 1, " . time() . ")");

$call = static function (object $obj, string $method, ...$args) {
    $m = new ReflectionMethod($obj, $method);
    $m->setAccessible(true);
    return $m->invoke($obj, ...$args);
};
$count = static function (string $prefixRegex): int {
    $n = 0;
    foreach (ReticulumPhp\CountingPdo::$counts as $sql => $c) {
        if (preg_match($prefixRegex, $sql)) {
            $n += $c;
        }
    }
    return $n;
};
$reset = static function (): void {
    ReticulumPhp\CountingPdo::$counts = [];
    ReticulumPhp\CountingPdo::$total = 0;
};
$failures = 0;
$check = static function (bool $ok, string $what) use (&$failures): void {
    echo ($ok ? 'ok   ' : 'FAIL ') . $what . "\n";
    if (!$ok) {
        $failures++;
    }
};

// A minimal DATA packet: HEADER_1, hops 0, 16-byte destination, 1 byte payload.
$rawPacket = "\x00\x00" . str_repeat("\x11", 16) . "\x00" . "x";
$packetBase64 = base64_encode($rawPacket);
$iface = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';

// Queue five packets for one interface in one request.
$reset();
for ($i = 0; $i < 5; $i++) {
    $call($storage, 'queueOutboundPacket', $iface, $packetBase64, 'relay_data', null);
}
$inserts = $count('/^INSERT INTO outbound_packets/i');
$capChecks = $count('/^SELECT packet_id FROM outbound_packets/i');
$pendingCounts = $count('/^SELECT COUNT\(\*\) AS pending FROM outbound_packets/i');
$wakeChecks = $count('/^SELECT 1 FROM wake_events/i');
$keyLookups = $count('/^SELECT public_key_hex FROM known_destinations/i');
$metadataLookups = $count('/^SELECT metadata_json FROM interfaces/i');
$check($inserts === 5, "five packets inserted ($inserts)");
$check($capChecks === 1, "queue cap checked once per interface per request ($capChecks)");
$check($pendingCounts <= 1, "pending count once per interface per request ($pendingCounts)");
$check($wakeChecks <= 1, "pending-wake lookup once per interface per request ($wakeChecks)");
$check($keyLookups === 1, "public key looked up once per destination per request ($keyLookups)");
$check($metadataLookups === 1, "interface metadata looked up once per request ($metadataLookups)");
$perPacket = (ReticulumPhp\CountingPdo::$total - 4) / 5.0; // minus the one-off lookups above
$check($perPacket <= 2.0, sprintf('at most two statements per additional packet (%.1f)', $perPacket));

// Handing those packets to the interface assigns the whole batch in one UPDATE.
$reset();
$batch = $storage->fetchOutboundBatch($iface, 64);
$assigns = $count('/^UPDATE outbound_packets\s+SET delivered_batch_id/i');
$check(count($batch['packets']) === 5, 'batch carries the five packets (' . count($batch['packets']) . ')');
$check($assigns === 1, "batch assignment is one UPDATE, not one per packet ($assigns)");

// Peer check is memoised within a request.
$reset();
$storage->isPhpPeerInterface($iface);
$storage->isPhpPeerInterface($iface);
$check($count('/^SELECT 1 FROM interfaces WHERE interface_id = :id AND peer_url/i') === 1, 'peer check queried once per interface per request');

array_map('unlink', glob($dir . '/*') ?: []);
rmdir($dir);
exit($failures === 0 ? 0 : 1);
