<?php
/**
 * /health is public, so it publishes an explicit allowlist and nothing else.
 *
 * Until 2026-09-30 recentInterfacesByStatus() decoded each interface's
 * metadata_json verbatim into /health. For a PHP peer that metadata is the
 * registration body, whose peer_interface_id and peer_session_token are the
 * credentials exchangeWithPhpPeer() presents to the other node's
 * /v1/interfaces/exchange; for a web client it carries identity_hash, the key
 * registerInterface() re-binds a browser's row by. Both production nodes
 * served a 64-character peer_session_token that way (checked 2026-09-29, key
 * presence only). /v1/monitor/data had the same leak through the
 * peer_session_token column.
 *
 * The rows below are written by the real registerInterface() and
 * upsertConfiguredInterface(), as the three kinds of client write them, plus
 * a metadata key nobody has invented yet: an allowlist must drop it too,
 * where a denylist would publish it.
 *
 * It also pins what the consumers read, so a later trim cannot break them:
 *   test-harnesses/staging/staging.sh status, e2e-local/start.sh,
 *   OPNS-RNS-Post-Bridge/rnsd-redeploy.sh + RNSD_REDEPLOY.md, and the
 *   storage budget notes (queues.storage_*).
 *
 * Run: php tests/health_allowlist_test.php
 */
declare(strict_types=1);

$root = dirname(__DIR__);
require_once $root . '/src/lib/database.php';
require_once $root . '/src/index.php';

use ReticulumPhp\HttpApi;
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

function call(object $obj, string $method, mixed ...$args): mixed
{
    return (new ReflectionMethod($obj, $method))->invoke($obj, ...$args);
}

$config = [
    'storage' => ['backend' => 'sqlite', 'sqlite_path' => ':memory:'],
    'http' => ['max_batch_packets' => 64, 'max_packet_bytes' => 512, 'idle_exchange_interval_ms' => 1000],
];
$storage = new Storage($config);
$storage->migrateIfNeeded();
$db = (new ReflectionProperty($storage, 'db'))->getValue($storage);

$hex = static fn (int $bytes): string => bin2hex(random_bytes($bytes));
$secrets = [];

// A web client (Retichat-js post_interface.js _register).
$webIdentity = $hex(16);
$web = $storage->registerInterface('Retichat Web', 1000000, 500, [
    'client' => 'rns-js', 'implementation' => 'PostInterface', 'mode' => 1, 'identity_hash' => $webIdentity,
]);
$secrets['web identity_hash'] = $webIdentity;
$secrets['web session_token'] = $web['session_token'];

// A PHP peer registering here (connectToPeer on the other node): its
// metadata carries the credentials for ITS exchange endpoint.
$peerIfaceId = $hex(16);
$peerToken = $hex(32);
$peer = $storage->registerInterface('selectivesubconscious.com', 1000000, 500, [
    'client' => 'reticulum-php', 'peer_url' => 'https://peer.example/reticulum',
    'peer_interface_id' => $peerIfaceId, 'peer_session_token' => $peerToken,
]);
$secrets['peer peer_interface_id'] = $peerIfaceId;
$secrets['peer peer_session_token'] = $peerToken;
$secrets['peer session_token'] = $peer['session_token'];

// The gateway bridge in wake mode (Reticulum-rust post_interface.rs
// register_with_remote), with a metadata key from the future.
$gwIfaceId = $hex(16);
$gwToken = $hex(32);
$gateway = $storage->registerInterface('RNS PostInterface (PostInterface Bridge)', 1000000, 500, [
    'client' => 'reticulum-php', 'implementation' => 'PostInterface', 'mode' => 6, 'transport' => null,
    'peer_url' => 'http://gateway.example:4371', 'peer_interface_id' => $gwIfaceId, 'peer_session_token' => $gwToken,
    'wake_url' => null, 'future_secret' => 'FUTURE-' . $hex(8),
]);
$secrets['gateway peer_interface_id'] = $gwIfaceId;
$secrets['gateway peer_session_token'] = $gwToken;
$secrets['gateway session_token'] = $gateway['session_token'];
$secrets['unlisted metadata key'] = 'FUTURE-';
$db->prepare("UPDATE interfaces SET status = 'offline' WHERE interface_id = :i")->execute([':i' => $gateway['interface_id']]);

// A peer this node configured and registered with (connectToPeer's own
// row): the peer_session_token column holds the other node's credential.
$configuredId = $hex(16);
$configuredToken = $hex(32);
$remoteId = $hex(16);
$remoteToken = $hex(32);
$storage->upsertConfiguredInterface($configuredId, 'retichat.com', $configuredToken, 1000000, 500,
    ['client' => 'reticulum-php', 'peer_url' => 'https://other.example/reticulum'],
    'https://other.example/reticulum', $remoteId, $remoteToken);
$secrets['configured session_token'] = $configuredToken;
$secrets['configured peer_interface_id'] = $remoteId;
$secrets['configured peer_session_token'] = $remoteToken;

$api = new HttpApi($config, $storage);
$body = call($api, 'healthBody');
$json = json_encode($body, JSON_THROW_ON_ERROR);
$decoded = json_decode($json, true, flags: JSON_THROW_ON_ERROR);

// ── (a) nothing secret reaches /health ─────────────────────────────────
echo "(a) /health carries no credential, identity hash or unlisted key\n";
foreach ($secrets as $what => $value) {
    check("/health omits the $what", !str_contains($json, $value));
}
check('/health omits peer URLs', !str_contains($json, 'peer.example') && !str_contains($json, 'gateway.example') && !str_contains($json, 'other.example'));

// ── (b) the rows are exactly the allowlist ─────────────────────────────
echo "(b) interface rows are the allowlist, not a filtered copy\n";
$rowKeys = ['interface_id', 'name', 'bitrate', 'mtu', 'status', 'created_at', 'last_seen_at',
            'rx_packets', 'rx_bytes', 'tx_packets', 'tx_bytes', 'metadata'];
$metadataKeys = ['client', 'implementation', 'mode', 'transport'];
$registry = $decoded['php_interface_registry'] ?? [];
$rows = array_merge($registry['recent_online'] ?? [], $registry['recent_offline'] ?? []);
check('four interface rows listed', count($rows) === 4, (string) count($rows));
foreach ($rows as $row) {
    $keys = array_keys($row);
    sort($keys);
    $want = $rowKeys;
    sort($want);
    check("row '{$row['name']}' has exactly the allowed keys", $keys === $want, implode(',', $keys));
    $extra = array_diff(array_keys($row['metadata'] ?? []), $metadataKeys);
    check("row '{$row['name']}' metadata has only allowed keys", $extra === [], implode(',', $extra));
}
$topKeys = array_keys($decoded);
sort($topKeys);
check('top level is status, transport_basis, environment, queues, php_interface_registry',
    $topKeys === ['environment', 'php_interface_registry', 'queues', 'status', 'transport_basis'], implode(',', $topKeys));

// ── (c) what the consumers read is still there ─────────────────────────
echo "(c) every field a consumer reads is still published\n";
$q = $decoded['queues'] ?? [];
foreach (['storage_bytes', 'storage_database_bytes', 'storage_database_free_bytes', 'storage_log_bytes',
          'storage_budget_bytes', 'interfaces', 'interfaces_online', 'validated_announces', 'known_destinations'] as $k) {
    check("queues.$k", array_key_exists($k, $q));
}
check('php_interface_registry.summary total/online/offline',
    isset($registry['summary']['total'], $registry['summary']['online'], $registry['summary']['offline'])
    && $registry['summary']['total'] === 4 && $registry['summary']['offline'] === 1);
$byName = [];
foreach ($rows as $row) {
    $byName[$row['name']] = $row;
}
$webRow = $byName['Retichat Web'] ?? [];
check('web row: interface_id, rx/tx, last_seen_at',
    ($webRow['interface_id'] ?? null) === $web['interface_id'] && isset($webRow['rx_packets'], $webRow['tx_packets'], $webRow['last_seen_at']));
check('web row: metadata.client and metadata.mode', ($webRow['metadata']['client'] ?? null) === 'rns-js' && ($webRow['metadata']['mode'] ?? null) === 1);
$gwRow = $byName['RNS PostInterface (PostInterface Bridge)'] ?? [];
check('bridge row: metadata.mode 6 and client (memory: gateway-transport-was-never-enabled)',
    ($gwRow['metadata']['mode'] ?? null) === 6 && ($gwRow['metadata']['client'] ?? null) === 'reticulum-php');
check('bridge row is listed under recent_offline', in_array('RNS PostInterface (PostInterface Bridge)', array_column($registry['recent_offline'] ?? [], 'name'), true));
check('metadata is a JSON object on every row (staging.sh calls .get on it)',
    !str_contains($json, '"metadata":[]'));

// ── (d) the monitor has the same leak, same fix ─────────────────────────
echo "(d) /v1/monitor/data carries no credential either\n";
$monitorJson = json_encode($storage->monitorData(), JSON_THROW_ON_ERROR);
foreach ($secrets as $what => $value) {
    check("monitor omits the $what", !str_contains($monitorJson, $value));
}
$monitorRows = $storage->monitorData()['interfaces'];
$peerUrls = array_values(array_filter(array_column($monitorRows, 'peer_url')));
sort($peerUrls);
check('monitor still shows each PHP peer\'s peer_url (the page labels peers by it)',
    $peerUrls === ['http://gateway.example:4371', 'https://other.example/reticulum', 'https://peer.example/reticulum'], implode(',', $peerUrls));
$first = $monitorRows[0] ?? [];
check('monitor rows keep name, status, rx/tx, last_seen_at, interface_id',
    isset($first['name'], $first['status'], $first['rx_packets'], $first['tx_packets'], $first['last_seen_at'], $first['interface_id']));

echo "\n$pass passed, $fail failed\n";
exit($fail === 0 ? 0 : 1);
