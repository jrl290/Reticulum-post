<?php
/**
 * The [interfaces] peering, configured as both live nodes configure it, still
 * peers, wakes and exchanges.
 *
 * On 2026-10-04 the wake_url path (wake_events, wake runners, the wake-event
 * CLI mode, the three wake providers) and the PostInterface client of
 * [post_interface_peers] were removed. Neither is the live peering, but all
 * three share words: an [interfaces] entry has type = PostInterface and a
 * wake_url key, and the live configs still carry `[wake] dispatch_limit = 4`.
 * The live peering is RequestPhpWakeTrait: GET /v1/initialize (and
 * maintenance) registers at node_url with peer_url and credentials, never a
 * wake_url; the exchange epilogue wakes the peer at the peer_url its row
 * stores (dispatchWakes, fire-and-forget); the woken node pulls with an
 * inline exchange (POST /v1/wake -> exchangeWithPhpPeer).
 *
 * Two nodes under `php -S`, each a copy of php/src with its own SQLite and a
 * config.toml laid out like the live one (2026-10-04): its [wake] block, its
 * [maintenance] values, its second [storage] section for log_path, and one
 * [interfaces] entry naming the other node, with type, enabled, node_url,
 * wake_url, bitrate and mtu. Then, in each direction: a browser on one node
 * asks for a path; the node forwards the path request to its peer, wakes it,
 * and the peer pulls the packet in. No wake_events table appears, no row
 * stores a wake_url, and neither node logs a refused or dropped wake.
 *
 * Run: php php/tests/live_interfaces_peering_test.php
 */
declare(strict_types=1);

$src = dirname(__DIR__) . '/src';

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

function copyTree(string $from, string $to): void
{
    mkdir($to, 0775, true);
    foreach (scandir($from) ?: [] as $entry) {
        if ($entry === '.' || $entry === '..' || str_starts_with($entry, 'config.') || $entry === 'build.json') {
            continue;
        }
        $path = $from . '/' . $entry;
        is_dir($path) ? copyTree($path, $to . '/' . $entry) : copy($path, $to . '/' . $entry);
    }
}

/** A port the OS just handed out, never one of the ports this workspace keeps for itself. */
function freePort(): int
{
    $reserved = [8080, 8897, 8898, 8899, 4371];
    do {
        $server = stream_socket_server('tcp://127.0.0.1:0', $errno, $errstr);
        $name = (string) stream_socket_get_name($server, false);
        fclose($server);
        $port = (int) substr($name, strrpos($name, ':') + 1);
    } while (in_array($port, $reserved, true));
    return $port;
}

/** @return array{int, array} status and decoded body */
function http(string $method, string $url, ?array $body = null): array
{
    $context = stream_context_create(['http' => [
        'method' => $method,
        'header' => "Content-Type: application/json\r\n",
        'content' => $body === null ? '' : json_encode($body),
        'ignore_errors' => true,
        'timeout' => 5,
    ]]);
    $response = @file_get_contents($url, false, $context);
    $status = 0;
    foreach ($http_response_header ?? [] as $line) {
        if (preg_match('#^HTTP/\S+ (\d{3})#', $line, $m) === 1) {
            $status = (int) $m[1];
        }
    }
    $decoded = is_string($response) ? json_decode($response, true) : null;
    return [$status, is_array($decoded) ? $decoded : []];
}

/** config.toml as the live nodes lay it out, for this node and its one peer. */
function liveConfig(string $dir, string $hostUrl, string $peerName, string $peerUrl): string
{
    return <<<TOML
host_url = "{$hostUrl}"

[wake]
dispatch_limit = 4

[storage]
backend = "sqlite"
sqlite_path = "{$dir}/node.sqlite"

[http]
idle_exchange_interval_ms = 1000
max_batch_packets = 64
max_packet_bytes = 512

[maintenance]
interface_stale_after_seconds = 300
batch_ttl_seconds = 86400
packet_hash_ttl_seconds = 30
path_request_tag_ttl_seconds = 30
reverse_path_ttl_seconds = 480
link_transport_ttl_seconds = 900

[transport]
rns_mtu = 500
pathfinder_max_hops = 128
path_expiry_default_seconds = 604800
path_expiry_access_point_seconds = 86400
path_expiry_roaming_seconds = 21600
max_random_blobs = 64



[storage]
log_path = "{$dir}/router.log"

[interfaces]

[[{$peerName}]]
type = PostInterface
enabled = yes
node_url = "{$peerUrl}"
wake_url = "{$hostUrl}/v1/wake"
bitrate = 62500
mtu = 500

TOML;
}

/** @return array{base: string, dir: string, proc: resource} */
function startNode(string $src, int $port, string $peerName, int $peerPort): array
{
    $dir = sys_get_temp_dir() . '/reticulum-live-peering-' . bin2hex(random_bytes(4));
    copyTree($src, $dir . '/src');
    $base = 'http://127.0.0.1:' . $port;
    file_put_contents($dir . '/src/config.toml', liveConfig($dir, $base, $peerName, 'http://127.0.0.1:' . $peerPort));
    $proc = proc_open(
        [PHP_BINARY, '-S', '127.0.0.1:' . $port, '-t', $dir . '/src', $dir . '/src/index.php'],
        [0 => ['file', '/dev/null', 'r'], 1 => ['file', $dir . '/server.out', 'w'], 2 => ['file', $dir . '/server.out', 'a']],
        $pipes
    );
    // Readiness is the server answering; the bound only turns a server that
    // never starts into a test failure instead of a hang.
    for ($i = 0; $i < 50 && http('GET', $base . '/health')[0] !== 200; $i++) {
        usleep(100000);
    }
    return ['base' => $base, 'dir' => $dir, 'proc' => $proc];
}

function stopNode(array $node): void
{
    proc_terminate($node['proc']);
    proc_close($node['proc']);
    exec('rm -rf ' . escapeshellarg($node['dir']));
}

function db(array $node): PDO
{
    $pdo = new PDO('sqlite:' . $node['dir'] . '/node.sqlite');
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    return $pdo;
}

/** The node's interface row for its peer. */
function peerRow(array $node, string $peerUrl): ?array
{
    $stmt = db($node)->prepare(
        'SELECT interface_id, session_token, peer_interface_id, peer_session_token, metadata_json FROM interfaces WHERE peer_url = :u'
    );
    $stmt->execute([':u' => $peerUrl]);
    $rows = $stmt->fetchAll(PDO::FETCH_ASSOC);
    return count($rows) === 1 ? $rows[0] : null;
}

/** Packets the node has taken in from an interface, by destination. */
function receivedFrom(array $node, string $interfaceId, string $destinationHex): int
{
    $stmt = db($node)->prepare(
        'SELECT COUNT(*) FROM inbound_packets WHERE interface_id = :i AND destination_hash_hex = :d'
    );
    $stmt->execute([':i' => $interfaceId, ':d' => $destinationHex]);
    return (int) $stmt->fetchColumn();
}

const PATH_REQUEST_CONTROL = '6b9f66014d9853faab220fba47d02761'; // rnstransport.path.request

/** A browser on $node asks for a path to a destination nobody knows. */
function browserAsksForAPath(array $node): array
{
    [$status, $reg] = http('POST', $node['base'] . '/v1/interfaces/register', [
        'name' => 'Retichat Web', 'bitrate' => 1000000, 'mtu' => 500,
        'metadata' => ['client' => 'rns-js', 'implementation' => 'PostInterface', 'mode' => 1, 'identity_hash' => bin2hex(random_bytes(16))],
    ]);
    $packet = chr(0x08) . chr(0x00) . hex2bin(PATH_REQUEST_CONTROL) . chr(0x00) . random_bytes(16) . random_bytes(16);
    [$exStatus, $ex] = http('POST', $node['base'] . '/v1/interfaces/exchange', [
        'interface_id' => $reg['interface_id'] ?? '', 'session_token' => $reg['session_token'] ?? '',
        'batch_id' => 'browser-' . bin2hex(random_bytes(4)), 'packets' => [base64_encode($packet)], 'max_packets' => 8,
    ]);
    return [$status === 200 && $exStatus === 200 && ($ex['accepted_packets'] ?? 0) === 1, $ex];
}

$portA = freePort();
$portB = freePort();
// A plays retichat.com (its entry names the other node "Selective
// Subconscious"), B plays selectivesubconscious.com.
$b = startNode($src, $portB, 'Retichat', $portA);
$a = startNode($src, $portA, 'Selective Subconscious', $portB);

echo "(a) the live config loads and peers\n";
foreach (['A' => $a, 'B' => $b] as $label => $node) {
    [$status, $health] = http('GET', $node['base'] . '/health');
    check("$label serves /health with the live config ([wake] block included)", $status === 200 && ($health['status'] ?? null) === 'ok', (string) $status);
    $wakeKeys = array_values(array_filter(array_keys($health['queues'] ?? []), static fn (string $k): bool => str_starts_with($k, 'wake_events')));
    check("$label's /health counts no wake events", $wakeKeys === [], implode(',', $wakeKeys));
}
[$status, $init] = http('GET', $a['base'] . '/v1/initialize');
check('A registers at B on /v1/initialize', $status === 200 && ($init['peers'][0]['status'] ?? null) === 'connected', (string) json_encode($init));
[$status, $init] = http('GET', $b['base'] . '/v1/initialize');
check('B, whose entry names A, finds the session A made and does not register again',
    $status === 200 && ($init['peers'][0]['status'] ?? null) === 'already_connected', (string) json_encode($init));
$rowA = peerRow($a, $b['base']);
$rowB = peerRow($b, $a['base']);
check('each node holds one row for the other', $rowA !== null && $rowB !== null);
check('the rows hold each other\'s credentials',
    ($rowA['peer_interface_id'] ?? null) === ($rowB['interface_id'] ?? '-') && ($rowA['peer_session_token'] ?? null) === ($rowB['session_token'] ?? '-')
    && ($rowB['peer_interface_id'] ?? null) === ($rowA['interface_id'] ?? '-') && ($rowB['peer_session_token'] ?? null) === ($rowA['session_token'] ?? '-'));
check('neither row stores a wake_url',
    !str_contains((string) ($rowA['metadata_json'] ?? ''), 'wake_url') && !str_contains((string) ($rowB['metadata_json'] ?? ''), 'wake_url'),
    ($rowA['metadata_json'] ?? '') . ' / ' . ($rowB['metadata_json'] ?? ''));

foreach ([['A', $a, 'B', $b, $rowB], ['B', $b, 'A', $a, $rowA]] as [$from, $sender, $to, $receiver, $receiverRowForSender]) {
    echo "(b) $from wakes $to, and $to pulls what $from queued for it\n";
    [$ok, $ex] = browserAsksForAPath($sender);
    check("a browser on $from sends a path request", $ok, (string) json_encode($ex));
    // The wake left $from before its answer to the browser did; $to then
    // calls $from's exchange. Bounded only so a lost wake fails the test
    // instead of hanging it (DESIGN_PRINCIPLES.md §1: well inside 5 s).
    $deadline = microtime(true) + 5.0;
    $got = 0;
    while (microtime(true) < $deadline && ($got = receivedFrom($receiver, (string) ($receiverRowForSender['interface_id'] ?? ''), PATH_REQUEST_CONTROL)) === 0) {
        usleep(50000);
    }
    check("$to took the forwarded path request in from $from, within 5 s of the browser's exchange", $got >= 1, (string) $got);
    $senderRowForReceiver = peerRow($sender, $receiver['base']);
    $stmt = db($sender)->prepare('SELECT COUNT(*) FROM outbound_packets WHERE interface_id = :i AND delivered_batch_id IS NOT NULL');
    $stmt->execute([':i' => (string) ($senderRowForReceiver['interface_id'] ?? '')]);
    check("$from handed the packet to $to in an exchange", (int) $stmt->fetchColumn() >= 1);
}

echo "(c) nothing of the removed paths\n";
foreach (['A' => $a, 'B' => $b] as $label => $node) {
    $pdo = db($node);
    $tables = $pdo->query("SELECT name FROM sqlite_master WHERE type = 'table' AND name IN ('wake_events', 'post_interface_peers')")->fetchAll(PDO::FETCH_COLUMN);
    check("$label has no wake_events or post_interface_peers table", $tables === [], implode(',', $tables));
    $withWakeUrl = (int) $pdo->query("SELECT COUNT(*) FROM interfaces WHERE metadata_json LIKE '%wake_url%'")->fetchColumn();
    check("no interface row on $label stores a wake_url", $withWakeUrl === 0, (string) $withWakeUrl);
    $log = (string) @file_get_contents($node['dir'] . '/server.out') . (string) @file_get_contents($node['dir'] . '/router.log');
    foreach (['[WAKE-REFUSED]', '[WAKE-DROP]', '[REG-WAKE-URL-IGNORED]', 'Unhandled HTTP exception', 'PHP Fatal', 'PHP Warning'] as $marker) {
        check("$label logged no $marker", !str_contains($log, $marker));
    }
}

stopNode($a);
stopNode($b);

echo "\n$pass passed, $fail failed\n";
exit($fail === 0 ? 0 : 1);
