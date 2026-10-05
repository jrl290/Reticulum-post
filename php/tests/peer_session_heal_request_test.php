<?php
/**
 * A request whose prelude re-registers a dead peering session answers 200,
 * and the repair is logged.
 *
 * WHAT THIS EXISTS TO PREVENT
 * ===========================
 * Maintenance Phase 12 (ensureConfiguredPeerSessions, RequestPhpWakeTrait)
 * re-registers an [interfaces] peer whose session has died, on whatever
 * request runs the prelude next. On b6c7809, live on both nodes, it then
 * called $this->log(). RequestPhpWakeTrait runs as Storage and log() is
 * HttpApi's, so that request died with "Call to undefined method
 * ReticulumPhp\Storage::log()" and answered 500 (a browser's exchange or the
 * peer's wake, whichever came first), and no [interfaces] entry after that
 * one was checked. The repair itself had already been made, so the 500 and
 * router.log's "Unhandled HTTP exception" were all that showed; the
 * "[peer] session to ... was dead" line was never written.
 * static_check_methods.php printed "Undefined: 0" over it.
 *
 * Two nodes under `php -S`, each a copy of php/src with its own SQLite and
 * the config.toml layout of the live nodes (as in
 * live_interfaces_peering_test.php: one [interfaces] entry naming the other
 * node), peer on GET /v1/initialize. Then A's session to B dies twice:
 *
 *   (a) the 2026-08-17 shape: A's row for B offline for two hours, and B
 *       holding no row for A, so B refuses A's credentials. A browser's
 *       exchange on A runs A's prelude.
 *   (b) A holds no row for B, while B still holds its row for A. B's wake
 *       runs A's prelude (POST /v1/wake, sent here as B's dispatchWakes
 *       sends it, so that its answer can be read).
 *
 * Each time the request answers 200 (the wake with its exchange done), A
 * holds one new, online row for B, B holds A's new credentials, A logs
 * "[peer] session to <B> was dead (<shape>) — re-registered: connected",
 * and neither node logs an unhandled exception or a PHP error. Then (c)
 * packets cross the repaired session both ways.
 *
 * Nothing waits for a clock to pass. The peer check's throttle
 * (transport_state peer_session_checked_at) and the prelude's 2-second gate
 * (the mtime of its lock file) are set due before each request.
 *
 * Run: php php/tests/peer_session_heal_request_test.php
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
    $dir = sys_get_temp_dir() . '/reticulum-peer-heal-' . bin2hex(random_bytes(4));
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
    @unlink(preludeLockFile($node['base']));
    exec('rm -rf ' . escapeshellarg($node['dir']));
}

function db(array $node): PDO
{
    $pdo = new PDO('sqlite:' . $node['dir'] . '/node.sqlite');
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    return $pdo;
}

/** The node's interface rows for a peer. */
function peerRows(array $node, string $peerUrl): array
{
    $stmt = db($node)->prepare(
        'SELECT interface_id, session_token, peer_interface_id, peer_session_token, status, last_seen_at FROM interfaces WHERE peer_url = :u'
    );
    $stmt->execute([':u' => $peerUrl]);
    return $stmt->fetchAll(PDO::FETCH_ASSOC);
}

/**
 * The file runInterfaceRequestPrelude() reads its 2-second gate from
 * (RequestHttpApiHelperTrait::maintenanceLockFilePath).
 */
function preludeLockFile(string $hostUrl): string
{
    return sys_get_temp_dir() . '/reticulum-php-maintenance-' . substr(hash('sha256', $hostUrl), 0, 16) . '.lock';
}

/** Make the node's next prelude run maintenance, and its Phase 12 check its peers. */
function peerCheckDue(array $node): void
{
    db($node)->prepare('DELETE FROM transport_state WHERE state_key = :k')->execute([':k' => 'peer_session_checked_at']);
    touch(preludeLockFile($node['base']), time() - 60);
}

/** @return array{int, int} the sizes of the node's two logs */
function logMark(array $node): array
{
    clearstatcache();
    return [(int) @filesize($node['dir'] . '/server.out'), (int) @filesize($node['dir'] . '/router.log')];
}

/** What the node has logged since $mark: php -S's stderr (error_log) and router.log (HttpApi::log). */
function loggedSince(array $node, array $mark): string
{
    return (string) @file_get_contents($node['dir'] . '/server.out', false, null, $mark[0])
        . (string) @file_get_contents($node['dir'] . '/router.log', false, null, $mark[1]);
}

function checkNothingWentWrong(string $label, string $log): void
{
    foreach (['Unhandled HTTP exception', 'Call to undefined method', 'PHP Fatal', 'PHP Warning'] as $marker) {
        check("$label logged no \"$marker\"", !str_contains($log, $marker), $log);
    }
}

/** A's one row for B is new and online, and each node holds the other's credentials. */
function checkRepaired(array $a, array $b, string $deadRowId): void
{
    $rowsA = peerRows($a, $b['base']);
    $rowsB = peerRows($b, $a['base']);
    $rowA = $rowsA[0] ?? [];
    $rowB = $rowsB[0] ?? [];
    check('A holds one row for B, a new one, online',
        count($rowsA) === 1 && ($rowA['interface_id'] ?? $deadRowId) !== $deadRowId && ($rowA['status'] ?? null) === 'online',
        (string) json_encode($rowsA));
    check('B holds one row for A', count($rowsB) === 1, (string) json_encode($rowsB));
    check('each holds the other\'s new credentials',
        ($rowA['peer_interface_id'] ?? null) === ($rowB['interface_id'] ?? '-') && ($rowA['peer_session_token'] ?? null) === ($rowB['session_token'] ?? '-')
        && ($rowB['peer_interface_id'] ?? null) === ($rowA['interface_id'] ?? '-') && ($rowB['peer_session_token'] ?? null) === ($rowA['session_token'] ?? '-'));
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

/** @return array{int, array} a browser's registration on the node, then its exchange */
function browserExchange(array $node, array $packets): array
{
    [$status, $reg] = http('POST', $node['base'] . '/v1/interfaces/register', [
        'name' => 'Retichat Web', 'bitrate' => 1000000, 'mtu' => 500,
        'metadata' => ['client' => 'rns-js', 'implementation' => 'PostInterface', 'mode' => 1, 'identity_hash' => bin2hex(random_bytes(16))],
    ]);
    if ($status !== 200) {
        return [$status, $reg];
    }
    $body = ['interface_id' => $reg['interface_id'] ?? '', 'session_token' => $reg['session_token'] ?? '', 'packets' => $packets, 'max_packets' => 8];
    if ($packets !== []) {
        $body['batch_id'] = 'browser-' . bin2hex(random_bytes(4));
    }
    return http('POST', $node['base'] . '/v1/interfaces/exchange', $body);
}

$portA = freePort();
$portB = freePort();
// A plays retichat.com, B selectivesubconscious.com, as in
// live_interfaces_peering_test.php.
$b = startNode($src, $portB, 'Retichat', $portA);
$a = startNode($src, $portA, 'Selective Subconscious', $portB);

echo "the two nodes peer as the live ones do\n";
[$status, $init] = http('GET', $a['base'] . '/v1/initialize');
check('A registers at B on /v1/initialize', $status === 200 && ($init['peers'][0]['status'] ?? null) === 'connected', (string) json_encode($init));
[$status, $init] = http('GET', $b['base'] . '/v1/initialize');
check('B finds the session A made', $status === 200 && ($init['peers'][0]['status'] ?? null) === 'already_connected', (string) json_encode($init));

echo "(a) A's row for B offline for two hours, B holding no row for A; a browser's exchange on A\n";
$markA = logMark($a);
$markB = logMark($b);
$dead = peerRows($a, $b['base'])[0] ?? [];
db($a)->prepare("UPDATE interfaces SET status = 'offline', last_seen_at = :t WHERE peer_url = :u")
    ->execute([':t' => time() - 7200, ':u' => $b['base']]);
db($b)->prepare('DELETE FROM interfaces WHERE peer_url = :u')->execute([':u' => $a['base']]);
[$status] = http('POST', $b['base'] . '/v1/interfaces/exchange', [
    'interface_id' => $dead['peer_interface_id'] ?? '', 'session_token' => $dead['peer_session_token'] ?? '', 'packets' => [],
]);
check('the session is dead: B refuses A\'s credentials', $status === 401, (string) $status);
peerCheckDue($a);

[$status, $exchange] = browserExchange($a, []);
check('the browser\'s exchange, which ran the repair, answers 200', $status === 200 && ($exchange['status'] ?? null) === 'accepted', $status . ' ' . json_encode($exchange));
checkRepaired($a, $b, (string) ($dead['interface_id'] ?? ''));
$logA = loggedSince($a, $markA);
check('A logs "[peer] session to <B> was dead (row offline) — re-registered: connected"',
    str_contains($logA, "[peer] session to {$b['base']} was dead (row offline) — re-registered: connected"), $logA);
checkNothingWentWrong('A', $logA);
checkNothingWentWrong('B', loggedSince($b, $markB));

echo "(b) A holding no row for B, B still holding its row for A; B's wake to A\n";
$markA = logMark($a);
$markB = logMark($b);
$dead = peerRows($a, $b['base'])[0] ?? [];
$bRowForA = peerRows($b, $a['base'])[0] ?? [];
db($a)->prepare('DELETE FROM interfaces WHERE peer_url = :u')->execute([':u' => $b['base']]);
peerCheckDue($a);

[$status, $wake] = http('POST', $a['base'] . '/v1/wake', ['waker_url' => $b['base']]);
check('B\'s wake, which ran the repair, answers 200, and A pulled from B over the new session',
    $status === 200 && ($wake['exchange']['status'] ?? null) === 'ok', $status . ' ' . json_encode($wake));
checkRepaired($a, $b, (string) ($dead['interface_id'] ?? ''));
check('B kept its row for A and took A\'s new credentials on it',
    (peerRows($b, $a['base'])[0]['interface_id'] ?? null) === ($bRowForA['interface_id'] ?? '-'));
$logA = loggedSince($a, $markA);
check('A logs "[peer] session to <B> was dead (no row) — re-registered: connected"',
    str_contains($logA, "[peer] session to {$b['base']} was dead (no row) — re-registered: connected"), $logA);
checkNothingWentWrong('A', $logA);
checkNothingWentWrong('B', loggedSince($b, $markB));

echo "(c) packets cross the repaired session both ways\n";
foreach ([['A', $a, 'B', $b], ['B', $b, 'A', $a]] as [$from, $sender, $to, $receiver]) {
    $rowForSender = (string) (peerRows($receiver, $sender['base'])[0]['interface_id'] ?? '');
    $before = receivedFrom($receiver, $rowForSender, PATH_REQUEST_CONTROL);
    $packet = chr(0x08) . chr(0x00) . hex2bin(PATH_REQUEST_CONTROL) . chr(0x00) . random_bytes(16) . random_bytes(16);
    [$status, $exchange] = browserExchange($sender, [base64_encode($packet)]);
    check("a browser on $from sends a path request", $status === 200 && ($exchange['accepted_packets'] ?? 0) === 1, $status . ' ' . json_encode($exchange));
    // The wake left $from before its answer to the browser did; $to then
    // calls $from's exchange. Bounded only so a lost wake fails the test
    // instead of hanging it (DESIGN_PRINCIPLES.md §1: well inside 5 s).
    $deadline = microtime(true) + 5.0;
    $got = $before;
    while (microtime(true) < $deadline && ($got = receivedFrom($receiver, $rowForSender, PATH_REQUEST_CONTROL)) === $before) {
        usleep(50000);
    }
    check("$to took the forwarded path request in from $from, within 5 s", $got > $before, "$before -> $got");
}

stopNode($a);
stopNode($b);

echo "\n$pass passed, $fail failed\n";
exit($fail === 0 ? 0 : 1);
