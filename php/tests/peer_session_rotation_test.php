<?php
/**
 * Rotating a PHP-to-PHP peering's credentials, as README "Rotating a PHP
 * peering's credentials" tells an operator to do it.
 *
 * Until 2026-09-30 /health and /v1/monitor published each peer row's
 * metadata and peer_session_token, so both halves of the retichat.com <->
 * selectiv peering's credentials were public. Rotating them means: on the
 * node whose config.toml has the [interfaces] block, DELETE its row for the
 * peer, then GET /v1/initialize there. connectToPeer() finds no row, makes a
 * new interface id and token, and registers at the peer, whose
 * registerInterface() re-binds its row in place with a new session token.
 *
 * The first draft of that procedure marked the row dead instead
 * (UPDATE ... status='offline', last_seen_at=0). Ordinary traffic undoes
 * that before the GET arrives: the peer's next exchange authenticates with
 * the leaked token and authenticateInterface() touches the row online again,
 * so connectToPeer() answers "already_connected" and rotates nothing. This
 * test puts exactly such an exchange between the two steps.
 *
 * Two real nodes, each a copy of php/src under `php -S` with its own SQLite:
 * A has an [interfaces] block for B, as an initiator does. Driven over HTTP;
 * the SQL step runs on A's database, as `node.sh sql-<node>` runs it.
 *
 * Run: php tests/peer_session_rotation_test.php
 */
declare(strict_types=1);

$src = dirname(__DIR__) . '/src';

/** The procedure's SQL step, exactly as README gives it. */
const ROTATE_SQL = 'DELETE FROM interfaces WHERE peer_url = :peer_url AND peer_interface_id IS NOT NULL';

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

function freePort(): int
{
    $server = stream_socket_server('tcp://127.0.0.1:0', $errno, $errstr);
    $name = (string) stream_socket_get_name($server, false);
    fclose($server);
    return (int) substr($name, strrpos($name, ':') + 1);
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

/** @return array{base: string, dir: string, proc: resource} */
function startNode(string $src, int $port, ?string $peerUrl): array
{
    $dir = sys_get_temp_dir() . '/reticulum-peer-rotation-' . bin2hex(random_bytes(4));
    copyTree($src, $dir . '/src');
    $lines = [
        'host_url = "http://127.0.0.1:' . $port . '"',
        '[storage]',
        'backend = "sqlite"',
        'sqlite_path = "' . $dir . '/node.sqlite"',
        'log_path = "' . $dir . '/router.log"',
    ];
    if ($peerUrl !== null) {
        array_push($lines, '[interfaces]', '[[Peer]]', 'node_url = "' . $peerUrl . '"');
    }
    file_put_contents($dir . '/src/config.toml', implode("\n", $lines) . "\n");
    $proc = proc_open(
        [PHP_BINARY, '-S', '127.0.0.1:' . $port, '-t', $dir . '/src', $dir . '/src/index.php'],
        [0 => ['file', '/dev/null', 'r'], 1 => ['file', $dir . '/server.out', 'w'], 2 => ['file', $dir . '/server.out', 'a']],
        $pipes
    );
    $base = 'http://127.0.0.1:' . $port;
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

/** @return list<array> the node's interface rows for a peer URL */
function peerRows(array $node, string $peerUrl): array
{
    $stmt = db($node)->prepare(
        'SELECT interface_id, session_token, peer_interface_id, peer_session_token, status FROM interfaces WHERE peer_url = :u'
    );
    $stmt->execute([':u' => $peerUrl]);
    return $stmt->fetchAll(PDO::FETCH_ASSOC);
}

/** An exchange as a peer (or anyone holding its credentials) makes it. */
function exchange(array $node, string $interfaceId, string $token): int
{
    return http('POST', $node['base'] . '/v1/interfaces/exchange', [
        'interface_id' => $interfaceId, 'session_token' => $token, 'packets' => [], 'max_packets' => 1,
    ])[0];
}

$portA = freePort();
$portB = freePort();
$b = startNode($src, $portB, null);
$a = startNode($src, $portA, $b['base']);

echo "(a) the peering, and what /health used to publish\n";
[$status, $init] = http('GET', $a['base'] . '/v1/initialize');
check('A registers at B on /v1/initialize', $status === 200 && ($init['peers'][0]['status'] ?? null) === 'connected', json_encode($init));
$rowA = peerRows($a, $b['base']);
$rowB = peerRows($b, $a['base']);
check('each node holds one row for the other', count($rowA) === 1 && count($rowB) === 1, count($rowA) . '/' . count($rowB));
$rowA = $rowA[0] ?? [];
$rowB = $rowB[0] ?? [];
// What leaked: B's row carries A's credential (B's /health published it as
// metadata.peer_session_token); A's row carries B's (A's monitor published
// the peer_session_token column).
$leakedAtA = [(string) ($rowB['peer_interface_id'] ?? ''), (string) ($rowB['peer_session_token'] ?? '')];
$leakedAtB = [(string) ($rowA['peer_interface_id'] ?? ''), (string) ($rowA['peer_session_token'] ?? '')];
check('the credential B holds for A is A\'s row id and token',
    $leakedAtA === [(string) ($rowA['interface_id'] ?? '-'), (string) ($rowA['session_token'] ?? '-')]);
check('the credential A holds for B is B\'s row id and token',
    $leakedAtB === [(string) ($rowB['interface_id'] ?? '-'), (string) ($rowB['session_token'] ?? '-')]);
check('A accepts an exchange with the credential B\'s /health leaked', exchange($a, ...$leakedAtA) === 200);
check('B accepts an exchange with the credential A\'s monitor leaked', exchange($b, ...$leakedAtB) === 200);

echo "(b) rotate: the SQL step on A, peer traffic, then GET /v1/initialize\n";
$stmt = db($a)->prepare(ROTATE_SQL);
$stmt->execute([':peer_url' => $b['base']]);
check('the SQL step touches exactly one row', $stmt->rowCount() === 1, (string) $stmt->rowCount());
// Between the operator's two commands the peering keeps running: B's next
// exchange arrives with the credential it holds, which is the leaked one.
check('B\'s next exchange with the old credential is refused at once (401)', exchange($a, ...$leakedAtA) === 401);
[$status, $init] = http('GET', $a['base'] . '/v1/initialize');
$newId = (string) ($init['peers'][0]['interface_id'] ?? '');
check('/v1/initialize re-registers: connected, under a new interface id',
    $status === 200 && ($init['peers'][0]['status'] ?? null) === 'connected' && $newId !== '' && $newId !== $leakedAtA[0], json_encode($init));

echo "(c) the leaked credentials are dead, the new ones work\n";
check('A refuses the credential B\'s /health leaked (401)', exchange($a, ...$leakedAtA) === 401);
check('B refuses the credential A\'s monitor leaked (401)', exchange($b, ...$leakedAtB) === 401);
$newA = peerRows($a, $b['base']);
$newB = peerRows($b, $a['base']);
check('each node still holds exactly one row for the other', count($newA) === 1 && count($newB) === 1, count($newA) . '/' . count($newB));
$newA = $newA[0] ?? [];
$newB = $newB[0] ?? [];
check('A\'s row is the new one', ($newA['interface_id'] ?? null) === $newId);
check('B re-bound its row in place: same interface id, new session token',
    ($newB['interface_id'] ?? null) === $leakedAtB[0] && ($newB['session_token'] ?? '') !== $leakedAtB[1]);
check('A holds B\'s new credential', ($newA['peer_interface_id'] ?? null) === ($newB['interface_id'] ?? '-')
    && ($newA['peer_session_token'] ?? null) === ($newB['session_token'] ?? '-'));
check('B holds A\'s new credential', ($newB['peer_interface_id'] ?? null) === $newId
    && ($newB['peer_session_token'] ?? null) === ($newA['session_token'] ?? '-'));
check('A accepts B with the new credential', exchange($a, (string) ($newB['peer_interface_id'] ?? ''), (string) ($newB['peer_session_token'] ?? '')) === 200);
check('B accepts A with the new credential', exchange($b, (string) ($newA['peer_interface_id'] ?? ''), (string) ($newA['peer_session_token'] ?? '')) === 200);

stopNode($a);
stopNode($b);

echo "\n$pass passed, $fail failed\n";
exit($fail === 0 ? 0 : 1);
