<?php
/**
 * The operator console answers only where debug.enabled is set.
 *
 * /v1/monitor, /v1/monitor/data|json, POST /v1/monitor/clear and POST
 * /v1/maintenance/flush have no authentication, and neither has monitor.php.
 * Until 2026-09-30 every node answered them: a POST of {"confirm":"YES"} to
 * /v1/monitor/clear (or to monitor.php?action=clear) deleted every table,
 * the transport identity and every peer session included, and
 * {"force":true} to /v1/maintenance/flush dropped every browser session.
 * They now sit behind the gate /debug always had.
 *
 * Two real nodes, one with debug off and one with it on, each a copy of
 * php/src served by `php -S` with its own SQLite, driven over HTTP; monitor.php
 * is run as a script against each node's config.
 *
 * Run: php tests/operator_routes_gated_test.php
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

function freePort(): int
{
    $server = stream_socket_server('tcp://127.0.0.1:0', $errno, $errstr);
    $name = (string) stream_socket_get_name($server, false);
    fclose($server);
    return (int) substr($name, strrpos($name, ':') + 1);
}

/** @return array{int, string} */
function http(string $method, string $url, ?string $body = null): array
{
    $context = stream_context_create(['http' => [
        'method' => $method,
        'header' => "Content-Type: application/json\r\n",
        'content' => $body ?? '',
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
    return [$status, is_string($response) ? $response : ''];
}

/** @return array{base: string, dir: string, proc: resource} */
function startNode(string $src, bool $debug): array
{
    $dir = sys_get_temp_dir() . '/reticulum-operator-gate-' . bin2hex(random_bytes(4));
    copyTree($src, $dir . '/src');
    $port = freePort();
    file_put_contents($dir . '/src/config.toml', implode("\n", [
        'host_url = "http://127.0.0.1:' . $port . '"',
        '[storage]',
        'backend = "sqlite"',
        'sqlite_path = "' . $dir . '/node.sqlite"',
        'log_path = "' . $dir . '/router.log"',
        '[debug]',
        'enabled = ' . ($debug ? 'true' : 'false'),
        '',
    ]));
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

function interfaceCount(array $node): int
{
    $pdo = new PDO('sqlite:' . $node['dir'] . '/node.sqlite');
    return (int) $pdo->query('SELECT COUNT(*) FROM interfaces')->fetchColumn();
}

function register(array $node): void
{
    http('POST', $node['base'] . '/v1/interfaces/register',
        json_encode(['name' => 'Retichat Web', 'bitrate' => 1000000, 'mtu' => 500, 'metadata' => ['client' => 'rns-js', 'mode' => 1]]));
}

function monitorScript(array $node, string $method): string
{
    // monitor.php reads $_SERVER and $_POST itself; run it as a script with
    // a POST clear request prepared the way the page's button sends it.
    $code = '$_SERVER["REQUEST_METHOD"] = ' . var_export($method, true) . '; $_GET["action"] = "clear"; $_POST["confirm"] = "YES"; '
          . 'require ' . var_export($node['dir'] . '/src/monitor.php', true) . ';';
    exec(escapeshellarg(PHP_BINARY) . ' -r ' . escapeshellarg($code) . ' 2>&1', $out);
    return implode("\n", $out);
}

$off = startNode($src, false);
$on = startNode($src, true);
check('both nodes answer /health', http('GET', $off['base'] . '/health')[0] === 200 && http('GET', $on['base'] . '/health')[0] === 200);

echo "(a) debug off: the operator routes do not exist\n";
foreach (['GET /v1/monitor', 'GET /v1/monitor/data', 'GET /v1/monitor/json', 'GET /debug'] as $route) {
    [$method, $path] = explode(' ', $route);
    [$status] = http($method, $off['base'] . $path);
    check("$route → 404", $status === 404, (string) $status);
}
register($off);
[$status] = http('POST', $off['base'] . '/v1/monitor/clear', '{"confirm":"YES"}');
check('POST /v1/monitor/clear → 404', $status === 404, (string) $status);
check('...and the interfaces table is untouched', interfaceCount($off) === 1, (string) interfaceCount($off));
[$status] = http('POST', $off['base'] . '/v1/maintenance/flush', '{"force":true}');
check('POST /v1/maintenance/flush → 404', $status === 404, (string) $status);
$output = monitorScript($off, 'POST');
check('monitor.php clear answers "not found"', trim($output) === 'not found', $output);
check('...and the interfaces table is untouched', interfaceCount($off) === 1, (string) interfaceCount($off));
check('the node still serves its clients (/health, register)', http('GET', $off['base'] . '/health')[0] === 200);

echo "(b) debug on: the console works as before\n";
register($on);
check('GET /v1/monitor → 200', http('GET', $on['base'] . '/v1/monitor')[0] === 200);
check('GET /v1/monitor/data → 200', http('GET', $on['base'] . '/v1/monitor/data')[0] === 200);
check('GET /debug → 200', http('GET', $on['base'] . '/debug')[0] === 200);
[$status] = http('POST', $on['base'] . '/v1/maintenance/flush', '{"force":false}');
check('POST /v1/maintenance/flush → 200', $status === 200, (string) $status);
[$status] = http('POST', $on['base'] . '/v1/monitor/clear', '{"confirm":"YES"}');
check('POST /v1/monitor/clear → 200 and clears', $status === 200 && interfaceCount($on) === 0, $status . ' / ' . interfaceCount($on));
register($on);
$output = monitorScript($on, 'POST');
check('monitor.php clear works where debug is on', str_contains($output, 'All tables cleared') && interfaceCount($on) === 0, substr($output, 0, 120));

stopNode($off);
stopNode($on);

echo "\n$pass passed, $fail failed\n";
exit($fail === 0 ? 0 : 1);
