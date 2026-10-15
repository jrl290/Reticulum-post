<?php
/**
 * The Swoole entry says in the node's error_log when it starts, when it shuts
 * down and when a worker dies (James, 2026-10-15: "Add the Swoole
 * start/shutdown logging"), so the next unexplained restart on selectiv
 * leaves a trace the account can read (SwooleLifecycle in
 * lib/swoole_node.php).
 *
 * Always: the lines' format. With RETICULUM_TEST_RUNTIME=swoole (and
 * RETICULUM_TEST_SWOOLE naming the extension, as for the HTTP tests): starts
 * swoole_server.php on a copy of the node, checks the start line names the
 * master, SIGKILLs a worker and checks the manager's line for it and that the
 * node still answers, then SIGTERMs the master and checks the shutdown line.
 *
 * Run: php tests/swoole_lifecycle_log_test.php
 *      RETICULUM_TEST_RUNTIME=swoole RETICULUM_TEST_SWOOLE=/path/swoole.so php tests/swoole_lifecycle_log_test.php
 */
declare(strict_types=1);

require_once dirname(__DIR__) . '/src/lib/swoole_node.php';

use ReticulumPhp\SwooleLifecycle;

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

echo "The lines\n";
$line = SwooleLifecycle::start(100, 101, 4, 8080, '4fe893a0123456789abcdef0123456789abcdef0');
check('start names master, manager, workers, port and the short build',
    $line === '[SWOOLE-START] master=100 manager=101 workers=4 port=8080 build=4fe893a01234', $line);
$line = SwooleLifecycle::start(100, 101, 4, 8080, null);
check('start without a build stamp says unknown', str_ends_with($line, 'build=unknown'), $line);
$line = SwooleLifecycle::shutdown(100, 1000, 1765);
check('shutdown names the master and how long it ran', $line === '[SWOOLE-SHUTDOWN] master=100 after 765 s', $line);
$line = SwooleLifecycle::workerError(2, 4242, 0, 9);
check('a killed worker names its signal', $line === '[SWOOLE-WORKER-ERROR] worker=2 pid=4242 exit=0 signal=9 (SIGKILL)', $line);
$line = SwooleLifecycle::workerError(1, 4243, 255, 0);
check('a worker that exited with a code has no signal name', $line === '[SWOOLE-WORKER-ERROR] worker=1 pid=4243 exit=255 signal=0', $line);
$line = SwooleLifecycle::workerError(1, 4244, 0, 7);
check('an unnamed signal is given by number', str_ends_with($line, 'signal=7 (signal 7)'), $line);

if (getenv('RETICULUM_TEST_RUNTIME') !== 'swoole') {
    echo "(the running server is checked with RETICULUM_TEST_RUNTIME=swoole)\n";
    echo "\nResults: $pass passed, $fail failed\n";
    exit($fail === 0 ? 0 : 1);
}

function copyTree(string $from, string $to): void
{
    mkdir($to, 0775, true);
    foreach (scandir($from) ?: [] as $entry) {
        if ($entry === '.' || $entry === '..' || str_starts_with($entry, 'config.') || $entry === 'build.json' || $entry === 'error_log') {
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

function healthStatus(string $base): int
{
    $context = stream_context_create(['http' => ['ignore_errors' => true, 'timeout' => 5]]);
    @file_get_contents($base . '/health', false, $context);
    return preg_match('#^HTTP/\S+ (\d{3})#', $http_response_header[0] ?? '', $m) === 1 ? (int) $m[1] : 0;
}

/**
 * The first error_log line matching $pattern, waiting for it up to 5 s: the
 * bound only turns a line that never comes into a failure instead of a hang.
 */
function waitForLine(string $log, string $pattern): ?string
{
    for ($i = 0; $i < 50; $i++) {
        if (preg_match($pattern, (string) @file_get_contents($log), $m) === 1) {
            return $m[0];
        }
        usleep(100000);
    }
    return null;
}

echo "The running server\n";
$dir = sys_get_temp_dir() . '/reticulum-swoole-lifecycle-' . bin2hex(random_bytes(4));
copyTree($src, $dir . '/src');
$port = freePort();
file_put_contents($dir . '/src/config.toml', implode("\n", [
    'host_url = "http://127.0.0.1:' . $port . '"',
    '[storage]',
    'backend = "sqlite"',
    'sqlite_path = "' . $dir . '/node.sqlite"',
    'log_path = "' . $dir . '/router.log"',
    '[swoole]',
    'enable_swoole = true',
    'workers = 2',
    '',
]));
$extension = getenv('RETICULUM_TEST_SWOOLE');
$extension = $extension === false ? 'swoole.so' : $extension;
// An empty error_log, as on selectiv: the entry's own default, the error_log
// next to the script, which is where Passenger's restarts must show.
$command = [PHP_BINARY, '-d', 'error_log='];
if ($extension !== '') {
    array_push($command, '-d', 'extension=' . $extension);
}
$command[] = $dir . '/src/swoole_server.php';
$env = getenv();
$env['PORT'] = (string) $port;
$io = [0 => ['file', '/dev/null', 'r'], 1 => ['file', $dir . '/server.out', 'w'], 2 => ['file', $dir . '/server.out', 'a']];
$proc = proc_open($command, $io, $pipes, null, $env);
$masterPid = (int) proc_get_status($proc)['pid'];
$log = $dir . '/src/error_log';
$base = 'http://127.0.0.1:' . $port;

$start = waitForLine($log, '/\[SWOOLE-START\] master=(\d+) manager=(\d+) workers=2 port=' . $port . ' build=\S+/');
check('the start line is in the error_log next to the script', $start !== null,
    'error_log: ' . (string) @file_get_contents($log) . ' server.out: ' . (string) @file_get_contents($dir . '/server.out'));
preg_match('/master=(\d+) manager=(\d+)/', (string) $start, $m);
check('it names the process Passenger started as the master', (int) ($m[1] ?? 0) === $masterPid, "line: $start, started: $masterPid");
$managerPid = (int) ($m[2] ?? 0);

for ($i = 0; $i < 50 && healthStatus($base) !== 200; $i++) {
    usleep(100000);
}
$workers = $managerPid > 0 ? array_values(array_filter(array_map('intval', explode("\n", (string) shell_exec('pgrep -P ' . $managerPid))))) : [];
check('the manager has the two workers', count($workers) === 2, 'workers: ' . implode(',', $workers));

if ($workers !== []) {
    posix_kill($workers[0], 9);
    $error = waitForLine($log, '/\[SWOOLE-WORKER-ERROR\] worker=\d+ pid=' . $workers[0] . ' exit=\d+ signal=9 \(SIGKILL\)/');
    check('a SIGKILLed worker is logged with its pid and signal', $error !== null, 'error_log: ' . (string) @file_get_contents($log));
}
$status = 0;
for ($i = 0; $i < 50 && ($status = healthStatus($base)) !== 200; $i++) {
    usleep(100000);
}
check('the node still answers after losing a worker', $status === 200, "status $status");
check('no shutdown line while it runs', !str_contains((string) @file_get_contents($log), '[SWOOLE-SHUTDOWN]'));

posix_kill($masterPid, 15);
$shutdown = waitForLine($log, '/\[SWOOLE-SHUTDOWN\] master=' . $masterPid . ' after \d+ s/');
check('SIGTERM to the master logs the shutdown', $shutdown !== null, 'error_log: ' . (string) @file_get_contents($log));
for ($i = 0; $i < 50 && proc_get_status($proc)['running']; $i++) {
    usleep(100000);
}
check('and the server exits', !proc_get_status($proc)['running']);

proc_terminate($proc, 9);
proc_close($proc);
exec('rm -rf ' . escapeshellarg($dir));

echo "\nResults: $pass passed, $fail failed\n";
exit($fail === 0 ? 0 : 1);
