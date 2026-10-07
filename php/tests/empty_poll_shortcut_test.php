<?php
/**
 * An idle client's empty poll is answered from its idle mark, without the
 * database, and never while anything waits for it (James, 2026-10-07).
 *
 * An idle client exchanges every idle_exchange_interval_ms (1 s), and each
 * exchange used to open the database to learn there was nothing. EmptyPoll
 * answers such a poll from a small file instead. This drives a real node
 * (php -S, SQLite, the node's per-request query log) over HTTP: a request that
 * writes no query-log line never opened the database. It checks that the
 * shortcut answers byte for byte as the full path does; that a queued packet,
 * an unacknowledged batch, a wrong token, a goodbye, an old mark and an owed
 * wake each send the poll down the full path; and, in process, the order
 * markIdle relies on and the sweep.
 *
 * Run: php tests/empty_poll_shortcut_test.php
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

/** @return array{int, string, array<string,string>} */
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
    $headers = [];
    foreach ($http_response_header ?? [] as $line) {
        if (preg_match('#^HTTP/\S+ (\d{3})#', $line, $m) === 1) {
            $status = (int) $m[1];
        } elseif (preg_match('#^(Content-Type|Access-Control-[A-Za-z-]+):\s*(.*)$#i', $line, $m) === 1) {
            $headers[strtolower($m[1])] = trim($m[2]);
        }
    }
    ksort($headers);
    return [$status, is_string($response) ? $response : '', $headers];
}

$dir = sys_get_temp_dir() . '/reticulum-empty-poll-' . bin2hex(random_bytes(4));
copyTree($src, $dir . '/src');
$port = freePort();
$queryLog = $dir . '/queries.log';
file_put_contents($dir . '/src/config.toml', implode("\n", [
    'host_url = "http://127.0.0.1:' . $port . '"',
    '[storage]',
    'backend = "sqlite"',
    'sqlite_path = "' . $dir . '/node.sqlite"',
    'log_path = "' . $dir . '/router.log"',
    'query_log_path = "' . $queryLog . '"',
    '[http]',
    // Long enough that a wake mark written this second is never "due" while
    // a step runs; the due test is checked with a mark written long ago.
    'min_wake_interval_ms = 10000',
    '[maintenance]',
    'interface_stale_after_seconds = 30',
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

// The node's own classes, in process, against the same config and database.
require $dir . '/src/index.php';
$config = \ReticulumPhp\loadRuntimeConfig($dir . '/src');
$storage = new \ReticulumPhp\Storage($config);
$markPath = static fn (string $interfaceId): string =>
    (\Closure::bind(static fn () => self::markPath(self::dir($config), $interfaceId), null, \ReticulumPhp\EmptyPoll::class))();
$markDir = (\Closure::bind(static fn () => self::dir($config), null, \ReticulumPhp\EmptyPoll::class))();
$queue = static function (string $interfaceId) use ($storage): void {
    // A DATA packet: HEADER_1 flags, 0 hops, a destination, context 0, payload.
    $raw = chr(0x00) . chr(0) . random_bytes(16) . chr(0) . 'queued for the shortcut test';
    (\Closure::bind(fn () => $this->queueOutboundPacket($interfaceId, base64_encode($raw), 'local_delivery'), $storage, \ReticulumPhp\Storage::class))();
};

function queryLines(string $path): int
{
    return is_file($path) ? count(file($path, FILE_SKIP_EMPTY_LINES)) : 0;
}

/** The request, and whether it wrote a query-log line (opened the database). @return array{int, string, array, bool} */
function request(string $url, array $body): array
{
    global $queryLog;
    $before = queryLines($queryLog);
    [$status, $text, $headers] = http('POST', $url, json_encode($body));
    // The log line is written at shutdown, after the answer; wait for it.
    for ($i = 0; $i < 20 && queryLines($queryLog) === $before; $i++) {
        usleep(10000);
    }
    return [$status, $text, $headers, queryLines($queryLog) > $before];
}

function register(string $base): array
{
    [, $text] = http('POST', $base . '/v1/interfaces/register',
        json_encode(['name' => 'Retichat Web', 'bitrate' => 1000000, 'mtu' => 500, 'metadata' => ['client' => 'rns-js', 'mode' => 1]]));
    return json_decode($text, true);
}

$exchange = $base . '/v1/interfaces/exchange';
$poll = $base . '/v1/interfaces/poll';
$a = register($base);
$empty = ['interface_id' => $a['interface_id'], 'session_token' => $a['session_token'], 'packets' => []];

echo "(a) an idle client's empty exchange skips the database, answering as the full path does\n";
[$s1, $full, $fullHeaders, $db1] = request($exchange, $empty);
check('the first exchange takes the full path', $s1 === 200 && $db1, "$s1");
check('...and leaves an idle mark', is_file($markPath($a['interface_id'])));
[$s2, $short, $shortHeaders, $db2] = request($exchange, $empty);
check('the next one opens no database', $s2 === 200 && !$db2, "$s2");
check('...and its body is the full path\'s, byte for byte', $short === $full, "$short vs $full");
check('...with the same headers', $shortHeaders === $fullHeaders && isset($shortHeaders['access-control-allow-origin']), json_encode($shortHeaders));
[$s, $withBatch, , $db] = request($exchange, $empty + ['batch_id' => 'b1', 'max_packets' => 8]);
check('a batch_id and max_packets do not stop it, and the batch_id is echoed', $s === 200 && !$db && json_decode($withBatch, true)['batch_id'] === 'b1', $withBatch);

echo "(b) the poll route\n";
$b = register($base);
$bPoll = ['interface_id' => $b['interface_id'], 'session_token' => $b['session_token']];
[$s, $fullPoll, , $db] = request($poll, $bPoll);
check('a first poll takes the full path', $s === 200 && $db);
[$s, $shortPoll, , $db] = request($poll, $bPoll);
check('the next poll opens no database and answers the same', $s === 200 && !$db && $shortPoll === $fullPoll, "$shortPoll vs $fullPoll");

echo "(c) anything other than an empty poll from the same token takes the full path\n";
[$s, , , $db] = request($exchange, ['session_token' => 'not-the-token'] + $empty);
check('a wrong token is refused by the full path (401)', $s === 401 && $db, "$s");
[$s, , , $db] = request($exchange, ['ack_batch_ids' => ['nope']] + $empty);
check('an acknowledgement goes to the database', $s === 200 && $db, "$s");
[$s, , , $db] = request($exchange, ['packets' => ['not base64!']] + $empty);
check('a packet goes to the full path (which rejects this one, 400)', $s === 400 && $db, "$s");
[$s, , , $db] = request($exchange, ['interface_id' => $a['interface_id'], 'session_token' => $a['session_token']]);
check('an exchange without packets is the full path\'s to refuse (400)', $s === 400 && $db, "$s");
[$s, , , $db] = request($exchange, ['max_packets' => 0] + $empty);
check('a bad max_packets is the full path\'s to refuse (400)', $s === 400 && $db, "$s");
[$s, , , $db] = request($exchange, $empty);
check('an empty poll is still answered from the mark', $s === 200 && !$db);

echo "(d) a queued packet is delivered on the next poll, and the mark returns only after its acknowledgement\n";
$queue($a['interface_id']);
check('queueing removes the mark', !is_file($markPath($a['interface_id'])));
[$s, $text, , $db] = request($exchange, $empty);
$delivery = json_decode($text, true);
check('the next poll takes the full path and delivers it', $s === 200 && $db && count($delivery['delivery_packets'] ?? []) === 1, $text);
check('...leaving no mark while the batch is unacknowledged', !is_file($markPath($a['interface_id'])));
[$s, $text, , $db] = request($exchange, $empty);
check('an empty poll without the acknowledgement takes the full path and gets the batch again', $s === 200 && $db && (json_decode($text, true)['delivery_batch_id'] ?? null) === $delivery['delivery_batch_id'], $text);
[$s, $text, , $db] = request($exchange, ['ack_batch_ids' => [$delivery['delivery_batch_id']]] + $empty);
check('the acknowledgement is taken (full path)', $s === 200 && $db && json_decode($text, true)['acked_batches'] === 1, $text);
check('...and the mark is back', is_file($markPath($a['interface_id'])));
[$s, , , $db] = request($exchange, $empty);
check('the next empty poll opens no database', $s === 200 && !$db);

echo "(e) a mark older than the bound is not honoured\n";
check('the bound is a third of interface_stale_after_seconds (30 s → 10 s)', \ReticulumPhp\EmptyPoll::seconds($config) === 10);
touch($markPath($a['interface_id']), time() - 10);
[$s, , , $db] = request($exchange, $empty);
check('an old mark sends the poll to the full path', $s === 200 && $db);
[$s, , , $db] = request($exchange, $empty);
check('...which writes a fresh one', $s === 200 && !$db);

echo "(f) an owed wake sends polls to the full path once an epilogue is due\n";
touch($markDir . '/wakes-owed', time());
[$s, , , $db] = request($exchange, $empty);
check('an owed wake inside min_wake_interval_ms leaves the shortcut on', $s === 200 && !$db);
touch($markDir . '/wakes-owed', time() - 20);
[$s, , , $db] = request($exchange, $empty);
check('an owed wake past min_wake_interval_ms takes the full path', $s === 200 && $db);
check('...whose epilogue, finding no peer owed, removes the wake mark', !is_file($markDir . '/wakes-owed'));
[$s, , , $db] = request($exchange, $empty);
check('the shortcut is back', $s === 200 && !$db);

echo "(g) goodbye and registration remove the mark\n";
[$s] = request($base . '/v1/interfaces/goodbye', ['interface_id' => $a['interface_id'], 'session_token' => $a['session_token']]);
check('goodbye is answered', $s === 200);
check('...and removes the mark', !is_file($markPath($a['interface_id'])));
[$s, , , $db] = request($exchange, $empty);
$pdo = new PDO('sqlite:' . $dir . '/node.sqlite');
$status = $pdo->query("SELECT status FROM interfaces WHERE interface_id = " . $pdo->quote($a['interface_id']))->fetchColumn();
check('a page restored after goodbye takes the full path and is online again', $s === 200 && $db && $status === 'online', "$s $status");
check('registration clears the mark of the interface it returns', (function () use ($markPath, $config, $b): bool {
    \ReticulumPhp\EmptyPoll::markIdle($config, $b['interface_id'], 'x', fn (): int => 0);
    $had = is_file($markPath($b['interface_id']));
    \ReticulumPhp\EmptyPoll::clear($config, $b['interface_id']);
    return $had && !is_file($markPath($b['interface_id']));
})());

$peerId = 'peer-' . bin2hex(random_bytes(4));
$pdo->prepare("INSERT INTO interfaces (interface_id, name, session_token, bitrate, mtu, status, metadata_json, created_at, last_seen_at, peer_url, peer_interface_id, peer_session_token) VALUES (?, 'peer', 'ptok', 1, 500, 'online', '{}', ?, ?, 'http://peer.example', 'their-id', 'their-tok')")
    ->execute([$peerId, time(), time()]);
$storage->markIdleIfNothingQueued($peerId, 'ptok');
check('a PHP peer is never marked (its rotation deletes the row in SQL, which must refuse it at once)', !is_file($markPath($peerId)));

echo "(h) markIdle writes before it counts\n";
$c = 'unit-' . bin2hex(random_bytes(4));
\ReticulumPhp\EmptyPoll::markIdle($config, $c, 'tok', fn (): int => 0);
check('nothing queued: the mark stays', is_file($markPath($c)));
\ReticulumPhp\EmptyPoll::markIdle($config, $c, 'tok', fn (): int => 1);
check('something unacknowledged: no mark', !is_file($markPath($c)));
$seenDuringCount = false;
\ReticulumPhp\EmptyPoll::markIdle($config, $c, 'tok', function () use ($markPath, $c, &$seenDuringCount): int {
    $seenDuringCount = is_file($markPath($c));
    return 1;
});
check('the mark exists while the count runs (a queue write then removes it)', $seenDuringCount);
\ReticulumPhp\EmptyPoll::markIdle($config, $c, 'tok', function () use ($config, $c): int {
    \ReticulumPhp\EmptyPoll::clear($config, $c); // a packet committed and its writer's removal, during the count
    return 0;
});
check('a removal during the count wins', !is_file($markPath($c)));
$threw = false;
try {
    \ReticulumPhp\EmptyPoll::markIdle($config, $c, 'tok', function (): int { throw new RuntimeException('db gone'); });
} catch (RuntimeException) {
    $threw = true;
}
check('a count that fails leaves no mark and is reported', $threw && !is_file($markPath($c)));

echo "(i) the bound\n";
$cfg = static fn (array $http, int $stale): array => ['http' => $http + ['idle_exchange_interval_ms' => 1000], 'maintenance' => ['interface_stale_after_seconds' => $stale]];
check('default 10 s under a 300 s stale sweep', \ReticulumPhp\EmptyPoll::seconds($cfg([], 300)) === 10);
check('15 s stale sweep (selectiv) → 5 s', \ReticulumPhp\EmptyPoll::seconds($cfg([], 15)) === 5);
check('a configured 3 s is kept', \ReticulumPhp\EmptyPoll::seconds($cfg(['empty_poll_shortcut_seconds' => 3], 300)) === 3);
check('0 turns it off', \ReticulumPhp\EmptyPoll::seconds($cfg(['empty_poll_shortcut_seconds' => 0], 300)) === 0);
check('a 2 s stale sweep leaves no room: off', \ReticulumPhp\EmptyPoll::seconds($cfg([], 2)) === 0);

echo "(j) the sweep removes marks too old to honour, at most once a minute\n";
$old = $markDir . '/' . str_repeat('0', 32);
$fresh = $markDir . '/' . str_repeat('1', 32);
file_put_contents($old, 'x');
touch($old, time() - 120);
file_put_contents($fresh, 'x');
touch($markDir . '/wakes-owed', time() - 120);
@unlink($markDir . '/swept');
\ReticulumPhp\EmptyPoll::sweep($config);
check('an old mark is removed, a fresh one kept', !is_file($old) && is_file($fresh));
check('the wake mark is not the sweep\'s to remove', is_file($markDir . '/wakes-owed'));
file_put_contents($old, 'x');
touch($old, time() - 120);
\ReticulumPhp\EmptyPoll::sweep($config);
check('a second sweep within the minute does nothing', is_file($old));
@unlink($markDir . '/wakes-owed');

echo "(k) the queue's one writer, and no transactions around it\n";
$srcFiles = array_merge([$src . '/index.php'], glob($src . '/lib/*.php') ?: []);
$inserts = [];
$transactions = [];
foreach ($srcFiles as $file) {
    // Code only: comments may describe a write without making one.
    $code = '';
    foreach (token_get_all((string) file_get_contents($file)) as $token) {
        if (is_array($token) && in_array($token[0], [T_COMMENT, T_DOC_COMMENT], true)) {
            continue;
        }
        $code .= is_array($token) ? $token[1] : $token;
    }
    if (preg_match_all('/INSERT\s+(?:OR\s+\w+\s+)?INTO\s+outbound_packets\b/i', $code, $m) > 0) {
        $inserts[basename($file)] = count($m[0]);
    }
    if (preg_match('/->\s*(beginTransaction|commit)\s*\(/', $code) === 1) {
        $transactions[] = basename($file);
    }
}
check('outbound_packets is inserted into only by queueOutboundPacket', $inserts === ['request_interface_runtime_trait.php' => 1], json_encode($inserts));
check('the node opens no transactions (the mark is removed right after the autocommit write)', $transactions === [], implode(', ', $transactions));

proc_terminate($proc);
proc_close($proc);
exec('rm -rf ' . escapeshellarg($dir) . ' ' . escapeshellarg($markDir));

echo "\nResults: $pass passed, $fail failed\n";
exit($fail > 0 ? 1 : 0);
