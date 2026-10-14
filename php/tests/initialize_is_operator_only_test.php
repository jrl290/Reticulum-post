<?php
/**
 * Initializing a node is the operator's `php index.php initialize`, on the
 * host. No web request can do it.
 *
 * Until 2026-10-14 GET /v1/initialize did it for anyone. It was routed ahead
 * of the gate that kept the other operator routes to nodes with debug.enabled
 * (those routes are gone too: the admin page replaced them), and it:
 * - ran migrate() in full: on MySQL/MariaDB 15 CREATE TABLE IF NOT EXISTS,
 *   22 CREATE INDEX that each fail with "duplicate key name", and 10
 *   information_schema reads, then said "migrated": true whatever migrate()
 *   reported;
 * - reset the web server's opcache;
 * - called connectToPeer() for each [interfaces] entry. That re-registers
 *   whenever the node's row for the peer is not online, and Phase 1 marks it
 *   offline after interface_stale_after_seconds without traffic (15 s on
 *   selectiv, 300 s on retichat.com, per their 2026-10-04 config). So one
 *   anonymous request in a quiet spell rotated the live peering, as README's
 *   rotation procedure does, with its costs. The initiator's row took a new
 *   id: its queue was lost, its paths were unusable until those destinations
 *   announced again, and links relayed across it were gone. The peer re-bound
 *   its row with a new token. Both old credentials answered 401. A peer that
 *   accepted the connection and stalled held the request, and one of the
 *   host's entry processes, for curl's 10 s ceiling.
 *
 * Nothing but an operator ever called it: no browser, gateway, deploy.sh or
 * harness. Peering and migration already heal on ordinary traffic
 * (maintenance Phase 12, migrateIfNeeded()).
 *
 * Two real nodes, each a copy of php/src under `php -S` with its own SQLite.
 * A has an [interfaces] block for B, as an initiator does.
 * (a) An anonymous GET /v1/initialize on either node answers 404 and
 *     registers nothing.
 * (b) `php index.php initialize` on A forms the peering and reports it. A
 *     second run, with the row online, changes nothing.
 * (c) With A's row offline, as Phase 1 leaves it after a quiet spell, an
 *     anonymous GET /v1/initialize changes neither node's row, and both
 *     credentials still work.
 * (d) The CLI reports a migration that failed and exits 1.
 * (e) Source: no web request can reach initializeNode(), the admin page's
 *     included (its Reconnect registers without migrating), and no file that
 *     deploy.sh ships calls opcache_reset(). opcache_reset.php did, for
 *     anyone who asked for it by URL, until 2026-10-14. The scanner is run
 *     on samples first, so a scanner that finds nothing cannot pass.
 *
 * On a4bcdda this fails (a), (b), (c) and (d): GET /v1/initialize answers 200
 * and registers, and index.php has no `initialize` mode. (e) fails too:
 * HttpApi::handle() calls initializeNode() and opcache_reset(), and so does
 * opcache_reset.php at file scope.
 *
 * Run: php php/tests/initialize_is_operator_only_test.php
 * INITIALIZE_SRC_DIR points it at another php/src, for mutation checks.
 */
declare(strict_types=1);

$src = getenv('INITIALIZE_SRC_DIR') ?: dirname(__DIR__) . '/src';

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
    $dir = sys_get_temp_dir() . '/reticulum-initialize-' . bin2hex(random_bytes(4));
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

/**
 * The operator's command, run on the node's own copy as it is run on a host:
 * `php index.php initialize`.
 *
 * @return array{int, array, string} exit code, decoded stdout, stderr
 */
function initializeCli(array $node): array
{
    $proc = proc_open(
        [PHP_BINARY, $node['dir'] . '/src/index.php', 'initialize'],
        [0 => ['file', '/dev/null', 'r'], 1 => ['pipe', 'w'], 2 => ['file', $node['dir'] . '/cli.err', 'w']],
        $pipes
    );
    $stdout = (string) stream_get_contents($pipes[1]);
    fclose($pipes[1]);
    $code = proc_close($proc);
    $decoded = json_decode($stdout, true);
    return [$code, is_array($decoded) ? $decoded : [], trim($stdout . ' ' . (string) @file_get_contents($node['dir'] . '/cli.err'))];
}

/**
 * Every call to a named function or method in $code, with the class and the
 * function it is in. Declarations, comments and strings are not calls.
 *
 * @return list<array{name: string, class: string, function: string, line: int}>
 */
function callSites(string $code, array $names): array
{
    $significant = [];
    foreach (token_get_all($code) as $token) {
        if (is_array($token) && in_array($token[0], [T_WHITESPACE, T_COMMENT, T_DOC_COMMENT], true)) {
            continue;
        }
        $significant[] = $token;
    }

    $found = [];
    $class = '';
    $classDepth = -1;
    $function = '(file scope)';
    $depth = 0;
    $count = count($significant);
    for ($i = 0; $i < $count; $i++) {
        $token = $significant[$i];
        $next = $significant[$i + 1] ?? null;
        $previous = $significant[$i - 1] ?? null;
        if ($token === '{' || (is_array($token) && in_array($token[0], [T_CURLY_OPEN, T_DOLLAR_OPEN_CURLY_BRACES], true))) {
            $depth++;
            continue;
        }
        if ($token === '}') {
            $depth--;
            if ($depth === $classDepth) {
                $class = '';
                $classDepth = -1;
            }
            continue;
        }
        if (!is_array($token)) {
            continue;
        }
        if (in_array($token[0], [T_CLASS, T_TRAIT], true) && is_array($next) && $next[0] === T_STRING) {
            $class = $next[1];
            $classDepth = $depth;
            continue;
        }
        if ($token[0] === T_FUNCTION && is_array($next) && $next[0] === T_STRING) {
            $function = $next[1];
            continue;
        }
        $name = match ($token[0]) {
            T_STRING => $token[1],
            T_NAME_FULLY_QUALIFIED => ltrim($token[1], '\\'),
            default => null,
        };
        if ($name === null || !in_array($name, $names, true) || $next !== '(') {
            continue;
        }
        if (is_array($previous) && in_array($previous[0], [T_FUNCTION, T_CONST, T_NEW], true)) {
            continue;
        }
        $found[] = ['name' => $name, 'class' => $class, 'function' => $function, 'line' => $token[2]];
    }
    return $found;
}

function describe(array $sites): string
{
    return implode(', ', array_map(
        static fn (array $s): string => $s['name'] . ' in ' . ($s['class'] !== '' ? $s['class'] . '::' : '') . $s['function'] . ':' . $s['line'],
        $sites
    )) ?: 'none';
}

$portA = freePort();
$portB = freePort();
$b = startNode($src, $portB, null);
$a = startNode($src, $portA, $b['base']);

echo "(a) an anonymous GET /v1/initialize is refused and registers nothing\n";
[$status, $body] = http('GET', $a['base'] . '/v1/initialize');
check('A answers 404', $status === 404, $status . ' ' . json_encode($body));
[$status, $body] = http('GET', $b['base'] . '/v1/initialize');
check('B answers 404', $status === 404, $status . ' ' . json_encode($body));
check('A holds no row for B, and B none for A',
    peerRows($a, $b['base']) === [] && peerRows($b, $a['base']) === [],
    count(peerRows($a, $b['base'])) . '/' . count(peerRows($b, $a['base'])));

echo "(b) the operator's `php index.php initialize` forms the peering\n";
[$code, $out, $raw] = initializeCli($a);
check('exits 0 and reports the peer connected and the schema migrated',
    $code === 0 && ($out['peers'][0]['status'] ?? null) === 'connected' && ($out['migrated'] ?? null) === true, "exit $code: $raw");
$rowA = peerRows($a, $b['base']);
$rowB = peerRows($b, $a['base']);
check('each node holds one row for the other', count($rowA) === 1 && count($rowB) === 1, count($rowA) . '/' . count($rowB));
$rowA = $rowA[0] ?? [];
$rowB = $rowB[0] ?? [];
check('the row it reports is A\'s row', ($out['peers'][0]['interface_id'] ?? null) === ($rowA['interface_id'] ?? '-'));
check('each holds the other\'s credential',
    ($rowA['peer_interface_id'] ?? null) === ($rowB['interface_id'] ?? '-') && ($rowA['peer_session_token'] ?? null) === ($rowB['session_token'] ?? '-')
    && ($rowB['peer_interface_id'] ?? null) === ($rowA['interface_id'] ?? '-') && ($rowB['peer_session_token'] ?? null) === ($rowA['session_token'] ?? '-'));
[$code, $out, $raw] = initializeCli($a);
check('a second run, with the row online, answers already_connected and keeps the row',
    $code === 0 && ($out['peers'][0]['status'] ?? null) === 'already_connected' && ($out['peers'][0]['interface_id'] ?? null) === ($rowA['interface_id'] ?? '-'),
    "exit $code: $raw");
check('and B keeps its token', (peerRows($b, $a['base'])[0]['session_token'] ?? null) === ($rowB['session_token'] ?? '-'));

echo "(c) a quiet spell: A's row offline, then an anonymous GET /v1/initialize\n";
// What Phase 1 (markStaleInterfacesOffline) leaves after
// interface_stale_after_seconds without traffic. Phase 12 heals such a row
// only once it has been offline for peer_session_heal_after_seconds.
$stmt = db($a)->prepare("UPDATE interfaces SET status = 'offline' WHERE interface_id = :id");
$stmt->execute([':id' => (string) ($rowA['interface_id'] ?? '')]);
check('A\'s row is offline', (peerRows($a, $b['base'])[0]['status'] ?? null) === 'offline');
[$status, $body] = http('GET', $a['base'] . '/v1/initialize');
check('A answers 404', $status === 404, $status . ' ' . json_encode($body));
$afterA = peerRows($a, $b['base']);
$afterB = peerRows($b, $a['base']);
check('A still holds exactly its row: same id, same tokens',
    count($afterA) === 1 && ($afterA[0]['interface_id'] ?? null) === $rowA['interface_id']
    && ($afterA[0]['session_token'] ?? null) === $rowA['session_token'] && ($afterA[0]['peer_session_token'] ?? null) === $rowA['peer_session_token'],
    json_encode(array_map(static fn (array $r): string => substr((string) $r['interface_id'], 0, 8), $afterA)));
check('B kept its row and its token',
    count($afterB) === 1 && ($afterB[0]['session_token'] ?? null) === $rowB['session_token'] && ($afterB[0]['peer_interface_id'] ?? null) === $rowA['interface_id']);
check('A accepts B with the credential B holds', exchange($a, (string) ($rowB['peer_interface_id'] ?? ''), (string) ($rowB['peer_session_token'] ?? '')) === 200);
check('B accepts A with the credential A holds', exchange($b, (string) ($rowA['peer_interface_id'] ?? ''), (string) ($rowA['peer_session_token'] ?? '')) === 200);

echo "(d) a migration that fails is reported, not counted as migrated\n";
// An index whose name a table has taken: SQLite refuses CREATE INDEX with
// "there is already a table named ...", which migrate() records as an error.
db($a)->exec('DROP INDEX idx_outbound_packets_queued');
db($a)->exec('CREATE TABLE idx_outbound_packets_queued (x INTEGER)');
[$code, $out, $raw] = initializeCli($a);
$errors = $out['migration']['errors'] ?? null;
check('exits 1, says migrated false and gives migrate()\'s error',
    $code === 1 && ($out['migrated'] ?? null) === false && is_array($errors) && count($errors) === 1
        && str_contains((string) $errors[0], 'idx_outbound_packets_queued'),
    "exit $code: $raw");
check('the peering is untouched', ($out['peers'][0]['status'] ?? null) === 'already_connected', json_encode($out['peers'] ?? null));

stopNode($a);
stopNode($b);

echo "(e) source: no web request reaches initializeNode() or opcache_reset()\n";
$samples = [
    'a route calling it' => ['<?php class HttpApi { function handle() { $s = $this->storage->initializeNode(); } }', ['HttpApi::handle']],
    'an admin action calling it' => ['<?php final class AdminConsole { private function act(): never { $this->storage->initializeNode(); } }', ['AdminConsole::act']],
    'a CLI function calling it' => ['<?php function runIndexCli() { $x->initializeNode(); }', ['runIndexCli']],
    'a fully qualified \\opcache_reset()' => ['<?php class HttpApi { function f() { \\opcache_reset(); } }', ['HttpApi::f']],
    'a declaration, a comment, a string, a function_exists() check' => [
        "<?php trait T { public function initializeNode(): array { return []; } } // opcache_reset();\n \$s = 'opcache_reset()'; if (function_exists('opcache_reset')) {}",
        [],
    ],
    'a closure inside a class method, and code after the class' => [
        '<?php class HttpApi { function g() { $f = function () { opcache_reset(); }; } } function runIndexCli() { $s->initializeNode(); }',
        ['HttpApi::g', 'runIndexCli'],
    ],
];
foreach ($samples as $label => [$code, $expected]) {
    $where = array_map(
        static fn (array $s): string => ($s['class'] !== '' ? $s['class'] . '::' : '') . $s['function'],
        callSites($code, ['initializeNode', 'opcache_reset'])
    );
    check("scanner: $label", $where === $expected, json_encode($where));
}

// The classes web requests run: HttpApi routes, and hands /admin to AdminConsole.
$routeClasses = ['HttpApi', 'AdminConsole'];
$httpApiSites = [];
$initializeNodeSites = [];
$opcacheSites = [];
// Every file deploy.sh ships: php/src's top-level and lib/ .php files.
// opcache_reset.php was one of them until 2026-10-14, reachable by URL.
$files = array_merge(glob($src . '/*.php') ?: [], glob($src . '/lib/*.php') ?: []);
foreach ($files as $file) {
    $sites = callSites((string) file_get_contents($file), ['initializeNode', 'migrate', 'opcache_reset']);
    foreach ($sites as $site) {
        $site['file'] = basename($file);
        if (in_array($site['class'], $routeClasses, true)) {
            $httpApiSites[] = $site;
        }
        if ($site['name'] === 'initializeNode') {
            $initializeNodeSites[] = $site;
        }
        if ($site['name'] === 'opcache_reset') {
            $opcacheSites[] = $site;
        }
    }
}
check('index.php, the other top-level files and lib/ were read',
    in_array($src . '/index.php', $files, true) && count($files) > 10 && $initializeNodeSites !== [], count($files) . ' files');
check('HttpApi and AdminConsole call none of initializeNode(), migrate(), opcache_reset()', $httpApiSites === [], describe($httpApiSites));
check('both classes were found', count(array_filter($files, static fn (string $f): bool => preg_match('/\\bfinal class (HttpApi|AdminConsole)\\b/', (string) file_get_contents($f)) === 1)) === 2);
check('initializeNode() is called only by runIndexCli()',
    $initializeNodeSites !== [] && array_filter($initializeNodeSites, static fn (array $s): bool => $s['function'] !== 'runIndexCli' || $s['class'] !== '') === [],
    describe($initializeNodeSites));
check('nothing deployed from php/src resets the opcache', $opcacheSites === [], describe($opcacheSites));

echo "\n$pass passed, $fail failed\n";
exit($fail === 0 ? 0 : 1);
