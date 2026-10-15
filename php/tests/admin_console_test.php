<?php
/**
 * The admin page (/admin): closed until someone on the host sets it up, then
 * a sign-in in front of the live view, the peering actions and the
 * maintenance actions. The operator routes it replaced are gone.
 *
 * Until 2026-10-14 the operator console was /v1/monitor, /v1/monitor/data|json,
 * POST /v1/monitor/clear, POST /v1/maintenance/flush, /debug and monitor.php.
 * None of them authenticated: every node answered them until 2026-09-30, and
 * then every node with debug.enabled set. A POST of {"confirm":"YES"} to
 * /v1/monitor/clear deleted every table, the transport identity and every peer
 * session included.
 *
 * Two real nodes, each a copy of php/src under `php -S` with its own SQLite
 * and debug.enabled on; A has an [interfaces] block for B. The admin
 * credentials live in each node's own temporary "home", never the real one.
 *
 * (a) Before `php index.php admin-setup`, every /admin path answers exactly as
 *     an unknown path does (404). The old routes answer 404 with debug.enabled
 *     on and leave the database alone; monitor.php is gone and deploy.sh
 *     retires it.
 * (b) admin-setup refuses a missing or malformed username, a password outside
 *     12..72 bytes, and a credentials file inside the web root; then stores
 *     the username and a bcrypt hash at mode 0600 (its directory 0700), never
 *     the password.
 * (c) The sign-in page carries no CORS header, a nonce CSP, no-store and no
 *     framing. A wrong password or username is 401 with no cookie; the right
 *     ones from another origin, 403. The right sign-in is a 303 with an
 *     HttpOnly, SameSite=Strict cookie scoped to /admin.
 * (d) Reconnect and Rotate for the configured peer. Reconnect forms the
 *     peering and then leaves the live row alone. Rotate gives A's row a new id
 *     and token, B keeps its row with a new token, the old credentials get 401
 *     at both ends and the new ones 200. With two rows naming the peer, Rotate
 *     is refused and deletes nothing. An unconfigured name is 404.
 * (e) Signed in, /admin/data and /admin/debug answer, and no session_token or
 *     peer_session_token in either database appears in them; signed out they
 *     are 401. A cookie that is expired, for another user, issued in the
 *     future, tampered with or signed with another key is signed out.
 * (f) An action needs this origin and the session's token: without the token,
 *     with a wrong one or another session's, or from another origin or site,
 *     a forced flush is 403 and the browser stays online. With them the flush
 *     runs, and forced, it marks the browser offline.
 * (g) The sixth sign-in attempt from one address within 15 minutes is 429,
 *     the right password included. Past a hundred an hour from all addresses
 *     together, only an address that signed in within 30 days may try.
 *     admin-setup lifts both.
 * (h) admin-setup again signs out every session; Sign out tells the browser to
 *     drop the cookie; admin-remove closes the page (404). B, never set up,
 *     answers 404 throughout.
 * (i) On samples: plain HTTP is refused except from loopback, and handle()
 *     checks that before anything else; the origin rules; where the
 *     credentials may live (symlinks resolved).
 * (j) A real browser (Playwright's Chromium, when the test finds it) signs in
 *     through the form, runs Flush stale sessions and signs out, each POST
 *     carrying this origin. (c) to (h) write their headers by hand, as no
 *     browser would have.
 *
 * On ee9c491 this fails (a), where /v1/monitor and the rest answer 200 with
 * debug.enabled and monitor.php exists, and everything after it: there is no
 * admin page and no admin-setup. On 1a2494a it fails (c)'s Referrer-Policy and
 * all of (j): the page sent no-referrer, so the browser sent `Origin: null`
 * with the sign-in and sameOrigin() refused it (403); no browser could sign in.
 *
 * Run: php php/tests/admin_console_test.php
 * With RETICULUM_TEST_RUNTIME=swoole the nodes run the Swoole entry instead
 * of `php -S` (tests/stubs/node_process.php), which answers with what went
 * through HttpIo only.
 * With RETICULUM_TEST_BACKEND=mysql each node keeps its data in a MySQL
 * database of its own, reticulum_admin_<random>, made at start and dropped at
 * stop, on the server RETICULUM_TEST_MYSQL_HOST and _PORT name (default
 * 127.0.0.1:3306), as RETICULUM_TEST_MYSQL_USER and _PASS (default root, no
 * password): a user who may create and drop such databases.
 * ADMIN_SRC_DIR points it at another php/src, for mutation checks.
 * ADMIN_PLAYWRIGHT_DIR is a directory with node_modules/playwright (default:
 * ../test-harnesses/distro-pipeline beside this repository); without one, (j)
 * says it was skipped.
 */
declare(strict_types=1);

require_once __DIR__ . '/stubs/node_process.php';

$src = getenv('ADMIN_SRC_DIR') ?: dirname(__DIR__) . '/src';
$deployScript = dirname(__DIR__, 2) . '/deploy.sh';

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

/**
 * One request; redirects are answers, not followed.
 *
 * @return array{status: int, headers: array<string, list<string>>, body: string}
 */
function request(string $method, string $url, array $headers = [], ?string $body = null): array
{
    $context = stream_context_create(['http' => [
        'method' => $method,
        'header' => implode("\r\n", $headers),
        'content' => $body ?? '',
        'ignore_errors' => true,
        'follow_location' => 0,
        'timeout' => 20,
    ]]);
    $response = @file_get_contents($url, false, $context);
    $lines = function_exists('http_get_last_response_headers') ? (http_get_last_response_headers() ?? []) : ($http_response_header ?? []);
    $status = 0;
    $parsed = [];
    foreach ($lines as $line) {
        if (preg_match('#^HTTP/\S+ (\d{3})#', $line, $m) === 1) {
            $status = (int) $m[1];
            $parsed = [];
            continue;
        }
        $colon = strpos($line, ':');
        if ($colon !== false) {
            $parsed[strtolower(trim(substr($line, 0, $colon)))][] = trim(substr($line, $colon + 1));
        }
    }
    return ['status' => $status, 'headers' => $parsed, 'body' => is_string($response) ? $response : ''];
}

function header1(array $response, string $name): ?string
{
    return $response['headers'][strtolower($name)][0] ?? null;
}

function jsonBody(array $response): array
{
    $decoded = json_decode($response['body'], true);
    return is_array($decoded) ? $decoded : [];
}

/** @return array{host: string, port: int, user: string, pass: string}|null the MySQL server, under RETICULUM_TEST_BACKEND=mysql */
function mysqlServer(): ?array
{
    if (getenv('RETICULUM_TEST_BACKEND') !== 'mysql') {
        return null;
    }
    return [
        'host' => getenv('RETICULUM_TEST_MYSQL_HOST') ?: '127.0.0.1',
        'port' => (int) (getenv('RETICULUM_TEST_MYSQL_PORT') ?: 3306),
        'user' => getenv('RETICULUM_TEST_MYSQL_USER') ?: 'root',
        'pass' => (string) getenv('RETICULUM_TEST_MYSQL_PASS'),
    ];
}

function mysqlPdo(array $server, ?string $dbname = null): PDO
{
    $dsn = sprintf('mysql:host=%s;port=%d;charset=utf8mb4', $server['host'], $server['port']) . ($dbname === null ? '' : ';dbname=' . $dbname);
    return new PDO($dsn, $server['user'], $server['pass'], [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]);
}

/** A TOML basic string. */
function tomlString(string $value): string
{
    return '"' . addcslashes($value, "\\\"") . '"';
}

function writeConfig(array $node, string $credentialsFile): void
{
    $mysql = mysqlServer();
    $storage = $mysql === null
        ? ['backend = "sqlite"', 'sqlite_path = "' . $node['dir'] . '/node.sqlite"']
        : [
            'backend = "mysql"',
            'mysql_host = ' . tomlString($mysql['host']),
            'mysql_port = ' . $mysql['port'],
            'mysql_dbname = ' . tomlString($node['mysql_db']),
            'mysql_user = ' . tomlString($mysql['user']),
            'mysql_pass = ' . tomlString($mysql['pass']),
        ];
    $lines = [
        'host_url = "' . $node['base'] . '"',
        '[storage]',
        ...$storage,
        'log_path = "' . $node['dir'] . '/router.log"',
        // On, so that the old operator routes would answer if they existed.
        '[debug]',
        'enabled = true',
        '[admin]',
        'credentials_file = "' . $credentialsFile . '"',
    ];
    if ($node['peer_url'] !== null) {
        array_push($lines, '[interfaces]', '[[B]]', 'node_url = "' . $node['peer_url'] . '"');
    }
    if (getenv('RETICULUM_TEST_RUNTIME') === 'swoole') {
        // As startNodeProcess() writes it; (b) rewrites the file while the node runs.
        array_push($lines, '[swoole]', 'enable_swoole = true');
    }
    file_put_contents($node['dir'] . '/src/config.toml', implode("\n", $lines) . "\n");
}

/** @return array{base: string, dir: string, peer_url: ?string, credentials: string, proc: resource} */
function startNode(string $src, int $port, ?string $peerUrl): array
{
    $dir = sys_get_temp_dir() . '/reticulum-admin-' . bin2hex(random_bytes(4));
    copyTree($src, $dir . '/src');
    $node = [
        'base' => 'http://127.0.0.1:' . $port,
        'dir' => $dir,
        'peer_url' => $peerUrl,
        // The layout admin-setup uses by default (~/.reticulum-post), in a
        // home of the test's own.
        'credentials' => $dir . '/home/.reticulum-post/admin.json',
        'mysql_db' => 'reticulum_admin_' . bin2hex(random_bytes(4)),
    ];
    $mysql = mysqlServer();
    if ($mysql !== null) {
        mysqlPdo($mysql)->exec('CREATE DATABASE `' . $node['mysql_db'] . '`');
    }
    writeConfig($node, $node['credentials']);
    $node['proc'] = startNodeProcess($dir . '/src', $port, $dir . '/server.out');
    // Readiness is the server answering; the bound only turns a server that
    // never starts into a test failure instead of a hang.
    for ($i = 0; $i < 50 && request('GET', $node['base'] . '/health')['status'] !== 200; $i++) {
        usleep(100000);
    }
    return $node;
}

function stopNode(array $node): void
{
    proc_terminate($node['proc']);
    proc_close($node['proc']);
    exec('rm -rf ' . escapeshellarg($node['dir']));
    $mysql = mysqlServer();
    if ($mysql !== null) {
        mysqlPdo($mysql)->exec('DROP DATABASE IF EXISTS `' . $node['mysql_db'] . '`');
    }
}

/**
 * `php index.php <args>` on the node's copy, as on a host; stdin is a pipe,
 * as it is when the password is piped in over ssh.
 *
 * @return array{code: int, out: string, err: string}
 */
function cli(array $node, array $args, string $stdin = ''): array
{
    $proc = proc_open(
        array_merge([PHP_BINARY, $node['dir'] . '/src/index.php'], $args),
        [0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']],
        $pipes
    );
    fwrite($pipes[0], $stdin);
    fclose($pipes[0]);
    $out = (string) stream_get_contents($pipes[1]);
    $err = (string) stream_get_contents($pipes[2]);
    fclose($pipes[1]);
    fclose($pipes[2]);
    return ['code' => proc_close($proc), 'out' => $out, 'err' => $err];
}

function db(array $node): PDO
{
    $mysql = mysqlServer();
    if ($mysql !== null) {
        return mysqlPdo($mysql, $node['mysql_db']);
    }
    $pdo = new PDO('sqlite:' . $node['dir'] . '/node.sqlite');
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    return $pdo;
}

/** @return list<array> the node's interface rows naming a peer URL */
function peerRows(array $node, string $peerUrl): array
{
    $stmt = db($node)->prepare(
        'SELECT interface_id, session_token, peer_interface_id, peer_session_token, status FROM interfaces WHERE peer_url = :u ORDER BY created_at'
    );
    $stmt->execute([':u' => $peerUrl]);
    return $stmt->fetchAll(PDO::FETCH_ASSOC);
}

function interfaceStatus(array $node, string $interfaceId): ?string
{
    $stmt = db($node)->prepare('SELECT status FROM interfaces WHERE interface_id = :id');
    $stmt->execute([':id' => $interfaceId]);
    $status = $stmt->fetchColumn();
    return $status === false ? null : (string) $status;
}

/** @return list<string> every credential either node holds */
function credentialsHeld(array ...$nodes): array
{
    $secrets = [];
    foreach ($nodes as $node) {
        foreach (db($node)->query('SELECT session_token, peer_session_token FROM interfaces')->fetchAll(PDO::FETCH_NUM) as $row) {
            foreach ($row as $value) {
                if (is_string($value) && strlen($value) >= 16) {
                    $secrets[] = $value;
                }
            }
        }
    }
    return array_values(array_unique($secrets));
}

/** An exchange as a peer (or anyone holding its credentials) makes it. */
function exchange(array $node, string $interfaceId, string $token): int
{
    return request('POST', $node['base'] . '/v1/interfaces/exchange', ['Content-Type: application/json'], json_encode([
        'interface_id' => $interfaceId, 'session_token' => $token, 'packets' => [], 'max_packets' => 1,
    ]))['status'];
}

function registerBrowser(array $node): array
{
    return jsonBody(request('POST', $node['base'] . '/v1/interfaces/register', ['Content-Type: application/json'], json_encode([
        'name' => 'Retichat Web', 'bitrate' => 1000000, 'mtu' => 500, 'metadata' => ['client' => 'rns-js', 'mode' => 1],
    ])));
}

function sessionCookie(array $response): ?string
{
    foreach ($response['headers']['set-cookie'] ?? [] as $line) {
        if (str_starts_with($line, 'reticulum_admin=')) {
            return explode(';', $line, 2)[0];
        }
    }
    return null;
}

function b64url(string $bytes): string
{
    return rtrim(strtr(base64_encode($bytes), '+/', '-_'), '=');
}

/** The key the node signs with: derived from the stored hash. */
function signingKey(string $passwordHash): string
{
    return hash_hmac('sha256', 'reticulum-post admin session v1', $passwordHash, true);
}

/** @return array{cookie: string, payload: string} a session cookie signed as the node signs one */
function forgeSession(string $passwordHash, array $claims): array
{
    $payload = b64url(json_encode($claims, JSON_THROW_ON_ERROR));
    return [
        'cookie' => 'reticulum_admin=' . $payload . '.' . b64url(hash_hmac('sha256', 'session|' . $payload, signingKey($passwordHash), true)),
        'payload' => $payload,
    ];
}

function action(array $node, string $cookie, string $token, string $path, array $body, array $headers = []): array
{
    return request('POST', $node['base'] . $path, array_merge([
        'Cookie: ' . $cookie,
        'Content-Type: application/json',
        'X-Admin-Csrf: ' . $token,
        'Origin: ' . $node['base'],
        'Sec-Fetch-Site: same-origin',
    ], $headers), json_encode($body));
}

function signIn(array $node, string $username, string $password, array $headers = []): array
{
    return request('POST', $node['base'] . '/admin/login', array_merge([
        'Content-Type: application/x-www-form-urlencoded',
        'Origin: ' . $node['base'],
        'Sec-Fetch-Site: same-origin',
    ], $headers), http_build_query(['username' => $username, 'password' => $password]));
}

$password = 'correct horse battery staple';
$portA = freePort();
$portB = freePort();
$b = startNode($src, $portB, null);
$a = startNode($src, $portA, $b['base']);

echo "(a) before admin-setup there is no admin page, and the old operator routes are gone\n";
$unknownGet = request('GET', $a['base'] . '/no-such-path');
$unknownPost = request('POST', $a['base'] . '/no-such-path', ['Content-Type: application/x-www-form-urlencoded'], 'username=james');
foreach (['GET /admin', 'GET /admin/', 'GET /admin/data', 'GET /admin/debug', 'POST /admin/login', 'POST /admin/maintenance', 'POST /admin/peers/rotate'] as $route) {
    [$method, $path] = explode(' ', $route);
    $r = request($method, $a['base'] . $path, ['Content-Type: application/x-www-form-urlencoded'], $method === 'POST' ? http_build_query(['username' => 'james', 'password' => $password]) : null);
    $unknown = $method === 'GET' ? $unknownGet : $unknownPost;
    check("$route answers as an unknown path does: 404", $r['status'] === 404 && $r['body'] === $unknown['body'], $r['status'] . ' ' . substr($r['body'], 0, 80));
}
$browser = registerBrowser($a);
foreach (['GET /v1/monitor', 'GET /v1/monitor/data', 'GET /v1/monitor/json', 'GET /debug', 'POST /v1/monitor/clear', 'POST /v1/maintenance/flush'] as $route) {
    [$method, $path] = explode(' ', $route);
    $r = request($method, $a['base'] . $path, ['Content-Type: application/json'], $method === 'POST' ? '{"confirm":"YES","force":true}' : null);
    check("$route answers 404, with debug.enabled on", $r['status'] === 404, $r['status'] . ' ' . substr($r['body'], 0, 80));
}
check('and they left the database alone: the browser registered before them is still online',
    isset($browser['interface_id']) && interfaceStatus($a, (string) $browser['interface_id']) === 'online');
check('monitor.php is gone from php/src', !file_exists($src . '/monitor.php'));
check('and deploy.sh RETIRED removes it from the nodes',
    preg_match('/^RETIRED=\((.*?)^\)/ms', (string) @file_get_contents($deployScript), $retired) === 1 && preg_match('/^\s*monitor\.php\s/m', $retired[1]) === 1);

echo "(b) admin-setup: only on the host, only a hash, only outside the web root\n";
$r = cli($a, ['admin-setup'], $password . "\n");
check('with the password piped in but no username it refuses', $r['code'] === 1 && str_contains($r['err'], 'Usage'), trim($r['err']));
$r = cli($a, ['admin-setup', 'ja mes'], $password . "\n");
check('a username with a space is refused', $r['code'] === 1 && !file_exists($a['credentials']), trim($r['err']));
$r = cli($a, ['admin-setup', 'james'], "elevenbytes\n");
check('a password under 12 bytes is refused', $r['code'] === 1 && !file_exists($a['credentials']), trim($r['err']));
$r = cli($a, ['admin-setup', 'james'], str_repeat('x', 73) . "\n");
check('a password over 72 bytes, of which bcrypt would check only 72, is refused', $r['code'] === 1 && !file_exists($a['credentials']), trim($r['err']));
writeConfig($a, $a['dir'] . '/src/admin.json');
$r = cli($a, ['admin-setup', 'james'], $password . "\n");
check('a credentials file in the directory the web server serves is refused',
    $r['code'] === 1 && !file_exists($a['dir'] . '/src/admin.json') && str_contains($r['err'], 'web server serves'), trim($r['err']));
writeConfig($a, $a['dir'] . '/public_html/admin.json');
$r = cli($a, ['admin-setup', 'james'], $password . "\n");
check('so is one anywhere under a public_html',
    $r['code'] === 1 && !file_exists($a['dir'] . '/public_html/admin.json') && str_contains($r['err'], 'public_html'), trim($r['err']));
writeConfig($a, $a['credentials']);
check('the refusals wrote nothing, and the page is still 404',
    !file_exists($a['credentials']) && request('GET', $a['base'] . '/admin')['status'] === 404);

$r = cli($a, ['admin-setup', 'james'], $password . "\n");
check('admin-setup james, with the password on stdin, exits 0', $r['code'] === 0, trim($r['err'] . ' ' . $r['out']));
$stored = (string) @file_get_contents($a['credentials']);
$credentials = json_decode($stored, true) ?: [];
$hash = (string) ($credentials['password_hash'] ?? '');
check('the file is mode 0600 and the directory it made 0700',
    is_file($a['credentials']) && (fileperms($a['credentials']) & 0777) === 0600 && (fileperms(dirname($a['credentials'])) & 0777) === 0700,
    is_file($a['credentials']) ? decoct(fileperms($a['credentials']) & 0777) . ' ' . decoct(fileperms(dirname($a['credentials'])) & 0777) : 'no file');
check('it holds the username and a bcrypt hash of the password',
    ($credentials['username'] ?? null) === 'james' && password_get_info($hash)['algoName'] === 'bcrypt' && password_verify($password, $hash));
check('and never the password', $stored !== '' && !str_contains($stored, $password) && !str_contains($stored, 'horse'));
check('it says where the file is and where to sign in', str_contains($r['out'], $a['credentials']) && str_contains($r['out'], $a['base'] . '/admin'), trim($r['out']));

echo "(c) the sign-in page and the sign-in\n";
$page = request('GET', $a['base'] . '/admin');
$csp = header1($page, 'content-security-policy') ?? '';
$nonce = preg_match("/'nonce-([^']+)'/", $csp, $m) === 1 ? $m[1] : '';
check('GET /admin is the sign-in form', $page['status'] === 200 && str_contains(header1($page, 'content-type') ?? '', 'text/html')
    && str_contains($page['body'], 'action="/admin/login"') && str_contains($page['body'], 'type="password"'), $page['status'] . ' ' . substr($page['body'], 0, 120));
check('with no CORS header', !isset($page['headers']['access-control-allow-origin']));
check("a CSP of default-src 'none' and the page's own nonce, and no framing",
    str_contains($csp, "default-src 'none'") && $nonce !== '' && str_contains($page['body'], 'nonce="' . $nonce . '"') && str_contains($csp, "frame-ancestors 'none'")
    && header1($page, 'x-frame-options') === 'DENY', $csp);
check('a new nonce each time', ($m2 = preg_match("/'nonce-([^']+)'/", header1(request('GET', $a['base'] . '/admin'), 'content-security-policy') ?? '', $again)) === 1 && $again[1] !== $nonce);
check('no-store, nosniff, and a referrer for this origin only (no-referrer would make a browser send Origin: null)',
    header1($page, 'cache-control') === 'no-store' && header1($page, 'x-content-type-options') === 'nosniff' && header1($page, 'referrer-policy') === 'same-origin');
$r = request('OPTIONS', $a['base'] . '/admin/data', ['Origin: http://evil.example', 'Access-Control-Request-Method: GET']);
check('a CORS preflight for an admin path is refused (404, no Allow-Origin)', $r['status'] === 404 && !isset($r['headers']['access-control-allow-origin']), (string) $r['status']);

$r = signIn($a, 'james', 'not the password');
check('a wrong password: 401, no cookie', $r['status'] === 401 && sessionCookie($r) === null && str_contains($r['body'], 'Wrong username or password'), (string) $r['status']);
$r = signIn($a, 'mallory', $password);
check('a wrong username with the right password: 401, no cookie', $r['status'] === 401 && sessionCookie($r) === null, (string) $r['status']);
$r = signIn($a, 'james', $password, ['Origin: http://evil.example']);
check('the right ones from another origin: 403, no cookie', $r['status'] === 403 && sessionCookie($r) === null, (string) $r['status']);
$r = request('POST', $a['base'] . '/admin/login', ['Content-Type: application/x-www-form-urlencoded', 'Sec-Fetch-Site: cross-site'],
    http_build_query(['username' => 'james', 'password' => $password]));
check('or from another site, by Sec-Fetch-Site: 403, no cookie', $r['status'] === 403 && sessionCookie($r) === null, (string) $r['status']);
$r = signIn($a, 'james', $password);
$cookie = sessionCookie($r) ?? '';
$setCookie = implode(' | ', $r['headers']['set-cookie'] ?? []);
check('the right ones: 303 to /admin with a session cookie', $r['status'] === 303 && header1($r, 'location') === '/admin' && $cookie !== '', $r['status'] . ' ' . $setCookie);
check('HttpOnly, SameSite=Strict, Path=/admin, and an expiry',
    stripos($setCookie, 'HttpOnly') !== false && stripos($setCookie, 'SameSite=Strict') !== false
    && stripos($setCookie, 'path=/admin') !== false && stripos($setCookie, 'expires=') !== false, $setCookie);

echo "(d) peering: Reconnect and Rotate for the configured peer\n";
$console = request('GET', $a['base'] . '/admin', ['Cookie: ' . $cookie]);
$token = preg_match('/data-token="([^"]+)"/', $console['body'], $t) === 1 ? html_entity_decode($t[1]) : '';
check('signed in, GET /admin is the console, with the session\'s action token',
    $console['status'] === 200 && $token !== '' && str_contains($console['body'], 'Sign out') && !isset($console['headers']['access-control-allow-origin']), (string) $console['status']);
$live = jsonBody(request('GET', $a['base'] . '/admin/data', ['Cookie: ' . $cookie]));
check('the live view lists the configured peer B, with no row yet',
    ($live['peers'][0]['name'] ?? null) === 'B' && ($live['peers'][0]['rows'] ?? null) === 0 && array_key_exists('interface', $live['peers'][0] ?? []) && $live['peers'][0]['interface'] === null,
    json_encode($live['peers'] ?? null));
$r = action($a, $cookie, $token, '/admin/peers/reconnect', ['peer' => 'B']);
$rowsA = peerRows($a, $b['base']);
$rowsB = peerRows($b, $a['base']);
check('Reconnect: 200 connected, one row at each end', $r['status'] === 200 && (jsonBody($r)['status'] ?? null) === 'connected'
    && count($rowsA) === 1 && count($rowsB) === 1, $r['status'] . ' ' . $r['body']);
$rowA = $rowsA[0] ?? [];
$rowB = $rowsB[0] ?? [];
$live = jsonBody(request('GET', $a['base'] . '/admin/data', ['Cookie: ' . $cookie]));
check('the live view shows B live, on that row', ($live['peers'][0]['live'] ?? null) === true && ($live['peers'][0]['rows'] ?? null) === 1
    && ($live['peers'][0]['interface']['interface_id'] ?? null) === ($rowA['interface_id'] ?? '-'), json_encode($live['peers'] ?? null));
$r = action($a, $cookie, $token, '/admin/peers/reconnect', ['peer' => 'B']);
check('Reconnect again leaves the live row alone: already_connected, same tokens at both ends',
    $r['status'] === 200 && (jsonBody($r)['status'] ?? null) === 'already_connected'
    && (peerRows($a, $b['base'])[0]['session_token'] ?? null) === ($rowA['session_token'] ?? '-')
    && (peerRows($b, $a['base'])[0]['session_token'] ?? null) === ($rowB['session_token'] ?? '-'), $r['body']);

$r = action($a, $cookie, $token, '/admin/peers/rotate', ['peer' => 'B']);
$rotated = jsonBody($r);
$newRowsA = peerRows($a, $b['base']);
$newRowsB = peerRows($b, $a['base']);
$newA = $newRowsA[0] ?? [];
$newB = $newRowsB[0] ?? [];
check('Rotate: 200 connected, naming the row it replaced', $r['status'] === 200 && ($rotated['status'] ?? null) === 'connected'
    && ($rotated['previous_interface_id'] ?? null) === ($rowA['interface_id'] ?? '-'), $r['status'] . ' ' . $r['body']);
check('A holds one row for B, with a new id and a new token', count($newRowsA) === 1
    && ($newA['interface_id'] ?? null) !== ($rowA['interface_id'] ?? null) && ($newA['session_token'] ?? null) !== ($rowA['session_token'] ?? null));
check('B keeps its row\'s id, with a new token, pointing at A\'s new row', count($newRowsB) === 1
    && ($newB['interface_id'] ?? null) === ($rowB['interface_id'] ?? '-') && ($newB['session_token'] ?? null) !== ($rowB['session_token'] ?? null)
    && ($newB['peer_interface_id'] ?? null) === ($newA['interface_id'] ?? '-'));
check('the old credentials get 401 at both ends',
    exchange($a, (string) ($rowB['peer_interface_id'] ?? ''), (string) ($rowB['peer_session_token'] ?? '')) === 401
    && exchange($b, (string) ($rowA['peer_interface_id'] ?? ''), (string) ($rowA['peer_session_token'] ?? '')) === 401);
check('the new ones 200 at both ends',
    exchange($a, (string) ($newB['peer_interface_id'] ?? ''), (string) ($newB['peer_session_token'] ?? '')) === 200
    && exchange($b, (string) ($newA['peer_interface_id'] ?? ''), (string) ($newA['peer_session_token'] ?? '')) === 200);

// A second row naming B, as README's step 1 says to stop at: a copy of A's
// row under another id and token of the same length (MySQL's columns hold
// no more).
$pdo = db($a);
$select = $pdo->prepare('SELECT * FROM interfaces WHERE interface_id = :id');
$select->execute([':id' => (string) ($newA['interface_id'] ?? '')]);
$twin = $select->fetch(PDO::FETCH_ASSOC) ?: [];
$twin['interface_id'] = 'twin' . substr((string) ($twin['interface_id'] ?? ''), 4);
$twin['session_token'] = 'twin' . substr((string) ($twin['session_token'] ?? ''), 4);
$columns = array_keys($twin);
$pdo->prepare('INSERT INTO interfaces (`' . implode('`, `', $columns) . '`) VALUES (:c' . implode(', :c', array_keys($columns)) . ')')
    ->execute(array_combine(array_map(static fn (int $i): string => ':c' . $i, array_keys($columns)), array_values($twin)));
$r = action($a, $cookie, $token, '/admin/peers/rotate', ['peer' => 'B']);
check('with two rows naming B, Rotate is refused (409) and deletes neither',
    $r['status'] === 409 && (jsonBody($r)['status'] ?? null) === 'refused_duplicate_rows' && count(peerRows($a, $b['base'])) === 2, $r['status'] . ' ' . $r['body']);
check('and the live view counts the two rows', (jsonBody(request('GET', $a['base'] . '/admin/data', ['Cookie: ' . $cookie]))['peers'][0]['rows'] ?? null) === 2);
$pdo->exec("DELETE FROM interfaces WHERE interface_id LIKE 'twin%'");
$pdo = null;
$r = action($a, $cookie, $token, '/admin/peers/rotate', ['peer' => 'Nope']);
$r2 = action($a, $cookie, $token, '/admin/peers/reconnect', ['peer' => 'Nope']);
check('a name [interfaces] does not configure is 404 not_configured, for both actions',
    $r['status'] === 404 && (jsonBody($r)['status'] ?? null) === 'not_configured' && $r2['status'] === 404, $r['status'] . '/' . $r2['status']);
check('no name at all is 400', action($a, $cookie, $token, '/admin/peers/rotate', [])['status'] === 400);
check('B still holds one row for A', count(peerRows($b, $a['base'])) === 1);

echo "(e) the live view and the debug report: signed in only, and no credential in them\n";
$data = request('GET', $a['base'] . '/admin/data', ['Cookie: ' . $cookie]);
$debug = request('GET', $a['base'] . '/admin/debug', ['Cookie: ' . $cookie]);
$live = jsonBody($data);
check('GET /admin/data: 200 JSON, no CORS header, no-store', $data['status'] === 200 && str_starts_with(header1($data, 'content-type') ?? '', 'application/json')
    && !isset($data['headers']['access-control-allow-origin']) && header1($data, 'cache-control') === 'no-store', (string) $data['status']);
check('it carries what the page draws', isset($live['generated_at'], $live['node'], $live['queues'], $live['peers'], $live['interfaces'], $live['outbound_pending'],
    $live['recent_inbound'], $live['recent_outbound'], $live['recent_batches']) && array_key_exists('build', $live['node'] ?? []), implode(',', array_keys($live)));
check('the browser is among its connections, with rx/tx', in_array($browser['interface_id'] ?? '-', array_column($live['interfaces'] ?? [], 'interface_id'), true)
    && isset(($live['interfaces'] ?? [[]])[0]['rx_bytes'], ($live['interfaces'] ?? [[]])[0]['tx_bytes']));
check('GET /admin/debug: 200 with the report', $debug['status'] === 200 && isset(jsonBody($debug)['report']['recent_interfaces']), (string) $debug['status']);
// The browser's token and the peering's two (each node holds the other's as
// peer_session_token), read from both databases.
$secrets = credentialsHeld($a, $b);
$leaks = array_values(array_filter($secrets, static fn (string $s): bool => str_contains($data['body'], $s) || str_contains($debug['body'], $s)));
check('no session_token or peer_session_token held by either node appears in either (' . count($secrets) . ' checked)',
    array_diff([(string) ($browser['session_token'] ?? '-'), (string) ($newA['session_token'] ?? '-'), (string) ($newB['session_token'] ?? '-')], $secrets) === []
    && $leaks === [], implode(',', array_map(static fn (string $s): string => substr($s, 0, 8), $leaks)));
foreach (['/admin/data', '/admin/debug'] as $path) {
    $r = request('GET', $a['base'] . $path);
    check("signed out, GET $path is 401 and carries nothing", $r['status'] === 401 && !str_contains($r['body'], 'interface'), $r['status'] . ' ' . $r['body']);
}
$now = time();
$good = forgeSession($hash, ['u' => 'james', 'iat' => $now, 'exp' => $now + 600, 'n' => 'test']);
check('a cookie signed as the node signs is accepted (so the bad ones below differ only where named)',
    request('GET', $a['base'] . '/admin/data', ['Cookie: ' . $good['cookie']])['status'] === 200);
$otherKey = password_hash('another password entirely', PASSWORD_BCRYPT, ['cost' => 4]);
$bad = [
    'that has expired' => forgeSession($hash, ['u' => 'james', 'iat' => $now - 7300, 'exp' => $now - 100, 'n' => 'test'])['cookie'],
    'for another user' => forgeSession($hash, ['u' => 'mallory', 'iat' => $now, 'exp' => $now + 600, 'n' => 'test'])['cookie'],
    'issued in the future' => forgeSession($hash, ['u' => 'james', 'iat' => $now + 3600, 'exp' => $now + 7200, 'n' => 'test'])['cookie'],
    'with its signature altered' => substr($cookie, 0, -2) . (str_ends_with($cookie, 'AA') ? 'BB' : 'AA'),
    'signed with another key' => forgeSession($otherKey, ['u' => 'james', 'iat' => $now, 'exp' => $now + 600, 'n' => 'test'])['cookie'],
];
foreach ($bad as $what => $badCookie) {
    check("a cookie $what is signed out (401)", request('GET', $a['base'] . '/admin/data', ['Cookie: ' . $badCookie])['status'] === 401);
}

echo "(f) an action needs this origin and the session's token\n";
$victim = registerBrowser($a);
$victimId = (string) ($victim['interface_id'] ?? '');
// A forced flush counts a browser seen in this second as fresh.
sleep(1);
$otherToken = b64url(hash_hmac('sha256', 'csrf|' . $good['payload'], signingKey($hash), true));
$attempts = [
    'no token' => ['Cookie: ' . $cookie, 'Content-Type: application/json', 'Origin: ' . $a['base']],
    'a wrong token' => ['Cookie: ' . $cookie, 'Content-Type: application/json', 'Origin: ' . $a['base'], 'X-Admin-Csrf: ' . strrev($token)],
    'another session\'s token' => ['Cookie: ' . $cookie, 'Content-Type: application/json', 'Origin: ' . $a['base'], 'X-Admin-Csrf: ' . $otherToken],
    'the token, from another origin' => ['Cookie: ' . $cookie, 'Content-Type: application/json', 'Origin: http://evil.example', 'X-Admin-Csrf: ' . $token],
    'the token, from another site' => ['Cookie: ' . $cookie, 'Content-Type: application/json', 'Sec-Fetch-Site: same-site', 'X-Admin-Csrf: ' . $token],
    'the token and no session' => ['Content-Type: application/json', 'Origin: ' . $a['base'], 'X-Admin-Csrf: ' . $token],
];
foreach ($attempts as $what => $headers) {
    $r = request('POST', $a['base'] . '/admin/maintenance', $headers, '{"force":true}');
    $expected = $what === 'the token and no session' ? 401 : 403;
    check("a forced flush with $what: $expected, and the browser stays online",
        $r['status'] === $expected && interfaceStatus($a, $victimId) === 'online', $r['status'] . ' ' . interfaceStatus($a, $victimId));
}
$r = action($a, $cookie, $token, '/admin/peers/rotate', ['peer' => 'B'], ['Origin: http://evil.example']);
check('a Rotate from another origin: 403, and A keeps its row', $r['status'] === 403 && (peerRows($a, $b['base'])[0]['interface_id'] ?? null) === ($newA['interface_id'] ?? '-'));
$r = action($a, $cookie, $token, '/admin/maintenance', ['force' => false]);
check('a flush with the token: 200 and maintenance\'s summary; a fresh browser stays online',
    $r['status'] === 200 && (jsonBody($r)['force'] ?? null) === false && is_array(jsonBody($r)['flushed'] ?? null) && interfaceStatus($a, $victimId) === 'online', $r['status'] . ' ' . substr($r['body'], 0, 120));
$r = action($a, $cookie, $token, '/admin/maintenance', ['force' => true]);
check('a forced flush with the token: 200, and the browser is offline', $r['status'] === 200 && (jsonBody($r)['force'] ?? null) === true
    && interfaceStatus($a, $victimId) === 'offline', $r['status'] . ' ' . interfaceStatus($a, $victimId));
check('it left the peering\'s row in place', (peerRows($a, $b['base'])[0]['interface_id'] ?? null) === ($newA['interface_id'] ?? '-'));

echo "(g) the sign-in throttle\n";
$codes = [];
for ($i = 1; $i <= 5; $i++) {
    $codes[] = signIn($a, 'james', 'wrong guess ' . $i)['status'];
}
check('five wrong passwords from one address: 401 each', $codes === [401, 401, 401, 401, 401], implode(',', $codes));
$r = signIn($a, 'james', $password);
check('the sixth attempt is 429 with Retry-After and no cookie, though the password is right',
    $r['status'] === 429 && (int) (header1($r, 'retry-after') ?? 0) > 0 && sessionCookie($r) === null, $r['status'] . ' ' . (header1($r, 'retry-after') ?? '-'));
$r = cli($a, ['admin-setup', 'james'], $password . "\n");
$r2 = signIn($a, 'james', $password);
check('admin-setup lifts it: the right password signs in again', $r['code'] === 0 && $r2['status'] === 303 && sessionCookie($r2) !== null, $r2['status'] . ' ' . trim($r['err']));
// The hundred-an-hour count is every address's together, so only
// admin-setup's clear lifts it: an address's own count is keyed by the
// password hash and goes with the old one anyway.
db($a)->exec("DELETE FROM transport_state WHERE state_key = 'admin-signin:tries:all'");
db($a)->prepare("INSERT INTO transport_state (state_key, state_value, updated_at) VALUES ('admin-signin:tries:all', '100', :now)")->execute([':now' => time()]);
$r = signIn($a, 'james', $password);
check('past a hundred attempts an hour from all addresses, one that signed in within 30 days still may', $r['status'] === 303, (string) $r['status']);
db($a)->exec("DELETE FROM transport_state WHERE state_key LIKE 'admin-signin:known:%'");
$r = signIn($a, 'james', $password);
check('...and one that has not gets 429 with Retry-After and no cookie, though the password is right',
    $r['status'] === 429 && (int) (header1($r, 'retry-after') ?? 0) > 0 && sessionCookie($r) === null, $r['status'] . ' ' . (header1($r, 'retry-after') ?? '-'));
$r = cli($a, ['admin-setup', 'james'], $password . "\n");
$r2 = signIn($a, 'james', $password);
$cookie2 = sessionCookie($r2) ?? '';
check('admin-setup lifts that too', $r['code'] === 0 && $r2['status'] === 303 && $cookie2 !== '', $r2['status'] . ' ' . trim($r['err']));

echo "(h) admin-setup again, Sign out, admin-remove\n";
check('admin-setup again signed out the session from before it', request('GET', $a['base'] . '/admin/data', ['Cookie: ' . $cookie])['status'] === 401);
check('and the forged cookie with it', request('GET', $a['base'] . '/admin/data', ['Cookie: ' . $good['cookie']])['status'] === 401);
check('the new session answers', request('GET', $a['base'] . '/admin/data', ['Cookie: ' . $cookie2])['status'] === 200);
$r = request('POST', $a['base'] . '/admin/logout', ['Cookie: ' . $cookie2, 'Origin: http://evil.example']);
check('Sign out from another origin is refused (403)', $r['status'] === 403 && sessionCookie($r) === null);
$r = request('POST', $a['base'] . '/admin/logout', ['Cookie: ' . $cookie2, 'Origin: ' . $a['base']]);
$dropped = implode(' | ', $r['headers']['set-cookie'] ?? []);
check('Sign out: 303 to /admin, telling the browser to drop the cookie', $r['status'] === 303 && header1($r, 'location') === '/admin'
    && str_contains($dropped, 'reticulum_admin=deleted') && stripos($dropped, 'Max-Age=0') !== false, $dropped);
$r = cli($a, ['admin-remove']);
check('admin-remove deletes the file and says so', $r['code'] === 0 && !file_exists($a['credentials']) && str_contains($r['out'], 'Removed'), trim($r['out'] . $r['err']));
check('the page is 404 again, and the session with it',
    request('GET', $a['base'] . '/admin')['status'] === 404 && request('GET', $a['base'] . '/admin/data', ['Cookie: ' . $cookie2])['status'] === 404);
check('B, never set up, answers 404', request('GET', $b['base'] . '/admin')['status'] === 404 && request('GET', $b['base'] . '/admin/data')['status'] === 404);
stopNode($a);
stopNode($b);

echo "(i) on samples: HTTPS only, this origin only, credentials outside the web root\n";
require_once $src . '/index.php';
$secure = [
    'HTTPS on' => [['HTTPS' => 'on', 'REMOTE_ADDR' => '203.0.113.5'], true],
    'REQUEST_SCHEME https' => [['REQUEST_SCHEME' => 'https', 'REMOTE_ADDR' => '203.0.113.5'], true],
    'plain HTTP from another machine' => [['REMOTE_ADDR' => '203.0.113.5'], false],
    'HTTPS off' => [['HTTPS' => 'off', 'REMOTE_ADDR' => '203.0.113.5'], false],
    'X-Forwarded-Proto, which anyone can send' => [['HTTP_X_FORWARDED_PROTO' => 'https', 'REMOTE_ADDR' => '203.0.113.5'], false],
    'plain HTTP from 127.0.0.1' => [['REMOTE_ADDR' => '127.0.0.1'], true],
    'plain HTTP from ::1' => [['REMOTE_ADDR' => '::1'], true],
];
foreach ($secure as $what => [$server, $expected]) {
    check("secure request, $what: " . ($expected ? 'yes' : 'no'), \ReticulumPhp\AdminConsole::secureRequest($server) === $expected);
}
$handle = new ReflectionMethod(\ReticulumPhp\AdminConsole::class, 'handle');
$lines = array_slice(file($handle->getFileName()) ?: [], $handle->getStartLine() - 1, $handle->getEndLine() - $handle->getStartLine() + 1);
$body = implode('', $lines);
$secureAt = strpos($body, 'self::secureRequest($server)');
check('handle() refuses an insecure request before it reads a session or routes',
    $secureAt !== false && $secureAt < (int) strpos($body, '$this->session(') && $secureAt < (int) strpos($body, "'/admin/login'"));
$origins = [
    'the same origin over HTTPS' => [['HTTPS' => 'on', 'HTTP_HOST' => 'retichat.com', 'HTTP_ORIGIN' => 'https://retichat.com', 'HTTP_SEC_FETCH_SITE' => 'same-origin'], true],
    'an http origin for an https page' => [['HTTPS' => 'on', 'HTTP_HOST' => 'retichat.com', 'HTTP_ORIGIN' => 'http://retichat.com'], false],
    'a subdomain' => [['HTTPS' => 'on', 'HTTP_HOST' => 'retichat.com', 'HTTP_ORIGIN' => 'https://chat.retichat.com'], false],
    'origin "null"' => [['HTTPS' => 'on', 'HTTP_HOST' => 'retichat.com', 'HTTP_ORIGIN' => 'null'], false],
    'Sec-Fetch-Site same-site' => [['HTTPS' => 'on', 'HTTP_HOST' => 'retichat.com', 'HTTP_SEC_FETCH_SITE' => 'same-site'], false],
    'neither header (not a browser; the token still applies)' => [['HTTPS' => 'on', 'HTTP_HOST' => 'retichat.com'], true],
];
foreach ($origins as $what => [$server, $expected]) {
    check("same origin, $what: " . ($expected ? 'yes' : 'no'), \ReticulumPhp\AdminConsole::sameOrigin($server) === $expected);
}
$root = sys_get_temp_dir() . '/reticulum-admin-placement-' . bin2hex(random_bytes(4));
mkdir($root . '/home/public_html/reticulum', 0700, true);
mkdir($root . '/served', 0700, true);
symlink($root . '/served', $root . '/link');
$placements = [
    'in the home, beside public_html' => [$root . '/home/.reticulum-post/admin.json', [$root . '/home/public_html/reticulum'], null],
    'under public_html, outside the node' => [$root . '/home/public_html/admin.json', [$root . '/home/public_html/reticulum'], 'public_html'],
    'in the node\'s directory' => [$root . '/served/admin.json', [$root . '/served'], 'web server serves'],
    'in the node\'s directory, by way of a symlink' => [$root . '/served/admin.json', [$root . '/link'], 'web server serves'],
    'beside it, sharing a prefix' => [$root . '/served2/admin.json', [$root . '/served'], null],
    'a relative path' => ['admin.json', [$root . '/served'], 'absolute'],
];
foreach ($placements as $what => [$path, $served, $expected]) {
    $problem = \ReticulumPhp\AdminCredentials::placementProblem($path, $served);
    check("credentials $what: " . ($expected === null ? 'allowed' : 'refused'),
        $expected === null ? $problem === null : is_string($problem) && str_contains($problem, $expected), (string) $problem);
}
exec('rm -rf ' . escapeshellarg($root));

echo "(j) a real browser: the sign-in form, an action, Sign out\n";
$playwrightDir = getenv('ADMIN_PLAYWRIGHT_DIR') ?: dirname(__DIR__, 3) . '/test-harnesses/distro-pipeline';
$nodeBinary = trim((string) shell_exec('command -v node'));
if ($nodeBinary === '' || !is_dir($playwrightDir . '/node_modules/playwright')) {
    echo "  skipped: no node, or no node_modules/playwright in $playwrightDir (set ADMIN_PLAYWRIGHT_DIR)\n";
} else {
    $c = startNode($src, freePort(), null);
    $r = cli($c, ['admin-setup', 'james'], $password . "\n");
    check('admin-setup on a fresh node', $r['code'] === 0, trim($r['err']));
    // The password goes in on stdin, not argv.
    $proc = proc_open(
        [$nodeBinary, __DIR__ . '/admin_console_browser.cjs', $playwrightDir, $c['base'], 'james'],
        [0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['file', $c['dir'] . '/browser.err', 'w']],
        $pipes
    );
    fwrite($pipes[0], $password . "\n");
    fclose($pipes[0]);
    $out = (string) stream_get_contents($pipes[1]);
    fclose($pipes[1]);
    proc_close($proc);
    $lines = array_values(array_filter(explode("\n", trim($out))));
    $seen = json_decode((string) end($lines), true) ?: [];
    $detail = trim($out . ' ' . (string) @file_get_contents($c['dir'] . '/browser.err'));
    check('the sign-in form posts with this origin, not "null", and signs in (303)',
        ($seen['signIn']['origin'] ?? null) === $c['base'] && ($seen['signIn']['status'] ?? null) === 303, $detail);
    check('the console loads', ($seen['console'] ?? false) === true, $detail);
    check('Flush stale sessions posts with this origin and runs (200)',
        ($seen['action']['origin'] ?? null) === $c['base'] && ($seen['action']['status'] ?? null) === 200, $detail);
    check('Sign out posts with this origin, answers 303 and leaves the sign-in form and no cookie',
        ($seen['signOut']['origin'] ?? null) === $c['base'] && ($seen['signOut']['status'] ?? null) === 303
        && ($seen['signedOut'] ?? false) === true && ($seen['cookieLeft'] ?? true) === false, $detail);
    stopNode($c);
}

echo "\n$pass passed, $fail failed\n";
exit($fail === 0 ? 0 : 1);
