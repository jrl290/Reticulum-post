<?php
/**
 * REGISTRATION-STAGE1.md §3, §5, §7, §8, §10, §11 and §12 as a client sees
 * them, on real nodes (a copy of php/src under `php -S`, each with its own
 * SQLite), driven with PHP streams.
 *
 * What only the HTTP layer can show: the challenge by GET and POST, with
 * Cache-Control: no-store; /health's hash_only_challenges moved by a POST by
 * hash, not by key or GET; every refusal body {"error", "message"}; the
 * register answer as sent; /exchange, /tx, /poll and /goodbye answering 409
 * and 401 as §7 says, register and challenge never; [registration] read from
 * config.toml; and no log line holding a token, signature, challenge or the
 * node secret.
 *
 * Before Stage 1 there is no challenge route.
 *
 * Run: php php/tests/registration_http_test.php
 */
declare(strict_types=1);

require_once __DIR__ . '/stubs/registration_fixture.php';
require_once __DIR__ . '/stubs/node_process.php';

const SUPERSEDED_MESSAGE = 'This identity connected from another tab or device. Reload to connect here.';

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
        echo "  FAIL $label" . ($detail !== '' ? "\n         $detail" : '') . "\n";
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

/**
 * A free loopback port the OS hands out, never one the private staging
 * chain uses (8897-8899) and never one something already listens on.
 */
function freePort(): int
{
    for ($attempt = 0; $attempt < 20; $attempt++) {
        $server = stream_socket_server('tcp://127.0.0.1:0', $errno, $errstr);
        $name = (string) stream_socket_get_name($server, false);
        fclose($server);
        $port = (int) substr($name, strrpos($name, ':') + 1);
        if (in_array($port, [8897, 8898, 8899], true)) {
            continue;
        }
        $held = [];
        exec('lsof -nP -iTCP:' . $port . ' -sTCP:LISTEN 2>/dev/null', $held);
        if ($held === []) {
            return $port;
        }
    }
    throw new RuntimeException('no free port');
}

/** @return array{0: int, 1: array, 2: array<string,string>, 3: string} status, decoded body, lower-cased headers, raw body */
function http(string $method, string $url, ?array $body = null, ?string $raw = null): array
{
    $context = stream_context_create(['http' => [
        'method' => $method,
        'header' => "Content-Type: application/json\r\n",
        'content' => $raw ?? ($body === null ? '' : json_encode($body)),
        'ignore_errors' => true,
        'timeout' => 5,
    ]]);
    $response = @file_get_contents($url, false, $context);
    $lines = function_exists('http_get_last_response_headers') ? (http_get_last_response_headers() ?? []) : ($http_response_header ?? []);
    $status = 0;
    $headers = [];
    foreach ($lines as $line) {
        if (preg_match('#^HTTP/\S+ (\d{3})#', $line, $m) === 1) {
            $status = (int) $m[1];
        } elseif (str_contains($line, ':')) {
            [$k, $v] = explode(':', $line, 2);
            $headers[strtolower(trim($k))] = trim($v);
        }
    }
    $decoded = is_string($response) ? json_decode($response, true) : null;

    return [$status, is_array($decoded) ? $decoded : [], $headers, is_string($response) ? $response : ''];
}

/** @return array{base: string, dir: string, proc: resource} */
function startNode(string $src, array $registrationLines = []): array
{
    $dir = sys_get_temp_dir() . '/reticulum-registration-http-' . bin2hex(random_bytes(4));
    copyTree($src, $dir . '/src');
    $port = freePort();
    file_put_contents($dir . '/src/config.toml', implode("\n", array_merge([
        'host_url = "http://127.0.0.1:' . $port . '"',
        '[storage]',
        'backend = "sqlite"',
        'sqlite_path = "' . $dir . '/node.sqlite"',
        'log_path = "' . $dir . '/router.log"',
        '[http]',
        'max_packet_bytes = 500',
    ], $registrationLines === [] ? [] : array_merge(['[registration]'], $registrationLines))) . "\n");
    $proc = startNodeProcess($dir . '/src', $port, $dir . '/server.out');
    // A test that dies before it stops this server (a fatal error, say under
    // a mutation) must not leave it running, holding its port: stop it at
    // shutdown unless it was stopped already.
    register_shutdown_function(static function () use ($proc, $dir): void {
        if (is_resource($proc)) {
            proc_terminate($proc);
            proc_close($proc);
            exec('rm -rf ' . escapeshellarg($dir));
        }
    });
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

function signedRegister(array $node, array $identity, array $metadata, string $name = 'Retichat Web'): array
{
    [, $challenge] = http('POST', $node['base'] . '/v1/interfaces/challenge', ['public_key' => $identity['public_key_hex']]);
    $body = RegFixture::body($identity, (string) ($challenge['challenge'] ?? str_repeat('0', 96)), $metadata, $name);
    [$status, $answer, , $raw] = http('POST', $node['base'] . '/v1/interfaces/register', $body);

    return [$status, $answer, $body, $raw];
}

function legacyRegister(array $node, array $metadata, string $name = 'Retichat Web'): array
{
    return http('POST', $node['base'] . '/v1/interfaces/register', ['name' => $name, 'bitrate' => 1000000, 'mtu' => 500, 'metadata' => $metadata]);
}

function exchange(array $node, string $path, string $id, string $token): array
{
    return http('POST', $node['base'] . $path, ['interface_id' => $id, 'session_token' => $token, 'packets' => [], 'max_packets' => 1]);
}

function registrationHealth(array $node): array
{
    return (array) (http('GET', $node['base'] . '/health')[1]['registration'] ?? []);
}

function nodeRow(array $node, string $id): array
{
    $st = (new PDO('sqlite:' . $node['dir'] . '/node.sqlite'))->prepare('SELECT status, session_token FROM interfaces WHERE interface_id = :i');
    $st->execute([':i' => $id]);

    return $st->fetch(PDO::FETCH_ASSOC) ?: [];
}

const ENDPOINTS = ['/v1/interfaces/exchange', '/v1/interfaces/tx', '/v1/interfaces/poll', '/v1/interfaces/goodbye'];

$node = startNode($src);
$identity = RegFixture::identity();

echo "(1) the challenge (§3)\n";
[$status, $body, $headers] = http('GET', $node['base'] . '/v1/interfaces/challenge?public_key=' . $identity['public_key_hex']);
check('GET /v1/interfaces/challenge?public_key= -> 200', $status === 200, json_encode($body));
check('...Cache-Control: no-store', ($headers['cache-control'] ?? '') === 'no-store');
check('...{status, version, identity_hash, challenge}, 96 hex', array_keys($body) === ['status', 'version', 'identity_hash', 'challenge']
    && $body['status'] === 'challenge' && $body['version'] === 1
    && $body['identity_hash'] === $identity['hash_hex'] && preg_match('/\A[0-9a-f]{96}\z/', (string) $body['challenge']) === 1);
[$status, $body, $headers] = http('GET', $node['base'] . '/v1/interfaces/challenge?identity_hash=' . $identity['hash_hex']);
check('GET ...?identity_hash= -> 200 with no-store', $status === 200 && ($headers['cache-control'] ?? '') === 'no-store' && ($body['identity_hash'] ?? '') === $identity['hash_hex']);
[$status, $body, $headers] = http('POST', $node['base'] . '/v1/interfaces/challenge', ['public_key' => $identity['public_key_hex']]);
check('POST by public_key -> 200 with no-store', $status === 200 && ($headers['cache-control'] ?? '') === 'no-store');
foreach (['both keys' => ['public_key' => $identity['public_key_hex'], 'identity_hash' => $identity['hash_hex']],
          'neither' => [], 'upper-case' => ['public_key' => strtoupper($identity['public_key_hex'])],
          'an extra key' => ['identity_hash' => $identity['hash_hex'], 'count' => 0]] as $what => $request) {
    [$status, $body, $headers] = http('POST', $node['base'] . '/v1/interfaces/challenge', $request);
    check("POST $what -> 400 bad_challenge_request {error, message}, no-store",
        $status === 400 && array_keys($body) === ['error', 'message'] && $body['error'] === 'bad_challenge_request' && ($headers['cache-control'] ?? '') === 'no-store',
        $status . ' ' . json_encode($body));
}
[$status, $body] = http('GET', $node['base'] . '/v1/interfaces/challenge');
check('GET with no query -> 400 bad_challenge_request', $status === 400 && ($body['error'] ?? null) === 'bad_challenge_request');
[$status, $body] = http('POST', $node['base'] . '/v1/interfaces/challenge', null);
check('POST with no body -> 400 bad_challenge_request (never 401)', $status === 400 && ($body['error'] ?? null) === 'bad_challenge_request');
check('/health: hash_only_challenges 0 after GETs by hash, POSTs by key and refused POSTs', (registrationHealth($node)['hash_only_challenges'] ?? null) === 0,
    json_encode(registrationHealth($node)));
[$status] = http('POST', $node['base'] . '/v1/interfaces/challenge', ['identity_hash' => $identity['hash_hex']]);
check('a POST by identity_hash -> 200, and hash_only_challenges 1', $status === 200 && (registrationHealth($node)['hash_only_challenges'] ?? null) === 1);
http('POST', $node['base'] . '/v1/interfaces/challenge', ['identity_hash' => bin2hex(random_bytes(16))]);
http('GET', $node['base'] . '/v1/interfaces/challenge?identity_hash=' . bin2hex(random_bytes(16)));
check('another POST by hash -> 2; a GET by hash does not move it', (registrationHealth($node)['hash_only_challenges'] ?? null) === 2);

echo "\n(2) register signed, exchange, re-register (§4, §5, §7, §8)\n";
[$status, $first, $firstBody, $raw] = signedRegister($node, $identity, RegFixture::browserMetadata());
check('POST /v1/interfaces/register (signed) -> 200', $status === 200, $raw);
check('the answer as sent: exactly §5\'s keys in order, integers where §5 has numbers',
    array_keys($first) === ['status', 'interface_id', 'identity_hash', 'session_token_encrypted', 'idle_exchange_interval_ms', 'max_batch_packets', 'max_packet_bytes']
    && $first['status'] === 'registered' && preg_match('/\A[0-9a-f]{32}\z/', (string) $first['interface_id']) === 1 && $first['identity_hash'] === $identity['hash_hex']
    && preg_match('/\A[0-9a-f]{320}\z/', (string) $first['session_token_encrypted']) === 1
    && $first['idle_exchange_interval_ms'] === 1000 && $first['max_batch_packets'] === 64 && $first['max_packet_bytes'] === 500, $raw);
check('...and no session_token or count anywhere in it', !str_contains($raw, 'session_token"') && !str_contains($raw, 'registration_seq'));
$t1 = (string) RegFixture::decrypt((string) ($first['session_token_encrypted'] ?? ''), $identity);
check('the token decrypts to 64 hex, and is not in the raw answer', preg_match('/\A[0-9a-f]{64}\z/', $t1) === 1 && !str_contains($raw, $t1));
$id1 = (string) $first['interface_id'];
[$status, $ex] = exchange($node, '/v1/interfaces/exchange', $id1, $t1);
check('/v1/interfaces/exchange with it -> 200', $status === 200, json_encode($ex));
[$status, $replay] = http('POST', $node['base'] . '/v1/interfaces/register', $firstBody);
check('the same body again -> 409 stale_challenge {error, message} (register never answers 401 or session_superseded)',
    $status === 409 && ($replay['error'] ?? '') === 'stale_challenge' && array_keys($replay) === ['error', 'message'], $status . ' ' . json_encode($replay));
[, $c] = http('POST', $node['base'] . '/v1/interfaces/challenge', ['public_key' => $identity['public_key_hex']]);
$tampered = RegFixture::body($identity, (string) $c['challenge'], RegFixture::browserMetadata());
$tampered['mtu'] = 501;
[$status, $body] = http('POST', $node['base'] . '/v1/interfaces/register', $tampered);
check('a tampered body -> 403 bad_registration_signature {error, message}', $status === 403 && ($body['error'] ?? '') === 'bad_registration_signature'
    && array_keys($body) === ['error', 'message'], $status . ' ' . json_encode($body));
[$status, $second] = signedRegister($node, $identity, RegFixture::browserMetadata());
$t2 = (string) RegFixture::decrypt((string) ($second['session_token_encrypted'] ?? ''), $identity);
check('a second tab registers: 200, same interface_id, a new token', $status === 200 && ($second['interface_id'] ?? '') === $id1 && $t2 !== $t1 && $t2 !== '');
foreach (ENDPOINTS as $path) {
    [$status, $body] = exchange($node, $path, $id1, $t1);
    check("$path with the first tab's token -> 409 session_superseded with §8's message",
        $status === 409 && $body === ['error' => 'session_superseded', 'message' => SUPERSEDED_MESSAGE], $status . ' ' . json_encode($body));
}
check('...the goodbye with it changed nothing: the row is online, with the second tab\'s token',
    (nodeRow($node, $id1)['status'] ?? '') === 'online' && (nodeRow($node, $id1)['session_token'] ?? '') === $t2);
foreach (ENDPOINTS as $path) {
    [$status, $body] = exchange($node, $path, $id1, bin2hex(random_bytes(32)));
    check("$path with a random token on the signed row -> 409 session_superseded", $status === 409 && ($body['error'] ?? '') === 'session_superseded');
}
foreach (ENDPOINTS as $path) {
    [$status, $body] = exchange($node, $path, bin2hex(random_bytes(16)), $t2);
    check("$path on an unknown interface -> 401 unauthorized {error, message}",
        $status === 401 && ($body['error'] ?? '') === 'unauthorized' && array_keys($body) === ['error', 'message'], $status . ' ' . json_encode($body));
}
[$status] = exchange($node, '/v1/interfaces/exchange', $id1, $t2);
check('the second tab\'s token works', $status === 200);

echo "\n(3) the legacy path beside it (§4.6)\n";
$claim = bin2hex(random_bytes(16));
[$status, $legacy, , $raw] = legacyRegister($node, ['client' => 'rns-js', 'mode' => 1, 'identity_hash' => $claim]);
check('an old page registers the legacy way: 200 with a plaintext session_token', $status === 200 && isset($legacy['session_token']) && !isset($legacy['session_token_encrypted']), $raw);
[$status, $legacy2] = legacyRegister($node, ['client' => 'rns-js', 'mode' => 1, 'identity_hash' => $claim]);
check('another old page with the claim re-binds its row', $status === 200 && ($legacy2['interface_id'] ?? '') === ($legacy['interface_id'] ?? '-'));
foreach (ENDPOINTS as $path) {
    [$status, $body] = exchange($node, $path, (string) $legacy['interface_id'], (string) $legacy['session_token']);
    check("$path with the replaced legacy token -> 401 unauthorized, as today", $status === 401 && ($body['error'] ?? '') === 'unauthorized', $status . ' ' . json_encode($body));
}
[$status] = exchange($node, '/v1/interfaces/exchange', (string) $legacy2['interface_id'], (string) $legacy2['session_token']);
check('the newer legacy token works', $status === 200);
[$status, $body] = legacyRegister($node, ['client' => 'rns-js', 'mode' => 1, 'identity_hash' => $identity['hash_hex']]);
check('an old page claiming the signed identity -> 403 identity_requires_signature, saying to reload',
    $status === 403 && ($body['error'] ?? '') === 'identity_requires_signature' && str_contains((string) ($body['message'] ?? ''), 'Reload'), $status . ' ' . json_encode($body));
[$status, $body] = legacyRegister($node, ['client' => 'rns-js', 'mode' => 6]);
check('a legacy browser in mode 6 -> 400 transit_mode_not_allowed', $status === 400 && ($body['error'] ?? '') === 'transit_mode_not_allowed');
[$status, $body] = http('POST', $node['base'] . '/v1/interfaces/register', ['bitrate' => 1000000, 'mtu' => 500, 'metadata' => ['client' => 'rns-js']]);
check('a legacy body with no name -> 400 as before, with a message', $status === 400 && ($body['error'] ?? '') === 'name must be a non-empty string' && isset($body['message']));
[$status, $body] = http('POST', $node['base'] . '/v1/interfaces/register', null, '{"name": "\ud800"}');
check('a register body that is not JSON (a lone surrogate) -> 400 {error, message}', $status === 400 && array_keys($body) === ['error', 'message'], json_encode($body));
[$status, $body] = http('POST', $node['base'] . '/v1/interfaces/exchange', ['interface_id' => $id1, 'session_token' => $t2, 'packets' => 'nope']);
check('any other 4xx carries {error, message} too (§10)', $status === 400 && isset($body['error'], $body['message']), $status . ' ' . json_encode($body));

echo "\n(4) /health (§12)\n";
[$status, $health, , $healthRaw] = http('GET', $node['base'] . '/health');
$registration = (array) ($health['registration'] ?? []);
check('/health has §12\'s registration object', $status === 200
    && array_keys($registration) === ['version', 'schema_migrated', 'enforce_signed_registration', 'browsers_online', 'hash_only_challenges']
    && $registration['version'] === 1 && $registration['schema_migrated'] === true && $registration['enforce_signed_registration'] === false
    && $registration['hash_only_challenges'] === 2, json_encode($registration));
check('...browsers_online: one signed, and the legacy browser rows with a claim', ($registration['browsers_online'] ?? null) === ['signed' => 1, 'legacy' => 1],
    json_encode($registration['browsers_online'] ?? null));
foreach (['the identity hash' => $identity['hash_hex'], 'the public key' => $identity['public_key_hex'], 'a session token' => $t2,
          'the legacy claim' => $claim, 'the legacy token' => (string) $legacy2['session_token']] as $what => $value) {
    check("/health carries no $what", !str_contains($healthRaw, $value));
}

echo "\n(5) the node's log: the tags, and no secret (§11)\n";
$log = (string) @file_get_contents($node['dir'] . '/server.out') . (string) @file_get_contents($node['dir'] . '/src/error_log');
check('[REG-SIGNED] created and rebound, [SESSION-SUPERSEDED], [REG-LEGACY], [REG-REFUSED] 409 stale_challenge are logged',
    str_contains($log, '[REG-SIGNED] identity=' . $identity['hash_hex'] . ' interface=' . substr($id1, 0, 8) . ' created')
    && str_contains($log, '[REG-SIGNED] identity=' . $identity['hash_hex'] . ' interface=' . substr($id1, 0, 8) . ' rebound')
    && str_contains($log, '[SESSION-SUPERSEDED] interface=' . substr($id1, 0, 8)) && str_contains($log, '[REG-LEGACY] client=rns-js action=created')
    && str_contains($log, '[REG-REFUSED] 409 stale_challenge client=rns-js identity=' . $identity['hash_hex']), $log);
check('[SESSION-SUPERSEDED] once, for four requests with the replaced token and four with random ones', substr_count($log, '[SESSION-SUPERSEDED]') === 1);
check('a refused challenge is logged [REG-REFUSED] 400 bad_challenge_request', str_contains($log, '[REG-REFUSED] 400 bad_challenge_request client=-'));
check('an undecodable register body is logged [REG-REFUSED] 400 too', str_contains($log, '[REG-REFUSED] 400 "invalid json" client=-'));
$secret = (string) (new PDO('sqlite:' . $node['dir'] . '/node.sqlite'))
    ->query("SELECT state_value FROM transport_state WHERE state_key = 'registration_challenge_secret_hex'")->fetchColumn();
foreach (['a session token' => $t1, 'the newer session token' => $t2, 'a signature' => $firstBody['registration']['signature'],
          'a challenge' => $firstBody['registration']['challenge'], 'a challenge\'s nonce' => substr($firstBody['registration']['challenge'], 0, 32),
          'a challenge\'s MAC' => substr($firstBody['registration']['challenge'], 32), 'the node secret' => $secret,
          'a legacy token' => (string) $legacy['session_token'], 'the newer legacy token' => (string) $legacy2['session_token']] as $what => $value) {
    check("the log never carries $what", $value !== '' && !str_contains($log, $value));
}
stopNode($node);

echo "\n(6) [registration] in config.toml (§13)\n";
$enforcing = startNode($src, ['enforce_signed_registration = true   # browsers only. James turns it on, on a date he sets.']);
check('/health shows what the node loaded: enforce_signed_registration true', (registrationHealth($enforcing)['enforce_signed_registration'] ?? null) === true);
[$status, $body] = legacyRegister($enforcing, ['client' => 'rns-js', 'mode' => 1]);
check('a legacy rns-js -> 403 signature_required, saying to reload', $status === 403 && ($body['error'] ?? '') === 'signature_required'
    && str_contains((string) ($body['message'] ?? ''), 'Reload'), $status . ' ' . json_encode($body));
$closedPort = freePort();
[$status] = legacyRegister($enforcing, RegFixture::phpPeerMetadata('http://127.0.0.1:' . $closedPort), 'peer');
check('a legacy reticulum-php is still accepted: the switch is for browsers only', $status === 200);
[$status] = legacyRegister($enforcing, RegFixture::pollGatewayMetadata(), 'RNS PostInterface');
check('a legacy rns-post-interface is still accepted', $status === 200);
[$status] = signedRegister($enforcing, RegFixture::identity(), RegFixture::browserMetadata());
check('a signed registration still -> 200', $status === 200);
stopNode($enforcing);
foreach (['off', 'no', '0', 'false'] as $value) {
    $offNode = startNode($src, ['enforce_signed_registration = ' . $value]);
    [$status] = legacyRegister($offNode, ['client' => 'rns-js', 'mode' => 1]);
    check("enforce_signed_registration = $value is off: /health false, a legacy browser registers",
        (registrationHealth($offNode)['enforce_signed_registration'] ?? null) === false && $status === 200);
    stopNode($offNode);
}
$yesNode = startNode($src, ['enforce_signed_registration = yes']);
check('enforce_signed_registration = yes is on, like the node\'s other switches', (registrationHealth($yesNode)['enforce_signed_registration'] ?? null) === true);
stopNode($yesNode);

echo "\n$pass passed, $fail failed\n";
exit($fail === 0 ? 0 : 1);
