<?php

declare(strict_types=1);

/**
 * The PHP node as a resident Swoole HTTP server, for a host that lets
 * Passenger run a long-lived process (selectiv: cPanel, Apache, Passenger
 * 6.1, alt-php83 with swoole.so; measured 2026-10-14). The same code as
 * index.php answers; what a process that outlives its requests must reset is
 * in lib/swoole_node.php.
 *
 * Apache keeps 80 and 443 and TLS; Passenger starts this file, gives it PORT
 * on 127.0.0.1 and proxies plain HTTP to it with the full path.
 *
 * It runs only where the config says so, [swoole] enable_swoole = true, and
 * `php index.php runtime` (deploy.sh runs it after every swap) writes the
 * rest: the Passenger app root outside the web root (~/reticulum-swoole:
 * Passengerfile.json, whose app_start_command starts this file with the
 * front secret's path; the secret; tmp/restart.txt) and the block in the web
 * directory's .htaccess that hands requests to Passenger with the secret in
 * X-Front-Secret. A request without it is refused with 403: the loopback
 * port is open to every account on the host. Beside the secret, the block's
 * X-Front-Https and X-Front-Client give the node HTTPS and REMOTE_ADDR as
 * Apache saw them; Passenger's own request is plain HTTP from 127.0.0.1.
 * Setting enable_swoole = false
 * and running `php index.php runtime` hands the node back to index.php.
 * See SwooleSetup in lib/swoole_node.php.
 *
 * Config, [swoole] (all optional):
 *   enable_swoole   this server answers the node (default false)
 *   workers         worker processes, each answering one request at a time
 *                   like one lsphp process (default 4)
 *   base_uri        the URL path the node answers under (default: host_url's
 *                   path; PassengerBaseURI, which Passenger exports, here)
 *   app_root        the Passenger app root (default ~/reticulum-swoole)
 *   php_binary      the PHP CLI Passenger starts (default /usr/local/bin/php)
 *   extension       the extension to load (default swoole.so; "" if built in)
 *   max_body_bytes  largest request body (default 8 MiB; Swoole answers 413)
 *   max_requests    replace a worker after this many requests (default 0, never)
 *
 * The code and the config are read once, at start, before the workers fork,
 * so every worker runs the same release. A deploy or a config change takes
 * effect when the app restarts (`php index.php runtime` touches restart.txt);
 * until then /health's build is unknown (LoadedCode).
 */

namespace ReticulumPhp;

// Reached as a web page through Apache: not an entry point there.
if (PHP_SAPI !== 'cli') {
    http_response_code(404);
    exit;
}

if (!extension_loaded('swoole')) {
    fwrite(STDERR, "swoole_server.php needs the swoole extension: php -d extension=swoole.so swoole_server.php\n");
    exit(1);
}
$port = (int) (getenv('PORT') ?: 0);
if ($port <= 0 || $port > 65535) {
    fwrite(STDERR, "swoole_server.php: PORT must name the port to listen on (Passenger sets it)\n");
    exit(1);
}

// The CLI prints errors to stdout, which here is the response body. Log them
// where the web SAPI does on cPanel: error_log next to the script.
ini_set('display_errors', '0');
ini_set('log_errors', '1');
if (!str_starts_with((string) ini_get('error_log'), '/')) {
    ini_set('error_log', __DIR__ . '/error_log');
}

require_once __DIR__ . '/index.php';
require_once __DIR__ . '/lib/swoole_node.php';

$config = loadRuntimeConfig(resolveRuntimeProjectRoot(__DIR__));
if (!SwooleSetup::enabled($config)) {
    fwrite(STDERR, "swoole_server.php: swoole.enable_swoole is off in the config; `php index.php runtime` hands the node back to index.php\n");
    exit(1);
}
$code = new LoadedCode(__DIR__);
$settings = $config['swoole'];
// The path Passengerfile.json's app_start_command passes; none for a test.
$frontSecret = '';
if (isset($argv[1])) {
    $frontSecret = trim((string) @file_get_contents($argv[1]));
    if (preg_match('/^[0-9a-f]{64}$/', $frontSecret) !== 1) {
        fwrite(STDERR, "swoole_server.php: {$argv[1]} does not hold a front secret\n");
        exit(1);
    }
}
$baseUri = rtrim((string) ($settings['base_uri']
    ?? (getenv('PASSENGER_BASE_URI') ?: (parse_url((string) ($config['host_url'] ?? ''), PHP_URL_PATH) ?: ''))), '/');

$server = new \Swoole\Http\Server('127.0.0.1', $port, SWOOLE_PROCESS);
$server->set([
    'worker_num' => $settings['workers'],
    // A request goes to an idle worker, never queued behind a busy one.
    'dispatch_mode' => 3,
    // exit becomes Swoole\ExitException only inside a coroutine; with the
    // hooks off, nothing in the node yields (see SwooleNode, which refuses a
    // second request while it answers one).
    'enable_coroutine' => true,
    'hook_flags' => 0,
    'max_request' => max(0, (int) ($settings['max_requests'] ?? 0)),
    'package_max_length' => $settings['max_body_bytes'],
    'http_compression' => false,
    'http_parse_post' => false,
    'http_parse_cookie' => false,
    'http_parse_files' => false,
    'log_level' => SWOOLE_LOG_WARNING,
]);

/** @var SwooleNode|null $node this worker's */
$node = null;

$server->on('workerStart', static function () use (&$node, $config, $code): void {
    $node = new SwooleNode($config, $code);
});

$server->on('request', static function (\Swoole\Http\Request $request, \Swoole\Http\Response $response) use (&$node, $frontSecret, $baseUri): void {
    $headers = is_array($request->header) ? $request->header : [];
    if ($frontSecret !== '' && !hash_equals($frontSecret, (string) ($headers['x-front-secret'] ?? ''))) {
        $response->status(403);
        $response->end();
        return;
    }
    // With a secret, every request still here came through Apache's block,
    // so its X-Front-Https and X-Front-Client are Apache's. Without one (a
    // test), nothing vouches for them.
    $vars = SwooleNode::serverVars(is_array($request->server) ? $request->server : [], $headers, $baseUri, ['x-front-secret'], $frontSecret !== '');
    try {
        [$status, $answerHeaders, $body] = $node->answer($vars, (string) $request->rawContent());
    } catch (\Throwable $error) {
        // answer() catches what the node throws; this is answer() itself.
        error_log('Reticulum-php: swoole_server.php: ' . get_class($error) . ': ' . $error->getMessage());
        $response->status(500);
        $response->end();
        return;
    }

    $response->status($status);
    foreach ($answerHeaders as [$name, $value]) {
        $response->header($name, $value);
    }
    if (!isset($answerHeaders['content-type'])) {
        // PHP's default under Apache (the monitor page sets none).
        $response->header('Content-Type', 'text/html; charset=UTF-8');
    }
    $bodiless = $status === 204 || $status === 304 || $vars['REQUEST_METHOD'] === 'HEAD';
    $response->end($bodiless ? '' : $body);
});

$server->start();
