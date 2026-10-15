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
 * on 127.0.0.1 and proxies plain HTTP to it with the full path. Setup, with
 * the node's files where deploy.sh puts them (~/public_html/reticulum) and
 * the app root outside the web root, as the 2026-10-14 probes ran:
 *
 *   ~/reticulum-swoole/Passengerfile.json:
 *     {"app_start_command": "/usr/local/bin/php -d extension=swoole.so
 *       /home/<user>/public_html/reticulum/swoole_server.php"}
 *   ~/public_html/reticulum/.htaccess, ahead of the existing rules:
 *     PassengerAppRoot /home/<user>/reticulum-swoole
 *     PassengerBaseURI /reticulum
 *     RequestHeader set X-Front-Secret "<swoole.front_secret>"
 *
 * Config, [swoole] (all optional):
 *   workers       worker processes, each answering one request at a time
 *                 like one lsphp process (default 4)
 *   base_uri      the URL path the node answers under, index.php's directory
 *                 in SCRIPT_NAME under Apache (default: PassengerBaseURI,
 *                 which Passenger exports, else host_url's path)
 *   front_secret  when set, a request without this X-Front-Secret header is
 *                 refused with 403: the loopback port is open to every
 *                 account on the host, Apache's .htaccess adds the header
 *   max_body_bytes  largest request body (default 8 MiB; Swoole answers 413)
 *   max_requests  replace a worker after this many requests (default 0, never)
 *
 * The code and the config are read once, at start, before the workers fork,
 * so every worker runs the same release and /health names it. A deploy or a
 * config change takes effect only when the app restarts
 * (`touch ~/reticulum-swoole/tmp/restart.txt`, or kill it: Passenger starts
 * it again).
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
$build = BuildStamp::read(__DIR__);
$settings = is_array($config['swoole'] ?? null) ? $config['swoole'] : [];
$frontSecret = (string) ($settings['front_secret'] ?? '');
$baseUri = rtrim((string) ($settings['base_uri']
    ?? (getenv('PASSENGER_BASE_URI') ?: (parse_url((string) ($config['host_url'] ?? ''), PHP_URL_PATH) ?: ''))), '/');

$server = new \Swoole\Http\Server('127.0.0.1', $port, SWOOLE_PROCESS);
$server->set([
    'worker_num' => max(1, (int) ($settings['workers'] ?? 4)),
    // A request goes to an idle worker, never queued behind a busy one.
    'dispatch_mode' => 3,
    // exit becomes Swoole\ExitException only inside a coroutine; with the
    // hooks off, nothing in the node yields (see SwooleNode, which refuses a
    // second request while it answers one).
    'enable_coroutine' => true,
    'hook_flags' => 0,
    'max_request' => max(0, (int) ($settings['max_requests'] ?? 0)),
    'package_max_length' => max(1, (int) ($settings['max_body_bytes'] ?? 8 * 1024 * 1024)),
    'http_compression' => false,
    'http_parse_post' => false,
    'http_parse_cookie' => false,
    'http_parse_files' => false,
    'log_level' => SWOOLE_LOG_WARNING,
]);

/** @var SwooleNode|null $node this worker's */
$node = null;

$server->on('workerStart', static function () use (&$node, $config, $build): void {
    $node = new SwooleNode($config, $build);
});

$server->on('request', static function (\Swoole\Http\Request $request, \Swoole\Http\Response $response) use (&$node, $frontSecret, $baseUri): void {
    $headers = is_array($request->header) ? $request->header : [];
    if ($frontSecret !== '' && !hash_equals($frontSecret, (string) ($headers['x-front-secret'] ?? ''))) {
        $response->status(403);
        $response->end();
        return;
    }
    $vars = SwooleNode::serverVars(is_array($request->server) ? $request->server : [], $headers, $baseUri, ['x-front-secret']);
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
