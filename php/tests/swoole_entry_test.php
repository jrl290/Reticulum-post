<?php
/**
 * The Swoole entry (swoole_server.php, lib/swoole_node.php) answers through
 * the node's own code, which was written for a web SAPI: php://input,
 * header(), http_response_code() and exit. What this pins, without Swoole:
 *
 * (a) HttpIo: with an HttpExchange begun, the body comes from it and the
 *     status and headers go to it (a later header replaces one of the same
 *     name, as header() does); after finish(), nothing does.
 * (b) SwooleNode::serverVars(): Swoole's request as index.php's $_SERVER,
 *     so HttpIo::normalizedPath() strips the base path Passenger passes on,
 *     and the front-secret header is not passed to the node.
 * (c) Under Swoole, exit ends the request as Swoole\ExitException, which a
 *     catch of \Throwable or \Exception takes. Every such catch whose try can
 *     end the request (exit, ->respond(), ->renderMonitorPage(), ->handle(),
 *     EmptyPoll::answer()) must let it through: an earlier
 *     catch (\Swoole\ExitException) or, first thing, an instanceof rethrow.
 *     HttpApi::handle()'s swallowed it, which made every answer a 500 (probe,
 *     2026-10-14). The scanner is first run on samples, so a scanner that
 *     finds nothing cannot pass.
 * (d) swoole_server.php reached through a web server answers 404 and starts
 *     nothing.
 * (e) The flags: [swoole] enable_swoole and [storage] backend read as the
 *     node's other switches do, off and mysql by default, and the template
 *     loads.
 * (f) `php index.php runtime` (SwooleSetup): on, it writes the app root
 *     (Passengerfile.json, the front secret, tmp/restart.txt) and the
 *     .htaccess block; again, nothing changes; off, it removes only the
 *     block. It refuses an app root inside the web directory and a node with
 *     no base path.
 * (g) LoadedCode: /health names the stamp on disk only while the code on
 *     disk is the code the process loaded.
 *
 * The node's answers under Swoole are held to index.php's by running the
 * HTTP tests on it: RETICULUM_TEST_RUNTIME=swoole (tests/stubs/node_process.php).
 */
declare(strict_types=1);

$src = dirname(__DIR__) . '/src';
require_once $src . '/index.php';
require_once $src . '/lib/swoole_node.php';

use ReticulumPhp\HttpExchange;
use ReticulumPhp\HttpIo;
use ReticulumPhp\SwooleNode;

$pass = 0;
$fail = 0;

function check(string $label, bool $ok, string $detail = ''): void
{
    global $pass, $fail;
    if ($ok) {
        $pass++;
        echo "  ok   $label\n";
        return;
    }
    $fail++;
    echo "  FAIL $label\n";
    if ($detail !== '') {
        echo "       $detail\n";
    }
}

echo "(a) HttpIo takes the body in and the status and headers out through an exchange\n";
$exchange = new HttpExchange('{"interface_id":"x"}');
HttpIo::begin($exchange);
check('the body is the exchange\'s', HttpIo::requestBody() === '{"interface_id":"x"}');
HttpIo::sendHeaders(404);
HttpIo::header('Cache-Control', 'no-store');
HttpIo::header('content-type', 'text/plain');
HttpIo::finish();
check('the status went to the exchange', $exchange->status === 404, (string) $exchange->status);
check('the headers went to it, a later one replacing one of the same name',
    $exchange->headers === [
        'content-type' => ['content-type', 'text/plain'],
        'access-control-allow-origin' => ['Access-Control-Allow-Origin', '*'],
        'access-control-allow-methods' => ['Access-Control-Allow-Methods', 'GET, POST, OPTIONS'],
        'access-control-allow-headers' => ['Access-Control-Allow-Headers', 'Content-Type, X-Interface-Id, X-Session-Token'],
        'access-control-max-age' => ['Access-Control-Max-Age', '86400'],
        'cache-control' => ['Cache-Control', 'no-store'],
    ], json_encode($exchange->headers));
check('after finish() the body is php://input again (empty in the CLI)', HttpIo::requestBody() === '');
@HttpIo::header('X-After', 'finish'); // to PHP's header(), too late in this CLI
check('...and a header goes to PHP, not the finished exchange', !isset($exchange->headers['x-after']));

echo "\n(b) Swoole's request becomes index.php's \$_SERVER\n";
$vars = SwooleNode::serverVars(
    ['request_method' => 'post', 'request_uri' => '/reticulum/v1/interfaces/exchange', 'query_string' => 'a=1',
        'server_protocol' => 'HTTP/1.1', 'request_time' => 1760000000, 'request_time_float' => 1760000000.25, 'remote_addr' => '127.0.0.1'],
    ['content-type' => 'application/json', 'content-length' => '20', 'x-interface-id' => 'abc', 'x-front-secret' => 's3cret'],
    '/reticulum/',
    ['x-front-secret']
);
check('method, URI with its query, time', $vars['REQUEST_METHOD'] === 'POST'
    && $vars['REQUEST_URI'] === '/reticulum/v1/interfaces/exchange?a=1' && $vars['QUERY_STRING'] === 'a=1'
    && $vars['REQUEST_TIME'] === 1760000000 && $vars['REQUEST_TIME_FLOAT'] === 1760000000.25, json_encode($vars));
check('headers as CGI names: CONTENT_TYPE and CONTENT_LENGTH bare, the rest HTTP_',
    $vars['CONTENT_TYPE'] === 'application/json' && $vars['CONTENT_LENGTH'] === '20' && $vars['HTTP_X_INTERFACE_ID'] === 'abc');
check('the front secret is not passed on', !isset($vars['HTTP_X_FRONT_SECRET']));
check('the node routes the path without the base, as under Apache',
    HttpIo::normalizedPath($vars['REQUEST_URI'], $vars) === '/v1/interfaces/exchange', HttpIo::normalizedPath($vars['REQUEST_URI'], $vars));
$root = SwooleNode::serverVars(['request_method' => 'GET', 'request_uri' => '/health'], [], '');
check('with no base path, /health is /health', HttpIo::normalizedPath($root['REQUEST_URI'], $root) === '/health');

echo "\n(c) no catch-all swallows the exit that ends a request\n";

/**
 * Each catch of \Throwable or \Exception, in a try whose block can end the
 * request, that does not let Swoole\ExitException through.
 *
 * @return list<string> "<file>:<line>"
 */
function swallowingCatches(string $code, string $file): array
{
    $tokens = array_values(array_filter(
        token_get_all($code),
        static fn ($t) => !is_array($t) || !in_array($t[0], [T_WHITESPACE, T_COMMENT, T_DOC_COMMENT], true)
    ));
    $text = static fn ($t): string => is_array($t) ? $t[1] : $t;
    $block = static function (int $open) use ($tokens, $text): int {
        $depth = 0;
        for ($i = $open; $i < count($tokens); $i++) {
            $s = $text($tokens[$i]);
            if ($s === '{' || $s === '${' || (is_array($tokens[$i]) && $tokens[$i][0] === T_CURLY_OPEN) || (is_array($tokens[$i]) && $tokens[$i][0] === T_DOLLAR_OPEN_CURLY_BRACES)) {
                $depth++;
            } elseif ($s === '}') {
                $depth--;
                if ($depth === 0) {
                    return $i;
                }
            }
        }
        return count($tokens) - 1;
    };
    $found = [];
    foreach ($tokens as $i => $token) {
        if (!is_array($token) || $token[0] !== T_TRY) {
            continue;
        }
        $tryEnd = $block($i + 1);
        $endsRequest = false;
        for ($j = $i + 1; $j < $tryEnd; $j++) {
            $t = $tokens[$j];
            if (is_array($t) && $t[0] === T_EXIT) {
                $endsRequest = true;
            }
            if (is_array($t) && $t[0] === T_STRING && is_array($tokens[$j - 1])
                && in_array($tokens[$j - 1][0], [T_OBJECT_OPERATOR, T_NULLSAFE_OBJECT_OPERATOR], true)
                && in_array($t[1], ['respond', 'renderMonitorPage', 'handle'], true)) {
                $endsRequest = true;
            }
            if (is_array($t) && $t[0] === T_STRING && $t[1] === 'answer' && $text($tokens[$j - 1]) === '::'
                && str_ends_with($text($tokens[$j - 2]), 'EmptyPoll')) {
                $endsRequest = true;
            }
        }
        $k = $tryEnd + 1;
        $exitCaughtEarlier = false;
        while (isset($tokens[$k]) && is_array($tokens[$k]) && $tokens[$k][0] === T_CATCH) {
            $line = $tokens[$k][2];
            $types = [];
            $variable = null;
            for ($k += 2; $text($tokens[$k]) !== ')'; $k++) {
                if (is_array($tokens[$k]) && $tokens[$k][0] === T_VARIABLE) {
                    $variable = $tokens[$k][1];
                } elseif ($text($tokens[$k]) !== '|') {
                    $types[] = ltrim($text($tokens[$k]), '\\');
                }
            }
            $bodyOpen = $k + 1;
            $bodyEnd = $block($bodyOpen);
            $body = '';
            for ($m = $bodyOpen + 1; $m < $bodyEnd; $m++) {
                $body .= $text($tokens[$m]);
            }
            $catchAll = array_filter($types, static fn (string $t) => in_array($t, ['Throwable', 'Exception'], true)) !== [];
            $rethrows = $variable !== null
                && str_starts_with($body, "if({$variable}instanceof\\Swoole\\ExitException){throw{$variable};}");
            if ($endsRequest && $catchAll && !$exitCaughtEarlier && !$rethrows) {
                $found[] = "{$file}:{$line}";
            }
            if (in_array('Swoole\\ExitException', $types, true)) {
                $exitCaughtEarlier = true;
            }
            $k = $bodyEnd + 1;
        }
    }
    return $found;
}

$samples = [
    'a catch-all around ->respond()' => ['<?php try { $this->respond(200, []); } catch (\Throwable $e) { log($e); }', 1],
    'a catch-all around exit' => ['<?php try { echo 1; exit; } catch (Throwable $e) { }', 1],
    'catch (\Exception) around EmptyPoll::answer()' => ['<?php try { EmptyPoll::answer($c, $m, $u, $s); } catch (\Exception $e) { }', 1],
    'a catch-all without a variable' => ['<?php try { $api->handle($m, $u, $s); } catch (\Throwable) { }', 1],
    'a rethrow that is not the first thing' => ['<?php try { $this->respond(1, []); } catch (\Throwable $e) { log($e); if ($e instanceof \Swoole\ExitException) { throw $e; } }', 1],
    'the outer one of two nested catch-alls' => ['<?php try { try { exit; } catch (\Throwable $e) { if ($e instanceof \Swoole\ExitException) { throw $e; } } } catch (\Throwable $f) { }', 1],
    'a rethrow first' => ['<?php try { $this->respond(200, []); } catch (\Throwable $e) { if ($e instanceof \Swoole\ExitException) { throw $e; } log($e); }', 0],
    'an ExitException catch before the catch-all' => ['<?php try { exit; } catch (\Swoole\ExitException) { } catch (\Throwable $e) { }', 0],
    'a catch-all around work that cannot end the request' => ['<?php try { $this->storage->dispatchWakes(); } catch (\Throwable $e) { }', 0],
    'a narrow catch around ->respond()' => ['<?php try { $this->respond(1, []); } catch (ApiError $e) { }', 0],
];
foreach ($samples as $label => [$code, $expected]) {
    $got = swallowingCatches($code, 'sample');
    check("finds $expected in: $label", count($got) === $expected, implode(', ', $got));
}

$files = array_merge([$src . '/index.php', $src . '/swoole_server.php'], glob($src . '/lib/*.php'));
$swallowing = [];
$scanned = 0;
foreach ($files as $path) {
    $swallowing = array_merge($swallowing, swallowingCatches((string) file_get_contents($path), substr($path, strlen($src) + 1)));
    $scanned++;
}
check("none in php/src ($scanned files)", $scanned > 20 && $swallowing === [], implode(', ', $swallowing));

echo "\n(d) swoole_server.php reached as a web page answers 404 and starts nothing\n";
$port = (static function (): int {
    $socket = stream_socket_server('tcp://127.0.0.1:0');
    $name = stream_socket_get_name($socket, false);
    fclose($socket);
    return (int) substr((string) $name, strrpos((string) $name, ':') + 1);
})();
$out = sys_get_temp_dir() . '/swoole-entry-test-' . bin2hex(random_bytes(4)) . '.out';
$proc = proc_open([PHP_BINARY, '-S', '127.0.0.1:' . $port, $src . '/swoole_server.php'],
    [0 => ['file', '/dev/null', 'r'], 1 => ['file', $out, 'w'], 2 => ['file', $out, 'a']], $pipes);
$status = 0;
$body = false;
for ($i = 0; $i < 50 && $status === 0; $i++) {
    usleep(100000);
    $body = @file_get_contents('http://127.0.0.1:' . $port . '/anything', false,
        stream_context_create(['http' => ['ignore_errors' => true, 'timeout' => 2]]));
    foreach ($http_response_header ?? [] as $line) {
        if (preg_match('#^HTTP/\S+ (\d{3})#', $line, $m) === 1) {
            $status = (int) $m[1];
        }
    }
}
proc_terminate($proc);
proc_close($proc);
@unlink($out);
check('404, empty', $status === 404 && $body === '', "$status " . var_export($body, true));

echo "\n(e) the flags read as the node's other switches do\n";
$tmp = sys_get_temp_dir() . '/swoole-entry-test-' . bin2hex(random_bytes(4));
mkdir($tmp . '/web/lib', 0777, true);
$load = static function (string $toml) use ($tmp): array {
    file_put_contents($tmp . '/web/config.toml', $toml);
    return \ReticulumPhp\Config::load($tmp . '/web');
};
$defaults = $load("host_url = \"https://example.test/reticulum\"\n");
check('enable_swoole is off by default, and the database is mysql',
    $defaults['swoole']['enable_swoole'] === false && \ReticulumPhp\Database::backend($defaults) === 'mysql'
    && !\ReticulumPhp\SwooleSetup::enabled($defaults));
foreach (['true' => true, '"yes"' => true, '1' => true, 'false' => false, '"off"' => false, '"no"' => false] as $value => $expected) {
    $loaded = $load("[swoole]\nenable_swoole = {$value}\n");
    check("enable_swoole = {$value} is " . ($expected ? 'on' : 'off'), \ReticulumPhp\SwooleSetup::enabled($loaded) === $expected);
}
$sqlite = $load("[storage]\nbackend = \"sqlite\"\n");
check('backend = "sqlite" is SQLite, at var/ under the project root by default',
    \ReticulumPhp\Database::backend($sqlite) === 'sqlite'
    && in_array($sqlite['storage']['sqlite_path'], [realpath($tmp . '/web') . '/var/reticulum-php.sqlite', $tmp . '/web/var/reticulum-php.sqlite'], true),
    (string) $sqlite['storage']['sqlite_path']);
try {
    $load("[swoole]\nworkers = 0\n");
    check('workers = 0 is refused', false);
} catch (\RuntimeException $error) {
    check('workers = 0 is refused', true);
}
copy($src . '/config.template.toml', $tmp . '/web/config.toml');
$template = \ReticulumPhp\Config::load($tmp . '/web');
check('the template loads, with enable_swoole off and mysql', !\ReticulumPhp\SwooleSetup::enabled($template)
    && \ReticulumPhp\Database::backend($template) === 'mysql');

echo "\n(f) php index.php runtime routes Apache as the config says\n";
use ReticulumPhp\SwooleSetup;
$web = $tmp . '/web';
touch($web . '/swoole_server.php');
$appRoot = $tmp . '/app';
$existing = "RewriteEngine On\nRedirectMatch 404 ^/reticulum/(error_log|var/)\nRewriteRule ^ index.php [L]\n";
file_put_contents($web . '/.htaccess', $existing);
$config = static fn (bool $on, array $extra = []): array => [
    'host_url' => 'https://example.test/reticulum',
    'swoole' => $extra + ['enable_swoole' => $on, 'app_root' => $appRoot],
];
$run = static function (array $config) use ($web): array {
    $out = fopen('php://memory', 'w+');
    $err = fopen('php://memory', 'w+');
    $code = SwooleSetup::apply($config, $web, false, $out, $err);
    rewind($out);
    rewind($err);
    return [$code, stream_get_contents($out), stream_get_contents($err)];
};
[$code, $said, $errors] = $run($config(true));
$htaccess = (string) file_get_contents($web . '/.htaccess');
$secret = trim((string) @file_get_contents($appRoot . '/front_secret'));
check('on: exit 0', $code === 0, $errors);
check('...a 64-hex front secret, mode 600', preg_match('/^[0-9a-f]{64}$/', $secret) === 1
    && (fileperms($appRoot . '/front_secret') & 0777) === 0600);
check('...Passengerfile.json starts swoole_server.php with the secret\'s path',
    json_decode((string) @file_get_contents($appRoot . '/Passengerfile.json'), true)
        === ['app_start_command' => '/usr/local/bin/php -d extension=swoole.so ' . $web . '/swoole_server.php ' . $appRoot . '/front_secret'],
    (string) @file_get_contents($appRoot . '/Passengerfile.json'));
check('...restart.txt is touched', is_file($appRoot . '/tmp/restart.txt'));
check('...the .htaccess keeps its rules and ends with the block',
    $htaccess === $existing . "\n" . SwooleSetup::BEGIN . "\nPassengerAppRoot \"{$appRoot}\"\nPassengerBaseURI \"/reticulum\"\n"
        . "RequestHeader set X-Front-Secret \"{$secret}\"\n" . SwooleSetup::END . "\n", $htaccess);
[$code] = $run($config(true));
check('on again: the same .htaccess and the same secret', $code === 0
    && file_get_contents($web . '/.htaccess') === $htaccess && trim((string) file_get_contents($appRoot . '/front_secret')) === $secret);
[$code] = $run($config(false));
check('off: only the block is removed', $code === 0 && file_get_contents($web . '/.htaccess') === $existing,
    (string) file_get_contents($web . '/.htaccess'));
[$code] = $run($config(false));
check('off again: nothing changes', $code === 0 && file_get_contents($web . '/.htaccess') === $existing);
[$code, , $errors] = $run($config(true, ['app_root' => $web . '/app']));
check('an app root inside the web directory is refused, .htaccess untouched', $code === 1
    && str_contains($errors, 'outside the web directory') && file_get_contents($web . '/.htaccess') === $existing, $errors);
[$code, , $errors] = $run(['swoole' => ['enable_swoole' => true, 'app_root' => $appRoot]]);
check('no host_url and no base_uri is refused', $code === 1 && str_contains($errors, 'needs host_url'), $errors);
[$code, , $errors] = $run($config(true, ['php_binary' => '/usr/bin/php; rm -rf ~']));
check('a value that would need quoting is refused', $code === 1 && str_contains($errors, 'swoole.php_binary'), $errors);
check('withBlock() on an empty file is the block alone',
    SwooleSetup::withBlock('', "B\n") === "B\n" && SwooleSetup::withBlock('', null) === '');

echo "\n(g) /health's build is unknown once the loaded code was replaced\n";
file_put_contents($web . '/index.php', '<?php // one release');
file_put_contents($web . '/lib/a.php', '<?php // one release');
file_put_contents($web . '/build.json', json_encode(['commit' => str_repeat('a', 40), 'stamped_at' => '2026-10-14T00:00:00Z']));
$loaded = new \ReticulumPhp\LoadedCode($web);
check('the stamp, while the code is the code loaded', $loaded->buildStamp()['commit'] === str_repeat('a', 40));
file_put_contents($web . '/build.json', json_encode(['commit' => null]));
check('...an unknown stamp on disk is unknown here too', $loaded->buildStamp()['commit'] === null);
file_put_contents($web . '/build.json', json_encode(['commit' => str_repeat('a', 40), 'stamped_at' => '2026-10-14T00:00:00Z']));
file_put_contents($web . '/lib/b.tmp', '<?php // the next release');
rename($web . '/lib/b.tmp', $web . '/lib/a.php');
check('a lib file renamed over (as the swap does): unknown, whatever the stamp says', $loaded->buildStamp() === ['commit' => null, 'stamped_at' => null]);
check('...and a process that loads it now names the stamp', (new \ReticulumPhp\LoadedCode($web))->buildStamp()['commit'] === str_repeat('a', 40));
exec('rm -rf ' . escapeshellarg($tmp));

echo "\n$pass passed, $fail failed\n";
exit($fail > 0 ? 1 : 0);
