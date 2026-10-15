<?php
/**
 * How an HTTP test starts its copy of the node: `php -S` on index.php, as
 * always, or with RETICULUM_TEST_RUNTIME=swoole the Swoole entry
 * (swoole_server.php) on the same copy and config, so the same assertions
 * hold the resident process to index.php's answers. RETICULUM_TEST_SWOOLE
 * names the extension to load (default swoole.so; "" when php already has it).
 *
 *   RETICULUM_TEST_RUNTIME=swoole php empty_poll_shortcut_test.php
 *
 * Not a test: php/tests/stubs/ holds fixtures, and deploy.sh runs only
 * php/tests/*.php.
 */
declare(strict_types=1);

/** @return resource the node's process; its output goes to $outFile */
function startNodeProcess(string $srcDir, int $port, string $outFile)
{
    $io = [0 => ['file', '/dev/null', 'r'], 1 => ['file', $outFile, 'w'], 2 => ['file', $outFile, 'a']];
    if (getenv('RETICULUM_TEST_RUNTIME') === 'swoole') {
        $extension = getenv('RETICULUM_TEST_SWOOLE');
        $extension = $extension === false ? 'swoole.so' : $extension;
        $command = $extension === ''
            ? [PHP_BINARY, $srcDir . '/swoole_server.php']
            : [PHP_BINARY, '-d', 'extension=' . $extension, $srcDir . '/swoole_server.php'];
        $env = getenv();
        $env['PORT'] = (string) $port;
        echo "(runtime: swoole_server.php)\n";

        return proc_open($command, $io, $pipes, null, $env);
    }

    return proc_open([PHP_BINARY, '-S', '127.0.0.1:' . $port, '-t', $srcDir, $srcDir . '/index.php'], $io, $pipes);
}
