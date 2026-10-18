<?php
/**
 * `php index.php switch-storage` moves a node's config to a fresh SQLite
 * database under Swoole (retichat.com, James 2026-10-18: "no data needs to
 * be transferred", and "Make sure we are installed as a Passenger service").
 *
 * (a) rewrite() sets [storage] backend and sqlite_path and [swoole]
 *     enable_swoole and changes no other line: in place where the key is,
 *     in every table of a section the file opens twice, under the first
 *     header where it is missing, in a new section where that is missing.
 *     It keeps CRLF, and a second run changes nothing.
 * (b) On a copy of php/src with the template's config, a MySQL password and
 *     a front secret in it: the command exits 0, its output holds no value
 *     from the file, the copy in ~/reticulum-config-backup is the old file at
 *     0600, the config keeps its mode and now loads as SQLite + Swoole, and
 *     no temporary file is left beside it. A second run changes nothing.
 * (c) The node then runs on the new database: `php index.php once` creates
 *     it at sqlite_path and exits 0.
 * (d) It refuses, changing nothing: --dry-run; a PHP config; no host_url;
 *     a relative sqlite_path.
 *
 * On main dff7500 index.php has no switch-storage mode, so (b)-(d) fail.
 *
 * Run: php php/tests/switch_storage_test.php
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
        echo "  ok   {$label}\n";
    } else {
        $fail++;
        echo "  FAIL {$label}" . ($detail === '' ? '' : " — {$detail}") . "\n";
    }
}

require_once $src . '/index.php';
require_once $src . '/lib/swoole_node.php';
require_once $src . '/lib/storage_switch.php';

use ReticulumPhp\Config;
use ReticulumPhp\StorageSwitch;

echo "(a) rewrite\n";
$wanted = StorageSwitch::wanted('/data/node.sqlite');
$in = "host_url = \"https://x/r\"\n[storage]\n# backend = \"mysql\"\nbackend = \"mysql\"  # live\nmysql_pass = \"pw\"\n\n[http]\nbackend = \"keep\"\n\n[storage]\nlog_path = \"/l\"\nsqlite_path = \"/old.sqlite\"\n[swoole]\nenable_swoole = false\n";
$out = StorageSwitch::rewrite($in, $wanted);
check('in place, in either [storage] table, the rest unchanged',
    $out === "host_url = \"https://x/r\"\n[storage]\n# backend = \"mysql\"\nbackend = \"sqlite\"\nmysql_pass = \"pw\"\n\n[http]\nbackend = \"keep\"\n\n[storage]\nlog_path = \"/l\"\nsqlite_path = \"/data/node.sqlite\"\n[swoole]\nenable_swoole = true\n", $out);
$out = StorageSwitch::rewrite("[storage]\nmysql_pass = \"pw\"\n[php]\nmemory_limit = \"128M\"", $wanted);
check('missing keys go under the first header; a missing section is appended',
    $out === "[storage]\nbackend = \"sqlite\"\nsqlite_path = \"/data/node.sqlite\"\nmysql_pass = \"pw\"\n[php]\nmemory_limit = \"128M\"\n\n[swoole]\nenable_swoole = true\n", $out);
$crlf = StorageSwitch::rewrite("[storage]\r\nbackend = \"mysql\"\r\n", StorageSwitch::wanted(null));
check('CRLF kept', $crlf === "[storage]\r\nbackend = \"sqlite\"\r\n\r\n[swoole]\r\nenable_swoole = true\r\n", json_encode($crlf));
check('a second rewrite changes nothing', StorageSwitch::rewrite($out, $wanted) === $out);

$tmp = sys_get_temp_dir() . '/switch-storage-' . bin2hex(random_bytes(4));
function freshNode(string $tmp, string $src, string $config, string $name = 'config.local.toml'): string
{
    $root = $tmp . '/node-' . bin2hex(random_bytes(3));
    mkdir($root . '/lib', 0755, true);
    foreach (glob($src . '/*.php') as $file) {
        copy($file, $root . '/' . basename($file));
    }
    foreach (glob($src . '/lib/*.php') as $file) {
        copy($file, $root . '/lib/' . basename($file));
    }
    file_put_contents($root . '/' . $name, $config);
    chmod($root . '/' . $name, 0640);

    return $root;
}
/** @return array{0: int, 1: string} */
function cli(string $root, array $args, string $home): array
{
    $command = array_merge([PHP_BINARY, $root . '/index.php'], $args);
    $process = proc_open($command, [1 => ['pipe', 'w'], 2 => ['redirect', 1]], $pipes, $root, ['HOME' => $home, 'PATH' => getenv('PATH') ?: '/usr/bin:/bin']);
    $output = (string) stream_get_contents($pipes[1]);
    fclose($pipes[1]);

    return [proc_close($process), $output];
}

$secret = 'pw-' . bin2hex(random_bytes(6));
$frontSecret = bin2hex(random_bytes(8));
$template = (string) file_get_contents($src . '/config.template.toml');
$template = str_replace('https://your-domain.com/reticulum', 'https://node.example/r-' . $frontSecret, $template);
$template = preg_replace('/^mysql_pass = .*$/m', 'mysql_pass = "' . $secret . '"', $template, 1, $hadPass);
if ($hadPass === 0) {
    $template = preg_replace('/^\[storage\]$/m', "[storage]\nmysql_pass = \"{$secret}\"", $template, 1);
}
$config = $template;
$home = $tmp . '/home';
mkdir($home, 0755, true);

echo "(b) switch-storage on the template's config\n";
{
    $root = freshNode($tmp, $src, $config);
    $sqlite = $tmp . '/data-' . bin2hex(random_bytes(3)) . '/node.sqlite';
    [$status, $output] = cli($root, ['switch-storage', '--sqlite-path', $sqlite], $home);
    check('exits 0', $status === 0, $output);
    check('prints no value from the file', !str_contains($output, $secret) && !str_contains($output, $frontSecret) && !str_contains($output, $sqlite) , $output);
    $backups = glob($home . '/reticulum-config-backup/config.local.toml.*') ?: [];
    check('one copy of the old file, 0600', count($backups) === 1 && file_get_contents($backups[0]) === $config && (fileperms($backups[0]) & 0777) === 0600);
    check('the config keeps its mode', (fileperms($root . '/config.local.toml') & 0777) === 0640);
    $loaded = Config::load($root);
    check('loads as SQLite at sqlite_path with Swoole on', $loaded['storage']['backend'] === 'sqlite' && $loaded['storage']['sqlite_path'] === $sqlite && $loaded['swoole']['enable_swoole'] === true);
    check('the MySQL settings are still there, for a rollback', $loaded['storage']['mysql_pass'] === $secret);
    $others = static fn (string $text): array => array_values(preg_grep('/^(backend|sqlite_path|enable_swoole) = /', explode("\n", $text), PREG_GREP_INVERT));
    $written = (string) file_get_contents($root . '/config.local.toml');
    check('no other line changed', $others($written) === $others($config));
    check('the three lines as written', preg_match_all('/^backend = "sqlite"$/m', $written) === 1 && preg_match_all('/^sqlite_path = /m', $written) === 1 && preg_match_all('/^enable_swoole = true$/m', $written) === 1);
    check('no temporary file left', glob($root . '/*.tmp') === []);
    [$status, $output] = cli($root, ['switch-storage', '--sqlite-path', $sqlite], $home);
    check('a second run changes nothing', $status === 0 && str_contains($output, 'nothing to change') && count(glob($home . '/reticulum-config-backup/*') ?: []) === 1, $output);

    echo "(c) the node runs on the new database\n";
    [$status, $output] = cli($root, ['once'], $home);
    check('`once` exits 0 and creates the database', $status === 0 && is_file($sqlite), substr($output, 0, 400));
}

echo "(d) refusals change nothing\n";
$refuses = static function (string $label, string $config, array $args, string $name = 'config.local.toml') use ($tmp, $src, $home): void {
    $root = freshNode($tmp, $src, $config, $name);
    [$status, $output] = cli($root, array_merge(['switch-storage'], $args), $home);
    check($label, $status !== 0 || str_contains($output, '--dry-run'), $output);
    check($label . ': file unchanged', file_get_contents($root . '/' . $name) === $config);
};
$refuses('--dry-run writes nothing', $config, ['--dry-run']);
$refuses('a PHP config', "<?php return ['storage' => ['backend' => 'mysql']];\n", [], 'config.php');
$refuses('no host_url', preg_replace('/^host_url = .*$/m', '', $config, 1), []);
$refuses('a relative sqlite_path', $config, ['--sqlite-path', 'var/x.sqlite']);

exec('rm -rf ' . escapeshellarg($tmp));
echo "\n{$pass} passed, {$fail} failed\n";
exit($fail === 0 ? 0 : 1);
