<?php
/**
 * The PHP node has no TCP bridge.
 *
 * James decided on 2026-10-04 to remove the TCP bridge from index.php:
 * TcpBridgeConfig, TcpBridgeState, TcpBridgeHdlc, TcpBridgeHttpClient,
 * TcpBridgeDaemon, runTcpBridge(), wakeTcpBridge(), and the config
 * normalising that fed them (Config::normalizeTcpBridgeConfig() and
 * synthesizeTcpBridgeConfig(), for a [tcp_bridge] block or an enabled
 * `type = TcpBridgeInterface` entry under [interfaces]). Nothing ever started
 * it: no CLI mode ran it, nothing in the workspace called either function,
 * and the tcp_bridge.php that the [wake] profile named until e3c05ea is in no
 * commit of this repository. Started, it would have been a long-running
 * process (a stream_select loop holding a TCP socket and a control socket),
 * and the PHP node starts no process but the storage reclaim
 * (only_storage_reclaim_starts_a_process_test.php).
 *
 * (a) The scanners are run on samples first, so a scanner that finds nothing
 *     cannot pass.
 * (b) No file under php/ outside php/tests (code, comments, the config
 *     templates) and not README.md names the bridge: "tcp bridge" in any
 *     spelling (TcpBridge*, tcp_bridge, tcp-bridge, TcpBridgeInterface,
 *     __tcp_bridge_local__), its control socket (rphp-bridge-), or a config
 *     key only it read (control_state_path, control_listen_host,
 *     control_listen_port, wake_profile, wake_target, read_chunk_bytes,
 *     target_host, target_port). A comment that names removed code sends
 *     the reader to code that does not exist.
 * (c) With index.php and every lib/ file it requires loaded, no class,
 *     interface, trait, function, constant or method of ReticulumPhp is a
 *     bridge one.
 * (d) Config::load(): a config.toml laid out like the live ones (2026-10-04)
 *     loads with its [interfaces] entry as written and no tcp_bridge key; a
 *     leftover [tcp_bridge] block or TcpBridgeInterface entry is no longer
 *     normalised (nothing is added to it, nothing is required of it); and the
 *     check kept from the old normaliser still refuses an [interfaces] that
 *     is not an object, or an entry in it that is not one.
 * (e) php/src names no 'wake' key in code. The bridge registered with
 *     metadata.wake (profile, target); a client that still sends one, and a
 *     live config's [wake] block, stay ignored because nothing reads them.
 *
 * On 1d99d49 this fails: (b) lists every bridge line of index.php, (c) finds
 * the five classes, the two functions and Config's two normalising methods,
 * (d) finds the [tcp_bridge] block given control_* and wake_* keys and the
 * TcpBridgeInterface entry refused for want of base_url, and (e) finds
 * TcpBridgeConfig::interfaceMetadata()'s 'wake'.
 *
 * Run: php php/tests/tcp_bridge_removed_test.php
 * TCP_BRIDGE_SCAN_ROOT points it at another checkout of this repository (the
 * directory holding php/ and README.md), for the before and mutation checks.
 */
declare(strict_types=1);

const BRIDGE_PATTERNS = [
    'tcp bridge' => '/tcp[\s_-]*bridge/i',
    'its control socket' => '/rphp-bridge/i',
    'a config key only the bridge read' => '/\b(control_state_path|control_listen_host|control_listen_port|wake_profile|wake_target|read_chunk_bytes|target_host|target_port)\b/',
];

/** @return list<array{line: int, what: string, text: string}> each line of $text that names the bridge */
function bridgeMentions(string $text): array
{
    $found = [];
    foreach (preg_split('/\r\n|\n|\r/', $text) ?: [] as $index => $line) {
        foreach (BRIDGE_PATTERNS as $what => $pattern) {
            if (preg_match($pattern, $line) === 1) {
                $found[] = ['line' => $index + 1, 'what' => $what, 'text' => trim($line)];
                break;
            }
        }
    }

    return $found;
}

/** @return list<int> the lines of $code where a string literal is exactly 'wake' or "wake" */
function wakeKeyLiterals(string $code): array
{
    $lines = [];
    foreach (token_get_all($code) as $token) {
        if (is_array($token) && $token[0] === T_CONSTANT_ENCAPSED_STRING
            && strtolower(substr($token[1], 1, -1)) === 'wake') {
            $lines[] = $token[2];
        }
    }

    return $lines;
}

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

$describe = static fn (array $found): string => implode('; ', array_map(
    static fn (array $f): string => ($f['file'] ?? '') . ':' . $f['line'] . ' ' . $f['what'] . ': ' . substr($f['text'], 0, 100),
    $found
));

echo "(a) the scanners find the bridge and the 'wake' key, and nothing else\n";
$samples = [
    'a bridge class' => ['final class TcpBridgeDaemon', 1],
    'its config key and normaliser' => ["\$c = self::normalizeTcpBridgeConfig(\$root, \$config);\n\$b = \$c['tcp_bridge'];", 2],
    'its interface type in a config template' => ["[[Old Bridge]]\ntype = TcpBridgeInterface", 1],
    'its wake profile and state file' => ["'__tcp_bridge_local__' . \$slug\n'/var/tcp-bridge-' . \$slug", 2],
    'a comment naming it' => ['// The TCP bridge wakes the next request.', 1],
    'its control socket' => ["'rphp-bridge-' . \$hash", 1],
    'a config key only it read' => ["control_state_path = \"x\"\n\$p = \$b['target_port'];\nwake_target", 3],
    'the PostInterface bridge, the gateway transport and a test listener' => [
        "[[PostInterface Bridge]]\n'transport' => 'tcp-backbone-gateway'\nstream_socket_server('tcp://127.0.0.1:0')\n// Bridge interface dedup\nsingle_bridge_copy_test.php\n'wake_url'",
        0,
    ],
];
foreach ($samples as $label => [$text, $expected]) {
    $found = bridgeMentions($text);
    check("$label: $expected found", count($found) === $expected, $describe($found));
}
$wakeSamples = [
    "a 'wake' key in single and double quotes" => ['<?php $a = [\'wake\' => 1]; $b = $m["wake"] ?? null;', 2],
    'a route, other keys, a comment and a word in a longer string' => [
        "<?php \$p = '/v1/wake'; \$u = \$m['wake_url']; // \$m['wake']\n\$s = 'wake the peer'; \$t = 'waker_url';",
        0,
    ],
];
foreach ($wakeSamples as $label => [$code, $expected]) {
    $lines = wakeKeyLiterals($code);
    check("$label: $expected found", count($lines) === $expected, implode(', ', $lines));
}

$root = rtrim(getenv('TCP_BRIDGE_SCAN_ROOT') ?: dirname(__DIR__, 2), '/');

echo "(b) nothing under php/ outside php/tests, and not README.md, names the bridge\n";
$files = [];
$iterator = new RecursiveIteratorIterator(
    new RecursiveCallbackFilterIterator(
        new RecursiveDirectoryIterator($root . '/php', FilesystemIterator::SKIP_DOTS),
        static fn (SplFileInfo $file): bool => !$file->isDir()
            || !in_array($file->getPathname(), [$root . '/php/tests', $root . '/php/var', $root . '/php/src/var'], true),
    )
);
foreach ($iterator as $file) {
    if ($file->isFile() && in_array(strtolower($file->getExtension()), ['php', 'toml', 'bak', 'md'], true)) {
        $files[] = $file->getPathname();
    }
}
if (is_file($root . '/README.md')) {
    $files[] = $root . '/README.md';
}
sort($files);
check('there are files to scan: index.php, lib/, the config templates, README.md',
    in_array($root . '/php/src/index.php', $files, true)
        && in_array($root . '/php/src/config.template.toml', $files, true)
        && in_array($root . '/README.md', $files, true)
        && count($files) >= 15,
    (string) count($files));

$mentions = [];
foreach ($files as $path) {
    foreach (bridgeMentions((string) file_get_contents($path)) as $found) {
        $found['file'] = substr($path, strlen($root) + 1);
        $mentions[] = $found;
    }
}
check('no line names the bridge', $mentions === [], count($mentions) . ' lines: ' . $describe(array_slice($mentions, 0, 12)));

echo "(c) loaded, ReticulumPhp declares nothing of the bridge\n";
require_once $root . '/php/src/lib/database.php';
require_once $root . '/php/src/index.php';

$isBridge = static fn (string $name): bool => preg_match('/tcp_?bridge/i', $name) === 1;
$ours = static fn (array $names): array => array_values(array_filter(
    $names,
    static fn (string $name): bool => stripos($name, 'ReticulumPhp\\') === 0,
));
$classes = $ours(array_merge(get_declared_classes(), get_declared_interfaces(), get_declared_traits()));
$functions = $ours(get_defined_functions()['user']);
$constants = $ours(array_keys(get_defined_constants(true)['user'] ?? []));
check('the node is loaded: Config, Storage, HttpApi, initializeRuntime() and its traits',
    class_exists('ReticulumPhp\\Config', false) && class_exists('ReticulumPhp\\Storage', false)
        && class_exists('ReticulumPhp\\HttpApi', false) && function_exists('ReticulumPhp\\initializeRuntime')
        && count($classes) >= 15,
    count($classes) . ' classes, interfaces and traits');

$declared = array_values(array_filter(array_merge($classes, $functions, $constants), $isBridge));
foreach ($classes as $class) {
    $reflection = new ReflectionClass($class);
    foreach ($reflection->getMethods() as $method) {
        if ($method->getDeclaringClass()->getName() === $reflection->getName() && $isBridge($method->getName())) {
            $declared[] = $class . '::' . $method->getName() . '()';
        }
    }
    foreach (array_keys($reflection->getConstants()) as $constant) {
        if ($isBridge($constant)) {
            $declared[] = $class . '::' . $constant;
        }
    }
}
check('no class, interface, trait, function, constant or method is a bridge one', $declared === [], implode(', ', $declared));
foreach (['TcpBridgeConfig', 'TcpBridgeState', 'TcpBridgeHdlc', 'TcpBridgeHttpClient', 'TcpBridgeDaemon'] as $class) {
    check("no class $class", !class_exists('ReticulumPhp\\' . $class, false));
}
foreach (['runTcpBridge', 'wakeTcpBridge'] as $function) {
    check("no function $function()", !function_exists('ReticulumPhp\\' . $function));
}
foreach (['normalizeTcpBridgeConfig', 'synthesizeTcpBridgeConfig'] as $method) {
    check("no Config::$method()", !method_exists('ReticulumPhp\\Config', $method));
}

echo "(d) Config::load() reads the live layout and no longer normalises a bridge\n";
$tmp = sys_get_temp_dir() . '/reticulum-tcp-bridge-removed-' . bin2hex(random_bytes(4));
mkdir($tmp, 0775, true);

/** @return array{?array, ?string} the loaded config, or the message it was refused with */
$load = static function (string $name, string $file, string $contents) use ($tmp): array {
    $dir = $tmp . '/' . $name;
    mkdir($dir, 0775, true);
    file_put_contents($dir . '/' . $file, $contents);
    try {
        return [\ReticulumPhp\Config::load($dir), null];
    } catch (\Throwable $error) {
        return [null, $error->getMessage()];
    }
};

// config.toml as both live nodes lay it out on 2026-10-04 (as in
// live_interfaces_peering_test.php): host_url, [wake], [storage], [http],
// [maintenance], [transport], a second [storage] for log_path, and one
// [interfaces] entry naming the peer.
$liveToml = <<<TOML
host_url = "https://node-a.invalid/reticulum"

[wake]
dispatch_limit = 4

[storage]
backend = "sqlite"
sqlite_path = "{$tmp}/node.sqlite"

[http]
idle_exchange_interval_ms = 1000
max_batch_packets = 64
max_packet_bytes = 512

[maintenance]
interface_stale_after_seconds = 300
batch_ttl_seconds = 86400

[transport]
rns_mtu = 500
pathfinder_max_hops = 128

[storage]
log_path = "{$tmp}/router.log"

[interfaces]

[[Node B]]
type = PostInterface
enabled = yes
node_url = "https://node-b.invalid/reticulum"
wake_url = "https://node-a.invalid/reticulum/v1/wake"
bitrate = 62500
mtu = 500
TOML;

[$live, $error] = $load('live', 'config.toml', $liveToml);
check('the live layout loads', is_array($live), (string) $error);
$live ??= [];
check('its [interfaces] entry is as written', ($live['interfaces'] ?? null) === ['Node B' => [
    'type' => 'PostInterface',
    'enabled' => true,
    'node_url' => 'https://node-b.invalid/reticulum',
    'wake_url' => 'https://node-a.invalid/reticulum/v1/wake',
    'bitrate' => 62500,
    'mtu' => 500,
]], json_encode($live['interfaces'] ?? null));
check('and nothing names a bridge', !array_key_exists('tcp_bridge', $live), json_encode(array_keys($live)));
check('host_url, the second [storage] and [debug] are normalised as before',
    ($live['host_url'] ?? null) === 'https://node-a.invalid/reticulum'
        && ($live['storage']['log_path'] ?? null) === $tmp . '/router.log'
        && ($live['storage']['sqlite_path'] ?? null) === $tmp . '/node.sqlite'
        && ($live['debug'] ?? null) === ['enabled' => false, 'max_rows' => 20]
        && ($live['http']['idle_exchange_interval_ms'] ?? null) === 1000,
    json_encode([$live['host_url'] ?? null, $live['storage'] ?? null, $live['debug'] ?? null]));

$leftoverBlock = <<<TOML
host_url = "https://node-a.invalid/reticulum"

[tcp_bridge]
base_url = "https://node-a.invalid/reticulum"
target_host = "127.0.0.1"
target_port = 4242
TOML;
[$block, $error] = $load('block', 'config.toml', $leftoverBlock);
check('a leftover [tcp_bridge] block loads', is_array($block), (string) $error);
check('and is left exactly as written: no control_* or wake_* key is added to it',
    ($block['tcp_bridge'] ?? null) === [
        'base_url' => 'https://node-a.invalid/reticulum',
        'target_host' => '127.0.0.1',
        'target_port' => 4242,
    ],
    json_encode($block['tcp_bridge'] ?? null));

$leftoverEntry = <<<TOML
host_url = "https://node-a.invalid/reticulum"

[interfaces]

[[Old Bridge]]
type = TcpBridgeInterface
enabled = yes
TOML;
[$entry, $error] = $load('entry', 'config.toml', $leftoverEntry);
check('a leftover TcpBridgeInterface entry loads: nothing requires base_url, target_host or target_port of it',
    is_array($entry), (string) $error);
check('and no tcp_bridge block is made from it', is_array($entry) && !array_key_exists('tcp_bridge', $entry),
    json_encode($entry['tcp_bridge'] ?? null));

[$scalar, $error] = $load('scalar', 'config.php', "<?php return ['interfaces' => 'Node B'];");
check('[interfaces] that is not an object is still refused',
    $scalar === null && $error === 'interfaces configuration must be an object', (string) $error);
[$scalarEntry, $error] = $load('scalar-entry', 'config.php', "<?php return ['interfaces' => ['Node B' => 'https://node-b.invalid']];");
check('an [interfaces] entry that is not an object is still refused',
    $scalarEntry === null && $error === 'interfaces.Node B must be an object', (string) $error);

foreach (new RecursiveIteratorIterator(new RecursiveDirectoryIterator($tmp, FilesystemIterator::SKIP_DOTS), RecursiveIteratorIterator::CHILD_FIRST) as $file) {
    $file->isDir() ? rmdir($file->getPathname()) : unlink($file->getPathname());
}
rmdir($tmp);

echo "(e) php/src names no 'wake' key: a client's metadata.wake and a [wake] block stay ignored\n";
$wakeKeys = [];
$sourceFiles = 0;
$sources = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($root . '/php/src', FilesystemIterator::SKIP_DOTS));
foreach ($sources as $file) {
    if (!$file->isFile() || strtolower($file->getExtension()) !== 'php') {
        continue;
    }
    $sourceFiles++;
    foreach (wakeKeyLiterals((string) file_get_contents($file->getPathname())) as $line) {
        $wakeKeys[] = substr($file->getPathname(), strlen($root) + 1) . ':' . $line;
    }
}
check('php/src has php files to scan', $sourceFiles >= 10, (string) $sourceFiles);
check("no string literal 'wake' in php/src", $wakeKeys === [], implode(', ', $wakeKeys));

echo "\n$pass passed, $fail failed\n";
exit($fail === 0 ? 0 : 1);
