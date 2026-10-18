<?php
/**
 * An [interfaces] entry is a peer only while it is on and a PostInterface (L76).
 *
 * WHAT THIS EXISTS TO PREVENT
 * ===========================
 * Both live configs (2026-10-04) write their peer as
 *
 *   [[Peer]]
 *   type = PostInterface
 *   enabled = yes
 *   node_url = "https://peer/reticulum"
 *
 * and configuredPeerEndpoints() read only node_url (or peer_url): every entry
 * with one was a peer, so `enabled = no` did nothing, and an operator could
 * not turn a peer off by config. initialize, the heal in maintenance and the
 * admin page all take their peers from it.
 *
 * As in RNS, an entry with `enabled` or `interface_enabled` is on only if one
 * of them is true, and a `type` must be PostInterface. An entry with neither
 * switch stays on, as before; RNS would take it as off.
 *
 * Run: php php/tests/interfaces_enabled_and_type_test.php
 */
declare(strict_types=1);

$root = dirname(__DIR__);
require_once $root . '/src/lib/database.php';
require_once $root . '/src/index.php';

use ReticulumPhp\Config;
use ReticulumPhp\Storage;

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

/** The peers a node with this config file would register at, by name. */
function peersFor(string $file, string $contents): array
{
    $dir = sys_get_temp_dir() . '/interfaces-enabled-' . bin2hex(random_bytes(4));
    mkdir($dir);
    file_put_contents("{$dir}/{$file}", $contents);
    try {
        $config = Config::load($dir);
    } finally {
        unlink("{$dir}/{$file}");
        rmdir($dir);
    }
    $config['storage'] = ['backend' => 'sqlite', 'sqlite_path' => ':memory:'];
    $storage = new Storage($config);

    return (new ReflectionMethod($storage, 'configuredPeerEndpoints'))->invoke($storage);
}

echo "config.toml, laid out as the live nodes write it:\n";
$peers = peersFor('config.toml', <<<'TOML'
[interfaces]

[[Live]]
type = PostInterface
enabled = yes
node_url = "https://live.test/reticulum"

[[Bare]]
node_url = "https://bare.test/reticulum"

[[Off]]
type = PostInterface
enabled = no
node_url = "https://off.test/reticulum"

[[OffFalse]]
type = PostInterface
enabled = false
node_url = "https://off-false.test/reticulum"

[[OffRns]]
type = PostInterface
interface_enabled = no
node_url = "https://off-rns.test/reticulum"

[[EitherOn]]
type = PostInterface
enabled = no
interface_enabled = yes
node_url = "https://either-on.test/reticulum"

[[Tcp]]
type = TCPClientInterface
enabled = yes
node_url = "https://tcp.test/reticulum"
TOML);
$names = array_keys($peers);
check('type = PostInterface, enabled = yes is a peer', isset($peers['Live']), implode(', ', $names));
check('an entry with neither switch nor type is still a peer', isset($peers['Bare']), implode(', ', $names));
check('enabled = no is not a peer', !isset($peers['Off']), implode(', ', $names));
check('enabled = false is not a peer', !isset($peers['OffFalse']), implode(', ', $names));
check('interface_enabled = no is not a peer', !isset($peers['OffRns']), implode(', ', $names));
check('enabled = no with interface_enabled = yes is a peer, as in RNS', isset($peers['EitherOn']), implode(', ', $names));
check('type = TCPClientInterface is not a peer, node_url or not', !isset($peers['Tcp']), implode(', ', $names));
check('and the peers keep their URLs',
    ($peers['Live'] ?? null) === ['exchange_url' => 'https://live.test/reticulum', 'wake_url' => 'https://live.test/reticulum/v1/wake'],
    json_encode($peers['Live'] ?? null));

echo "config.php, whose values come as PHP gives them:\n";
$peers = peersFor('config.php', <<<'PHP'
<?php
return ['interfaces' => [
    'StrNo' => ['type' => 'PostInterface', 'enabled' => 'no', 'node_url' => 'https://a.test'],
    'StrFalse' => ['enabled' => 'false', 'node_url' => 'https://b.test'],
    'StrZero' => ['enabled' => '0', 'node_url' => 'https://c.test'],
    'IntZero' => ['enabled' => 0, 'node_url' => 'https://d.test'],
    'Off' => ['enabled' => 'off', 'node_url' => 'https://e.test'],
    'BoolTrue' => ['type' => 'PostInterface', 'enabled' => true, 'node_url' => 'https://f.test'],
    'StrYes' => ['enabled' => 'Yes', 'node_url' => 'https://g.test'],
    'IntOne' => ['enabled' => 1, 'node_url' => 'https://h.test'],
    'TypeSpaced' => ['type' => ' PostInterface ', 'node_url' => 'https://i.test'],
]];
PHP);
$names = array_keys($peers);
sort($names);
check("'no', 'false', '0', 0 and 'off' are off; true, 'Yes', 1 on",
    $names === ['BoolTrue', 'IntOne', 'StrYes', 'TypeSpaced'], implode(', ', $names));

echo "\n$pass passed, $fail failed\n";
exit($fail === 0 ? 0 : 1);
