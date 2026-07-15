<?php

declare(strict_types=1);

/**
 * Reticulum PHP Monitor
 * Standalone — reads config.toml directly, no reticulum class dependencies.
 */

function monitorLoadConfig(string $root): array
{
    $path = $root . '/config.toml';
    if (!is_file($path)) die('config.toml not found');
    $raw = file_get_contents($path);
    if ($raw === false) die('cannot read config.toml');
    $lines = explode("\n", $raw);
    $config = [];
    $section = '';
    foreach ($lines as $line) {
        $line = trim($line);
        if ($line === '' || $line[0] === '#') continue;
        if (preg_match('/^\[(\w+)\]$/', $line, $m)) { $section = $m[1]; if (!isset($config[$section])) $config[$section] = []; continue; }
        if (preg_match('/^(\w+)\s*=\s*(.+)$/', $line, $m)) {
            $val = trim($m[2], " \t\n\r\0\x0B\"'");
            if ($section !== '') $config[$section][$m[1]] = $val; else $config[$m[1]] = $val;
        }
    }
    return $config;
}

$root = __DIR__;
$config = monitorLoadConfig($root);
$storage = $config['storage'] ?? [];
$backend = $storage['backend'] ?? 'mysql';

if ($backend === 'mysql') {
    $dsn = sprintf('mysql:host=%s;port=%d;dbname=%s;charset=utf8mb4',
        $storage['mysql_host'] ?? '127.0.0.1',
        (int)($storage['mysql_port'] ?? 3306),
        $storage['mysql_dbname'] ?? 'reticulum_php');
    $db = new PDO($dsn, $storage['mysql_user'] ?? 'root', $storage['mysql_pass'] ?? '', [
        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
    ]);
} else {
    $db = new PDO('sqlite:' . ($storage['sqlite_path'] ?? ($root . '/var/reticulum-php.sqlite')), null, null, [
        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
    ]);
}

$TABLES = [
    'inbound_packets', 'inbound_batches',
    'outbound_packets', 'outbound_batches',
    'packet_hashes', 'path_request_tags',
    'reverse_path_entries', 'link_transport_entries',
    'path_entries', 'known_destinations', 'local_destinations',
    'wake_events', 'php_peer_sessions', 'post_interface_peers',
    'transport_state',
    'interfaces',
];

$action = $_GET['action'] ?? '';
$message = '';
$cleared = false;

if ($action === 'clear' && ($_SERVER['REQUEST_METHOD'] ?? '') === 'POST') {
    if (($_POST['confirm'] ?? '') === 'YES') {
        foreach ($TABLES as $t) {
            try { $db->exec($backend === 'mysql' ? "DELETE FROM `{$t}`" : "DELETE FROM {$t}"); }
            catch (\Throwable $e) { $message .= "{$t}: " . $e->getMessage() . "\n"; }
        }
        if ($message === '') { $message = 'All tables cleared.'; $cleared = true; }
    } else { $message = 'Type YES to confirm.'; }
}

$tables = []; $total = 0;
foreach ($TABLES as $t) {
    try { $n = (int)$db->query($backend === 'mysql' ? "SELECT COUNT(*) FROM `{$t}`" : "SELECT COUNT(*) FROM {$t}")->fetchColumn(); $tables[$t] = $n; $total += $n; }
    catch (\Throwable $e) { $tables[$t] = -1; }
}

header('Content-Type: text/html; charset=utf-8');
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Reticulum Monitor</title>
<style>
body { font-family: -apple-system, sans-serif; max-width: 600px; margin: 2em auto; padding: 0 1em; background: #111; color: #eee; }
h1 { font-size: 1.3em; }
table { width: 100%; border-collapse: collapse; margin: 1em 0; }
th, td { text-align: left; padding: 4px 8px; border-bottom: 1px solid #333; }
.total { font-weight: bold; }
.danger { background: #c00; color: #fff; border: none; padding: 10px 20px; font-size: 1em; cursor: pointer; }
.danger:hover { background: #f00; }
input[type=text] { padding: 8px; font-size: 1em; margin-right: 8px; background: #222; color: #eee; border: 1px solid #555; }
.msg { padding: 10px; margin: 1em 0; border-radius: 4px; }
.msg.ok { background: #063; }
.msg.err { background: #600; }
</style>
</head>
<body>

<h1>Reticulum Monitor</h1>
<p>Host: <?=htmlspecialchars($config['host_url'] ?? 'unknown')?> | Backend: <?=htmlspecialchars($backend)?></p>

<?php if ($message !== ''): ?>
<div class="msg <?=$cleared ? 'ok' : 'err'?>"><?=nl2br(htmlspecialchars($message))?></div>
<?php endif; ?>

<h2>Tables (<?=count($tables)?> — <?=number_format($total)?> total rows)</h2>
<table>
<tr><th>Table</th><th>Rows</th></tr>
<?php foreach ($tables as $name => $count): ?>
<?php $s = $count === -1 ? ' style="color:#f66"' : ($count > 10000 ? ' style="color:#fa0"' : ''); ?>
<tr><td><?=$name?></td><td<?=$s?>><?=$count === -1 ? 'ERROR' : number_format($count)?></td></tr>
<?php endforeach; ?>
<tr class="total"><td>Total</td><td><?=number_format($total)?></td></tr>
</table>

<h2>Clear All Data</h2>
<form method="POST" action="?action=clear" onsubmit="return confirm('Delete ALL rows from ALL tables?')">
<input type="text" name="confirm" placeholder="Type YES to confirm" required autocomplete="off" style="width:200px">
<button type="submit" class="danger">Clear All Data</button>
</form>

</body>
</html>
