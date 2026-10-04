<?php
/**
 * A client-supplied metadata.wake_url makes this node do nothing.
 *
 * THE DEAD PATH (live on d4ceda7)
 * ===============================
 * The wake_url path of 2026-07-03 (f19a8d7) was superseded on 2026-07-10
 * (606d800) by peer_url and the inline fire-and-forget wakes of
 * RequestPhpWakeTrait, and never removed. It stayed reachable by anyone:
 * registerInterface() stored the registration metadata as given;
 * queueOutboundPacket() then inserted a wake_events row
 * (scheduleWakeEventIfNeeded) whenever packets queued for a row whose
 * metadata carried a wake_url, which is every announce and every forwarded
 * path request; the next request's epilogue ran
 * `exec("php index.php wake-event <id> &")` for each row, and that process
 * (or `php index.php once`) POSTed <wake_url>/v1/wake. So a registration could
 * make the node start a process per wake event and send requests to a URL of
 * the registrant's choosing. James decided on 2026-10-04 that the PHP node
 * starts no process except the storage reclaim.
 *
 * WHAT THIS PINS
 * ==============
 * (a) registration strips metadata.wake_url on all three of
 *     registerInterface()'s paths (new row, identity re-bind, PHP-peer
 *     re-bind), says [REG-WAKE-URL-IGNORED] once per registration, and still
 *     stores what the live peering needs (peer_url and its credentials);
 * (b) packets queued for such a row leave no wake_events row, and the request
 *     epilogue starts no process and connects to nothing but the PHP peer's
 *     own peer_url (the live wake, which must keep working);
 * (c) `php index.php once` contacts nobody, and `php index.php wake-event`
 *     is no longer a mode;
 * (d) a fresh database has neither wake_events nor post_interface_peers, and
 *     a database that has them (both live nodes do) keeps them and their
 *     rows through the migration, with no error;
 * (e) /health's queues and /debug carry no wake_events counts.
 *
 * Every process-starting function is replaced in namespace ReticulumPhp (the
 * traits call them unqualified, so these answer first): a call is recorded
 * and nothing runs. The registrant's wake_url is a listening socket nobody
 * may connect to; the PHP peer's peer_url is another, which the live wake
 * must reach.
 *
 * On d4ceda7 (a), (b), (c), (d) and (e) fail. Run:
 *   php php/tests/wake_url_path_removed_test.php
 */
declare(strict_types=1);

namespace ReticulumPhp;

final class Spawned
{
    /** @var list<string> */
    public static array $calls = [];
}

function exec(string $command, mixed &$output = null, mixed &$result_code = null): string|false
{
    Spawned::$calls[] = 'exec ' . $command;
    $output = [];
    $result_code = 0;
    return '';
}

function shell_exec(string $command): string|false|null
{
    Spawned::$calls[] = 'shell_exec ' . $command;
    return null;
}

function system(string $command, mixed &$result_code = null): string|false
{
    Spawned::$calls[] = 'system ' . $command;
    $result_code = 0;
    return '';
}

function passthru(string $command, mixed &$result_code = null): ?bool
{
    Spawned::$calls[] = 'passthru ' . $command;
    $result_code = 0;
    return null;
}

function proc_open(mixed $command, array $descriptors, mixed &$pipes, mixed ...$rest): mixed
{
    Spawned::$calls[] = 'proc_open ' . json_encode($command);
    return false;
}

function popen(string $command, string $mode): mixed
{
    Spawned::$calls[] = 'popen ' . $command;
    return false;
}

$root = dirname(__DIR__);
require_once $root . '/src/lib/database.php';
require_once $root . '/src/index.php';

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
    \mkdir($to, 0775, true);
    foreach (\scandir($from) ?: [] as $entry) {
        if ($entry === '.' || $entry === '..' || \str_starts_with($entry, 'config.') || $entry === 'build.json') {
            continue;
        }
        $path = $from . '/' . $entry;
        \is_dir($path) ? copyTree($path, $to . '/' . $entry) : \copy($path, $to . '/' . $entry);
    }
}

function removeTree(string $dir): void
{
    foreach (\scandir($dir) ?: [] as $entry) {
        if ($entry === '.' || $entry === '..') {
            continue;
        }
        $path = $dir . '/' . $entry;
        \is_dir($path) && !\is_link($path) ? removeTree($path) : @\unlink($path);
    }
    @\rmdir($dir);
}

/** @return array{0: resource, 1: string} a listening socket and its http:// URL */
function listener(): array
{
    $server = \stream_socket_server('tcp://127.0.0.1:0', $errno, $errstr);
    if ($server === false) {
        throw new \RuntimeException("cannot listen: $errstr");
    }
    return [$server, 'http://' . \stream_socket_get_name($server, false)];
}

/** Every connection already made to $server (they wait in the backlog). */
function accepted($server): array
{
    $requests = [];
    while (($conn = @\stream_socket_accept($server, 0)) !== false) {
        \stream_set_timeout($conn, 2);
        $requests[] = (string) \fread($conn, 8192);
        \fclose($conn);
    }
    return $requests;
}

function tableExists(\PDO $pdo, string $table): bool
{
    $stmt = $pdo->prepare("SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = :t");
    $stmt->execute([':t' => $table]);
    return $stmt->fetchColumn() !== false;
}

function rowCount(\PDO $pdo, string $table, string $where = '1 = 1', array $params = []): int
{
    $stmt = $pdo->prepare("SELECT COUNT(*) FROM {$table} WHERE {$where}");
    $stmt->execute($params);
    return (int) $stmt->fetchColumn();
}

function storedMetadata(\PDO $pdo, string $interfaceId): array
{
    $stmt = $pdo->prepare('SELECT metadata_json FROM interfaces WHERE interface_id = :i');
    $stmt->execute([':i' => $interfaceId]);
    $decoded = \json_decode((string) $stmt->fetchColumn(), true);
    return \is_array($decoded) ? $decoded : [];
}

/** A path request a browser sends for a destination nobody has a path to. */
function pathRequestBase64(): string
{
    $control = \hex2bin('6b9f66014d9853faab220fba47d02761'); // rnstransport.path.request
    return \base64_encode(\chr(0x08) . \chr(0x00) . $control . \chr(0x00) . \random_bytes(16) . \random_bytes(16));
}

$work = \sys_get_temp_dir() . '/reticulum-wake-url-removed-' . \bin2hex(\random_bytes(4));
copyTree($root . '/src', $work . '/src');
$errorLog = $work . '/php-errors.log';
\ini_set('error_log', $errorLog);
\ini_set('log_errors', '1');
[$trap, $trapUrl] = listener();       // the registrant's wake_url: nobody may connect
[$peerSock, $peerUrl] = listener();   // a PHP peer's peer_url: the live wake goes here
\file_put_contents($work . '/src/config.toml', \implode("\n", [
    'host_url = "http://127.0.0.1:9/this-node"',
    '',
    '[wake]',
    'dispatch_limit = 4',
    '',
    '[storage]',
    'backend = "sqlite"',
    'sqlite_path = "' . $work . '/node.sqlite"',
    'log_path = "' . $work . '/router.log"',
]) . "\n");
$config = Config::load($work . '/src');
$storage = new Storage($config);
$storage->migrateIfNeeded();
$pdo = new \PDO('sqlite:' . $work . '/node.sqlite');
$pdo->setAttribute(\PDO::ATTR_ERRMODE, \PDO::ERRMODE_EXCEPTION);
$ignoredLines = static fn (): int => \substr_count((string) @\file_get_contents($errorLog), '[REG-WAKE-URL-IGNORED]');

echo "(a) registration does not store a client's wake_url\n";
$browser = $storage->registerInterface('Retichat Web', 1000000, 500, [
    'client' => 'rns-js', 'implementation' => 'PostInterface', 'mode' => 1, 'identity_hash' => \bin2hex(\random_bytes(16)),
]);
check('an ordinary registration logs nothing', $ignoredLines() === 0, (string) $ignoredLines());

$identity = \bin2hex(\random_bytes(16));
$registrantMetadata = [
    'client' => 'rns-post-interface', 'implementation' => 'PostInterface', 'mode' => 6,
    'identity_hash' => $identity, 'wake_url' => $trapUrl,
];
$registrant = $storage->registerInterface('Wake URL registrant', 1000000, 500, $registrantMetadata);
check('a registration carrying wake_url is still registered',
    \is_string($registrant['interface_id'] ?? null) && \is_string($registrant['session_token'] ?? null));
$stored = storedMetadata($pdo, $registrant['interface_id']);
check('its row stores no wake_url', !\array_key_exists('wake_url', $stored), (string) \json_encode($stored));
check('and keeps the rest of its metadata', ($stored['client'] ?? null) === 'rns-post-interface'
    && ($stored['identity_hash'] ?? null) === $identity, (string) \json_encode($stored));
check('[REG-WAKE-URL-IGNORED] is logged once for it', $ignoredLines() === 1, (string) $ignoredLines());
check('the log line does not carry the URL', !\str_contains((string) @\file_get_contents($errorLog), $trapUrl));

$rebound = $storage->registerInterface('Wake URL registrant', 1000000, 500, $registrantMetadata);
check('re-binding by identity_hash keeps the same row', ($rebound['interface_id'] ?? null) === $registrant['interface_id']);
check('and still stores no wake_url', !\array_key_exists('wake_url', storedMetadata($pdo, $registrant['interface_id'])));
check('and logs once more, once per registration', $ignoredLines() === 2, (string) $ignoredLines());

$peerMetadata = [
    'client' => 'reticulum-php', 'peer_url' => $peerUrl,
    'peer_interface_id' => \bin2hex(\random_bytes(16)), 'peer_session_token' => \bin2hex(\random_bytes(32)),
    'wake_url' => $trapUrl . '/v1/wake',
];
$peer = $storage->registerInterface('peer node', 1000000, 500, $peerMetadata);
$peerAgain = $storage->registerInterface('peer node', 1000000, 500, $peerMetadata);
check('a PHP peer re-registering keeps its row', ($peerAgain['interface_id'] ?? null) === ($peer['interface_id'] ?? '-'));
$peerRow = $pdo->query("SELECT peer_url, peer_interface_id, peer_session_token, metadata_json FROM interfaces WHERE interface_id = " . $pdo->quote($peer['interface_id']))->fetch(\PDO::FETCH_ASSOC);
check('its row stores no wake_url', !\str_contains((string) ($peerRow['metadata_json'] ?? ''), 'wake_url'), (string) ($peerRow['metadata_json'] ?? ''));
check('and keeps peer_url and the peer credentials the live peering uses',
    ($peerRow['peer_url'] ?? null) === $peerUrl
        && ($peerRow['peer_interface_id'] ?? null) === $peerMetadata['peer_interface_id']
        && ($peerRow['peer_session_token'] ?? null) === $peerMetadata['peer_session_token']);
check('[REG-WAKE-URL-IGNORED] is logged for each of its registrations too', $ignoredLines() === 4, (string) $ignoredLines());

echo "(b) packets queue for that row: no wake event, no process, no request to its URL\n";
for ($i = 0; $i < 3; $i++) {
    $storage->ingestInboundBatchInline($browser['interface_id'], 'batch-' . $i, [pathRequestBase64()]);
}
$queuedForRegistrant = rowCount($pdo, 'outbound_packets', 'interface_id = :i AND acked_at IS NULL', [':i' => $registrant['interface_id']]);
$queuedForPeer = rowCount($pdo, 'outbound_packets', 'interface_id = :i AND acked_at IS NULL', [':i' => $peer['interface_id']]);
check('the browser\'s path requests queued for the registrant (the precondition)', $queuedForRegistrant === 3, (string) $queuedForRegistrant);
check('and for the PHP peer', $queuedForPeer === 3, (string) $queuedForPeer);
$wakeRows = tableExists($pdo, 'wake_events') ? rowCount($pdo, 'wake_events') : 0;
check('no wake_events row exists', $wakeRows === 0, $wakeRows . ' rows');

$api = new HttpApi($config, $storage, $work);
(new \ReflectionMethod($api, 'runInterfaceRequestEpilogue'))->invoke($api);
check('the request epilogue starts no process', Spawned::$calls === [], \implode(' | ', Spawned::$calls));
$toPeer = accepted($peerSock);
check('the epilogue wakes the PHP peer at its own peer_url (the live wake)',
    \count($toPeer) === 1 && \str_starts_with($toPeer[0], 'POST /v1/wake ') && \str_contains($toPeer[0], '"waker_url":"http:\/\/127.0.0.1:9\/this-node"'),
    \json_encode($toPeer));
$toTrap = accepted($trap);
check('nothing connects to the registrant\'s wake_url', $toTrap === [], \json_encode($toTrap));

echo "(c) the CLI contacts nobody, and wake-event is not a mode\n";
$cli = static function (array $args) use ($work): array {
    $proc = \proc_open(
        \array_merge([\PHP_BINARY, $work . '/src/index.php'], $args),
        [0 => ['file', '/dev/null', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']],
        $pipes
    );
    $out = (string) \stream_get_contents($pipes[1]);
    $err = (string) \stream_get_contents($pipes[2]);
    \fclose($pipes[1]);
    \fclose($pipes[2]);
    return [\proc_close($proc), $out, $err];
};
// The CLI process has exited when these return, so any connection it made is
// already waiting in the trap's backlog.
[$code, $out] = $cli(['once']);
$once = \json_decode($out, true);
check('`php index.php once` succeeds', $code === 0 && \is_array($once), \substr($out, 0, 300));
check('and reports no wake dispatch', \is_array($once) && !\array_key_exists('wake', $once), (string) \json_encode($once['wake'] ?? null));
$toTrap = accepted($trap);
check('and nothing connects to the registrant\'s wake_url', $toTrap === [], \json_encode($toTrap));
[$code, $out, $err] = $cli(['wake-event', '1']);
check('`php index.php wake-event 1` is refused as an unsupported mode',
    $code === 1 && \str_contains($err, 'Unsupported index mode: wake-event'), "exit $code: " . \trim($out . ' ' . $err));
$toTrap = accepted($trap);
check('and nothing connects to the registrant\'s wake_url', $toTrap === [], \json_encode($toTrap));

echo "(d) the tables: not created on a fresh database, never dropped from a live one\n";
check('a fresh database has no wake_events table', !tableExists($pdo, 'wake_events'));
check('a fresh database has no post_interface_peers table', !tableExists($pdo, 'post_interface_peers'));

// A database as the live nodes have it: both tables, with rows, and the
// fingerprint of the schema code that created them.
$livePath = $work . '/live.sqlite';
$liveConfig = $config;
$liveConfig['storage']['sqlite_path'] = $livePath;
(new Storage($liveConfig))->migrateIfNeeded();
$live = new \PDO('sqlite:' . $livePath);
$live->setAttribute(\PDO::ATTR_ERRMODE, \PDO::ERRMODE_EXCEPTION);
$live->exec('CREATE TABLE IF NOT EXISTS wake_events (
    wake_event_id INTEGER PRIMARY KEY AUTOINCREMENT, interface_id VARCHAR(64) NOT NULL DEFAULT \'\',
    wake_profile VARCHAR(64) DEFAULT NULL, wake_target VARCHAR(512) DEFAULT NULL, wake_data_json TEXT,
    queue_reason VARCHAR(64) DEFAULT NULL, queued_packet_count INT NOT NULL DEFAULT 0,
    created_at INT NOT NULL DEFAULT 0, dispatched_at INT DEFAULT NULL, failed_at INT DEFAULT NULL,
    dispatch_result_json TEXT, failure_message TEXT, claimed_at INT DEFAULT NULL, claimed_by_pid INT DEFAULT NULL)');
$live->exec('CREATE INDEX IF NOT EXISTS idx_wake_events_created ON wake_events (created_at)');
$live->exec('CREATE TABLE IF NOT EXISTS post_interface_peers (
    peer_id INTEGER PRIMARY KEY AUTOINCREMENT, name VARCHAR(255) NOT NULL DEFAULT \'\',
    local_interface_id VARCHAR(64) NOT NULL, remote_node_url VARCHAR(512) DEFAULT NULL,
    local_wake_url VARCHAR(512) DEFAULT NULL, status VARCHAR(32) NOT NULL DEFAULT \'offline\')');
$live->exec("INSERT INTO wake_events (interface_id, wake_profile, wake_target, wake_data_json, created_at)
             VALUES ('old-row', '__http_wake__', 'https://stale.example', '{}', 1)");
$live->exec("INSERT INTO post_interface_peers (name, local_interface_id) VALUES ('stale', 'old-local')");
$live->exec("UPDATE schema_meta SET fingerprint = 'schema-before-2026-10-04' WHERE meta_key = 'migration'");
$migration = (new Storage($liveConfig))->migrateIfNeeded();
check('the changed schema code migrates the live-shaped database once more', !isset($migration['skipped']), (string) \json_encode($migration));
check('with no error', ($migration['errors'] ?? null) === [], (string) \json_encode($migration['errors'] ?? null));
check('and records its fingerprint', $live->query("SELECT fingerprint FROM schema_meta WHERE meta_key = 'migration'")->fetchColumn() !== 'schema-before-2026-10-04');
check('wake_events is still there, with its row', tableExists($live, 'wake_events') && rowCount($live, 'wake_events') === 1);
check('post_interface_peers is still there, with its row', tableExists($live, 'post_interface_peers') && rowCount($live, 'post_interface_peers') === 1);
$liveStorage = new Storage($liveConfig);
$maintenance = $liveStorage->runMaintenance(300, 86400);
check('maintenance runs on it', \is_array($maintenance));
check('and leaves the old wake_events row alone (nothing touches the table)', tableExists($live, 'wake_events') && rowCount($live, 'wake_events') === 1);
check('maintenance runs on the fresh database too', \is_array($storage->runMaintenance(300, 86400)));
check('and none of it started a process', Spawned::$calls === [], \implode(' | ', Spawned::$calls));

echo "(e) /health and /debug report no wake events\n";
$queues = $storage->healthSummary();
$wakeKeys = \array_values(\array_filter(\array_keys($queues), static fn (string $k): bool => \str_starts_with($k, 'wake_events')));
check('/health queues has no wake_events_* key', $wakeKeys === [], \implode(',', $wakeKeys));
check('/health queues still has its consumers\' keys', isset($queues['interfaces'], $queues['interfaces_online'], $queues['storage_bytes']));
$debug = $storage->debugReport(5);
check('/debug has no recent_wake_events', !\array_key_exists('recent_wake_events', $debug), \implode(',', \array_keys($debug)));

\fclose($trap);
\fclose($peerSock);
removeTree($work);

echo "\n$pass passed, $fail failed\n";
exit($fail === 0 ? 0 : 1);
