<?php
/**
 * A wake makes this node call its PHP peer's exchange, and the peer's
 * credentials go only to the URL stored on that peer's row.
 *
 * THE DEFECT (live on 3281ad5)
 * ============================
 * POST /v1/wake {"waker_url": W} runs exchangeWithPhpPeer(W). That found the
 * peer row with `WHERE peer_url = W`, then POSTed the row's peer_interface_id
 * and peer_session_token to W . '/v1/interfaces/exchange': the CALLER's string,
 * not the row's. On MySQL/MariaDB the interfaces table is utf8mb4_unicode_ci,
 * which ignores case, accents, compatibility forms and trailing spaces, so
 * W = https://rétichat.com/reticulum (an IDN look-alike someone can register,
 * with its own certificate) finds the row for https://retichat.com/reticulum,
 * and the credentials for retichat.com go to the look-alike. With them the
 * holder can exchange as this node: drain and ack the inter-relay queue and
 * inject transit packets. SQLite compares bytes, so no test here saw it.
 *
 * THE FIX
 * =======
 * The lookup may still match a look-alike; what it returns is not trusted.
 * The caller's URL must equal the row's own peer_url byte for byte, after the
 * same normalisation on both sides (trailing '/' and one '/v1/wake' suffix
 * removed), compared with hash_equals in PHP. If it does not, nothing is sent,
 * nothing is drained, and [WAKE-REFUSED] is logged (not [WAKE-DROP], which
 * means a wake of ours that did not leave). If it does, the exchange goes to
 * the row's normalised peer_url, never to the request's string.
 *
 * HOW THIS TEST SEES IT
 * =====================
 * - The real traits run against SQLite in memory, with peer_url declared under
 *   a collation that folds the way utf8mb4_unicode_ci does (ICU root collator
 *   at primary strength, trailing spaces ignored as in PAD SPACE).
 * - Every way out of the process is replaced: the traits live in namespace
 *   ReticulumPhp and call curl_init, file_get_contents and
 *   stream_socket_client unqualified, so the ReticulumPhp\ functions below
 *   answer first. Each records the URL and body and sends nothing.
 * - Each waker_url runs twice: once through the real lookup over the folding
 *   column, and once through a lookup that returns the peer row whatever the
 *   URL (the lookup as no defence at all). Either way the credentials may only
 *   go to the stored URL.
 *
 * - (5) runs the legitimate wakes end to end, two nodes under `php -S`, so the
 *   real /v1/wake handler and real curl still deliver them.
 *
 * On 3281ad5's trait the look-alike cases FAIL (credentials sent to the
 * look-alike), and so do the legitimate '/v1/wake' and trailing-'/' cases
 * (the exchange went to '…/v1/wake/v1/interfaces/exchange'):
 *
 *   git show 3281ad5:php/src/lib/request_php_wake_trait.php > /tmp/old_wake.php
 *   mkdir /tmp/old_src && git archive 3281ad5 php/src | tar -x -C /tmp/old_src
 *   WAKE_TRAIT_PATH=/tmp/old_wake.php WAKE_SRC_DIR=/tmp/old_src/php/src \
 *     php php/tests/wake_exchanges_only_with_stored_peer_url_test.php
 *
 * Run: php php/tests/wake_exchanges_only_with_stored_peer_url_test.php
 */
declare(strict_types=1);

namespace ReticulumPhp;

$root = dirname(__DIR__);
require_once $root . '/src/lib/database.php';
require_once $root . '/src/lib/request_json_codec_trait.php';
$wakeTraitPath = getenv('WAKE_TRAIT_PATH');
require_once ($wakeTraitPath !== false && $wakeTraitPath !== '')
    ? $wakeTraitPath
    : $root . '/src/lib/request_php_wake_trait.php';
$regTraitPath = getenv('REG_TRAIT_PATH');
require_once ($regTraitPath !== false && $regTraitPath !== '')
    ? $regTraitPath
    : $root . '/src/lib/request_interface_registry_trait.php';

// ── Every way out of the process, recorded and not sent ─────────────────

final class Outbound
{
    /** @var list<array{via: string, url: string, body: string}> */
    public static array $requests = [];

    /** What the "peer" answers to an exchange: nothing to deliver. */
    public const RESPONSE = '{"status":"ok","delivery_packets":[],"delivery_batch_id":null}';
}

function curl_init(?string $url = null): \stdClass
{
    $handle = new \stdClass();
    $handle->url = (string) $url;
    $handle->body = '';

    return $handle;
}

function curl_setopt(\stdClass $handle, int $option, mixed $value): bool
{
    if ($option === \CURLOPT_URL) {
        $handle->url = (string) $value;
    }
    if ($option === \CURLOPT_POSTFIELDS) {
        $handle->body = is_array($value) ? http_build_query($value) : (string) $value;
    }

    return true;
}

function curl_exec(\stdClass $handle): string
{
    Outbound::$requests[] = ['via' => 'curl', 'url' => $handle->url, 'body' => $handle->body];

    return Outbound::RESPONSE;
}

function curl_getinfo(\stdClass $handle, ?int $option = null): mixed
{
    return 200;
}

function curl_error(\stdClass $handle): string
{
    return '';
}

function curl_close(\stdClass $handle): void
{
}

function file_get_contents(string $filename, bool $use_include_path = false, mixed $context = null, int $offset = 0, ?int $length = null): string|false
{
    if (preg_match('#^[a-z][a-z0-9+.-]*://#i', $filename) === 1) {
        $options = is_resource($context) ? \stream_context_get_options($context) : [];
        Outbound::$requests[] = ['via' => 'stream', 'url' => $filename, 'body' => (string) ($options['http']['content'] ?? '')];

        return false;
    }

    return \file_get_contents($filename, $use_include_path, $context, $offset, $length);
}

/** @return resource|false */
function stream_socket_client(string $address, &$errorCode = null, &$errorMessage = null, ?float $timeout = null, int $flags = 0, mixed $context = null): mixed
{
    Outbound::$requests[] = ['via' => 'socket', 'url' => $address, 'body' => ''];
    $errorCode = 0;
    $errorMessage = 'recorded by the test, not sent';

    return false;
}

/** @return resource|false */
function fsockopen(string $hostname, int $port = -1, &$errorCode = null, &$errorMessage = null, ?float $timeout = null): mixed
{
    Outbound::$requests[] = ['via' => 'fsockopen', 'url' => $hostname . ':' . $port, 'body' => ''];

    return false;
}

// ── utf8mb4_unicode_ci, as far as these URLs need it ────────────────────

/**
 * MySQL/MariaDB utf8mb4_unicode_ci compares by UCA primary weight (case,
 * accents and compatibility forms such as fullwidth letters fold away) and is
 * PAD SPACE (trailing spaces do not count). The ICU root collator at primary
 * strength gives the same answer for every string below. Without intl, a fold
 * of exactly the characters this test uses stands in.
 */
function unicodeCiCompare(string $a, string $b): int
{
    static $collator = null;
    $a = rtrim($a, ' ');
    $b = rtrim($b, ' ');
    if (class_exists(\Collator::class)) {
        if ($collator === null) {
            $collator = new \Collator('root');
            $collator->setStrength(\Collator::PRIMARY);
        }
        $result = $collator->compare($a, $b);
        if (is_int($result)) {
            return $result <=> 0;
        }
    }
    $fold = static fn (string $s): string => strtolower(strtr($s, ['é' => 'e', 'É' => 'e', 'ｒ' => 'r']));

    return strcmp($fold($a), $fold($b)) <=> 0;
}

function foldingSqlite(): \PDO
{
    if (class_exists(\Pdo\Sqlite::class)) {
        $db = new \Pdo\Sqlite('sqlite::memory:');
        $db->createCollation('UNICODE_CI', __NAMESPACE__ . '\unicodeCiCompare');
    } else {
        $db = new \PDO('sqlite::memory:');
        $db->sqliteCreateCollation('UNICODE_CI', __NAMESPACE__ . '\unicodeCiCompare');
    }
    $db->setAttribute(\PDO::ATTR_ERRMODE, \PDO::ERRMODE_EXCEPTION);

    return $db;
}

// ── The node under test ─────────────────────────────────────────────────

const PEER_ROW_ID = 'a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1';
const PEER_INTERFACE_ID = 'c0ffeec0ffeec0ffeec0ffeec0ffee00';
const PEER_SESSION_TOKEN = '5ec4e75ec4e75ec4e75ec4e75ec4e75ec4e75ec4e75ec4e75ec4e75ec4e7beef';
const OWED_ACKS = ['ack-owed-1', 'ack-owed-2'];

final class WakeHarness
{
    use RequestPhpWakeTrait;
    use RequestInterfaceRegistryTrait {
        RequestInterfaceRegistryTrait::phpPeerInterfaceByPeerUrl as private realPhpPeerInterfaceByPeerUrl;
    }
    use RequestJsonCodecTrait;

    private \PDO $db;
    private string $backend = 'sqlite';
    private array $config = ['http' => ['max_batch_packets' => 64]];

    /** @var list<string> */
    public array $ingested = [];

    public function __construct(public readonly string $storedPeerUrl, private readonly bool $lookupMatchesAnything)
    {
        $this->db = foldingSqlite();
        $this->db->exec(
            'CREATE TABLE interfaces (
                interface_id TEXT PRIMARY KEY, name TEXT, session_token TEXT,
                bitrate INTEGER, mtu INTEGER, status TEXT, metadata_json TEXT,
                created_at INTEGER, last_seen_at INTEGER, updated_at INTEGER,
                peer_url TEXT COLLATE UNICODE_CI, peer_interface_id TEXT, peer_session_token TEXT,
                last_wake_sent_at INTEGER, pending_ack_batch_ids_json TEXT
            )'
        );
        $insert = $this->db->prepare(
            "INSERT INTO interfaces (interface_id, name, session_token, bitrate, mtu, status, metadata_json,
                                     created_at, last_seen_at, peer_url, peer_interface_id, peer_session_token,
                                     pending_ack_batch_ids_json)
             VALUES (:id, 'peer', 'our-own-token-for-the-peer', 1000000, 500, 'offline', '{}', 1, 1,
                     :peer_url, :peer_interface_id, :peer_session_token, :acks)"
        );
        $insert->execute([
            ':id' => PEER_ROW_ID,
            ':peer_url' => $storedPeerUrl,
            ':peer_interface_id' => PEER_INTERFACE_ID,
            ':peer_session_token' => PEER_SESSION_TOKEN,
            ':acks' => json_encode(OWED_ACKS),
        ]);
    }

    /**
     * The real lookup over the folding column, or (lookupMatchesAnything) the
     * peer row for any URL at all: the lookup as no defence.
     */
    public function phpPeerInterfaceByPeerUrl(string $peerUrl): ?array
    {
        if (!$this->lookupMatchesAnything) {
            return $this->realPhpPeerInterfaceByPeerUrl($peerUrl);
        }
        $row = $this->db->query(
            'SELECT interface_id, peer_url, peer_interface_id, peer_session_token, status, last_seen_at FROM interfaces'
        )->fetch(\PDO::FETCH_ASSOC);

        return is_array($row) ? $row : null;
    }

    public function ingestInboundBatchInline(string $interfaceId, string $batchId, array $packets): array
    {
        $this->ingested[] = $batchId;

        return ['processing' => []];
    }

    /** Does the folding column match this URL? (proves the simulation folds) */
    public function columnMatches(string $url): bool
    {
        $st = $this->db->prepare('SELECT 1 FROM interfaces WHERE peer_url = :u');
        $st->execute([':u' => $url]);

        return $st->fetch() !== false;
    }

    /** Does this node's lookup (whichever kind) hand back the peer row for this URL? */
    public function lookupFinds(string $url): bool
    {
        return $this->phpPeerInterfaceByPeerUrl($url) !== null;
    }

    /** @return list<string> */
    public function owedAcks(): array
    {
        $json = (string) $this->db->query('SELECT pending_ack_batch_ids_json FROM interfaces')->fetchColumn();
        $decoded = json_decode($json, true);

        return is_array($decoded) ? $decoded : [];
    }
}

// ── Checks ──────────────────────────────────────────────────────────────

$logFile = tempnam(sys_get_temp_dir(), 'wake-refused-');
ini_set('error_log', $logFile);
ini_set('log_errors', '1');

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

/** @return array{result: array, requests: list<array{via: string, url: string, body: string}>, refused: int, dropped: int, acks: list<string>} */
function wake(WakeHarness $node, string $wakerUrl): array
{
    global $logFile;
    clearstatcache(true, $logFile);
    $offset = (int) filesize($logFile);
    Outbound::$requests = [];
    $result = $node->exchangeWithPhpPeer($wakerUrl);
    clearstatcache(true, $logFile);
    $log = (string) \file_get_contents($logFile, false, null, $offset);

    return [
        'result' => $result,
        'requests' => Outbound::$requests,
        'refused' => substr_count($log, '[WAKE-REFUSED]'),
        'dropped' => substr_count($log, '[WAKE-DROP]'),
        'acks' => $node->owedAcks(),
    ];
}

function describe(array $requests): string
{
    if ($requests === []) {
        return 'no outbound request';
    }

    return implode('; ', array_map(
        static fn (array $r): string => $r['via'] . ' ' . json_encode($r['url'], JSON_UNESCAPED_SLASHES)
            . (str_contains($r['body'], PEER_SESSION_TOKEN) ? ' WITH the peer session token' : ''),
        $requests
    ));
}

const RETICHAT = 'https://retichat.com/reticulum';
const RETICHAT_EXCHANGE = RETICHAT . '/v1/interfaces/exchange';

echo "\n(0) the simulated utf8mb4_unicode_ci folds the way MySQL does\n";
$probe = new WakeHarness(RETICHAT, false);
foreach ([
    'an accented host' => 'https://rétichat.com/reticulum',
    'an upper-case host' => 'https://RETICHAT.COM/reticulum',
    'an upper-case path' => 'https://retichat.com/Reticulum',
    'a fullwidth letter' => 'https://ｒetichat.com/reticulum',
    'a trailing space' => RETICHAT . ' ',
] as $label => $url) {
    check("the peer_url column matches $label", $probe->columnMatches($url));
}
check('the peer_url column does not match another port', !$probe->columnMatches('https://retichat.com:443/reticulum'));

/**
 * Waker URLs that are the stored peer (same bytes after the shared
 * normalisation) and look-alikes that only a folding lookup, or none, confuses.
 */
$sameNode = [
    'the stored URL exactly' => RETICHAT,
    'the stored URL + trailing /' => RETICHAT . '/',
    'the stored URL + /v1/wake' => RETICHAT . '/v1/wake',
    'the stored URL + /v1/wake/' => RETICHAT . '/v1/wake/',
];
$lookAlikes = [
    'accented host (IDN look-alike)' => 'https://rétichat.com/reticulum',
    'accented host + /v1/wake' => 'https://rétichat.com/reticulum/v1/wake',
    'upper-case host' => 'https://RETICHAT.COM/reticulum',
    'upper-case path' => 'https://retichat.com/Reticulum',
    'fullwidth letter' => 'https://ｒetichat.com/reticulum',
    'trailing space' => RETICHAT . ' ',
    'explicit default port' => 'https://retichat.com:443/reticulum',
    'another port' => 'https://retichat.com:8443/reticulum',
    'IDN punycode of the look-alike' => 'https://xn--rtichat-bya.com/reticulum',
    'http instead of https' => 'http://retichat.com/reticulum',
];

foreach ([false => 'the real lookup over the folding column', true => 'a lookup that returns the peer row for ANY URL'] as $anything => $how) {
    $anything = (bool) $anything;
    echo "\n(" . ($anything ? '2' : '1') . ") $how\n";

    foreach ($sameNode as $label => $wakerUrl) {
        $node = new WakeHarness(RETICHAT, $anything);
        $w = wake($node, $wakerUrl);
        $only = count($w['requests']) === 1 ? $w['requests'][0] : null;
        check(
            "[$label] exchanges once, with the stored URL",
            $only !== null && $only['url'] === RETICHAT_EXCHANGE,
            describe($w['requests'])
        );
        check(
            "[$label] presents the peer's credentials and the owed acks",
            $only !== null
                && str_contains($only['body'], PEER_INTERFACE_ID)
                && str_contains($only['body'], PEER_SESSION_TOKEN)
                && str_contains($only['body'], OWED_ACKS[0])
        );
        check("[$label] status ok, nothing refused", ($w['result']['status'] ?? null) === 'ok' && $w['refused'] === 0, json_encode($w['result']));
    }

    foreach ($lookAlikes as $label => $wakerUrl) {
        $node = new WakeHarness(RETICHAT, $anything);
        $w = wake($node, $wakerUrl);
        check("[$label] sends nothing anywhere", $w['requests'] === [], describe($w['requests']));
        check("[$label] leaves the acks owed to the real peer", $w['acks'] === OWED_ACKS, json_encode($w['acks']));
        if ($node->lookupFinds($wakerUrl)) {
            // The lookup handed back the peer row: this is the refusal.
            check(
                "[$label] is refused and logged [WAKE-REFUSED] once, not [WAKE-DROP]",
                ($w['result']['status'] ?? null) === 'refused' && $w['refused'] === 1 && $w['dropped'] === 0,
                json_encode($w['result'], JSON_UNESCAPED_SLASHES) . " refused-logs={$w['refused']} drop-logs={$w['dropped']}"
            );
            check(
                "[$label] the refusal does not hand the stored URL back to the caller",
                !str_contains((string) json_encode($w['result'], JSON_UNESCAPED_SLASHES), RETICHAT . '"')
            );
        } else {
            check("[$label] is an unknown peer", ($w['result']['status'] ?? null) === 'unknown_peer', json_encode($w['result']));
        }
    }
}

echo "\n(3) a row stored with a legacy /v1/wake suffix: the exchange still goes to its base URL\n";
const SELECTIV = 'https://selectivesubconscious.com/reticulum';
foreach ([false, true] as $anything) {
    $how = $anything ? 'any-URL lookup' : 'real lookup';
    $node = new WakeHarness(SELECTIV . '/v1/wake', $anything);
    $w = wake($node, SELECTIV);
    check(
        "[$how] the base URL exchanges with " . SELECTIV . '/v1/interfaces/exchange',
        count($w['requests']) === 1 && $w['requests'][0]['url'] === SELECTIV . '/v1/interfaces/exchange',
        describe($w['requests'])
    );
    $node = new WakeHarness(SELECTIV . '/v1/wake', $anything);
    $w = wake($node, 'https://sélectivesubconscious.com/reticulum/v1/wake');
    check("[$how] its accented look-alike sends nothing", $w['requests'] === [], describe($w['requests']));
}
// registerInterface stores rtrim(trim(peer_url), '/'), so a registration
// naming '/' leaves a peer row with an empty peer_url, which waker_url '/'
// then finds. There is no URL to send to; 3281ad5 sent the credentials to
// '//v1/interfaces/exchange', which curl reads as host "v1".
foreach ([false, true] as $anything) {
    $how = $anything ? 'any-URL lookup' : 'real lookup';
    $w = wake(new WakeHarness('', $anything), '/');
    check(
        "[$how] a row with an empty peer_url is never exchanged with, and the wake is refused",
        $w['requests'] === [] && ($w['result']['status'] ?? null) === 'refused',
        describe($w['requests']) . ' ' . json_encode($w['result'], JSON_UNESCAPED_SLASHES)
    );
}

echo "\n(4) wherever a request went, the peer's credentials went only to the stored URL\n";
$leaks = [];
foreach ([false, true] as $anything) {
    foreach ($sameNode + $lookAlikes as $label => $wakerUrl) {
        $w = wake(new WakeHarness(RETICHAT, $anything), $wakerUrl);
        foreach ($w['requests'] as $r) {
            $carries = str_contains($r['body'], PEER_SESSION_TOKEN) || str_contains($r['url'], PEER_SESSION_TOKEN)
                || str_contains($r['body'], PEER_INTERFACE_ID);
            if ($carries && $r['url'] !== RETICHAT_EXCHANGE) {
                $leaks[] = $label . ' -> ' . json_encode($r['url'], JSON_UNESCAPED_SLASHES);
            }
        }
    }
}
check('no request carried the credentials to any other URL', $leaks === [], implode("\n         ", $leaks));

// ── (5) The same, end to end ────────────────────────────────────────────
// Two real nodes, each a copy of php/src under `php -S` with its own SQLite;
// A has an [interfaces] block for B, as an initiator does. The real /v1/wake
// handler, the real lookup and real curl. SQLite cannot fold, so this part
// proves the legitimate wake still lands, not the look-alike refusal (that is
// (1) and (2)). This code is in namespace ReticulumPhp, where file_get_contents
// and stream_socket_client are the recording stand-ins, so it calls the global
// functions by their \ names.

echo "\n(5) end to end: two nodes under php -S, the real /v1/wake handler and real curl\n";

/** @return array{int, array} status and decoded body */
function e2eHttp(string $method, string $url, ?array $body = null): array
{
    $context = \stream_context_create(['http' => [
        'method' => $method,
        'header' => "Content-Type: application/json\r\n",
        'content' => $body === null ? '' : json_encode($body),
        'ignore_errors' => true,
        'timeout' => 5,
    ]]);
    $response = @\file_get_contents($url, false, $context);
    $headers = function_exists('http_get_last_response_headers')
        ? (http_get_last_response_headers() ?? [])
        : ($http_response_header ?? []);
    $status = 0;
    foreach ($headers as $line) {
        if (preg_match('#^HTTP/\S+ (\d{3})#', $line, $m) === 1) {
            $status = (int) $m[1];
        }
    }
    $decoded = is_string($response) ? json_decode($response, true) : null;

    return [$status, is_array($decoded) ? $decoded : []];
}

function e2eFreePort(): int
{
    $server = \stream_socket_server('tcp://127.0.0.1:0');
    $name = (string) \stream_socket_get_name($server, false);
    fclose($server);

    return (int) substr($name, strrpos($name, ':') + 1);
}

function e2eCopyTree(string $from, string $to): void
{
    mkdir($to, 0775, true);
    foreach (scandir($from) ?: [] as $entry) {
        if ($entry === '.' || $entry === '..' || str_starts_with($entry, 'config.') || $entry === 'build.json') {
            continue;
        }
        $path = $from . '/' . $entry;
        is_dir($path) ? e2eCopyTree($path, $to . '/' . $entry) : copy($path, $to . '/' . $entry);
    }
}

/** @return array{base: string, dir: string, proc: resource} */
function e2eStartNode(string $src, int $port, ?string $peerUrl): array
{
    $dir = sys_get_temp_dir() . '/reticulum-wake-stored-url-' . bin2hex(random_bytes(4));
    e2eCopyTree($src, $dir . '/src');
    $lines = [
        'host_url = "http://127.0.0.1:' . $port . '"',
        '[storage]',
        'backend = "sqlite"',
        'sqlite_path = "' . $dir . '/node.sqlite"',
        'log_path = "' . $dir . '/router.log"',
    ];
    if ($peerUrl !== null) {
        array_push($lines, '[interfaces]', '[[Peer]]', 'node_url = "' . $peerUrl . '"');
    }
    file_put_contents($dir . '/src/config.toml', implode("\n", $lines) . "\n");
    $proc = proc_open(
        [PHP_BINARY, '-S', '127.0.0.1:' . $port, '-t', $dir . '/src', $dir . '/src/index.php'],
        [0 => ['file', '/dev/null', 'r'], 1 => ['file', $dir . '/server.out', 'w'], 2 => ['file', $dir . '/server.out', 'a']],
        $pipes
    );
    $base = 'http://127.0.0.1:' . $port;
    // Readiness is the server answering; the bound only turns a server that
    // never starts into a test failure instead of a hang.
    for ($i = 0; $i < 50 && e2eHttp('GET', $base . '/health')[0] !== 200; $i++) {
        usleep(100000);
    }

    return ['base' => $base, 'dir' => $dir, 'proc' => $proc];
}

function e2eStopNode(array $node): void
{
    proc_terminate($node['proc']);
    proc_close($node['proc']);
    exec('rm -rf ' . escapeshellarg($node['dir']));
}

function e2eServerLog(array $node): string
{
    return (string) @\file_get_contents($node['dir'] . '/server.out');
}

$e2eSrc = getenv('WAKE_SRC_DIR');
$e2eSrc = ($e2eSrc !== false && $e2eSrc !== '') ? $e2eSrc : $root . '/src';
$b = e2eStartNode($e2eSrc, e2eFreePort(), null);
$a = e2eStartNode($e2eSrc, e2eFreePort(), $b['base']);

[$status, $init] = e2eHttp('GET', $a['base'] . '/v1/initialize');
check('A registers at B on /v1/initialize', $status === 200 && ($init['peers'][0]['status'] ?? null) === 'connected', (string) json_encode($init));

foreach ([
    "B's URL exactly" => $b['base'],
    "B's URL + /v1/wake" => $b['base'] . '/v1/wake',
    "B's URL + trailing /" => $b['base'] . '/',
] as $label => $wakerUrl) {
    [$status, $woke] = e2eHttp('POST', $a['base'] . '/v1/wake', ['waker_url' => $wakerUrl]);
    check(
        "A woken with [$label] exchanges with B, and B accepts the credentials",
        $status === 200 && ($woke['exchange']['status'] ?? null) === 'ok'
            && ($woke['exchange']['peer_url'] ?? null) === $b['base'],
        (string) json_encode($woke['exchange'] ?? $woke, JSON_UNESCAPED_SLASHES)
    );
}
[$status, $woke] = e2eHttp('POST', $b['base'] . '/v1/wake', ['waker_url' => $a['base']]);
check(
    "B woken with A's URL exchanges with A, and A accepts the credentials",
    $status === 200 && ($woke['exchange']['status'] ?? null) === 'ok',
    (string) json_encode($woke['exchange'] ?? $woke, JSON_UNESCAPED_SLASHES)
);

// A URL A holds no peer row for, listening: the inline exchange has finished
// by the time A answers, so a connection it made would already be queued.
$trap = \stream_socket_server('tcp://127.0.0.1:0');
$trapUrl = 'http://' . \stream_socket_get_name($trap, false);
[$status, $woke] = e2eHttp('POST', $a['base'] . '/v1/wake', ['waker_url' => $trapUrl]);
$trapped = @\stream_socket_accept($trap, 0);
check(
    'a wake naming a URL A has no row for is an unknown peer, and nothing connects to that URL',
    $trapped === false && ($woke['exchange']['status'] ?? null) === 'unknown_peer',
    (string) json_encode($woke['exchange'] ?? $woke, JSON_UNESCAPED_SLASHES)
);
fclose($trap);

check('neither node logged [WAKE-REFUSED] for the legitimate wakes',
    !str_contains(e2eServerLog($a) . e2eServerLog($b), '[WAKE-REFUSED]'));

e2eStopNode($a);
e2eStopNode($b);

@unlink($logFile);

echo "\nResults: $pass passed, $fail failed\n";
exit($fail > 0 ? 1 : 0);
