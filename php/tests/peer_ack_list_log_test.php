<?php
/**
 * An ack list that does not decode is logged, and the exchange goes on.
 *
 * WHAT THIS PINS
 * ==============
 * RequestPhpWakeTrait keeps the delivery batch ids this node owes a PHP peer
 * in interfaces.pending_ack_batch_ids_json. When that column does not decode,
 * drainPeerAckBatchIds() and appendPeerAckBatchId() each write a [peer] line
 * to PHP's error log and start the list afresh. On b6c7809 both lines were
 * $this->log(...); the trait runs as Storage, which has no log(), so the line
 * was never written and the request died with "Call to undefined method
 * ReticulumPhp\Storage::log()". static_check_methods.php now finds such a
 * call, but nothing pinned the lines themselves: deleting them shipped green.
 *
 *   (1) A wake's exchange over a list that does not decode still goes to the
 *       stored URL, carrying no acks; the column is reset to []; one line
 *       names the peer row and the decode error.
 *   (2) A delivery batch acked over a list that does not decode: one line,
 *       and the list holds only the new batch id. In a request this needs a
 *       write between the drain (which has just reset the column) and the
 *       ack, which nothing in php/src makes, so it is called directly.
 *   (3) Over a list that decodes, neither writes a line.
 *
 * Not here: the third such line in this trait, "[peer] exchangeWithPhpPeer:
 * json_encode failed", cannot be written. Its json_encode() is given
 * JSON_PARTIAL_OUTPUT_ON_ERROR, which takes precedence over
 * JSON_THROW_ON_ERROR, so it never throws and the catch never runs.
 *
 * Every way out of the process is replaced, as in
 * wake_exchanges_only_with_stored_peer_url_test.php: the trait calls
 * curl_init, file_get_contents and stream_socket_client unqualified, so the
 * ReticulumPhp\ functions below answer first and send nothing.
 *
 * On b6c7809's trait (1) and (2) fail with that Error:
 *
 *   git show b6c7809:php/src/lib/request_php_wake_trait.php > /tmp/old_wake.php
 *   WAKE_TRAIT_PATH=/tmp/old_wake.php php php/tests/peer_ack_list_log_test.php
 *
 * Run: php php/tests/peer_ack_list_log_test.php
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
require_once $root . '/src/lib/request_interface_registry_trait.php';

// ── Every way out of the process, recorded and not sent ─────────────────

final class Outbound
{
    /** @var list<array{url: string, body: string}> */
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
        $handle->body = (string) $value;
    }

    return true;
}

function curl_exec(\stdClass $handle): string
{
    Outbound::$requests[] = ['url' => $handle->url, 'body' => $handle->body];

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
        Outbound::$requests[] = ['url' => $filename, 'body' => '(stream)'];

        return false;
    }

    return \file_get_contents($filename, $use_include_path, $context, $offset, $length);
}

/** @return resource|false */
function stream_socket_client(string $address, &$errorCode = null, &$errorMessage = null, ?float $timeout = null, int $flags = 0, mixed $context = null): mixed
{
    Outbound::$requests[] = ['url' => $address, 'body' => '(socket)'];
    $errorCode = 0;
    $errorMessage = 'recorded by the test, not sent';

    return false;
}

/** @return resource|false */
function fsockopen(string $hostname, int $port = -1, &$errorCode = null, &$errorMessage = null, ?float $timeout = null): mixed
{
    Outbound::$requests[] = ['url' => $hostname . ':' . $port, 'body' => '(fsockopen)'];

    return false;
}

// ── The node under test ─────────────────────────────────────────────────

const PEER_URL = 'https://peer-b.invalid/reticulum';
const PEER_EXCHANGE = PEER_URL . '/v1/interfaces/exchange';
const PEER_ROW_ID = 'a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1';
const PEER_INTERFACE_ID = 'c0ffeec0ffeec0ffeec0ffeec0ffee00';
const PEER_SESSION_TOKEN = '5ec4e75ec4e75ec4e75ec4e75ec4e75ec4e75ec4e75ec4e75ec4e75ec4e7beef';
/** A column value that does not decode: cut off mid-string. */
const UNREADABLE = '["ack-owed-1", "ack-ow';

/** The real traits, over SQLite in memory, with the peer row in place. */
final class AckHarness
{
    use RequestPhpWakeTrait;
    use RequestInterfaceRegistryTrait;
    use RequestJsonCodecTrait;

    private \PDO $db;
    private string $backend = 'sqlite';
    private array $config = ['http' => ['max_batch_packets' => 64]];

    public function __construct(string $pendingAcks)
    {
        $this->db = new \PDO('sqlite::memory:');
        $this->db->setAttribute(\PDO::ATTR_ERRMODE, \PDO::ERRMODE_EXCEPTION);
        $this->db->exec(
            'CREATE TABLE interfaces (
                interface_id TEXT PRIMARY KEY, name TEXT, session_token TEXT,
                bitrate INTEGER, mtu INTEGER, status TEXT, metadata_json TEXT,
                created_at INTEGER, last_seen_at INTEGER, updated_at INTEGER,
                peer_url TEXT, peer_interface_id TEXT, peer_session_token TEXT,
                last_wake_sent_at INTEGER, pending_ack_batch_ids_json TEXT
            )'
        );
        $this->db->prepare(
            "INSERT INTO interfaces (interface_id, name, session_token, bitrate, mtu, status, metadata_json,
                                     created_at, last_seen_at, peer_url, peer_interface_id, peer_session_token,
                                     pending_ack_batch_ids_json)
             VALUES (:id, 'peer', 'our-own-token-for-the-peer', 1000000, 500, 'online', '{}', 1, 1,
                     :peer_url, :peer_interface_id, :peer_session_token, :acks)"
        )->execute([
            ':id' => PEER_ROW_ID,
            ':peer_url' => PEER_URL,
            ':peer_interface_id' => PEER_INTERFACE_ID,
            ':peer_session_token' => PEER_SESSION_TOKEN,
            ':acks' => $pendingAcks,
        ]);
    }

    public function ingestInboundBatchInline(string $interfaceId, string $batchId, array $packets): array
    {
        return ['processing' => []];
    }

    /** The ack an exchange makes for a delivery batch the peer sent. */
    public function ackDeliveryBatch(string $batchId): void
    {
        $this->appendPeerAckBatchId(PEER_ROW_ID, $batchId);
    }

    public function pendingAcks(): string
    {
        return (string) $this->db->query('SELECT pending_ack_batch_ids_json FROM interfaces')->fetchColumn();
    }
}

// ── Checks ──────────────────────────────────────────────────────────────

$logFile = tempnam(sys_get_temp_dir(), 'peer-ack-log-');
ini_set('error_log', $logFile);
ini_set('log_errors', '1');
register_shutdown_function(static function () use ($logFile): void {
    @unlink($logFile);
});

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

/**
 * Run $step and return what it returned (or the Throwable it threw) and the
 * lines it wrote to PHP's error log.
 *
 * @return array{result: mixed, error: ?\Throwable, log: list<string>}
 */
function run(callable $step): array
{
    global $logFile;
    clearstatcache(true, $logFile);
    $offset = (int) filesize($logFile);
    Outbound::$requests = [];
    $result = null;
    $error = null;
    try {
        $result = $step();
    } catch (\Throwable $e) {
        $error = $e;
    }
    clearstatcache(true, $logFile);
    $log = (string) \file_get_contents($logFile, false, null, $offset);

    return ['result' => $result, 'error' => $error, 'log' => array_values(array_filter(explode("\n", $log), 'strlen'))];
}

/** The lines of $log that contain $needle. */
function linesWith(array $log, string $needle): array
{
    return array_values(array_filter($log, static fn (string $line): bool => str_contains($line, $needle)));
}

function thrown(?\Throwable $error): string
{
    return $error === null ? '' : get_class($error) . ': ' . $error->getMessage();
}

// The decode error PHP gives for UNREADABLE, which each line must carry.
try {
    json_decode(UNREADABLE, true, flags: \JSON_THROW_ON_ERROR);
    $why = '(it decoded)';
} catch (\JsonException $e) {
    $why = $e->getMessage();
}

echo "(1) a wake's exchange over an ack list that does not decode\n";
$node = new AckHarness(UNREADABLE);
$r = run(static fn (): array => $node->exchangeWithPhpPeer(PEER_URL));
$only = count(Outbound::$requests) === 1 ? Outbound::$requests[0] : null;
$sent = $only !== null ? json_decode($only['body'], true) : null;
check('the exchange completes: status ok, nothing thrown',
    $r['error'] === null && ($r['result']['status'] ?? null) === 'ok',
    thrown($r['error']) . ' ' . json_encode($r['result']));
check('it goes once, to the stored URL, with the peer\'s credentials and no acks',
    $only !== null && $only['url'] === PEER_EXCHANGE && is_array($sent)
    && ($sent['session_token'] ?? null) === PEER_SESSION_TOKEN && ($sent['ack_batch_ids'] ?? null) === [],
    json_encode(Outbound::$requests, JSON_UNESCAPED_SLASHES));
check('the list is reset to []', $node->pendingAcks() === '[]', $node->pendingAcks());
$expected = '[peer] drainPeerAckBatchIds: decodeJson failed for ' . PEER_ROW_ID . ': ' . $why;
check("one line: \"{$expected}\"",
    count(linesWith($r['log'], $expected)) === 1 && count(linesWith($r['log'], '[peer]')) === 1,
    'error log: ' . json_encode($r['log'], JSON_UNESCAPED_SLASHES));

echo "(2) a delivery batch acked over an ack list that does not decode\n";
$node = new AckHarness(UNREADABLE);
$r = run(static fn () => $node->ackDeliveryBatch('batch-new'));
check('nothing thrown', $r['error'] === null, thrown($r['error']));
check('the list holds only the new batch id', $node->pendingAcks() === '["batch-new"]', $node->pendingAcks());
$expected = '[peer] appendPeerAckBatchId: decodeJson failed for ' . PEER_ROW_ID . ': ' . $why;
check("one line: \"{$expected}\"",
    count(linesWith($r['log'], $expected)) === 1 && count(linesWith($r['log'], '[peer]')) === 1,
    'error log: ' . json_encode($r['log'], JSON_UNESCAPED_SLASHES));
check('nothing left the process', Outbound::$requests === [], json_encode(Outbound::$requests, JSON_UNESCAPED_SLASHES));

echo "(3) over an ack list that decodes, no line\n";
$node = new AckHarness('["ack-owed-1"]');
$r = run(static fn (): array => $node->exchangeWithPhpPeer(PEER_URL));
$sent = count(Outbound::$requests) === 1 ? json_decode(Outbound::$requests[0]['body'], true) : null;
check('the exchange carries the owed ack, and no [peer] line is written',
    $r['error'] === null && ($r['result']['status'] ?? null) === 'ok' && is_array($sent)
    && ($sent['ack_batch_ids'] ?? null) === ['ack-owed-1'] && linesWith($r['log'], '[peer]') === [],
    thrown($r['error']) . ' ' . json_encode($r['log'], JSON_UNESCAPED_SLASHES));
$r = run(static fn () => $node->ackDeliveryBatch('batch-next'));
check('the next ack is appended, and no [peer] line is written',
    $r['error'] === null && $node->pendingAcks() === '["batch-next"]' && linesWith($r['log'], '[peer]') === [],
    thrown($r['error']) . ' ' . $node->pendingAcks() . ' ' . json_encode($r['log'], JSON_UNESCAPED_SLASHES));

echo "\n$pass passed, $fail failed\n";
exit($fail === 0 ? 0 : 1);
