<?php
/**
 * A browser's interface row is re-bound by identity_hash only by a real
 * identity hash, and only by exact match on that row's own top-level value.
 *
 * Before this fix, registerInterface() matched the registration's identity_hash
 * against metadata_json with a bare, unescaped LIKE
 * (`metadata_json LIKE '%"identity_hash":"' . $hash . '"%'`, LIMIT 1). Two ways
 * to abuse it, both proven against the real trait on 35314f4:
 *
 *   1. A claim of '%' (or '_%', '%%') is a LIKE wildcard: it matched an
 *      ARBITRARY existing browser row with no knowledge of any hash, re-bound
 *      it (new session token), 401'd the victim's token, and overwrote its
 *      metadata.
 *   2. A nested {"x":{"identity_hash":"…"}} in some unrelated row's metadata
 *      matched the LIKE, so a registration could capture a planted row — or a
 *      holder's first registration could land on an attacker's planted nested
 *      row instead of its own.
 *
 * The fix: a raw identity_hash is an UNAUTHENTICATED claim (signed registration
 * is the separate follow-up redesign). So it is honoured for row matching ONLY
 * when it is a well-formed identity hash — exactly 32 lowercase hex characters —
 * and the lookup is an EXACT match on the row's own TOP-LEVEL metadata
 * identity_hash (a LIKE only narrows the candidates; each is json_decoded and
 * compared with hash_equals in PHP). A legitimate re-registration with the same
 * hash still re-binds in place; a different valid hash gets its own row.
 *
 * Each defence is pinned on its own, because either one alone stops the
 * wildcard attack on the victim in (1):
 *   - the validation, by (5): a malformed claim never re-binds even a row that
 *     was made with the SAME malformed claim, and by (6): every malformed claim
 *     (including 32 hex + a trailing newline) is logged [REG-BAD-IDENTITY];
 *   - the exact top-level compare, by (2): the nested-key row.
 * The SQL itself must also prepare on MySQL/MariaDB, which SQLite cannot show;
 * no_backslash_in_sql_literals_test.php guards that.
 *
 * This test runs against the real trait (SQLite in-memory). It asserts the
 * fixed behaviour, so on an export of 35314f4 (REG_TRAIT_PATH=/path/to/old.php)
 * the attack cases FAIL — that is the regression the fix removes.
 *
 * Run: php tests/interface_identity_rebind_test.php
 *      REG_TRAIT_PATH=/tmp/old_trait_35314f4.php php tests/interface_identity_rebind_test.php  # attacks FAIL (bug present)
 */
declare(strict_types=1);

namespace ReticulumPhp;

$root = dirname(__DIR__);
require_once $root . '/src/lib/database.php';
require_once $root . '/src/lib/request_json_codec_trait.php';
$traitPath = getenv('REG_TRAIT_PATH');
require_once ($traitPath !== false && $traitPath !== '')
    ? $traitPath
    : $root . '/src/lib/request_interface_registry_trait.php';

// authenticateInterface() throws ReticulumPhp\ApiError on a bad token. The real
// class lives in index.php; a stand-in keeps the test from booting the app.
if (!class_exists(ApiError::class)) {
    class ApiError extends \RuntimeException
    {
        public function __construct(public readonly int $statusCode, string $message, public readonly array $payload = [])
        {
            parent::__construct($message);
        }
    }
}

final class RebindHarness
{
    use RequestInterfaceRegistryTrait;
    use RequestJsonCodecTrait;

    public \PDO $db;
    public string $backend = 'sqlite';

    public function __construct()
    {
        $this->db = new \PDO('sqlite::memory:', options: [\PDO::ATTR_ERRMODE => \PDO::ERRMODE_EXCEPTION]);
        $this->db->exec(
            'CREATE TABLE interfaces (
                interface_id TEXT PRIMARY KEY, name TEXT, session_token TEXT,
                bitrate INTEGER, mtu INTEGER, status TEXT, metadata_json TEXT,
                created_at INTEGER, last_seen_at INTEGER, updated_at INTEGER,
                peer_url TEXT, peer_interface_id TEXT, peer_session_token TEXT,
                last_wake_sent_at INTEGER, pending_ack_batch_ids_json TEXT
            )'
        );
    }

    /** Register as the Retichat web client does, with a given identity_hash claim. */
    public function registerBrowser(mixed $identityClaim): array
    {
        return $this->registerInterface('Retichat Web', 1000000, 500, [
            'client' => 'rns-js',
            'implementation' => 'PostInterface',
            'mode' => 1,
            'identity_hash' => $identityClaim,
        ]);
    }

    /** Insert a row verbatim (to plant a nested-key row the attacker controls). */
    public function plantRaw(string $interfaceId, string $token, array $metadata): void
    {
        $st = $this->db->prepare(
            "INSERT INTO interfaces (interface_id, name, session_token, bitrate, mtu, status, metadata_json, created_at, last_seen_at)
             VALUES (?, 'planted', ?, 1000000, 500, 'online', ?, ?, ?)"
        );
        $st->execute([$interfaceId, $token, self::encodeJson($metadata), time(), time()]);
    }

    public function metaFor(string $interfaceId): array
    {
        $st = $this->db->prepare('SELECT metadata_json FROM interfaces WHERE interface_id = ?');
        $st->execute([$interfaceId]);
        $row = $st->fetch(\PDO::FETCH_ASSOC);

        return is_array($row) ? self::decodeJson((string) $row['metadata_json']) : [];
    }

    public function rowCount(): int
    {
        return (int) $this->db->query('SELECT COUNT(*) FROM interfaces')->fetchColumn();
    }

    public function authOk(string $interfaceId, string $token): bool
    {
        try {
            $this->authenticateInterface($interfaceId, $token);
            return true;
        } catch (\Throwable $e) {
            return false;
        }
    }
}

// Capture error_log so the [REG-BAD-IDENTITY] contract is asserted, not assumed.
$logFile = tempnam(sys_get_temp_dir(), 'reg-bad-identity-');
ini_set('error_log', $logFile);

/** Number of [REG-BAD-IDENTITY] lines error_log received while $fn ran. */
function badIdentityLogsDuring(callable $fn): int
{
    global $logFile;
    clearstatcache(true, $logFile);
    $offset = (int) filesize($logFile);
    $fn();
    clearstatcache(true, $logFile);

    return substr_count((string) file_get_contents($logFile, false, null, $offset), '[REG-BAD-IDENTITY]');
}

$pass = 0;
$fail = 0;
function check(string $label, bool $ok): void
{
    global $pass, $fail;
    if ($ok) {
        $pass++;
        echo "  ok   $label\n";
    } else {
        $fail++;
        echo "  FAIL $label\n";
    }
}

$h = new RebindHarness();

// A real browser row, identity hash fixed (letters present so upper-case is a
// genuinely different, non-hex string, not accidentally equal).
$victimHash = 'deadbeefcafef00d0123456789abcdef';
$victim = $h->registerBrowser($victimHash);
$victimToken = $victim['session_token'];
check('a valid 32-hex browser registers and authenticates', $h->authOk($victim['interface_id'], $victimToken));

// ── Attacks: none may re-bind the victim's row ──────────────────────────
// Each is a malformed identity_hash claim. On the fixed trait it is treated as
// no identity (a fresh row). On 35314f4 the wildcards re-bind the victim.
echo "\n(1) a malformed identity_hash claim never captures an existing row\n";
$attacks = [
    "wildcard '%'"            => '%',
    "wildcard '_%'"           => '_%',
    "wildcard '%%'"           => '%%',
    '31-character hash'       => substr($victimHash, 0, 31),
    '33-character hash'       => $victimHash . 'a',
    'upper-case of the hash'  => strtoupper($victimHash),
    'hash with a double-quote' => substr($victimHash, 0, 31) . '"',
    'hash with a backslash'   => substr($victimHash, 0, 31) . '\\',
    'non-string claim (array)' => ['identity_hash' => $victimHash],
];
foreach ($attacks as $label => $claim) {
    $before = $h->rowCount();
    $res = $h->registerBrowser($claim);
    check("[$label] does not return the victim's interface_id", $res['interface_id'] !== $victim['interface_id']);
    check("[$label] the victim's token still authenticates", $h->authOk($victim['interface_id'], $victimToken));
    check("[$label] the victim's metadata is untouched", ($h->metaFor($victim['interface_id'])['identity_hash'] ?? null) === $victimHash);
    check("[$label] a fresh row was created", $h->rowCount() === $before + 1);
}

// ── Nested-key row: a planted row whose identity_hash is only nested must ──
// never be matched, so a holder's registration lands on its own row.
echo "\n(2) a nested identity_hash never binds a row\n";
$targetHash = 'feedface00112233445566778899aabb';
$h->plantRaw('planted_nested', 'planted-token', [
    'client' => 'rns-js',
    'implementation' => 'PostInterface',
    'mode' => 1,
    'wrap' => ['identity_hash' => $targetHash],
]);
$before = $h->rowCount();
$holder = $h->registerBrowser($targetHash);
check('the holder gets its own row, not the planted nested row', $holder['interface_id'] !== 'planted_nested');
check('a fresh row was created for the holder', $h->rowCount() === $before + 1);
check("the planted row's token is not re-bound", $h->authOk('planted_nested', 'planted-token'));
check('the planted row still has no top-level identity_hash', !array_key_exists('identity_hash', $h->metaFor('planted_nested')));

// ── Legitimate behaviour is preserved ───────────────────────────────────
echo "\n(3) the real holder still re-binds in place; a new identity gets a new row\n";
$reReg = $h->registerBrowser($victimHash);
check('same hash re-binds in place (same interface_id)', $reReg['interface_id'] === $victim['interface_id']);
check('the re-bind rotates the session token', $reReg['session_token'] !== $victimToken);
check('the rotated-away token no longer authenticates', !$h->authOk($victim['interface_id'], $victimToken));
check('the new token authenticates the victim row', $h->authOk($victim['interface_id'], $reReg['session_token']));

$otherHash = '00112233445566778899aabbccddeeff';
$before = $h->rowCount();
$other = $h->registerBrowser($otherHash);
check('a different valid hash creates its own row', $other['interface_id'] !== $victim['interface_id']);
check('the different-hash row is new', $h->rowCount() === $before + 1);
check('the different-hash row authenticates with its own token', $h->authOk($other['interface_id'], $other['session_token']));

// An empty / absent claim is the normal "no identity" case: a fresh row, no
// match, every time (this is how a client with no identity_hash behaves).
echo "\n(4) an absent identity_hash is simply a new row\n";
$before = $h->rowCount();
$anon1 = $h->registerBrowser('');
$anon2 = $h->registerBrowser('');
check('two empty-claim registrations are two distinct rows', $anon1['interface_id'] !== $anon2['interface_id']);
check('empty-claim registrations created two rows', $h->rowCount() === $before + 2);

// ── The validation is pinned on its own ─────────────────────────────────
// (1) cannot tell whether the validation or the exact compare stopped the
// attack. Here the earlier row was made with the SAME malformed claim, so the
// exact compare WOULD match it: only the validation keeps the second
// registration from re-binding (and so rotating the first one's token).
echo "\n(5) a malformed claim never re-binds, even a row made with the same claim\n";
$malformed = [
    "wildcard '%'"                  => '%',
    "wildcard '_%'"                 => '_%',
    "non-hex 'ZZZZ'"                => 'ZZZZ',
    'upper-case hash'               => strtoupper($victimHash),
    '31-character hash'             => substr($victimHash, 0, 31),
    '32 hex + trailing newline'     => $victimHash . "\n",
];
foreach ($malformed as $label => $claim) {
    $first = $h->registerBrowser($claim);
    $second = $h->registerBrowser($claim);
    check("[$label] registered twice gives two distinct rows", $first['interface_id'] !== $second['interface_id']);
    check("[$label] the first registration's token still authenticates", $h->authOk($first['interface_id'], $first['session_token']));
}

// ── A dropped claim speaks (silent-failures rule) ───────────────────────
echo "\n(6) every malformed claim is logged [REG-BAD-IDENTITY]; valid and absent claims are not\n";
$logged = [
    "wildcard '%'"                  => '%',
    "wildcard '_%'"                 => '_%',
    'upper-case hash'               => strtoupper($victimHash),
    '33-character hash'             => $victimHash . 'a',
    'hash with a backslash'         => substr($victimHash, 0, 31) . '\\',
    '32 hex + trailing newline'     => $victimHash . "\n",
    'non-string claim (array)'      => [$victimHash],
    'non-string claim (int)'        => 12345,
];
foreach ($logged as $label => $claim) {
    $n = badIdentityLogsDuring(static fn () => $h->registerBrowser($claim));
    check("[$label] logged [REG-BAD-IDENTITY] once (got $n)", $n === 1);
}
$n = badIdentityLogsDuring(static fn () => $h->registerBrowser($victimHash));
check("a valid 32-hex claim is not logged (got $n)", $n === 0);
$n = badIdentityLogsDuring(static fn () => $h->registerBrowser(''));
check("an empty claim is not logged (got $n)", $n === 0);
$n = badIdentityLogsDuring(static fn () => $h->registerInterface('Retichat Web', 1000000, 500, ['client' => 'rns-js']));
check("an absent claim is not logged (got $n)", $n === 0);
@unlink($logFile);

echo "\nResults: $pass passed, $fail failed\n";
exit($fail > 0 ? 1 : 0);
