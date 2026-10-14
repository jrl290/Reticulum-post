<?php
/**
 * REGISTRATION-STAGE1.md §12's operator rule: the count never goes back.
 *
 * A signed row's registration_seq is what makes a captured signed body
 * single use (§3). It must never restart at 0 under the same node secret
 * (transport_state's registration_challenge_secret_hex), or a body already
 * used at a low count works once more. So interfaces is emptied only
 * together with transport_state, and never while transport_state survives:
 *
 *   (1) Storage::clearAllData() (POST /v1/monitor/clear) empties
 *       transport_state and interfaces. This passed before Stage 1: it
 *       pins. With Stage 1, a body used before the clear stays refused
 *       after it.
 *   (2) monitor.php's clear stops at the first DELETE that fails: with a
 *       SQLite trigger failing only the transport_state DELETE, it leaves
 *       interfaces alone. Until Stage 1 it caught each failure and went on.
 *
 * Run: php php/tests/clear_all_data_test.php
 */
declare(strict_types=1);

require_once dirname(__DIR__) . '/src/index.php';
require_once __DIR__ . '/stubs/registration_fixture.php';

const SECRET_KEY = 'registration_challenge_secret_hex';

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

function count_of(PDO $db, string $table): int
{
    return (int) $db->query("SELECT COUNT(*) FROM {$table}")->fetchColumn();
}

function remove_tree(string $path): void
{
    if (is_dir($path) && !is_link($path)) {
        foreach (scandir($path) ?: [] as $entry) {
            if ($entry !== '.' && $entry !== '..') {
                remove_tree($path . '/' . $entry);
            }
        }
        rmdir($path);
    } elseif (file_exists($path) || is_link($path)) {
        unlink($path);
    }
}

/** A node secret and a browser row, as a node that has served a browser holds them. */
function seed(ReticulumPhp\Storage $storage): void
{
    RegFixture::db($storage)->prepare('INSERT INTO transport_state (state_key, state_value, updated_at) VALUES (:k, :v, 1)')
        ->execute([':k' => SECRET_KEY, ':v' => bin2hex(random_bytes(32))]);
    RegFixture::capture(static fn () => $storage->registerInterface('Retichat Web', 1000000, 500, ['client' => 'rns-js', 'mode' => 1]));
}

echo "(1) clearAllData() empties transport_state with interfaces\n";
$storage = RegFixture::storage();
$db = RegFixture::db($storage);
seed($storage);
check('before: a node secret in transport_state, a row in interfaces', count_of($db, 'transport_state') === 1 && count_of($db, 'interfaces') === 1);
$storage->clearAllData();
check('interfaces is empty', count_of($db, 'interfaces') === 0);
check('transport_state is empty: the node secret went with it', count_of($db, 'transport_state') === 0);

echo "\n(1b) so a body used before the clear stays used after it\n";
if (!method_exists($storage, 'issueChallenge')) {
    check("Stage 1's signed registration exists", false, 'no Storage::issueChallenge()');
} else {
    $storage = RegFixture::storage();
    $db = RegFixture::db($storage);
    $identity = RegFixture::identity();
    $used = RegFixture::body($identity, RegFixture::challenge($storage, $identity), RegFixture::browserMetadata());
    [$first] = RegFixture::capture(static fn () => $storage->registerFromBody($used));
    check('a signed registration at count 0 binds (the precondition)', RegFixture::outcome($first) === [200, null]);
    $storage->issueChallenge(['identity_hash' => bin2hex(random_bytes(16))]);
    check('transport_state holds the node secret and the hash-only count', count_of($db, 'transport_state') === 2, (string) count_of($db, 'transport_state'));
    $secretBefore = RegFixture::secret($storage);
    [$again] = RegFixture::capture(static fn () => $storage->registerFromBody($used));
    check('the used body is refused before the clear', RegFixture::outcome($again) === [409, 'stale_challenge'], json_encode(RegFixture::outcome($again)));
    $storage->clearAllData();
    [$after] = RegFixture::capture(static fn () => $storage->registerFromBody($used));
    check('the used body is still refused after the clear (count 0 again, but a new secret)',
        RegFixture::outcome($after) === [409, 'stale_challenge'], json_encode(RegFixture::outcome($after)));
    check('and checking it made no secret', RegFixture::secret($storage) === '');
    [$fresh] = RegFixture::capture(static fn () => RegFixture::register($storage, $identity));
    check('a fresh challenge binds again, under a new secret',
        RegFixture::outcome($fresh) === [200, null] && RegFixture::secret($storage) !== '' && RegFixture::secret($storage) !== $secretBefore);

    // The hazard the rule prevents: interfaces emptied, transport_state kept.
    $kept = RegFixture::storage();
    $keptDb = RegFixture::db($kept);
    $victim = RegFixture::identity();
    $captured = RegFixture::body($victim, RegFixture::challenge($kept, $victim), RegFixture::browserMetadata());
    RegFixture::capture(static fn () => $kept->registerFromBody($captured));
    $keptDb->exec('DELETE FROM interfaces');
    [$replayed] = RegFixture::capture(static fn () => $kept->registerFromBody($captured));
    check('(why) with interfaces emptied and the secret kept, a used body binds once more', RegFixture::outcome($replayed) === [200, null]);
}

echo "\n(2) monitor.php's clear stops at the first failed DELETE, so interfaces never outlives transport_state\n";
$dir = sys_get_temp_dir() . '/clear-all-data-' . bin2hex(random_bytes(4));
mkdir($dir . '/src/lib', 0775, true);
copy(dirname(__DIR__) . '/src/monitor.php', $dir . '/src/monitor.php');
copy(dirname(__DIR__) . '/src/lib/empty_poll.php', $dir . '/src/lib/empty_poll.php');
file_put_contents($dir . '/src/config.toml', implode("\n", [
    '[storage]', 'backend = "sqlite"', 'sqlite_path = "' . $dir . '/node.sqlite"', '[debug]', 'enabled = true', '']));
$node = RegFixture::storage([], $dir . '/node.sqlite');
$ndb = RegFixture::db($node);
seed($node);
$ndb->exec("INSERT INTO packet_hashes (packet_hash_hex, first_seen_at) VALUES ('aa', 1)");
$ndb->exec("CREATE TRIGGER keep_transport_state BEFORE DELETE ON transport_state
            BEGIN SELECT RAISE(ABORT, 'transport_state is kept by this test'); END");
$run = static function () use ($dir): string {
    $code = '$_SERVER["REQUEST_METHOD"] = "POST"; $_GET["action"] = "clear"; $_POST["confirm"] = "YES"; require '
        . var_export($dir . '/src/monitor.php', true) . ';';
    $proc = proc_open([PHP_BINARY, '-r', $code], [0 => ['file', '/dev/null', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes);
    $out = (string) stream_get_contents($pipes[1]) . (string) stream_get_contents($pipes[2]);
    fclose($pipes[1]);
    fclose($pipes[2]);
    proc_close($proc);

    return $out;
};
$output = $run();
check('the clear reports the failed table and that it stopped',
    str_contains($output, 'transport_state') && str_contains($output, 'stopped; later tables untouched'), substr(strip_tags($output), 0, 300));
check('the tables before it were emptied', count_of($ndb, 'packet_hashes') === 0);
check('transport_state (the node secret) is untouched', count_of($ndb, 'transport_state') === 1);
check('interfaces is untouched: no browser row lost while the secret survives', count_of($ndb, 'interfaces') === 1);
$ndb->exec('DROP TRIGGER keep_transport_state');
$output = $run();
check('with nothing failing, the clear empties everything',
    str_contains($output, 'All tables cleared') && count_of($ndb, 'interfaces') === 0 && count_of($ndb, 'transport_state') === 0,
    substr(strip_tags($output), 0, 300));
unset($node, $ndb);
remove_tree($dir);

echo "\n$pass passed, $fail failed\n";
exit($fail === 0 ? 0 : 1);
