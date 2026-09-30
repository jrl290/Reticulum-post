<?php
/**
 * The build stamp: deploy.sh names the commit it deploys, /health publishes
 * it, verify-live-stamp.sh compares it with a ref. No credentials anywhere.
 *
 * Nodes are deployed from `git archive`, which carries no .git, and until
 * 2026-09-30 the only way to learn what a node ran was verify-deploy.sh over
 * SSH. The 2026-09-30 release review could not check PHP drift for that
 * reason.
 *
 *   (a) write-build-stamp.sh resolves any ref to the full commit, and
 *       BuildStamp::read() gives it back from the directory it wrote;
 *   (b) it refuses a ref that is not a commit, and writes nothing;
 *   (c) on a git-archive stage laid out as deploy.sh lays it out, the stamp
 *       lands next to index.php, where /health reads it;
 *   (d) deploy.sh calls the writer on its stage, uploads the stamp after the
 *       lint, and backs up the previous stamp for a rollback;
 *   (e) verify-live-stamp.sh: match → 0, older commit → 1 with the distance,
 *       no stamp → 2, no answer → 2 (read through file:// URLs, no server).
 *
 * Run: php tests/build_stamp_test.php
 */
declare(strict_types=1);

$root = dirname(__DIR__);
$repo = dirname($root);
require_once $root . '/src/lib/database.php';
require_once $root . '/src/index.php';

use ReticulumPhp\BuildStamp;

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

/** @return array{int, string} exit code and combined output */
function run(string $command, array $env = []): array
{
    $prefix = '';
    foreach ($env as $k => $v) {
        $prefix .= $k . '=' . escapeshellarg($v) . ' ';
    }
    exec($prefix . $command . ' 2>&1', $out, $code);
    return [$code, implode("\n", $out)];
}

$tmp = sys_get_temp_dir() . '/reticulum-build-stamp-' . bin2hex(random_bytes(4));
mkdir($tmp, 0775, true);
$writer = escapeshellarg($repo . '/write-build-stamp.sh');
$checker = escapeshellarg($repo . '/verify-live-stamp.sh');
[, $head] = run('git -C ' . escapeshellarg($repo) . ' rev-parse HEAD');
[, $parent] = run('git -C ' . escapeshellarg($repo) . ' rev-parse HEAD~1');
[, $short] = run('git -C ' . escapeshellarg($repo) . ' rev-parse --short HEAD');

// ── (a) any ref → the full commit ───────────────────────────────────────
echo "(a) the writer names the full commit\n";
[$code] = run("$writer HEAD " . escapeshellarg($tmp));
$stamp = BuildStamp::read($tmp);
check('HEAD is stamped as its 40-hex commit', $code === 0 && $stamp['commit'] === $head, json_encode($stamp));
check('stamped_at is a UTC timestamp within a minute of now',
    is_string($stamp['stamped_at']) && abs(strtotime($stamp['stamped_at']) - time()) < 60, (string) $stamp['stamped_at']);
run("$writer " . escapeshellarg($short) . ' ' . escapeshellarg($tmp));
check('a short sha is stamped as the full commit', BuildStamp::read($tmp)['commit'] === $head);
run("$writer HEAD~1 " . escapeshellarg($tmp));
check('HEAD~1 is stamped as its own commit, not HEAD', BuildStamp::read($tmp)['commit'] === $parent);

// ── (b) a bad ref writes nothing ────────────────────────────────────────
echo "(b) a ref that is not a commit is refused\n";
$empty = $tmp . '/empty';
mkdir($empty);
[$code, $out] = run("$writer no-such-ref-" . bin2hex(random_bytes(3)) . ' ' . escapeshellarg($empty));
check('non-zero exit for an unknown ref', $code !== 0, $out);
check('no build.json written for an unknown ref', !is_file($empty . '/build.json'));
[$code] = run("$writer HEAD " . escapeshellarg($tmp . '/missing-dir'));
check('non-zero exit for a missing directory', $code !== 0);

// ── (c) the deploy stage layout ─────────────────────────────────────────
echo "(c) on a git-archive stage the stamp sits next to index.php\n";
$stage = $tmp . '/stage';
mkdir($stage);
run('git -C ' . escapeshellarg($repo) . ' archive HEAD php/src | tar -x -C ' . escapeshellarg($stage));
run("$writer HEAD " . escapeshellarg($stage . '/php/src'));
check('stage has index.php and build.json side by side',
    is_file($stage . '/php/src/index.php') && is_file($stage . '/php/src/build.json'));
check('the stage stamp reads back as HEAD', BuildStamp::read($stage . '/php/src')['commit'] === $head);
check('HttpApi reads the stamp from index.php\'s own directory by default',
    (new ReflectionParameter([\ReticulumPhp\HttpApi::class, '__construct'], 'buildStampDir'))->getDefaultValue()
        === dirname((new ReflectionClass(\ReticulumPhp\HttpApi::class))->getFileName()));

// ── (d) deploy.sh wiring ────────────────────────────────────────────────
echo "(d) deploy.sh writes, uploads and backs up the stamp\n";
$deploy = (string) file_get_contents($repo . '/deploy.sh');
$archiveAt = strpos($deploy, 'git -C "$REPO_DIR" archive "$REF"');
$writeAt = strpos($deploy, '"$REPO_DIR/write-build-stamp.sh" "$REF" "$STAGE_SRC"');
$lintAt = strpos($deploy, 'deployed code does not parse');
$uploadAt = strpos($deploy, '"$STAGE_SRC/build.json" "$host:~/${REMOTE_DIR}/build.json"');
check('the stamp is written on the stage after git archive', $archiveAt !== false && $writeAt !== false && $writeAt > $archiveAt);
check('the stamp is uploaded after the remote lint', $lintAt !== false && $uploadAt !== false && $uploadAt > $lintAt);
check('the backup keeps the previous stamp, or an unknown one',
    str_contains($deploy, 'cp build.json ../reticulum-rollback/') && str_contains($deploy, '{\"commit\":null}'));
check('build.json is not a deployed php file verify-deploy.sh would hash', !str_ends_with(BuildStamp::FILE, '.php'));
$gitignore = (string) file_get_contents($repo . '/.gitignore');
check('a stray php/src/build.json is ignored, so it cannot dirty the deploy tree check',
    preg_match('#^php/src/build\.json$#m', $gitignore) === 1);

// ── (e) verify-live-stamp.sh ────────────────────────────────────────────
echo "(e) verify-live-stamp.sh compares /health with a ref\n";
$health = static function (?array $build) use ($tmp): string {
    $path = $tmp . '/health-' . bin2hex(random_bytes(3)) . '.json';
    $body = ['status' => 'ok', 'queues' => []];
    if ($build !== null) {
        $body['build'] = $build;
    }
    file_put_contents($path, json_encode($body));
    return 'file://' . $path;
};
[$code, $out] = run("$checker HEAD", ['HEALTH_URL' => $health(['commit' => $head, 'stamped_at' => '2026-09-30T12:00:00Z'])]);
check('a node stamped with HEAD passes (exit 0)', $code === 0, $out);
[$code, $out] = run("$checker HEAD", ['HEALTH_URL' => $health(['commit' => $parent, 'stamped_at' => '2026-09-30T12:00:00Z'])]);
check('a node one commit behind fails (exit 1) and says so', $code === 1 && str_contains($out, '1 commit(s) behind HEAD'), $out);
[$code, $out] = run("$checker HEAD~1", ['HEALTH_URL' => $health(['commit' => $parent, 'stamped_at' => '2026-09-30T12:00:00Z'])]);
check('the same node passes against the ref it runs', $code === 0, $out);
[$code, $out] = run("$checker HEAD", ['HEALTH_URL' => $health(['commit' => str_repeat('0', 40), 'stamped_at' => '2026-09-30T12:00:00Z'])]);
check('a commit this repo does not have fails (exit 1)', $code === 1 && str_contains($out, 'not in this repository'), $out);
[$code, $out] = run("$checker HEAD", ['HEALTH_URL' => $health(null)]);
check('a node without a stamp is unknown (exit 2), not a pass', $code === 2 && str_contains($out, 'no build stamp'), $out);
[$code, $out] = run("$checker HEAD", ['HEALTH_URL' => $health(['commit' => null])]);
check('a rolled-back "unknown" stamp is unknown (exit 2)', $code === 2, $out);
[$code, $out] = run("$checker HEAD", ['HEALTH_URL' => 'file://' . $tmp . '/no-such-health.json']);
check('a node that does not answer is unknown (exit 2)', $code === 2 && str_contains($out, 'did not answer'), $out);

run('rm -rf ' . escapeshellarg($tmp));

echo "\n$pass passed, $fail failed\n";
exit($fail === 0 ? 0 : 1);
