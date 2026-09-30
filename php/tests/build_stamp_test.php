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
 *   (d) deploy.sh, run for real against a stand-in node (ssh and scp are
 *       local stubs, verify-deploy.sh a stub that passes or fails): the node
 *       says "unknown" from before the code goes up until verification has
 *       passed, and names the commit only after it; a failed verification or
 *       lint leaves "unknown"; the rollback copy keeps the previous stamp, or
 *       an unknown one for a node that had none;
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

// ── (d) deploy.sh against a stand-in node ────────────────────────────────
echo "(d) deploy.sh names the commit only on verified code\n";
// A clone of this repo at HEAD, with the working tree's deploy.sh and writer
// (so an uncommitted edit to them is what runs) and a verify-deploy.sh stub.
// ssh and scp are stubs on PATH that act on a directory standing in for the
// node's home; deploy.sh runs under `env -i`, so no real credential or host
// can reach it, and the host is in .invalid, which never resolves.
$sandbox = $tmp . '/deploy';
$clone = $sandbox . '/repo';
$bin = $sandbox . '/bin';
$badPhp = $sandbox . '/badphp';
$node = $sandbox . '/node';
$stubLog = $sandbox . '/stub.log';
foreach ([$bin, $badPhp] as $dir) {
    mkdir($dir, 0775, true);
}
run('git clone -q ' . escapeshellarg($repo) . ' ' . escapeshellarg($clone));
copy($repo . '/deploy.sh', $clone . '/deploy.sh');
copy($repo . '/write-build-stamp.sh', $clone . '/write-build-stamp.sh');
$stubs = [
    $bin . '/ssh' => <<<'SH'
#!/usr/bin/env bash
# ssh stand-in: skip options and the host, run the command at the fake node.
while [[ $# -gt 0 ]]; do
  case "$1" in -o) shift 2 ;; -*) shift ;; *) break ;; esac
done
shift
[[ -n "${STUB_LINT_FAIL:-}" ]] && PATH="$STUB_BADPHP:$PATH"
cd "$STUB_HOME" && HOME="$STUB_HOME" PATH="$PATH" exec bash -c "$*"
SH,
    $bin . '/scp' => <<<'SH'
#!/usr/bin/env bash
# scp stand-in: copy sources to host:~/path under the fake node's home, and
# log what the node's stamp said when code (a .php file) arrived.
args=()
while [[ $# -gt 0 ]]; do
  case "$1" in -o) shift 2 ;; -*) shift ;; *) args+=("$1"); shift ;; esac
done
n=${#args[@]}
dest="${args[$((n - 1))]}"
path="${dest#*:}"; path="${path#\~/}"
for src in "${args[@]:0:$((n - 1))}"; do
  case "$src" in *.php) echo "code-upload stamp: $(cat "$STUB_HOME/public_html/reticulum/build.json" 2>/dev/null || echo none)" >> "$STUB_LOG"; break ;; esac
done
cp "${args[@]:0:$((n - 1))}" "$STUB_HOME/$path"
SH,
    $clone . '/verify-deploy.sh' => <<<'SH'
#!/usr/bin/env bash
echo "verify-time stamp: $(cat "$STUB_HOME/public_html/reticulum/build.json" 2>/dev/null || echo none)" >> "$STUB_LOG"
exit "${STUB_VERIFY_EXIT:-0}"
SH,
    $badPhp . '/php' => "#!/bin/sh\necho \"PHP Parse error: stand-in lint failure in \$2\"\n",
];
foreach ($stubs as $path => $script) {
    file_put_contents($path, $script);
    chmod($path, 0755);
}

/** Put the stand-in node back to "running $parent", optionally with no stamp. */
$resetNode = static function (?string $stampCommit) use ($node, $stubLog): void {
    exec('rm -rf ' . escapeshellarg($node));
    mkdir($node . '/public_html/reticulum/lib', 0775, true);
    file_put_contents($node . '/public_html/reticulum/index.php', "<?php // old code\n");
    if ($stampCommit !== null) {
        file_put_contents($node . '/public_html/reticulum/build.json',
            json_encode(['commit' => $stampCommit, 'stamped_at' => '2026-09-01T00:00:00Z']) . "\n");
    }
    @unlink($stubLog);
};
$deploy = static function (array $extraEnv = []) use ($clone, $bin, $badPhp, $node, $stubLog): array {
    [, $gitPath] = run('command -v git');
    $env = array_merge([
        'PATH' => implode(':', [$bin, dirname(PHP_BINARY), dirname($gitPath), '/usr/bin', '/bin']),
        'HOME' => $node,
        'STUB_HOME' => $node,
        'STUB_LOG' => $stubLog,
        'STUB_BADPHP' => $badPhp,
        'RETICHAT_SSH_HOST' => 'stub@retichat.invalid',
        'DEPLOY_SKIP_TESTS' => '1',
    ], $extraEnv);
    $prefix = 'env -i';
    foreach ($env as $k => $v) {
        $prefix .= ' ' . $k . '=' . escapeshellarg($v);
    }
    exec($prefix . ' bash ' . escapeshellarg($clone . '/deploy.sh') . ' HEAD retichat 2>&1', $out, $code);
    return [$code, implode("\n", $out), is_file($stubLog) ? (string) file_get_contents($stubLog) : ''];
};
$nodeStamp = static fn (): ?string => BuildStamp::read($node . '/public_html/reticulum')['commit'];
$rollbackStamp = static fn (): ?string => BuildStamp::read($node . '/public_html/reticulum-rollback')['commit'];

$resetNode($parent);
[$code, $out, $log] = $deploy();
check('a verified deploy exits 0', $code === 0, $out);
check('...and the node then names HEAD', $nodeStamp() === $head, (string) $nodeStamp());
check('...the node said "unknown" when the code arrived, not the old commit',
    str_contains($log, 'code-upload stamp: {"commit":null}') && !str_contains($log, $parent), $log);
check('...and still "unknown" while verify-deploy.sh ran, not HEAD', str_contains($log, 'verify-time stamp: {"commit":null}'), $log);
check('...the rollback copy names the commit the node ran before', $rollbackStamp() === $parent, (string) $rollbackStamp());
check('...and the deployed code is the ref\'s, not the old file',
    !str_contains((string) @file_get_contents($node . '/public_html/reticulum/index.php'), 'old code'));

$resetNode($parent);
[$code, $out, $log] = $deploy(['STUB_VERIFY_EXIT' => '1']);
check('a deploy whose byte verification fails exits non-zero', $code !== 0, $out);
check('...and leaves the node saying "unknown", not HEAD and not the old commit', $nodeStamp() === null
    && is_file($node . '/public_html/reticulum/build.json'), (string) @file_get_contents($node . '/public_html/reticulum/build.json'));
check('...with the old stamp kept for a rollback', $rollbackStamp() === $parent, (string) $rollbackStamp());

$resetNode($parent);
[$code, $out, $log] = $deploy(['STUB_LINT_FAIL' => '1']);
check('a deploy whose code fails the remote lint exits non-zero, before verification',
    $code !== 0 && str_contains($out, 'does not parse') && !str_contains($log, 'verify-time'), $out);
check('...and leaves the node saying "unknown"', $nodeStamp() === null
    && is_file($node . '/public_html/reticulum/build.json'), (string) @file_get_contents($node . '/public_html/reticulum/build.json'));

$resetNode(null);
[$code, $out] = $deploy();
check('a node deployed before stamps gets an explicit unknown rollback stamp',
    $code === 0 && $nodeStamp() === $head
    && str_contains((string) @file_get_contents($node . '/public_html/reticulum-rollback/build.json'), '"commit":null'), $out);

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
// HEAD~1..HEAD is one commit, or more when HEAD is a merge (a merged branch
// brings its own commits), and the checker counts them all.
[, $behind] = run('git -C ' . escapeshellarg($repo) . ' rev-list --count HEAD~1..HEAD');
check('a node on HEAD~1 fails (exit 1) and says how far behind', $code === 1 && str_contains($out, trim($behind) . ' commit(s) behind HEAD'), $out);
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
