<?php
/**
 * deploy.sh never leaves a node running a mix of two releases.
 *
 * Until 2026-10-04 deploy.sh scp'd the top-level files straight into the live
 * directory and lib/ a few seconds after them. For those seconds a node ran
 * e3c05ea's index.php with the old lib/ (every exchange a 500, every ingest
 * "Class ReticulumPhp\WakeConfig not found"); the lint ran only once the
 * files were live; and a file a commit deleted stayed on the node for good.
 *
 * This runs the real deploy.sh, from a scratch clone of this repo carrying
 * the working tree's deploy.sh, verify-deploy.sh and write-build-stamp.sh,
 * against two stand-in nodes: retichat through sshpass with a fake password,
 * selectiv through key auth. ssh, scp and sshpass are shims, first on PATH,
 * that map stub@<node>.invalid:~/... to a directory per node and refuse every
 * other host; curl, wget, rsync, sftp and nc are shims that refuse outright.
 * deploy.sh runs under `env -i` with stdin from /dev/null, from a wrapper that
 * sources only the fake deploy.env written here and refuses unless every host
 * in it is in .invalid (which never resolves) and every one of those tools
 * resolves to its shim. The real deploy.env is never read.
 *
 *   (a) a good ref: code reaches each node only through ~/reticulum-incoming;
 *       it goes live in ONE remote command per node, only after every node
 *       has linted every file of it, with the stamp saying "unknown" from the
 *       first rename; the RETIRED files are removed and held by the rollback
 *       copy, which holds the whole previous tree; config, var/ and every file
 *       the deploy does not own survive; no rm touches anything else;
 *   (b) a ref with a syntax error changes nothing on any node, stamps and
 *       rollback copies included;
 *   (c) a ref one node's php rejects changes nothing on the other node either;
 *   (d) a failure after the swap prints a rollback command, without the
 *       password, that restores the previous tree, retired files and stamp;
 *   (e) a ref that still ships a RETIRED file (an older ref) keeps it;
 *   (f) a rollback copy that lost a file (a full disk, say) stops the swap
 *       before anything changes, so nothing is replaced or removed that the
 *       rollback command could not restore;
 *   (g) a php file the node keeps (its _test.php) that does not parse stops
 *       the deploy before anything goes live on any node, as the live lint
 *       after the swap would otherwise stop it with one node already live; a
 *       node file whose name has a space, and a RETIRED file that no longer
 *       parses, stop nothing (scenario (a));
 *   (h) a rename that fails part way through the swap, the disk full from
 *       then on: the same command puts the previous release back, stamp
 *       included, by renames out of ~/reticulum-rollback, the files it added
 *       moved back to ~/reticulum-incoming;
 *   (i) a connection that drops part way through the swap (SIGHUP and SIGPIPE
 *       to the node's shell, the answer lost): the node finishes the swap;
 *   (j) deploy.sh refuses a RETIRED list naming a file the node owns
 *       (config.php, _test.php) before it contacts any node; and (a) holds
 *       whatever RETIRED lists, nothing included;
 *   (k) the guards: the shims refuse a host outside .invalid and a password
 *       other than the fake one, and the wrapper refuses a deploy.env that
 *       names a real host or lies outside the sandbox.
 *
 * Run: php tests/deploy_never_mixes_releases_test.php
 * Against another deploy.sh (to see what it would fail):
 *   DEPLOY_SH_UNDER_TEST=/path/to/deploy.sh php tests/deploy_never_mixes_releases_test.php
 * With dash as the nodes' shell, to hold the remote commands to POSIX sh:
 *   STUB_REMOTE_SHELL=dash php tests/deploy_never_mixes_releases_test.php
 */
declare(strict_types=1);

$root = dirname(__DIR__);
$repo = dirname($root);

const NULL_STAMP = '{"commit":null}';
const FAKE_PASS = 'fake-password-for-the-deploy-test';

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

function refuse(string $why): never
{
    fwrite(STDERR, "deploy_never_mixes_releases_test: refusing to run: $why\n");
    exit(1);
}

function esc(string $s): string
{
    return escapeshellarg($s);
}

/** @return array{int, string} exit code and combined output */
function sh(string $command): array
{
    $out = [];
    exec($command . ' 2>&1', $out, $code);
    return [$code, implode("\n", $out)];
}

function put(string $path, string $content): void
{
    if (!is_dir(dirname($path))) {
        mkdir(dirname($path), 0775, true);
    }
    file_put_contents($path, $content);
}

/** @return array<string, string> relative path => md5, every file under $dir */
function snapshot(string $dir): array
{
    $files = [];
    if (!is_dir($dir)) {
        return $files;
    }
    $it = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($dir, FilesystemIterator::SKIP_DOTS));
    foreach ($it as $file) {
        if ($file->isFile()) {
            $files[substr($file->getPathname(), strlen($dir) + 1)] = md5_file($file->getPathname());
        }
    }
    ksort($files);
    return $files;
}

/** @param array<string, string> $before @param array<string, string> $after */
function snapshotDiff(array $before, array $after): string
{
    $lines = [];
    foreach ($before as $path => $hash) {
        if (!isset($after[$path])) {
            $lines[] = "removed $path";
        } elseif ($after[$path] !== $hash) {
            $lines[] = "changed $path";
        }
    }
    foreach (array_diff_key($after, $before) as $path => $_) {
        $lines[] = "added $path";
    }
    return implode(', ', array_slice($lines, 0, 8)) . (count($lines) > 8 ? ', …' : '');
}

function normPath(string $path): string
{
    $parts = [];
    foreach (explode('/', $path) as $part) {
        if ($part === '' || $part === '.') {
            continue;
        }
        if ($part === '..') {
            array_pop($parts);
            continue;
        }
        $parts[] = $part;
    }
    return '/' . implode('/', $parts);
}

function within(string $path, string $dir): bool
{
    return $path === $dir || str_starts_with($path, $dir . '/');
}

function stampCommit(string $live): ?string
{
    $raw = @file_get_contents($live . '/build.json');
    if ($raw === false) {
        return 'none';
    }
    $data = json_decode($raw, true);
    return is_array($data) && array_key_exists('commit', $data) ? $data['commit'] : 'unreadable';
}

// ── The sandbox, and the guards that keep it one ─────────────────────────
$tmp = realpath(sys_get_temp_dir()) . '/reticulum-deploy-swap-' . bin2hex(random_bytes(4));
$clone = $tmp . '/repo';
$bin = $tmp . '/bin';
$remoteBin = $tmp . '/remote-bin';
$nodesDir = $tmp . '/nodes';
$lintCache = $tmp . '/lint-cache';
$stubLog = $tmp . '/stub.log';
$stubOps = $tmp . '/stub.ops';
$stubLib = $tmp . '/stub-lib.sh';
$wrapper = $tmp . '/run-with-fake-env.sh';
$fakeEnv = $clone . '/deploy.env';
$realDeployEnv = $repo . '/deploy.env';
$deploySh = getenv('DEPLOY_SH_UNDER_TEST') ?: $repo . '/deploy.sh';
$nodes = ['retichat' => $nodesDir . '/retichat', 'selectiv' => $nodesDir . '/selectiv'];

$repoReal = realpath($repo);
if ($repoReal === false || within($tmp, $repoReal)) {
    refuse("the sandbox $tmp would lie inside the repository");
}
if (normPath($fakeEnv) === normPath($realDeployEnv) || dirname($fakeEnv) === $repoReal) {
    refuse('the fake deploy.env would be the real one');
}
if (!is_file($deploySh)) {
    refuse("no deploy.sh at $deploySh");
}
// The scripts under test reach a node only through ssh, scp and sshpass on
// PATH (the shims), and read no deploy.env themselves; anything else could
// bypass the stand-ins, so the test does not run it at all.
foreach ([$deploySh, $repo . '/verify-deploy.sh', $repo . '/write-build-stamp.sh'] as $script) {
    foreach (file($script, FILE_IGNORE_NEW_LINES) as $n => $line) {
        $code = ltrim($line);
        if ($code === '' || $code[0] === '#') {
            continue;
        }
        if (preg_match('#(^|[\s;&|(`"\'])/[^\s;&|]*/(ssh|scp|sshpass|curl|wget|rsync|sftp|nc)\b#', $code)) {
            refuse(basename($script) . ':' . ($n + 1) . ' calls a network tool by absolute path, past the shims');
        }
        if (preg_match('#\b(curl|wget|verify-live-stamp\.sh)\b|https?://#', $code)) {
            refuse(basename($script) . ':' . ($n + 1) . ' fetches a URL, which the stand-ins do not cover');
        }
        if (preg_match('#(^|[;&|]\s*|\b(then|do|else)\s+)(source|\.)\s+\S*deploy\.env#', $code)) {
            refuse(basename($script) . ':' . ($n + 1) . ' sources a deploy.env itself');
        }
    }
}

foreach ([$bin, $remoteBin, $nodesDir, $lintCache, $tmp . '/operator-home'] as $dir) {
    mkdir($dir, 0775, true);
}
[$code, $out] = sh('git clone -q ' . esc($repo) . ' ' . esc($clone));
if ($code !== 0) {
    refuse("git clone failed: $out");
}
[, $repoHead] = sh('git -C ' . esc($repo) . ' rev-parse HEAD');
[, $head] = sh('git -C ' . esc($clone) . ' rev-parse HEAD');
if ($head !== $repoHead) {
    refuse("the clone is at $head, not this repository's HEAD $repoHead");
}
[, $parent] = sh('git -C ' . esc($clone) . ' rev-parse HEAD~1');
copy($deploySh, $clone . '/deploy.sh');
copy($repo . '/verify-deploy.sh', $clone . '/verify-deploy.sh');
copy($repo . '/write-build-stamp.sh', $clone . '/write-build-stamp.sh');
foreach (['deploy.sh', 'verify-deploy.sh', 'write-build-stamp.sh'] as $script) {
    chmod($clone . '/' . $script, 0755);
}
file_put_contents($fakeEnv, implode("\n", [
    '# The deploy test\'s stand-in credentials: hosts in .invalid, a fake password.',
    'export RETICHAT_SSH_HOST="stub@retichat.invalid"',
    'export RETICHAT_SSH_PASS="' . FAKE_PASS . '"',
    'export SELECTIV_SSH_HOST="stub@selectiv.invalid"',
    'export SELECTIV_SSH_PASS=""',
    '',
]));

/**
 * A bash array's entries as a script assigns it (NAME=( ... ), on one line or
 * several, with comments); null when the script has no such assignment.
 * @return list<string>|null
 */
function bashArray(string $script, string $name): ?array
{
    $entries = null;
    foreach (file($script, FILE_IGNORE_NEW_LINES) as $line) {
        if ($entries === null) {
            if (!preg_match('/^' . preg_quote($name, '/') . '=\((.*)$/', $line, $m)) {
                continue;
            }
            $entries = [];
            $line = $m[1];
        }
        $code = trim((string) preg_replace('/#.*/', '', $line));
        $closed = strpos($code, ')');
        if ($closed !== false) {
            $code = substr($code, 0, $closed);
        }
        if (trim($code) !== '') {
            array_push($entries, ...preg_split('/\s+/', trim($code)));
        }
        if ($closed !== false) {
            return $entries;
        }
    }
    return null;
}

// RETIRED, as the working tree's deploy.sh lists it (whatever is under test).
// It may be empty: entries are dropped once every node is past them. The
// deploy's own "retiring, where present:" line is checked against it, so a
// list this parser misread fails the test instead of silently testing less.
$retired = bashArray($repo . '/deploy.sh', 'RETIRED');
if ($retired === null) {
    refuse('deploy.sh has no RETIRED=( ... ) list to take the expected removals from');
}

// ── The stand-ins ───────────────────────────────────────────────────────
$scripts = [
    $stubLib => <<<'SH'
# Helpers the stand-ins share (builtins where they will do: on macOS every
# process the stand-ins start costs the suite time). Every remote operation
# gets a number.
next_op() {
  local n=0
  [ -f "$STUB_OPS" ] && read -r n < "$STUB_OPS"
  n=$((n + 1))
  echo "$n" > "$STUB_OPS"
  echo "$n"
}
# A fingerprint of everything in the live directory except the stamp.
live_fp() {
  ( cd "$1/public_html/reticulum" 2>/dev/null && find . -type f ! -path ./build.json -exec cksum {} + | LC_ALL=C sort ) | cksum
}
stamp() {
  local line=""
  if [ -f "$1/public_html/reticulum/build.json" ]; then IFS= read -r line < "$1/public_html/reticulum/build.json"; printf '%s' "$line"; else printf none; fi
}
abs_path() {
  case "$1" in
    /*) printf '%s' "$1" ;;
    *) printf '%s/%s' "$PWD" "$1" ;;
  esac
}
refuse() {
  printf 'REFUSED\t%s\n' "$*" >> "$STUB_LOG"
  echo "stand-in: refusing $*" >&2
  exit 255
}
SH,
    $bin . '/ssh' => <<<'SH'
#!/usr/bin/env bash
# ssh stand-in. Connects nowhere: runs the command in the directory standing
# in for the node's home, for stub@<node>.invalid only.
set -u
. "$STUB_LIB"
batch=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    -o) [[ "${2:-}" == "BatchMode=yes" ]] && batch=1; shift 2 ;;
    -[pilFJ]) shift 2 ;;
    -*) shift ;;
    *) break ;;
  esac
done
target="${1:-}"
[[ $# -gt 0 ]] && shift
host="${target#*@}"
node="${host%.invalid}"
if [[ "$host" != *.invalid || -z "$node" || "$node" == */* || ! -d "$STUB_NODES/$node" ]]; then
  refuse "ssh to $target"
fi
home="$STUB_NODES/$node"
[ -t 0 ] || cat > /dev/null   # a real ssh forwards stdin, and so drains it
op=$(next_op)
before=$(live_fp "$home")
stamp_before=$(stamp "$home")
# The command's output is held back until it ends: when the node side marks
# the connection dropped (the mv stand-in's STUB_MV_HUP), none of it arrives.
(cd "$home" && HOME="$home" STUB_OP="$op" STUB_NODE="$node" PATH="$STUB_REMOTE_BIN:$PATH" "$STUB_REMOTE_SHELL" -c "$*") > "$STUB_SANDBOX/ssh-out"
rc=$?
if [[ -f "$STUB_LOG.dropped" ]]; then
  rm -f "$STUB_LOG.dropped"
  : > "$STUB_SANDBOX/ssh-out"
  echo "stand-in: connection to $target lost" >&2
  rc=255
fi
changed=0
[[ "$before" != "$(live_fp "$home")" ]] && changed=1
printf 'OP\t%s\tssh\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$op" "$node" "${STUB_VIA:-key}" "$batch" "$changed" "$rc" \
  "$stamp_before" "$(stamp "$home")" "$*" >> "$STUB_LOG"
while IFS= read -r line || [[ -n "$line" ]]; do printf '%s\n' "$line"; done < "$STUB_SANDBOX/ssh-out"
exit $rc
SH,
    $bin . '/scp' => <<<'SH'
#!/usr/bin/env bash
# scp stand-in. Copies local files to stub@<node>.invalid:~/path, which is
# <node's home>/path; refuses any other host or path.
set -u
. "$STUB_LIB"
batch=0
args=()
while [[ $# -gt 0 ]]; do
  case "$1" in
    -o) [[ "${2:-}" == "BatchMode=yes" ]] && batch=1; shift 2 ;;
    -[PiFJlSc]) shift 2 ;;
    -*) shift ;;
    *) args+=("$1"); shift ;;
  esac
done
n=${#args[@]}
[[ $n -ge 2 ]] || refuse "scp without a source and a destination"
dest="${args[$((n - 1))]}"
target="${dest%%:*}"
path="${dest#*:}"
host="${target#*@}"
node="${host%.invalid}"
if [[ "$dest" != *:* || "$host" != *.invalid || -z "$node" || "$node" == */* || ! -d "$STUB_NODES/$node" ]]; then
  refuse "scp to $dest"
fi
case "$path" in
  "~/"*) path="${path#\~/}" ;;
  *) refuse "scp to $dest: only ~/ paths" ;;
esac
for src in "${args[@]:0:$((n - 1))}"; do
  [[ "$src" == *:* ]] && refuse "scp from a remote $src"
done
home="$STUB_NODES/$node"
op=$(next_op)
before=$(live_fp "$home")
stamp_before=$(stamp "$home")
names=""
for src in "${args[@]:0:$((n - 1))}"; do names="$names ${src##*/}"; done
cp "${args[@]:0:$((n - 1))}" "$home/$path"
rc=$?
changed=0
[[ "$before" != "$(live_fp "$home")" ]] && changed=1
printf 'OP\t%s\tscp\t%s\t%s\t%s\t%s\t%s\t%s\t%s\tdest=%s files=%s\n' "$op" "$node" "${STUB_VIA:-key}" "$batch" "$changed" "$rc" \
  "$stamp_before" "$(stamp "$home")" "$path" "${names# }" >> "$STUB_LOG"
exit $rc
SH,
    $bin . '/sshpass' => <<<'SH'
#!/usr/bin/env bash
# sshpass stand-in: -e only, the test's fake password only, ssh or scp only,
# and those are the stand-ins beside it.
set -u
. "$STUB_LIB"
[[ "${1:-}" == "-e" ]] || refuse "sshpass without -e"
shift
[[ "${SSHPASS:-}" == "$STUB_FAKE_PASS" ]] || refuse "sshpass with a password that is not the test's fake one"
case "${1:-}" in
  ssh|scp) ;;
  *) refuse "sshpass running ${1:-nothing}" ;;
esac
cmd="$1"
shift
STUB_VIA=sshpass exec "$STUB_BIN/$cmd" "$@"
SH,
    $remoteBin . '/mv' => <<<'SH'
#!/usr/bin/env bash
# mv on the node: logs what the stamp said at the instant of each rename.
# STUB_MV_FAIL=<rel>: renaming ~/reticulum-incoming/<rel> fails, and the
# disk is full from then on: every cp on the node fails.
# STUB_MV_HUP=<rel>: before renaming it, the connection drops: the shell
# running the command gets SIGHUP and SIGPIPE, and the ssh stand-in returns
# none of its output.
. "$STUB_LIB"
ops=()
for a in "$@"; do case "$a" in -*) ;; *) ops+=("$a") ;; esac; done
src=$(abs_path "${ops[0]:-}")
if [[ -n "${STUB_MV_FAIL:-}" && "$src" == "$HOME/reticulum-incoming/$STUB_MV_FAIL" ]]; then
  printf 'MVFAIL\t%s\t%s\t%s\n' "${STUB_OP:-?}" "${STUB_NODE:-?}" "$src" >> "$STUB_LOG"
  : > "$STUB_LOG.full"
  echo "mv: cannot move '${ops[0]}': Disk quota exceeded" >&2
  exit 1
fi
if [[ -n "${STUB_MV_HUP:-}" && "$src" == "$HOME/reticulum-incoming/$STUB_MV_HUP" ]]; then
  : > "$STUB_LOG.dropped"
  kill -HUP "$PPID"
  kill -PIPE "$PPID"
fi
printf 'MV\t%s\t%s\t%s\t%s\t%s\n' "${STUB_OP:-?}" "${STUB_NODE:-?}" "$(stamp "$HOME")" \
  "$src" "$(abs_path "${ops[1]:-}")" >> "$STUB_LOG"
exec /bin/mv "$@"
SH,
    $remoteBin . '/rm' => <<<'SH'
#!/usr/bin/env bash
# rm on the node: logs every path it is asked to remove.
. "$STUB_LIB"
for a in "$@"; do
  case "$a" in -*) ;; *) printf 'RM\t%s\t%s\t%s\n' "${STUB_OP:-?}" "${STUB_NODE:-?}" "$(abs_path "$a")" >> "$STUB_LOG" ;; esac
done
exec /bin/rm "$@"
SH,
    $remoteBin . '/cp' => <<<'SH'
#!/usr/bin/env bash
# cp on the node. With STUB_CP_DROP=<path under the live directory>, a copy
# into ~/reticulum-rollback loses that one file, as a full disk would. Once
# the mv stand-in has filled the disk (STUB_MV_FAIL), every cp fails.
if [[ -f "$STUB_LOG.full" ]]; then
  printf 'CPFULL\t%s\t%s\n' "${STUB_OP:-?}" "${STUB_NODE:-?}" >> "$STUB_LOG"
  echo "cp: Disk quota exceeded" >&2
  exit 1
fi
/bin/cp "$@"
rc=$?
if [[ -n "${STUB_CP_DROP:-}" ]]; then
  for a in "$@"; do
    case "$a" in *reticulum-rollback*) /bin/rm -f "$HOME/reticulum-rollback/$STUB_CP_DROP"; break ;; esac
  done
fi
exit $rc
SH,
    $remoteBin . '/php' => <<<'SH'
#!/usr/bin/env bash
# php on the node. `php -l <file>` is the real lint (remembered by content,
# so the same bytes are not linted twice), logged with where it ran.
# STUB_LINT_FAIL_NODE=<node> fails every lint on that node;
# STUB_LIVE_LINT_FAIL_NODE=<node> fails only lints run in its live directory
# after the swap (while the stamp says "unknown").
if [[ $# -eq 2 && "$1" == "-l" ]]; then
  f="$2"
  . "$STUB_LIB"
  if [[ -n "${STUB_LINT_FAIL_NODE:-}" && "$STUB_LINT_FAIL_NODE" == "${STUB_NODE:-}" ]] \
     || [[ -n "${STUB_LIVE_LINT_FAIL_NODE:-}" && "$STUB_LIVE_LINT_FAIL_NODE" == "${STUB_NODE:-}" \
           && "$PWD" == "$HOME/public_html/reticulum" && "$(stamp "$HOME")" == '{"commit":null}' ]]; then
    printf 'LINT\t%s\t%s\t%s\t%s\tfail\n' "${STUB_OP:-?}" "${STUB_NODE:-?}" "$PWD" "$f" >> "$STUB_LOG"
    echo "PHP Parse error:  stand-in parse error in $f on line 1"
    echo "Errors parsing $f"
    exit 255
  fi
  key=$(cksum 2>/dev/null < "$f")
  key="${key// /_}"
  if [[ -n "$key" && -f "$STUB_LINT_CACHE/$key" ]]; then
    out="No syntax errors detected in $f"
    rc=0
  else
    out=$("$STUB_REAL_PHP" -l "$f" 2>&1)
    rc=$?
    [[ $rc -eq 0 && "$out" == "No syntax errors"* && -n "$key" ]] && : > "$STUB_LINT_CACHE/$key"
  fi
  result=fail
  [[ $rc -eq 0 ]] && result=ok
  printf 'LINT\t%s\t%s\t%s\t%s\t%s\n' "${STUB_OP:-?}" "${STUB_NODE:-?}" "$PWD" "$f" "$result" >> "$STUB_LOG"
  printf '%s\n' "$out"
  exit $rc
fi
exec "$STUB_REAL_PHP" "$@"
SH,
    $wrapper => <<<'SH'
#!/usr/bin/env bash
# Sources ONLY the fake deploy.env it is given, which must lie in the sandbox,
# and refuses unless every host in it is a stand-in in .invalid and ssh, scp
# and sshpass resolve to the stand-ins. Then runs: bash "$@".
set -u
fake="${1:-}"
shift
case "$fake" in
  "$STUB_SANDBOX"/*) ;;
  *) echo "wrapper: refusing to source $fake: not in the test sandbox" >&2; exit 97 ;;
esac
. "$fake" || { echo "wrapper: could not source $fake" >&2; exit 97; }
for v in RETICHAT_SSH_HOST SELECTIV_SSH_HOST; do
  case "${!v:-}" in
    *.invalid) ;;
    *) echo "wrapper: refusing: $v=${!v:-} is not a stand-in in .invalid" >&2; exit 97 ;;
  esac
done
for tool in ssh scp sshpass curl wget rsync sftp nc; do
  [ "$(command -v "$tool")" = "$STUB_BIN/$tool" ] \
    || { echo "wrapper: refusing: $tool resolves to $(command -v "$tool"), not the stand-in" >&2; exit 97; }
done
exec bash "$@"
SH,
];
// Nothing under test calls these (the test refuses to run a script that
// does), but should one start to, it reaches no host either.
foreach (['curl', 'wget', 'rsync', 'sftp', 'nc'] as $tool) {
    $scripts[$bin . '/' . $tool] = <<<SH
#!/usr/bin/env bash
. "\$STUB_LIB"
refuse "$tool \$*"
SH;
}
foreach ($scripts as $path => $script) {
    file_put_contents($path, $script);
    chmod($path, 0755);
}

[, $gitPath] = sh('command -v git');
$baseEnv = [
    'PATH' => implode(':', [$bin, dirname(PHP_BINARY), dirname($gitPath), '/usr/bin', '/bin', '/usr/sbin', '/sbin']),
    'HOME' => $tmp . '/operator-home',
    'LC_ALL' => 'C',
    'STUB_SANDBOX' => $tmp,
    'STUB_BIN' => $bin,
    'STUB_REMOTE_BIN' => $remoteBin,
    'STUB_NODES' => $nodesDir,
    'STUB_LIB' => $stubLib,
    'STUB_LOG' => $stubLog,
    'STUB_OPS' => $stubOps,
    'STUB_LINT_CACHE' => $lintCache,
    'STUB_REAL_PHP' => PHP_BINARY,
    'STUB_FAKE_PASS' => FAKE_PASS,
    'DEPLOY_SKIP_TESTS' => '1',
    // The shell the stand-in nodes run commands with (dash: are they POSIX?).
    'STUB_REMOTE_SHELL' => getenv('STUB_REMOTE_SHELL') ?: 'bash',
];

/** env -i with only the sandbox's variables, stdin from /dev/null. */
$isolated = static function (string $command, array $extraEnv = []) use ($baseEnv): array {
    $prefix = 'env -i';
    foreach (array_merge($baseEnv, $extraEnv) as $k => $v) {
        $prefix .= ' ' . $k . '=' . esc($v);
    }
    return sh($prefix . ' ' . $command . ' < /dev/null');
};

/** @return array{ops: list<array>, mvs: list<array>, rms: list<array>, lints: list<array>, refused: list<string>} */
$readLog = static function () use ($stubLog): array {
    $log = ['ops' => [], 'mvs' => [], 'rms' => [], 'lints' => [], 'refused' => []];
    foreach (is_file($stubLog) ? file($stubLog, FILE_IGNORE_NEW_LINES) : [] as $line) {
        $f = explode("\t", $line);
        switch ($f[0]) {
            case 'OP':
                $log['ops'][] = ['op' => (int) $f[1], 'kind' => $f[2], 'node' => $f[3], 'via' => $f[4], 'batch' => $f[5] === '1',
                    'changed' => $f[6] === '1', 'rc' => (int) $f[7], 'stamp_before' => $f[8], 'stamp_after' => $f[9], 'detail' => $f[10] ?? ''];
                break;
            case 'MV':
                $log['mvs'][] = ['op' => (int) $f[1], 'node' => $f[2], 'stamp' => $f[3], 'src' => normPath($f[4]), 'dst' => normPath($f[5])];
                break;
            case 'RM':
                $log['rms'][] = ['op' => (int) $f[1], 'node' => $f[2], 'path' => normPath($f[3])];
                break;
            case 'LINT':
                $log['lints'][] = ['op' => (int) $f[1], 'node' => $f[2], 'pwd' => $f[3], 'file' => $f[4], 'result' => $f[5]];
                break;
            case 'REFUSED':
                $log['refused'][] = $line;
                break;
        }
    }
    usort($log['ops'], static fn (array $a, array $b): int => $a['op'] <=> $b['op']);
    return $log;
};

/** Run deploy.sh <ref> [node] from the clone, through the wrapper. */
$deploy = static function (string $ref, string $only = '', array $extraEnv = []) use ($isolated, $readLog, $wrapper, $fakeEnv, $clone, $stubLog, $stubOps): array {
    @unlink($stubLog);
    @unlink($stubOps);
    @unlink($stubLog . '.full');
    [$code, $out] = $isolated(implode(' ', array_map('esc', array_filter(
        ['bash', $wrapper, $fakeEnv, $clone . '/deploy.sh', $ref, $only],
        static fn (string $a): bool => $a !== '',
    ))), $extraEnv);
    return [$code, preg_replace('/\e\[[0-9;]*m/', '', $out), $readLog()];
};

/** The ref's code as deploy.sh ships it: top-level and lib/ .php, minus the node-owned names. */
$refCode = static function (string $ref) use ($clone): array {
    $files = [];
    [, $list] = sh('git -C ' . esc($clone) . ' ls-tree -r --name-only ' . esc($ref) . ' -- php/src');
    foreach (explode("\n", $list) as $path) {
        if (!preg_match('#^php/src/((?:lib/)?[^/]+\.php)$#', $path, $m) || in_array($m[1], ['config.php', '_test.php'], true)) {
            continue;
        }
        $files[$m[1]] = (string) shell_exec('git -C ' . esc($clone) . ' cat-file blob ' . esc($ref . ':' . $path));
    }
    return $files;
};

/** A commit on top of HEAD in the clone, made without touching its working tree or index. */
$commitOnHead = static function (array $changes, string $message) use ($clone, $tmp): string {
    $index = $tmp . '/scratch-index';
    @unlink($index);
    $git = 'GIT_INDEX_FILE=' . esc($index) . ' git -C ' . esc($clone);
    sh("$git read-tree HEAD");
    foreach ($changes as $path => $content) {
        $blobFile = $tmp . '/scratch-blob';
        file_put_contents($blobFile, $content);
        [, $blob] = sh("$git hash-object -w " . esc($blobFile));
        sh("$git update-index --add --cacheinfo 100644," . trim($blob) . ',' . esc($path));
    }
    [, $tree] = sh("$git write-tree");
    [$code, $commit] = sh("$git -c user.name=deploy-test -c user.email=deploy-test@example.invalid commit-tree " . esc(trim($tree)) . ' -p HEAD -m ' . esc($message));
    if ($code !== 0 || !preg_match('/^[0-9a-f]{40}$/', trim($commit))) {
        refuse("could not make the test commit '$message': $commit");
    }
    return trim($commit);
};

$headCode = $refCode('HEAD');
$oldStampJson = '{"commit":"' . $parent . '","stamped_at":"2026-09-01T00:00:00Z"}';

/**
 * A node running "the previous release": HEAD's code with every file marked
 * old, the RETIRED files, and everything a node keeps that no deploy owns.
 */
$resetNode = static function (string $home) use ($headCode, $retired, $oldStampJson): void {
    exec('rm -rf ' . esc($home));
    $live = $home . '/public_html/reticulum';
    mkdir($live . '/lib', 0775, true);
    foreach ($headCode as $rel => $content) {
        put("$live/$rel", preg_replace('/<\?php/', '<?php /* previous release */', $content, 1));
    }
    // The last RETIRED file no longer parses: the swap removes it, so the
    // lint before the swap must not stop the deploy over it.
    foreach ($retired as $i => $rel) {
        put("$live/$rel", "<?php\n// $rel, as the previous release had it\n"
            . ($i === count($retired) - 1 ? "function (\n" : ''));
    }
    put("$live/build.json", $oldStampJson . "\n");
    // The node's own: secrets, state, logs, and files no commit ever had.
    put("$live/config.toml", "[database]\npassword = \"node-owned\"\n");
    put("$live/config.local.toml", "[node]\nname = \"node-owned\"\n");
    put("$live/config.php", "<?php\nreturn ['owned_by' => 'the node'];\n");
    put("$live/_test.php", "<?php\n// a node-owned scratch file\n");
    put("$live/local_tool.php", "<?php\n// a php file the node keeps that no commit has\n");
    put("$live/local tool.php", "<?php\n// another, whose name has a space\n");
    put("$live/lib/local_extra.php", "<?php\n// another, in lib/\n");
    put("$live/notes.txt", "not code\n");
    put("$live/.htaccess", "Options -Indexes\n");
    put("$live/error_log", "[01-Oct-2026] an old warning\n");
    put("$live/var/reticulum-php.sqlite", random_bytes(4096));
    put("$live/var/identity", random_bytes(64));
    put("$live/var/router.log", "router log\n");
    put("$live/var/cache/compiled.php", "<?php\n// runtime state that happens to be php\n");
    // Beside the live directory: another site's file, the web-root rollback
    // copy older deploys made, and a stale, broken incoming directory.
    put("$home/public_html/index.html", "<html>another site</html>\n");
    put("$home/public_html/reticulum-rollback/index.php", "<?php // the web-root rollback copy of older deploys\n");
    put("$home/reticulum-incoming/stale.php", "<?php function (\n");
    put("$home/reticulum-incoming/lib/stale_lib.php", "<?php // left by an earlier deploy\n");
};

/** Files under the live directory that are code a deploy replaces: *.php and lib/*.php. */
$isLiveCode = static fn (string $rel): bool => preg_match('#^public_html/reticulum/(lib/)?[^/]+\.php$#', $rel) === 1;

/** Everything the deploy does not own, from a whole-home snapshot. */
$notOwned = static function (array $snap) use ($headCode, $retired): array {
    $owned = [];
    foreach (array_merge(array_keys($headCode), $retired, ['build.json']) as $rel) {
        $owned['public_html/reticulum/' . $rel] = true;
    }
    return array_filter($snap, static fn (string $rel): bool => !isset($owned[$rel])
        && !str_starts_with($rel, 'reticulum-rollback/') && !str_starts_with($rel, 'reticulum-incoming/'), ARRAY_FILTER_USE_KEY);
};

$withoutIncoming = static fn (array $snap): array => array_filter($snap,
    static fn (string $rel): bool => !str_starts_with($rel, 'reticulum-incoming/'), ARRAY_FILTER_USE_KEY);

$describeOps = static fn (array $ops): string => implode('; ', array_map(
    static fn (array $o): string => "#{$o['op']} {$o['kind']} " . substr($o['detail'], 0, 60), $ops)) ?: 'none';

// ── (a) a good ref ───────────────────────────────────────────────────────
echo "(a) a good ref goes live in one command per node, after every node has linted it\n";
$before = [];
foreach ($nodes as $name => $home) {
    $resetNode($home);
    $before[$name] = snapshot($home);
}
[$code, $out, $log] = $deploy('HEAD');
check('the deploy of HEAD to both nodes exits 0, verified', $code === 0 && str_contains($out, 'every node matches'), $out);
check('no host outside .invalid was asked for, and no other password', $log['refused'] === [], implode('; ', $log['refused']));

$removeSet = array_values(array_diff($retired, array_keys($headCode)));
$announced = preg_match('/retiring, where present: (.+)$/m', $out, $m) ? preg_split('/\s+/', trim($m[1])) : [];
sort($announced);
$expectedRemovals = $removeSet;
sort($expectedRemovals);
check('deploy.sh retires exactly the RETIRED files HEAD lacks' . ($removeSet === [] ? ' (none: RETIRED lists nothing HEAD lacks)' : ''),
    $announced === $expectedRemovals, 'it said: ' . (implode(' ', $announced) ?: 'nothing') . '; expected: ' . (implode(' ', $expectedRemovals) ?: 'nothing'));
$firstLive = null;
foreach ($log['ops'] as $o) {
    if ($o['changed']) {
        $firstLive = $firstLive === null ? $o['op'] : min($firstLive, $o['op']);
    }
}
$incomingLintOps = [];
foreach ($nodes as $name => $home) {
    foreach ($log['lints'] as $l) {
        if ($l['node'] === $name && $l['pwd'] === "$home/reticulum-incoming") {
            $incomingLintOps[$name][$l['file']] = $l['op'];
        }
    }
}
check('nothing went live on any node until both had linted the ref in ~/reticulum-incoming',
    count($incomingLintOps) === count($nodes) && $firstLive !== null
    && max(array_merge(...array_values(array_map('array_values', $incomingLintOps)))) < $firstLive,
    'first live change: #' . ($firstLive ?? '-') . ', incoming lints: ' . json_encode(array_map('array_values', $incomingLintOps)));

foreach ($nodes as $name => $home) {
    $live = "$home/public_html/reticulum";
    $after = snapshot($home);
    $nodeOps = array_values(array_filter($log['ops'], static fn (array $o): bool => $o['node'] === $name));

    $phpUploads = array_values(array_filter($nodeOps, static fn (array $o): bool => $o['kind'] === 'scp'
        && preg_match('/files=.*\.php\b/', $o['detail']) === 1));
    check("$name: every php upload went to ~/reticulum-incoming, none into the live directory",
        $phpUploads !== [] && array_filter($phpUploads, static fn (array $o): bool => !str_starts_with($o['detail'], 'dest=reticulum-incoming/')) === [],
        $describeOps($phpUploads));

    $lintedFiles = array_keys($incomingLintOps[$name] ?? []);
    sort($lintedFiles);
    $codeFiles = array_keys($headCode);
    sort($codeFiles);
    check("$name: the node's php -l ran on every file of the ref before it went live", $lintedFiles === $codeFiles,
        'linted ' . count($lintedFiles) . ' of ' . count($codeFiles));

    // The live lint after the swap meets the php files the node keeps, so
    // they are linted before anything goes live too; the files the swap
    // removes are not (the last RETIRED one does not parse).
    $nodeKept = [];
    foreach (array_keys($before[$name]) as $rel) {
        $short = substr($rel, strlen('public_html/reticulum/'));
        if ($isLiveCode($rel) && !isset($headCode[$short]) && !in_array($short, $removeSet, true)) {
            $nodeKept[] = $short;
        }
    }
    sort($nodeKept);
    $keptLinted = array_values(array_unique(array_column(array_filter($log['lints'], static fn (array $l): bool => $l['node'] === $name
        && $l['pwd'] === "$home/public_html/reticulum" && $firstLive !== null && $l['op'] < $firstLive), 'file')));
    sort($keptLinted);
    check("$name: ...and on every php file the node keeps that the swap leaves live, not on the ones it removes",
        $keptLinted === $nodeKept, 'linted: ' . implode(', ', $keptLinted) . '; expected: ' . implode(', ', $nodeKept));

    $changing = array_values(array_filter($nodeOps, static fn (array $o): bool => $o['changed']));
    check("$name: exactly one remote command changed the live directory, an ssh (the swap)",
        count($changing) === 1 && $changing[0]['kind'] === 'ssh', $describeOps($changing));

    $swapOp = $changing[0]['op'] ?? -1;
    $swapMvs = array_values(array_filter($log['mvs'], static fn (array $m): bool => $m['op'] === $swapOp));
    $unknownThroughout = $changing !== [] && ($changing[0]['stamp_before'] === NULL_STAMP
        || ($swapMvs !== [] && array_filter($swapMvs, static fn (array $m): bool => $m['stamp'] !== NULL_STAMP) === []));
    check("$name: the stamp said \"unknown\" from before the first file went live", $unknownThroughout,
        'stamp before: ' . ($changing[0]['stamp_before'] ?? '-') . ', at the renames: ' . implode(' ', array_unique(array_column($swapMvs, 'stamp'))));
    check("$name: ...every file went live by a rename out of ~/reticulum-incoming, lib/ before the entry points",
        count($swapMvs) === count($headCode) && array_filter($swapMvs, static fn (array $m): bool => !within($m['src'], "$home/reticulum-incoming")
            || !within($m['dst'], $live)) === []
        && max(array_keys(array_filter($swapMvs, static fn (array $m): bool => str_starts_with($m['dst'], "$live/lib/"))) ?: [-1])
            < min(array_keys(array_filter($swapMvs, static fn (array $m): bool => !str_starts_with($m['dst'], "$live/lib/"))) ?: [PHP_INT_MAX]),
        count($swapMvs) . ' renames for ' . count($headCode) . ' files');

    $mismatched = [];
    foreach ($headCode as $rel => $content) {
        if (@file_get_contents("$live/$rel") !== $content) {
            $mismatched[] = $rel;
        }
    }
    check("$name: the live code is the ref's, byte for byte", $mismatched === [], implode(', ', $mismatched));
    check("$name: ...and the node names HEAD once verified", stampCommit($live) === $head, (string) stampCommit($live));

    $stillThere = array_values(array_filter($removeSet, static fn (string $rel): bool => file_exists("$live/$rel")));
    check("$name: the RETIRED files are gone from the live directory" . ($removeSet === [] ? ' (RETIRED lists nothing to remove)' : ''),
        $stillThere === [], implode(', ', $stillThere));

    $notHeld = [];
    foreach ($before[$name] as $rel => $hash) {
        if ($isLiveCode($rel) && @md5_file("$home/reticulum-rollback/" . substr($rel, strlen('public_html/reticulum/'))) !== $hash) {
            $notHeld[] = $rel;
        }
    }
    check("$name: ~/reticulum-rollback holds the whole previous tree, retired files included", $notHeld === [], implode(', ', $notHeld));
    check("$name: ...and the previous stamp", trim((string) @file_get_contents("$home/reticulum-rollback/build.json")) === $oldStampJson);

    $kept = $notOwned($before[$name]);
    check("$name: config, var/, the node's own files and everything beside the live directory survive",
        $kept !== [] && array_intersect_assoc($kept, $after) === $kept, snapshotDiff($kept, $after));

    $badRm = array_values(array_filter($log['rms'], static fn (array $r): bool => $r['node'] === $name
        && !within($r['path'], "$home/reticulum-incoming") && !within($r['path'], "$home/reticulum-rollback")
        && !in_array($r['path'], array_map(static fn (string $rel): string => "$live/$rel", $removeSet), true)));
    check("$name: nothing was removed but RETIRED files and the deploy's own two directories",
        $badRm === [], implode(', ', array_column($badRm, 'path')));

    check("$name: ~/reticulum-incoming was made afresh: nothing left there earlier was kept, or went live",
        !file_exists("$home/reticulum-incoming/stale.php") && !file_exists("$live/stale.php") && !file_exists("$live/lib/stale_lib.php"));

    $vias = array_unique(array_column($nodeOps, 'via'));
    $expectVia = $name === 'retichat' ? 'sshpass' : 'key';
    check("$name: every remote command went through " . ($expectVia === 'sshpass' ? 'sshpass, with the fake password' : 'key auth with BatchMode'),
        $vias === [$expectVia] && ($expectVia === 'sshpass' || array_filter($nodeOps, static fn (array $o): bool => !$o['batch']) === []),
        implode(',', $vias));
}

// ── (b) a ref with a syntax error ────────────────────────────────────────
echo "(b) a ref with a syntax error changes nothing on any node\n";
$brokenFile = array_values(array_filter(array_keys($headCode), static fn (string $rel): bool => str_starts_with($rel, 'lib/')))[0];
$broken = $commitOnHead(["php/src/$brokenFile" => $headCode[$brokenFile] . "\nfunction (\n"], 'deploy test: a syntax error');
foreach ($nodes as $name => $home) {
    $resetNode($home);
    $before[$name] = snapshot($home);
}
[$code, $out, $log] = $deploy($broken);
check('the deploy exits non-zero, saying the ref does not parse, before any verification',
    $code !== 0 && str_contains($out, 'does not parse') && !str_contains($out, 'Verifying deployed bytes'), $out);
foreach ($nodes as $name => $home) {
    $after = snapshot($home);
    check("$name: nothing outside ~/reticulum-incoming changed: live code, stamp, rollback copy",
        $withoutIncoming($after) === $withoutIncoming($before[$name]), snapshotDiff($withoutIncoming($before[$name]), $withoutIncoming($after)));
    check("$name: ...the node still names the commit it runs", stampCommit("$home/public_html/reticulum") === $parent,
        (string) stampCommit("$home/public_html/reticulum"));
    check("$name: ...and no remote command touched the live directory",
        array_filter($log['ops'], static fn (array $o): bool => $o['node'] === $name && $o['changed']) === []);
}

// ── (c) a ref that one node rejects ──────────────────────────────────────
echo "(c) a ref that does not parse on one node goes live on neither\n";
foreach ($nodes as $name => $home) {
    $resetNode($home);
    $before[$name] = snapshot($home);
}
[$code, $out, $log] = $deploy('HEAD', '', ['STUB_LINT_FAIL_NODE' => 'selectiv']);
check('the deploy exits non-zero: selectiv\'s php rejects it', $code !== 0 && preg_match('/selectivesubconscious\.com: .*does not parse/', $out) === 1, $out);
foreach ($nodes as $name => $home) {
    check("$name: nothing outside ~/reticulum-incoming changed",
        $withoutIncoming(snapshot($home)) === $withoutIncoming($before[$name]),
        snapshotDiff($withoutIncoming($before[$name]), $withoutIncoming(snapshot($home))));
}

// ── (d) a failure after the swap, and the rollback command ──────────────
echo "(d) after a failure past the swap, the printed rollback command restores the previous tree\n";
$home = $nodes['retichat'];
$live = "$home/public_html/reticulum";
$resetNode($home);
$beforeD = snapshot($home);
[$code, $out, $log] = $deploy('HEAD', 'retichat', ['STUB_LIVE_LINT_FAIL_NODE' => 'retichat']);
check('a live lint failure exits non-zero, before verification',
    $code !== 0 && str_contains($out, 'deployed code does not parse') && !str_contains($out, 'Verifying deployed bytes'), $out);
check('...the node says "unknown", not the old commit and not HEAD', stampCommit($live) === null, (string) stampCommit($live));
$hint = preg_match('/roll back with: (.+)$/m', $out, $m) ? trim($m[1]) : '';
check('...it prints a rollback command', $hint !== '', $out);
check('...which names the password variable, not the password', !str_contains($out, FAKE_PASS), $hint);
[$rbCode, $rbOut] = $isolated(implode(' ', array_map('esc', ['bash', $wrapper, $fakeEnv, '-c', $hint])));
$afterRb = snapshot($home);
$notRestored = [];
foreach ($beforeD as $rel => $hash) {
    if (($isLiveCode($rel) || $rel === 'public_html/reticulum/build.json') && ($afterRb[$rel] ?? null) !== $hash) {
        $notRestored[] = $rel;
    }
}
check('running it restores every previous file, retired files and the old stamp included',
    $rbCode === 0 && $notRestored === [], "exit $rbCode; " . ($notRestored === [] ? $rbOut : implode(', ', $notRestored)));
check('...and leaves config, var/ and the node\'s own files as they were',
    array_intersect_assoc($notOwned($beforeD), $afterRb) === $notOwned($beforeD), snapshotDiff($notOwned($beforeD), $afterRb));

// ── (e) an older ref that still ships a RETIRED file ─────────────────────
echo "(e) a ref that ships a RETIRED file itself keeps it\n";
if ($retired === []) {
    echo "  n/a  RETIRED is empty\n";
} else {
    $shipped = $retired[0];
    $shippedContent = "<?php\n// $shipped, shipped again by an older ref\n";
    $older = $commitOnHead(["php/src/$shipped" => $shippedContent], 'deploy test: a ref that still has a retired file');
    $resetNode($home);
    [$code, $out, $log] = $deploy($older, 'retichat');
    check('the deploy exits 0', $code === 0, $out);
    check("...$shipped is live, with that ref's content", @file_get_contents("$live/$shipped") === $shippedContent);
    $others = array_values(array_filter(array_slice($retired, 1), static fn (string $rel): bool => file_exists("$live/$rel")));
    check('...and the other RETIRED files are gone', $others === [], implode(', ', $others));
}

// ── (f) a rollback copy that lost a file ─────────────────────────────────
echo "(f) a rollback copy that lacks a live file stops the swap before anything changes\n";
$lost = $retired[0] ?? 'index.php';
$resetNode($home);
$beforeG = snapshot($home);
[$code, $out, $log] = $deploy('HEAD', 'retichat', ['STUB_CP_DROP' => $lost]);
check("the deploy exits non-zero, saying ~/reticulum-rollback does not hold $lost and nothing changed",
    $code !== 0 && str_contains($out, "does not hold $lost; nothing changed"), $out);
$afterG = snapshot($home);
$liveOnly = static fn (array $snap): array => array_filter($snap,
    static fn (string $rel): bool => str_starts_with($rel, 'public_html/'), ARRAY_FILTER_USE_KEY);
check('...the live directory is untouched: code, RETIRED files and stamp', $liveOnly($afterG) === $liveOnly($beforeG),
    snapshotDiff($liveOnly($beforeG), $liveOnly($afterG)));

// ── (g) a php file the node keeps that does not parse ────────────────────
echo "(g) a php file the node keeps that does not parse stops the deploy before anything goes live\n";
foreach ($nodes as $name => $nodeHome) {
    $resetNode($nodeHome);
}
put($nodes['retichat'] . '/public_html/reticulum/_test.php', "<?php\n// the node's own scratch file, broken\nfunction (\n");
foreach ($nodes as $name => $nodeHome) {
    $before[$name] = snapshot($nodeHome);
}
[$code, $out, $log] = $deploy('HEAD');
check('the deploy exits non-zero, naming the node\'s _test.php, before any verification',
    $code !== 0 && preg_match('/on the node, not in [0-9a-f]+: \S*_test\.php: php -l exited/', $out) === 1
    && str_contains($out, 'nothing went live on any node') && !str_contains($out, 'Verifying deployed bytes'), $out);
foreach ($nodes as $name => $nodeHome) {
    check("$name: nothing outside ~/reticulum-incoming changed: live code, stamp, rollback copy",
        $withoutIncoming(snapshot($nodeHome)) === $withoutIncoming($before[$name]),
        snapshotDiff($withoutIncoming($before[$name]), $withoutIncoming(snapshot($nodeHome))));
}

// ── (h) a rename that fails part way ─────────────────────────────────────
echo "(h) a swap that fails part way, on a full disk, puts the previous release back in the same command\n";
$added = 'lib/added_by_this_release.php';
$withAdded = $commitOnHead(["php/src/$added" => "<?php\n// new in this release\n"], 'deploy test: a release that adds a file');
$resetNode($home);
$beforeH = snapshot($home);
[$code, $out, $log] = $deploy($withAdded, 'retichat', ['STUB_MV_FAIL' => 'index.php']);
check('the deploy exits non-zero, saying the swap failed and was undone, before verification',
    $code !== 0 && str_contains($out, 'swap failed and was undone') && !str_contains($out, 'Verifying deployed bytes'), $out);
check('...with no rollback for a person to run', !str_contains($out, 'roll back with'), $out);
$swapOps = array_values(array_filter($log['ops'], static fn (array $o): bool => str_contains($o['detail'], 'mv -f')));
$swapMvs = array_values(array_filter($log['mvs'], static fn (array $m): bool => $m['op'] === ($swapOps[0]['op'] ?? -1)));
$addedIn = array_filter($swapMvs, static fn (array $m): bool => $m['src'] === "$home/reticulum-incoming/$added" && $m['dst'] === "$live/$added");
$addedOut = array_filter($swapMvs, static fn (array $m): bool => $m['src'] === "$live/$added" && $m['dst'] === "$home/reticulum-incoming/$added");
$putBack = array_filter($swapMvs, static fn (array $m): bool => within($m['src'], "$home/reticulum-rollback") && within($m['dst'], $live));
check('...one command renamed lib/ in, the new file included, failed at the entry point, and renamed it all back out of ~/reticulum-rollback',
    count($swapOps) === 1 && $addedIn !== [] && $addedOut !== [] && count($putBack) > 1
    && array_filter($log['ops'], static fn (array $o): bool => $o['changed']) === [],
    count($swapOps) . ' swap command(s), ' . count($swapMvs) . ' renames, ' . count($putBack) . ' put back');
check('...the live directory is exactly as before: code, RETIRED files, stamp, the node\'s own files',
    $liveOnly(snapshot($home)) === $liveOnly($beforeH), snapshotDiff($liveOnly($beforeH), $liveOnly(snapshot($home))));
check('...the file the release added went back to ~/reticulum-incoming, not deleted',
    !file_exists("$live/$added") && is_file("$home/reticulum-incoming/$added"));
check('...no rm touched the live directory', array_filter($log['rms'], static fn (array $r): bool => within($r['path'], $live)) === [],
    implode(', ', array_column($log['rms'], 'path')));
check('...all of it with the disk full from the failed rename on (the stand-in\'s cp refused from then)',
    is_file($stubLog . '.full'));

// ── (i) the connection drops part way through the swap ──────────────────
echo "(i) a connection that drops part way through the swap does not stop it there\n";
$resetNode($home);
[$code, $out, $log] = $deploy('HEAD', 'retichat', ['STUB_MV_HUP' => 'index.php']);
check('the deploy exits non-zero with no answer from the node, printing the rollback command, before verification',
    $code !== 0 && str_contains($out, 'no answer from the node') && str_contains($out, 'roll back with')
    && !str_contains($out, 'Verifying deployed bytes'), $out);
$mismatched = array_keys(array_filter($headCode, static fn (string $content, string $rel): bool => @file_get_contents("$live/$rel") !== $content, ARRAY_FILTER_USE_BOTH));
check('...the node, hung up on, finished the swap: the live code is the ref\'s, every file', $mismatched === [],
    count($mismatched) . ' of ' . count($headCode) . ' not the ref\'s: ' . implode(', ', array_slice($mismatched, 0, 5)));
$stillThere = array_values(array_filter($removeSet, static fn (string $rel): bool => file_exists("$live/$rel")));
check('...the RETIRED files are gone', $stillThere === [], implode(', ', $stillThere));
check('...and the stamp says "unknown"', stampCommit($live) === null, (string) stampCommit($live));

// ── (j) a RETIRED list naming a file the node owns ───────────────────────
echo "(j) deploy.sh refuses a RETIRED list that names a file the node owns\n";
$underTest = (string) file_get_contents($deploySh);
foreach (['config.php', '_test.php'] as $owned) {
    if (preg_match('/^RETIRED=\(/m', $underTest) !== 1) {
        check("RETIRED listing $owned is refused", false, 'the deploy.sh under test has no RETIRED list');
        continue;
    }
    $variant = $clone . '/deploy-retiring-' . $owned . '.sh';
    file_put_contents($variant, preg_replace('/^RETIRED=\(/m', 'RETIRED=(' . $owned . ' ', $underTest, 1));
    chmod($variant, 0755);
    @unlink($stubLog);
    [$code, $out] = $isolated(implode(' ', array_map('esc', ['bash', $wrapper, $fakeEnv, $variant, 'HEAD'])));
    check("RETIRED listing $owned is refused before any node is contacted",
        $code !== 0 && str_contains($out, "RETIRED lists $owned") && !is_file($stubLog), $out);
}

// ── (k) the guards ───────────────────────────────────────────────────────
echo "(k) the stand-ins and the wrapper refuse anything that is not the sandbox\n";
@unlink($stubLog);
[$code, $out] = $isolated(esc("$bin/ssh") . ' -o BatchMode=yes stub@guard-test.example ' . esc('echo ran-on-the-node'));
check('the ssh stand-in refuses a host outside .invalid, running nothing',
    $code === 255 && !str_contains($out, 'ran-on-the-node') && str_contains((string) @file_get_contents($stubLog), 'REFUSED'), $out);
@unlink($stubLog);
[$code, $out] = $isolated(esc("$bin/scp") . ' ' . esc($fakeEnv) . ' stub@guard-test.example:~/x');
check('the scp stand-in refuses one too', $code === 255 && str_contains((string) @file_get_contents($stubLog), 'REFUSED'), $out);
[$code, $out] = $isolated('env SSHPASS=some-other-password ' . esc("$bin/sshpass") . ' -e ssh stub@retichat.invalid ' . esc('echo ran-on-the-node'));
check('the sshpass stand-in refuses any password but the fake one', $code === 255 && !str_contains($out, 'ran-on-the-node'), $out);
@unlink($stubLog);
[$code, $out] = $isolated('curl -s https://guard-test.example/health');
check('curl on the sandbox PATH is a stand-in that refuses', $code === 255 && str_contains((string) @file_get_contents($stubLog), 'REFUSED'), $out);
$guardEnv = $tmp . '/guard.env';
file_put_contents($guardEnv, "export RETICHAT_SSH_HOST=\"stub@guard-test.example\"\nexport SELECTIV_SSH_HOST=\"stub@selectiv.invalid\"\n");
@unlink($stubLog);
[$code, $out] = $isolated(implode(' ', array_map('esc', ['bash', $wrapper, $guardEnv, $clone . '/deploy.sh', 'HEAD'])));
check('the wrapper refuses a deploy.env naming a host outside .invalid, and deploy.sh never starts',
    $code === 97 && !str_contains($out, 'Checking working tree') && !is_file($stubLog), $out);
[$code, $out] = $isolated(implode(' ', array_map('esc', ['bash', $wrapper, '/dev/null', $clone . '/deploy.sh', 'HEAD'])));
check('the wrapper refuses a deploy.env outside the sandbox', $code === 97 && !str_contains($out, 'Checking working tree'), $out);

exec('rm -rf ' . esc($tmp));

echo "\n$pass passed, $fail failed\n";
exit($fail === 0 ? 0 : 1);
