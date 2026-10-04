<?php
/**
 * The PHP node starts no process except the storage reclaim.
 *
 * James decided on 2026-10-04 that the only process the PHP node may start is
 * the detached `php index.php reclaim` of
 * RequestStorageBudgetTrait::spawnDetachedStorageReclaim(). Until that day it
 * also ran `exec("php index.php wake-event <id> &")` from every request's
 * epilogue (spawnDetachedWakeRunner) and proc_open() for "command" wake
 * profiles (CommandWakeProvider), both for the wake_url path that anyone
 * could arm by registering with metadata.wake_url
 * (tests/wake_url_path_removed_test.php).
 *
 * This reads every .php file under php/src with PHP's own tokenizer and
 * lists each place that can start a process: a call to exec, shell_exec,
 * system, passthru, proc_open, popen, pcntl_exec or pcntl_fork (method calls
 * such as $pdo->exec() and Database::exec(), declarations, and curl_exec are
 * not calls to those functions); a backtick shell command; and one of those
 * names as a string, the way a callable is passed (function_exists('exec')
 * is allowed, it only asks). The list must be exactly one entry: exec in
 * spawnDetachedStorageReclaim(). The scanner is first run on samples, so a
 * scanner that finds nothing cannot pass.
 *
 * On d4ceda7 this fails: it also finds exec in spawnDetachedWakeRunner()
 * and proc_open in CommandWakeProvider::dispatch().
 *
 * Run: php php/tests/only_storage_reclaim_starts_a_process_test.php
 * SPAWN_SCAN_DIR points it at another php/src, for mutation checks.
 */
declare(strict_types=1);

const PROCESS_FUNCTIONS = ['exec', 'shell_exec', 'system', 'passthru', 'proc_open', 'popen', 'pcntl_exec', 'pcntl_fork'];

/**
 * @return list<array{line: int, what: string, function: string}> every place
 *         in $code that can start a process, with the named function it is in
 */
function processStarts(string $code): array
{
    $tokens = token_get_all($code);
    $significant = [];
    foreach ($tokens as $token) {
        if (is_array($token) && in_array($token[0], [T_WHITESPACE, T_COMMENT, T_DOC_COMMENT], true)) {
            continue;
        }
        $significant[] = $token;
    }

    $found = [];
    $function = '(file scope)';
    $line = 1;
    $inBackticks = false;
    $count = count($significant);
    for ($i = 0; $i < $count; $i++) {
        $token = $significant[$i];
        if (is_array($token)) {
            $line = $token[2];
        }
        $previous = $significant[$i - 1] ?? null;
        $next = $significant[$i + 1] ?? null;

        // The named function or method this token is in. Closures have no
        // name and stay attributed to the function around them.
        if (is_array($token) && $token[0] === T_FUNCTION && is_array($next) && $next[0] === T_STRING) {
            $function = $next[1];
            continue;
        }

        if ($token === '`') {
            // One command per opening backtick; the closing one ends it.
            if (!$inBackticks) {
                $found[] = ['line' => $line, 'what' => 'backtick shell command', 'function' => $function];
            }
            $inBackticks = !$inBackticks;
            continue;
        }

        if (!is_array($token)) {
            continue;
        }

        if (in_array($token[0], [T_STRING, T_NAME_FULLY_QUALIFIED, T_NAME_QUALIFIED], true)) {
            $parts = explode('\\', $token[1]);
            $name = strtolower((string) end($parts));
            if (!in_array($name, PROCESS_FUNCTIONS, true) || $next !== '(') {
                continue;
            }
            $before = is_array($previous) ? $previous[0] : $previous;
            if (in_array($before, [T_OBJECT_OPERATOR, T_NULLSAFE_OBJECT_OPERATOR, T_DOUBLE_COLON, T_FUNCTION, T_NEW, T_CONST], true)) {
                continue;
            }
            $found[] = ['line' => $line, 'what' => $name . '()', 'function' => $function];
            continue;
        }

        if ($token[0] === T_CONSTANT_ENCAPSED_STRING) {
            $name = strtolower(substr($token[1], 1, -1));
            if (!in_array($name, PROCESS_FUNCTIONS, true)) {
                continue;
            }
            $callee = $significant[$i - 2] ?? null;
            if ($previous === '(' && is_array($callee) && strtolower($callee[1]) === 'function_exists') {
                continue;
            }
            $found[] = ['line' => $line, 'what' => "'{$name}' as a string", 'function' => $function];
        }
    }

    return $found;
}

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

$describe = static fn (array $found): string => implode('; ', array_map(
    static fn (array $f): string => "{$f['what']} in {$f['function']}() line {$f['line']}",
    $found
));

echo "(a) the scanner finds what starts a process, and nothing else\n";
$samples = [
    'exec() in a method' => ['<?php class A { function f() { exec("ls"); } }', 1],
    'a fully qualified \\proc_open()' => ['<?php function g() { $p = \\proc_open(["ls"], [], $pipes); }', 1],
    'popen, shell_exec, system and passthru' => ['<?php popen("ls", "r"); shell_exec("ls"); System("ls"); passthru("ls");', 4],
    'pcntl_fork and pcntl_exec' => ['<?php $pid = pcntl_fork(); pcntl_exec("/bin/ls");', 2],
    'two backtick commands' => ['<?php $x = `ls`; $y = `ls {$x}`;', 2],
    'a callable string' => ['<?php call_user_func(\'exec\', "ls"); $f = "proc_open";', 2],
    'PDO, Database and curl calls of the same name' => ['<?php $pdo->exec("x"); $db?->exec("x"); Database::exec("x"); curl_exec($c);', 0],
    'declarations and a function_exists() check' => ['<?php class B { public function exec(string $s) {} } if (function_exists(\'exec\')) {}', 0],
    'names in comments and longer strings' => ["<?php // exec(\"ls\")\n/* proc_open() */ \$s = 'exec this';", 0],
];
foreach ($samples as $label => [$code, $expected]) {
    $found = processStarts($code);
    check("$label: $expected found", count($found) === $expected, $describe($found));
}

echo "(b) php/src starts one process: the storage reclaim\n";
$srcDir = getenv('SPAWN_SCAN_DIR') ?: dirname(__DIR__) . '/src';
$files = [];
$iterator = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($srcDir, FilesystemIterator::SKIP_DOTS));
foreach ($iterator as $file) {
    if ($file->isFile() && strtolower($file->getExtension()) === 'php') {
        $files[] = $file->getPathname();
    }
}
sort($files);
check('php/src has php files to scan', count($files) >= 10, (string) count($files));

$all = [];
foreach ($files as $path) {
    foreach (processStarts((string) file_get_contents($path)) as $found) {
        $found['file'] = substr($path, strlen($srcDir) + 1);
        $all[] = $found;
    }
}
$listing = implode('; ', array_map(
    static fn (array $f): string => "{$f['file']}:{$f['line']} {$f['what']} in {$f['function']}()",
    $all
));
check('exactly one place in php/src can start a process', count($all) === 1, $listing);
$reclaim = array_values(array_filter(
    $all,
    static fn (array $f): bool => $f['file'] === 'lib/request_storage_budget_trait.php'
        && $f['what'] === 'exec()'
        && $f['function'] === 'spawnDetachedStorageReclaim'
));
check('it is exec() in RequestStorageBudgetTrait::spawnDetachedStorageReclaim()', count($reclaim) === 1, $listing);
$reclaimSource = (string) @file_get_contents($srcDir . '/lib/request_storage_budget_trait.php');
check('and what it starts is `php index.php reclaim`, detached',
    preg_match("/'%s %s reclaim > \\/dev\\/null 2>&1 &'/", $reclaimSource) === 1);

echo "\n$pass passed, $fail failed\n";
exit($fail === 0 ? 0 : 1);
