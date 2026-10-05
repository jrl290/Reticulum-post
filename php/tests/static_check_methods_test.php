<?php
/**
 * static_check_methods.php resolves every call on the class it runs in.
 *
 * WHAT THIS EXISTS TO PREVENT
 * ===========================
 * On b6c7809, live on both nodes, RequestPhpWakeTrait (used by Storage)
 * called $this->log(), which only RequestHttpApiHelperTrait (used by HttpApi)
 * defines. The request whose prelude re-registered a dead peering session
 * answered 500 with "Call to undefined method ReticulumPhp\Storage::log()".
 * static_check_methods.php put every file into one body, found a log() in
 * one of them and printed "Undefined: 0". This test keeps the checker honest
 * on fixtures it can be wrong about, and on php/src itself.
 *
 *   (a) b6c7809's shape, cut down to the four pieces that made it: the check
 *       reports Storage's $this->log() at its line and fails; with the call
 *       made error_log() it passes.
 *   (b) What must resolve does, and nothing in a comment, a string or a
 *       heredoc is a call: sibling traits, a trait's own trait, an `as`
 *       alias, self:: and static::, parent:: on a built-in parent, typed
 *       properties ($this->storage->, $this->db->), Name::m(), [$this, 'm'],
 *       a first-class callable. Its warnings name a trait no class uses and
 *       a private method nothing calls, and not one a sibling trait calls
 *       (b6c7809's check listed 114 private methods as unused, 109 of them
 *       called).
 *   (c) Every kind of call that does not resolve is reported, each once.
 *   (d) On php/src the check passes, and the methods it gives each class are
 *       the ones PHP reflects with index.php loaded.
 *
 * Run: php php/tests/static_check_methods_test.php
 */
declare(strict_types=1);

$checker = __DIR__ . '/static_check_methods.php';

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
        echo "  FAIL $label" . ($detail !== '' ? "\n       " . str_replace("\n", "\n       ", $detail) : '') . "\n";
    }
}

/** Write a fixture tree (relative path => source) and return its directory. */
function fixture(array $files): string
{
    $dir = sys_get_temp_dir() . '/static-check-fixture-' . bin2hex(random_bytes(4));
    foreach ($files as $path => $code) {
        @mkdir(dirname($dir . '/' . $path), 0775, true);
        file_put_contents($dir . '/' . $path, $code);
    }
    return $dir;
}

/** @return array{int, string} the checker's exit code and output */
function runCheck(string $checker, string $dir, array $flags = []): array
{
    $command = array_merge([PHP_BINARY, $checker], $flags, [$dir]);
    $proc = proc_open($command, [1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes);
    $out = stream_get_contents($pipes[1]) . stream_get_contents($pipes[2]);
    fclose($pipes[1]);
    fclose($pipes[2]);
    return [proc_close($proc), $out];
}

/** The 1-based line of the first occurrence of $needle in $code. */
function lineOf(string $code, string $needle): int
{
    $at = strpos($code, $needle);
    return $at === false ? -1 : substr_count($code, "\n", 0, $at) + 1;
}

function undefinedLines(string $out): array
{
    preg_match_all('/^UNDEFINED: (.*)$/m', $out, $m);
    return $m[1];
}

// ─── (a) b6c7809's shape ───────────────────────────────────────────────────
echo "(a) b6c7809: a trait of Storage calls log(), which only HttpApi has\n";

$index = <<<'PHP'
<?php

declare(strict_types=1);

namespace ReticulumPhp;

use PDO;

final class Storage
{
    use RequestMaintenanceTrait;
    use RequestPhpWakeTrait;

    private PDO $db;
}

final class HttpApi
{
    use RequestHttpApiHelperTrait;

    public function __construct(private readonly Storage $storage)
    {
    }

    public function handle(): void
    {
        try {
            $this->storage->runMaintenance();
        } catch (\Throwable $error) {
            $this->log('error', 'Unhandled HTTP exception: ' . $error->getMessage());
        }
    }
}
PHP;
$maintenance = <<<'PHP'
<?php

declare(strict_types=1);

namespace ReticulumPhp;

trait RequestMaintenanceTrait
{
    public function runMaintenance(): array
    {
        $summary = [];
        $this->ensureConfiguredPeerSessions(time(), $summary);
        return $summary;
    }
}
PHP;
$helper = <<<'PHP'
<?php

declare(strict_types=1);

namespace ReticulumPhp;

trait RequestHttpApiHelperTrait
{
    private function log(string $level, string $message): void
    {
        error_log("[{$level}] {$message}");
    }
}
PHP;
$wake = static fn (string $logCall): string => <<<PHP
<?php

declare(strict_types=1);

namespace ReticulumPhp;

trait RequestPhpWakeTrait
{
    public function ensureConfiguredPeerSessions(int \$now, array &\$summary): void
    {
        \$result = \$this->connectToPeer('https://peer.example');
        \$summary['peer_sessions_healed'][] = \$result;
        {$logCall}
    }

    private function connectToPeer(string \$exchangeUrl): array
    {
        return ['status' => 'connected', 'peer_url' => \$exchangeUrl];
    }
}
PHP;

$broken = $wake("\$this->log('warning', sprintf('[peer] session to %s was dead (%s) — re-registered: %s', 'https://peer.example', 'no row', \$result['status']));");
$dir = fixture([
    'index.php' => $index,
    'lib/request_maintenance_trait.php' => $maintenance,
    'lib/request_http_api_helper_trait.php' => $helper,
    'lib/request_php_wake_trait.php' => $broken,
]);
[$code, $out] = runCheck($checker, $dir);
$expected = sprintf(
    'ReticulumPhp\Storage has no method log(), called as $this->log() at lib/request_php_wake_trait.php:%d (trait RequestPhpWakeTrait); defined only in RequestHttpApiHelperTrait (used by HttpApi)',
    lineOf($broken, '$this->log(')
);
check('the check reports Storage\'s $this->log(), at its line, and says where log() is', undefinedLines($out) === [$expected], $out);
check('and fails: exit 1 and "Undefined: 1", which deploy.sh refuses', $code === 1 && str_contains($out, 'Undefined: 1 '), $out);

file_put_contents($dir . '/lib/request_php_wake_trait.php', $wake("error_log(sprintf('[peer] session to %s was dead (%s) — re-registered: %s', 'https://peer.example', 'no row', \$result['status']));"));
[$code, $out] = runCheck($checker, $dir);
check('with the call made error_log() it passes: exit 0 and "Undefined: 0"', $code === 0 && str_contains($out, 'Undefined: 0 '), $out);
exec('rm -rf ' . escapeshellarg($dir));

// ─── (b) What must resolve ─────────────────────────────────────────────────
echo "(b) what must resolve does; comments, strings and heredocs are not code\n";

$dir = fixture([
    'index.php' => <<<'PHP'
<?php

declare(strict_types=1);

namespace ReticulumPhp;

use PDO;
use RuntimeException;

final class ApiError extends RuntimeException
{
    public function __construct(string $message, public readonly int $statusCode = 500)
    {
        parent::__construct($message);
    }
}

final class Database
{
    public static function quoteTable(string $name): string
    {
        return '"' . $name . '"';
    }
}

final class Storage
{
    use TraitOne;
    use TraitTwo {
        helper as protected aliasedHelper;
    }

    private PDO $db;

    public function __construct()
    {
        $this->db = new PDO('sqlite::memory:');
    }

    public function publicEntry(): int
    {
        return $this->one() + $this->aliasedHelper() + count([$this, 'fromTraitThree']);
    }
}

final class HttpApi
{
    public function __construct(private readonly Storage $storage)
    {
    }

    public function handle(): string
    {
        // $this->notACall() in a comment is not a call
        $text = '$this->notACallEither()';
        $page = <<<HTML
<script>function flushStale() { return 1; }</script> {$this->storage->publicEntry()}
HTML;
        $callable = $this->storage->publicEntry(...);
        return $text . $page . Database::quoteTable('x') . (string) $callable();
    }
}
PHP,
    'lib/trait_one.php' => <<<'PHP'
<?php

declare(strict_types=1);

namespace ReticulumPhp;

trait TraitOne
{
    use TraitThree;

    public function one(): int
    {
        return $this->helper() + self::staticHelper() + static::staticHelper() + $this->fromTraitThree();
    }

    private static function staticHelper(): int
    {
        return 1;
    }
}
PHP,
    'lib/trait_two.php' => <<<'PHP'
<?php

declare(strict_types=1);

namespace ReticulumPhp;

trait TraitTwo
{
    private function helper(): int
    {
        return $this->db->prepare('SELECT 1') !== false ? 1 : 0;
    }

    private function neverCalled(): void
    {
    }
}
PHP,
    'lib/trait_three.php' => <<<'PHP'
<?php

declare(strict_types=1);

namespace ReticulumPhp;

trait TraitThree
{
    private function fromTraitThree(): int
    {
        return strlen(Database::quoteTable('t'));
    }
}
PHP,
    'lib/orphan_trait.php' => <<<'PHP'
<?php

declare(strict_types=1);

namespace ReticulumPhp;

trait OrphanTrait
{
    private function lonely(): void
    {
        $this->whateverItLikes();
    }
}
PHP,
]);
[$code, $out] = runCheck($checker, $dir);
check('every call resolves: exit 0 and "Undefined: 0"', $code === 0 && str_contains($out, 'Undefined: 0 ') && undefinedLines($out) === [], $out);
// ApiError 1 (parent::), Storage 3 (two $this->, one [$this, 'm']), HttpApi 3
// (heredoc, first-class callable, Name::), TraitOne 4, TraitTwo 1 ($this->db->),
// TraitThree 1; OrphanTrait's call resolves on no class.
check('all 13 calls were read and resolved, none skipped', preg_match('/^(\d+) calls resolved/m', $out, $m) === 1 && (int) $m[1] === 13, $out);
check('the trait no class uses is named', str_contains($out, 'TRAIT USED BY NO CLASS: ReticulumPhp\OrphanTrait (lib/orphan_trait.php)'), $out);
check('the private method nothing calls is named, and only it (the orphan trait\'s are not listed again)',
    str_contains($out, 'UNUSED: lib/trait_two.php::neverCalled()') && !str_contains($out, '::lonely()')
    && str_contains($out, 'Unused: 2'), $out);
check('a private method a sibling trait calls is not unused', !str_contains($out, '::helper()') && !str_contains($out, '::fromTraitThree()') && !str_contains($out, '::staticHelper()'), $out);
exec('rm -rf ' . escapeshellarg($dir));

// ─── (c) What must not resolve ─────────────────────────────────────────────
echo "(c) every kind of call that does not resolve is reported, each once\n";

$index = <<<'PHP'
<?php

declare(strict_types=1);

namespace ReticulumPhp;

use PDO;
use RuntimeException;

final class ApiError extends RuntimeException
{
    public function __construct(string $message)
    {
        parent::__construct($message);
        parent::noSuchParentMethod();
    }
}

final class Database
{
    private static function privateHelper(): void
    {
    }
}

final class Storage
{
    use StorageTrait;

    private PDO $db;

    private function privateOnStorage(): void
    {
    }
}

final class HttpApi
{
    use HttpApiTrait;

    public function __construct(private readonly Storage $storage)
    {
    }

    public function handle(): void
    {
        $this->storage->privateOnStorage();
        $this->storage->noSuchStorageMethod();
        $page = <<<HTML
<script>function flushStale() {}</script>
HTML;
        $this->flushStale();
    }
}
PHP;
$storageTrait = <<<'PHP'
<?php

declare(strict_types=1);

namespace ReticulumPhp;

trait StorageTrait
{
    abstract private function mustImplement(): void;

    public function run(): void
    {
        $this->log('warning', 'x');
        if (method_exists($this, 'note')) {
            $this->note('moved');
        }
        self::decodeJson('{}');
        static::encodeJson([]);
        array_map([$this, 'mapper'], []);
        $this->db->notAPdoMethod();
        Database::privateHelper();
        Database::noSuchStatic();
        NoSuchClass::make();
    }
}
PHP;
$httpTrait = <<<'PHP'
<?php

declare(strict_types=1);

namespace ReticulumPhp;

trait HttpApiTrait
{
    private function log(string $level, string $message): void
    {
    }

    private function note(string $message): void
    {
    }

    private static function decodeJson(string $json): mixed
    {
        return json_decode($json, true);
    }
}
PHP;
$dir = fixture(['index.php' => $index, 'lib/storage_trait.php' => $storageTrait, 'lib/http_api_trait.php' => $httpTrait]);
[$code, $out] = runCheck($checker, $dir);
$at = static fn (string $file, string $code, string $needle): string => $file . ':' . lineOf($code, $needle);
$expected = [
    'parent::m() the parent lacks' => 'RuntimeException (parent of ReticulumPhp\ApiError) has no method noSuchParentMethod() a child can call, called as parent::noSuchParentMethod() at ' . $at('index.php', $index, 'noSuchParentMethod'),
    'a private method of a typed property' => 'ReticulumPhp\Storage::privateOnStorage() is private, called from ReticulumPhp\HttpApi as $this->storage->privateOnStorage() at ' . $at('index.php', $index, '$this->storage->privateOnStorage'),
    'a method a typed property lacks' => 'ReticulumPhp\Storage has no method noSuchStorageMethod(), called as $this->storage->noSuchStorageMethod() at ' . $at('index.php', $index, 'noSuchStorageMethod'),
    'a method only a heredoc\'s JavaScript "defines"' => 'ReticulumPhp\HttpApi has no method flushStale(), called as $this->flushStale() at ' . $at('index.php', $index, '$this->flushStale'),
    'an abstract method the class does not implement' => 'ReticulumPhp\Storage does not implement abstract mustImplement() declared in ReticulumPhp\StorageTrait (lib/storage_trait.php:' . lineOf($storageTrait, 'mustImplement') . ')',
    '$this->m() that only another class has' => 'ReticulumPhp\Storage has no method log(), called as $this->log() at ' . $at('lib/storage_trait.php', $storageTrait, '$this->log') . ' (trait StorageTrait); defined only in HttpApiTrait (used by HttpApi)',
    'a call behind method_exists()' => 'ReticulumPhp\Storage has no method note(), called as $this->note() at ' . $at('lib/storage_trait.php', $storageTrait, '$this->note') . ' (trait StorageTrait); defined only in HttpApiTrait (used by HttpApi)',
    'self::m() that only another class has' => 'ReticulumPhp\Storage has no method decodeJson(), called as self::decodeJson() at ' . $at('lib/storage_trait.php', $storageTrait, 'self::decodeJson') . ' (trait StorageTrait); defined only in HttpApiTrait (used by HttpApi)',
    'static::m() nothing has' => 'ReticulumPhp\Storage has no method encodeJson(), called as static::encodeJson() at ' . $at('lib/storage_trait.php', $storageTrait, 'static::encodeJson') . ' (trait StorageTrait)',
    '[$this, \'m\'] nothing has' => 'ReticulumPhp\Storage has no method mapper(), called as $this->mapper() at ' . $at('lib/storage_trait.php', $storageTrait, "'mapper'") . ' (trait StorageTrait)',
    'a method PDO lacks, on the PDO-typed $db' => 'PDO has no method notAPdoMethod(), called as $this->db->notAPdoMethod() at ' . $at('lib/storage_trait.php', $storageTrait, 'notAPdoMethod') . ' (trait StorageTrait)',
    'a private static method of another class' => 'ReticulumPhp\Database::privateHelper() is private, called from ReticulumPhp\Storage as Database::privateHelper() at ' . $at('lib/storage_trait.php', $storageTrait, 'Database::privateHelper') . ' (trait StorageTrait)',
    'a static method a class lacks' => 'ReticulumPhp\Database has no method noSuchStatic(), called as Database::noSuchStatic() at ' . $at('lib/storage_trait.php', $storageTrait, 'noSuchStatic') . ' (trait StorageTrait)',
    'a class that does not exist' => 'NoSuchClass::make() at ' . $at('lib/storage_trait.php', $storageTrait, 'NoSuchClass') . ' (trait StorageTrait): class ReticulumPhp\NoSuchClass does not exist',
];
$lines = undefinedLines($out);
foreach ($expected as $label => $line) {
    check($label, count(array_keys($lines, $line, true)) === 1, "expected: {$line}\n--- output ---\n{$out}");
}
check('nothing else is reported, and the check fails', count($lines) === count($expected) && $code === 1 && str_contains($out, 'Undefined: ' . count($expected) . ' '), $out);
exec('rm -rf ' . escapeshellarg($dir));

// ─── (d) php/src ───────────────────────────────────────────────────────────
echo "(d) php/src passes, and each class has the methods PHP gives it\n";

$src = dirname(__DIR__) . '/src';
[$code, $out] = runCheck($checker, $src);
check('the check passes on php/src', $code === 0 && str_contains($out, 'Undefined: 0 '), $out);
check('it resolved Storage\'s and HttpApi\'s calls',
    preg_match('/^  Storage\s+\d+ methods, +(\d+) traits$/m', $out, $s) === 1 && (int) $s[1] > 0
    && preg_match('/^  HttpApi\s+\d+ methods, +(\d+) traits$/m', $out, $h) === 1 && (int) $h[1] > 0
    && preg_match('/^(\d+) calls resolved/m', $out, $r) === 1 && (int) $r[1] > 500, $out);

[$code, $json] = runCheck($checker, $src, ['--methods']);
$composed = json_decode($json, true);
check('--methods lists php/src\'s classes', $code === 0 && is_array($composed) && $composed !== [], $json);
require_once $src . '/index.php';
$reflected = [];
foreach (get_declared_classes() as $class) {
    if (str_starts_with($class, 'ReticulumPhp\\')) {
        $names = array_map(static fn (ReflectionMethod $m): string => strtolower($m->getName()), (new ReflectionClass($class))->getMethods());
        $names = array_values(array_unique($names));
        sort($names);
        $reflected[$class] = $names;
    }
}
ksort($reflected);
$composed = is_array($composed) ? $composed : [];
ksort($composed);
check('the check sees the classes PHP declares', array_keys($composed) === array_keys($reflected),
    'check: ' . implode(', ', array_keys($composed)) . "\nPHP:   " . implode(', ', array_keys($reflected)));
foreach ($reflected as $class => $names) {
    $mine = $composed[$class] ?? [];
    check("{$class}: the check's " . count($mine) . ' methods are the ' . count($names) . ' PHP reflects',
        $mine === $names,
        'only the check: ' . implode(', ', array_diff($mine, $names)) . "\nonly PHP: " . implode(', ', array_diff($names, $mine)));
}

echo "\n$pass passed, $fail failed\n";
exit($fail === 0 ? 0 : 1);
