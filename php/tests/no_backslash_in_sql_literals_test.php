<?php
declare(strict_types=1);
/**
 * REGRESSION GUARD — no SQL string literal in php/src may contain a backslash.
 *
 * Production runs MySQL 8.4 / MariaDB 11.4 in the default sql_mode
 * (Database::connect does not set NO_BACKSLASH_ESCAPES), where a backslash
 * inside a '...' literal is an escape character. SQLite, which every test here
 * uses, reads the same literal as standard SQL, where a backslash is an
 * ordinary character. The same text means two things, and the difference only
 * shows in production.
 *
 * The interface-identity hotfix (ad89d9f) wrote
 *     "... WHERE metadata_json LIKE :hash_pattern ESCAPE '\\'"
 * in a double-quoted PHP string, so the SQL was ESCAPE '\'. SQLite prepares it;
 * MySQL reads '\' as an unterminated literal (error 1064), so every browser
 * registration would have failed on both relays with the suite green. Same
 * class as 2026-09-23 (unique_named_placeholders_test.php): a query MySQL
 * cannot prepare. Use a bound parameter, or an ESCAPE character that is not a
 * backslash ('!').
 *
 * How it scans: token_get_all() over every .php file under php/src. Adjacent
 * string literals joined by '.' (a bare $variable operand, and each
 * interpolation inside a "..." string or heredoc, read as '?') are evaluated to
 * their runtime text. Text that reads as SQL (an upper-case SQL keyword) is
 * split into '...' literals ('' is an escaped quote), and a literal holding a
 * backslash is a failure.
 *
 * Run: php php/tests/no_backslash_in_sql_literals_test.php
 */

/** Runtime text of a single-quoted PHP literal's body. */
function singleQuotedValue(string $body): string
{
    return (string) preg_replace_callback('/\\\\([\\\\\'])/', static fn (array $m): string => $m[1], $body);
}

/** Runtime text of a "..." or heredoc fragment (PHP's double-quote escapes). */
function doubleQuotedValue(string $body, bool $heredoc): string
{
    return (string) preg_replace_callback(
        '/\\\\(?:([nrtvef\\\\$"])|([0-7]{1,3})|x([0-9A-Fa-f]{1,2})|u\{([0-9A-Fa-f]+)\})/',
        static function (array $m) use ($heredoc): string {
            if (($m[1] ?? '') !== '') {
                if ($m[1] === '"' && $heredoc) {
                    return $m[0]; // \" is not an escape inside a heredoc
                }
                return ['n' => "\n", 'r' => "\r", 't' => "\t", 'v' => "\v", 'e' => "\e", 'f' => "\f",
                        '\\' => '\\', '$' => '$', '"' => '"'][$m[1]];
            }
            if (($m[2] ?? '') !== '') {
                return chr(octdec($m[2]) & 0xFF);
            }
            if (($m[3] ?? '') !== '') {
                return chr(hexdec($m[3]));
            }
            return mb_chr((int) hexdec($m[4]), 'UTF-8');
        },
        $body
    );
}

function nextSignificant(array $tokens, int $i): int
{
    $n = count($tokens);
    while ($i < $n && is_array($tokens[$i]) && in_array($tokens[$i][0], [T_WHITESPACE, T_COMMENT, T_DOC_COMMENT], true)) {
        $i++;
    }
    return $i;
}

/**
 * Read one string-ish operand at $i.
 * Returns [runtime text, line, index after it, is a literal] or null.
 */
function readOperand(array $tokens, int $i): ?array
{
    $n = count($tokens);
    if ($i >= $n) {
        return null;
    }
    $tok = $tokens[$i];

    if (is_array($tok) && $tok[0] === T_CONSTANT_ENCAPSED_STRING) {
        $raw = ltrim($tok[1], 'bB');
        $body = substr($raw, 1, -1);
        $text = $raw[0] === "'" ? singleQuotedValue($body) : doubleQuotedValue($body, false);
        return [$text, $tok[2], $i + 1, true];
    }

    // "...{$x}..." or a heredoc/nowdoc: literal pieces, each interpolation '?'.
    $isQuote = $tok === '"';
    $isHeredoc = is_array($tok) && $tok[0] === T_START_HEREDOC;
    if ($isQuote || $isHeredoc) {
        $nowdoc = $isHeredoc && str_contains($tok[1], "'");
        $line = is_array($tok) ? $tok[2] : 0;
        $text = '';
        $inInterpolation = false;
        for ($j = $i + 1; $j < $n; $j++) {
            $t = $tokens[$j];
            if (($isQuote && $t === '"') || ($isHeredoc && is_array($t) && $t[0] === T_END_HEREDOC)) {
                return [$text, $line, $j + 1, true];
            }
            if (is_array($t) && $t[0] === T_ENCAPSED_AND_WHITESPACE) {
                $text .= $nowdoc ? $t[1] : doubleQuotedValue($t[1], $isHeredoc);
                $line = $line ?: $t[2];
                $inInterpolation = false;
            } elseif (!$inInterpolation) {
                $text .= '?';
                $inInterpolation = true;
            }
        }
        return null;
    }

    // A bare $variable operand in a '.' chain (not $x->y, $x[...], $x(...)).
    if (is_array($tok) && $tok[0] === T_VARIABLE) {
        $k = nextSignificant($tokens, $i + 1);
        $after = $tokens[$k] ?? null;
        if ($after === '[' || $after === '(' || (is_array($after) && in_array($after[0], [T_OBJECT_OPERATOR, T_NULLSAFE_OBJECT_OPERATOR, T_DOUBLE_COLON], true))) {
            return null;
        }
        return ['?', $tok[2], $i + 1, false];
    }

    return null;
}

/** Every '.'-joined string expression in $code: [line, runtime text]. */
function stringExpressions(string $code): array
{
    $tokens = token_get_all($code);
    $n = count($tokens);
    $out = [];
    $i = 0;
    while ($i < $n) {
        $op = readOperand($tokens, $i);
        if ($op === null) {
            $i++;
            continue;
        }
        [$text, $line, $j, $hasLiteral] = $op;
        while (true) {
            $k = nextSignificant($tokens, $j);
            if (($tokens[$k] ?? null) !== '.') {
                break;
            }
            $next = readOperand($tokens, nextSignificant($tokens, $k + 1));
            if ($next === null) {
                break;
            }
            $text .= $next[0];
            $hasLiteral = $hasLiteral || $next[3];
            $j = $next[2];
        }
        if ($hasLiteral) {
            $out[] = [$line, $text];
        }
        $i = $j;
    }
    return $out;
}

/** The '...' literals in a SQL text that contain a backslash. */
function backslashLiterals(string $sql): array
{
    $found = [];
    $len = strlen($sql);
    $i = 0;
    while ($i < $len) {
        if ($sql[$i] !== "'") {
            $i++;
            continue;
        }
        $i++;
        $content = '';
        $closed = false;
        while ($i < $len) {
            if ($sql[$i] === "'") {
                if ($i + 1 < $len && $sql[$i + 1] === "'") {
                    $content .= "''";
                    $i += 2;
                    continue;
                }
                $closed = true;
                $i++;
                break;
            }
            $content .= $sql[$i];
            $i++;
        }
        if (str_contains($content, '\\')) {
            $found[] = "'" . $content . ($closed ? "'" : ' (unterminated)');
        }
    }
    return $found;
}

function looksLikeSql(string $text): bool
{
    return preg_match('/\b(SELECT|INSERT|UPDATE|DELETE|REPLACE|CREATE|ALTER|DROP|WHERE|LIKE|ESCAPE|VALUES)\b/', $text) === 1;
}

/** Findings for PHP source text: "line N: <literal>". */
function sqlBackslashFindings(string $code): array
{
    $findings = [];
    foreach (stringExpressions($code) as [$line, $text]) {
        if (!looksLikeSql($text)) {
            continue;
        }
        foreach (backslashLiterals($text) as $literal) {
            $findings[] = sprintf('line %d: %s', $line, $literal);
        }
    }
    return $findings;
}

$failures = 0;
$expect = function (bool $ok, string $what) use (&$failures): void {
    echo ($ok ? 'ok   ' : 'FAIL ') . $what . "\n";
    if (!$ok) {
        $failures++;
    }
};

// 1. The scanner flags the exact query the hotfix first shipped (ad89d9f).
$ad89d9f = <<<'PHP'
<?php
        $stmt = $this->db->prepare(
            "SELECT interface_id, name, metadata_json
             FROM interfaces
             WHERE metadata_json LIKE :hash_pattern ESCAPE '\\'"
        );
PHP;
$found = sqlBackslashFindings($ad89d9f);
$expect(count($found) === 1, "flags ad89d9f's ESCAPE '\\' in a double-quoted string (" . json_encode($found) . ')');

// 2. The same literal built by concatenation, or in a single-quoted string.
$split = <<<'PHP'
<?php
        $sql = "SELECT a FROM t WHERE b LIKE :p ESCAPE '" . '\\' . "'";
PHP;
$expect(count(sqlBackslashFindings($split)) === 1, 'flags a backslash literal assembled by concatenation');
$single = <<<'PHP'
<?php
        $sql = 'SELECT a FROM t WHERE b LIKE :p ESCAPE \'\\\\\'';
PHP;
$expect(count(sqlBackslashFindings($single)) === 1, "flags ESCAPE '\\\\' in a single-quoted string (SQLite rejects it, MySQL reads one backslash)");
$heredoc = <<<'PHP'
<?php
        $sql = <<<SQL
            SELECT a FROM t WHERE b = '{$x}\\n'
        SQL;
PHP;
$expect(count(sqlBackslashFindings($heredoc)) === 1, 'flags a backslash literal inside an interpolated heredoc');

// 3. What must not be flagged.
$clean = <<<'PHP'
<?php
        $a = $this->db->prepare('SELECT a FROM t WHERE b LIKE :p ESCAPE \'!\'');
        $b = $this->db->prepare(
            'SELECT interface_id, name, metadata_json
             FROM interfaces
             WHERE metadata_json LIKE :hash_pattern'
        );
        $c = "SELECT a FROM t WHERE b = '" . $v . "'";
        $d = 'ReticulumPhp\\Database';
        $e = preg_replace('/^INSERT\s+OR\s+IGNORE\s+INTO\s/i', 'INSERT IGNORE INTO ', $sql);
        error_log('[X] can\'t parse \\d here');
        $f = "line\n" . "SELECT 'a''b' FROM t";
PHP;
$found = sqlBackslashFindings($clean);
$expect($found === [], "no false positives: ESCAPE '!', bound LIKE, namespaces, regexes, prose (" . json_encode($found) . ')');

// 4. The real source is clean.
$srcRoot = dirname(__DIR__) . '/src';
$files = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($srcRoot, FilesystemIterator::SKIP_DOTS));
$scanned = 0;
$realFindings = 0;
foreach ($files as $file) {
    if ($file->getExtension() !== 'php') {
        continue;
    }
    $scanned++;
    foreach (sqlBackslashFindings((string) file_get_contents($file->getPathname())) as $finding) {
        echo 'FAIL ' . substr($file->getPathname(), strlen($srcRoot) + 1) . ' ' . $finding . "\n";
        $realFindings++;
        $failures++;
    }
}
$expect($scanned > 0, "scanned {$scanned} file(s) under php/src");
if ($realFindings === 0) {
    echo "ok   no SQL string literal under php/src contains a backslash\n";
}

exit($failures === 0 ? 0 : 1);
