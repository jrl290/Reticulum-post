<?php
declare(strict_types=1);
/**
 * REGRESSION GUARD — no prepared statement may use a named placeholder twice.
 *
 * Production runs MySQL with native prepared statements
 * (database.php: PDO::ATTR_EMULATE_PREPARES = false). MySQL rejects a query
 * that binds the same named placeholder in two places with
 * SQLSTATE[HY093] "Invalid parameter number". SQLite — which every test here
 * uses — accepts it. On 2026-09-23 linkTransportEntries() shipped with
 * ":active_after" twice: the suite was green, both nodes were deployed and
 * hash-verified, and from then on every link packet from a browser died in
 * the inbound batch with that exception, so no browser could talk to rfed.
 *
 * The first version of this scan read only `$var = …; ->prepare($var)`
 * blocks, with a regular expression: a statement written inline,
 * concatenated, wrapped by Database::insertOrSql() or upsertSql(), or taken
 * from an array in a foreach was never read (REGISTRATION-STAGE1.md §14). It
 * now reads php/src with token_get_all and checks
 *
 *   (a) every `->prepare(` argument: its literal text, inline, concatenated
 *       and wrapped, each ternary branch apart, and through `$this->name()`
 *       or `Class::name()` into that method's return statements;
 *   (b) a `->prepare($var)`: the texts $var can hold, from the last `$var =`
 *       before it in its function with every `$var .=` after that, or the
 *       strings of the array a foreach takes it from; no gate on whether the
 *       text looks like SQL;
 *   (c) every string expression under php/src that holds a named
 *       placeholder, array elements included, with or without a prepare()
 *       in sight.
 *
 * It fails, never passes, on what it cannot read: a file that does not
 * parse, a `->prepare($var)` it cannot resolve, a prepare() argument with a
 * text it cannot read at all (one ternary branch is enough), and more texts
 * than it follows (MAX_TEXTS). Text it does not know (a variable it does not
 * follow, a call it does not resolve) is an opaque piece, and a name that
 * runs into one (":id{$i}") is not counted. Every `.=` between the
 * assignment and the prepare() is applied, exclusive branches included: a
 * false alarm there is the price of not reading control flow, and is fixed
 * by writing the statement another way.
 *
 * Run: php php/tests/unique_named_placeholders_test.php
 */

final class PlaceholderScanner
{
    /** Stands for text the scanner does not know. */
    public const OPAQUE = "\x00";
    /** The texts followed for one statement or string; more is a finding, never a silent cut. */
    public const MAX_TEXTS = 256;
    private const MAX_DEPTH = 6;
    private const OPENERS = ['(', '[', '{', T_CURLY_OPEN, T_DOLLAR_OPEN_CURLY_BRACES, T_ATTRIBUTE];
    /** A named placeholder: after a character that can precede one in SQL, and not running into more name or into an opaque piece. */
    private const PLACEHOLDER = '/(?:^|[\s(=,<>+\-*\/|!])\:([A-Za-z_][A-Za-z0-9_]*)(?![A-Za-z0-9_\x00])/';

    /** @var array<string, list<array{0: int|string, 1: string, 2: int}>> label => tokens, without whitespace and comments */
    private array $toks = [];
    /** @var array<string, array<int, int>> label => opener index => closer index (brackets, strings, heredocs) */
    private array $match = [];
    /** @var array<string, list<array{name: ?string, body: ?array{0: int, 1: int}}>> */
    private array $fns = [];
    /** @var array<string, list<array{0: string, 1: int, 2: int, 3: int}>> method name => [label, from, to, function] of each return */
    private array $returns = [];
    private bool $overflow = false;

    /** @var list<string> */
    public array $findings = [];
    public int $prepares = 0;
    public int $strings = 0;

    /** @param array<string, string> $sources label => PHP source */
    public function __construct(array $sources)
    {
        foreach ($sources as $label => $code) {
            try {
                $this->toks[$label] = self::tokens($code);
            } catch (ParseError $e) {
                $this->findings[] = sprintf('%s:%d does not parse: %s', $label, $e->getLine(), $e->getMessage());
                $this->toks[$label] = [];
            }
            $this->match[$label] = $this->matchGroups($label);
            $this->fns[$label] = $this->functions($label);
        }
        foreach (array_keys($sources) as $label) {
            foreach ($this->fns[$label] as $index => $fn) {
                if ($fn['name'] === null || $fn['body'] === null) {
                    continue;
                }
                for ($i = $fn['body'][0] + 1; $i < $fn['body'][1]; $i++) {
                    if ($this->toks[$label][$i][0] === T_RETURN && $this->enclosingFunction($label, $i) === $index) {
                        $this->returns[$fn['name']][] = [$label, $i + 1, $this->statementEnd($label, $i + 1), $index];
                    }
                }
            }
        }
    }

    public function scan(): void
    {
        foreach (array_keys($this->toks) as $label) {
            $this->scanPrepares($label);
            $this->scanSegments($label, 0, count($this->toks[$label]));
        }
    }

    /** @return list<string> the named placeholders that appear more than once in one text */
    public static function repeated(string $sql): array
    {
        preg_match_all(self::PLACEHOLDER, $sql, $m);

        return array_map('strval', array_keys(array_filter(array_count_values($m[1]), static fn (int $n): bool => $n > 1)));
    }

    // ── (a) and (b): every ->prepare( argument ───────────────────────────────

    private function scanPrepares(string $f): void
    {
        $t = $this->toks[$f];
        for ($i = 0; $i + 2 < count($t); $i++) {
            if (!in_array($t[$i][0], [T_OBJECT_OPERATOR, T_NULLSAFE_OBJECT_OPERATOR], true)
                || $t[$i + 1][0] !== T_STRING || strtolower($t[$i + 1][1]) !== 'prepare' || $t[$i + 2][0] !== '(') {
                continue;
            }
            $this->prepares++;
            $open = $i + 2;
            $fn = $this->enclosingFunction($f, $open);
            $where = sprintf('%s:%d ->prepare(', $f, $t[$open][2]);
            $args = $this->splitTop($f, $open + 1, $this->match[$f][$open], ',');
            $this->overflow = false;
            if ($args === []) {
                $texts = [self::OPAQUE];
            } elseif ($args[0][1] - $args[0][0] === 1 && $t[$args[0][0]][0] === T_VARIABLE) {
                $var = $t[$args[0][0]][1];
                $texts = $this->resolveVariable($f, $args[0][0], $fn, 0);
                if ($texts === null) {
                    $this->findings[] = "{$where}{$var}): cannot resolve {$var} (no assignment or foreach before it in its function)";
                    continue;
                }
            } else {
                $texts = $this->evalRange($f, $args[0][0], $args[0][1], $fn, 0, true);
            }
            if ($this->overflow) {
                $this->findings[] = $where . '…): more than ' . self::MAX_TEXTS . ' possible texts, more than the scan follows';
                continue;
            }
            if (array_filter($texts, static fn (string $s): bool => trim(str_replace(self::OPAQUE, '', $s)) === '') !== []) {
                $this->findings[] = $where . '…): ' . (count($texts) > 1 ? 'one of its statement texts' : 'its statement text') . ' cannot be read';
                continue;
            }
            foreach ($texts as $sql) {
                $dups = self::repeated($sql);
                if ($dups !== []) {
                    $this->findings[] = $where . '…): ' . self::names($dups) . ' twice in ' . self::excerpt($sql);
                }
            }
        }
    }

    // ── (c): every string expression ─────────────────────────────────────────

    /** Split [$a, $b) at expression boundaries, check each piece, and descend into every group. */
    private function scanSegments(string $f, int $a, int $b): void
    {
        $t = $this->toks[$f];
        $start = $a;
        for ($i = $a; $i <= $b; $i++) {
            if ($i < $b) {
                $id = $t[$i][0];
                if (in_array($id, self::OPENERS, true)) {
                    $this->scanSegments($f, $i + 1, $this->match[$f][$i]);
                    $i = $this->match[$f][$i];
                    continue;
                }
                if ($id === '"' || $id === T_START_HEREDOC) {
                    $i = $this->match[$f][$i];
                    continue;
                }
                if (!self::isBoundary($id)) {
                    continue;
                }
            }
            if ($i > $start) {
                $this->checkSegment($f, $start, $i);
            }
            $start = $i + 1;
        }
    }

    private function checkSegment(string $f, int $a, int $b): void
    {
        $t = $this->toks[$f];
        $literals = [];
        for ($i = $a; $i < $b; $i = $this->after($f, $i)) {
            if (in_array($t[$i][0], [T_CONSTANT_ENCAPSED_STRING, '"', T_START_HEREDOC], true)) {
                $literals[] = [$i, $this->after($f, $i)];
            }
        }
        if ($literals === []) {
            return;
        }
        $this->overflow = false;
        $texts = $this->evalRange($f, $a, $b, null, 0, false);
        foreach ($literals as [$la, $lb]) {
            // Each string on its own as well, for an expression around it
            // that the evaluation does not read (a cast, arithmetic).
            $texts = $this->union($texts, $this->evalOperand($f, $la, $lb, null, 0, false));
        }
        if ($this->overflow) {
            $this->findings[] = sprintf('%s:%d string: more than %d possible texts, more than the scan follows', $f, $t[$a][2], self::MAX_TEXTS);

            return;
        }
        foreach ($texts as $sql) {
            if (preg_match(self::PLACEHOLDER, $sql) !== 1) {
                continue;
            }
            $this->strings++;
            $dups = self::repeated($sql);
            if ($dups !== []) {
                $this->findings[] = sprintf('%s:%d string: %s twice in %s', $f, $t[$a][2], self::names($dups), self::excerpt($sql));
            }
        }
    }

    private static function isBoundary(int|string $id): bool
    {
        static $ids = null;
        $ids ??= array_flip([
            ';', ',', '=', '?', ':', '!', '<', '>', '|', '&', '^',
            T_DOUBLE_ARROW, T_COALESCE, T_RETURN, T_ECHO, T_PRINT, T_AS, T_CASE, T_THROW, T_YIELD, T_ELSE,
            T_CONCAT_EQUAL, T_PLUS_EQUAL, T_MINUS_EQUAL, T_MUL_EQUAL, T_DIV_EQUAL, T_MOD_EQUAL, T_COALESCE_EQUAL,
            T_AND_EQUAL, T_OR_EQUAL, T_XOR_EQUAL, T_SL_EQUAL, T_SR_EQUAL, T_POW_EQUAL,
            T_IS_EQUAL, T_IS_IDENTICAL, T_IS_NOT_EQUAL, T_IS_NOT_IDENTICAL, T_IS_SMALLER_OR_EQUAL, T_IS_GREATER_OR_EQUAL,
            T_SPACESHIP, T_BOOLEAN_AND, T_BOOLEAN_OR, T_LOGICAL_AND, T_LOGICAL_OR, T_LOGICAL_XOR, T_INSTANCEOF,
        ]);

        return isset($ids[$id]);
    }

    // ── evaluation: the texts an expression can have ───────────────────────

    /** @return list<string> */
    private function evalRange(string $f, int $a, int $b, ?int $fn, int $depth, bool $resolve): array
    {
        $t = $this->toks[$f];
        while ($a < $b && $t[$a][0] === '(' && $this->match[$f][$a] === $b - 1) {
            $a++;
            $b--;
        }
        if ($a >= $b) {
            return [self::OPAQUE];
        }
        // ?: binds loosest, then ??, then the concatenation.
        $q = $this->topLevel($f, $a, $b, ['?']);
        if ($q !== null) {
            $c = $this->ternaryColon($f, $q, $b);
            if ($c === null) {
                return [self::OPAQUE];
            }
            $then = $c === $q + 1
                ? $this->evalRange($f, $a, $q, $fn, $depth, $resolve)
                : $this->evalRange($f, $q + 1, $c, $fn, $depth, $resolve);

            return $this->union($then, $this->evalRange($f, $c + 1, $b, $fn, $depth, $resolve));
        }
        $q = $this->topLevel($f, $a, $b, [T_COALESCE]);
        if ($q !== null) {
            return $this->union($this->evalRange($f, $a, $q, $fn, $depth, $resolve), $this->evalRange($f, $q + 1, $b, $fn, $depth, $resolve));
        }
        $parts = $this->splitTop($f, $a, $b, '.');
        if (count($parts) > 1) {
            $texts = [''];
            foreach ($parts as [$pa, $pb]) {
                $texts = $this->product($texts, $this->evalRange($f, $pa, $pb, $fn, $depth, $resolve));
            }

            return $texts;
        }

        return $this->evalOperand($f, $a, $b, $fn, $depth, $resolve);
    }

    /** @return list<string> */
    private function evalOperand(string $f, int $a, int $b, ?int $fn, int $depth, bool $resolve): array
    {
        $t = $this->toks[$f];
        $first = $t[$a];
        if ($b - $a === 1 && $first[0] === T_CONSTANT_ENCAPSED_STRING) {
            return [self::literal($first[1])];
        }
        if (($first[0] === '"' || $first[0] === T_START_HEREDOC) && $this->match[$f][$a] === $b - 1) {
            // A nowdoc (<<<'X') has no escapes and no interpolation.
            $escapes = !($first[0] === T_START_HEREDOC && str_contains($first[1], "'"));

            return $this->interpolated($f, $a + 1, $b - 1, $fn, $depth, $resolve, $escapes);
        }
        if ($b - $a === 1 && $first[0] === T_VARIABLE) {
            return ($resolve ? $this->resolveVariable($f, $a, $fn, $depth) : null) ?? [self::OPAQUE];
        }
        // $this->name(…), Class::name(…), self::name(…), static::name(…)
        if ($b - $a >= 4 && $t[$a + 2][0] === T_STRING && $t[$a + 3][0] === '(' && $this->match[$f][$a + 3] === $b - 1
            && (($first[0] === T_VARIABLE && $first[1] === '$this' && in_array($t[$a + 1][0], [T_OBJECT_OPERATOR, T_NULLSAFE_OBJECT_OPERATOR], true))
                || (in_array($first[0], [T_STRING, T_STATIC, T_NAME_QUALIFIED, T_NAME_FULLY_QUALIFIED], true) && $t[$a + 1][0] === T_DOUBLE_COLON))) {
            $name = strtolower($t[$a + 2][1]);
            $args = $this->splitTop($f, $a + 4, $b - 1, ',');
            // The wrappers rewrite their SQL argument per backend; its text is the statement's.
            if ($name === 'insertorsql') {
                return isset($args[1]) ? $this->evalRange($f, $args[1][0], $args[1][1], $fn, $depth, $resolve) : [self::OPAQUE];
            }
            if ($name === 'upsertsql') {
                return isset($args[0]) ? $this->evalRange($f, $args[0][0], $args[0][1], $fn, $depth, $resolve) : [self::OPAQUE];
            }
            if ($resolve && $depth < self::MAX_DEPTH && isset($this->returns[$name])) {
                $texts = [];
                foreach ($this->returns[$name] as [$rf, $ra, $rb, $rfn]) {
                    $texts = $this->union($texts, $this->evalRange($rf, $ra, $rb, $rfn, $depth + 1, true));
                }

                return $texts === [] ? [self::OPAQUE] : $texts;
            }
        }

        return [self::OPAQUE];
    }

    /** The texts of an interpolated string or heredoc, between its delimiters. @return list<string> */
    private function interpolated(string $f, int $a, int $b, ?int $fn, int $depth, bool $resolve, bool $escapes): array
    {
        $t = $this->toks[$f];
        $texts = [''];
        for ($i = $a; $i < $b; $i++) {
            $id = $t[$i][0];
            if ($id === T_ENCAPSED_AND_WHITESPACE) {
                $texts = $this->product($texts, [$escapes ? self::whitespaceEscapes($t[$i][1]) : $t[$i][1]]);
                continue;
            }
            $part = [self::OPAQUE];
            if ($id === T_CURLY_OPEN || $id === T_DOLLAR_OPEN_CURLY_BRACES) {
                $close = $this->match[$f][$i];
                if ($id === T_CURLY_OPEN && $close === $i + 2 && $t[$i + 1][0] === T_VARIABLE && $resolve) {
                    $part = $this->resolveVariable($f, $i + 1, $fn, $depth) ?? [self::OPAQUE];
                }
                $i = $close;
            } elseif ($id === T_VARIABLE) {
                $next = $t[$i + 1][0] ?? null;
                if ($next === '[') {
                    $i = $this->match[$f][$i + 1];
                } elseif ($next === T_OBJECT_OPERATOR || $next === T_NULLSAFE_OBJECT_OPERATOR) {
                    $i += 2;
                } elseif ($resolve) {
                    $part = $this->resolveVariable($f, $i, $fn, $depth) ?? [self::OPAQUE];
                }
            }
            $texts = $this->product($texts, $part);
        }

        return $texts;
    }

    /**
     * (b): the texts $var can hold at token $p — from the nearest `$var =`
     * or foreach binding it before $p in the same function (or at top level),
     * with every `$var .=` between that and $p applied. Null when there is
     * neither.
     *
     * @return list<string>|null
     */
    private function resolveVariable(string $f, int $p, ?int $fn, int $depth): ?array
    {
        if ($depth >= self::MAX_DEPTH) {
            return null;
        }
        $t = $this->toks[$f];
        $name = $t[$p][1];
        $low = $fn === null ? -1 : $this->fns[$f][$fn]['body'][0];
        for ($i = $p - 1; $i > $low; $i--) {
            $id = $t[$i][0];
            if ($id === T_VARIABLE && $t[$i][1] === $name && ($t[$i + 1][0] ?? null) === '='
                && $this->statementStart($f, $i) && $this->enclosingFunction($f, $i) === $fn) {
                $end = $this->statementEnd($f, $i + 2);
                if ($end > $p) {
                    // $p is in this assignment's own right-hand side
                    // ($sql = Database::upsertSql($sql, …)): the value before it.
                    continue;
                }

                return $this->appends($f, $name, $end, $p, $fn, $depth,
                    $this->evalRange($f, $i + 2, $end, $fn, $depth + 1, true));
            }
            if ($id === T_FOREACH && ($t[$i + 1][0] ?? null) === '(' && $this->enclosingFunction($f, $i) === $fn) {
                $close = $this->match[$f][$i + 1];
                $as = $this->topLevel($f, $i + 2, $close, [T_AS]);
                if ($close > $p || $as === null || !$this->binds($f, $as + 1, $close, $name)) {
                    continue;
                }
                $strings = $this->arrayStrings($f, $i + 2, $as, $fn, $depth + 1);

                return $strings === [] ? null : $this->appends($f, $name, $close, $p, $fn, $depth, $strings);
            }
        }

        return null;
    }

    /** @return list<string> $texts with every `$name .=` in ($from, $p) applied */
    private function appends(string $f, string $name, int $from, int $p, ?int $fn, int $depth, array $texts): array
    {
        $t = $this->toks[$f];
        for ($j = $from + 1; $j < $p; $j++) {
            if ($t[$j][0] === T_VARIABLE && $t[$j][1] === $name && ($t[$j + 1][0] ?? null) === T_CONCAT_EQUAL
                && $this->enclosingFunction($f, $j) === $fn) {
                $end = $this->statementEnd($f, $j + 2);
                if ($end > $p) {
                    break; // $p is in this append's own right-hand side
                }
                $texts = $this->product($texts, $this->evalRange($f, $j + 2, $end, $fn, $depth + 1, true));
                $j = $end;
            }
        }

        return $texts;
    }

    private function binds(string $f, int $a, int $b, string $name): bool
    {
        for ($k = $a; $k < $b; $k++) {
            if ($this->toks[$f][$k][0] === T_VARIABLE && $this->toks[$f][$k][1] === $name) {
                return true;
            }
        }

        return false;
    }

    /** Every readable text in the array an expression is (or a variable was assigned). @return list<string> */
    private function arrayStrings(string $f, int $a, int $b, ?int $fn, int $depth): array
    {
        $t = $this->toks[$f];
        if ($depth >= self::MAX_DEPTH) {
            return [];
        }
        if ($b - $a === 1 && $t[$a][0] === T_VARIABLE) {
            $low = $fn === null ? -1 : $this->fns[$f][$fn]['body'][0];
            for ($i = $a - 1; $i > $low; $i--) {
                if ($t[$i][0] === T_VARIABLE && $t[$i][1] === $t[$a][1] && ($t[$i + 1][0] ?? null) === '='
                    && $this->statementStart($f, $i) && $this->enclosingFunction($f, $i) === $fn) {
                    return $this->arrayStrings($f, $i + 2, $this->statementEnd($f, $i + 2), $fn, $depth + 1);
                }
            }

            return [];
        }
        if ($t[$a][0] === '[' && $this->match[$f][$a] === $b - 1) {
            [$inner0, $inner1] = [$a + 1, $b - 1];
        } elseif ($t[$a][0] === T_ARRAY && ($t[$a + 1][0] ?? null) === '(' && $this->match[$f][$a + 1] === $b - 1) {
            [$inner0, $inner1] = [$a + 2, $b - 1];
        } else {
            return array_values(array_filter($this->evalRange($f, $a, $b, $fn, $depth, true),
                static fn (string $s): bool => trim(str_replace(self::OPAQUE, '', $s)) !== ''));
        }
        $texts = [];
        foreach ($this->splitTop($f, $inner0, $inner1, ',') as [$ea, $eb]) {
            $arrow = $this->topLevel($f, $ea, $eb, [T_DOUBLE_ARROW]);
            $texts = $this->union($texts, $this->arrayStrings($f, $arrow === null ? $ea : $arrow + 1, $eb, $fn, $depth));
        }

        return $texts;
    }

    // ── token structure ──────────────────────────────────────────────────────

    /** @return list<array{0: int|string, 1: string, 2: int}> */
    private static function tokens(string $code): array
    {
        $out = [];
        $line = 1;
        foreach (token_get_all($code, TOKEN_PARSE) as $token) {
            if (!is_array($token)) {
                $out[] = [$token, $token, $line];
                continue;
            }
            [$id, $text, $line] = $token;
            if (in_array($id, [T_WHITESPACE, T_COMMENT, T_DOC_COMMENT, T_OPEN_TAG, T_INLINE_HTML], true)) {
                continue;
            }
            // A closing tag ends a statement; <?= starts one.
            $out[] = $id === T_CLOSE_TAG || $id === T_OPEN_TAG_WITH_ECHO ? [';', ';', $line] : [$id, $text, $line];
        }

        return $out;
    }

    /** @return array<int, int> */
    private function matchGroups(string $f): array
    {
        $match = [];
        $stack = [];
        $t = $this->toks[$f];
        $n = count($t);
        for ($i = 0; $i < $n; $i++) {
            $id = $t[$i][0];
            if ($id === '"' || $id === T_START_HEREDOC) {
                $end = $id === '"' ? '"' : T_END_HEREDOC;
                $open = $i;
                $inner = [];
                for ($i++; $i < $n && $t[$i][0] !== $end; $i++) {
                    $tid = $t[$i][0];
                    if ($tid === '[' || $tid === T_CURLY_OPEN || $tid === T_DOLLAR_OPEN_CURLY_BRACES || $tid === '{') {
                        $inner[] = $i;
                    } elseif (($tid === ']' || $tid === '}') && $inner !== []) {
                        $match[array_pop($inner)] = $i;
                    }
                }
                $match[$open] = $i;
                continue;
            }
            if (in_array($id, self::OPENERS, true)) {
                $stack[] = $i;
            } elseif (($id === ')' || $id === ']' || $id === '}') && $stack !== []) {
                $match[array_pop($stack)] = $i;
            }
        }

        return $match;
    }

    /** @return list<array{name: ?string, body: ?array{0: int, 1: int}}> */
    private function functions(string $f): array
    {
        $t = $this->toks[$f];
        $n = count($t);
        $fns = [];
        for ($i = 0; $i < $n; $i++) {
            if ($t[$i][0] !== T_FUNCTION) {
                continue;
            }
            $j = $i + 1;
            if (($t[$j][0] ?? null) === '&') {
                $j++;
            }
            $name = null;
            if (($t[$j][0] ?? null) === T_STRING) {
                $name = strtolower($t[$j][1]);
                $j++;
            }
            if (($t[$j][0] ?? null) !== '(') {
                continue;
            }
            $body = null;
            for ($k = $this->match[$f][$j] + 1; $k < $n; $k++) {
                $id = $t[$k][0];
                if ($id === '(') {
                    $k = $this->match[$f][$k];
                } elseif ($id === '{') {
                    $body = [$k, $this->match[$f][$k]];
                    break;
                } elseif ($id === ';') {
                    break;
                }
            }
            $fns[] = ['name' => $name, 'body' => $body];
        }

        return $fns;
    }

    /** The innermost function whose body holds token $p, or null at top level. */
    private function enclosingFunction(string $f, int $p): ?int
    {
        $best = null;
        $span = PHP_INT_MAX;
        foreach ($this->fns[$f] as $index => $fn) {
            if ($fn['body'] !== null && $fn['body'][0] < $p && $p < $fn['body'][1] && $fn['body'][1] - $fn['body'][0] < $span) {
                $best = $index;
                $span = $fn['body'][1] - $fn['body'][0];
            }
        }

        return $best;
    }

    /** The index after the token, or the whole group, that starts at $i. */
    private function after(string $f, int $i): int
    {
        $id = $this->toks[$f][$i][0];
        if (isset($this->match[$f][$i]) && (in_array($id, self::OPENERS, true) || $id === '"' || $id === T_START_HEREDOC)) {
            return $this->match[$f][$i] + 1;
        }

        return $i + 1;
    }

    /** The first token in [$a, $b), outside every group, whose id is one of $ids. */
    private function topLevel(string $f, int $a, int $b, array $ids): ?int
    {
        for ($i = $a; $i < $b; $i = $this->after($f, $i)) {
            if (in_array($this->toks[$f][$i][0], $ids, true)) {
                return $i;
            }
        }

        return null;
    }

    /** @return list<array{0: int, 1: int}> [$a, $b) split at each top-level $id, empty pieces dropped */
    private function splitTop(string $f, int $a, int $b, int|string $id): array
    {
        $parts = [];
        $start = $a;
        for ($i = $a; $i < $b; $i = $this->after($f, $i)) {
            if ($this->toks[$f][$i][0] === $id) {
                $parts[] = [$start, $i];
                $start = $i + 1;
            }
        }
        $parts[] = [$start, $b];

        return array_values(array_filter($parts, static fn (array $p): bool => $p[1] > $p[0]));
    }

    private function ternaryColon(string $f, int $q, int $b): ?int
    {
        $nested = 0;
        for ($i = $q + 1; $i < $b; $i = $this->after($f, $i)) {
            $id = $this->toks[$f][$i][0];
            if ($id === '?') {
                $nested++;
            } elseif ($id === ':') {
                if ($nested === 0) {
                    return $i;
                }
                $nested--;
            }
        }

        return null;
    }

    /** The ';' that ends the statement whose expression starts at $i. */
    private function statementEnd(string $f, int $i): int
    {
        $n = count($this->toks[$f]);
        for (; $i < $n; $i = $this->after($f, $i)) {
            if ($this->toks[$f][$i][0] === ';') {
                return $i;
            }
        }

        return $n;
    }

    private function statementStart(string $f, int $i): bool
    {
        $prev = $this->toks[$f][$i - 1][0] ?? ';';

        return in_array($prev, [';', '{', '}', ')', ':', T_ELSE, T_DO], true);
    }

    private static function literal(string $token): string
    {
        $body = substr($token, 1, -1);
        if ($token[0] === "'") {
            return str_replace(['\\\\', "\\'"], ['\\', "'"], $body);
        }

        return self::whitespaceEscapes($body);
    }

    /** \n, \t, \r, \v and \f in a double-quoted string or heredoc are whitespace, which bounds a placeholder. */
    private static function whitespaceEscapes(string $text): string
    {
        return (string) preg_replace('/\\\\[ntrvf]/', ' ', $text);
    }

    /** @return list<string> */
    private function union(array $a, array $b): array
    {
        $texts = array_values(array_unique(array_merge($a, $b)));
        if (count($texts) > self::MAX_TEXTS) {
            $this->overflow = true;

            return array_slice($texts, 0, self::MAX_TEXTS);
        }

        return $texts;
    }

    /** @return list<string> */
    private function product(array $a, array $b): array
    {
        $texts = [];
        foreach ($a as $x) {
            foreach ($b as $y) {
                $texts[$x . $y] = true;
                if (count($texts) > self::MAX_TEXTS) {
                    $this->overflow = true;

                    return array_slice(array_map('strval', array_keys($texts)), 0, self::MAX_TEXTS);
                }
            }
        }

        return array_map('strval', array_keys($texts));
    }

    private static function names(array $placeholders): string
    {
        return implode(', ', array_map(static fn (string $p): string => ':' . $p, $placeholders));
    }

    private static function excerpt(string $sql): string
    {
        $flat = trim((string) preg_replace('/\s+/', ' ', str_replace(self::OPAQUE, '…', $sql)));

        return '"' . (strlen($flat) > 160 ? substr($flat, 0, 157) . '...' : $flat) . '"';
    }
}

/** The findings for one class body. */
function scanMembers(string $members): array
{
    $scanner = new PlaceholderScanner(['snippet.php' => "<?php\nfinal class Snippet\n{\n{$members}\n}\n"]);
    $scanner->scan();

    return $scanner->findings;
}

/** The prepare() findings, (a) and (b), that contain $needle. */
function prepareFindings(array $findings, string $needle): array
{
    return array_values(array_filter($findings, static fn (string $s): bool => str_contains($s, '->prepare(') && str_contains($s, $needle)));
}

$failures = 0;
$check = static function (bool $ok, string $label, array $findings) use (&$failures): void {
    if ($ok) {
        echo "ok   {$label}\n";

        return;
    }
    echo "FAIL: {$label}: " . json_encode($findings, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE) . "\n";
    $failures++;
};

// 1. The exact query that broke production on 2026-09-23.
$found = scanMembers(<<<'PHP'
    private function linkTransportEntries(): void
    {
        $query = "SELECT lte.* FROM link_transport_entries AS lte WHERE lte.link_id_hex = :link_id_hex";
        $query .= ' AND ((lte.validated = 1 AND lte.updated_at >= :active_after)'
            . ' OR (lte.proof_expires_at IS NULL AND lte.updated_at >= :active_after))';
        $stmt = $this->db->prepare($query);
    }
PHP);
$check(prepareFindings($found, ':active_after twice') !== [], 'the scanner flags a placeholder used twice (the 2026-09-23 query)', $found);

// 2. Ternary alternatives (one statement per backend) are not a repeat.
$found = scanMembers(<<<'PHP'
    private function upsert(): void
    {
        $sql = $this->backend === 'mysql'
            ? "INSERT INTO t (k, v, at) VALUES (:key, :value, :now) ON DUPLICATE KEY UPDATE v = VALUES(v)"
            : "INSERT INTO t (k, v, at) VALUES (:key, :value, :now) ON CONFLICT(k) DO UPDATE SET v = excluded.v";
        $stmt = $this->db->prepare($sql);
        $stmt = $this->db->prepare($this->backend === 'mysql'
            ? 'UPDATE t SET v = :value WHERE k = :key'
            : 'UPDATE OR IGNORE t SET v = :value WHERE k = :key');
    }
PHP);
$check($found === [], 'per-backend ternary alternatives are separate statements, assigned or inline', $found);

// 3. §8's compare-and-swap, written inline with one placeholder twice.
$found = scanMembers(<<<'PHP'
    private function logSupersededOnce(string $interfaceId, string $tokenHash): void
    {
        $stmt = $this->db->prepare(
            'UPDATE interfaces SET superseded_logged_hash = :new_hash
              WHERE interface_id = :id AND superseded_logged_hash <> :new_hash'
        );
    }
PHP);
$check(prepareFindings($found, ':new_hash twice') !== [], "the scanner flags §8's compare-and-swap written inline with one placeholder twice", $found);

// 4. An inline concatenation.
$found = scanMembers(<<<'PHP'
    private function pathFor(): void
    {
        $stmt = $this->db->prepare('SELECT * FROM path_entries WHERE destination_hash_hex = :destination_hash_hex'
            . ' OR next_hop_hex = :destination_hash_hex');
    }
PHP);
$check(prepareFindings($found, ':destination_hash_hex twice') !== [], 'the scanner flags an inline concatenation', $found);

// 5. A literal wrapped by insertOrSql() or upsertSql().
$found = scanMembers(<<<'PHP'
    private function remember(): void
    {
        $stmt = $this->db->prepare(Database::insertOrSql($this->backend,
            'INSERT OR IGNORE INTO interfaces (interface_id, created_at, updated_at) VALUES (:interface_id, :now, :now)'));
        $stmt = $this->db->prepare(Database::upsertSql(
            'INSERT INTO transport_state (state_key, state_value, updated_at) VALUES (:state_key, :state_value, :now)
             ON CONFLICT(state_key) DO UPDATE SET state_value = :state_value', $this->backend));
    }
PHP);
$check(prepareFindings($found, ':now twice') !== [] && prepareFindings($found, ':state_value twice') !== [],
    'the scanner flags a wrapped literal (insertOrSql and upsertSql)', $found);

// 6. A statement array prepared in a foreach.
$found = scanMembers(<<<'PHP'
    private function retire(string $interfaceId): void
    {
        foreach ([
            ['local_destinations', 'DELETE FROM local_destinations WHERE interface_id = :interface_id'],
            ['path_entries', 'DELETE FROM path_entries WHERE interface_id = :interface_id OR next_hop_interface_id = :interface_id'],
        ] as [$table, $sql]) {
            $stmt = $this->db->prepare($sql);
            $stmt->bindValue(':interface_id', $interfaceId);
            Database::executeWithRetry($stmt, 'retire:' . $table);
        }
    }
PHP);
$check(prepareFindings($found, ':interface_id twice') !== [], 'the scanner flags a statement array prepared in a foreach', $found);

// 7. A ->prepare($var) it cannot resolve fails; it is not passed unread.
$found = scanMembers(<<<'PHP'
    private function run(string $statement): void
    {
        $stmt = $this->db->prepare($statement);
    }
PHP);
$check(prepareFindings($found, 'cannot resolve $statement') !== [], 'a ->prepare($var) the scanner cannot resolve is a failure', $found);

// 8. So is a statement text it cannot read, in every branch or in one, and
//    a file that does not parse.
$found = scanMembers(<<<'PHP'
    private function countRows(string $table): void
    {
        $stmt = $this->db->prepare(sprintf('SELECT COUNT(*) FROM %s', $table));
        $stmt = $this->db->prepare($this->backend === 'mysql' ? $this->mysqlCountSql() : 'SELECT COUNT(*) FROM t WHERE k = :k');
    }
PHP);
$check(prepareFindings($found, ': its statement text cannot be read') !== []
    && prepareFindings($found, ': one of its statement texts cannot be read') !== [],
    'a statement text the scanner cannot read, in every branch or in one, is a failure', $found);
$found = scanMembers(<<<'PHP'
    private function broken(): void
    {
        $stmt = $this->db->prepare('SELECT 1 FROM t WHERE k = :k';
    }
PHP);
$check(array_filter($found, static fn (string $s): bool => str_contains($s, 'does not parse')) !== [], 'a file that does not parse is a failure, not a crash', $found);

// 9. Placeholder names built at run time are not a repeat.
$found = scanMembers(<<<'PHP'
    private function deleteMany(array $ids): void
    {
        $in = [];
        foreach (array_keys($ids) as $i) {
            $in[] = ":id{$i}";
        }
        $sql = 'DELETE FROM outbound_packets WHERE packet_id IN (' . implode(', ', $in) . ')';
        $stmt = $this->db->prepare($sql);
        $stmt = $this->db->prepare("SELECT 1 FROM outbound_packets WHERE packet_id = :id{$this->a} OR packet_id = :id{$this->b}");
    }
PHP);
$check($found === [], 'placeholder names built at run time (":id{$i}") are not counted as a repeat', $found);

// 10. A statement a method returns.
$found = scanMembers(<<<'PHP'
    private function seed(): void
    {
        $stmt = $this->db->prepare($this->seedSql());
    }

    private function seedSql(): string
    {
        return 'SELECT raw FROM inbound_packets WHERE packet_hash_hex = :hash OR original_hash_hex = :hash';
    }
PHP);
$check(prepareFindings($found, ':hash twice') !== [], 'the scanner follows a prepare() into the method that returns its statement', $found);

// 11. (c): a string with a placeholder twice, no prepare() in sight.
$found = scanMembers(<<<'PHP'
    private const RETIRE = [
        'outbound_batches' => 'DELETE FROM outbound_batches WHERE interface_id = :interface_id OR peer_interface_id = :interface_id',
    ];
PHP);
$check(array_filter($found, static fn (string $s): bool => str_contains($s, ' string: :interface_id twice')) !== [],
    'the scanner flags a string with a placeholder twice wherever it is', $found);

// 12. The real source: every .php under php/src.
$root = dirname(__DIR__) . '/src';
$sources = [];
foreach (new RecursiveIteratorIterator(new RecursiveDirectoryIterator($root, FilesystemIterator::SKIP_DOTS)) as $file) {
    if ($file->isFile() && str_ends_with($file->getFilename(), '.php')) {
        $sources[substr($file->getPathname(), strlen($root) + 1)] = (string) file_get_contents($file->getPathname());
    }
}
ksort($sources);
$scanner = new PlaceholderScanner($sources);
$scanner->scan();
foreach ($scanner->findings as $finding) {
    echo "FAIL: {$finding}\n";
    $failures++;
}
// A scan that read nothing would pass: it must have read the statements.
if ($scanner->prepares < 100) {
    echo "FAIL: the scan read only {$scanner->prepares} prepare() calls under php/src\n";
    $failures++;
} elseif ($scanner->findings === []) {
    printf("ok   no statement or string under php/src uses a named placeholder twice (%d files, %d prepare() calls, %d texts with a placeholder)\n",
        count($sources), $scanner->prepares, $scanner->strings);
}

exit($failures === 0 ? 0 : 1);
