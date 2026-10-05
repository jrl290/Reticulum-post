<?php

declare(strict_types=1);

/**
 * Static analysis: every method call in php/src resolves on the class it
 * runs in.
 *
 * WHAT THIS EXISTS TO PREVENT
 * ===========================
 * Until 2026-10-05 this file put every trait and index.php into one body and
 * asked only whether SOME file defined a method of the called name. A trait
 * is not code of its own: it runs as part of each class that uses it, and a
 * call in it must resolve on that class. RequestPhpWakeTrait, used by
 * Storage, called $this->log(), which only RequestHttpApiHelperTrait, used by
 * HttpApi, defines. On b6c7809, live on both nodes, the request whose prelude
 * re-registered a dead peering session (ensureConfiguredPeerSessions, Phase
 * 12 of maintenance) died with "Call to undefined method
 * ReticulumPhp\Storage::log()" and answered 500, whichever client sent it,
 * and the rest of the loop never ran; this check printed "Undefined: 0".
 * RequestControlPlaneTrait guarded the same call with method_exists(), so
 * its "[local_destinations] ... moved" line was never written at all.
 *
 * A property is the same: $this->db->query() in a trait runs as every class
 * that uses the trait, and on a class with no $db it dies with "Call to a
 * member function query() on null".
 *
 * HOW IT RESOLVES
 * ===============
 * The sources (php/src/*.php and php/src/lib/*.php, what deploy.sh ships)
 * are tokenized, so comments, strings and heredocs are not code: the monitor
 * page's JavaScript `function flushStale()` is not a PHP method. A class has
 * its own methods, those of every trait it uses (recursively, with `as`
 * aliases and `insteadof`), and its parent's that are not private (a class
 * in php/src, or a built-in one by reflection). As in PHP, a concrete method
 * implements an abstract one of the same name, whichever trait or parent
 * each comes from. A class's properties are found the same way: its own
 * (promoted constructor parameters included), its traits', and its
 * parent's that are not private. Every call in a class's own body and in the
 * body of every trait it uses, recursively, is resolved on THAT class:
 *
 *   $this->m(), $this?->m(), $this::m(), self::m(), static::m(),
 *   [$this, 'm'], array($this, 'm'), [self::class, 'm'], [static::class, 'm'],
 *   [__CLASS__, 'm'], 'self::m', 'static::m'
 *       m must be a method of the class;
 *   parent::m(), [parent::class, 'm'], 'parent::m'
 *       m must be a method of the class's parent, not private;
 *   $this->p->m(), $this->p?->m(), $this->p::m(), [$this->p, 'm'],
 *   self::$p->m(), static::$p->m(), $this::$p->m()
 *       p must be a property of the class (one that is only ever assigned,
 *       never declared, is not); when it is declared with a class type
 *       (Storage's PDO $db, HttpApi's Storage $storage), m must be a method
 *       of that class, public unless it is the class itself;
 *   Name::m(), [Name::class, 'm'], 'Name::m' (a string that is exactly that)
 *       the class must exist, in php/src or built in, and have m, public
 *       unless called from inside it. A class name in a string is fully
 *       qualified, as PHP reads it.
 *
 * A method_exists() guard does not make a call resolve: on a class without
 * the method the guarded line never runs. A concrete class must implement
 * every abstract method it composes.
 *
 * WHAT IT CANNOT CHECK
 * ====================
 * Each of these is listed under Warnings as NOT CHECKED and counted on the
 * summary line. None counts as resolved and none fails the check;
 * tests/static_check_methods_test.php requires php/src to have none.
 *   - A name decided at run time: $this->$name(), $this->{...}(),
 *     self::$name(), $this->p->$name(), [$this, 'parent::m'].
 *   - A call on a property declared without a class type (or with a union
 *     of types), or on a property not declared in a class that has __get().
 *   - Every call in a closure that is rebound to another object or scope:
 *     one passed straight to Closure::bind(), one written in parentheses
 *     before ->bindTo() or ->call(), or one assigned to a variable that the
 *     same class body passes to Closure::bind() or calls ->bindTo() or
 *     ->call() on.
 *   - A rebinding of a closure it cannot see, whose calls were therefore
 *     resolved on the class whose body holds it: any other Closure::bind()
 *     or ->bindTo(), and ->call() on a property declared \Closure. Any other
 *     ->call() is read as an ordinary method call: it is a common name.
 * Not read at all, because PHP picks their receiver at run time: calls on a
 * local variable ($api->handle()), on what a call returns, and on an object
 * or class reached any way but $this, self, static, parent, a property of
 * $this or a class's own name. On no call does it check the number of
 * arguments, or that a method called statically is static.
 *
 * Warnings, which do not fail the check: the calls above; a trait no class
 * uses (nothing composes it, so its calls resolve on nothing); and a private
 * method that nothing in any class composing it calls (one of a trait no
 * class uses is not listed again).
 *
 * deploy.sh runs this and greps the summary line for "Undefined: 0".
 * tests/static_check_methods_test.php checks this checker on fixtures,
 * b6c7809's shape included, and on php/src.
 *
 * Run: php php/tests/static_check_methods.php [src-dir]
 *      php php/tests/static_check_methods.php --methods [src-dir]   (each class's methods, as JSON)
 */

const SCALAR_TYPES = [
    'array', 'bool', 'callable', 'false', 'float', 'int', 'iterable', 'mixed',
    'never', 'null', 'object', 'string', 'true', 'void', 'self', 'static', 'parent',
];
const MODIFIERS = [T_PUBLIC, T_PROTECTED, T_PRIVATE, T_STATIC, T_ABSTRACT, T_FINAL, T_READONLY, T_VAR];
const NAME_TOKENS = [T_STRING, T_NAME_QUALIFIED, T_NAME_FULLY_QUALIFIED, T_NAME_RELATIVE];
const OBJECT_OPERATORS = [T_OBJECT_OPERATOR, T_NULLSAFE_OBJECT_OPERATOR];
const IDENTIFIER = '[A-Za-z_\x80-\xff][A-Za-z0-9_\x80-\xff]*';
/** A string literal that is exactly [\]Name[\Name...]::method: a callable. */
const STRING_CALLABLE = '/^\\\\?((?:' . IDENTIFIER . '\\\\)*' . IDENTIFIER . ')::(' . IDENTIFIER . ')$/';

/** Index of the next token after $i that is code, or -1. */
function nextCode(array $tokens, int $i): int
{
    for ($j = $i + 1, $n = count($tokens); $j < $n; $j++) {
        if (!$tokens[$j]->isIgnorable()) {
            return $j;
        }
    }
    return -1;
}

/** Index of the last token before $i that is code, or -1. */
function prevCode(array $tokens, int $i): int
{
    for ($j = $i - 1; $j >= 0; $j--) {
        if (!$tokens[$j]->isIgnorable()) {
            return $j;
        }
    }
    return -1;
}

/** A method or property name: after `function`, `->` or `::` PHP takes keywords too (`list`). */
function isIdentifier(?PhpToken $t): bool
{
    return $t !== null && preg_match('/^' . IDENTIFIER . '$/', $t->text) === 1;
}

function tokenAt(array $tokens, int $i): ?PhpToken
{
    return $i >= 0 ? $tokens[$i] : null;
}

/** A class name as written, resolved against the file's namespace and imports. */
function resolveName(string $name, string $namespace, array $imports): string
{
    if ($name[0] === '\\') {
        return substr($name, 1);
    }
    if (str_starts_with(strtolower($name), 'namespace\\')) {
        return ltrim($namespace . '\\' . substr($name, 10), '\\');
    }
    $first = strtolower(explode('\\', $name)[0]);
    if (isset($imports[$first])) {
        $rest = substr($name, strlen($first));
        return $imports[$first] . $rest;
    }
    return ltrim($namespace . '\\' . $name, '\\');
}

/** The index of the token that closes the bracket opened at $open. */
function closingIndex(array $tokens, int $open): int
{
    $pairs = ['(' => ')', '[' => ']', '{' => '}'];
    $want = $pairs[$tokens[$open]->text];
    $depth = 0;
    for ($j = $open, $n = count($tokens); $j < $n; $j++) {
        $text = $tokens[$j]->text;
        if ($text === $tokens[$open]->text || ($want === '}' && ($tokens[$j]->is(T_CURLY_OPEN) || $tokens[$j]->is(T_DOLLAR_OPEN_CURLY_BRACES)))) {
            $depth++;
        } elseif ($text === $want) {
            $depth--;
            if ($depth === 0) {
                return $j;
            }
        }
    }
    return $n - 1;
}

/** The index of the '(' that the ')' at $close closes. */
function openingParen(array $tokens, int $close): int
{
    $depth = 0;
    for ($j = $close; $j >= 0; $j--) {
        if ($tokens[$j]->text === ')') {
            $depth++;
        } elseif ($tokens[$j]->text === '(') {
            $depth--;
            if ($depth === 0) {
                return $j;
            }
        }
    }
    return 0;
}

/** The value of a string literal that interpolates nothing. */
function stringValue(PhpToken $t): string
{
    $text = ltrim($t->text, 'bB');
    $inner = substr($text, 1, -1);
    return $text[0] === "'" ? strtr($inner, ['\\\\' => '\\', "\\'" => "'"]) : stripcslashes($inner);
}

/**
 * A callable array [X, 'm'] or array(X, 'm'), where X is the tokens $first
 * to $last, written $written: the method, how the array is written, and the
 * string's line and index; or null.
 */
function callableArray(array $tokens, int $first, int $last, string $written): ?array
{
    $open = prevCode($tokens, $first);
    if ($open < 0) {
        return null;
    }
    if ($tokens[$open]->text === '[') {
        [$opener, $closer] = ['[', ']'];
    } elseif ($tokens[$open]->text === '(' && ($keyword = prevCode($tokens, $open)) >= 0 && $tokens[$keyword]->is(T_ARRAY)) {
        [$opener, $closer] = ['array(', ')'];
    } else {
        return null;
    }
    $comma = nextCode($tokens, $last);
    $string = $comma >= 0 && $tokens[$comma]->text === ',' ? nextCode($tokens, $comma) : -1;
    $end = $string >= 0 ? nextCode($tokens, $string) : -1;
    if ($end < 0 || !$tokens[$string]->is(T_CONSTANT_ENCAPSED_STRING) || $tokens[$end]->text !== $closer) {
        return null;
    }
    $method = stringValue($tokens[$string]);
    return [
        'method' => $method,
        'identifier' => preg_match('/^' . IDENTIFIER . '$/', $method) === 1,
        'text' => $opener . $written . ', ' . $tokens[$string]->text . $closer,
        'line' => $tokens[$string]->line,
        'index' => $string,
    ];
}

/**
 * The index of the last token of the closure or arrow function whose
 * `function` or `fn` is at $at; $at itself when it is a named function.
 */
function closureEnd(array $tokens, int $at): int
{
    $open = nextCode($tokens, $at);
    if ($open >= 0 && $tokens[$open]->text === '&') {
        $open = nextCode($tokens, $open);
    }
    if ($open < 0 || $tokens[$open]->text !== '(') {
        return $at;
    }
    $j = closingIndex($tokens, $open);
    if ($tokens[$at]->is(T_FUNCTION)) {
        // function (...) [use (...)] [: type] { ... }
        for ($j = nextCode($tokens, $j); $j >= 0 && $tokens[$j]->text !== '{'; $j = nextCode($tokens, $j)) {
            if ($tokens[$j]->text === '(') {
                $j = closingIndex($tokens, $j);
            }
        }
        return $j < 0 ? count($tokens) - 1 : closingIndex($tokens, $j);
    }
    // fn (...) [: type] => expression, which ends before the first `,` or `;`
    // at its own depth, or before a closing bracket it did not open
    for ($j = nextCode($tokens, $j); $j >= 0 && !$tokens[$j]->is(T_DOUBLE_ARROW); $j = nextCode($tokens, $j)) {
    }
    if ($j < 0) {
        return count($tokens) - 1;
    }
    $depth = 0;
    for ($k = nextCode($tokens, $j); $k >= 0; $k = nextCode($tokens, $k)) {
        $text = $tokens[$k]->text;
        if (in_array($text, ['(', '[', '{'], true) || $tokens[$k]->is([T_CURLY_OPEN, T_DOLLAR_OPEN_CURLY_BRACES, T_ATTRIBUTE])) {
            $depth++;
        } elseif (in_array($text, [')', ']', '}'], true)) {
            if ($depth === 0) {
                return prevCode($tokens, $k);
            }
            $depth--;
        } elseif ($depth === 0 && ($text === ',' || $text === ';')) {
            return prevCode($tokens, $k);
        }
    }
    return count($tokens) - 1;
}

/**
 * The class a property or parameter at $var is declared with, or null when
 * it has no type, a scalar one, or a union or intersection.
 */
function declaredType(array $tokens, int $var, string $namespace, array $imports): ?string
{
    $b = prevCode($tokens, $var);
    if ($b < 0 || !$tokens[$b]->is(NAME_TOKENS)) {
        return null;
    }
    $before = prevCode($tokens, $b);
    if ($before >= 0 && in_array($tokens[$before]->text, ['|', '&', '('], true)) {
        return null;
    }
    $name = $tokens[$b]->text;
    if (in_array(strtolower($name), SCALAR_TYPES, true)) {
        return null;
    }
    return resolveName($name, $namespace, $imports);
}

/** A property declared at $var, read back over its type and modifiers. */
function propertyDeclaration(array $tokens, int $var, string $namespace, array $imports): array
{
    $visibility = 'public';
    $static = false;
    for ($b = prevCode($tokens, $var); $b >= 0; $b = prevCode($tokens, $b)) {
        $t = $tokens[$b];
        if ($t->is([T_PUBLIC, T_PROTECTED, T_PRIVATE])) {
            $visibility = strtolower($t->text);
        } elseif ($t->is(T_STATIC)) {
            $static = true;
        } elseif (!$t->is(MODIFIERS) && !$t->is(NAME_TOKENS) && !$t->is([T_ARRAY, T_CALLABLE])
            && !in_array($t->text, ['?', '|', '&', '(', ')'], true)) {
            break;
        }
    }
    return ['type' => declaredType($tokens, $var, $namespace, $imports), 'visibility' => $visibility, 'static' => $static];
}

/**
 * One file's class-likes (with their methods, properties, trait uses and
 * calls), the calls made outside any class, and notes on what cannot be
 * followed.
 */
function scanFile(string $code, string $file): array
{
    $tokens = PhpToken::tokenize($code);
    $n = count($tokens);
    $namespace = '';
    $imports = [];
    $classLikes = [];
    $fileCalls = [];
    $notes = [];
    $scopes = [];      // open class-like bodies: [key, bodyDepth]
    $pending = null;   // key of a class-like whose body opens at the next '{'
    $depth = 0;
    $property = null;  // the property statement being read, for `private int $a, $b;`
    $closures = [];    // index of a closure's `function` or `fn` => index of its last token
    $assigned = [];    // class-like key ('' outside one) => variable => closures assigned to it
    $rebinds = [];     // each Closure::bind(), ->bindTo() and ->call()

    $addCall = static function (array $call) use (&$scopes, &$classLikes, &$fileCalls, $file): void {
        $call['file'] = $file;
        if ($scopes === []) {
            $fileCalls[] = $call;
        } else {
            $classLikes[end($scopes)[0]]['calls'][] = $call;
        }
    };

    // After `$this->p` or `self::$p` (its last token at $at): a call on p, if
    // one follows. $dynamic: p's name is decided at run time.
    $propertyCall = static function (int $at, string $property, string $written, bool $dynamic = false) use ($tokens, $addCall): void {
        $op = nextCode($tokens, $at);
        if ($op < 0 || !($tokens[$op]->is(OBJECT_OPERATORS) || $tokens[$op]->is(T_DOUBLE_COLON))) {
            return;
        }
        $m = nextCode($tokens, $op);
        if ($m < 0) {
            return;
        }
        $after = nextCode($tokens, $tokens[$m]->text === '{' ? closingIndex($tokens, $m) : $m);
        if ($after < 0 || $tokens[$after]->text !== '(') {
            return; // a property of p, a constant, ::class: no call on p
        }
        $shown = $written . $tokens[$op]->text . ($tokens[$m]->text === '{' ? '{...}' : $tokens[$m]->text) . '()';
        if (isIdentifier($tokens[$m]) && !$dynamic) {
            $addCall(['kind' => 'property', 'property' => $property, 'method' => $tokens[$m]->text, 'text' => $shown, 'line' => $tokens[$m]->line, 'index' => $m]);
        } elseif (isIdentifier($tokens[$m]) || $tokens[$m]->is(T_VARIABLE) || $tokens[$m]->text === '{') {
            $addCall(['kind' => 'dynamic', 'text' => $shown, 'line' => $tokens[$m]->line, 'index' => $m]);
        }
    };

    for ($i = 0; $i < $n; $i++) {
        $t = $tokens[$i];
        if ($t->isIgnorable()) {
            continue;
        }
        $scope = $scopes === [] ? null : end($scopes);
        $scopeKey = $scope === null ? '' : $scope[0];
        $atBody = $scope !== null && $depth === $scope[1];

        if ($t->text === '{' || $t->is(T_CURLY_OPEN) || $t->is(T_DOLLAR_OPEN_CURLY_BRACES)) {
            $depth++;
            if ($pending !== null && $t->text === '{') {
                $scopes[] = [$pending, $depth];
                $pending = null;
            }
            continue;
        }
        if ($t->text === '}') {
            if ($scope !== null && $depth === $scope[1]) {
                array_pop($scopes);
            }
            $depth--;
            continue;
        }
        if ($atBody && $t->text === ';') {
            $property = null;
            continue;
        }

        if ($t->is(T_NAMESPACE)) {
            $j = nextCode($tokens, $i);
            if ($j >= 0 && $tokens[$j]->is(NAME_TOKENS)) {
                $namespace = $tokens[$j]->text;
                $imports = [];
            } elseif ($j >= 0 && $tokens[$j]->text === '{') {
                $namespace = '';
                $imports = [];
            }
            continue;
        }

        if ($t->is(T_USE)) {
            $j = nextCode($tokens, $i);
            if ($j < 0 || $tokens[$j]->text === '(') {
                continue; // a closure's use (...)
            }
            if ($atBody) {
                // Trait use, with an optional adaptation block.
                $key = $scope[0];
                for (; $j >= 0 && $tokens[$j]->text !== ';' && $tokens[$j]->text !== '{'; $j = nextCode($tokens, $j)) {
                    if ($tokens[$j]->is(NAME_TOKENS)) {
                        $classLikes[$key]['uses'][] = resolveName($tokens[$j]->text, $namespace, $imports);
                    }
                }
                if ($j >= 0 && $tokens[$j]->text === '{') {
                    $close = closingIndex($tokens, $j);
                    $statement = [];
                    for ($k = $j + 1; $k < $close; $k++) {
                        if ($tokens[$k]->isIgnorable()) {
                            continue;
                        }
                        if ($tokens[$k]->text !== ';') {
                            $statement[] = $tokens[$k];
                            continue;
                        }
                        // [Trait::]method as [visibility] [alias]  |  Trait::method insteadof Other[, ...]
                        $asAt = null;
                        $insteadofAt = null;
                        foreach ($statement as $s => $st) {
                            if ($st->is(T_AS)) {
                                $asAt = $s;
                            } elseif ($st->is(T_INSTEADOF)) {
                                $insteadofAt = $s;
                            }
                        }
                        if ($insteadofAt !== null && $insteadofAt >= 3) {
                            $others = [];
                            foreach (array_slice($statement, $insteadofAt + 1) as $st) {
                                if ($st->is(NAME_TOKENS)) {
                                    $others[] = resolveName($st->text, $namespace, $imports);
                                }
                            }
                            $classLikes[$key]['adaptations'][] = [
                                'trait' => resolveName($statement[$insteadofAt - 3]->text, $namespace, $imports),
                                'method' => $statement[$insteadofAt - 1]->text,
                                'alias' => null,
                                'visibility' => null,
                                'insteadof' => $others,
                            ];
                        } elseif ($asAt !== null) {
                            $source = $statement[$asAt - 1]->text;
                            $trait = $asAt >= 3 ? resolveName($statement[$asAt - 3]->text, $namespace, $imports) : null;
                            $visibility = null;
                            $alias = null;
                            foreach (array_slice($statement, $asAt + 1) as $st) {
                                if ($st->is([T_PUBLIC, T_PROTECTED, T_PRIVATE])) {
                                    $visibility = strtolower($st->text);
                                } elseif (isIdentifier($st)) {
                                    $alias = $st->text;
                                }
                            }
                            $classLikes[$key]['adaptations'][] = ['trait' => $trait, 'method' => $source, 'alias' => $alias, 'visibility' => $visibility, 'insteadof' => []];
                        }
                        $statement = [];
                    }
                    $i = $close;
                } elseif ($j < 0) {
                    break; // no ';': nothing more to read
                } else {
                    $i = $j;
                }
                continue;
            }
            if ($scope === null) {
                // A file-level import: use A\B [as C], ...; or use A\{B, C as D};
                if ($tokens[$j]->is(T_FUNCTION) || $tokens[$j]->is(T_CONST)) {
                    continue;
                }
                $prefix = '';
                $last = null;
                for (; $j >= 0 && $tokens[$j]->text !== ';'; $j = nextCode($tokens, $j)) {
                    $tk = $tokens[$j];
                    if ($tk->is(NAME_TOKENS) && $last === null) {
                        $last = ltrim($prefix . $tk->text, '\\');
                    } elseif ($tk->is(T_NS_SEPARATOR) && $last !== null) {
                        $prefix = $last . '\\';
                        $last = null;
                    } elseif ($tk->is(T_AS)) {
                        $alias = $tokens[nextCode($tokens, $j)]->text;
                        $imports[strtolower($alias)] = (string) $last;
                        $last = null;
                        $j = nextCode($tokens, $j);
                    } elseif ($tk->text === ',' || $tk->text === '}') {
                        if ($last !== null) {
                            $parts = explode('\\', $last);
                            $imports[strtolower(end($parts))] = $last;
                        }
                        $last = null;
                        if ($tk->text === '}') {
                            $prefix = '';
                        }
                    }
                }
                if ($last !== null) {
                    $parts = explode('\\', $last);
                    $imports[strtolower(end($parts))] = $last;
                }
                if ($j < 0) {
                    break; // no ';': nothing more to read
                }
                $i = $j;
                continue;
            }
            continue;
        }

        if ($t->is([T_CLASS, T_TRAIT, T_INTERFACE, T_ENUM])) {
            $p = prevCode($tokens, $i);
            if ($p >= 0 && $tokens[$p]->is(T_DOUBLE_COLON)) {
                continue; // Name::class
            }
            $anonymous = $p >= 0 && $tokens[$p]->is(T_NEW);
            $j = nextCode($tokens, $i);
            if ($anonymous) {
                $name = 'class@anonymous ' . $file . ':' . $t->line;
                if ($j >= 0 && $tokens[$j]->text === '(') {
                    $j = nextCode($tokens, closingIndex($tokens, $j));
                }
            } else {
                if (!isIdentifier(tokenAt($tokens, $j))) {
                    continue;
                }
                $name = ltrim($namespace . '\\' . $tokens[$j]->text, '\\');
                $j = nextCode($tokens, $j);
            }
            $abstract = false;
            for ($b = prevCode($tokens, $i); $b >= 0 && $tokens[$b]->is([T_ABSTRACT, T_FINAL, T_READONLY]); $b = prevCode($tokens, $b)) {
                $abstract = $abstract || $tokens[$b]->is(T_ABSTRACT);
            }
            $extends = null;
            $mode = null;
            for (; $j >= 0 && $tokens[$j]->text !== '{'; $j = nextCode($tokens, $j)) {
                if ($tokens[$j]->is(T_EXTENDS)) {
                    $mode = 'extends';
                } elseif ($tokens[$j]->is(T_IMPLEMENTS)) {
                    $mode = 'implements';
                } elseif ($mode === 'extends' && $extends === null && $tokens[$j]->is(NAME_TOKENS)) {
                    $extends = resolveName($tokens[$j]->text, $namespace, $imports);
                }
            }
            if ($j < 0) {
                break; // a header with no body: nothing more to read
            }
            $key = strtolower($name);
            $classLikes[$key] = [
                'name' => $name,
                'kind' => strtolower($t->text),
                'file' => $file,
                'line' => $t->line,
                'abstract' => $abstract || $t->is(T_INTERFACE),
                'extends' => $t->is(T_INTERFACE) ? null : $extends,
                'uses' => [],
                'adaptations' => [],
                'methods' => [],
                'properties' => [],
                'calls' => [],
            ];
            $pending = $key;
            $i = $j - 1; // the main loop opens the body at '{'
            continue;
        }

        if ($atBody && $t->is(T_FUNCTION)) {
            $visibility = 'public';
            $static = false;
            $abstract = $classLikes[$scope[0]]['kind'] === 'interface';
            for ($b = prevCode($tokens, $i); $b >= 0 && $tokens[$b]->is(MODIFIERS); $b = prevCode($tokens, $b)) {
                if ($tokens[$b]->is([T_PUBLIC, T_PROTECTED, T_PRIVATE])) {
                    $visibility = strtolower($tokens[$b]->text);
                }
                $static = $static || $tokens[$b]->is(T_STATIC);
                $abstract = $abstract || $tokens[$b]->is(T_ABSTRACT);
            }
            $j = nextCode($tokens, $i);
            if ($j >= 0 && $tokens[$j]->text === '&') {
                $j = nextCode($tokens, $j);
            }
            if (!isIdentifier(tokenAt($tokens, $j))) {
                continue;
            }
            $method = $tokens[$j]->text;
            $classLikes[$scope[0]]['methods'][strtolower($method)] = [
                'name' => $method,
                'visibility' => $visibility,
                'static' => $static,
                'abstract' => $abstract,
                'file' => $file,
                'line' => $tokens[$j]->line,
                'origin' => $classLikes[$scope[0]]['name'],
            ];
            $open = nextCode($tokens, $j);
            if ($open < 0 || $tokens[$open]->text !== '(') {
                continue;
            }
            $close = closingIndex($tokens, $open);
            if (strtolower($method) === '__construct') {
                // Promoted constructor parameters are properties.
                for ($k = $open + 1; $k < $close; $k++) {
                    if (!$tokens[$k]->is(T_VARIABLE)) {
                        continue;
                    }
                    $promoted = null;
                    for ($b = prevCode($tokens, $k); $b > $open && !in_array($tokens[$b]->text, [',', '('], true); $b = prevCode($tokens, $b)) {
                        if ($tokens[$b]->is([T_PUBLIC, T_PROTECTED, T_PRIVATE])) {
                            $promoted = strtolower($tokens[$b]->text);
                        } elseif ($tokens[$b]->is(T_READONLY)) {
                            $promoted ??= 'public';
                        }
                    }
                    if ($promoted !== null) {
                        $classLikes[$scope[0]]['properties'][substr($tokens[$k]->text, 1)] = [
                            'type' => declaredType($tokens, $k, $namespace, $imports),
                            'visibility' => $promoted,
                            'static' => false,
                            'origin' => $classLikes[$scope[0]]['name'],
                            'file' => $file,
                            'line' => $tokens[$k]->line,
                        ];
                    }
                }
            }
            $i = $close; // parameters hold no calls; the body is read by the main loop
            continue;
        }

        if ($atBody && $t->is(T_VARIABLE)) {
            $p = prevCode($tokens, $i);
            if ($property === null || $p < 0 || $tokens[$p]->text !== ',') {
                $property = propertyDeclaration($tokens, $i, $namespace, $imports);
            }
            $classLikes[$scope[0]]['properties'][substr($t->text, 1)] = $property + [
                'origin' => $classLikes[$scope[0]]['name'],
                'file' => $file,
                'line' => $t->line,
            ];
            continue;
        }

        // ── Closures, and what rebinds them ───────────────────────────────
        if (!$atBody && $t->is([T_FUNCTION, T_FN])) {
            $end = closureEnd($tokens, $i);
            if ($end !== $i) {
                $closures[$i] = $end;
                // $f = function () {...};  $f = static fn () => ...;
                $b = prevCode($tokens, $i);
                if ($b >= 0 && $tokens[$b]->is(T_STATIC)) {
                    $b = prevCode($tokens, $b);
                }
                $v = $b >= 0 && $tokens[$b]->text === '=' ? prevCode($tokens, $b) : -1;
                $before = $v >= 0 ? prevCode($tokens, $v) : -1;
                if ($v >= 0 && $tokens[$v]->is(T_VARIABLE) && $tokens[$v]->text !== '$this'
                    && ($before < 0 || !($tokens[$before]->is(OBJECT_OPERATORS) || $tokens[$before]->is(T_DOUBLE_COLON)))) {
                    $assigned[$scopeKey][$tokens[$v]->text][] = $i;
                }
            }
            continue;
        }

        if ($t->is(OBJECT_OPERATORS)) {
            // (function () {...})->bindTo(...), $f->call(...): a closure, rebound.
            // A property's ->bindTo() or ->call() is read by its type, below.
            $m = nextCode($tokens, $i);
            $after = $m >= 0 ? nextCode($tokens, $m) : -1;
            $method = $m >= 0 ? strtolower($tokens[$m]->text) : '';
            $receiver = prevCode($tokens, $i);
            $before = $receiver >= 0 ? prevCode($tokens, $receiver) : -1;
            $variable = $receiver >= 0 && $tokens[$receiver]->is(T_VARIABLE) && $tokens[$receiver]->text !== '$this'
                && ($before < 0 || !($tokens[$before]->is(OBJECT_OPERATORS) || $tokens[$before]->is(T_DOUBLE_COLON)));
            if (($method === 'bindto' || $method === 'call') && $after >= 0 && $tokens[$after]->text === '('
                && ($variable || ($receiver >= 0 && $tokens[$receiver]->text === ')'))) {
                $rebind = ['closure' => null, 'variable' => $variable ? $tokens[$receiver]->text : null, 'scope' => $scopeKey,
                    'where' => $file . ':' . $tokens[$m]->line, 'text' => '->' . $tokens[$m]->text . '()',
                    // call() is a common method name: only a closure this check can see makes it a rebinding
                    'certain' => $method === 'bindto'];
                if (!$variable) {
                    $open = openingParen($tokens, $receiver);
                    $called = prevCode($tokens, $open);
                    $first = nextCode($tokens, $open);
                    if ($first >= 0 && $tokens[$first]->is(T_STATIC)) {
                        $first = nextCode($tokens, $first);
                    }
                    $isArguments = $called >= 0 && ($tokens[$called]->is(NAME_TOKENS) || $tokens[$called]->is(T_VARIABLE)
                        || in_array($tokens[$called]->text, [')', ']'], true));
                    if (!$isArguments && $first >= 0 && $tokens[$first]->is([T_FUNCTION, T_FN])) {
                        $rebind['closure'] = $first;
                    }
                }
                $rebinds[] = $rebind;
            }
            continue;
        }

        // ── Calls ──────────────────────────────────────────────────────────
        if ($t->is(T_VARIABLE) && $t->text === '$this') {
            $op = nextCode($tokens, $i);
            if ($op < 0 || !($tokens[$op]->is(OBJECT_OPERATORS) || $tokens[$op]->is(T_DOUBLE_COLON))) {
                // [$this, 'm'], array($this, 'm')
                $callable = callableArray($tokens, $i, $i, '$this');
                if ($callable !== null) {
                    $addCall($callable['identifier']
                        ? ['kind' => 'this', 'method' => $callable['method'], 'text' => $callable['text'], 'line' => $callable['line'], 'index' => $callable['index']]
                        : ['kind' => 'dynamic', 'text' => $callable['text'], 'line' => $callable['line'], 'index' => $callable['index']]);
                }
                continue;
            }
            $static = $tokens[$op]->is(T_DOUBLE_COLON);
            $written = '$this' . $tokens[$op]->text;
            $m = nextCode($tokens, $op);
            if ($m < 0) {
                continue;
            }
            $member = $tokens[$m];
            if ($member->is(T_VARIABLE) || $member->text === '{') {
                $end = $member->text === '{' ? closingIndex($tokens, $m) : $m;
                $after = nextCode($tokens, $end);
                $shown = $written . ($member->text === '{' ? '{...}' : $member->text);
                if ($after >= 0 && $tokens[$after]->text === '(') {
                    // $this->$name(), $this->{...}(), $this::$name()
                    $addCall(['kind' => 'dynamic', 'text' => $shown . '()', 'line' => $member->line, 'index' => $m]);
                } elseif ($static && $member->is(T_VARIABLE)) {
                    $propertyCall($m, substr($member->text, 1), $shown); // $this::$p->m()
                } else {
                    $propertyCall($end, '', $shown, true); // $this->$name->m()
                }
                continue;
            }
            if (!isIdentifier($member)) {
                continue;
            }
            $after = nextCode($tokens, $m);
            if ($after >= 0 && $tokens[$after]->text === '(') {
                // $this->m(), $this?->m(), $this::m()
                $addCall(['kind' => $static ? 'static' : 'this', 'method' => $member->text, 'text' => $written . $member->text . '()', 'line' => $member->line, 'index' => $m]);
            } elseif (!$static) {
                // $this->p->m(), $this->p?->m(), $this->p::m()
                $propertyCall($m, $member->text, $written . $member->text);
                // [$this->p, 'm']
                $callable = callableArray($tokens, $i, $m, $written . $member->text);
                if ($callable !== null) {
                    $addCall($callable['identifier']
                        ? ['kind' => 'property', 'property' => $member->text, 'method' => $callable['method'], 'text' => $callable['text'], 'line' => $callable['line'], 'index' => $callable['index']]
                        : ['kind' => 'dynamic', 'text' => $callable['text'], 'line' => $callable['line'], 'index' => $callable['index']]);
                }
            }
            continue;
        }

        if ($t->is(T_CLASS_C)) {
            // [__CLASS__, 'm']
            $callable = callableArray($tokens, $i, $i, '__CLASS__');
            if ($callable !== null) {
                $addCall($callable['identifier']
                    ? ['kind' => 'self', 'class' => null, 'method' => $callable['method'], 'text' => $callable['text'], 'line' => $callable['line'], 'index' => $callable['index']]
                    : ['kind' => 'dynamic', 'text' => $callable['text'], 'line' => $callable['line'], 'index' => $callable['index']]);
            }
            continue;
        }

        if ($t->is(T_CONSTANT_ENCAPSED_STRING)) {
            // 'self::m', 'Name::m': a string that is exactly a static callable
            if (preg_match(STRING_CALLABLE, stringValue($t), $sm) === 1) {
                $lower = strtolower($sm[1]);
                $kind = in_array($lower, ['self', 'static', 'parent'], true) ? $lower : 'class';
                $addCall(['kind' => $kind, 'class' => $kind === 'class' ? $sm[1] : null, 'method' => $sm[2], 'text' => $t->text, 'line' => $t->line, 'index' => $i]);
            }
            continue;
        }

        if ($t->is(NAME_TOKENS) || $t->is(T_STATIC)) {
            $colons = nextCode($tokens, $i);
            if ($colons < 0 || !$tokens[$colons]->is(T_DOUBLE_COLON)) {
                continue;
            }
            $p = prevCode($tokens, $i);
            if ($p >= 0 && ($tokens[$p]->is(OBJECT_OPERATORS) || $tokens[$p]->is([T_DOUBLE_COLON, T_FUNCTION, T_CONST]))) {
                continue;
            }
            $m = nextCode($tokens, $colons);
            if ($m < 0) {
                continue;
            }
            $after = nextCode($tokens, $m);
            $lower = strtolower($t->text);
            $kind = match (true) {
                $t->is(T_STATIC) => 'static',
                $lower === 'self' => 'self',
                $lower === 'parent' => 'parent',
                default => 'class',
            };
            $class = $kind === 'class' ? resolveName($t->text, $namespace, $imports) : null;
            $written = $t->text . '::';
            if ($tokens[$m]->is(T_CLASS)) {
                // [Name::class, 'm'], array(self::class, 'm')
                $callable = callableArray($tokens, $i, $m, $written . 'class');
                if ($callable !== null) {
                    $addCall($callable['identifier']
                        ? ['kind' => $kind, 'class' => $class, 'method' => $callable['method'], 'text' => $callable['text'], 'line' => $callable['line'], 'index' => $callable['index']]
                        : ['kind' => 'dynamic', 'text' => $callable['text'], 'line' => $callable['line'], 'index' => $callable['index']]);
                }
                continue;
            }
            if ($tokens[$m]->is(T_VARIABLE)) {
                if ($kind === 'class') {
                    continue; // another class's static property: not $this's
                }
                if ($after >= 0 && $tokens[$after]->text === '(') {
                    // self::$name(): a static method whose name is in $name
                    $addCall(['kind' => 'dynamic', 'text' => $written . $tokens[$m]->text . '()', 'line' => $tokens[$m]->line, 'index' => $m]);
                } else {
                    $propertyCall($m, substr($tokens[$m]->text, 1), $written . $tokens[$m]->text); // self::$p->m()
                }
                continue;
            }
            if (isIdentifier($tokens[$m]) && $after >= 0 && $tokens[$after]->text === '(') {
                $addCall(['kind' => $kind, 'class' => $class, 'method' => $tokens[$m]->text, 'text' => $written . $tokens[$m]->text . '()', 'line' => $tokens[$m]->line, 'index' => $m]);
                if ($kind === 'class' && strtolower((string) $class) === 'closure' && strtolower($tokens[$m]->text) === 'bind') {
                    // Closure::bind(<closure>, $newThis, $newScope)
                    $rebind = ['closure' => null, 'variable' => null, 'scope' => $scopeKey,
                        'where' => $file . ':' . $tokens[$m]->line, 'text' => $written . $tokens[$m]->text . '()', 'certain' => true];
                    $first = nextCode($tokens, $after);
                    if ($first >= 0 && $tokens[$first]->is(T_STATIC)) {
                        $first = nextCode($tokens, $first);
                    }
                    $comma = $first >= 0 ? nextCode($tokens, $first) : -1;
                    if ($first >= 0 && $tokens[$first]->is([T_FUNCTION, T_FN])) {
                        $rebind['closure'] = $first;
                    } elseif ($first >= 0 && $tokens[$first]->is(T_VARIABLE) && $comma >= 0 && $tokens[$comma]->text === ',') {
                        $rebind['variable'] = $tokens[$first]->text;
                    }
                    $rebinds[] = $rebind;
                }
            }
            continue;
        }
    }

    // A rebound closure runs as whatever object and scope it is given: its
    // calls cannot be resolved on the class whose body holds it.
    $ranges = [];
    foreach ($rebinds as $rebind) {
        $starts = $rebind['closure'] !== null
            ? [$rebind['closure']]
            : ($rebind['variable'] !== null ? ($assigned[$rebind['scope']][$rebind['variable']] ?? []) : []);
        if ($starts === [] && !$rebind['certain']) {
            continue; // ->call() on something that is not a closure this check can see
        }
        if ($starts === []) {
            $notes[] = sprintf('%s at %s rebinds a closure this check cannot follow; the calls in that closure were resolved on the class whose body holds it', $rebind['text'], $rebind['where']);
            continue;
        }
        foreach ($starts as $start) {
            $ranges[] = [$start, $closures[$start] ?? $start, $rebind['where']];
        }
    }
    if ($ranges !== []) {
        $mark = static function (array $call) use ($ranges): array {
            foreach ($ranges as [$start, $end, $where]) {
                if ($call['index'] >= $start && $call['index'] <= $end) {
                    $call['rebound'] ??= $where;
                }
            }
            return $call;
        };
        foreach ($classLikes as $key => $info) {
            $classLikes[$key]['calls'] = array_map($mark, $info['calls']);
        }
        $fileCalls = array_map($mark, $fileCalls);
    }

    return [$classLikes, $fileCalls, $notes];
}

// ─── Read the sources ──────────────────────────────────────────────────────

$args = array_slice($argv, 1);
$dumpMethods = in_array('--methods', $args, true);
$args = array_values(array_diff($args, ['--methods']));
$srcDir = rtrim($args[0] ?? (__DIR__ . '/../src'), '/');
$files = array_merge(glob($srcDir . '/*.php') ?: [], glob($srcDir . '/lib/*.php') ?: []);
if ($files === []) {
    echo "No php files under {$srcDir}\n\nUndefined: (nothing read)\n";
    exit(1);
}

$classLikes = [];
$fileCalls = [];
$notes = [];
foreach ($files as $path) {
    $rel = substr($path, strlen($srcDir) + 1);
    [$found, $calls, $fileNotes] = scanFile((string) file_get_contents($path), $rel);
    foreach ($found as $key => $info) {
        $classLikes[$key] = $info;
    }
    foreach ($calls as $call) {
        $fileCalls[] = $call;
    }
    foreach ($fileNotes as $note) {
        $notes[] = $note;
    }
}

// ─── What each class has ───────────────────────────────────────────────────

/** Every trait a class-like uses, recursively, in use order. */
function traitsOf(string $key, array $classLikes, array $seen = []): array
{
    $out = [];
    foreach ($classLikes[$key]['uses'] ?? [] as $trait) {
        $traitKey = strtolower($trait);
        if (isset($seen[$traitKey])) {
            continue;
        }
        $seen[$traitKey] = true;
        $out[$traitKey] = $trait;
        $out += traitsOf($traitKey, $classLikes, $seen + $out);
    }
    return $out;
}

/** Put $method in $into under $lower unless a method is there; a concrete one replaces an abstract one. */
function composeMethod(array &$into, string $lower, array $method): void
{
    if (!isset($into[$lower]) || ($into[$lower]['abstract'] && !$method['abstract'])) {
        $into[$lower] = $method;
    }
}

/**
 * The methods a class-like has: lowercase name => method. The class's own
 * win over its traits', which win over the parent's; a concrete method from
 * any of them implements an abstract one of the same name, as in PHP.
 */
function methodsOf(string $key, array $classLikes, array &$cache, array &$problems): array
{
    if (isset($cache[$key])) {
        return $cache[$key];
    }
    $cache[$key] = []; // a cycle resolves to nothing rather than recursing
    $info = $classLikes[$key];

    $fromTraits = [];
    foreach ($info['uses'] as $trait) {
        $traitKey = strtolower($trait);
        if (!isset($classLikes[$traitKey]) || $classLikes[$traitKey]['kind'] !== 'trait') {
            $problems[] = sprintf('%s uses %s, which is no trait in the sources (%s:%d)', $info['name'], $trait, $info['file'], $info['line']);
            continue;
        }
        foreach (methodsOf($traitKey, $classLikes, $cache, $problems) as $lower => $method) {
            composeMethod($fromTraits, $lower, $method);
        }
    }
    // T::m insteadof U: the class gets T's m.
    foreach ($info['adaptations'] as $adaptation) {
        if ($adaptation['insteadof'] === []) {
            continue;
        }
        $traitKey = strtolower((string) $adaptation['trait']);
        $chosen = isset($classLikes[$traitKey]) ? (methodsOf($traitKey, $classLikes, $cache, $problems)[strtolower($adaptation['method'])] ?? null) : null;
        if ($chosen === null) {
            $problems[] = sprintf('%s takes %s from %s, which has no such method (%s)', $info['name'], $adaptation['method'], $adaptation['trait'], $info['file']);
            continue;
        }
        $fromTraits[strtolower($adaptation['method'])] = $chosen;
    }
    // [T::]m as [visibility] [alias]
    foreach ($info['adaptations'] as $adaptation) {
        if ($adaptation['insteadof'] !== []) {
            continue;
        }
        $source = $fromTraits[strtolower($adaptation['method'])] ?? null;
        if ($adaptation['trait'] !== null && isset($classLikes[strtolower($adaptation['trait'])])) {
            $source = methodsOf(strtolower($adaptation['trait']), $classLikes, $cache, $problems)[strtolower($adaptation['method'])] ?? $source;
        }
        if ($source === null) {
            $problems[] = sprintf('%s adapts %s, which none of its traits has (%s)', $info['name'], $adaptation['method'], $info['file']);
            continue;
        }
        if ($adaptation['visibility'] !== null) {
            $source['visibility'] = $adaptation['visibility'];
        }
        if ($adaptation['alias'] !== null) {
            $fromTraits[strtolower($adaptation['alias'])] = $source;
        } else {
            $fromTraits[strtolower($adaptation['method'])] = $source;
        }
    }

    $methods = $info['methods'] + $fromTraits;

    if ($info['extends'] !== null) {
        foreach (inheritedMethods($info['extends'], $classLikes, $cache, $problems, $info) as $lower => $method) {
            composeMethod($methods, $lower, $method);
        }
    }

    return $cache[$key] = $methods;
}

/** A parent's methods a child can call: not private. */
function inheritedMethods(string $parent, array $classLikes, array &$cache, array &$problems, array $child): array
{
    $parentKey = strtolower($parent);
    if (isset($classLikes[$parentKey])) {
        $all = methodsOf($parentKey, $classLikes, $cache, $problems);
    } elseif (class_exists($parent)) {
        $all = [];
        foreach ((new ReflectionClass($parent))->getMethods() as $reflected) {
            $all[strtolower($reflected->getName())] = [
                'name' => $reflected->getName(),
                'visibility' => $reflected->isPrivate() ? 'private' : ($reflected->isProtected() ? 'protected' : 'public'),
                'static' => $reflected->isStatic(),
                'abstract' => $reflected->isAbstract(),
                'file' => '(built-in)',
                'line' => 0,
                'origin' => $reflected->getDeclaringClass()->getName(),
            ];
        }
    } else {
        $problems[] = sprintf('%s extends %s, which does not exist (%s:%d)', $child['name'], $parent, $child['file'], $child['line']);
        return [];
    }
    return array_filter($all, static fn (array $m): bool => $m['visibility'] !== 'private');
}

/**
 * The properties a class-like has: name => declaration. Its own win over its
 * traits', which win over the parent's that are not private.
 */
function propertiesOf(string $key, array $classLikes, array &$cache): array
{
    if (isset($cache[$key])) {
        return $cache[$key];
    }
    $cache[$key] = []; // a cycle resolves to nothing rather than recursing
    $info = $classLikes[$key];
    $properties = $info['properties'];
    foreach (array_keys(traitsOf($key, $classLikes)) as $traitKey) {
        $properties += $classLikes[$traitKey]['properties'] ?? [];
    }
    $parent = $info['extends'];
    $inherited = [];
    if ($parent !== null && isset($classLikes[strtolower($parent)])) {
        $inherited = propertiesOf(strtolower($parent), $classLikes, $cache);
    } elseif ($parent !== null && class_exists($parent)) {
        foreach ((new ReflectionClass($parent))->getProperties() as $reflected) {
            $type = $reflected->getType();
            $inherited[$reflected->getName()] = [
                'type' => $type instanceof ReflectionNamedType && !$type->isBuiltin() ? $type->getName() : null,
                'visibility' => $reflected->isPrivate() ? 'private' : ($reflected->isProtected() ? 'protected' : 'public'),
                'static' => $reflected->isStatic(),
                'origin' => $reflected->getDeclaringClass()->getName(),
                'file' => '(built-in)',
                'line' => 0,
            ];
        }
    }
    foreach ($inherited as $name => $declaration) {
        if ($declaration['visibility'] !== 'private') {
            $properties[$name] ??= $declaration;
        }
    }
    return $cache[$key] = $properties;
}

/** Methods of a class named in a call or a property type: from the sources, or a built-in class. */
function methodsOfClass(string $class, array $classLikes, array &$cache, array &$problems): ?array
{
    $classKey = strtolower($class);
    if (isset($classLikes[$classKey])) {
        return methodsOf($classKey, $classLikes, $cache, $problems);
    }
    if (class_exists($class) || interface_exists($class) || enum_exists($class)) {
        $methods = [];
        foreach ((new ReflectionClass($class))->getMethods() as $reflected) {
            $methods[strtolower($reflected->getName())] = [
                'name' => $reflected->getName(),
                'visibility' => $reflected->isPrivate() ? 'private' : ($reflected->isProtected() ? 'protected' : 'public'),
                'static' => $reflected->isStatic(),
                'abstract' => false,
                'file' => '(built-in)',
                'line' => 0,
                'origin' => $reflected->getDeclaringClass()->getName(),
            ];
        }
        return $methods;
    }
    return null;
}

/** " (used by A, B)" for a trait that classes use; '' otherwise. */
function usedBy(array $info, array $classLikes): string
{
    if ($info['kind'] !== 'trait') {
        return '';
    }
    $users = [];
    foreach ($classLikes as $userKey => $user) {
        if ($user['kind'] !== 'trait' && isset(traitsOf($userKey, $classLikes)[strtolower($info['name'])])) {
            $users[] = shortName($user['name']);
        }
    }
    return $users === [] ? '' : ' (used by ' . implode(', ', $users) . ')';
}

/** Where a method name is defined at all, for the report: "Trait (used by HttpApi)". */
function definedElsewhere(string $method, array $classLikes): string
{
    $where = [];
    foreach ($classLikes as $info) {
        if (isset($info['methods'][strtolower($method)])) {
            $where[] = shortName($info['name']) . usedBy($info, $classLikes);
        }
    }
    return $where === [] ? '' : '; defined only in ' . implode(', ', $where);
}

/** Where a property is declared at all, for the report. */
function declaredElsewhere(string $property, array $classLikes): string
{
    $where = [];
    foreach ($classLikes as $info) {
        if (array_key_exists($property, $info['properties'])) {
            $where[] = shortName($info['name']) . usedBy($info, $classLikes);
        }
    }
    return $where === [] ? '' : '; declared only in ' . implode(', ', $where);
}

function shortName(string $name): string
{
    $pos = strrpos($name, '\\');
    return $pos === false ? $name : substr($name, $pos + 1);
}

// --methods: each class's methods as this check composes them, for
// tests/static_check_methods_test.php to compare with PHP's reflection.
if ($dumpMethods) {
    $cache = [];
    $problems = [];
    $dump = [];
    foreach ($classLikes as $key => $info) {
        if ($info['kind'] === 'class' || $info['kind'] === 'enum') {
            $names = array_keys(methodsOf($key, $classLikes, $cache, $problems));
            sort($names);
            $dump[$info['name']] = $names;
        }
    }
    echo json_encode($dump, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . "\n";
    exit($problems === [] ? 0 : 1);
}

// ─── Resolve every call on the class it runs in ────────────────────────────

$cache = [];
$propertyCache = [];
$problems = [];
$undefined = [];
$notChecked = [];
$resolved = 0;
$calledIn = []; // class key => lowercase names called on the class itself
$classes = array_filter($classLikes, static fn (array $c): bool => $c['kind'] === 'class' || $c['kind'] === 'enum');

$report = static function (string $message) use (&$undefined): void {
    $undefined[$message] = true;
};
$cannotCheck = static function (string $message) use (&$notChecked): void {
    $notChecked[$message] = true;
};

/** Check $call, a call to a method of $class made from class $fromKey (null at file scope). */
$checkNamed = static function (array $call, string $class, ?string $fromKey, string $where) use (&$cache, &$problems, $classLikes, $report, &$resolved, &$calledIn): void {
    $methods = methodsOfClass($class, $classLikes, $cache, $problems);
    if ($methods === null) {
        $report(sprintf('%s at %s: class %s does not exist', $call['text'], $where, $class));
        return;
    }
    $method = $methods[strtolower($call['method'])] ?? null;
    if ($method === null && !isset($methods[$call['kind'] === 'property' ? '__call' : '__callstatic'])) {
        $report(sprintf('%s has no method %s(), called as %s at %s%s', $class, $call['method'], $call['text'], $where, definedElsewhere($call['method'], $classLikes)));
        return;
    }
    $sameClass = $fromKey !== null && strtolower($class) === $fromKey;
    if ($method !== null && !$sameClass && $method['visibility'] !== 'public') {
        $report(sprintf('%s::%s() is %s, called from %s as %s at %s', $class, $method['name'], $method['visibility'], $fromKey === null ? 'file scope' : $classLikes[$fromKey]['name'], $call['text'], $where));
        return;
    }
    if ($sameClass) {
        $calledIn[$fromKey][strtolower($call['method'])] = true;
    }
    $resolved++;
};

foreach ($classes as $key => $class) {
    $methods = methodsOf($key, $classLikes, $cache, $problems);
    $properties = propertiesOf($key, $classLikes, $propertyCache);
    $bodies = [$key => $class['name']] + traitsOf($key, $classLikes);

    if (!$class['abstract']) {
        foreach ($methods as $method) {
            if ($method['abstract']) {
                $report(sprintf('%s does not implement abstract %s() declared in %s (%s:%d)', $class['name'], $method['name'], $method['origin'], $method['file'], $method['line']));
            }
        }
    }

    foreach (array_keys($bodies) as $bodyKey) {
        if (!isset($classLikes[$bodyKey])) {
            continue; // reported by methodsOf
        }
        $body = $classLikes[$bodyKey];
        foreach ($body['calls'] as $call) {
            $where = sprintf('%s:%d', $call['file'], $call['line']) . ($bodyKey !== $key ? ' (trait ' . shortName($body['name']) . ')' : '');
            if (isset($call['rebound'])) {
                $cannotCheck(sprintf('%s at %s runs in a closure rebound at %s, as whatever object and class that gives it', $call['text'], $where, $call['rebound']));
                continue;
            }
            switch ($call['kind']) {
                case 'dynamic':
                    $cannotCheck(sprintf('%s at %s: the name is decided at run time', $call['text'], $where));
                    break;
                case 'this':
                case 'self':
                case 'static':
                    $calledIn[$key][strtolower($call['method'])] = true;
                    if (!isset($methods[strtolower($call['method'])])
                        && !isset($methods[$call['kind'] === 'this' ? '__call' : '__callstatic'])) {
                        $report(sprintf('%s has no method %s(), called as %s at %s%s', $class['name'], $call['method'], $call['text'], $where, definedElsewhere($call['method'], $classLikes)));
                    } else {
                        $resolved++;
                    }
                    break;
                case 'parent':
                    if ($class['extends'] === null) {
                        $report(sprintf('%s has no parent, called as %s at %s', $class['name'], $call['text'], $where));
                        break;
                    }
                    $inherited = inheritedMethods($class['extends'], $classLikes, $cache, $problems, $class);
                    if (!isset($inherited[strtolower($call['method'])])) {
                        $report(sprintf('%s (parent of %s) has no method %s() a child can call, called as %s at %s', $class['extends'], $class['name'], $call['method'], $call['text'], $where));
                    } else {
                        $resolved++;
                    }
                    break;
                case 'property':
                    if (!array_key_exists($call['property'], $properties)) {
                        if (isset($methods['__get'])) {
                            $cannotCheck(sprintf('%s at %s: %s declares no property $%s and has __get()', $call['text'], $where, $class['name'], $call['property']));
                        } else {
                            $report(sprintf('%s has no property $%s, called as %s at %s%s', $class['name'], $call['property'], $call['text'], $where, declaredElsewhere($call['property'], $classLikes)));
                        }
                        break;
                    }
                    $type = $properties[$call['property']]['type'];
                    if ($type === null) {
                        $cannotCheck(sprintf('%s at %s: property $%s of %s has no class type', $call['text'], $where, $call['property'], $class['name']));
                        break;
                    }
                    if (strtolower($type) === 'closure' && in_array(strtolower($call['method']), ['bind', 'bindto', 'call'], true)) {
                        $cannotCheck(sprintf('%s at %s rebinds the closure in $%s, which this check cannot follow; the calls in that closure were resolved on the class whose body holds it', $call['text'], $where, $call['property']));
                    }
                    $checkNamed($call, $type, $key, $where);
                    break;
                default:
                    $checkNamed($call, (string) $call['class'], $key, $where);
            }
        }
    }
}

foreach ($fileCalls as $call) {
    $where = sprintf('%s:%d', $call['file'], $call['line']);
    if (isset($call['rebound'])) {
        $cannotCheck(sprintf('%s at %s runs in a closure rebound at %s, as whatever object and class that gives it', $call['text'], $where, $call['rebound']));
    } elseif ($call['kind'] === 'class') {
        $checkNamed($call, (string) $call['class'], null, $where);
    } else {
        $report(sprintf('%s outside any class at %s', $call['text'], $where));
    }
}

foreach ($notes as $note) {
    $cannotCheck($note);
}

foreach ($problems as $problem) {
    $report($problem);
}

// ─── Report ────────────────────────────────────────────────────────────────

echo count($files) . ' files, ' . count($classes) . ' classes, '
    . count(array_filter($classLikes, static fn (array $c): bool => $c['kind'] === 'trait')) . " traits\n";
foreach ($classes as $key => $class) {
    $traits = traitsOf($key, $classLikes);
    printf("  %-20s %3d methods, %2d traits\n", shortName($class['name']), count(methodsOf($key, $classLikes, $cache, $problems)), count($traits));
}
echo "{$resolved} calls resolved on the class they run in; " . count($notChecked) . " calls not checked (listed under Warnings)\n\n";

foreach (array_keys($undefined) as $message) {
    echo "UNDEFINED: {$message}\n";
}
if ($resolved === 0) {
    // A scanner that sees nothing passes everything.
    echo "UNDEFINED: no call was resolved: the scanner read nothing it could check\n";
    $undefined['(nothing resolved)'] = true;
}

echo "\n── Warnings ──\n";
foreach (array_keys($notChecked) as $message) {
    echo "  NOT CHECKED: {$message}\n";
}
$warnings = 0;
$orphans = [];
foreach ($classLikes as $traitKey => $trait) {
    if ($trait['kind'] !== 'trait') {
        continue;
    }
    $usedBy = array_filter(array_keys($classes), static fn (string $key): bool => isset(traitsOf($key, $classLikes)[$traitKey]));
    if ($usedBy === []) {
        echo "  TRAIT USED BY NO CLASS: {$trait['name']} ({$trait['file']}); its calls resolve on nothing and are not checked\n";
        $orphans[$traitKey] = true;
        $warnings++;
    }
}
$used = [];
foreach ($classes as $key => $class) {
    foreach (methodsOf($key, $classLikes, $cache, $problems) as $lower => $method) {
        if (isset($calledIn[$key][$lower])) {
            $used[strtolower($method['origin']) . '::' . strtolower($method['name'])] = true;
        }
    }
}
foreach ($classLikes as $key => $info) {
    if (isset($orphans[$key])) {
        continue; // said above: nothing composes it
    }
    foreach ($info['methods'] as $lower => $method) {
        if ($method['visibility'] === 'private' && !str_starts_with($lower, '__')
            && !isset($used[strtolower($info['name']) . '::' . $lower])) {
            echo "  UNUSED: {$method['file']}::{$method['name']}() is private and nothing calls it\n";
            $warnings++;
        }
    }
}

echo "\n" . str_repeat('=', 50) . "\n";
echo 'Undefined: ' . count($undefined) . "  Unused: {$warnings}  Not checked: " . count($notChecked) . "\n";
exit($undefined === [] ? 0 : 1);
