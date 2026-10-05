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
 * HOW IT RESOLVES
 * ===============
 * The sources (php/src/*.php and php/src/lib/*.php, what deploy.sh ships)
 * are tokenized, so comments, strings and heredocs are not code: the monitor
 * page's JavaScript `function flushStale()` is not a PHP method. A class has
 * its own methods, those of every trait it uses (recursively, with `as`
 * aliases), and its parent's that are not private (a class in php/src, or a
 * built-in one by reflection). Every call in a class's own body and in the
 * body of every trait it uses, recursively, is resolved on THAT class:
 *
 *   $this->m(), $this?->m(), [$this, 'm'], self::m(), static::m()
 *       m must be a method of the class;
 *   parent::m()
 *       m must be a method of the class's parent, not private;
 *   $this->p->m(), where property p is declared with a class type
 *       (Storage's PDO $db, HttpApi's Storage $storage)
 *       m must be a method of that type, public unless it is the class itself;
 *   Name::m(), Name a class in php/src or a built-in one
 *       the class must exist and have m, public unless called from inside it.
 *
 * A method_exists() guard does not make a call resolve: on a class without
 * the method the guarded line never runs. Calls on local variables and
 * dynamic calls ($this->$name()) are not resolvable here and are not checked.
 * A concrete class must implement every abstract method it composes.
 *
 * Warnings, which do not fail the check: a trait no class uses (nothing
 * composes it, so its calls resolve on nothing), and a private method that
 * nothing in any class composing it calls (one of a trait no class uses is
 * not listed again).
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
    return $t !== null && preg_match('/^[A-Za-z_\x80-\xff][A-Za-z0-9_\x80-\xff]*$/', $t->text) === 1;
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

/**
 * One file's class-likes (with their methods, properties, trait uses and
 * calls) and the calls made outside any class.
 */
function scanFile(string $code, string $file): array
{
    $tokens = PhpToken::tokenize($code);
    $n = count($tokens);
    $namespace = '';
    $imports = [];
    $classLikes = [];
    $fileCalls = [];
    $scopes = [];      // open class-like bodies: [key, bodyDepth]
    $pending = null;   // key of a class-like whose body opens at the next '{'
    $depth = 0;

    $addCall = static function (array $call) use (&$scopes, &$classLikes, &$fileCalls, $file): void {
        $call['file'] = $file;
        if ($scopes === []) {
            $fileCalls[] = $call;
        } else {
            $classLikes[end($scopes)[0]]['calls'][] = $call;
        }
    };

    for ($i = 0; $i < $n; $i++) {
        $t = $tokens[$i];
        if ($t->isIgnorable()) {
            continue;
        }
        $scope = $scopes === [] ? null : end($scopes);
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
                        // [Trait::]method as [visibility] [alias]  |  [Trait::]method insteadof ...
                        $asAt = null;
                        foreach ($statement as $s => $st) {
                            if ($st->is(T_AS)) {
                                $asAt = $s;
                            }
                        }
                        if ($asAt !== null) {
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
                            $classLikes[$key]['adaptations'][] = ['trait' => $trait, 'method' => $source, 'alias' => $alias, 'visibility' => $visibility];
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
                    if ($tokens[$k]->is(T_VARIABLE)) {
                        $promoted = false;
                        for ($b = prevCode($tokens, $k); $b > $open && !in_array($tokens[$b]->text, [',', '('], true); $b = prevCode($tokens, $b)) {
                            $promoted = $promoted || $tokens[$b]->is([T_PUBLIC, T_PROTECTED, T_PRIVATE, T_READONLY]);
                        }
                        if ($promoted) {
                            $classLikes[$scope[0]]['properties'][substr($tokens[$k]->text, 1)] = declaredType($tokens, $k, $namespace, $imports);
                        }
                    }
                }
            }
            $i = $close; // parameters hold no calls; the body is read by the main loop
            continue;
        }

        if ($atBody && $t->is(T_VARIABLE)) {
            $classLikes[$scope[0]]['properties'][substr($t->text, 1)] = declaredType($tokens, $i, $namespace, $imports);
            continue;
        }

        // ── Calls ──────────────────────────────────────────────────────────
        if ($t->is(T_VARIABLE) && $t->text === '$this') {
            $arrow = nextCode($tokens, $i);
            if ($arrow >= 0 && $tokens[$arrow]->is([T_OBJECT_OPERATOR, T_NULLSAFE_OBJECT_OPERATOR])) {
                $m = nextCode($tokens, $arrow);
                if (!isIdentifier(tokenAt($tokens, $m))) {
                    continue; // $this->$name(), $this->{...}
                }
                $after = nextCode($tokens, $m);
                if ($after >= 0 && $tokens[$after]->text === '(') {
                    $addCall(['kind' => 'this', 'method' => $tokens[$m]->text, 'line' => $tokens[$m]->line]);
                } elseif ($after >= 0 && $tokens[$after]->is([T_OBJECT_OPERATOR, T_NULLSAFE_OBJECT_OPERATOR])) {
                    $m2 = nextCode($tokens, $after);
                    $after2 = nextCode($tokens, $m2);
                    if (isIdentifier(tokenAt($tokens, $m2)) && $after2 >= 0 && $tokens[$after2]->text === '(') {
                        $addCall(['kind' => 'property', 'property' => $tokens[$m]->text, 'method' => $tokens[$m2]->text, 'line' => $tokens[$m2]->line]);
                    }
                }
                continue;
            }
            // [$this, 'm']
            $p = prevCode($tokens, $i);
            $comma = nextCode($tokens, $i);
            $str = nextCode($tokens, $comma);
            $end = nextCode($tokens, $str);
            if ($p >= 0 && $tokens[$p]->text === '[' && $comma >= 0 && $tokens[$comma]->text === ','
                && $str >= 0 && $tokens[$str]->is(T_CONSTANT_ENCAPSED_STRING) && $end >= 0 && $tokens[$end]->text === ']') {
                $addCall(['kind' => 'this', 'method' => trim($tokens[$str]->text, '\'"'), 'line' => $tokens[$str]->line]);
            }
            continue;
        }

        if ($t->is(NAME_TOKENS) || $t->is(T_STATIC)) {
            $colons = nextCode($tokens, $i);
            if ($colons < 0 || !$tokens[$colons]->is(T_DOUBLE_COLON)) {
                continue;
            }
            $p = prevCode($tokens, $i);
            if ($p >= 0 && $tokens[$p]->is([T_OBJECT_OPERATOR, T_NULLSAFE_OBJECT_OPERATOR, T_DOUBLE_COLON, T_FUNCTION, T_CONST])) {
                continue;
            }
            $m = nextCode($tokens, $colons);
            $after = nextCode($tokens, $m);
            $lower = strtolower($t->text);
            $kind = match (true) {
                $t->is(T_STATIC) => 'static',
                $lower === 'self' => 'self',
                $lower === 'parent' => 'parent',
                default => 'class',
            };
            $class = $kind === 'class' ? resolveName($t->text, $namespace, $imports) : null;
            if (isIdentifier(tokenAt($tokens, $m)) && $after >= 0 && $tokens[$after]->text === '(' && !$tokens[$m]->is(T_CLASS)) {
                $addCall(['kind' => $kind, 'class' => $class, 'method' => $tokens[$m]->text, 'line' => $tokens[$m]->line]);
            } elseif ($m >= 0 && $tokens[$m]->is(T_CLASS) && ($kind === 'self' || $kind === 'static')) {
                // [self::class, 'm'] / [static::class, 'm']
                $comma = nextCode($tokens, $m);
                $str = nextCode($tokens, $comma);
                $end = nextCode($tokens, $str);
                if ($p >= 0 && $tokens[$p]->text === '[' && $comma >= 0 && $tokens[$comma]->text === ','
                    && $str >= 0 && $tokens[$str]->is(T_CONSTANT_ENCAPSED_STRING) && $end >= 0 && $tokens[$end]->text === ']') {
                    $addCall(['kind' => $kind, 'class' => null, 'method' => trim($tokens[$str]->text, '\'"'), 'line' => $tokens[$str]->line]);
                }
            }
            continue;
        }
    }

    return [$classLikes, $fileCalls];
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
foreach ($files as $path) {
    $rel = substr($path, strlen($srcDir) + 1);
    [$found, $calls] = scanFile((string) file_get_contents($path), $rel);
    foreach ($found as $key => $info) {
        $classLikes[$key] = $info;
    }
    foreach ($calls as $call) {
        $fileCalls[] = $call;
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

/**
 * The methods a class-like has: lowercase name => method. The class's own
 * win over its traits', which win over the parent's.
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
            $fromTraits[$lower] ??= $method;
        }
    }
    foreach ($info['adaptations'] as $adaptation) {
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
            $methods[$lower] ??= $method;
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

/** Where a method name is defined at all, for the report: "Trait (used by HttpApi)". */
function definedElsewhere(string $method, array $classLikes): string
{
    $where = [];
    foreach ($classLikes as $info) {
        if (!isset($info['methods'][strtolower($method)])) {
            continue;
        }
        $users = [];
        if ($info['kind'] === 'trait') {
            foreach ($classLikes as $userKey => $user) {
                if ($user['kind'] !== 'trait' && isset(traitsOf($userKey, $classLikes)[strtolower($info['name'])])) {
                    $users[] = shortName($user['name']);
                }
            }
        }
        $where[] = shortName($info['name']) . ($users !== [] ? ' (used by ' . implode(', ', $users) . ')' : '');
    }
    return $where === [] ? '' : '; defined only in ' . implode(', ', $where);
}

function shortName(string $name): string
{
    $pos = strrpos($name, '\\');
    return $pos === false ? $name : substr($name, $pos + 1);
}

function describeCall(array $call): string
{
    return match ($call['kind']) {
        'this' => '$this->' . $call['method'] . '()',
        'property' => '$this->' . $call['property'] . '->' . $call['method'] . '()',
        'self', 'static', 'parent' => $call['kind'] . '::' . $call['method'] . '()',
        default => shortName((string) $call['class']) . '::' . $call['method'] . '()',
    };
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
$problems = [];
$undefined = [];
$resolved = 0;
$unchecked = 0;
$calledIn = []; // class key => lowercase names called on the class itself
$classes = array_filter($classLikes, static fn (array $c): bool => $c['kind'] === 'class' || $c['kind'] === 'enum');

$report = static function (string $message) use (&$undefined): void {
    $undefined[$message] = true;
};

/** Check $call, a call to a method of $class made from class $fromKey (null at file scope). */
$checkNamed = static function (array $call, string $class, ?string $fromKey, string $where) use (&$cache, &$problems, $classLikes, $report, &$resolved): void {
    $methods = methodsOfClass($class, $classLikes, $cache, $problems);
    if ($methods === null) {
        $report(sprintf('%s at %s: class %s does not exist', describeCall($call), $where, $class));
        return;
    }
    $method = $methods[strtolower($call['method'])] ?? null;
    if ($method === null && !isset($methods[$call['kind'] === 'property' ? '__call' : '__callstatic'])) {
        $report(sprintf('%s has no method %s(), called as %s at %s%s', $class, $call['method'], describeCall($call), $where, definedElsewhere($call['method'], $classLikes)));
        return;
    }
    $sameClass = $fromKey !== null && strtolower($class) === $fromKey;
    if ($method !== null && !$sameClass && $method['visibility'] !== 'public') {
        $report(sprintf('%s::%s() is %s, called from %s as %s at %s', $class, $method['name'], $method['visibility'], $fromKey === null ? 'file scope' : $classLikes[$fromKey]['name'], describeCall($call), $where));
        return;
    }
    $resolved++;
};

foreach ($classes as $key => $class) {
    $methods = methodsOf($key, $classLikes, $cache, $problems);
    $bodies = [$key => $class['name']] + traitsOf($key, $classLikes);

    if (!$class['abstract']) {
        foreach ($methods as $method) {
            if ($method['abstract']) {
                $report(sprintf('%s does not implement abstract %s() declared in %s (%s:%d)', $class['name'], $method['name'], $method['origin'], $method['file'], $method['line']));
            }
        }
    }

    // Properties declared by the class or by any trait it uses.
    $properties = [];
    foreach (array_keys($bodies) as $bodyKey) {
        $properties += $classLikes[$bodyKey]['properties'] ?? [];
    }

    foreach (array_keys($bodies) as $bodyKey) {
        if (!isset($classLikes[$bodyKey])) {
            continue; // reported by methodsOf
        }
        $body = $classLikes[$bodyKey];
        foreach ($body['calls'] as $call) {
            $where = sprintf('%s:%d', $call['file'], $call['line']) . ($bodyKey !== $key ? ' (trait ' . shortName($body['name']) . ')' : '');
            switch ($call['kind']) {
                case 'this':
                case 'self':
                case 'static':
                    $calledIn[$key][strtolower($call['method'])] = true;
                    if (!isset($methods[strtolower($call['method'])])
                        && !isset($methods[$call['kind'] === 'this' ? '__call' : '__callstatic'])) {
                        $report(sprintf('%s has no method %s(), called as %s at %s%s', $class['name'], $call['method'], describeCall($call), $where, definedElsewhere($call['method'], $classLikes)));
                    } else {
                        $resolved++;
                    }
                    break;
                case 'parent':
                    if ($class['extends'] === null) {
                        $report(sprintf('%s has no parent, called as %s at %s', $class['name'], describeCall($call), $where));
                        break;
                    }
                    $inherited = inheritedMethods($class['extends'], $classLikes, $cache, $problems, $class);
                    if (!isset($inherited[strtolower($call['method'])])) {
                        $report(sprintf('%s (parent of %s) has no method %s() a child can call, called as %s at %s', $class['extends'], $class['name'], $call['method'], describeCall($call), $where));
                    } else {
                        $resolved++;
                    }
                    break;
                case 'property':
                    $type = $properties[$call['property']] ?? null;
                    if ($type === null) {
                        $unchecked++;
                        break;
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
    if ($call['kind'] === 'class') {
        $checkNamed($call, (string) $call['class'], null, $where);
    } else {
        $report(sprintf('%s outside any class at %s', describeCall($call), $where));
    }
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
echo "{$resolved} calls resolved on the class they run in; {$unchecked} calls on untyped properties not checked\n\n";

foreach (array_keys($undefined) as $message) {
    echo "UNDEFINED: {$message}\n";
}
if ($resolved === 0) {
    // A scanner that sees nothing passes everything.
    echo "UNDEFINED: no call was resolved: the scanner read nothing it could check\n";
    $undefined['(nothing resolved)'] = true;
}

echo "\n── Warnings ──\n";
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
echo 'Undefined: ' . count($undefined) . "  Unused: {$warnings}\n";
exit($undefined === [] ? 0 : 1);
