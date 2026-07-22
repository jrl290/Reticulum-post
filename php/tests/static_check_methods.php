<?php

declare(strict_types=1);

/**
 * Static analysis: treat ALL trait files + index.php as a single composed
 * class body and verify every $this->method() call has a definition.
 *
 * Run: php php/tests/static_check_methods.php
 */

$srcDir = __DIR__ . '/../src/lib';
$indexFile = __DIR__ . '/../src/index.php';

$allDefined = [];
$allCode = '';

foreach (glob("$srcDir/*.php") as $file) {
    $code = file_get_contents($file);
    $allCode .= $code;
    preg_match_all('/function\s+(\w+)\s*\(/', $code, $m);
    foreach ($m[1] as $name) { $allDefined[$name] = true; }
}
if (file_exists($indexFile)) {
    $code = file_get_contents($indexFile);
    $allCode .= $code;
    preg_match_all('/function\s+(\w+)\s*\(/', $code, $m);
    foreach ($m[1] as $name) { $allDefined[$name] = true; }
}

preg_match_all('/\$this->(\w+)\s*\(/', $allCode, $calls);
$allCalls = array_unique($calls[1]);

$props = ['db', 'config', 'storage', 'cache', 'owner'];
$errors = 0;

echo count($allDefined) . " methods defined, " . count($allCalls) . " unique \$this-> calls\n\n";

foreach ($allCalls as $call) {
    if (in_array($call, $props, true)) continue;
    if (!isset($allDefined[$call])) {
        $callers = [];
        foreach (glob("$srcDir/*.php") as $file) {
            if (preg_match('/\$this->' . $call . '\s*\(/', file_get_contents($file)))
                $callers[] = basename($file);
        }
        echo "UNDEFINED: \$this->$call() in " . implode(', ', $callers) . "\n";
        $errors++;
    }
}

echo "\n── Unused private methods ──\n";
$warnings = 0;
foreach (glob("$srcDir/*.php") as $file) {
    $code = file_get_contents($file);
    preg_match_all('/private\s+function\s+(\w+)\s*\(/', $code, $priv);
    foreach ($priv[1] as $method) {
        $other = str_replace($code, '', $allCode);
        if (strpos($other, '$this->' . $method . '(') === false) {
            echo "  UNUSED: " . basename($file) . "::$method()\n";
            $warnings++;
        }
    }
}

echo "\n" . str_repeat('=', 50) . "\n";
echo "Undefined: $errors  Unused: $warnings\n";
exit($errors > 0 ? 1 : 0);
