<?php

declare(strict_types=1);

/**
 * There must be exactly one PostInterface.py in this repository.
 *
 * WHAT THIS EXISTS TO PREVENT
 * ===========================
 * On 2026-08-17 this file existed six times across the workspace in four
 * different versions: three inside this repo (python/RNS/Interfaces/,
 * docker/bridge/interfaces/, python/bridge-conf/interfaces/), one dropped
 * untracked into the Reticulum-master upstream mirror, one in e2e-local/, and
 * one installed in .venv. Two of them dated from a commit literally named
 * "BEFORE: snapshot local state before pulling retichat.com server code" and
 * were never touched again.
 *
 * Nothing pointed at which one was authoritative. The README said the bridge
 * "lives in python/" while python/ held two different versions of it. Any fix
 * had a one-in-three chance of landing in a file nothing loads, and any diff
 * against the wrong copy showed phantom regressions — the newest copy looked
 * like it had *lost* a PROOF hop fix, when in fact it had generalised that fix
 * to every link packet.
 *
 * The same disease removed Reticulum-post/js/ (commit 14dd75c) and
 * Retichat-js/selectiv-snapshot/. Duplicated source is where regressions
 * incubate: one copy is always wrong, and you cannot tell which.
 *
 * Out-of-repo copies (Reticulum-master, e2e-local) are symlinks to the
 * canonical file so they cannot drift. This test guards the repo itself.
 */

$root = dirname(__DIR__, 2);
$canonical = 'php/../python/RNS/Interfaces/PostInterface.py';
$canonicalReal = $root . '/python/RNS/Interfaces/PostInterface.py';

$failures = [];

if (!is_file($canonicalReal)) {
    $failures[] = 'python/RNS/Interfaces/PostInterface.py is missing — it is the '
        . 'one maintained copy of the bridge (see python/README.md)';
}

// Find every PostInterface.py tracked in this repository.
$tracked = [];
$output = [];
exec('git -C ' . escapeshellarg($root) . ' ls-files 2>/dev/null', $output);
foreach ($output as $path) {
    if (basename(trim($path)) === 'PostInterface.py') {
        $tracked[] = trim($path);
    }
}

if (count($tracked) > 1) {
    $failures[] = sprintf(
        'found %d tracked copies of PostInterface.py; there must be exactly one:',
        count($tracked)
    );
    foreach ($tracked as $t) {
        $failures[] = '    ' . $t;
    }
    $failures[] = '  Keep python/RNS/Interfaces/PostInterface.py and delete the rest. '
        . 'A deployment or test environment that needs the file should symlink '
        . 'it, not copy it.';
} elseif (count($tracked) === 1 && $tracked[0] !== 'python/RNS/Interfaces/PostInterface.py') {
    $failures[] = sprintf(
        'the single tracked copy is %s, expected python/RNS/Interfaces/PostInterface.py — '
        . 'update python/README.md and this test if the canonical location moved',
        $tracked[0]
    );
}

// The README must name the canonical path, since "which copy is real" was the
// whole problem.
$readme = $root . '/python/README.md';
if (!is_file($readme)) {
    $failures[] = 'python/README.md is missing — it names the canonical copy';
} else {
    $text = file_get_contents($readme);
    if (!str_contains($text, 'python/RNS/Interfaces/PostInterface.py')) {
        $failures[] = 'python/README.md no longer names the canonical file path';
    }
}

if ($failures !== []) {
    fwrite(STDERR, "FAIL: bridge source is duplicated\n\n");
    foreach ($failures as $f) {
        fwrite(STDERR, "  - {$f}\n");
    }
    fwrite(STDERR, "\n");
    exit(1);
}

printf("PASS: exactly one tracked PostInterface.py (%s)\n", $tracked[0] ?? 'none');
exit(0);
