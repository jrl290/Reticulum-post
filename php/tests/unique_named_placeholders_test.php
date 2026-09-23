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
 * The scan follows the code's own shape: for every `->prepare($var)` it takes
 * the text from the nearest `$var = ` assignment to the prepare() call, splits
 * it into ternary alternatives (lines beginning with `?` or `:`), and counts
 * the placeholders in each alternative.
 *
 * Run: php php/tests/unique_named_placeholders_test.php
 */

function repeatedPlaceholders(string $code): array
{
    $findings = [];
    if (!preg_match_all('/->prepare\(\s*\$([A-Za-z_][A-Za-z0-9_]*)\s*\)/', $code, $calls, PREG_OFFSET_CAPTURE)) {
        return $findings;
    }
    foreach ($calls[1] as [$var, $offset]) {
        $start = strrpos(substr($code, 0, $offset), '$' . $var . ' = ');
        if ($start === false) {
            continue;
        }
        $block = substr($code, $start, $offset - $start);
        // Ternary alternatives are separate queries: "$sql = cond\n ? '...'\n : '...';"
        $alternatives = preg_split('/^\s*[?:]\s/m', $block) ?: [$block];
        foreach ($alternatives as $alt) {
            preg_match_all('/[\s(=,<>]:([a-z_][a-z0-9_]*)\b/', $alt, $m);
            $counts = array_count_values($m[1]);
            $dups = array_keys(array_filter($counts, static fn (int $n): bool => $n > 1));
            if ($dups !== []) {
                $line = substr_count(substr($code, 0, $start), "\n") + 1;
                $findings[] = sprintf('$%s at line %d: %s', $var, $line, implode(', ', $dups));
            }
        }
    }
    return $findings;
}

$failures = 0;

// 1. The scanner recognises the exact query that broke production.
$broken = <<<'PHP'
        $query = "SELECT lte.* FROM link_transport_entries AS lte WHERE lte.link_id_hex = :link_id_hex";
        $query .= ' AND ((lte.validated = 1 AND lte.updated_at >= :active_after)'
            . ' OR (lte.proof_expires_at IS NULL AND lte.updated_at >= :active_after))';
        $stmt = $this->db->prepare($query);
PHP;
$found = repeatedPlaceholders($broken);
if (count($found) !== 1 || !str_contains($found[0], 'active_after')) {
    echo "FAIL: the scanner did not flag the 2026-09-23 query: " . json_encode($found) . "\n";
    $failures++;
} else {
    echo "ok   scanner flags a placeholder used twice\n";
}

// 2. Ternary alternatives (one query per backend) are not a repeat.
$ternary = <<<'PHP'
        $sql = $this->backend === 'mysql'
            ? "INSERT INTO t (k, v, at) VALUES (:key, :value, :now) ON DUPLICATE KEY UPDATE v = VALUES(v)"
            : "INSERT INTO t (k, v, at) VALUES (:key, :value, :now) ON CONFLICT(k) DO UPDATE SET v = excluded.v";
        $stmt = $this->db->prepare($sql);
PHP;
if (repeatedPlaceholders($ternary) !== []) {
    echo "FAIL: the scanner flagged a per-backend ternary\n";
    $failures++;
} else {
    echo "ok   per-backend ternary alternatives are separate queries\n";
}

// 3. The real source is clean.
foreach (glob(__DIR__ . '/../src/lib/*.php') as $file) {
    foreach (repeatedPlaceholders(file_get_contents($file)) as $finding) {
        echo "FAIL: " . basename($file) . " " . $finding . "\n";
        $failures++;
    }
}
if ($failures === 0) {
    echo "ok   no prepared statement in src/lib uses a named placeholder twice\n";
}

exit($failures === 0 ? 0 : 1);
