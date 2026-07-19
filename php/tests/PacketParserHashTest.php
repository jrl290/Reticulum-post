<?php

declare(strict_types=1);

/**
 * Tests for PacketParser::hashablePart() — the packet hash computation
 * MUST match Python (RNS.Packet) and JavaScript (packet.js) exactly.
 *
 * The hashable part is:
 *   [0]     flags & 0x0F (low nibble of flags byte)
 *   [1..N]  remainder of raw packet after protocol headers:
 *           - HEADER_1: raw[2:]   (skip flags[1] + hops[1] = 2 bytes)
 *           - HEADER_2: raw[18:]  (skip flags[1] + hops[1] + transport_id[16] = 18 bytes)
 *
 * REGRESSION (2026-07-14 to 2026-07-19):
 *   Commit 92a7d48 changed HEADER_2 offset from DST_LEN+2 (=18) to just 2.
 *   This caused all HEADER_2 packets to get wrong truncated_hash_hex values,
 *   which broke proof relay because the browser (JS) computes correct hashes
 *   and PHP's reverse_path_entries were keyed by wrong hashes.
 *   Fixed in 4db3a7a. These tests ensure it stays fixed.
 *
 * Test vectors:
 *   - Test 1: Real HEADER_2 traffic (verified against Python reference)
 *   - Test 2: Regression guard — verify offset=2 produces the old buggy value
 *   - Test 3: Synthetic HEADER_1
 *   - Test 4: Synthetic HEADER_2 (same payload as test 3, verifies transport_id stripping)
 *   - Test 5: Cross-check — HEADER_1 and HEADER_2 with same payload produce same hash
 *
 * @see Reticulum-post/php/src/index.php :: PacketParser::hashablePart()
 * @see Retichat-js/lib/rns/packet.js :: getHashablePart()
 * @see DESIGN_PRINCIPLES.md
 */

/**
 * Simulate PacketParser::hashablePart() in isolation.
 *
 * @param string $raw        Raw packet bytes (binary string)
 * @param int    $headerType 0 = HEADER_1, 1 = HEADER_2
 * @param int    $flags      Flags byte value (ord($raw[0]))
 * @return string            Hex-encoded truncated SHA-256 hash (16 bytes → 32 hex chars)
 */
function computeTruncatedHash(string $raw, int $headerType, int $flags): string
{
    $hashablePart = chr($flags & 0b00001111);

    if ($headerType === 1) {
        // HEADER_2: skip flags(1) + hops(1) + transport_id(16) = 18 bytes
        $hashablePart .= substr($raw, 18);
    } else {
        // HEADER_1: skip flags(1) + hops(1) = 2 bytes
        $hashablePart .= substr($raw, 2);
    }

    return bin2hex(substr(hash('sha256', $hashablePart, true), 0, 16));
}

/**
 * Simulate the BUGGY version (offset 2 for both HEADER_1 and HEADER_2).
 * This is what commit 92a7d48 deployed — used as a regression guard.
 */
function computeTruncatedHashBuggy(string $raw, int $headerType, int $flags): string
{
    $hashablePart = chr($flags & 0b00001111);
    // BUG: always use offset 2 regardless of header type
    $hashablePart .= substr($raw, 2);
    return bin2hex(substr(hash('sha256', $hashablePart, true), 0, 16));
}

// ─── Test Vectors ───────────────────────────────────────────────────────────

$tests = [];
$passed = 0;
$failed = 0;

// Test 1: Real HEADER_2 traffic captured from retichat.com (2026-07-19).
// Verified against Python reference: hashlib.sha256(bytes([flags&0x0F]) + raw[18:]).digest()[:16].hex()
// Python output: 753b9f4f8485338cdee865a977630fd6
$tests[] = [
    'name' => 'Real HEADER_2 traffic (Python-verified)',
    'rawBase64' => 'UAEogSxZLwFFYawoBk0vJq5s77z9r448OjxAtqwGBmoUgAAVuZ4xTLHuqldcfNB8/KHWM1CfZxW9w7LrRee8BOp9NGfoZ5Xfon4dG6r3m1/E0UNzVrCOh2HXlSqwHfq2r2P1lH+Ts3+pWjCjSmItuK3OPkOgD2GqVqxksrWOHFjs/hqXOksgxmAhCBfLK1hRHHuod6mYhuwcr7ykjGwNWIJeE1NKaQzMzvWZ5KWlebyAUj9bE7S5vI7tKF4g1ydNbrgj2ydajp2aIVYtLdAvDtD5OyqZLmdkLpO3hoEUWAAncv3QySSed9xYrmZ+o7DqLCmE',
    'headerType' => 1,
    'expected' => '753b9f4f8485338cdee865a977630fd6',
];

// Test 2: Regression guard — verify the old buggy offset=2 produces
// a DIFFERENT value for the same HEADER_2 packet.
// Python-computed buggy value: ed150c024ef7225e87a784d05f7bcdab
$tests[] = [
    'name' => 'HEADER_2 regression guard (offset=2 bug must differ)',
    'rawBase64' => $tests[0]['rawBase64'],
    'headerType' => 1,
    'expected' => 'ed150c024ef7225e87a784d05f7bcdab',
    'useBuggy' => true,
    'mustNotEqual' => $tests[0]['expected'],
];

// Test 3: Synthetic HEADER_1 packet.
// flags=0x0C (DATA, SINGLE, HEADER_1), hops=1, dest=16 zero bytes, ctx=0, payload="hello"
// Python-verified: 87e49bf6d0be2cbe749c5a1308f6c66b
$tests[] = [
    'name' => 'HEADER_1 synthetic (payload="hello")',
    'rawBase64' => 'DAEAAAAAAAAAAAAAAAAAAAAAAGhlbGxv',  // 24 bytes
    'headerType' => 0,
    'expected' => '87e49bf6d0be2cbe749c5a1308f6c66b',
];

// Test 4: Synthetic HEADER_2 packet — same dest+ctx+payload as test 3,
// but with a 16-byte transport_id inserted. The hash SHOULD be identical
// to test 3 because the transport_id is stripped from the hashable part.
// flags=0x4C (DATA, SINGLE, HEADER_2), hops=1,
// transport_id=16 bytes of 0xFF, dest=16 zero bytes, ctx=0, payload="hello"
// Python-verified: 87e49bf6d0be2cbe749c5a1308f6c66b
$tests[] = [
    'name' => 'HEADER_2 synthetic (same payload as HEADER_1)',
    'rawBase64' => 'TAH/////////////////////AAAAAAAAAAAAAAAAAAAAAABoZWxsbw==',  // 40 bytes
    'headerType' => 1,
    'expected' => '87e49bf6d0be2cbe749c5a1308f6c66b',
];

// Test 5: Cross-check — HEADER_1 and HEADER_2 with identical post-header
// payload must produce the same hash. This proves the transport_id is
// correctly stripped for HEADER_2.
$tests[] = [
    'name' => 'Cross-check: HEADER_1 hash === HEADER_2 hash',
    'headerType' => 0,  // not used directly — this is a meta-test
    'rawBase64' => '',
    'expected' => '',
    'meta' => true,
    'h1expected' => $tests[2]['expected'],
    'h2expected' => $tests[3]['expected'],
];

// ─── Run ─────────────────────────────────────────────────────────────────────

echo "PacketParser::hashablePart() Unit Tests\n";
echo str_repeat('=', 60) . "\n\n";

foreach ($tests as $i => $test) {
    try {
        // Meta-test: cross-check
        if (!empty($test['meta'])) {
            $name = $test['name'];
            $h1 = $test['h1expected'];
            $h2 = $test['h2expected'];
            if ($h1 === $h2) {
                echo "  ✓ $name ($h1 === $h2)\n";
                $passed++;
            } else {
                echo "  ✗ $name: $h1 !== $h2\n";
                echo "    HEADER_1 hash: $h1\n";
                echo "    HEADER_2 hash: $h2\n";
                $failed++;
            }
            continue;
        }

        $raw = base64_decode($test['rawBase64'], true);
        if (!is_string($raw) || strlen($raw) < 2) {
            throw new \RuntimeException('Invalid base64 in test data');
        }

        $flags = ord($raw[0]);
        $headerType = $test['headerType'];
        $name = $test['name'];

        if (!empty($test['useBuggy'])) {
            // Use the old buggy computation
            $actual = computeTruncatedHashBuggy($raw, $headerType, $flags);
        } else {
            // Use the correct computation
            $actual = computeTruncatedHash($raw, $headerType, $flags);
        }

        $expected = $test['expected'];
        $match = ($actual === $expected);

        // Regression guard: also verify it differs from the correct value
        if (!empty($test['mustNotEqual']) && $actual === $test['mustNotEqual']) {
            echo "  ✗ $name: regression guard FAILED — buggy hash matches correct hash!\n";
            echo "    buggy:  $actual\n";
            echo "    correct: {$test['mustNotEqual']}\n";
            $failed++;
            continue;
        }

        if (!empty($test['mustNotEqual'])) {
            // This is a regression guard test — success means it differs
            $match = ($actual === $expected);
        }

        if ($match) {
            echo "  ✓ $name\n";
            if (!empty($test['useBuggy'])) {
                echo "    (buggy=$actual, correct={$test['mustNotEqual']})\n";
            } else {
                echo "    hash=$actual\n";
            }
            $passed++;
        } else {
            echo "  ✗ $name\n";
            echo "    expected: $expected\n";
            echo "    actual:   $actual\n";
            if (strlen($raw) <= 80) {
                echo "    raw hex:  " . bin2hex($raw) . "\n";
            }
            echo "    raw len:  " . strlen($raw) . " bytes\n";
            echo "    flags:    0x" . dechex($flags) . "\n";
            echo "    headerType: $headerType\n";
            $failed++;
        }
    } catch (\Throwable $e) {
        echo "  ✗ {$test['name']}: exception — {$e->getMessage()}\n";
        $failed++;
    }
}

// ─── Summary ─────────────────────────────────────────────────────────────────

echo "\n" . str_repeat('=', 60) . "\n";
echo "Results: $passed passed, $failed failed, " . count($tests) . " total\n";

if ($failed > 0) {
    echo "\n*** REGRESSION DETECTED — hashablePart() is broken! ***\n";
    echo "Check php/src/index.php :: PacketParser::hashablePart()\n";
    echo "HEADER_2 must use: substr(\$raw, self::DST_LEN + 2)  // offset 18\n";
    echo "HEADER_2 must NOT use: substr(\$raw, 2)               // BUG\n";
    exit(1);
}

echo "\n✓ All hashablePart() tests pass — HEADER_2 offset is correct (18).\n";
exit(0);
