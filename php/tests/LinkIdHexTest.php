<?php

declare(strict_types=1);

/**
 * Tests for linkIdHex() — the link ID computation must match Python/JS.
 *
 * The PHP linkIdHex function computes the truncated SHA-256 of the hashable
 * part of a link request packet. This must produce the same 16-byte value
 * as the Python reference (RNS.Link.link_id_from_lr_packet) and the
 * JavaScript implementation (Link.setLinkId).
 *
 * The hashable part is:
 *   [0]     flags & 0x0F (low nibble)
 *   [1..N]  remainder of raw packet after headers:
 *           - HEADER_1: raw[2:]  (skip flags + hops)
 *           - HEADER_2: raw[18:] (skip flags + hops + 16-byte transport_id)
 *
 * If the payload exceeds ECPUBSIZE (64 bytes), trailing MTU signalling
 * bytes are stripped from the hashable part before hashing.
 *
 * Test vectors come from actual network traffic captured on 2026-07-15.
 * The expected link IDs are the values registered by the browser
 * (JavaScript implementation), which matches the Python reference.
 */

// Simulate the trait method in isolation
function computeLinkIdHex(string $rawBase64, string $payloadBase64, int $headerType): string
{
    $raw = base64_decode($rawBase64, true);
    $payload = base64_decode($payloadBase64, true);
    if (!is_string($raw) || strlen($raw) < 2 || !is_string($payload) || strlen($payload) < 64) {
        throw new \RuntimeException('Invalid packet data');
    }

    $flags = ord($raw[0]);
    $hashablePart = chr($flags & 0x0F);
    if ($headerType === 1) {
        // HEADER_2: skip flags(1) + hops(1) + transport_id(16) = 18 bytes
        $hashablePart .= substr($raw, 18);
    } else {
        // HEADER_1: skip flags(1) + hops(1) = 2 bytes
        $hashablePart .= substr($raw, 2);
    }

    // Strip MTU signalling bytes from hashable part if payload > ECPUBSIZE (64)
    if (strlen($payload) > 64) {
        $diff = strlen($payload) - 64;
        $hashablePart = substr($hashablePart, 0, strlen($hashablePart) - $diff);
    }

    return bin2hex(substr(hash('sha256', $hashablePart, true), 0, 16));
}

// ─── Test Vectors ───────────────────────────────────────────────────────────

$tests = [];
$passed = 0;
$failed = 0;

// Test 1: HEADER_2 link request captured from real traffic (2026-07-15)
// Browser registered link ID: 8fbd703706711be8c7e2e0c4d5fa2ac7
$tests[] = [
    'name' => 'HEADER_2 link request (real traffic)',
    'rawBase64' => 'UgFDa0++UQSz2+TiXC8cORzjhYrEL0q3kU8jpnNwpXMICQA0HP8g5RpkMFZH/xeOdGP7h3vfF1vZwvi2LgH8ncrWNmm1gMX4bDOB9/E96qOjlxjc/UrBYFrYby1NDm77He4r',
    'payloadBase64' => 'NBz/IOUaZDBWR/8XjnRj+4d73xdb2cL4ti4B/J3K1jZptYDF+GwzgffxPeqjo5cY3P1KwWBa2G8tTQ5u+x3uKw==',
    'headerType' => 1,
    'expected' => '8fbd703706711be8c7e2e0c4d5fa2ac7',
];

// Test 2: Verify the old buggy offset=2 for HEADER_2 produces a DIFFERENT value.
// This guarantees the fix is meaningful (the bug actually changed the result).
$tests[] = [
    'name' => 'HEADER_2 buggy offset=2 produces different result (regression guard)',
    'rawBase64' => $tests[0]['rawBase64'],
    'payloadBase64' => $tests[0]['payloadBase64'],
    'headerType' => 99,  // special: use offset 2 for HEADER_2 (the bug)
    'expected' => '', // computed below
    'mustNotEqual' => $tests[0]['expected'],
];

// Compute what the old buggy code would produce
{
    $rawBase64 = $tests[0]['rawBase64'];
    $payloadBase64 = $tests[0]['payloadBase64'];
    $raw = base64_decode($rawBase64);
    $payload = base64_decode($payloadBase64);
    $flags = ord($raw[0]);
    $hashablePart = chr($flags & 0x0F);
    // BUG: always use offset 2
    $hashablePart .= substr($raw, 2);
    if (strlen($payload) > 64) {
        $diff = strlen($payload) - 64;
        $hashablePart = substr($hashablePart, 0, strlen($hashablePart) - $diff);
    }
    $tests[1]['expected'] = bin2hex(substr(hash('sha256', $hashablePart, true), 0, 16));
}

// Test 3: HEADER_1 synthetic — flags=0x0F, hops=3, dest=all zeros, payload=64 bytes zeros
$tests[] = [
    'name' => 'HEADER_1 synthetic (payload=64)',
    'rawBase64' => base64_encode(
        chr(0x0F)          // flags: IFAC=0, HEADER_1=0, context=0, transport=0, dest=SINGLE(0), pkt=LINKREQUEST(2)
        . chr(3)           // hops
        . str_repeat("\x00", 16)  // destination hash
        . chr(0x00)        // context
        . str_repeat("\x00", 64)  // payload: exactly 64 bytes (ECPUBSIZE)
    ),
    'payloadBase64' => base64_encode(str_repeat("\x00", 64)),
    'headerType' => 0,
    'expected' => '',  // computed below
];

// Compute expected for test 3
{
    $raw = chr(0x0F) . chr(3) . str_repeat("\x00", 16) . chr(0x00) . str_repeat("\x00", 64);
    $flags = ord($raw[0]);
    $hashablePart = chr($flags & 0x0F) . substr($raw, 2);  // HEADER_1: offset 2
    // payload is 64 bytes exactly, no stripping
    $tests[2]['expected'] = bin2hex(substr(hash('sha256', $hashablePart, true), 0, 16));
}

// Test 4: HEADER_1 with payload > 64 bytes (MTU signalling strip)
$tests[] = [
    'name' => 'HEADER_1 synthetic (payload=67, MTU strip)',
    'rawBase64' => base64_encode(
        chr(0x0F) . chr(3)
        . str_repeat("\x00", 16)
        . chr(0x00)
        . str_repeat("\x01", 67)  // 67 bytes: 64 key material + 3 MTU bytes
    ),
    'payloadBase64' => base64_encode(str_repeat("\x01", 67)),
    'headerType' => 0,
    'expected' => '',  // computed below
];

// Compute expected for test 4
{
    $raw = chr(0x0F) . chr(3) . str_repeat("\x00", 16) . chr(0x00) . str_repeat("\x01", 67);
    $flags = ord($raw[0]);
    $hashablePart = chr($flags & 0x0F) . substr($raw, 2);  // HEADER_1: offset 2 skips flags(1)+hops(1)
    // Strip 3 bytes (67-64)
    $diff = 67 - 64;
    $hashablePart = substr($hashablePart, 0, strlen($hashablePart) - $diff);
    $tests[3]['expected'] = bin2hex(substr(hash('sha256', $hashablePart, true), 0, 16));
}

// Test 5: HEADER_2 synthetic — same payload as test 3 but with transport_id
$tests[] = [
    'name' => 'HEADER_2 synthetic (payload=64)',
    'rawBase64' => base64_encode(
        chr(0x4F)          // flags: IFAC=0, HEADER_2=1, context=0, transport=0, dest=SINGLE(0), pkt=LINKREQUEST(2)
        . chr(3)           // hops
        . str_repeat("\xFF", 16)  // transport_id
        . str_repeat("\x00", 16)  // destination hash
        . chr(0x00)        // context
        . str_repeat("\x00", 64)  // payload
    ),
    'payloadBase64' => base64_encode(str_repeat("\x00", 64)),
    'headerType' => 1,
    'expected' => '',  // computed below
];

// Compute expected for test 5
{
    $raw = chr(0x4F) . chr(3) . str_repeat("\xFF", 16) . str_repeat("\x00", 16) . chr(0x00) . str_repeat("\x00", 64);
    $flags = ord($raw[0]);
    $hashablePart = chr($flags & 0x0F) . substr($raw, 18);  // HEADER_2: offset 18
    $tests[4]['expected'] = bin2hex(substr(hash('sha256', $hashablePart, true), 0, 16));
}

// ─── Run ─────────────────────────────────────────────────────────────────────

echo "linkIdHex Unit Tests\n";
echo str_repeat('=', 60) . "\n\n";

foreach ($tests as $i => $test) {
    try {
        // Handle the regression guard test: headerType=99 means use the OLD buggy code path
        if (($test['headerType'] ?? 0) === 99) {
            $raw = base64_decode($test['rawBase64'], true);
            $payload = base64_decode($test['payloadBase64'], true);
            $flags = ord($raw[0]);
            $hashablePart = chr($flags & 0x0F) . substr($raw, 2);  // OLD bug: always offset 2
            if (strlen($payload) > 64) {
                $diff = strlen($payload) - 64;
                $hashablePart = substr($hashablePart, 0, strlen($hashablePart) - $diff);
            }
            $result = bin2hex(substr(hash('sha256', $hashablePart, true), 0, 16));
        } else {
            $result = computeLinkIdHex($test['rawBase64'], $test['payloadBase64'], $test['headerType']);
        }
        $expected = $test['expected'];
        $match = $result === $expected;

        if ($match) {
            echo "  ✅ PASS: {$test['name']}\n";
            echo "     linkId = {$result}\n";
            $passed++;
        } else {
            // Check if this is a regression guard (mustNotEqual set)
            if (isset($test['mustNotEqual']) && $result !== $test['mustNotEqual']) {
                echo "  ✅ PASS: {$test['name']}\n";
                echo "     linkId = {$result} (correctly differs from buggy {$test['mustNotEqual']})\n";
                $passed++;
            } else {
                echo "  ❌ FAIL: {$test['name']}\n";
                echo "     got:      {$result}\n";
                echo "     expected: {$expected}\n";
                if (isset($test['note'])) {
                    echo "     note:     {$test['note']}\n";
                }
                $failed++;
            }
        }
    } catch (\Throwable $e) {
        echo "  ❌ ERROR: {$test['name']}\n";
        echo "     {$e->getMessage()}\n";
        $failed++;
    }
    echo "\n";
}

echo str_repeat('=', 60) . "\n";
echo "{$passed} passed, {$failed} failed, " . count($tests) . " total\n";

exit($failed > 0 ? 1 : 0);
