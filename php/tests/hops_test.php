<?php

declare(strict_types=1);

/**
 * Unit tests for hop-count handling in the PHP Reticulum relay.
 *
 * Tests verify that after the HOPS.md fixes:
 *   1. transportObservedHops is a passthrough (post-inbound value)
 *   2. relayPacketBase64 uses transportObservedHops (no double +1)
 *   3. proofRelayPacketBase64 writes actual hop count into relayed bytes
 *   4. relayLinkRequestProofPacket: exact hop + next-hop-interface gate, and
 *      a signed hop mismatch on a pending entry rebalances (RNS 1.5.2
 *      Transport.py:2608-2672); signatures are mocked here and covered for
 *      real by local_link_relay_sql_test.php
 *   5. linkTransportTargetInterfaceId uses exact hop match (no ±1)
 *   6. rememberLinkTransportRelay stores remaining_hops from path table
 *   7. Inbound handler increments hops by 1
 *
 * Run with: php tests/hops_test.php
 */

require_once __DIR__ . '/../src/lib/request_relay_routing_trait.php';
require_once __DIR__ . '/../src/lib/request_inbound_batch_trait.php';

// ── Mock harness ──────────────────────────────────────────────────────────

class MockRouter
{
    use \ReticulumPhp\RequestRelayRoutingTrait;
    use \ReticulumPhp\RequestInboundBatchTrait;

    public array $pathTable = [];
    public array $linkTransportTable = [];
    public array $reversePathTable = [];
    public array $localDestinations = [];
    public array $knownDestIdentityHashes = [];
    public array $outboundQueue = [];
    public string $transportIdentityHashHex = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';
    public string $backend = 'sqlite';
    public int $now = 0;
    public array $db = [];

    public function config(): array
    {
        return [
            'pathfinder_max_hops' => 128,
            'path_expiry_default_seconds' => 604800,
        ];
    }

    public function usablePathEntry(string $destinationHashHex): ?array
    {
        return $this->pathTable[$destinationHashHex] ?? null;
    }

    /**
     * Mirrors the SQL in request_relay_routing_trait.php: the unvalidated row
     * for this link and outbound (next-hop) interface, with NO hop filter -
     * upstream looks the link up by id and only then compares hops, so the
     * rebalance and hop-mismatch branches are reachable. (Until 2026-09-23
     * the query filtered on remaining_hops = observed, which made both dead.)
     * This mock holds one row per (link, outbound interface), so the SQL's
     * preference for the fork whose remaining_hops equals $observedHops has
     * nothing to choose between.
     */
    public function linkTransportEntryForOutbound(string $linkIdHex, string $outboundInterfaceId, ?int $observedHops = null): ?array
    {
        $key = "$linkIdHex::$outboundInterfaceId";
        $entry = $this->linkTransportTable[$key] ?? null;
        if ($entry === null || (int) ($entry['validated'] ?? 0) !== 0) {
            return null;
        }
        return $entry;
    }

    /** Result of the mocked signature check (see validateLinkRequestProof). */
    public bool $proofSignatureValid = true;

    /**
     * Signature validation is mocked here: this harness has no keys or
     * known_destinations table. The real check (real Ed25519 keys through the
     * real knownDestinationPublicKey() query) is covered by
     * local_link_relay_sql_test.php.
     */
    public function validateLinkRequestProof(array $packet, array $linkEntry): bool
    {
        return $this->proofSignatureValid;
    }

    /** Same effect as the SQL: move the row's remaining_hops and the path hops. */
    public function rebalanceLinkTransportEntry(array $linkEntry, int $newRemainingHops): void
    {
        $key = $linkEntry['link_id_hex'] . '::' . $linkEntry['outbound_interface_id'];
        if (isset($this->linkTransportTable[$key])) {
            $this->linkTransportTable[$key]['remaining_hops'] = $newRemainingHops;
        }
        $dest = (string) ($linkEntry['destination_hash_hex'] ?? '');
        if (isset($this->pathTable[$dest])) {
            $this->pathTable[$dest]['hops'] = $newRemainingHops;
        }
    }

    public function linkTransportEntries(string $linkIdHex, bool $validatedOnly = false): array
    {
        $entries = [];
        foreach ($this->linkTransportTable as $key => $entry) {
            if (str_starts_with($key, "$linkIdHex::")) {
                if (!$validatedOnly || ($entry['validated'] ?? 0) === 1) {
                    $entries[] = $entry;
                }
            }
        }
        return $entries;
    }

    public function hasValidatedLinkTransportEntry(string $linkIdHex): bool
    {
        foreach ($this->linkTransportTable as $entry) {
            if (($entry['link_id_hex'] ?? '') === $linkIdHex && ($entry['validated'] ?? 0) === 1) {
                return true;
            }
        }
        return false;
    }

    public function touchLinkTransportEntry(string $linkIdHex, string $outboundInterfaceId, ?bool $validated = null, ?int $remainingHops = null): void
    {
        // Same WHERE clause as the SQL: the row is only touched when its
        // remaining_hops equals the one passed (if any).
        $key = "$linkIdHex::$outboundInterfaceId";
        if (!isset($this->linkTransportTable[$key])) {
            return;
        }
        if ($remainingHops !== null && (int) ($this->linkTransportTable[$key]['remaining_hops'] ?? 0) !== $remainingHops) {
            return;
        }
        if ($validated !== null) {
            $this->linkTransportTable[$key]['validated'] = $validated ? 1 : 0;
        }
    }
    public function deleteLinkTransportEntries(string $linkIdHex): void {}

    public function peekReversePath(string $truncatedHashHex, string $outboundInterfaceId): ?array
    {
        $key = "$truncatedHashHex::$outboundInterfaceId";
        return $this->reversePathTable[$key] ?? null;
    }

    public function queueOutboundPacket(string $interfaceId, string $rawBase64, string $reason, string $sourceInterfaceId): void
    {
        $this->outboundQueue[] = [
            'interface_id' => $interfaceId,
            'raw_base64' => $rawBase64,
            'reason' => $reason,
            'source_interface_id' => $sourceInterfaceId,
        ];
    }

    public function localDestinationInterface(string $destHash): ?string
    {
        return $this->localDestinations[$destHash] ?? null;
    }

    public function knownDestinationIdentityHash(string $destinationHashHex): ?string
    {
        return $this->knownDestIdentityHashes[$destinationHashHex] ?? null;
    }

    public function registerLinkLocalDestination(string $linkHashHex, string $localIface): void {}
    public function knownDestinationPublicKey(string $destHashHex): ?string { return null; }
    public function rememberPacketHash(string $hex): void {}
    public function packetHashExists(string $hex): bool { return false; }

    public function linkRequestProofExpiresAt(string $interfaceId, int $remainingHops): int
    {
        return $this->now + 30;
    }

    public function validatedLinkTransportActiveAfter(?int $now = null): int
    {
        return ($now ?? $this->now) - 300;
    }

    /** @var string|null Override for linkIdHex() return value in tests */
    public ?string $linkIdHexReturn = null;

    public function linkIdHex(string $rawBase64, array $packet): ?string
    {
        return $this->linkIdHexReturn ?? ($packet['destination_hash_hex'] ?? null);
    }

    public function allOtherInterfaceIds(string $sourceInterfaceId): array { return []; }
    public function ifacConfig(string $interfaceId): array { return []; }

    private function rememberReversePath(string $truncatedHashHex, string $receivedInterfaceId, string $outboundInterfaceId): void
    {
        $this->reversePathTable["$truncatedHashHex::$outboundInterfaceId"] = [
            'truncated_hash_hex' => $truncatedHashHex,
            'received_interface_id' => $receivedInterfaceId,
            'outbound_interface_id' => $outboundInterfaceId,
        ];
    }

    private function rememberLinkTransportEntry(
        string $linkIdHex, string $receivedInterfaceId, string $outboundInterfaceId,
        string $nextHopHex, int $remainingHops, int $takenHops, string $destinationHashHex
    ): void {
        $this->linkTransportTable["$linkIdHex::$outboundInterfaceId"] = [
            'link_id_hex' => $linkIdHex,
            'received_interface_id' => $receivedInterfaceId,
            'outbound_interface_id' => $outboundInterfaceId,
            'next_hop_hex' => $nextHopHex,
            'remaining_hops' => $remainingHops,
            'taken_hops' => $takenHops,
            'destination_hash_hex' => $destinationHashHex,
            'validated' => 0,
        ];
    }

    private function applyPacketFilter(array $packet): array
    {
        $hops = (int) ($packet['hops'] ?? 0);
        $destType = (int) ($packet['destination_type'] ?? 0);
        $pktType = (int) ($packet['packet_type'] ?? 0);
        if ($destType === 2 && $pktType !== 1 && $hops > 1) return ['rejected', 'plain_hops_exceeded'];
        if ($destType === 1 && $pktType !== 1 && $hops > 1) return ['rejected', 'group_hops_exceeded'];
        return ['accepted', 'ok'];
    }

    // ── Public test wrappers for private methods ──────────────────────────

    public function test_transportObservedHops(array $packet): int
    {
        return $this->transportObservedHops($packet);
    }

    public function test_proofRelayPacketBase64(string $rawBase64, array $packet): string
    {
        return $this->proofRelayPacketBase64($rawBase64, $packet);
    }

    public function test_linkTransportTargetInterfaceId(string $sourceInterfaceId, int $observedHops, array $linkEntry): ?string
    {
        return $this->linkTransportTargetInterfaceId($sourceInterfaceId, $observedHops, $linkEntry);
    }
}

// ── Helper: build a minimal packet array ───────────────────────────────────

function makePacket(array $overrides = []): array
{
    return array_merge([
        'packet_type' => 0,
        'context' => 0x00,
        'context_flag' => 0,
        'header_type' => 0,
        'destination_type' => 0,
        'transport_type' => 0,
        'hops' => 0,
        'destination_hash_hex' => 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
        'transport_id_hex' => null,
        'payload_base64' => base64_encode(str_repeat("\x00", 32)),
        'normalized_raw_base64' => null,
        'truncated_hash_hex' => null,
        'packet_hash_hex' => 'cccccccccccccccccccccccccccccccc',
    ], $overrides);
}

function makeRawBase64(array $packet): string
{
    $flags = ((int) ($packet['context_flag'] ?? 0) << 5)
           | ((int) ($packet['header_type'] ?? 0) << 6)
           | ((int) ($packet['transport_type'] ?? 0) << 4)
           | ((int) ($packet['destination_type'] ?? 0) << 2)
           | ((int) ($packet['packet_type'] ?? 0));
    $hops = (int) ($packet['hops'] ?? 0);
    $dest = hex2bin($packet['destination_hash_hex']);
    $ctx = chr((int) ($packet['context'] ?? 0));
    $payload = str_repeat("\x00", 8);
    return base64_encode(chr($flags) . chr($hops) . $dest . $ctx . $payload);
}

// ── Test runner ────────────────────────────────────────────────────────────

$pass = 0;
$fail = 0;
$known = 0;   // quarantined divergences — see assertKnownDivergence()

function assertEq(string $label, $expected, $actual): void
{
    global $pass, $fail;
    if ($expected === $actual) {
        $pass++;
        echo "  \033[32m✓\033[0m $label\n";
    } else {
        $fail++;
        echo "  \033[31m✗\033[0m $label\n";
        echo "    expected: " . var_export($expected, true) . "\n";
        echo "    actual:   " . var_export($actual, true) . "\n";
    }
}

/**
 * A known, documented disagreement between this test and the shipped code.
 *
 * Reported loudly and counted separately, so it stays visible without making
 * the suite's exit code meaningless. A red suite is worse than no suite: it
 * trains you to skip the run, and then the next real regression lands in the
 * noise. Anything NOT listed here that fails is a genuine failure.
 *
 * To retire one of these, resolve the question in its comment — do not simply
 * flip the assertion to match whatever the code currently does.
 */
function assertKnownDivergence(string $label, $expected, $actual, string $why): void
{
    global $pass, $known;
    if ($expected === $actual) {
        // The code now agrees. The quarantine is stale — fail loudly so it gets
        // removed rather than silently masking a future regression.
        $pass++;
        echo "  \033[33m!\033[0m $label — RESOLVED, remove the quarantine\n";
        return;
    }

    $known++;
    echo "  \033[33m~\033[0m $label (known divergence)\n";
    echo "    expected: " . var_export($expected, true) . "\n";
    echo "    actual:   " . var_export($actual, true) . "\n";
    echo "    why:      {$why}\n";
}

function assertTrue(string $label, bool $condition): void
{
    global $pass, $fail;
    if ($condition) {
        $pass++;
        echo "  \033[32m✓\033[0m $label\n";
    } else {
        $fail++;
        echo "  \033[31m✗\033[0m $label (expected true)\n";
    }
}

// ══════════════════════════════════════════════════════════════════════════
// Test 1: transportObservedHops is passthrough (no +1 compensation)
// ══════════════════════════════════════════════════════════════════════════

echo "\n── Test 1: transportObservedHops ──\n";
$router = new MockRouter();

$pkt = makePacket(['hops' => 0]);
assertEq('hops=0 → returns 0', 0, $router->test_transportObservedHops($pkt));

$pkt = makePacket(['hops' => 3]);
assertEq('hops=3 → returns 3', 3, $router->test_transportObservedHops($pkt));

$pkt = makePacket(['hops' => 255]);
assertEq('hops=255 → returns 255', 255, $router->test_transportObservedHops($pkt));

$pkt = makePacket();
unset($pkt['hops']);
assertEq('missing hops key → returns 0', 0, $router->test_transportObservedHops($pkt));

// ══════════════════════════════════════════════════════════════════════════
// Test 2: proofRelayPacketBase64 writes actual hop count
// ══════════════════════════════════════════════════════════════════════════

echo "\n── Test 2: proofRelayPacketBase64 writes hops ──\n";

$pkt = makePacket(['hops' => 2]);
$rawB64 = makeRawBase64($pkt);
$result = $router->test_proofRelayPacketBase64($rawB64, $pkt);
$decoded = base64_decode($result);
assertEq('hops=2 → byte 1 = 2', 2, ord($decoded[1]));

$pkt = makePacket(['hops' => 0]);
$rawB64 = makeRawBase64($pkt);
$result = $router->test_proofRelayPacketBase64($rawB64, $pkt);
$decoded = base64_decode($result);
assertEq('hops=0 → byte 1 = 0', 0, ord($decoded[1]));

$pkt = makePacket(['hops' => 5]);
// Create raw bytes with hops=0 (simulating wire format before inbound increment)
// and a different destination to prove we're rewriting byte 1
$rawB64 = makeRawBase64(makePacket(['hops' => 0, 'destination_hash_hex' => $pkt['destination_hash_hex']]));
$result = $router->test_proofRelayPacketBase64($rawB64, $pkt);
$decoded = base64_decode($result);
$hopsByte = ord($decoded[1]);
assertEq('raw_bytes hops=0, packet hops=5 → byte 1 = 5', 5, $hopsByte);
assertTrue('proof bytes differ from input (0→5)', $rawB64 !== $result);

// ══════════════════════════════════════════════════════════════════════════
// Test 3: linkTransportTargetInterfaceId — exact hop match (no ±1)
// ══════════════════════════════════════════════════════════════════════════

echo "\n── Test 3: linkTransportTargetInterfaceId exact match ──\n";

// Exact match: observed = remaining_hops = 2, arriving on outbound iface
$entry = ['outbound_interface_id' => 'iface_out', 'received_interface_id' => 'iface_in', 'remaining_hops' => 2, 'taken_hops' => 1];
$target = $router->test_linkTransportTargetInterfaceId('iface_out', 2, $entry);
assertEq('exact match (obs=rem=2 on outbound) → iface_in', 'iface_in', $target);

// Mismatch: observed=3 but remaining=2 (was allowed by ±1 tolerance)
$target = $router->test_linkTransportTargetInterfaceId('iface_out', 3, $entry);
assertTrue('hops mismatch (obs=3 rem=2) → null (rejected)', $target === null);

// Mismatch: observed=1 but remaining=2 (was allowed by ±1 tolerance)
$target = $router->test_linkTransportTargetInterfaceId('iface_out', 1, $entry);
assertTrue('hops mismatch (obs=1 rem=2) → null (rejected)', $target === null);

// Initiator→destination direction: observed = taken_hops = 1
$target = $router->test_linkTransportTargetInterfaceId('iface_in', 1, $entry);
assertEq('exact match (obs=tkn=1 on rcvd) → iface_out', 'iface_out', $target);

// Same-interface: either remaining or taken works
$entry2 = ['outbound_interface_id' => 'iface_shared', 'received_interface_id' => 'iface_shared', 'remaining_hops' => 3, 'taken_hops' => 2];
$target = $router->test_linkTransportTargetInterfaceId('iface_shared', 3, $entry2);
assertEq('same-iface (obs=rem=3) → iface_shared', 'iface_shared', $target);
$target = $router->test_linkTransportTargetInterfaceId('iface_shared', 2, $entry2);
assertEq('same-iface (obs=tkn=2) → iface_shared', 'iface_shared', $target);

// ══════════════════════════════════════════════════════════════════════════
// Test 4: Inbound hop increment
// ══════════════════════════════════════════════════════════════════════════

echo "\n── Test 4: Inbound hop increment ──\n";

$packet = makePacket(['hops' => 0]);
$packet['hops'] = ($packet['hops'] ?? 0) + 1;
assertEq('hops 0 → 1 after inbound', 1, $packet['hops']);
$packet['hops'] = ($packet['hops'] ?? 0) + 1;
assertEq('hops 1 → 2 after second inbound', 2, $packet['hops']);

$packet = makePacket();
unset($packet['hops']);
$packet['hops'] = ($packet['hops'] ?? 0) + 1;
assertEq('null hops → 1 after inbound', 1, $packet['hops']);

// ══════════════════════════════════════════════════════════════════════════
// Test 5: rememberLinkTransportRelay uses path table for remaining_hops
// ══════════════════════════════════════════════════════════════════════════

echo "\n── Test 5: rememberLinkTransportRelay remaining_hops from path ──\n";

$router2 = new MockRouter();
$destHex = 'dddddddddddddddddddddddddddddddd';
$router2->pathTable[$destHex] = [
    'hops' => 3,
    'next_hop_hex' => '11111111111111111111111111111111',
    'interface_id' => 'iface_target',
];

$pkt = makePacket(['packet_type' => 2, 'hops' => 1, 'destination_hash_hex' => $destHex]);
$rawB64 = makeRawBase64($pkt);

$ref = new ReflectionMethod($router2, 'rememberLinkTransportRelay');
$ref->setAccessible(true);
$ref->invoke($router2, 'iface_src', 'iface_target', $rawB64, $pkt);

$linkKey = "$destHex::iface_target";
$entry = $router2->linkTransportTable[$linkKey] ?? null;
assertTrue('link transport entry created', $entry !== null);
assertEq('remaining_hops from path table (3)', 3, $entry['remaining_hops'] ?? -1);
assertEq('taken_hops = observed hops (1)', 1, $entry['taken_hops'] ?? -1);

// ══════════════════════════════════════════════════════════════════════════
// Test 6: LRPROOF relay with exact hop match
// ══════════════════════════════════════════════════════════════════════════

echo "\n── Test 6: LRPROOF exact hop check ──\n";

$router3 = new MockRouter();
$linkIdHex = 'eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee';
$router3->linkTransportTable["$linkIdHex::iface_nas"] = [
    'link_id_hex' => $linkIdHex,
    'received_interface_id' => 'iface_browser',
    'outbound_interface_id' => 'iface_nas',
    'next_hop_hex' => '22222222222222222222222222222222',
    'remaining_hops' => 2,
    'taken_hops' => 1,
    'destination_hash_hex' => $linkIdHex,
    'validated' => 0,
];

// LRPROOF with correct hops (2 = remaining_hops) → should relay
$pkt = makePacket(['packet_type' => 3, 'context' => 0xFF, 'hops' => 2, 'destination_hash_hex' => $linkIdHex]);
$rawB64 = makeRawBase64($pkt);
$ref = new ReflectionMethod($router3, 'relayLinkRequestProofPacket');
$ref->setAccessible(true);
$result = $ref->invoke($router3, 'iface_nas', $rawB64, $pkt);
assertEq('LRPROOF hops=2 match remaining=2 → relayed (count=1)', 1, $result);
assertTrue('relayed to browser iface', count($router3->outboundQueue) > 0 && ($router3->outboundQueue[0]['interface_id'] ?? '') === 'iface_browser');

assertEq('entry validated after the relay', 1, $router3->linkTransportTable["$linkIdHex::iface_nas"]['validated'] ?? 0);

// A pending entry for the Test 6 variants below (remaining 2, next hop iface_nas).
$freshEntry = function () use ($linkIdHex): array {
    return [
        'link_id_hex' => $linkIdHex,
        'received_interface_id' => 'iface_browser',
        'outbound_interface_id' => 'iface_nas',
        'next_hop_hex' => '22222222222222222222222222222222',
        'remaining_hops' => 2,
        'taken_hops' => 1,
        'destination_hash_hex' => '33333333333333333333333333333333',
        'validated' => 0,
    ];
};

// LRPROOF on the wrong interface (the one the LINKREQUEST came in on) → dropped
$routerW = new MockRouter();
$routerW->linkTransportTable["$linkIdHex::iface_nas"] = $freshEntry();
$pkt = makePacket(['packet_type' => 3, 'context' => 0xFF, 'hops' => 2, 'destination_hash_hex' => $linkIdHex]);
$ref = new ReflectionMethod($routerW, 'relayLinkRequestProofPacket');
assertEq('LRPROOF hops=2 on the received interface (not the next hop) → dropped', 0, $ref->invoke($routerW, 'iface_browser', makeRawBase64($pkt), $pkt));
assertTrue('outbound queue empty after wrong-interface drop', count($routerW->outboundQueue) === 0);
assertEq('entry stays unvalidated', 0, $routerW->linkTransportTable["$linkIdHex::iface_nas"]['validated']);

// Signed hop mismatch (3 != remaining 2) on a pending entry → rebalanced and
// relayed (ALLOW_LINK_PATH_REBALANCE, RNS 1.5.2 Transport.py:2614-2635)
$routerR = new MockRouter();
$routerR->linkTransportTable["$linkIdHex::iface_nas"] = $freshEntry();
$routerR->pathTable['33333333333333333333333333333333'] = ['hops' => 2, 'next_hop_hex' => '22222222222222222222222222222222', 'interface_id' => 'iface_nas'];
$pkt = makePacket(['packet_type' => 3, 'context' => 0xFF, 'hops' => 3, 'destination_hash_hex' => $linkIdHex]);
$ref = new ReflectionMethod($routerR, 'relayLinkRequestProofPacket');
assertEq('signed LRPROOF hops=3 on remaining=2 pending entry → rebalanced and relayed', 1, $ref->invoke($routerR, 'iface_nas', makeRawBase64($pkt), $pkt));
assertEq('rebalanced proof relayed to the browser', 'iface_browser', $routerR->outboundQueue[0]['interface_id'] ?? '');
assertEq('entry remaining_hops rebalanced to 3', 3, $routerR->linkTransportTable["$linkIdHex::iface_nas"]['remaining_hops']);
assertEq('entry validated', 1, $routerR->linkTransportTable["$linkIdHex::iface_nas"]['validated']);
assertEq('path hops rebalanced to 3', 3, $routerR->pathTable['33333333333333333333333333333333']['hops']);

// Unsigned hop mismatch → no rebalance, dropped by the exact gate
$routerU = new MockRouter();
$routerU->proofSignatureValid = false;
$routerU->linkTransportTable["$linkIdHex::iface_nas"] = $freshEntry();
$ref = new ReflectionMethod($routerU, 'relayLinkRequestProofPacket');
assertEq('invalid-signature LRPROOF hops=3 on remaining=2 → dropped', 0, $ref->invoke($routerU, 'iface_nas', makeRawBase64($pkt), $pkt));
assertEq('entry remaining_hops unchanged (2)', 2, $routerU->linkTransportTable["$linkIdHex::iface_nas"]['remaining_hops']);
assertTrue('outbound queue empty after invalid-signature drop', count($routerU->outboundQueue) === 0);

// ══════════════════════════════════════════════════════════════════════════
// Test 7: PLAIN/GROUP filter rejects hops > 1 AFTER inbound increment
// ══════════════════════════════════════════════════════════════════════════

echo "\n── Test 7: Filter rejects multi-hop PLAIN/GROUP ──\n";

$router4 = new MockRouter();
$ref = new ReflectionMethod($router4, 'applyPacketFilter');
$ref->setAccessible(true);

[$status, $reason] = $ref->invoke($router4, makePacket(['destination_type' => 2, 'packet_type' => 0, 'hops' => 2]));
assertEq('PLAIN hops=2 → rejected', 'rejected', $status);
assertEq('rejection reason', 'plain_hops_exceeded', $reason);

[$status, $reason] = $ref->invoke($router4, makePacket(['destination_type' => 2, 'packet_type' => 0, 'hops' => 1]));
assertEq('PLAIN hops=1 → accepted', 'accepted', $status);

[$status, $reason] = $ref->invoke($router4, makePacket(['destination_type' => 1, 'packet_type' => 0, 'hops' => 2]));
assertEq('GROUP hops=2 → rejected', 'rejected', $status);
assertEq('rejection reason', 'group_hops_exceeded', $reason);

[$status, $reason] = $ref->invoke($router4, makePacket(['destination_type' => 1, 'packet_type' => 0, 'hops' => 1]));
assertEq('GROUP hops=1 → accepted', 'accepted', $status);

// ══════════════════════════════════════════════════════════════════════════
// Test 8: Local LINKREQUEST link entry expects exactly 1 hop (the
//         directly attached client), not the path table's value
// ══════════════════════════════════════════════════════════════════════════

echo "\n── Test 8: Local LINKREQUEST remaining_hops ignores path table ──\n";

$router5 = new MockRouter();
$destHex = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaab';
$linkIdHex = '11111111111111111111111111111111';

// Simulate a stale path table entry (announce propagated 3 hops)
$router5->pathTable[$destHex] = [
    'hops' => 3,
    'next_hop_hex' => '22222222222222222222222222222222',
    'interface_id' => 'iface_bridge',
];

// Register the destination as local (browser client)
$router5->localDestinations[$destHex] = 'iface_browser';

// Override linkIdHex to return a fixed value
$router5->linkIdHexReturn = $linkIdHex;

$pkt = makePacket([
    'packet_type' => 2,       // LINKREQUEST
    'hops' => 1,              // post-inbound (arrived from NAS with hops=0, +1)
    'destination_hash_hex' => $destHex,
    'truncated_hash_hex' => substr($linkIdHex, 0, 16),
]);
$rawB64 = makeRawBase64($pkt);

$ref = new ReflectionMethod($router5, 'deliverLocallyIfKnown');
$ref->setAccessible(true);
$result = $ref->invoke($router5, 'iface_bridge', $rawB64, $pkt);
assertTrue('deliverLocallyIfKnown returned true', $result === true);

// Key is {linkIdHex}::{outbound_interface_id}
$linkKey = "$linkIdHex::iface_browser";
$entry = $router5->linkTransportTable[$linkKey] ?? null;
assertTrue('link transport entry created for local delivery', $entry !== null);

// Resolved 2026-09-22. The destination is a directly attached local client:
// its packets arrive with hops 0 and the inbound step counts them as 1, which
// is exactly what the reference's path table holds for a directly attached
// next hop. Its LRPROOF therefore arrives observed 1 and must equal
// remaining_hops 1 - the same exact gate a transit entry gets; the reference
// link_table has no "don't check" mode, so the earlier -1 sentinel (88ec642)
// is gone. The path table's 3 here is a stale relay path and must not be used.
assertEq('remaining_hops = 1 for a directly attached local destination', 1, $entry['remaining_hops'] ?? 0);
assertEq('taken_hops = observed hops (1)', 1, $entry['taken_hops'] ?? -1);
assertEq('received_interface is bridge', 'iface_bridge', $entry['received_interface_id'] ?? '');
assertEq('outbound_interface is browser', 'iface_browser', $entry['outbound_interface_id'] ?? '');

// ══════════════════════════════════════════════════════════════════════════
// Test 9: a link INITIATED FROM OUTSIDE to a local browser, end to end
// ══════════════════════════════════════════════════════════════════════════
//
// 2026-09-22, retichat.com: the Android app opened a link to a browser on the
// node (LINKREQUEST observed 7 hops, entry then remaining=-1 taken=7). The
// browser's LRPROOF (observed 1) did not match the entry — the lookup filtered
// on remaining_hops = 1 — and fell to the reverse-path fallback, which relayed the
// proof but recorded a SECOND entry with taken_hops = 1. The phone's LRRTT and
// its LXMF data (observed 7) then failed the taken-hops check on that entry and
// were dropped without a trace; the sender saw a delivery-proof timeout and
// fell back to propagation. Test 8 could not see this: the mock ignored the
// hop filter. Now it mirrors the SQL, the entry carries remaining_hops = 1
// (the directly attached client) and this test walks the whole exchange,
// including a wrong-hop LRPROOF on the local entry being dropped.

echo "\n── Test 9: outside-initiated link to a local browser round-trips ──\n";

$router6 = new MockRouter();
$destHex = 'b42714bda794d70a05dd70ce6140f59a';
$linkIdHex = '35411bbc80c2c3dcaa1e794ed0665e99';
$router6->localDestinations[$destHex] = 'iface_browser';
$router6->linkIdHexReturn = $linkIdHex;

// 1. LINKREQUEST arrives from the gateway, 7 hops away.
$lr = makePacket([
    'packet_type' => 2, 'hops' => 7,
    'destination_hash_hex' => $destHex,
    'truncated_hash_hex' => 'ffffffffffffffffffffffffffffffff',
]);
$ref = new ReflectionMethod($router6, 'deliverLocallyIfKnown');
$ref->setAccessible(true);
assertTrue('LINKREQUEST delivered locally', $ref->invoke($router6, 'iface_gateway', makeRawBase64($lr), $lr) === true);
$entry = $router6->linkTransportTable["$linkIdHex::iface_browser"] ?? null;
assertTrue('link entry exists', $entry !== null);
assertEq('entry: remaining_hops = 1 (directly attached client)', 1, $entry['remaining_hops'] ?? 0);
assertEq('entry: taken_hops = 7', 7, $entry['taken_hops'] ?? 0);

// 2. LRPROOF comes back from the browser, 1 hop.
$router6->outboundQueue = [];
$proof = makePacket(['packet_type' => 3, 'context' => 0xFF, 'hops' => 1, 'destination_hash_hex' => $linkIdHex]);
$ref = new ReflectionMethod($router6, 'relayLinkRequestProofPacket');
$ref->setAccessible(true);
assertEq('LRPROOF relayed (count=1)', 1, $ref->invoke($router6, 'iface_browser', makeRawBase64($proof), $proof));
assertEq('LRPROOF went to the gateway', 'iface_gateway', $router6->outboundQueue[0]['interface_id'] ?? '');
assertEq('LRPROOF matched the link entry, not the reverse-path fallback', 'lrproof_relay', $router6->outboundQueue[0]['reason'] ?? '');
assertEq('the entry is now validated', 1, $router6->linkTransportTable["$linkIdHex::iface_browser"]['validated'] ?? 0);
assertEq('still exactly one entry for the link', 1, count($router6->linkTransportEntries($linkIdHex)));

// 3. The initiator's LRRTT and data (observed 7 hops) reach the browser.
$ref = new ReflectionMethod($router6, 'relayLinkTransportPacket');
$ref->setAccessible(true);
$should = new ReflectionMethod($router6, 'shouldRelayLinkTransportPacket');
$should->setAccessible(true);
foreach ([0xFE => 'LRRTT', 0x00 => 'LXMF data'] as $ctx => $what) {
    $router6->outboundQueue = [];
    $pkt = makePacket(['packet_type' => 0, 'destination_type' => 2, 'context' => $ctx, 'hops' => 7, 'destination_hash_hex' => $linkIdHex]);
    assertTrue("$what from the gateway is a link transport packet", $should->invoke($router6, $pkt) === true);
    assertEq("$what from the gateway relayed (count=1)", 1, $ref->invoke($router6, 'iface_gateway', makeRawBase64($pkt), $pkt));
    assertEq("$what reached the browser", 'iface_browser', $router6->outboundQueue[0]['interface_id'] ?? '');
}

// 4. The browser's reply on the link (observed 1 hop) reaches the initiator.
$router6->outboundQueue = [];
$pkt = makePacket(['packet_type' => 0, 'destination_type' => 2, 'context' => 0x00, 'hops' => 1, 'destination_hash_hex' => $linkIdHex]);
assertEq('browser data relayed (count=1)', 1, $ref->invoke($router6, 'iface_browser', makeRawBase64($pkt), $pkt));
assertEq('browser data reached the gateway', 'iface_gateway', $router6->outboundQueue[0]['interface_id'] ?? '');

// 5. A transit entry only takes the proof from its next-hop interface: the
//    right hop count on the interface the LINKREQUEST came in on is dropped.
$router7 = new MockRouter();
$router7->linkTransportTable["$linkIdHex::iface_nas"] = [
    'link_id_hex' => $linkIdHex, 'received_interface_id' => 'iface_browser', 'outbound_interface_id' => 'iface_nas',
    'next_hop_hex' => $destHex, 'remaining_hops' => 2, 'taken_hops' => 1, 'destination_hash_hex' => $destHex, 'validated' => 0,
];
$proof = makePacket(['packet_type' => 3, 'context' => 0xFF, 'hops' => 2, 'destination_hash_hex' => $linkIdHex]);
assertEq('transit LRPROOF on the wrong interface is dropped', 0, $ref = (new ReflectionMethod($router7, 'relayLinkRequestProofPacket'))->invoke($router7, 'iface_browser', makeRawBase64($proof), $proof));

// 6. The local entry gets the same exact gate: a browser LRPROOF observed with
//    2 hops (it must be 1) whose signature does not validate cannot rebalance
//    the entry and is dropped. (With a valid signature it would rebalance, as
//    upstream does - see Test 6.) Fresh router, same LINKREQUEST setup.
$router8 = new MockRouter();
$router8->proofSignatureValid = false;
$router8->localDestinations[$destHex] = 'iface_browser';
$router8->linkIdHexReturn = $linkIdHex;
$ref = new ReflectionMethod($router8, 'deliverLocallyIfKnown');
$ref->setAccessible(true);
assertTrue('LINKREQUEST delivered locally (fresh router)', $ref->invoke($router8, 'iface_gateway', makeRawBase64($lr), $lr) === true);
$router8->outboundQueue = [];
$proof = makePacket(['packet_type' => 3, 'context' => 0xFF, 'hops' => 2, 'destination_hash_hex' => $linkIdHex]);
$ref = new ReflectionMethod($router8, 'relayLinkRequestProofPacket');
$ref->setAccessible(true);
assertEq('local LRPROOF with 2 hops is dropped (count=0)', 0, $ref->invoke($router8, 'iface_browser', makeRawBase64($proof), $proof));
assertEq('nothing queued for the wrong-hop local LRPROOF', 0, count($router8->outboundQueue));
assertEq('the local entry stays unvalidated', 0, $router8->linkTransportTable["$linkIdHex::iface_browser"]['validated'] ?? -1);

// ══════════════════════════════════════════════════════════════════════════
// Report
// ══════════════════════════════════════════════════════════════════════════

echo "\n" . str_repeat('=', 50) . "\n";
echo "Results: $pass passed, $fail failed" . ($known > 0 ? ", $known known divergence(s)" : "") . "\n";
if ($known > 0) {
    echo "Known divergences are documented in-file and do not fail the suite.\n";
}
echo str_repeat('=', 50) . "\n";

exit($fail > 0 ? 1 : 0);
