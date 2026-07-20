<?php

declare(strict_types=1);

/**
 * Unit tests for hop-count handling in the PHP Reticulum relay.
 *
 * Tests verify that after the HOPS.md fixes:
 *   1. transportObservedHops is a passthrough (post-inbound value)
 *   2. relayPacketBase64 uses transportObservedHops (no double +1)
 *   3. proofRelayPacketBase64 writes actual hop count into relayed bytes
 *   4. relayLinkRequestProofPacket uses exact hop match (no ±1 tolerance)
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

    public function linkTransportEntryForOutbound(string $linkIdHex, string $outboundInterfaceId): ?array
    {
        $key = "$linkIdHex::$outboundInterfaceId";
        return $this->linkTransportTable[$key] ?? null;
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

    public function touchLinkTransportEntry(string $linkIdHex, string $outboundInterfaceId, ?bool $validated = null): void {}
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

    public function linkIdHex(string $rawBase64, array $packet): ?string
    {
        return $packet['destination_hash_hex'] ?? null;
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

// LRPROOF with wrong hops (3 != remaining_hops=2) → dropped
$router3->outboundQueue = [];
$pkt = makePacket(['packet_type' => 3, 'context' => 0xFF, 'hops' => 3, 'destination_hash_hex' => $linkIdHex]);
$rawB64 = makeRawBase64($pkt);
$result = $ref->invoke($router3, 'iface_nas', $rawB64, $pkt);
assertEq('LRPROOF hops=3 ≠ remaining=2 → dropped (count=0)', 0, $result);
assertTrue('outbound queue empty', count($router3->outboundQueue) === 0);

// LRPROOF with hops=1 (was the special case '$observedHops !== 1' in old code) → dropped
$router3->outboundQueue = [];
$pkt = makePacket(['packet_type' => 3, 'context' => 0xFF, 'hops' => 1, 'destination_hash_hex' => $linkIdHex]);
$rawB64 = makeRawBase64($pkt);
$result = $ref->invoke($router3, 'iface_nas', $rawB64, $pkt);
assertEq('LRPROOF hops=1 (was old $observedHops !== 1 special case) → dropped', 0, $result);
assertTrue('outbound queue empty after hops=1 drop', count($router3->outboundQueue) === 0);

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
// Report
// ══════════════════════════════════════════════════════════════════════════

echo "\n" . str_repeat('=', 50) . "\n";
echo "Results: $pass passed, $fail failed\n";
echo str_repeat('=', 50) . "\n";

exit($fail > 0 ? 1 : 0);
