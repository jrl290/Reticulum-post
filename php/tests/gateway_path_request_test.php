<?php

declare(strict_types=1);

/**
 * Regression tests for gateway path-request routing.
 *
 * Verifies Python Transport.path_request() behaviour (Transport.py:2910-2940):
 *   1. Local client (rns-js) → forward to ALL other interfaces
 *   2. Transit (PHP peer / bridge) → forward to LOCAL CLIENTS only
 *   3. Transit, no local clients → IGNORE
 *   4. Tag dedup → duplicate tag → IGNORE
 *   5. Known path → answer with path response
 *   6. Requestor is next hop → IGNORE
 *
 * Run with: php tests/gateway_path_request_test.php
 */

require_once __DIR__ . '/../src/lib/request_control_plane_trait.php';
require_once __DIR__ . '/../src/lib/request_relay_routing_trait.php';
require_once __DIR__ . '/../src/lib/request_path_state_trait.php';
require_once __DIR__ . '/stubs/PacketParser.php';

// ── Minimal stubs for traits we don't need ───────────────────────────────

// ── Minimal stubs for traits we don't need ───────────────────────────────

// RequestControlPlaneTrait calls these, provide no-ops / simple stubs
trait RequestPacketIngestStub
{
    private function applyPacketFilter(array $packet): array
    {
        return ['accepted', 'ok'];
    }
    public function rememberPacketHash(string $hex): void {}
    public function packetHashExists(string $hex): bool { return false; }
}

trait RequestInterfaceRuntimeStub
{
    public array $ifaceMetadata = [];
    public function interfaceMetadata(string $interfaceId): array
    {
        return $this->ifaceMetadata[$interfaceId] ?? [];
    }
    public function isPhpPeerInterface(string $interfaceId): bool { return false; }
}

// ── Mock router ──────────────────────────────────────────────────────────

class GatewayMockRouter
{
    use \ReticulumPhp\RequestControlPlaneTrait;
    use \ReticulumPhp\RequestRelayRoutingTrait;
    use \ReticulumPhp\RequestPathStateTrait;
    use RequestPacketIngestStub;
    use RequestInterfaceRuntimeStub;

    /** @var list<array{interface_id:string, raw_base64:string, reason:string, source_interface_id:string}> */
    public array $outboundQueue = [];

    /** @var array<string, bool> */
    public array $pathRequestTags = [];

    /** @var array<string, array> */
    public array $pathTable = [];

    /** @var array<string, array> */
    public array $announceCache = [];

    /** @var list<string> */
    public array $localClientInterfaceIds = [];

    /** @var array<string, array> */
    public array $knownDestinations = [];

    public string $transportIdentityHashHex = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';

    // ── Stub helpers ─────────────────────────────────────────────────

    public function rememberPathRequestTag(string $tagKeyHex): bool
    {
        if (isset($this->pathRequestTags[$tagKeyHex])) {
            return false;
        }
        $this->pathRequestTags[$tagKeyHex] = true;
        return true;
    }

    public function pathEntry(string $destinationHashHex): ?array
    {
        return $this->pathTable[$destinationHashHex] ?? null;
    }

    public function isInterfaceActive(string $interfaceId): bool
    {
        // Any non-empty interface ID is active for test purposes
        return $interfaceId !== '';
    }

    public function announceRawByPacketHash(string $packetHashHex): ?string
    {
        return $this->announceCache[$packetHashHex] ?? null;
    }

    public function knownDestinationPublicKey(string $destinationHashHex): ?string
    {
        return null;
    }

    public function knownDestinationIdentityHash(string $destinationHashHex): ?string
    {
        return $this->knownDestinations[$destinationHashHex]['identity_hash_hex'] ?? null;
    }

    public function pathRequestControlHashHex(): string
    {
        // Well-known path request control hash
        return '6b9f66014d9853faab220fba47d02761';
    }

    public function transportIdentityHashHex(): string
    {
        return $this->transportIdentityHashHex;
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

    public function allOtherInterfaceIds(string $sourceInterfaceId): array
    {
        // Return all "online" transit interfaces except the source.
        // In tests we treat iface_backbone and iface_peer as transit,
        // and local_client_1 as rns-js (excluded here because it's local).
        $all = ['iface_backbone', 'iface_peer', 'local_client_1'];
        return array_values(array_filter(
            $all,
            fn(string $id) => $id !== $sourceInterfaceId
        ));
    }

    public function onlineLocalClientInterfaceIds(string $excludeInterfaceId): array
    {
        return array_values(array_filter(
            $this->localClientInterfaceIds,
            fn(string $id) => $id !== $excludeInterfaceId
        ));
    }

    public function ifacConfig(string $interfaceId): array { return []; }

    // decodeJson is called by the traits
    public static function decodeJson(string $json): mixed
    {
        if ($json === '') return [];
        $decoded = json_decode($json, true);
        return is_array($decoded) ? $decoded : [];
    }

    // config helper
    public function config(): array
    {
        return [
            'pathfinder_max_hops' => 128,
            'path_expiry_default_seconds' => 604800,
        ];
    }

    // ── Test helper: call processAcceptedPathRequest ──────────────────

    /**
     * @return array{0: string, 1: string, 2: int}
     */
    public function testProcessPathRequest(string $interfaceId, string $rawBase64, array $packet): array
    {
        return $this->processAcceptedPathRequest($interfaceId, $rawBase64, $packet);
    }
}

// ── Helper: build a path-request payload ─────────────────────────────────

function makePathRequestPayload(string $requestedDestHex, ?string $requestorTransportHex = null, ?string $tagBytes = null): string
{
    $payload = hex2bin($requestedDestHex);
    if ($requestorTransportHex !== null) {
        $payload .= hex2bin($requestorTransportHex);
    }
    if ($tagBytes !== null) {
        $payload .= hex2bin($tagBytes);
    } else {
        $payload .= random_bytes(8); // random tag
    }
    return $payload;
}

function makePathRequestPacket(string $requestedDestHex, array $overrides = []): array
{
    $tag = bin2hex(random_bytes(8));
    $payload = makePathRequestPayload($requestedDestHex, null, $tag);
    return array_merge([
        'packet_type' => 0,           // DATA
        'context' => 0x00,
        'context_flag' => 0,
        'header_type' => 0,
        'destination_type' => 2,       // PLAIN (path requests use PLAIN)
        'transport_type' => 0,
        'hops' => 0,
        'destination_hash_hex' => '6b9f66014d9853faab220fba47d02761', // path request control hash
        'transport_id_hex' => null,
        'payload_base64' => base64_encode($payload),
        'packet_hash_hex' => bin2hex(random_bytes(32)),
        'truncated_hash_hex' => bin2hex(random_bytes(8)),
        'normalized_raw_base64' => null,
    ], $overrides);
}

function makeRawBase64ForPacket(array $packet): string
{
    $flags = ((int) ($packet['context_flag'] ?? 0) << 5)
           | ((int) ($packet['header_type'] ?? 0) << 6)
           | ((int) ($packet['transport_type'] ?? 0) << 4)
           | ((int) ($packet['destination_type'] ?? 0) << 2)
           | ((int) ($packet['packet_type'] ?? 0));
    $hops = (int) ($packet['hops'] ?? 0);
    $dest = hex2bin($packet['destination_hash_hex']);
    $ctx = chr((int) ($packet['context'] ?? 0));
    $payload = base64_decode($packet['payload_base64']);
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
// Test 1: Local client → forward to ALL other interfaces
// ══════════════════════════════════════════════════════════════════════════

echo "\n── Test 1: Local client (rns-js) → forward to ALL interfaces ──\n";

$router = new GatewayMockRouter();
$router->ifaceMetadata['local_client_1'] = ['client' => 'rns-js', 'mode' => 1];
$router->localClientInterfaceIds = ['local_client_1'];

$pkt = makePathRequestPacket('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaab');
$rawB64 = makeRawBase64ForPacket($pkt);
$pkt['normalized_raw_base64'] = $rawB64;

[$status, $reason, $queued] = $router->testProcessPathRequest('local_client_1', $rawB64, $pkt);

assertEq('status is forwarded', 'forwarded', $status);
assertEq('reason is unknown_destination_forwarded', 'unknown_destination_forwarded', $reason);
// Forwarded to iface_backbone and iface_peer (both transit, not local_client_1)
assertEq('queued to 2 interfaces', 2, $queued);
assertEq('first target is iface_backbone', 'iface_backbone', $router->outboundQueue[0]['interface_id']);
assertEq('second target is iface_peer', 'iface_peer', $router->outboundQueue[1]['interface_id']);
assertEq('reason is path_request_forward', 'path_request_forward', $router->outboundQueue[0]['reason']);
// Source interface (local_client_1) is excluded
$targetIds = array_column($router->outboundQueue, 'interface_id');
assertTrue('local_client_1 excluded from targets', !in_array('local_client_1', $targetIds, true));

// ══════════════════════════════════════════════════════════════════════════
// Test 2: Transit (backbone bridge) → forward to local clients only
// ══════════════════════════════════════════════════════════════════════════

echo "\n── Test 2: Transit (bridge) → forward to local clients only ──\n";

$router = new GatewayMockRouter();
$router->ifaceMetadata['iface_backbone'] = ['client' => 'rns-post-interface', 'mode' => 6];
$router->ifaceMetadata['local_client_1'] = ['client' => 'rns-js', 'mode' => 1];
$router->ifaceMetadata['local_client_2'] = ['client' => 'rns-js', 'mode' => 1];
$router->localClientInterfaceIds = ['local_client_1', 'local_client_2'];

$pkt = makePathRequestPacket('bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb');
$rawB64 = makeRawBase64ForPacket($pkt);
$pkt['normalized_raw_base64'] = $rawB64;

[$status, $reason, $queued] = $router->testProcessPathRequest('iface_backbone', $rawB64, $pkt);

assertEq('status is forwarded', 'forwarded', $status);
assertEq('reason is forwarded_to_local_clients', 'forwarded_to_local_clients', $reason);
assertEq('queued to 2 local clients', 2, $queued);
// Only local clients, not transit interfaces
$targetIds = array_column($router->outboundQueue, 'interface_id');
assertTrue('local_client_1 is a target', in_array('local_client_1', $targetIds, true));
assertTrue('local_client_2 is a target', in_array('local_client_2', $targetIds, true));
assertTrue('iface_peer NOT a target', !in_array('iface_peer', $targetIds, true));
assertTrue('iface_backbone NOT a target', !in_array('iface_backbone', $targetIds, true));

// ══════════════════════════════════════════════════════════════════════════
// Test 3: Transit, no local clients → IGNORE
// ══════════════════════════════════════════════════════════════════════════

echo "\n── Test 3: Transit, no local clients → IGNORE ──\n";

$router = new GatewayMockRouter();
$router->ifaceMetadata['iface_peer'] = ['client' => 'reticulum-php'];
$router->localClientInterfaceIds = []; // no local clients

$pkt = makePathRequestPacket('cccccccccccccccccccccccccccccccc');
$rawB64 = makeRawBase64ForPacket($pkt);
$pkt['normalized_raw_base64'] = $rawB64;

[$status, $reason, $queued] = $router->testProcessPathRequest('iface_peer', $rawB64, $pkt);

assertEq('status is ignored', 'ignored', $status);
assertEq('reason is unknown_destination_transit', 'unknown_destination_transit', $reason);
assertEq('queued is 0', 0, $queued);
assertEq('outbound queue empty', 0, count($router->outboundQueue));

// ══════════════════════════════════════════════════════════════════════════
// Test 4: Duplicate tag → IGNORE
// ══════════════════════════════════════════════════════════════════════════

echo "\n── Test 4: Duplicate path request tag → IGNORE ──\n";

$router = new GatewayMockRouter();
$router->ifaceMetadata['local_client_1'] = ['client' => 'rns-js', 'mode' => 1];
$router->localClientInterfaceIds = ['local_client_1'];

$tag = 'aabbccddaabbccdd';
$payload = makePathRequestPayload('dddddddddddddddddddddddddddddddd', null, $tag);
$pkt = makePathRequestPacket('dddddddddddddddddddddddddddddddd', [
    'payload_base64' => base64_encode($payload),
]);
$rawB64 = makeRawBase64ForPacket($pkt);
$pkt['normalized_raw_base64'] = $rawB64;

// First request — should be forwarded
[$status1, $reason1, $queued1] = $router->testProcessPathRequest('local_client_1', $rawB64, $pkt);
assertEq('first request: status forwarded', 'forwarded', $status1);
assertTrue('first request: queued > 0', $queued1 > 0);

// Second request with same tag — should be ignored
$router->outboundQueue = [];
[$status2, $reason2, $queued2] = $router->testProcessPathRequest('local_client_1', $rawB64, $pkt);
assertEq('second request: status ignored', 'ignored', $status2);
assertEq('second request: reason duplicate_path_request_tag', 'duplicate_path_request_tag', $reason2);
assertEq('second request: queued 0', 0, $queued2);
assertEq('second request: outbound queue empty', 0, count($router->outboundQueue));

// ══════════════════════════════════════════════════════════════════════════
// Test 5: Known path → path response queued
// ══════════════════════════════════════════════════════════════════════════

echo "\n── Test 5: Known path → path response queued ──\n";

$router = new GatewayMockRouter();
$router->ifaceMetadata['local_client_1'] = ['client' => 'rns-js', 'mode' => 1];

$requestedDest = 'eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee';
$announceHash = 'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff';
$announceRaw = chr(0x00) . chr(0x00) . hex2bin($requestedDest) . chr(0x00) . str_repeat("\x00", 16);
$router->announceCache[$announceHash] = base64_encode($announceRaw);

$router->pathTable[$requestedDest] = [
    'destination_hash_hex' => $requestedDest,
    'next_hop_hex' => '11111111111111111111111111111111',
    'hops' => 3,
    'expires_at' => time() + 86400,
    'interface_id' => 'iface_backbone',
    'packet_hash_hex' => $announceHash,
    'announce_emitted' => 0,
    'updated_at' => time(),
    'random_blobs_json' => '[]',
];

$pkt = makePathRequestPacket($requestedDest);
$rawB64 = makeRawBase64ForPacket($pkt);
$pkt['normalized_raw_base64'] = $rawB64;

[$status, $reason, $queued] = $router->testProcessPathRequest('local_client_1', $rawB64, $pkt);

assertEq('status is response_queued', 'response_queued', $status);
assertEq('reason is known_path_response', 'known_path_response', $reason);
assertEq('queued is 1', 1, $queued);
assertEq('outbound reason is path_response', 'path_response', $router->outboundQueue[0]['reason']);
assertEq('outbound target is local_client_1', 'local_client_1', $router->outboundQueue[0]['interface_id']);

// ══════════════════════════════════════════════════════════════════════════
// Test 6: Requestor is next hop → IGNORE
// ══════════════════════════════════════════════════════════════════════════

echo "\n── Test 6: Requestor is next hop → IGNORE ──\n";

$router = new GatewayMockRouter();
$router->ifaceMetadata['local_client_1'] = ['client' => 'rns-js', 'mode' => 1];

$requestedDest = 'ffffffffffffffffffffffffffffffff';
$requestorTransport = '11111111111111111111111111111111'; // same as next_hop

$announceHash = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';
$announceRaw = chr(0x00) . chr(0x00) . hex2bin($requestedDest) . chr(0x00) . str_repeat("\x00", 16);
$router->announceCache[$announceHash] = base64_encode($announceRaw);

$router->pathTable[$requestedDest] = [
    'destination_hash_hex' => $requestedDest,
    'next_hop_hex' => $requestorTransport, // same as requestor
    'hops' => 2,
    'expires_at' => time() + 86400,
    'interface_id' => 'iface_backbone',
    'packet_hash_hex' => $announceHash,
    'announce_emitted' => 0,
    'updated_at' => time(),
    'random_blobs_json' => '[]',
];

$payload = makePathRequestPayload($requestedDest, $requestorTransport, 'aabbccdd');
$pkt = makePathRequestPacket($requestedDest, [
    'payload_base64' => base64_encode($payload),
]);
$rawB64 = makeRawBase64ForPacket($pkt);
$pkt['normalized_raw_base64'] = $rawB64;

[$status, $reason, $queued] = $router->testProcessPathRequest('local_client_1', $rawB64, $pkt);

assertEq('status is ignored', 'ignored', $status);
assertEq('reason is requestor_is_next_hop', 'requestor_is_next_hop', $reason);
assertEq('queued is 0', 0, $queued);

// ══════════════════════════════════════════════════════════════════════════
// Test 7: Payload too short → IGNORE
// ══════════════════════════════════════════════════════════════════════════

echo "\n── Test 7: Payload too short → IGNORE ──\n";

$router = new GatewayMockRouter();
$router->ifaceMetadata['local_client_1'] = ['client' => 'rns-js', 'mode' => 1];

$pkt = makePathRequestPacket('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaab', [
    'payload_base64' => base64_encode(hex2bin('aaaa')), // only 2 bytes
]);
$rawB64 = makeRawBase64ForPacket($pkt);
$pkt['normalized_raw_base64'] = $rawB64;

[$status, $reason, $queued] = $router->testProcessPathRequest('local_client_1', $rawB64, $pkt);

assertEq('status is ignored', 'ignored', $status);
assertEq('reason is path_request_payload_too_short', 'path_request_payload_too_short', $reason);
assertEq('queued is 0', 0, $queued);

// ══════════════════════════════════════════════════════════════════════════
// Test 8: Tagless path request (payload exactly 16 bytes) → IGNORE
// ══════════════════════════════════════════════════════════════════════════

echo "\n── Test 8: Tagless path request (payload=16 bytes) → IGNORE ──\n";

$router = new GatewayMockRouter();
$router->ifaceMetadata['local_client_1'] = ['client' => 'rns-js', 'mode' => 1];

// Payload exactly 16 bytes (destination hash only, no tag/requestor bytes)
// This hits strlen($payload) < 17 → path_request_payload_too_short
$payload = hex2bin('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaab');
$pkt = makePathRequestPacket('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaab', [
    'payload_base64' => base64_encode($payload),
]);
$rawB64 = makeRawBase64ForPacket($pkt);
$pkt['normalized_raw_base64'] = $rawB64;

[$status, $reason, $queued] = $router->testProcessPathRequest('local_client_1', $rawB64, $pkt);

assertEq('status is ignored', 'ignored', $status);
assertEq('reason is path_request_payload_too_short', 'path_request_payload_too_short', $reason);
assertEq('queued is 0', 0, $queued);

// ══════════════════════════════════════════════════════════════════════════
// Test 9: Transit with source excluded from local clients
// ══════════════════════════════════════════════════════════════════════════

echo "\n── Test 9: Transit → local client excludes source iface ──\n";

$router = new GatewayMockRouter();
$router->ifaceMetadata['iface_peer'] = ['client' => 'reticulum-php'];
$router->ifaceMetadata['local_client_1'] = ['client' => 'rns-js', 'mode' => 1];
$router->localClientInterfaceIds = ['local_client_1', 'iface_peer']; // peer is also a local client? edge case

$pkt = makePathRequestPacket('0000000000000000000000000000000f');
$rawB64 = makeRawBase64ForPacket($pkt);
$pkt['normalized_raw_base64'] = $rawB64;

[$status, $reason, $queued] = $router->testProcessPathRequest('iface_peer', $rawB64, $pkt);

assertEq('status is forwarded', 'forwarded', $status);
assertEq('reason is forwarded_to_local_clients', 'forwarded_to_local_clients', $reason);
// iface_peer is in localClientIds but should be excluded as source
$targetIds = array_column($router->outboundQueue, 'interface_id');
assertTrue('iface_peer excluded (is source)', !in_array('iface_peer', $targetIds, true));
assertTrue('local_client_1 included', count($targetIds) === 1 && $targetIds[0] === 'local_client_1');

// ══════════════════════════════════════════════════════════════════════════
// Test 10: Known path but cached announce missing → IGNORE
// ══════════════════════════════════════════════════════════════════════════

echo "\n── Test 10: Known path, missing cached announce → IGNORE ──\n";

$router = new GatewayMockRouter();
$router->ifaceMetadata['local_client_1'] = ['client' => 'rns-js', 'mode' => 1];

$requestedDest = 'deadbeefdeadbeefdeadbeefdeadbeef';
$router->pathTable[$requestedDest] = [
    'destination_hash_hex' => $requestedDest,
    'next_hop_hex' => '22222222222222222222222222222222',
    'hops' => 1,
    'expires_at' => time() + 86400,
    'interface_id' => 'iface_backbone',
    'packet_hash_hex' => 'missing_missing_missing_missing_miss',
    'announce_emitted' => 0,
    'updated_at' => time(),
    'random_blobs_json' => '[]',
];
// announceCache is empty — announceRawByPacketHash returns null

$pkt = makePathRequestPacket($requestedDest);
$rawB64 = makeRawBase64ForPacket($pkt);
$pkt['normalized_raw_base64'] = $rawB64;

[$status, $reason, $queued] = $router->testProcessPathRequest('local_client_1', $rawB64, $pkt);

assertEq('status is ignored', 'ignored', $status);
assertEq('reason is cached_announce_not_found', 'cached_announce_not_found', $reason);
assertEq('queued is 0', 0, $queued);

// ══════════════════════════════════════════════════════════════════════════

echo "\n────────────────────────────────────────\n";
echo "Results: $pass passed, $fail failed\n";
echo "────────────────────────────────────────\n";

exit($fail > 0 ? 1 : 0);
