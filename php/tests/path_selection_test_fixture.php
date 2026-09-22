<?php
/**
 * Shared fixture for the PHP relay's path-selection and local-destination
 * tests: an in-memory SQLite router built from the real traits, plus packet,
 * announce and path-seeding helpers. Extracted from path_selection_test.php
 * on 2026-09-22 so local_destination_moves_test.php can reuse it.
 */
declare(strict_types=1);

require_once __DIR__ . '/../src/lib/request_control_plane_trait.php';
require_once __DIR__ . '/../src/lib/request_path_state_trait.php';
require_once __DIR__ . '/../src/lib/request_json_codec_trait.php';
require_once __DIR__ . '/../src/lib/request_relay_routing_trait.php';
require_once __DIR__ . '/../src/lib/database.php';

// ══════════════════════════════════════════════════════════════════════════
// Mock harness
// ══════════════════════════════════════════════════════════════════════════

class PathSelectionMockRouter
{
    use \ReticulumPhp\RequestControlPlaneTrait;
    use \ReticulumPhp\RequestPathStateTrait;
    use \ReticulumPhp\RequestJsonCodecTrait;
    use \ReticulumPhp\RequestRelayRoutingTrait;

    public \PDO $db;
    public string $backend = 'sqlite';
    public array $config = [];
    /** @var array<string, array> */
    public array $metadataByInterface = [];

    public function __construct()
    {
        $this->db = new \PDO('sqlite::memory:', options: [
            \PDO::ATTR_ERRMODE => \PDO::ERRMODE_EXCEPTION,
        ]);

        $this->db->exec('CREATE TABLE local_destinations (
            destination_hash_hex TEXT PRIMARY KEY,
            interface_id TEXT NOT NULL,
            registered_at INTEGER NOT NULL
        )');
        $this->db->exec('CREATE TABLE path_entries (
            destination_hash_hex TEXT PRIMARY KEY,
            next_hop_hex TEXT NOT NULL,
            hops INTEGER NOT NULL,
            expires_at INTEGER NOT NULL,
            random_blobs_json TEXT NOT NULL DEFAULT \'[]\',
            interface_id TEXT NOT NULL,
            packet_hash_hex TEXT NOT NULL,
            announce_emitted INTEGER NOT NULL,
            updated_at INTEGER NOT NULL
        )');

        $this->config = [
            'transport' => [
                'pathfinder_max_hops' => 128,
                'path_expiry_default_seconds' => 604800,
                'max_random_blobs' => 64,
            ],
        ];
    }

    // ── Overrides: avoid real DB / real interface lookups ─────────────

    private function interfaceMetadata(string $interfaceId): array
    {
        return $this->metadataByInterface[$interfaceId] ?? [];
    }

    private function isInterfaceActive(string $interfaceId): bool
    {
        // For tests, all interfaces are active.
        return true;
    }

    // ── Stubs for trait requirements ──────────────────────────────────

    public function rememberKnownDestination(string $destHashHex, string $packetHashHex, array $announce): void {}
    public function registerLocalDestinationIfOwnInterface(string $destHashHex, string $interfaceId): void {}
    public function knownDestinationPublicKey(string $destHashHex): ?string { return null; }

    // ── Public test entry point ───────────────────────────────────────

    /**
     * @return array{0: string, 1: string}  ['validated'|'invalid', $reason]
     */
    public function test_upsertPathFromAnnounce(string $interfaceId, array $packet, array $announce): array
    {
        return $this->upsertPathFromAnnounce($interfaceId, $packet, $announce);
    }

    /** Read the path table row for assertions. */
    public function test_pathEntry(string $destinationHashHex): ?array
    {
        return $this->pathEntry($destinationHashHex);
    }
}

// ══════════════════════════════════════════════════════════════════════════
// Helpers
// ══════════════════════════════════════════════════════════════════════════

/**
 * Create a minimal packet array (what the PHP relay sees post-parse).
 */
function mkPacket(array $overrides = []): array
{
    return array_merge([
        'packet_type'       => 0,
        'context'           => 0x00,
        'context_flag'      => 0,
        'header_type'       => 0,
        'destination_type'  => 0,
        'transport_type'    => 0,
        'hops'              => 2,          // post-inbound (transportObservedHops)
        'destination_hash_hex' => '1762c055000000000000000000000000',
        'transport_id_hex'  => null,       // null = direct (no intermediate transport)
        'payload_base64'    => 'AAAA',
        'normalized_raw_base64' => null,
        'truncated_hash_hex'=> null,
        'packet_hash_hex'   => 'cccccccccccccccccccccccccccccccc',
    ], $overrides);
}

/**
 * Create a minimal announce array (as returned by AnnounceValidator::validate).
 *
 * The random_hash_hex must be 10 bytes (20 hex chars) for randomBlobTimebase()
 * to parse it correctly.
 */
function mkAnnounce(array $overrides = []): array
{
    return array_merge([
        'random_hash_hex'   => 'aaaa11112222333344445555',  // 10 bytes = 20 hex
        'announce_emitted'  => time(),
        'identity_hash_hex' => 'eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee',
        'public_key_hex'    => null,
    ], $overrides);
}

/**
 * Pre-seed the path_entries table with an existing (longer) path.
 *
 * Returns the random_blobs_json that was written so the caller can assert
 * against the same blob.
 */
function seedPath(PathSelectionMockRouter $r, string $destHex, int $hops, string $ifaceId, string $blobHex, int $emitted = 0): string
{
    $emitted = $emitted ?: time() - 60;
    $expires = time() + 3600;
    $blobsJson = json_encode([$blobHex], JSON_THROW_ON_ERROR);

    $stmt = $r->db->prepare('INSERT OR REPLACE INTO path_entries
        (destination_hash_hex, next_hop_hex, hops, expires_at,
         random_blobs_json, interface_id, packet_hash_hex,
         announce_emitted, updated_at)
        VALUES (:dh, :nh, :hops, :exp, :blobs, :iface, :ph, :emitted, :upd)');
    $stmt->execute([
        ':dh'      => $destHex,
        ':nh'      => $destHex,
        ':hops'    => $hops,
        ':exp'     => $expires,
        ':blobs'   => $blobsJson,
        ':iface'   => $ifaceId,
        ':ph'      => 'cccccccccccccccccccccccccccccccc',
        ':emitted' => $emitted,
        ':upd'     => time(),
    ]);

    return $blobsJson;
}

// ══════════════════════════════════════════════════════════════════════════
// Test runner
// ══════════════════════════════════════════════════════════════════════════

$pass = 0;
$fail = 0;

