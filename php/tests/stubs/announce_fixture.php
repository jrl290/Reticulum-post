<?php
/**
 * Test-side RNS announces, DATA packets and cache requests, built from the
 * RNS 1.5.2 layout independently of php/src (Packet.py,
 * Destination.announce, Identity):
 *
 *   name_hash   = SHA-256("app.aspect…")[:10]
 *   dest        = SHA-256(name_hash || identity_hash)[:16]
 *   random_hash = 5 random bytes || u40be(emitted seconds)
 *   signed      = dest || public_key || name_hash || random_hash || app_data
 *   payload     = public_key(64) || name_hash || random_hash || signature(64) || app_data
 *   raw         = flags(0x01: HEADER_1, SINGLE, ANNOUNCE) || hops || dest || context(0) || payload
 *
 * The hop count is outside the hashable part (Packet.get_hashable_part), so a
 * copy with another hop count has the same packet hash and the same random
 * blob: a replay. Identities come from RegFixture::identity().
 *
 * Not a test: php/tests/stubs/ holds fixtures, and deploy.sh runs only
 * php/tests/*.php.
 */
declare(strict_types=1);

final class AnnounceFixture
{
    /** @return array{raw: string, dest_hex: string, random_hex: string, packet_hash_hex: string, emitted: int} */
    public static function announce(array $identity, string $fullName, int $hops = 0, ?string $randomHash = null, string $appData = '', ?int $emitted = null): array
    {
        $nameHash = substr(hash('sha256', $fullName, true), 0, 10);
        $dest = substr(hash('sha256', $nameHash . $identity['hash'], true), 0, 16);
        $emitted ??= time();
        $randomHash ??= random_bytes(5) . substr(pack('J', $emitted), 3, 5);
        $signature = sodium_crypto_sign_detached($dest . $identity['public_key'] . $nameHash . $randomHash . $appData, $identity['ed_sk']);
        $payload = $identity['public_key'] . $nameHash . $randomHash . $signature . $appData;
        $raw = chr(0x01) . chr($hops) . $dest . chr(0x00) . $payload;

        return [
            'raw' => $raw,
            'dest_hex' => bin2hex($dest),
            'random_hex' => bin2hex($randomHash),
            'packet_hash_hex' => self::packetHash($raw),
            'emitted' => $emitted,
        ];
    }

    /** The same announce with another (unsigned) hop count: same packet hash, same blob. */
    public static function withHops(string $raw, int $hops): string
    {
        return $raw[0] . chr($hops) . substr($raw, 2);
    }

    /** A DATA packet (HEADER_1, SINGLE) to a destination. */
    public static function data(string $destHex, string $payload = ''): string
    {
        return chr(0x00) . chr(0) . (string) hex2bin($destHex) . chr(0x00) . ($payload === '' ? random_bytes(40) : $payload);
    }

    /**
     * A CACHE_REQUEST (DATA, context 0x08) for the announce with this packet
     * hash: its payload is the full 32-byte hash (Transport.cache_request).
     * Addressed to a destination nobody holds, so the request itself is
     * neither delivered nor routed.
     */
    public static function cacheRequest(string $packetHashHex): string
    {
        return chr(0x00) . chr(0) . random_bytes(16) . chr(0x08) . (string) hex2bin($packetHashHex);
    }

    /** Packet.get_hashable_part, hashed: the low flag bits, then the packet past the header (and transport id). */
    public static function packetHash(string $raw): string
    {
        $flags = ord($raw[0]);
        $headerTwo = ($flags & 0x40) !== 0;

        return hash('sha256', chr($flags & 0x0F) . substr($raw, $headerTwo ? 18 : 2));
    }

    /** Feed raw packets to the real inbound path, as an exchange from $interfaceId would. */
    public static function ingest(ReticulumPhp\Storage $storage, string $interfaceId, string ...$raws): array
    {
        return $storage->ingestInboundBatchInline($interfaceId, 'b-' . bin2hex(random_bytes(8)), array_map('base64_encode', $raws));
    }
}
