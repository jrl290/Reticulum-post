<?php

declare(strict_types=1);

namespace ReticulumPhp;

use PDO;

// Reticulum-php is request-operated. These LXMF handoff helpers turn queued
// application payloads into normal Reticulum packets during a request; they do
// not add a second transport path outside authenticated exchanges.

trait RequestLxmfHandoffTrait
{
    public function handoffLxmfOutboxWire(string $wireBase64, bool $queuePathRequest = false): array
    {
        $wire = base64_decode($wireBase64, true);
        if (!is_string($wire) || strlen($wire) <= 16) {
            throw new \RuntimeException('wire_base64 must decode to a destination hash and packet payload');
        }

        $destinationHashHex = bin2hex(substr($wire, 0, 16));
        $packetPayload = substr($wire, 16);

        $path = $this->usableLxmfOutboxPathEntry($destinationHashHex);
        if ($path === null) {
            $queuedInterfaceIds = $queuePathRequest
                ? $this->queuePathRequestForDestination($destinationHashHex)
                : [];

            return [
                'status' => 'waiting_for_path',
                'destination_hash_hex' => $destinationHashHex,
                'queued_interface_ids' => $queuedInterfaceIds,
                'path_request_queued' => $queuedInterfaceIds !== [],
            ];
        }

        $destination = $this->knownDestinationRecord($destinationHashHex);
        if ($destination === null) {
            $queuedInterfaceIds = $queuePathRequest
                ? $this->queuePathRequestForDestination($destinationHashHex)
                : [];

            return [
                'status' => 'waiting_for_identity',
                'destination_hash_hex' => $destinationHashHex,
                'queued_interface_ids' => $queuedInterfaceIds,
                'path_request_queued' => $queuedInterfaceIds !== [],
            ];
        }

        $interfaceId = (string) ($path['interface_id'] ?? '');
        if ($interfaceId === '') {
            throw new \RuntimeException('usable path did not contain an interface id');
        }

        $packetRaw = $this->buildOutboundSinglePacket(
            $destinationHashHex,
            $packetPayload,
            $destination,
            $path,
            $interfaceId,
        );

        if (strlen($packetRaw) > $this->maxPacketBytesForInterface($interfaceId)) {
            throw new \RuntimeException('generated packet exceeds max_packet_bytes for interface');
        }

        $this->queueOutboundPacket($interfaceId, base64_encode($packetRaw), 'lxmf_outbox');
        $parsed = PacketParser::parseRaw($packetRaw);

        return [
            'status' => 'queued',
            'destination_hash_hex' => $destinationHashHex,
            'interface_id' => $interfaceId,
            'packet_hash_hex' => (string) ($parsed['packet_hash_hex'] ?? ''),
            'queued_interface_ids' => [$interfaceId],
        ];
    }

    public function interfaceName(string $interfaceId): ?string
    {
        $stmt = $this->db->prepare(
            'SELECT name FROM interfaces WHERE interface_id = :interface_id LIMIT 1'
        );
        $stmt->bindValue(':interface_id', $interfaceId, PDO::PARAM_STR);
        $row = $stmt->execute(); $row = $stmt->fetch(PDO::FETCH_ASSOC);

        return is_array($row) ? (string) ($row['name'] ?? '') : null;
    }

    private function knownDestinationRecord(string $destinationHashHex): ?array
    {
        $stmt = $this->db->prepare(
            'SELECT public_key_hex, identity_hash_hex, ratchet_hex, updated_at
             FROM known_destinations
             WHERE destination_hash_hex = :destination_hash_hex
             LIMIT 1'
        );
        $stmt->bindValue(':destination_hash_hex', $destinationHashHex, PDO::PARAM_STR);
        $row = $stmt->execute(); $row = $stmt->fetch(PDO::FETCH_ASSOC);

        return is_array($row) ? $row : null;
    }

    private function usableLxmfOutboxPathEntry(string $destinationHashHex): ?array
    {
        $path = $this->usablePathEntry($destinationHashHex);
        if ($path === null) {
            return null;
        }

        $interfaceId = (string) ($path['interface_id'] ?? '');
        if ($interfaceId === '') {
            return null;
        }

        $metadata = $this->interfaceMetadata($interfaceId);
        if ((string) ($metadata['transport'] ?? '') !== 'php-peer-exchange') {
            return $path;
        }

        foreach ($this->activePeerInterfaceIds('') as $candidateInterfaceId) {
            if ($candidateInterfaceId === $interfaceId) {
                continue;
            }

            $candidateMetadata = $this->interfaceMetadata($candidateInterfaceId);
            if ((string) ($candidateMetadata['transport'] ?? '') === 'http-exchange') {
                return null;
            }
        }

        return $path;
    }

    private function knownRatchetMaxAgeSeconds(): int
    {
        $receiverWindow = max(0, (512 - 1) * (30 * 60));
        return min($receiverWindow, 60 * 60 * 24 * 30);
    }

    private function freshRatchetHex(array $destination): ?string
    {
        $ratchetHex = $destination['ratchet_hex'] ?? null;
        if (!is_string($ratchetHex) || $ratchetHex === '') {
            return null;
        }

        $updatedAt = (int) ($destination['updated_at'] ?? 0);
        if ($updatedAt <= 0) {
            return null;
        }

        if ($updatedAt + $this->knownRatchetMaxAgeSeconds() < time()) {
            return null;
        }

        return $ratchetHex;
    }

    private function queuePathRequestForDestination(string $destinationHashHex): array
    {
        $destinationHash = hex2bin($destinationHashHex);
        if (!is_string($destinationHash) || strlen($destinationHash) !== 16) {
            throw new \RuntimeException('destination hash must be 16 bytes');
        }

        $controlHash = hex2bin($this->pathRequestControlHashHex());
        if (!is_string($controlHash) || strlen($controlHash) !== 16) {
            throw new \RuntimeException('path request control hash must be 16 bytes');
        }

        $payload = $destinationHash . random_bytes(8);
        $raw = chr(0x08) . chr(0x00) . $controlHash . chr(0x00) . $payload;
        $packetBase64 = base64_encode($raw);
        $interfaceIds = [];

        foreach ($this->activePeerInterfaceIds('') as $interfaceId) {
            $this->queueOutboundPacket($interfaceId, $packetBase64, 'lxmf_path_request');
            $interfaceIds[] = $interfaceId;
        }

        return array_values(array_unique($interfaceIds));
    }

    private function buildOutboundSinglePacket(
        string $destinationHashHex,
        string $payload,
        array $destination,
        ?array $path = null,
        ?string $interfaceId = null,
    ): string
    {
        if (!function_exists('openssl_encrypt')) {
            throw new \RuntimeException('ext/openssl is required for outbound LXMF handoff');
        }

        if (!function_exists('sodium_crypto_scalarmult') || !function_exists('sodium_crypto_scalarmult_base')) {
            throw new \RuntimeException('ext/sodium is required for outbound LXMF handoff');
        }

        $destinationHash = hex2bin($destinationHashHex);
        if (!is_string($destinationHash) || strlen($destinationHash) !== 16) {
            throw new \RuntimeException('destination hash must be 16 bytes');
        }

        $publicKey = hex2bin((string) ($destination['public_key_hex'] ?? ''));
        if (!is_string($publicKey) || strlen($publicKey) !== 64) {
            throw new \RuntimeException('known destination public key must be 64 bytes');
        }

        $targetPublicKey = substr($publicKey, 0, 32);
        $ratchetHex = $this->freshRatchetHex($destination);
        if (is_string($ratchetHex) && $ratchetHex !== '') {
            $ratchet = hex2bin($ratchetHex);
            if (!is_string($ratchet) || strlen($ratchet) !== 32) {
                throw new \RuntimeException('known destination ratchet must be 32 bytes');
            }

            $targetPublicKey = $ratchet;
        }

        $identityHash = hex2bin((string) ($destination['identity_hash_hex'] ?? ''));
        if (!is_string($identityHash) || strlen($identityHash) !== 16) {
            $identityHash = substr(hash('sha256', $publicKey, true), 0, 16);
        }

        $ephemeralSecret = random_bytes(SODIUM_CRYPTO_BOX_SECRETKEYBYTES);
        $ephemeralPublic = sodium_crypto_scalarmult_base($ephemeralSecret);
        $sharedKey = sodium_crypto_scalarmult($ephemeralSecret, $targetPublicKey);
        $derivedKey = hash_hkdf('sha256', $sharedKey, 64, '', $identityHash);
        if (!is_string($derivedKey) || strlen($derivedKey) !== 64) {
            throw new \RuntimeException('unable to derive outbound LXMF packet key');
        }

        $token = $this->encryptIdentityToken($payload, $derivedKey);
        $packetRaw = chr(0x00) . chr(0x00) . $destinationHash . chr(0x00) . $ephemeralPublic . $token;

        return $this->wrapOutboundHttpExchangePacket($packetRaw, $destinationHashHex, $path, $interfaceId);
    }

    private function wrapOutboundHttpExchangePacket(
        string $packetRaw,
        string $destinationHashHex,
        ?array $path,
        ?string $interfaceId,
    ): string
    {
        if ($path === null || $interfaceId === null) {
            return $packetRaw;
        }

        $metadata = $this->interfaceMetadata($interfaceId);
        if ((string) ($metadata['transport'] ?? '') !== 'http-exchange') {
            return $packetRaw;
        }

        $nextHopHex = strtolower((string) ($path['next_hop_hex'] ?? ''));
        $normalizedDestinationHashHex = strtolower($destinationHashHex);
        $remainingHops = (int) ($path['hops'] ?? 0);
        if ($nextHopHex === '') {
            return $packetRaw;
        }

        if ($remainingHops <= 1 && hash_equals($nextHopHex, $normalizedDestinationHashHex)) {
            return $packetRaw;
        }

        $nextHop = hex2bin($nextHopHex);
        if (!is_string($nextHop) || strlen($nextHop) !== 16) {
            throw new \RuntimeException('usable path next hop must be 16 bytes for http-exchange outbound');
        }

        $flags = ord($packetRaw[0]);
        $transportFlags = ($flags & 0x20) | 0x40 | 0x10 | ($flags & 0x0F);

        return chr($transportFlags) . $packetRaw[1] . $nextHop . substr($packetRaw, 2);
    }

    private function encryptIdentityToken(string $payload, string $derivedKey): string
    {
        $signingKey = substr($derivedKey, 0, 32);
        $encryptionKey = substr($derivedKey, 32, 32);
        $iv = random_bytes(16);
        $ciphertext = openssl_encrypt(
            $payload,
            'aes-256-cbc',
            $encryptionKey,
            OPENSSL_RAW_DATA,
            $iv,
        );

        if (!is_string($ciphertext)) {
            throw new \RuntimeException('unable to encrypt outbound LXMF packet payload');
        }

        $signedParts = $iv . $ciphertext;
        return $signedParts . hash_hmac('sha256', $signedParts, $signingKey, true);
    }
}