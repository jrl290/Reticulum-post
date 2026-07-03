<?php

declare(strict_types=1);

namespace ReticulumPhp;

// Reticulum-php is request-operated. These announce and control-plane helpers
// validate state and queue responses for the next authenticated exchange;
// they do not create a separate always-on transport path.

trait RequestControlPlaneTrait
{
    private function processAcceptedAnnounce(string $interfaceId, array $packet): array
    {
        try {
            $knownPublicKeyHex = $this->knownDestinationPublicKey((string) $packet['destination_hash_hex']);
            $announce = AnnounceValidator::validate($packet, $knownPublicKeyHex);
            $this->rememberKnownDestination(
                (string) $packet['destination_hash_hex'],
                (string) $packet['packet_hash_hex'],
                $announce,
            );

            // Register as a local destination if the announce arrived on a non-relay interface
            // (e.g. the browser's HTTP exchange interface, not a backbone-facing transport)
            $this->registerLocalDestinationIfOwnInterface((string) $packet['destination_hash_hex'], $interfaceId);

            return $this->upsertPathFromAnnounce($interfaceId, $packet, $announce);
        } catch (\Throwable $error) {
            return ['invalid', $error->getMessage()];
        }
    }

    private function isPathRequestPacket(array $packet): bool
    {
        return (int) ($packet['packet_type'] ?? -1) === 0
            && (int) ($packet['destination_type'] ?? -1) === 2
            && (string) ($packet['destination_hash_hex'] ?? '') === $this->pathRequestControlHashHex();
    }

    private function processAcceptedPathRequest(string $interfaceId, string $rawBase64, array $packet): array
    {
        $payload = base64_decode((string) ($packet['payload_base64'] ?? ''), true);
        if (!is_string($payload) || strlen($payload) < 17) {
            return ['ignored', 'path_request_payload_too_short', 0];
        }

        $destinationHashHex = bin2hex(substr($payload, 0, 16));
        $requestorTransportHex = null;
        $tagBytes = null;

        if (strlen($payload) > 32) {
            $requestorTransportHex = bin2hex(substr($payload, 16, 16));
            $tagBytes = substr($payload, 32);
        } elseif (strlen($payload) > 16) {
            $tagBytes = substr($payload, 16);
        }

        if (!is_string($tagBytes) || $tagBytes === '') {
            return ['ignored', 'path_request_without_tag', 0];
        }

        if (strlen($tagBytes) > 16) {
            $tagBytes = substr($tagBytes, 0, 16);
        }

        $tagKeyHex = bin2hex(hex2bin($destinationHashHex) . $tagBytes);
        if (!$this->rememberPathRequestTag($tagKeyHex)) {
            return ['ignored', 'duplicate_path_request_tag', 0];
        }

        $path = $this->usablePathEntry($destinationHashHex);
        if ($path === null) {
            $queued = $this->forwardPathRequestPacket($interfaceId, $rawBase64, $packet);
            if ($queued > 0) {
                return ['forwarded', 'unknown_destination_forwarded', $queued];
            }

            return ['ignored', 'unknown_destination_path', 0];
        }

        $nextHopHex = (string) $path['next_hop_hex'];
        if ($requestorTransportHex !== null && hash_equals($requestorTransportHex, $nextHopHex)) {
            return ['ignored', 'requestor_is_next_hop', 0];
        }

        $announceRaw = $this->announceRawByPacketHash((string) $path['packet_hash_hex']);
        if ($announceRaw === null) {
            return ['ignored', 'cached_announce_not_found', 0];
        }

        $responseRaw = $this->buildPathResponsePacket(
            $announceRaw,
            (string) $destinationHashHex,
            (int) $path['hops']
        );
        $this->queueOutboundPacket($interfaceId, base64_encode($responseRaw), 'path_response', $interfaceId);

        return ['response_queued', 'known_path_response', 1];
    }

    private function isCacheRequestPacket(array $packet): bool
    {
        return (int) ($packet['packet_type'] ?? -1) === 0
            && (int) ($packet['context'] ?? -1) === 0x08;
    }

    private function processAcceptedCacheRequest(string $rawBase64, array $packet): array
    {
        $payload = base64_decode((string) ($packet['payload_base64'] ?? ''), true);
        if (!is_string($payload) || strlen($payload) !== 32) {
            return ['ignored', 'cache_request_hash_length_invalid', 0, false];
        }

        $cachedAnnounce = $this->cachedAnnounceRecordByPacketHash(bin2hex($payload));
        if ($cachedAnnounce === null) {
            return ['miss', 'cached_announce_not_found', 0, false];
        }

        $queued = $this->replayCachedAnnouncePacket(
            (string) $cachedAnnounce['received_interface_id'],
            (string) $cachedAnnounce['raw_base64']
        );

        if ($queued === 0) {
            return ['miss', 'cached_announce_not_relayed', 0, false];
        }

        return ['replayed', 'cached_announce_replayed', $queued, true];
    }

    private function shouldRelayAcceptedPacket(array $packet): bool
    {
        if ((int) ($packet['packet_type'] ?? -1) === 1 && (string) ($packet['announce_status'] ?? '') === 'invalid') {
            return false;
        }

        if ($this->isPathRequestPacket($packet)) {
            return false;
        }

        if ((int) ($packet['destination_type'] ?? -1) === 3) {
            return false;
        }

        return true;
    }

    private function registerLocalDestinationIfOwnInterface(string $destinationHashHex, string $interfaceId): void
    {
        // Only register as local if this interface is NOT a relay/peer interface
        $metadata = $this->interfaceMetadata($interfaceId);
        $transport = (string) ($metadata['transport'] ?? '');
        // http-exchange = browser, unknown/unset = local client
        if ($transport === 'tcp-backbone-gateway' || $transport === 'php-peer-exchange') {
            return; // Don't register backbone-facing interfaces as local
        }

        $stmt = $this->db->prepare(
            'INSERT OR REPLACE INTO local_destinations (destination_hash_hex, interface_id, registered_at)
             VALUES (:dest, :iface, :ts)'
        );
        $stmt->bindValue(':dest', $destinationHashHex, SQLITE3_TEXT);
        $stmt->bindValue(':iface', $interfaceId, SQLITE3_TEXT);
        $stmt->bindValue(':ts', time(), SQLITE3_INTEGER);
        $stmt->execute();
    }

    private function localDestinationInterface(string $destinationHashHex): ?string
    {
        $stmt = $this->db->prepare(
            'SELECT interface_id FROM local_destinations WHERE destination_hash_hex = :dest LIMIT 1'
        );
        $stmt->bindValue(':dest', $destinationHashHex, SQLITE3_TEXT);
        $row = $stmt->execute()->fetchArray(SQLITE3_ASSOC);

        if (!is_array($row)) {
            return null;
        }

        $ifaceId = (string) ($row['interface_id'] ?? '');
        // Verify the interface still exists
        $metadata = $this->interfaceMetadata($ifaceId);
        if ($metadata === []) {
            return null;
        }

        return $ifaceId;
    }

    private function relayTargetsForAcceptedPacket(string $sourceInterfaceId, array $packet): array
    {
        $activeTargets = $this->activePeerInterfaceIds($sourceInterfaceId);
        if ($activeTargets === []) {
            return [];
        }

        if ((int) ($packet['packet_type'] ?? -1) !== 1) {
            $path = $this->usablePathEntry((string) ($packet['destination_hash_hex'] ?? ''));
            if ($path !== null) {
                $targetInterfaceId = (string) ($path['interface_id'] ?? '');
                if ($targetInterfaceId !== '' && in_array($targetInterfaceId, $activeTargets, true)) {
                    return [$targetInterfaceId];
                }
            }
        }

        return $activeTargets;
    }

    private function upsertPathFromAnnounce(string $interfaceId, array $packet, array $announce): array
    {
        $destinationHashHex = (string) $packet['destination_hash_hex'];
        $normalizedDestinationHashHex = strtolower($destinationHashHex);
        $hops = (int) $packet['hops'];
        $maxHops = (int) ($this->config['transport']['pathfinder_max_hops'] ?? 128);
        if ($hops > $maxHops) {
            return ['validated', 'announce_hops_exceeded'];
        }

        $current = $this->pathEntry($destinationHashHex);
        $randomHashHex = (string) $announce['random_hash_hex'];
        $announceEmitted = (int) $announce['announce_emitted'];
        $now = time();
        $shouldAdd = false;
        $reason = 'announce_ignored';

        if ($current === null) {
            $shouldAdd = true;
            $reason = 'new_destination';
            $randomBlobs = [$randomHashHex];
        } else {
            $currentUsable = $this->usablePathEntry($destinationHashHex) !== null;
            $currentNextHopHex = strtolower((string) ($current['next_hop_hex'] ?? ''));
            $currentInterfaceId = (string) ($current['interface_id'] ?? '');
            $incomingTransportIdHex = $packet['transport_id_hex'] === null ? null : strtolower((string) $packet['transport_id_hex']);
            $metadata = $this->interfaceMetadata($interfaceId);
            $preserveTransportPath = $currentUsable
                && $currentInterfaceId !== ''
                && hash_equals($currentInterfaceId, $interfaceId)
                && (string) ($metadata['transport'] ?? '') === 'http-exchange'
                && $currentNextHopHex !== ''
                && !hash_equals($currentNextHopHex, $normalizedDestinationHashHex)
                && $incomingTransportIdHex === null
                && $hops <= 1;

            if ($preserveTransportPath) {
                return ['validated', 'transport_path_preserved'];
            }

            $randomBlobs = self::decodeJson((string) $current['random_blobs_json']);
            $blobSeen = in_array($randomHashHex, $randomBlobs, true);
            $pathExpires = (int) $current['expires_at'];
            $existingHops = (int) $current['hops'];
            $pathTimebase = $this->randomBlobTimebase($randomBlobs);

            if (!$currentUsable) {
                $shouldAdd = true;
                $reason = 'unusable_path_replaced';
            } elseif ($hops <= $existingHops) {
                if (!$blobSeen && $announceEmitted > $pathTimebase) {
                    $shouldAdd = true;
                    $reason = 'better_or_equal_hops_newer_announce';
                }
            } else {
                if ($now >= $pathExpires && !$blobSeen) {
                    $shouldAdd = true;
                    $reason = 'expired_path_replaced';
                } elseif (!$blobSeen && $announceEmitted > (int) $current['announce_emitted']) {
                    $shouldAdd = true;
                    $reason = 'newer_announce_replaced';
                }
            }

            if ($shouldAdd) {
                $randomBlobs = array_values(array_unique(array_merge([$randomHashHex], $randomBlobs)));
            }
        }

        if (!$shouldAdd) {
            return ['validated', $reason];
        }

        $maxRandomBlobs = (int) ($this->config['transport']['max_random_blobs'] ?? 64);
        $randomBlobs = array_slice($randomBlobs, 0, $maxRandomBlobs);
        $nextHopHex = $packet['transport_id_hex'] === null ? $destinationHashHex : (string) $packet['transport_id_hex'];
        $expiresAt = $now + $this->pathExpirySeconds($interfaceId);

        $stmt = $this->db->prepare(
            'INSERT INTO path_entries (
                destination_hash_hex,
                next_hop_hex,
                hops,
                expires_at,
                random_blobs_json,
                interface_id,
                packet_hash_hex,
                announce_emitted,
                updated_at
            ) VALUES (
                :destination_hash_hex,
                :next_hop_hex,
                :hops,
                :expires_at,
                :random_blobs_json,
                :interface_id,
                :packet_hash_hex,
                :announce_emitted,
                :updated_at
            )
            ON CONFLICT(destination_hash_hex) DO UPDATE SET
                next_hop_hex = excluded.next_hop_hex,
                hops = excluded.hops,
                expires_at = excluded.expires_at,
                random_blobs_json = excluded.random_blobs_json,
                interface_id = excluded.interface_id,
                packet_hash_hex = excluded.packet_hash_hex,
                announce_emitted = excluded.announce_emitted,
                updated_at = excluded.updated_at'
        );
        $stmt->bindValue(':destination_hash_hex', $destinationHashHex, SQLITE3_TEXT);
        $stmt->bindValue(':next_hop_hex', $nextHopHex, SQLITE3_TEXT);
        $stmt->bindValue(':hops', $hops, SQLITE3_INTEGER);
        $stmt->bindValue(':expires_at', $expiresAt, SQLITE3_INTEGER);
        $stmt->bindValue(':random_blobs_json', self::encodeJson($randomBlobs), SQLITE3_TEXT);
        $stmt->bindValue(':interface_id', $interfaceId, SQLITE3_TEXT);
        $stmt->bindValue(':packet_hash_hex', (string) $packet['packet_hash_hex'], SQLITE3_TEXT);
        $stmt->bindValue(':announce_emitted', $announceEmitted, SQLITE3_INTEGER);
        $stmt->bindValue(':updated_at', $now, SQLITE3_INTEGER);
        $stmt->execute();

        return ['path_updated', $reason];
    }
}