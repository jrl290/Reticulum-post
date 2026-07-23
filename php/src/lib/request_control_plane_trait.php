<?php

declare(strict_types=1);

namespace ReticulumPhp;

use PDO;

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

    /**
     * Return online local-client (rns-js) interface IDs excluding the given
     * source.  Used by the gateway procedure to forward transit path
     * requests to local clients only (Transport.py line 2930-2935).
     *
     * @return list<string>
     */
    private function onlineLocalClientInterfaceIds(string $excludeInterfaceId): array
    {
        $stmt = $this->db->prepare(
            "SELECT interface_id, metadata_json FROM interfaces
             WHERE status = 'online'
               AND interface_id != :exclude_id"
        );
        $stmt->bindValue(':exclude_id', $excludeInterfaceId, PDO::PARAM_STR);
        $stmt->execute();

        $ids = [];
        while (($row = $stmt->fetch(PDO::FETCH_ASSOC)) !== false) {
            $metadata = self::decodeJson((string) ($row['metadata_json'] ?? ''));
            if (((string) ($metadata['client'] ?? '')) === 'rns-js') {
                $ids[] = (string) $row['interface_id'];
            }
        }

        return $ids;
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
            // Python Transport.path_request() gateway procedure
            // (Transport.py lines 2910-2940):
            //
            //   1. From local client (rns-js): forward to ALL other
            //      interfaces — the gateway advertises the request to
            //      the wider network on behalf of its client.
            //
            //   2. From transit (PHP peer / backbone bridge): forward
            //      to LOCAL CLIENTS ONLY — ask local clients if they
            //      know the destination. Do NOT forward back to transit
            //      interfaces, as that creates amplification loops.
            //
            //   3. From transit with no local clients: ignore.
            $metadata = $this->interfaceMetadata($interfaceId);
            $isLocalClient = ((string) ($metadata['client'] ?? '') === 'rns-js');

            if ($isLocalClient) {
                // Case 1: local client → forward to all interfaces
                $queued = $this->forwardPathRequestPacket($interfaceId, $rawBase64, $packet);
                if ($queued > 0) {
                    return ['forwarded', 'unknown_destination_forwarded', $queued];
                }

                return ['ignored', 'unknown_destination_path', 0];
            }

            // Case 2: transit → forward to local clients only
            $localClientIds = $this->onlineLocalClientInterfaceIds($interfaceId);
            if ($localClientIds !== []) {
                $relayPacketBase64 = $this->relayPacketBase64($rawBase64, $packet);
                $queued = 0;
                foreach ($localClientIds as $localIfaceId) {
                    $this->queueOutboundPacket($localIfaceId, $relayPacketBase64, 'path_request_forward', $interfaceId);
                    $queued++;
                }

                return ['forwarded', 'forwarded_to_local_clients', $queued];
            }

            // Case 3: transit with no local clients → ignore
            return ['ignored', 'unknown_destination_transit', 0];
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
        // Announces: relay when the path was updated OR when it's time
        // for a periodic refresh. The Python reference re-relays announces
        // periodically to keep downstream path tables alive. Without this,
        // paths on downstream nodes (NAS, Meshchat) expire and destinations
        // become unreachable.
        if ((int) ($packet['packet_type'] ?? -1) === 1) {
            $status = (string) ($packet['announce_status'] ?? '');
            if ($status === 'path_updated') {
                return true;
            }
            if ($status === 'validated') {
                return $this->shouldRefreshAnnounceRelay((string) ($packet['destination_hash_hex'] ?? ''));
            }
            return false;
        }

        // Path requests are handled separately.
        if ($this->isPathRequestPacket($packet)) {
            return false;
        }

        // Data and link packets: relay if a usable path exists.
        // Proofs (type 3) are routed by reverse path, not generic relay.
        if ((int) ($packet['packet_type'] ?? -1) === 3) {
            return false;
        }

        return true;
    }

    private function shouldRefreshAnnounceRelay(string $destinationHashHex): bool
    {
        // Re-relay validated announces no more than once every 5 minutes
        // per destination. This keeps downstream path tables alive without
        // flooding the network.
        $path = $this->pathEntry($destinationHashHex);
        if ($path === null) {
            return false;
        }

        $updatedAt = (int) ($path['updated_at'] ?? 0);
        $now = time();
        $refreshInterval = (int) ($this->config['transport']['announce_refresh_seconds'] ?? 300);

        return ($now - $updatedAt) >= $refreshInterval;
    }

    private function touchPathEntryTimestamp(string $destinationHashHex): void
    {
        $now = time();
        $stmt = $this->db->prepare(
            'UPDATE path_entries SET updated_at = :now WHERE destination_hash_hex = :dest'
        );
        $stmt->bindValue(':now', $now, PDO::PARAM_INT);
        $stmt->bindValue(':dest', $destinationHashHex, PDO::PARAM_STR);
        $stmt->execute();
    }

    private function registerLocalDestinationIfOwnInterface(string $destinationHashHex, string $interfaceId): void
    {
        // PHP peer interfaces are transit pipes, not local endpoints.
        // Their announces represent destinations on the remote node.
        if ($this->isPhpPeerInterface($interfaceId)) {
            return;
        }

        // Only rns-js browser/client endpoints can register local destinations.
        // Bridge/post-interface tunnels (client=rns-post-interface or
        // client=reticulum-php) carry foreign announces that must NOT
        // overwrite real endpoint registrations.
        $metadata = $this->interfaceMetadata($interfaceId);
        $client = (string) ($metadata['client'] ?? '');
        if ($client !== 'rns-js') {
            // This is a bridge/tunnel — do NOT register its announces as local.
            return;
        }

        $mode = (int) ($metadata['mode'] ?? 1); // default MODE_FULL

        // RNS mode constants: MODE_ACCESS_POINT=3, MODE_BOUNDARY=5, MODE_GATEWAY=6
        if ($mode === 3 || $mode === 5 || $mode === 6) {
            return; // Transit interface — announces represent remote peers, not local
        }

        // Endpoint registrations from actual browsers/clients take priority.
        // If the existing registration is also an endpoint, allow the new
        // endpoint to overwrite (browser re-registered on new interface).
        $existing = $this->localDestinationRaw($destinationHashHex);
        if ($existing !== null) {
            $existingIface = (string) ($existing['interface_id'] ?? '');
            if ($existingIface === $interfaceId) {
                // Same interface re-announcing — update timestamp below.
            } else {
                $existingIsTransit = $this->isPhpPeerInterface($existingIface)
                    || in_array((int) ($this->interfaceMode($existingIface)), [3, 5, 6], true);
                $newIsTransit = $this->isPhpPeerInterface($interfaceId)
                    || in_array($mode, [3, 5, 6], true);
                if (!$existingIsTransit && $newIsTransit) {
                    // Existing is a real endpoint, new is transit — keep existing.
                    return;
                }
                // Otherwise: endpoint→endpoint (re-registration), transit→endpoint,
                // or transit→transit — allow the update.
                $del = $this->db->prepare('DELETE FROM local_destinations WHERE destination_hash_hex = :dest');
                $del->bindValue(':dest', $destinationHashHex, PDO::PARAM_STR);
                $del->execute();
            }
        }

        $stmt = $this->db->prepare($this->insertOrSql(
            'INSERT OR IGNORE INTO local_destinations (destination_hash_hex, interface_id, registered_at)
             VALUES (:dest, :iface, :ts)'
        ));
        $stmt->bindValue(':dest', $destinationHashHex, PDO::PARAM_STR);
        $stmt->bindValue(':iface', $interfaceId, PDO::PARAM_STR);
        $stmt->bindValue(':ts', time(), PDO::PARAM_INT);
        $stmt->execute();
    }

    private function localDestinationRaw(string $destinationHashHex): ?array
    {
        $stmt = $this->db->prepare(
            'SELECT interface_id, registered_at FROM local_destinations WHERE destination_hash_hex = :dest LIMIT 1'
        );
        $stmt->bindValue(':dest', $destinationHashHex, PDO::PARAM_STR);
        $row = $stmt->execute(); $row = $stmt->fetch(PDO::FETCH_ASSOC);
        return is_array($row) ? $row : null;
    }

    private function localDestinationInterface(string $destinationHashHex): ?string
    {
        $stmt = $this->db->prepare(
            'SELECT interface_id FROM local_destinations WHERE destination_hash_hex = :dest LIMIT 1'
        );
        $stmt->bindValue(':dest', $destinationHashHex, PDO::PARAM_STR);
        $row = $stmt->execute(); $row = $stmt->fetch(PDO::FETCH_ASSOC);

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
        // Standard RNS: relay announces to all other interfaces.
        if ((int) ($packet['packet_type'] ?? -1) === 1) {
            return $this->allOtherInterfaceIds($sourceInterfaceId);
        }

        // Non-announce: follow the path table to the next-hop interface.
        $destHashHex = (string) ($packet['destination_hash_hex'] ?? '');
        $path = $this->usablePathEntry($destHashHex);
        if ($path !== null) {
            $targetInterfaceId = (string) ($path['interface_id'] ?? '');
            if ($targetInterfaceId !== '' && $targetInterfaceId !== $sourceInterfaceId) {
                return [$targetInterfaceId];
            }
        }

        // Link-addressed packets (e.g. RTT on established links) have
        // a link ID as destination, which won't be in the path table.
        // The link ID is registered in local_destinations when the
        // LRPROOF is relayed. Check there as a fallback.
        if ($path === null && $destHashHex !== '') {
            $localIface = $this->localDestinationInterface($destHashHex);
            if ($localIface !== null && $localIface !== $sourceInterfaceId) {
                return [$localIface];
            }
        }

        return [];
    }

    private function upsertPathFromAnnounce(string $interfaceId, array $packet, array $announce): array
    {
        $destinationHashHex = (string) $packet['destination_hash_hex'];
        $normalizedDestinationHashHex = strtolower($destinationHashHex);
        // Python reference increments packet.hops at inbound() start (L1398),
        // then stores the already-incremented value in path table (L1837→1957).
        // transportObservedHops() mirrors this: it returns hops+1, the number
        // of hops taken including this node.
        $hops = $this->transportObservedHops($packet);
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

        $sql = 'INSERT INTO path_entries (
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
                updated_at = excluded.updated_at';
        $sql = Database::upsertSql($sql, $this->backend);
        $stmt = $this->db->prepare($sql);
        $stmt->bindValue(':destination_hash_hex', $destinationHashHex, PDO::PARAM_STR);
        $stmt->bindValue(':next_hop_hex', $nextHopHex, PDO::PARAM_STR);
        $stmt->bindValue(':hops', $hops, PDO::PARAM_INT);
        $stmt->bindValue(':expires_at', $expiresAt, PDO::PARAM_INT);
        $stmt->bindValue(':random_blobs_json', self::encodeJson($randomBlobs), PDO::PARAM_STR);
        $stmt->bindValue(':interface_id', $interfaceId, PDO::PARAM_STR);
        $stmt->bindValue(':packet_hash_hex', (string) $packet['packet_hash_hex'], PDO::PARAM_STR);
        $stmt->bindValue(':announce_emitted', $announceEmitted, PDO::PARAM_INT);
        $stmt->bindValue(':updated_at', $now, PDO::PARAM_INT);
        $stmt->execute();

        return ['path_updated', $reason];
    }
}