<?php

declare(strict_types=1);

namespace ReticulumPhp;

use PDO;

// Reticulum-php is request-operated. These inbound batch helpers accept,
// process, and summarize packets only during authenticated request exchanges;
// they do not create a second transport path.

trait RequestInboundBatchTrait
{
    public function recordInboundBatch(string $interfaceId, string $batchId, array $packets): array
    {
        $duplicateCheck = $this->db->prepare(
            'SELECT packet_count, byte_count FROM inbound_batches WHERE interface_id = :interface_id AND batch_id = :batch_id'
        );
        $duplicateCheck->bindValue(':interface_id', $interfaceId, PDO::PARAM_STR);
        $duplicateCheck->bindValue(':batch_id', $batchId, PDO::PARAM_STR);
        $existing = $duplicateCheck->execute(); $row = $duplicateCheck->fetch(PDO::FETCH_ASSOC);

        if (is_array($existing)) {
            return [
                'duplicate_batch' => true,
                'accepted_packets' => (int) $existing['packet_count'],
                'accepted_bytes' => (int) $existing['byte_count'],
            ];
        }

        $byteCount = $this->batchByteCount($packets);

        try {
            $stmt = $this->db->prepare(
                'INSERT INTO inbound_batches (
                    interface_id, batch_id, packet_count, byte_count,
                    payload_json, created_at, processed_at, processing_summary_json
                )
                 VALUES (
                    :interface_id, :batch_id, :packet_count, :byte_count,
                    :payload_json, :created_at, NULL, NULL
                )'
            );
            $stmt->bindValue(':interface_id', $interfaceId, PDO::PARAM_STR);
            $stmt->bindValue(':batch_id', $batchId, PDO::PARAM_STR);
            $stmt->bindValue(':packet_count', count($packets), PDO::PARAM_INT);
            $stmt->bindValue(':byte_count', $byteCount, PDO::PARAM_INT);
            $stmt->bindValue(':payload_json', self::encodeJson($packets), PDO::PARAM_STR);
            $stmt->bindValue(':created_at', time(), PDO::PARAM_INT);
            $stmt->execute();
        } catch (\PDOException $e) {
            // Race: another request inserted the same batch between our
            // duplicate check and this insert. Treat as duplicate.
            if (str_contains($e->getMessage(), 'Duplicate entry') || str_contains($e->getMessage(), 'UNIQUE constraint')) {
                return [
                    'duplicate_batch' => true,
                    'accepted_packets' => count($packets),
                    'accepted_bytes' => $byteCount,
                ];
            }
            throw $e;
        }

        $this->incrementInterfaceRxCounters($interfaceId, count($packets), $byteCount);

        return [
            'duplicate_batch' => false,
            'accepted_packets' => count($packets),
            'accepted_bytes' => $byteCount,
        ];
    }

    public function ingestInboundBatchInline(string $interfaceId, string $batchId, array $packets): array
    {
        $duplicateCheck = $this->db->prepare(
            'SELECT packet_count, byte_count FROM inbound_batches WHERE interface_id = :interface_id AND batch_id = :batch_id'
        );
        $duplicateCheck->bindValue(':interface_id', $interfaceId, PDO::PARAM_STR);
        $duplicateCheck->bindValue(':batch_id', $batchId, PDO::PARAM_STR);
        $existing = $duplicateCheck->execute(); $row = $duplicateCheck->fetch(PDO::FETCH_ASSOC);

        if (is_array($existing)) {
            return [
                'duplicate_batch' => true,
                'accepted_packets' => (int) $existing['packet_count'],
                'accepted_bytes' => (int) $existing['byte_count'],
                'processing' => null,
            ];
        }

        $byteCount = $this->batchByteCount($packets);
        $now = time();
        $claim = $this->db->prepare(
            'INSERT INTO inbound_batches (
                interface_id, batch_id, packet_count, byte_count,
                payload_json, created_at, processed_at, processing_summary_json
            )
             VALUES (
                :interface_id, :batch_id, :packet_count, :byte_count,
                :payload_json, :created_at, :processed_at, NULL
            )'
        );
        $claim->bindValue(':interface_id', $interfaceId, PDO::PARAM_STR);
        $claim->bindValue(':batch_id', $batchId, PDO::PARAM_STR);
        $claim->bindValue(':packet_count', count($packets), PDO::PARAM_INT);
        $claim->bindValue(':byte_count', $byteCount, PDO::PARAM_INT);
        $claim->bindValue(':payload_json', self::encodeJson([]), PDO::PARAM_STR);
        $claim->bindValue(':created_at', $now, PDO::PARAM_INT);
        $claim->bindValue(':processed_at', 0, PDO::PARAM_INT);
        try {
            $claim->execute();
        } catch (\PDOException $e) {
            if (str_contains($e->getMessage(), 'Duplicate entry') || str_contains($e->getMessage(), 'UNIQUE constraint')) {
                return [
                    'duplicate_batch' => true,
                    'accepted_packets' => count($packets),
                    'accepted_bytes' => $byteCount,
                ];
            }
            throw $e;
        }

        $this->incrementInterfaceRxCounters($interfaceId, count($packets), $byteCount);

        $summary = $this->newInboundProcessingSummary();
        $row = [
            'interface_id' => $interfaceId,
            'batch_id' => $batchId,
            'payload_json' => self::encodeJson($packets),
        ];
        $this->processInboundBatchRow($row, $summary);

        return [
            'duplicate_batch' => false,
            'accepted_packets' => count($packets),
            'accepted_bytes' => $byteCount,
            'processing' => $summary,
        ];
    }

    public function processInboundBatches(int $limit): array
    {
        $summary = $this->newInboundProcessingSummary();
        $stmt = $this->db->prepare(
            'SELECT interface_id, batch_id, payload_json
             FROM inbound_batches
             WHERE processed_at IS NULL
             ORDER BY created_at ASC
             LIMIT :limit'
        );
        $stmt->bindValue(':limit', $limit, PDO::PARAM_INT);
        $stmt->execute();

        while (($row = $stmt->fetch(PDO::FETCH_ASSOC)) !== false) {
            if (!is_array($row)) {
                continue;
            }

            $this->processInboundBatchRow($row, $summary);
        }

        return $summary;
    }

    public function processInboundBatch(string $interfaceId, string $batchId): array
    {
        $summary = $this->newInboundProcessingSummary();
        $stmt = $this->db->prepare(
            'SELECT interface_id, batch_id, payload_json
             FROM inbound_batches
             WHERE interface_id = :interface_id
               AND batch_id = :batch_id
               AND processed_at IS NULL
             LIMIT 1'
        );
        $stmt->bindValue(':interface_id', $interfaceId, PDO::PARAM_STR);
        $stmt->bindValue(':batch_id', $batchId, PDO::PARAM_STR);
        $row = $stmt->execute(); $row = $stmt->fetch(PDO::FETCH_ASSOC);

        if (!is_array($row)) {
            return $summary;
        }

        $this->processInboundBatchRow($row, $summary);

        return $summary;
    }

    private function newInboundProcessingSummary(): array
    {
        return [
            'batches_processed' => 0,
            'packets_parsed' => 0,
            'packet_errors' => 0,
            'packets_rejected' => 0,
            'outbound_proofs_marked' => 0,
            'announces_validated' => 0,
            'announce_paths_updated' => 0,
            'announce_validation_failures' => 0,
            'path_requests_seen' => 0,
            'path_requests_forwarded' => 0,
            'path_responses_queued' => 0,
            'path_requests_ignored' => 0,
            'cache_requests_seen' => 0,
            'cache_requests_replayed' => 0,
            'cache_requests_ignored' => 0,
            'relay_packets_queued' => 0,
            'local_deliveries' => 0,
        ];
    }

    private function deliverLocallyIfKnown(string $sourceInterfaceId, string $rawBase64, array $packet): bool
    {
        $destHash = (string) ($packet['destination_hash_hex'] ?? '');
        $pktType = (int) ($packet['packet_type'] ?? -1);
        error_log("[deliverLocallyIfKnown] type=$pktType dest=" . substr($destHash,0,12) . " src=" . substr($sourceInterfaceId,0,10));
        if ($destHash === '') {
            return false;
        }

        $localIface = $this->localDestinationInterface($destHash);
        error_log("[deliverLocallyIfKnown] localIface=" . ($localIface ? substr($localIface,0,10) : 'null'));

        // Fallback: if exact destination hash isn't registered, try to
        // match by identity. Different aspects of the same identity
        // (e.g. identity vs lxmf.delivery) have different destination
        // hashes but must route to the same endpoint.
        if ($localIface === null) {
            $destIdentityHex = $this->knownDestinationIdentityHash($destHash);
            if ($destIdentityHex !== null) {
                // Check all local destinations for one with the same identity
                $stmt = $this->db->prepare(
                    'SELECT ld.interface_id
                     FROM local_destinations ld
                     INNER JOIN known_destinations kd
                       ON kd.destination_hash_hex = ld.destination_hash_hex
                     WHERE kd.identity_hash_hex = :id_hash
                     LIMIT 1'
                );
                $stmt->bindValue(':id_hash', $destIdentityHex, PDO::PARAM_STR);
                $stmt->execute();
                $row = $stmt->fetch(PDO::FETCH_ASSOC);
                if (is_array($row)) {
                    $localIface = (string) ($row['interface_id'] ?? '');
                }
            }
        }

        if ($localIface === null || $localIface === $sourceInterfaceId) {
            return false;
        }

        // Queue the packet as-is (no hop increment) for local delivery
        $queueReason = 'local_delivery';
        $this->queueOutboundPacket($localIface, $rawBase64, $queueReason, $sourceInterfaceId);

        // Remember the reverse path so proofs can be routed back to the
        // requester (the bridge/NAS). This is needed for both DATA (type 0)
        // and LINKREQUEST (type 2) packets — without it, regular proofs
        // for opportunistically-delivered data cannot find their way back.
        if ((int) ($packet['packet_type'] ?? -1) === 0 || (int) ($packet['packet_type'] ?? -1) === 2) {
            $truncatedHashHex = (string) ($packet['truncated_hash_hex'] ?? '');
            if ($truncatedHashHex !== '') {
                $this->rememberReversePath($truncatedHashHex, $sourceInterfaceId, $localIface);
            }
        }

        // For LINKREQUEST packets, also register the link hash as a local
        // destination so that subsequent link packets (RTT, data, close)
        // addressed to the link's truncated hash can be delivered to the
        // browser rather than being relayed to peers.
        if ((int) ($packet['packet_type'] ?? -1) === 2) {
            $truncatedHashHex = (string) ($packet['truncated_hash_hex'] ?? '');
            if ($truncatedHashHex !== '') {
                $this->registerLinkLocalDestination($truncatedHashHex, $localIface);
            }

            // Create a link transport entry so that returning LRPROOF,
            // LRRTT and subsequent link-addressed packets are routed
            // back to the link initiator (NAS). Python reference creates
            // this unconditionally in Transport.outbound() for all
            // forwarded LINKREQUESTs, including to local clients.
            $destinationHashHex = (string) ($packet['destination_hash_hex'] ?? '');
            $linkIdHex = $this->linkIdHex($rawBase64, $packet);
            if ($linkIdHex !== null && $linkIdHex !== '') {
                $path = $this->usablePathEntry($destinationHashHex);
                $remainingHops = $path !== null ? (int) ($path['hops'] ?? 0) : $this->transportObservedHops($packet);
                $takenHops = $this->transportObservedHops($packet);
                $nextHopHex = $path !== null ? (string) ($path['next_hop_hex'] ?? $destinationHashHex) : $destinationHashHex;
                $this->rememberLinkTransportEntry(
                    $linkIdHex,
                    $sourceInterfaceId,
                    $localIface,
                    $nextHopHex,
                    $remainingHops,
                    $takenHops,
                    $destinationHashHex
                );
            }
        }

        error_log("[deliverLocallyIfKnown] returning TRUE (queued local_delivery)");
        return true;
    }

    /**
     * Look up the identity hash for a destination hash from known_destinations.
     */
    private function knownDestinationIdentityHash(string $destinationHashHex): ?string
    {
        $stmt = $this->db->prepare(
            'SELECT identity_hash_hex FROM known_destinations
             WHERE destination_hash_hex = :dest
             LIMIT 1'
        );
        $stmt->bindValue(':dest', $destinationHashHex, PDO::PARAM_STR);
        $stmt->execute();
        $row = $stmt->fetch(PDO::FETCH_ASSOC);
        return is_array($row) ? ($row['identity_hash_hex'] ?? null) : null;
    }

    /**
     * Register a link's truncated hash as a local destination so that
     * link packets (RTT, data, close) addressed to the link hash are
     * delivered to the browser rather than relayed to peers.
     */
    private function registerLinkLocalDestination(string $linkHashHex, string $localIface): void
    {
        $stmt = $this->db->prepare($this->insertOrSql(
            'INSERT OR REPLACE INTO local_destinations (
                destination_hash_hex, interface_id, registered_at
             ) VALUES (
                :dest, :iface, :ts
             )'
        ));
        $stmt->bindValue(':dest', $linkHashHex, PDO::PARAM_STR);
        $stmt->bindValue(':iface', $localIface, PDO::PARAM_STR);
        $stmt->bindValue(':ts', time(), PDO::PARAM_INT);
        $stmt->execute();
    }

    private function processInboundBatchRow(array $row, array &$summary): void
    {
        $interfaceId = (string) $row['interface_id'];
        $batchId = (string) $row['batch_id'];
        $packets = self::decodeJson((string) $row['payload_json']);
        $ifacConfig = $this->ifacConfig($interfaceId);
        $parsedPackets = 0;
        $errorPackets = 0;
        $packetIndex = 0;

        foreach ($packets as $packetBase64) {
            $rawBase64 = is_string($packetBase64) ? $packetBase64 : '';

            try {
                if ($rawBase64 === '') {
                    throw new RuntimeException('Packet entry must be a non-empty base64 string');
                }

                $rawPacket = base64_decode($rawBase64, true);
                if (!is_string($rawPacket)) {
                    throw new RuntimeException('Packet entry is not valid base64');
                }

                $packet = PacketParser::parseRaw($rawPacket, $ifacConfig);
                $normalizedRawBase64 = (string) ($packet['normalized_raw_base64'] ?? $rawBase64);
                [$filterStatus, $filterReason] = $this->applyPacketFilter($packet);
                $packet['filter_status'] = $filterStatus;
                $packet['filter_reason'] = $filterReason;
                $packet['announce_status'] = null;
                $packet['announce_reason'] = null;

                if ($filterStatus === 'accepted' && (int) $packet['packet_type'] === 1) {
                    [$announceStatus, $announceReason] = $this->processAcceptedAnnounce($interfaceId, $packet);
                    $packet['announce_status'] = $announceStatus;
                    $packet['announce_reason'] = $announceReason;

                    if ($announceStatus === 'validated' || $announceStatus === 'path_updated') {
                        $summary['announces_validated']++;
                    }

                    if ($announceStatus === 'path_updated') {
                        $summary['announce_paths_updated']++;
                    }

                    if ($announceStatus === 'invalid') {
                        $summary['announce_validation_failures']++;
                    }
                }

                if ($filterStatus === 'accepted' && $this->isPathRequestPacket($packet)) {
                    $summary['path_requests_seen']++;
                    [$pathRequestStatus, $pathRequestReason, $pathRequestQueued] = $this->processAcceptedPathRequest($interfaceId, $normalizedRawBase64, $packet);
                    if ($pathRequestStatus === 'response_queued') {
                        $summary['path_responses_queued']++;
                    } elseif ($pathRequestStatus === 'forwarded') {
                        $summary['path_requests_forwarded']++;
                    } else {
                        $summary['path_requests_ignored']++;
                    }

                    $packet['announce_status'] = $pathRequestStatus;
                    $packet['announce_reason'] = $pathRequestReason;
                    $summary['relay_packets_queued'] += $pathRequestQueued;
                }

                $cacheRequestReplayed = false;
                if ($filterStatus === 'accepted' && $this->isCacheRequestPacket($packet)) {
                    $summary['cache_requests_seen']++;
                    [$cacheRequestStatus, $cacheRequestReason, $cacheRequestQueued, $cacheRequestReplayed] = $this->processAcceptedCacheRequest($normalizedRawBase64, $packet);
                    if ($cacheRequestReplayed) {
                        $summary['cache_requests_replayed']++;
                    } else {
                        $summary['cache_requests_ignored']++;
                    }
                    $packet['announce_status'] = $cacheRequestStatus;
                    $packet['announce_reason'] = $cacheRequestReason;
                    $summary['relay_packets_queued'] += $cacheRequestQueued;
                }

                if ($filterStatus === 'accepted' && $this->shouldReverseRouteProofPacket($packet)) {
                    $proofMatch = $this->recordInboundProofDelivery($packet);
                    if ($proofMatch !== null) {
                        $summary['outbound_proofs_marked']++;
                        $packet['announce_status'] = 'outbound_proof_marked';
                        $packet['announce_reason'] = (string) ($proofMatch['packet_hash_hex'] ?? '');
                    }
                }

                $deliveredLocally = false;
                if ($filterStatus === 'accepted'
                    && in_array((int) ($packet['packet_type'] ?? -1), [0, 2], true)
                    && (int) ($packet['destination_type'] ?? -1) !== 3
                ) {
                    $deliveredLocally = $this->deliverLocallyIfKnown($interfaceId, $normalizedRawBase64, $packet);
                    if ($deliveredLocally) {
                        $summary['local_deliveries']++;
                    }
                }

                if (!$deliveredLocally) {
                    if ($filterStatus === 'accepted' && $this->shouldTransportLinkRequestProofPacket($packet)) {
                        error_log("[relay-cascade] LRPROOF matched, calling relayLinkRequestProofPacket");
                        $summary['relay_packets_queued'] += $this->relayLinkRequestProofPacket($interfaceId, $normalizedRawBase64, $packet);
                    } elseif ($filterStatus === 'accepted' && $this->shouldRelayLinkTransportPacket($packet)) {
                        $summary['relay_packets_queued'] += $this->relayLinkTransportPacket($interfaceId, $normalizedRawBase64, $packet);
                    } elseif ($filterStatus === 'accepted' && $this->shouldReverseRouteProofPacket($packet)) {
                        error_log("[relay-cascade] regular proof matched, calling relayProofPacket");
                        $summary['relay_packets_queued'] += $this->relayProofPacket($interfaceId, $normalizedRawBase64, $packet);
                    } elseif ($filterStatus === 'accepted' && !$cacheRequestReplayed && $this->shouldRelayAcceptedPacket($packet)) {
                        error_log("[relay-cascade] fallthrough to relayAcceptedPacket type=" . ($packet['packet_type']??'?') . " dest=" . substr((string)($packet['destination_hash_hex']??''),0,12));
                        $summary['relay_packets_queued'] += $this->relayAcceptedPacket($interfaceId, $normalizedRawBase64, $packet);
                    }
                }

                $this->storeInboundPacket($interfaceId, $batchId, $packetIndex, 'parsed', $normalizedRawBase64, $packet, null);
                $parsedPackets++;
                if ($filterStatus !== 'accepted') {
                    $summary['packets_rejected']++;
                }
            } catch (\Throwable $error) {
                $rawPacket = is_string($rawBase64) ? base64_decode($rawBase64, true) : false;
                $packet = [
                    'packet_hash_hex' => null,
                    'truncated_hash_hex' => null,
                    'packet_size' => is_string($rawPacket) ? strlen($rawPacket) : 0,
                    'ifac_flag' => is_string($rawPacket) && $rawPacket !== '' && (ord($rawPacket[0]) & 0x80) === 0x80 ? 1 : 0,
                    'header_type' => null,
                    'transport_type' => null,
                    'destination_type' => null,
                    'packet_type' => null,
                    'context_flag' => null,
                    'hops' => null,
                    'context' => null,
                    'transport_id_hex' => null,
                    'destination_hash_hex' => null,
                    'payload_base64' => null,
                    'filter_status' => null,
                    'filter_reason' => null,
                    'announce_status' => null,
                    'announce_reason' => null,
                ];
                $this->storeInboundPacket($interfaceId, $batchId, $packetIndex, 'error', $rawBase64, $packet, $error->getMessage());
                $errorPackets++;
            }

            $packetIndex++;
        }

        $this->markInboundBatchProcessed($interfaceId, $batchId, $packetIndex, $parsedPackets, $errorPackets);

        $summary['batches_processed']++;
        $summary['packets_parsed'] += $parsedPackets;
        $summary['packet_errors'] += $errorPackets;
    }

    private function markInboundBatchProcessed(
        string $interfaceId,
        string $batchId,
        int $processedPackets,
        int $parsedPackets,
        int $errorPackets
    ): void {
        $batchSummary = [
            'processed_packets' => $processedPackets,
            'parsed_packets' => $parsedPackets,
            'error_packets' => $errorPackets,
        ];
        $update = $this->db->prepare(
            'UPDATE inbound_batches
             SET processed_at = :processed_at, processing_summary_json = :processing_summary_json
             WHERE interface_id = :interface_id AND batch_id = :batch_id'
        );
        $update->bindValue(':processed_at', time(), PDO::PARAM_INT);
        $update->bindValue(':processing_summary_json', self::encodeJson($batchSummary), PDO::PARAM_STR);
        $update->bindValue(':interface_id', $interfaceId, PDO::PARAM_STR);
        $update->bindValue(':batch_id', $batchId, PDO::PARAM_STR);
        $update->execute();
    }

    private function batchByteCount(array $packets): int
    {
        $byteCount = 0;
        foreach ($packets as $packetBase64) {
            $byteCount += strlen((string) base64_decode((string) $packetBase64, true));
        }

        return $byteCount;
    }

    private function incrementInterfaceRxCounters(string $interfaceId, int $packetCount, int $byteCount): void
    {
        $counterStmt = $this->db->prepare(
            'UPDATE interfaces
             SET rx_packets = rx_packets + :packet_count,
                 rx_bytes = rx_bytes + :byte_count,
                 last_seen_at = :last_seen_at,
                 status = :status
             WHERE interface_id = :interface_id'
        );
        $counterStmt->bindValue(':packet_count', $packetCount, PDO::PARAM_INT);
        $counterStmt->bindValue(':byte_count', $byteCount, PDO::PARAM_INT);
        $counterStmt->bindValue(':last_seen_at', time(), PDO::PARAM_INT);
        $counterStmt->bindValue(':status', 'online', PDO::PARAM_STR);
        $counterStmt->bindValue(':interface_id', $interfaceId, PDO::PARAM_STR);
        $counterStmt->execute();
    }
}