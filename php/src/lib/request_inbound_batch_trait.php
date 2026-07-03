<?php

declare(strict_types=1);

namespace ReticulumPhp;

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
        $duplicateCheck->bindValue(':interface_id', $interfaceId, SQLITE3_TEXT);
        $duplicateCheck->bindValue(':batch_id', $batchId, SQLITE3_TEXT);
        $existing = $duplicateCheck->execute()->fetchArray(SQLITE3_ASSOC);

        if (is_array($existing)) {
            return [
                'duplicate_batch' => true,
                'accepted_packets' => (int) $existing['packet_count'],
                'accepted_bytes' => (int) $existing['byte_count'],
            ];
        }

        $byteCount = $this->batchByteCount($packets);

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
        $stmt->bindValue(':interface_id', $interfaceId, SQLITE3_TEXT);
        $stmt->bindValue(':batch_id', $batchId, SQLITE3_TEXT);
        $stmt->bindValue(':packet_count', count($packets), SQLITE3_INTEGER);
        $stmt->bindValue(':byte_count', $byteCount, SQLITE3_INTEGER);
        $stmt->bindValue(':payload_json', self::encodeJson($packets), SQLITE3_TEXT);
        $stmt->bindValue(':created_at', time(), SQLITE3_INTEGER);
        $stmt->execute();

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
        $duplicateCheck->bindValue(':interface_id', $interfaceId, SQLITE3_TEXT);
        $duplicateCheck->bindValue(':batch_id', $batchId, SQLITE3_TEXT);
        $existing = $duplicateCheck->execute()->fetchArray(SQLITE3_ASSOC);

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
        $claim->bindValue(':interface_id', $interfaceId, SQLITE3_TEXT);
        $claim->bindValue(':batch_id', $batchId, SQLITE3_TEXT);
        $claim->bindValue(':packet_count', count($packets), SQLITE3_INTEGER);
        $claim->bindValue(':byte_count', $byteCount, SQLITE3_INTEGER);
        $claim->bindValue(':payload_json', self::encodeJson([]), SQLITE3_TEXT);
        $claim->bindValue(':created_at', $now, SQLITE3_INTEGER);
        $claim->bindValue(':processed_at', 0, SQLITE3_INTEGER);
        $claim->execute();

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
        $stmt->bindValue(':limit', $limit, SQLITE3_INTEGER);
        $result = $stmt->execute();

        while (($row = $result->fetchArray(SQLITE3_ASSOC)) !== false) {
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
        $stmt->bindValue(':interface_id', $interfaceId, SQLITE3_TEXT);
        $stmt->bindValue(':batch_id', $batchId, SQLITE3_TEXT);
        $row = $stmt->execute()->fetchArray(SQLITE3_ASSOC);

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

    /**
     * Deliver a packet directly if the destination is 0 hops away via some interface.
     * Uses the path table — no separate local_destinations table needed.
     */
    private function deliverIfDirectlyAttached(string $sourceInterfaceId, string $rawBase64, array $packet): bool
    {
        $destHash = (string) ($packet['destination_hash_hex'] ?? '');
        if ($destHash === '') {
            return false;
        }

        $targetIface = $this->directlyAttachedInterface($destHash);
        if ($targetIface === null || $targetIface === $sourceInterfaceId) {
            return false;
        }

        $queueReason = 'direct_delivery';
        $this->queueOutboundPacket($targetIface, $rawBase64, $queueReason, $sourceInterfaceId);

        // Remember reverse path so return PROOFs can be routed back
        $truncatedHashHex = (string) ($packet['truncated_hash_hex'] ?? '');
        if ($truncatedHashHex !== '') {
            $this->rememberReversePath($truncatedHashHex, $sourceInterfaceId, $targetIface);
        }

        // Remember link transport entry for LINKREQUEST so LRPROOFs can be routed back
        if ((int) ($packet['packet_type'] ?? -1) === 2) {
            $this->rememberLinkTransportRelay($sourceInterfaceId, $targetIface, $rawBase64, $packet);
        }

        return true;
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

                $deliveredDirectly = false;
                if ($filterStatus === 'accepted'
                    && in_array((int) ($packet['packet_type'] ?? -1), [0, 2], true)
                    && (int) ($packet['destination_type'] ?? -1) !== 3
                ) {
                    $deliveredDirectly = $this->deliverIfDirectlyAttached($interfaceId, $normalizedRawBase64, $packet);
                    if ($deliveredDirectly) {
                        $summary['local_deliveries']++;
                    }
                }

                if (!$deliveredDirectly) {
                    if ($filterStatus === 'accepted' && $this->shouldTransportLinkRequestProofPacket($packet)) {
                        $summary['relay_packets_queued'] += $this->relayLinkRequestProofPacket($interfaceId, $normalizedRawBase64, $packet);
                    } elseif ($filterStatus === 'accepted' && $this->shouldRelayLinkTransportPacket($packet)) {
                        $summary['relay_packets_queued'] += $this->relayLinkTransportPacket($interfaceId, $normalizedRawBase64, $packet);
                    } elseif ($filterStatus === 'accepted' && $this->shouldReverseRouteProofPacket($packet)) {
                        $summary['relay_packets_queued'] += $this->relayProofPacket($interfaceId, $normalizedRawBase64, $packet);
                    } elseif ($filterStatus === 'accepted' && !$cacheRequestReplayed && $this->shouldRelayAcceptedPacket($packet)) {
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
        $update->bindValue(':processed_at', time(), SQLITE3_INTEGER);
        $update->bindValue(':processing_summary_json', self::encodeJson($batchSummary), SQLITE3_TEXT);
        $update->bindValue(':interface_id', $interfaceId, SQLITE3_TEXT);
        $update->bindValue(':batch_id', $batchId, SQLITE3_TEXT);
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
        $counterStmt->bindValue(':packet_count', $packetCount, SQLITE3_INTEGER);
        $counterStmt->bindValue(':byte_count', $byteCount, SQLITE3_INTEGER);
        $counterStmt->bindValue(':last_seen_at', time(), SQLITE3_INTEGER);
        $counterStmt->bindValue(':status', 'online', SQLITE3_TEXT);
        $counterStmt->bindValue(':interface_id', $interfaceId, SQLITE3_TEXT);
        $counterStmt->execute();
    }
}