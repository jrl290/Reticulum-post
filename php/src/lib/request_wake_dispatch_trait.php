<?php

declare(strict_types=1);

namespace ReticulumPhp;

use PDO;

// Reticulum-php is request-operated. These wake dispatch helpers only claim,
// materialize, and complete wake work for the next authenticated request; they
// do not form an independent transport loop.

trait RequestWakeDispatchTrait
{
    /**
     * Read the wake_profile for a given wake event without claiming it.
     * Used by the CLI wake-event router to dispatch to the correct handler.
     */
    public function wakeEventProfile(int $wakeEventId): ?string
    {
        $stmt = $this->db->prepare(
            'SELECT wake_profile FROM wake_events WHERE wake_event_id = :wake_event_id LIMIT 1'
        );
        $stmt->bindValue(':wake_event_id', $wakeEventId, PDO::PARAM_INT);
        $stmt->execute();
        $row = $stmt->fetch(PDO::FETCH_ASSOC);

        return is_array($row) ? ($row['wake_profile'] ?? null) : null;
    }

    public function pendingWakeEventIdsForSpawn(int $limit): array
    {
        $stmt = $this->db->prepare(
            'SELECT wake_event_id
             FROM wake_events
             WHERE dispatched_at IS NULL
               AND failed_at IS NULL
               AND claimed_at IS NULL
             ORDER BY created_at ASC, wake_event_id ASC
             LIMIT :limit'
        );
        $stmt->bindValue(':limit', $limit, PDO::PARAM_INT);
        $stmt->execute();

        $wakeEventIds = [];
        while (($row = $stmt->fetch(PDO::FETCH_ASSOC)) !== false) {
            if (!is_array($row)) {
                continue;
            }

            $wakeEventId = (int) ($row['wake_event_id'] ?? 0);
            if ($wakeEventId <= 0) {
                continue;
            }

            $wakeEventIds[] = $wakeEventId;
        }

        return $wakeEventIds;
    }

    public function dispatchWakeEventById(int $wakeEventId, int $runnerPid, WakeDispatcher $dispatcher): array
    {
        if (!$this->claimWakeEventForRunner($wakeEventId, $runnerPid)) {
            return [
                'status' => 'noop',
                'wake_event_id' => $wakeEventId,
            ];
        }

        $stmt = $this->db->prepare(
            'SELECT
                wake_event_id,
                interface_id,
                wake_profile,
                wake_target,
                wake_data_json,
                queue_reason,
                queued_packet_count,
                created_at
             FROM wake_events
                         WHERE wake_event_id = :wake_event_id
               AND dispatched_at IS NULL
               AND failed_at IS NULL
             LIMIT 1'
        );
        $stmt->bindValue(':wake_event_id', $wakeEventId, PDO::PARAM_INT);
        $stmt->execute(); $row = $stmt->fetch(PDO::FETCH_ASSOC);

        if (!is_array($row)) {
            return [
                'status' => 'noop',
                'wake_event_id' => $wakeEventId,
            ];
        }

        try {
            $event = $this->wakeEventFromRow($row);
            $dispatchResult = $dispatcher->dispatch($event);
            $this->markWakeEventDispatched($wakeEventId, $dispatchResult);

            return [
                'status' => 'dispatched',
                'wake_event_id' => $wakeEventId,
                'dispatch_result' => $dispatchResult,
            ];
        } catch (\Throwable $error) {
            $this->markWakeEventFailed($wakeEventId, $error->getMessage());

            return [
                'status' => 'failed',
                'wake_event_id' => $wakeEventId,
                'error' => $error->getMessage(),
            ];
        }
    }

    public function failWakeEvent(int $wakeEventId, string $message): void
    {
        $this->markWakeEventFailed($wakeEventId, $message);
    }

    private function claimWakeEventForRunner(int $wakeEventId, int $runnerPid): bool
    {
        $select = $this->db->prepare(
            'SELECT dispatched_at, failed_at, claimed_by_pid
             FROM wake_events
             WHERE wake_event_id = :wake_event_id
             LIMIT 1'
        );
        $select->bindValue(':wake_event_id', $wakeEventId, PDO::PARAM_INT);
        $select->execute(); $row = $select->fetch(PDO::FETCH_ASSOC);
        if (!is_array($row)) {
            return false;
        }

        if ($row['dispatched_at'] !== null || $row['failed_at'] !== null) {
            return false;
        }

        $claimedByPid = $row['claimed_by_pid'];
        if ($claimedByPid !== null) {
            return (int) $claimedByPid === $runnerPid;
        }

        $claim = $this->db->prepare(
            'UPDATE wake_events
             SET claimed_at = :claimed_at,
                 claimed_by_pid = :claimed_by_pid
             WHERE wake_event_id = :wake_event_id
               AND dispatched_at IS NULL
               AND failed_at IS NULL
               AND claimed_by_pid IS NULL'
        );
        $claim->bindValue(':claimed_at', time(), PDO::PARAM_INT);
        $claim->bindValue(':claimed_by_pid', $runnerPid, PDO::PARAM_INT);
        $claim->bindValue(':wake_event_id', $wakeEventId, PDO::PARAM_INT);
        $claim->execute();
        if ($claim->rowCount() === 1) {
            return true;
        }

        $select->execute(); $row = $select->fetch(PDO::FETCH_ASSOC);
        return is_array($row) && (int) ($row['claimed_by_pid'] ?? 0) === $runnerPid;
    }

    public function dispatchPendingWakeEvents(int $limit, WakeDispatcher $dispatcher): array
    {
        $summary = [
            'pending_before' => $this->countByQuery('SELECT COUNT(*) FROM wake_events WHERE dispatched_at IS NULL AND failed_at IS NULL AND claimed_at IS NULL'),
            'dispatched' => 0,
            'failed' => 0,
        ];
        $rows = [];

        $stmt = $this->db->prepare(
            'SELECT
                wake_event_id,
                interface_id,
                wake_profile,
                wake_target,
                wake_data_json,
                queue_reason,
                queued_packet_count,
                created_at
             FROM wake_events
             WHERE dispatched_at IS NULL AND failed_at IS NULL
                             AND claimed_at IS NULL
             ORDER BY created_at ASC, wake_event_id ASC
             LIMIT :limit'
        );
        $stmt->bindValue(':limit', $limit, PDO::PARAM_INT);
        $stmt->execute();

        while (($row = $stmt->fetch(PDO::FETCH_ASSOC)) !== false) {
            if (is_array($row)) {
                $rows[] = $row;
            }
        }

        foreach ($rows as $row) {
            $wakeEventId = (int) ($row['wake_event_id'] ?? 0);
            if ($wakeEventId <= 0) {
                continue;
            }

            try {
                $event = $this->wakeEventFromRow($row);
                $dispatchResult = $dispatcher->dispatch($event);
                $this->markWakeEventDispatched($wakeEventId, $dispatchResult);
                $summary['dispatched']++;
            } catch (\Throwable $error) {
                $this->markWakeEventFailed($wakeEventId, $error->getMessage());
                $summary['failed']++;
            }
        }

        $summary['pending_after'] = $this->countByQuery('SELECT COUNT(*) FROM wake_events WHERE dispatched_at IS NULL AND failed_at IS NULL AND claimed_at IS NULL');
        return $summary;
    }

    private function wakeEventFromRow(array $row): array
    {
        return [
            'wake_event_id' => (int) ($row['wake_event_id'] ?? 0),
            'interface_id' => (string) ($row['interface_id'] ?? ''),
            'wake_profile' => (string) ($row['wake_profile'] ?? ''),
            'wake_target' => (string) ($row['wake_target'] ?? ''),
            'wake_data' => self::decodeJson((string) ($row['wake_data_json'] ?? '[]')),
            'queue_reason' => (string) ($row['queue_reason'] ?? ''),
            'queued_packet_count' => (int) ($row['queued_packet_count'] ?? 0),
            'created_at' => (int) ($row['created_at'] ?? 0),
        ];
    }

    private function markWakeEventDispatched(int $wakeEventId, array $dispatchResult): void
    {
        $stmt = $this->db->prepare(
            'UPDATE wake_events
             SET dispatched_at = :dispatched_at,
                 claimed_at = NULL,
                 claimed_by_pid = NULL,
                 failed_at = NULL,
                 failure_message = NULL,
                 dispatch_result_json = :dispatch_result_json
             WHERE wake_event_id = :wake_event_id'
        );
        $stmt->bindValue(':dispatched_at', time(), PDO::PARAM_INT);
        $stmt->bindValue(':dispatch_result_json', self::encodeJson($dispatchResult), PDO::PARAM_STR);
        $stmt->bindValue(':wake_event_id', $wakeEventId, PDO::PARAM_INT);
        $stmt->execute();
    }

    private function markWakeEventFailed(int $wakeEventId, string $message): void
    {
        $stmt = $this->db->prepare(
            'UPDATE wake_events
             SET failed_at = :failed_at,
                 claimed_at = NULL,
                 claimed_by_pid = NULL,
                 failure_message = :failure_message
             WHERE wake_event_id = :wake_event_id'
        );
        $stmt->bindValue(':failed_at', time(), PDO::PARAM_INT);
        $stmt->bindValue(':failure_message', $message, PDO::PARAM_STR);
        $stmt->bindValue(':wake_event_id', $wakeEventId, PDO::PARAM_INT);
        $stmt->execute();
    }
}