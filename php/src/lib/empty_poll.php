<?php

declare(strict_types=1);

namespace ReticulumPhp;

/**
 * The empty-poll shortcut (James, 2026-10-07): an idle client's poll is
 * answered from one small file, without opening the database.
 *
 * An idle client exchanges every idle_exchange_interval_ms (1 s by default).
 * Each of those exchanges parsed the config, connected to MySQL, checked the
 * schema fingerprint, authenticated, ran the seed check, looked for packets
 * and for peers to wake, and answered that there was nothing. As clients are
 * added these empty polls become nearly all of a node's work, and on shared
 * hosting the account's one CPU core and 40 entry processes are the ceiling.
 *
 * THE IDLE MARK
 * -------------
 * <dir>/<sha256(interface_id)>, holding a digest of the interface's session
 * token. It says: this interface had nothing unacknowledged queued for it
 * when the mark was written. answer() honours it only for an exchange or poll
 * that sends no packets and no acknowledgements, from the same token, while
 * the mark is younger than seconds().
 *
 *   - Only a full exchange or poll that authenticated the client writes it
 *     (markIdle), and it writes the mark BEFORE counting the interface's
 *     unacknowledged packets, removing it again if the count is not zero.
 *     queueOutboundPacket removes the mark AFTER each write to the queue.
 *     Either order of the two lands on "no mark": a packet committed before
 *     the count is counted, and one committed after it has its mark removal
 *     after the mark was written. The queue writes are autocommit (the node
 *     opens no transactions); one inside a transaction would have to remove
 *     the mark after its commit. Pinned by tests/empty_poll_shortcut_test.php.
 *   - Registration, goodbye and the replacement of a peer's row remove it,
 *     so a token that is no longer the interface's stops being answered at
 *     once rather than when the mark expires.
 *   - A PHP peer's interface (another node, or a gateway) is never marked:
 *     an operator revokes a leaked peer session by deleting the row in SQL,
 *     and the old credential must be refused (401) at its next exchange.
 *     The shortcut is for browsers, which are the many idle clients.
 *   - seconds() is at most a third of interface_stale_after_seconds, so the
 *     client's full exchange, which refreshes last_seen_at, runs maintenance
 *     and the wake epilogue, still comes well inside the stale sweep.
 *
 * THE WAKE MARK
 * -------------
 * <dir>/wakes-owed exists while some PHP peer has packets or acknowledgements
 * waiting for it; RequestPhpWakeTrait::dispatchWakes rewrites it at every
 * epilogue that finds such a peer, so its mtime is that epilogue's time. The
 * epilogue wakes such peers, at most once per min_wake_interval_ms each. So
 * once min_wake_interval_ms has passed since the last epilogue, no poll takes
 * the shortcut until one has run again: the peers are woken as often as
 * before, while a peer that stays unreachable does not turn the shortcut off.
 *
 * Anything this class cannot read or write means "no shortcut": the poll
 * takes the full path, which is what every poll did before.
 *
 * What it gives up: a database the full path cannot reach is a 500 to every
 * request, and a marked client's empty polls still get "nothing" until its
 * mark runs out (seconds()). An operator who edits the interfaces table in
 * SQL is seen by marked browsers seconds() late too; the operator wipes
 * (/v1/monitor/clear, monitor.php) remove every mark, and peers have none.
 */
final class EmptyPoll
{
    /** The longest a mark is honoured, before the stale-sweep bound. */
    public const DEFAULT_SECONDS = 10;
    private const WAKES_OWED = 'wakes-owed';
    private const SWEPT = 'swept';
    /** How often sweep() looks, and the age past which it removes a mark. */
    private const SWEEP_SECONDS = 60;

    /**
     * How long an idle mark is honoured: http.empty_poll_shortcut_seconds
     * (default 10), at most a third of maintenance.interface_stale_after_seconds.
     * 0 turns the shortcut off.
     */
    public static function seconds(array $config): int
    {
        $configured = (int) ($config['http']['empty_poll_shortcut_seconds'] ?? self::DEFAULT_SECONDS);
        $maintenance = $config['maintenance'] ?? $config['worker'] ?? [];
        $staleAfter = (int) ($maintenance['interface_stale_after_seconds'] ?? 15);
        return max(0, min($configured, intdiv($staleAfter, 3)));
    }

    /**
     * Answer an idle client's exchange or poll from its mark, and exit. Returns
     * without answering whenever anything is other than plainly so: the
     * request then takes the full path, which answers or rejects it as before.
     */
    public static function answer(array $config, string $method, string $uri, array $server): void
    {
        $seconds = self::seconds($config);
        if ($seconds === 0 || $method !== 'POST') {
            return;
        }
        $path = HttpIo::normalizedPath($uri, $server);
        $isExchange = $path === '/v1/interfaces/exchange' || $path === '/v1/interfaces/tx';
        if (!$isExchange && $path !== '/v1/interfaces/poll') {
            return;
        }
        $dir = self::dir($config);
        // The same test as dispatchWakes' gate: a wake would go out now.
        $owedSince = @filemtime($dir . '/' . self::WAKES_OWED);
        $minWakeInterval = (int) ($config['http']['min_wake_interval_ms'] ?? 1000);
        if ($owedSince !== false && (time() - $owedSince) * 1000 >= $minWakeInterval) {
            return;
        }

        $raw = file_get_contents('php://input');
        $body = is_string($raw) && $raw !== '' ? json_decode($raw, true) : null;
        if (!is_array($body)) {
            return;
        }
        $interfaceId = $body['interface_id'] ?? null;
        $sessionToken = $body['session_token'] ?? null;
        if (!is_string($interfaceId) || trim($interfaceId) === '' || !is_string($sessionToken) || trim($sessionToken) === '') {
            return;
        }
        if (($body['ack_batch_ids'] ?? []) !== []) {
            return;
        }
        if ($isExchange && ($body['packets'] ?? null) !== []) {
            return;
        }
        if (array_key_exists('max_packets', $body) && !(is_int($body['max_packets']) && $body['max_packets'] >= 1)) {
            return;
        }
        $batchId = $body['batch_id'] ?? null;
        if ($isExchange && $batchId !== null && !(is_string($batchId) && preg_match('/^[\x21-\x7e]+$/', $batchId) === 1)) {
            return;
        }

        $mark = self::markPath($dir, $interfaceId);
        $writtenAt = @filemtime($mark);
        if ($writtenAt === false) {
            return;
        }
        $age = time() - $writtenAt;
        if ($age < 0 || $age >= $seconds) {
            return;
        }
        $held = @file_get_contents($mark);
        if (!is_string($held) || !hash_equals($held, self::tokenDigest($interfaceId, $sessionToken))) {
            return;
        }

        $idleMs = (int) $config['http']['idle_exchange_interval_ms'];
        // The full path's answer when nothing came in and nothing is queued,
        // key for key (index.php, the exchange and poll routes).
        $payload = $isExchange
            ? [
                'status' => 'accepted',
                'batch_id' => $batchId,
                'duplicate_batch' => false,
                'accepted_packets' => 0,
                'accepted_bytes' => 0,
                'processed_inline' => false,
                'processing' => null,
                'acked_batches' => 0,
                'delivery_batch_id' => null,
                'delivery_packets' => [],
                'delivery_more' => false,
                'idle_exchange_interval_ms' => $idleMs,
            ]
            : [
                'status' => 'ok',
                'idle_exchange_interval_ms' => $idleMs,
                'acked_batches' => 0,
                'batch_id' => null,
                'packets' => [],
                'more' => false,
            ];
        HttpIo::sendHeaders(200);
        echo json_encode($payload, JSON_THROW_ON_ERROR);
        exit;
    }

    /**
     * After a full exchange or poll that authenticated $interfaceId: mark it
     * idle if nothing unacknowledged is queued for it. The mark is written
     * before the count (see the class comment for why the order matters).
     *
     * @param callable(): int $unacknowledgedCount
     */
    public static function markIdle(array $config, string $interfaceId, string $sessionToken, callable $unacknowledgedCount, ?int $writtenAt = null): void
    {
        if (self::seconds($config) === 0) {
            return;
        }
        $dir = self::dir($config);
        if (!is_dir($dir) && !@mkdir($dir, 0700) && !is_dir($dir)) {
            return;
        }
        $mark = self::markPath($dir, $interfaceId);
        $tmp = $mark . '.' . bin2hex(random_bytes(4));
        if (@file_put_contents($tmp, self::tokenDigest($interfaceId, $sessionToken)) === false
            || !@touch($tmp, $writtenAt ?? time())
            || !@rename($tmp, $mark)) {
            @unlink($tmp);
            return;
        }
        try {
            $count = $unacknowledgedCount();
        } catch (\Throwable $error) {
            @unlink($mark);
            throw $error;
        }
        if ($count !== 0) {
            @unlink($mark);
        }
    }

    /** Something may now be waiting for $interfaceId, or its token changed. */
    public static function clear(array $config, string $interfaceId): void
    {
        @unlink(self::markPath(self::dir($config), $interfaceId));
    }

    /**
     * dispatchWakes calls this before it looks for peers to wake, and
     * noteWakesOwed() after, if it found any. Removing first and writing after
     * means two overlapping epilogues can leave a mark nothing is owed for
     * (a poll per min_wake_interval_ms takes the full path until an epilogue
     * finds nothing), but never remove one that is owed.
     */
    public static function clearWakesOwed(array $config): void
    {
        @unlink(self::dir($config) . '/' . self::WAKES_OWED);
    }

    public static function noteWakesOwed(array $config): void
    {
        $dir = self::dir($config);
        if (!is_dir($dir) && !@mkdir($dir, 0700) && !is_dir($dir)) {
            return;
        }
        @touch($dir . '/' . self::WAKES_OWED);
    }

    /**
     * Remove marks too old to be honoured, at most once a minute (the
     * maintenance prelude calls it). Each browser session leaves one mark
     * behind, and the account's quota counts the files.
     */
    public static function sweep(array $config): void
    {
        $dir = self::dir($config);
        $stamp = $dir . '/' . self::SWEPT;
        $now = time();
        $last = @filemtime($stamp);
        if ($last !== false && $now - $last < self::SWEEP_SECONDS) {
            return;
        }
        if (!is_dir($dir)) {
            return;
        }
        @touch($stamp);
        self::removeMarks($dir, $now - self::SWEEP_SECONDS);
    }

    /** Remove every idle mark (the operator's forced maintenance flush). */
    public static function clearAll(array $config): void
    {
        $dir = self::dir($config);
        if (is_dir($dir)) {
            self::removeMarks($dir, PHP_INT_MAX);
        }
    }

    private static function removeMarks(string $dir, int $writtenBefore): void
    {
        foreach (scandir($dir) ?: [] as $entry) {
            if ($entry === '.' || $entry === '..' || $entry === self::WAKES_OWED || $entry === self::SWEPT) {
                continue;
            }
            $path = $dir . '/' . $entry;
            $writtenAt = @filemtime($path);
            if ($writtenAt !== false && $writtenAt < $writtenBefore) {
                @unlink($path);
            }
        }
    }

    /** One directory per node, beside its maintenance lock file. */
    private static function dir(array $config): string
    {
        // Config::load's host_url, or monitor.php's raw one: same directory.
        $host = rtrim((string) ($config['host_url'] ?? $config['http']['advertise_url'] ?? 'default'), '/');
        $hostHash = substr(hash('sha256', $host), 0, 16);
        return sys_get_temp_dir() . '/reticulum-php-idle-' . $hostHash;
    }

    private static function markPath(string $dir, string $interfaceId): string
    {
        return $dir . '/' . substr(hash('sha256', $interfaceId), 0, 32);
    }

    private static function tokenDigest(string $interfaceId, string $sessionToken): string
    {
        return hash('sha256', $interfaceId . "\0" . $sessionToken);
    }
}
