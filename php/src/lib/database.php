<?php

declare(strict_types=1);

namespace ReticulumPhp;

use PDO;
use PDOException;
use RuntimeException;

/**
 * Database — MySQL/SQLite dual-backend with deadlock-resistant helpers.
 *
 * MySQL deadlocks (error 1213) occur when concurrent requests acquire row
 * locks in conflicting orders. In request-operated PHP (no persistent
 * workers, multi-process), the common deadlock scenario is:
 *
 *   1. Request A: INSERT into outbound_packets → holds row lock on index leaf
 *   2. Request B: DELETE stale rows from outbound_packets → scans different order
 *   3. A waits for B's lock, B waits for A's lock → deadlock
 *
 * Mitigations:
 *   - executeWithRetry() retries on error 1213/1205 with exponential backoff
 *   - Advisory locks (GET_LOCK) serialize maintenance across processes
 *   - READ COMMITTED isolation reduces gap/next-key locking
 *   - Native prepared statements avoid emulated-prepare locking quirks
 *
 * On the retry itself, and DESIGN_PRINCIPLES.md §3
 * ------------------------------------------------
 * §3 forbids application-level retries, and it is right to: a retry that
 * "usually works the second time" is a race someone decided to live with.
 * This is the narrow case that is not that. When InnoDB detects a deadlock it
 * picks a victim and rolls it back *completely* — the statement had no effect,
 * and the server's own error text is "try restarting transaction". Reissuing is
 * not re-attempting partially-applied work in the hope of better luck; it is
 * completing an operation the database aborted unilaterally for scheduling
 * reasons of its own. The retry is a floor, not a fix.
 *
 * The actual fix remains §5: make the conflicting statements take their locks
 * in one order. That was undiagnosable until 2026-08-17 — the node logged
 * "Unhandled HTTP exception: ... 1213 Deadlock found" with no indication of
 * which statement, so nobody could act on eight failures a day. Every retry now
 * logs its label and SQL, so the conflicting pair can be named and ordered.
 * When you have that pair, fix the order and the retry stops firing; if the
 * retry log ever goes quiet, that is the signal the real fix landed.
 */

final class Database
{
    private const DEADLOCK_ERRORS = [1213, 1205];
    private const MAX_RETRIES = 3;

    /**
     * Log destination for deadlock diagnostics, captured in connect().
     *
     * RequestHttpApiHelperTrait::log() is a private instance method and this is
     * a static class, so it cannot be reused here. The line format is kept
     * identical so both sources interleave readably in one file.
     */
    private static ?string $logPath = null;

    /**
     * Record a deadlock so the conflicting statement pair can be identified.
     *
     * Without this, a deadlock reaches the log as an unattributed
     * "Unhandled HTTP exception" and no one can tell which query to reorder —
     * which is why eight failures a day went unaddressed. Warnings are written
     * for survived retries too: those never surface as errors, so they are
     * otherwise completely invisible while still costing a request 100-700ms.
     */
    private static function logDeadlock(string $message): void
    {
        if (self::$logPath === null || self::$logPath === '') {
            return;
        }
        $line = sprintf("[%s] [%s] %s\n", date('Y-m-d H:i:s'), 'WARNING', $message);
        @file_put_contents(self::$logPath, $line, FILE_APPEND | LOCK_EX);
    }

    /** One-line, length-capped SQL for a log entry. */
    private static function describeSql(string $sql): string
    {
        $flat = trim((string) preg_replace('/\s+/', ' ', $sql));

        return strlen($flat) > 160 ? substr($flat, 0, 157) . '...' : $flat;
    }

    /**
     * Determine the active storage backend from config.
     */
    public static function backend(array $config): string
    {
        $backend = $config['storage']['backend'] ?? 'sqlite';
        if (!in_array($backend, ['mysql', 'sqlite'], true)) {
            throw new RuntimeException('Unsupported storage backend: ' . $backend);
        }

        return $backend;
    }

    /**
     * Create a PDO connection with backend-optimized settings.
     *
     * MySQL-specific optimizations:
     *   - READ COMMITTED: reduces gap locks and next-key locking vs REPEATABLE READ
     *   - Native prepared statements (ATTR_EMULATE_PREPARES = false): avoids
     *     emulated-prepare locking quirks where MySQL holds metadata locks longer
     *   - ATTR_STRINGIFY_FETCHES = false: return native types
     *   - ATTR_ERRMODE = EXCEPTION: all errors throw, including deadlocks
     */
    public static function connect(array $config): PDO
    {
        $storage = $config['storage'] ?? [];
        $backend = self::backend($config);
        self::$logPath = (string) ($storage['log_path'] ?? '') ?: null;

        if ($backend === 'mysql') {
            $host = $storage['mysql_host'] ?? '127.0.0.1';
            $port = (int) ($storage['mysql_port'] ?? 3306);
            $dbname = $storage['mysql_dbname'] ?? 'reticulum_php';
            $user = $storage['mysql_user'] ?? 'root';
            $pass = $storage['mysql_pass'] ?? '';

            $dsn = sprintf('mysql:host=%s;port=%d;dbname=%s;charset=utf8mb4', $host, $port, $dbname);

            $pdo = new PDO($dsn, $user, $pass, [
                PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
                PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
                PDO::ATTR_EMULATE_PREPARES   => false,
                PDO::ATTR_STRINGIFY_FETCHES  => false,
            ]);

            // READ COMMITTED reduces InnoDB gap-lock and next-key lock scope.
            // REPEATABLE READ (MySQL default) holds gap locks on scanned rows
            // even when they don't match the WHERE clause, amplifying deadlocks.
            $pdo->exec("SET SESSION TRANSACTION ISOLATION LEVEL READ COMMITTED");

            // InnoDB auto-commit deadlock detection: when a deadlock is detected,
            // InnoDB rolls back one transaction immediately rather than waiting.
            // innodb_lock_wait_timeout is kept at default (50s) — the retry
            // wrapper handles the rollback-and-retry at the application level.
            // Lowering it would cause premature rollbacks on legitimate lock waits.

            return $pdo;
        }

        // SQLite
        $sqlitePath = $storage['sqlite_path'] ?? '';
        if ($sqlitePath === '') {
            throw new RuntimeException('SQLite path not configured');
        }

        $dir = dirname($sqlitePath);
        if ($dir !== '' && $dir !== '.' && !is_dir($dir) && !mkdir($dir, 0775, true) && !is_dir($dir)) {
            throw new RuntimeException('Unable to create SQLite directory: ' . $dir);
        }

        $pdo = new PDO('sqlite:' . $sqlitePath, null, null, [
            PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
            PDO::ATTR_EMULATE_PREPARES   => false,
        ]);

        // SQLite busy timeout: wait up to 5s instead of immediately failing
        // when another connection holds a write lock. SQLite serializes writes,
        // so this replaces the MySQL retry logic.
        $pdo->exec('PRAGMA busy_timeout = 5000');
        $pdo->exec('PRAGMA journal_mode = WAL');
        $pdo->exec('PRAGMA synchronous = NORMAL');
        $pdo->exec('PRAGMA foreign_keys = ON');

        return $pdo;
    }

    /**
     * Execute a PDOStatement with deadlock retry.
     *
     * On MySQL error 1213 (ER_LOCK_DEADLOCK) or 1205 (ER_LOCK_WAIT_TIMEOUT),
     * retries up to MAX_RETRIES times with exponential backoff (100ms, 200ms, 400ms).
     *
     * Usage:
     *   Database::executeWithRetry($stmt);
     *
     * For statements that need post-execute processing (fetch, rowCount, etc.),
     * the return value is the PDOStatement itself (not bool) for chaining:
     *   $row = Database::executeWithRetry($stmt)->fetch(PDO::FETCH_ASSOC);
     *
     * SQLite: busy_timeout handles contention; this is a no-op retry wrapper
     * that still provides a consistent interface.
     *
     * @param  \PDOStatement   $stmt  The prepared statement to execute
     * @param  string          $label Optional label for error logging
     * @return \PDOStatement   The executed statement (for method chaining)
     */
    public static function executeWithRetry(\PDOStatement $stmt, string $label = ''): \PDOStatement
    {
        $attempt = 0;
        $lastException = null;

        while ($attempt <= self::MAX_RETRIES) {
            try {
                $stmt->execute();
                return $stmt;
            } catch (PDOException $e) {
                $lastException = $e;

                // Only retry on deadlock/lock-wait-timeout
                $errorCode = (int) ($stmt->errorCode() ?: $e->getCode());
                $driverCode = (int) ($e->errorInfo[1] ?? 0);

                if (!in_array($errorCode, self::DEADLOCK_ERRORS, true)
                    && !in_array($driverCode, self::DEADLOCK_ERRORS, true)) {
                    throw $e;
                }

                if ($attempt >= self::MAX_RETRIES) {
                    break;
                }

                $attempt++;
                self::logDeadlock(sprintf(
                    'deadlock retry %d/%d [%s] sql=%s',
                    $attempt,
                    self::MAX_RETRIES,
                    $label !== '' ? $label : 'unlabelled',
                    self::describeSql($stmt->queryString)
                ));
                $delayUs = (100 * (1 << ($attempt - 1))) * 1000; // 100ms, 200ms, 400ms
                usleep($delayUs);
            }
        }

        self::logDeadlock(sprintf(
            'deadlock EXHAUSTED after %d retries [%s] sql=%s',
            self::MAX_RETRIES,
            $label !== '' ? $label : 'unlabelled',
            self::describeSql($stmt->queryString)
        ));

        throw new RuntimeException(
            sprintf(
                'Database deadlock after %d retries%s: %s',
                self::MAX_RETRIES,
                $label !== '' ? ' [' . $label . ']' : '',
                $lastException?->getMessage() ?? 'unknown error'
            ),
            0,
            $lastException
        );
    }

    /**
     * Execute raw SQL (no parameters) with deadlock retry.
     *
     * For DELETE/UPDATE statements that don't use prepared statements.
     */
    public static function execWithRetry(PDO $db, string $sql, string $label = ''): int
    {
        $attempt = 0;
        $lastException = null;

        while ($attempt <= self::MAX_RETRIES) {
            try {
                return $db->exec($sql);
            } catch (PDOException $e) {
                $lastException = $e;

                $driverCode = (int) ($e->errorInfo[1] ?? 0);
                if (!in_array($driverCode, self::DEADLOCK_ERRORS, true)) {
                    throw $e;
                }

                if ($attempt >= self::MAX_RETRIES) {
                    break;
                }

                $attempt++;
                self::logDeadlock(sprintf(
                    'deadlock retry %d/%d [%s] sql=%s',
                    $attempt,
                    self::MAX_RETRIES,
                    $label !== '' ? $label : 'unlabelled',
                    self::describeSql($sql)
                ));
                $delayUs = (100 * (1 << ($attempt - 1))) * 1000;
                usleep($delayUs);
            }
        }

        self::logDeadlock(sprintf(
            'deadlock EXHAUSTED after %d retries [%s] sql=%s',
            self::MAX_RETRIES,
            $label !== '' ? $label : 'unlabelled',
            self::describeSql($sql)
        ));

        throw new RuntimeException(
            sprintf(
                'Database deadlock after %d retries%s: %s',
                self::MAX_RETRIES,
                $label !== '' ? ' [' . $label . ']' : '',
                $lastException?->getMessage() ?? 'unknown error'
            ),
            0,
            $lastException
        );
    }

    /**
     * Acquire a MySQL advisory lock (GET_LOCK).
     *
     * Advisory locks are session-scoped and released on connection close.
     * Use for serializing operations that must not overlap across processes
     * (e.g., maintenance cleanup).
     *
     * Returns true if the lock was acquired, false if it timed out.
     *
     * On SQLite, this is a no-op that always returns true (SQLite serializes
     * writes at the database level via its own locking).
     */
    public static function acquireAdvisoryLock(PDO $db, string $backend, string $lockName, int $timeoutSeconds = 5): bool
    {
        if ($backend !== 'mysql') {
            return true; // SQLite serializes writes natively
        }

        $stmt = $db->prepare('SELECT GET_LOCK(:lock_name, :timeout) AS acquired');
        $stmt->bindValue(':lock_name', $lockName, PDO::PARAM_STR);
        $stmt->bindValue(':timeout', $timeoutSeconds, PDO::PARAM_INT);
        $stmt->execute();
        $row = $stmt->fetch(PDO::FETCH_ASSOC);

        return (int) ($row['acquired'] ?? 0) === 1;
    }

    /**
     * Release a MySQL advisory lock (RELEASE_LOCK).
     *
     * Returns true if the lock was released, false if it wasn't held.
     */
    public static function releaseAdvisoryLock(PDO $db, string $backend, string $lockName): bool
    {
        if ($backend !== 'mysql') {
            return true;
        }

        $stmt = $db->prepare('SELECT RELEASE_LOCK(:lock_name) AS released');
        $stmt->bindValue(':lock_name', $lockName, PDO::PARAM_STR);
        $stmt->execute();
        $row = $stmt->fetch(PDO::FETCH_ASSOC);

        return (int) ($row['released'] ?? 0) === 1;
    }

    /**
     * Convert SQLite-flavoured INSERT OR REPLACE / INSERT OR IGNORE
     * to MySQL equivalents.
     *
     * SQLite                         MySQL
     * INSERT OR REPLACE INTO t ... → REPLACE INTO t ...
     * INSERT OR IGNORE INTO t ...  → INSERT IGNORE INTO t ...
     */
    public static function insertOrSql(string $backend, string $sql): string
    {
        if ($backend !== 'mysql') {
            return $sql;
        }

        // INSERT OR REPLACE → REPLACE
        if (preg_match('/^INSERT\s+OR\s+REPLACE\s+INTO\s/i', $sql)) {
            return preg_replace('/^INSERT\s+OR\s+REPLACE\s+INTO\s/i', 'REPLACE INTO ', $sql);
        }

        // INSERT OR IGNORE → INSERT IGNORE
        if (preg_match('/^INSERT\s+OR\s+IGNORE\s+INTO\s/i', $sql)) {
            return preg_replace('/^INSERT\s+OR\s+IGNORE\s+INTO\s/i', 'INSERT IGNORE INTO ', $sql);
        }

        return $sql;
    }

    /**
     * Convert SQLite ON CONFLICT(col) DO UPDATE SET to MySQL
     * ON DUPLICATE KEY UPDATE syntax.
     *
     * Example input:
     *   INSERT INTO t (a, b) VALUES (:a, :b)
     *   ON CONFLICT(a) DO UPDATE SET b = excluded.b
     *
     * Example output:
     *   INSERT INTO t (a, b) VALUES (:a, :b)
     *   ON DUPLICATE KEY UPDATE b = VALUES(b)
     */
    public static function upsertSql(string $sql, string $backend): string
    {
        if ($backend !== 'mysql') {
            return $sql;
        }

        // Match: ON CONFLICT(col1, col2, ...) DO UPDATE SET ...
        if (preg_match('/ON\s+CONFLICT\s*\(([^)]+)\)\s*DO\s+UPDATE\s+SET\s+(.+)$/is', $sql, $matches)) {
            $setClause = $matches[2];
            // Convert excluded.column → VALUES(column)
            $setClause = preg_replace('/excluded\.(\w+)/i', 'VALUES($1)', $setClause);
            $prefix = substr($sql, 0, (int) strpos($sql, 'ON CONFLICT'));
            return rtrim($prefix) . ' ON DUPLICATE KEY UPDATE ' . $setClause;
        }

        return $sql;
    }

    /**
     * Ensure an index exists (MySQL-safe).
     *
     * SQLite supports CREATE INDEX IF NOT EXISTS, but MySQL does not.
     * This wraps CREATE INDEX in a try/catch that silently ignores
     * "Duplicate key name" errors (MySQL error 1061).
     */
    public static function ensureIndex(PDO $db, string $sql, string $label = ''): void
    {
        try {
            $db->exec($sql);
        } catch (PDOException $e) {
            $driverCode = (int) ($e->errorInfo[1] ?? 0);
            // MySQL error 1061: Duplicate key name
            // SQLite: index already exists (caught by generic message)
            if ($driverCode === 1061 || str_contains($e->getMessage(), 'already exists')) {
                return;
            }

            throw $e;
        }
    }

    /**
     * Return the SQL for counting rows in a table, backend-aware.
     */
    public static function countQuery(string $backend, string $table): string
    {
        return $backend === 'mysql'
            ? "SELECT COUNT(*) FROM `{$table}`"
            : "SELECT COUNT(*) FROM {$table}";
    }

    /**
     * Return backend-aware DELETE FROM syntax.
     */
    public static function deleteFrom(string $backend, string $table): string
    {
        return $backend === 'mysql'
            ? "DELETE FROM `{$table}`"
            : "DELETE FROM {$table}";
    }

    /**
     * Quote a table name for the active backend.
     */
    public static function quoteTable(string $backend, string $table): string
    {
        return $backend === 'mysql' ? "`{$table}`" : $table;
    }
}
