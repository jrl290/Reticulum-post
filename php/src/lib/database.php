<?php

declare(strict_types=1);

namespace ReticulumPhp;

use PDO;

/**
 * Database connection factory for Reticulum-php.
 *
 * Supports MySQL (default) and SQLite backends through a unified PDO interface.
 * Backend selection is driven by config key [storage] backend = "mysql"|"sqlite".
 */
final class Database
{
    /**
     * Create a PDO connection based on runtime config.
     *
     * @param array $config Normalized Reticulum-php config array.
     * @return PDO Configured, exception-mode PDO handle.
     */
    public static function connect(array $config): PDO
    {
        $backend = self::resolveBackend($config);

        if ($backend === 'mysql') {
            return self::connectMysql($config);
        }

        return self::connectSqlite($config);
    }

    /**
     * Return the resolved backend name ('mysql' or 'sqlite').
     */
    public static function backend(array $config): string
    {
        return self::resolveBackend($config);
    }

    /**
     * Check whether a table column exists.
     *
     * Dispatches to backend-appropriate introspection:
     *   - MySQL: SHOW COLUMNS FROM <table>
     *   - SQLite: PRAGMA table_info(<table>)
     */
    public static function columnExists(PDO $pdo, string $backend, string $table, string $column): bool
    {
        if ($backend === 'mysql') {
            // SHOW COLUMNS doesn't support bound parameters — interpolate safely.
            // $column is always a hardcoded schema identifier, never user input.
            $stmt = $pdo->query('SHOW COLUMNS FROM `' . $table . '` LIKE \'' . $column . '\'');
            return $stmt->fetch(PDO::FETCH_ASSOC) !== false;
        }

        // SQLite
        $result = $pdo->query('PRAGMA table_info(' . $table . ')');
        while ($row = $result->fetch(PDO::FETCH_ASSOC)) {
            if (($row['name'] ?? '') === $column) {
                return true;
            }
        }
        return false;
    }

    /**
     * Convert a SQLite-style upsert to the active backend dialect.
     *
     * SQLite:   INSERT ... ON CONFLICT(col) DO UPDATE SET a = excluded.a
     * MySQL:    INSERT ... ON DUPLICATE KEY UPDATE a = VALUES(a)
     *
     * @param string $sql      SQL string using SQLite ON CONFLICT syntax.
     * @param string $backend  'mysql' or 'sqlite'.
     * @return string          Backend-appropriate SQL.
     */
    public static function upsertSql(string $sql, string $backend): string
    {
        if ($backend !== 'mysql') {
            return $sql;
        }

        $sql = preg_replace(
            '/ON CONFLICT\s*\([^)]+\)\s*DO UPDATE SET\s*/',
            'ON DUPLICATE KEY UPDATE ',
            $sql
        );

        $sql = preg_replace('/\bexcluded\.(\w+)/', 'VALUES($1)', $sql);

        return $sql;
    }

    // -----------------------------------------------------------------------
    // Internal
    // -----------------------------------------------------------------------

    private static function resolveBackend(array $config): string
    {
        $backend = strtolower((string) ($config['storage']['backend'] ?? 'mysql'));

        if (!in_array($backend, ['mysql', 'sqlite'], true)) {
            throw new \RuntimeException(
                'Unsupported storage backend: ' . $backend . '. Supported: mysql, sqlite'
            );
        }

        return $backend;
    }

    private static function connectMysql(array $config): PDO
    {
        $host    = (string) ($config["storage"]["mysql_host"] ?? "127.0.0.1");
        $port    = (int)    ($config["storage"]["mysql_port"] ?? 3306);
        $dbname  = (string) ($config["storage"]["mysql_dbname"] ?? "reticulum_php");
        $user    = (string) ($config["storage"]["mysql_user"] ?? "");
        $pass    = (string) ($config["storage"]["mysql_pass"] ?? "");

        if ($host === "" || $dbname === "") {
            throw new \RuntimeException(
                "MySQL backend requires storage.mysql_host and storage.mysql_dbname"
            );
        }

        $dsn = sprintf(
            "mysql:host=%s;port=%d;dbname=%s;charset=utf8mb4",
            $host,
            $port,
            $dbname
        );

        $pdo = new PDO($dsn, $user, $pass, [
            PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
            PDO::ATTR_EMULATE_PREPARES   => false,
        ]);

        $pdo->exec("SET SESSION TRANSACTION ISOLATION LEVEL READ COMMITTED");

        return $pdo;
    }

    private static function connectSqlite(array $config): PDO
    {
        $path = (string) ($config['storage']['sqlite_path'] ?? '');

        if ($path === '') {
            throw new \RuntimeException(
                'SQLite backend requires storage.sqlite_path'
            );
        }

        $dir = dirname($path);
        if (!is_dir($dir)) {
            @mkdir($dir, 0755, true);
        }

        $pdo = new PDO('sqlite:' . $path, null, null, [
            PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
        ]);

        // SQLite-specific pragmas — constrain memory on shared hosting
        $pdo->exec('PRAGMA journal_mode=WAL');
        // Limit page cache to ~2 MB (negative = kibibytes).  Default is 2 MB,
        // but make it explicit so a hosting provider override cannot inflate it.
        $pdo->exec('PRAGMA cache_size = -2000');
        // Disable memory-mapped I/O — mmap can inflate the process virtual
        // address space and trigger hosting physical-RAM limits.
        $pdo->exec('PRAGMA mmap_size = 0');
        // Wait up to 30 s for a write lock.  A 300 MB database with
        // maintenance queries can hold locks for several seconds on a shared
        // host; 5 s was too short.
        $pdo->exec('PRAGMA busy_timeout = 30000');
        // synchronous=NORMAL is crash-safe with WAL and ~10× faster writes
        // than FULL, reducing lock-hold duration under contention.
        $pdo->exec('PRAGMA synchronous = NORMAL');

        return $pdo;
    }
}
