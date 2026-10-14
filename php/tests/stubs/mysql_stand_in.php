<?php
/**
 * MySQL for the tests, which have no MySQL server: a PDO over a SQLite file
 * that records every statement as issued, with the session's
 * lock_wait_timeout at that moment, and runs it in SQLite's form. It answers
 * the MySQL-only statements the node issues as MySQL would: the session's
 * lock_wait_timeout and SET SESSION, information_schema, SHOW INDEX, ON
 * DUPLICATE KEY, the ENGINE, ALGORITHM and LOCK clauses, an ALTER adding
 * several columns, OPTIMIZE and ANALYZE TABLE (a table's failure as rows of
 * the answer). It can fail one statement with 1205, MySQL's lock wait
 * timeout, or with any other exception. Used by
 * schema_migration_lock_wait_test.php and storage_reclaim_lock_wait_test.php.
 *
 * Not a test: php/tests/stubs/ holds fixtures, and deploy.sh runs only
 * php/tests/*.php.
 */
declare(strict_types=1);

/**
 * MySQL as the node sees it, over a SQLite file: each statement recorded as
 * issued, then run in SQLite's form.
 */
final class MysqlStandInPdo extends PDO
{
    /** @var list<array{sql: string, via: string, lock_wait: int}> */
    public array $log = [];
    /** The session's lock_wait_timeout. */
    public int $lockWait = 86400;
    /** The first statement matching this fails with 1205, as a lock wait timeout. */
    public ?string $timeOut = null;
    /** The first statement matching $throwOn throws $throw instead: any other failure. */
    public ?string $throwOn = null;
    public ?Throwable $throw = null;
    /** The session's lock_wait_timeout cannot be read (a connection gone). */
    public bool $unreadable = false;
    /**
     * OPTIMIZE TABLE's answer for a table, as [Msg_type, Msg_text] rows; a
     * table not named here answers as InnoDB does when the rebuild went
     * through: a note, then status OK.
     * @var array<string, list<array{0: string, 1: string}>>
     */
    public array $optimizeAnswers = [];

    public function __construct(string $path)
    {
        parent::__construct('sqlite:' . $path);
        $this->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    }

    public function exec(string $statement): int|false
    {
        $sql = $this->note($statement, 'exec');
        if (preg_match('/\ASET SESSION lock_wait_timeout = ([0-9]+)\z/', $sql, $m) === 1) {
            $this->lockWait = (int) $m[1];

            return 0;
        }
        $rows = 0;
        foreach (self::sqlite($sql) as $sqlite) {
            $rows += (int) parent::exec($sqlite);
        }

        return $rows;
    }

    public function query(string $query, ?int $fetchMode = null, mixed ...$fetchModeArgs): PDOStatement|false
    {
        $sql = $this->note($query, 'query');
        if ($sql === 'SELECT @@SESSION.lock_wait_timeout') {
            if ($this->unreadable) {
                throw self::error(2006, 'MySQL server has gone away');
            }
            $sql = 'SELECT ' . $this->lockWait;
        }
        if (preg_match('/\A(OPTIMIZE|ANALYZE) TABLE (`\w+`(?:, `\w+`)*)\z/', $sql, $m) === 1) {
            return $this->adminAnswer(strtolower($m[1]), $m[2]);
        }
        [$sqlite] = self::sqlite($sql);

        return $fetchMode === null ? parent::query($sqlite) : parent::query($sqlite, $fetchMode, ...$fetchModeArgs);
    }

    public function prepare(string $query, array $options = []): PDOStatement|false
    {
        [$sqlite] = self::sqlite($this->note($query, 'prepare'));

        return parent::prepare($sqlite, $options);
    }

    private function note(string $statement, string $via): string
    {
        $sql = (string) preg_replace('/\s+/', ' ', trim($statement));
        $this->log[] = ['sql' => $sql, 'via' => $via, 'lock_wait' => $this->lockWait];
        if ($this->timeOut !== null && preg_match($this->timeOut, $sql) === 1) {
            $this->timeOut = null;
            throw self::error(1205, 'Lock wait timeout exceeded; try restarting transaction');
        }
        if ($this->throwOn !== null && $this->throw !== null && preg_match($this->throwOn, $sql) === 1) {
            [$throw, $this->throwOn, $this->throw] = [$this->throw, null, null];
            throw $throw;
        }

        return $sql;
    }

    /**
     * What MySQL answers OPTIMIZE or ANALYZE TABLE with: per table, rows of
     * Table, Op, Msg_type and Msg_text. A table's failure is a row, not an
     * error of the statement.
     */
    private function adminAnswer(string $op, string $tables): PDOStatement|false
    {
        $selects = [];
        foreach (explode(', ', $tables) as $quoted) {
            $table = trim($quoted, '`');
            $rows = $op === 'optimize'
                ? ($this->optimizeAnswers[$table] ?? [['note', 'Table does not support optimize, doing recreate + analyze instead'], ['status', 'OK']])
                : [['status', 'OK']];
            foreach ($rows as [$type, $text]) {
                $selects[] = sprintf('SELECT %s AS "Table", %s AS "Op", %s AS "Msg_type", %s AS "Msg_text"',
                    $this->quote('node.' . $table), $this->quote($op), $this->quote($type), $this->quote($text));
            }
        }

        return parent::query(implode(' UNION ALL ', $selects));
    }

    private static function error(int $code, string $message): PDOException
    {
        $e = new PDOException("SQLSTATE[HY000]: General error: {$code} {$message}");
        $e->errorInfo = ['HY000', $code, $message];

        return $e;
    }

    /** @return list<string> the statement as SQLite takes it */
    private static function sqlite(string $sql): array
    {
        $answers = [
            'SELECT COLUMN_NAME FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = :table'
                => 'SELECT name AS COLUMN_NAME FROM pragma_table_info(:table)',
            'SELECT DATA_TYPE FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = :t AND COLUMN_NAME = :c'
                => 'SELECT lower(type) AS DATA_TYPE FROM pragma_table_info(:t) WHERE name = :c',
            'SELECT TABLE_NAME, INDEX_NAME FROM information_schema.STATISTICS WHERE TABLE_SCHEMA = DATABASE()'
                => "SELECT m.name AS TABLE_NAME, il.name AS INDEX_NAME FROM sqlite_master AS m, pragma_index_list(m.name) AS il WHERE m.type = 'table'",
            'SELECT TABLE_NAME FROM information_schema.TABLES WHERE TABLE_SCHEMA = DATABASE()'
                => "SELECT name AS TABLE_NAME FROM sqlite_master WHERE type = 'table'",
            "SELECT COUNT(*) FROM information_schema.STATISTICS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'link_transport_entries' AND INDEX_NAME = 'PRIMARY' AND COLUMN_NAME = 'remaining_hops'"
                => "SELECT COUNT(*) FROM pragma_table_info('link_transport_entries') WHERE name = 'remaining_hops' AND pk > 0",
            'SHOW INDEX FROM interfaces'
                => "SELECT il.name AS Key_name, 1 - il.\"unique\" AS Non_unique, ii.name AS Column_name FROM pragma_index_list('interfaces') AS il, pragma_index_info(il.name) AS ii",
            'INSERT INTO schema_meta (meta_key, fingerprint, applied_at) VALUES (:k, :f, :t) ON DUPLICATE KEY UPDATE fingerprint = VALUES(fingerprint), applied_at = VALUES(applied_at)'
                => 'INSERT INTO schema_meta (meta_key, fingerprint, applied_at) VALUES (:k, :f, :t) ON CONFLICT(meta_key) DO UPDATE SET fingerprint = excluded.fingerprint, applied_at = excluded.applied_at',
            'INSERT INTO `transport_state` (state_key, state_value, updated_at) VALUES (:key, :value, :now) ON DUPLICATE KEY UPDATE state_value = VALUES(state_value), updated_at = VALUES(updated_at)'
                => 'INSERT INTO transport_state (state_key, state_value, updated_at) VALUES (:key, :value, :now) ON CONFLICT(state_key) DO UPDATE SET state_value = excluded.state_value, updated_at = excluded.updated_at',
        ];
        if (isset($answers[$sql])) {
            return [$answers[$sql]];
        }
        // storageFootprint()'s sizes, from a table the test fills.
        $sizes = ' FROM information_schema.TABLES WHERE table_schema = DATABASE() AND table_name IN (';
        if (str_contains($sql, $sizes)) {
            return [str_replace($sizes, ' FROM stand_in_table_sizes WHERE table_name IN (', $sql)];
        }
        if (preg_match('/information_schema|\ASHOW |ON DUPLICATE KEY| MODIFY |@@/', $sql) === 1) {
            throw new LogicException("the stand-in has no SQLite form of: {$sql}");
        }
        if (str_starts_with($sql, 'CREATE TABLE ')) {
            $sql = str_replace(' ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci', '', $sql);

            return [str_replace('BIGINT AUTO_INCREMENT PRIMARY KEY', 'INTEGER PRIMARY KEY AUTOINCREMENT', $sql)];
        }
        if (preg_match('/\A(ALTER TABLE `\w+`) (ADD COLUMN .*), ALGORITHM=INSTANT\z/', $sql, $m) === 1) {
            $statements = [];
            foreach (preg_split('/, (?=ADD COLUMN `)/', $m[2]) ?: [] as $clause) {
                $statements[] = $m[1] . ' ' . preg_replace('/ AFTER `\w+`\z/', '', $clause);
            }

            return $statements;
        }
        if (preg_match('/\A(CREATE (?:UNIQUE )?INDEX .*) ALGORITHM=INPLACE LOCK=NONE\z/', $sql, $m) === 1) {
            return [$m[1]];
        }

        return [$sql];
    }
}

/** A Storage on $pdo, as the given backend, with $config's other sections. */
function standInStorage(string $path, MysqlStandInPdo $pdo, string $backend = 'mysql', array $config = []): ReticulumPhp\Storage
{
    $storage = new ReticulumPhp\Storage(['storage' => ['backend' => 'sqlite', 'sqlite_path' => $path, 'log_path' => dirname($path) . '/router.log']] + $config);
    (new ReflectionProperty(ReticulumPhp\Storage::class, 'db'))->setValue($storage, $pdo);
    (new ReflectionProperty(ReticulumPhp\Storage::class, 'backend'))->setValue($storage, $backend);

    return $storage;
}
