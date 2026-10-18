<?php
declare(strict_types=1);

namespace ReticulumPhp;

/**
 * `php index.php switch-storage [--sqlite-path <absolute path>] [--dry-run]`:
 * moves a node from MySQL to a fresh SQLite database run by Swoole under
 * Passenger, as selectiv has run since 2026-10-15. An operator's command on
 * the host; nothing here answers a web request.
 *
 * It edits the TOML file Config::load() reads, after a copy of it (0600)
 * in ~/reticulum-config-backup/:
 * - [storage] backend = "sqlite", and sqlite_path when given;
 * - [swoole] enable_swoole = true.
 * Every other line stays as it was. Then it loads the config again and
 * checks those three values; if they are not what it wrote, it puts the
 * copy back and exits 1. It prints key names and yes/no facts, never a
 * value: the file holds the node's secrets and the MySQL password.
 *
 * No row moves: the SQLite database starts empty (James, 2026-10-18), so
 * the node has a new transport identity and its peers, gateways and
 * browsers register again when it answers them 401. The MySQL database is
 * left as it is, for a rollback (put the copy back, run `runtime`).
 * The next step is `php index.php runtime`, which writes Passengerfile.json
 * and the .htaccess block and checks /health. Whether swoole.php_binary
 * loads swoole and pdo_sqlite is for the operator to check beforehand: this
 * starts no process (only the storage reclaim may), and `runtime` fails if
 * /health does not answer from Swoole.
 */
final class StorageSwitch
{
    /** The values written, by section then key. */
    public static function wanted(?string $sqlitePath): array
    {
        $storage = ['backend' => 'sqlite'];
        if ($sqlitePath !== null) {
            $storage['sqlite_path'] = $sqlitePath;
        }

        return ['storage' => $storage, 'swoole' => ['enable_swoole' => true]];
    }

    /**
     * $toml with each wanted key set. A key already in its section (in any
     * of that section's tables: the template has [storage] twice) is
     * rewritten in place; one that is missing goes under the section's first
     * header, and a missing section is appended.
     */
    public static function rewrite(string $toml, array $wanted): string
    {
        $eol = str_contains($toml, "\r\n") ? "\r\n" : "\n";
        $lines = preg_split('/\r\n|\n/', $toml) ?: [];
        if ($lines !== [] && end($lines) === '') {
            array_pop($lines);
        }
        $section = null;
        $firstHeader = [];
        $found = [];
        foreach ($lines as $index => $line) {
            if (preg_match('/^\s*\[([^\[\]]+)\]\s*(#.*)?$/', $line, $match) === 1) {
                $section = trim($match[1]);
                $firstHeader[$section] ??= $index;
                continue;
            }
            if (preg_match('/^\s*\[\[/', $line) === 1 || $section === null || !isset($wanted[$section])) {
                continue;
            }
            if (preg_match('/^(\s*)([A-Za-z0-9_]+)\s*=/', $line, $match) === 1 && array_key_exists($match[2], $wanted[$section])) {
                $lines[$index] = $match[1] . self::assignment($match[2], $wanted[$section][$match[2]]);
                $found[$section][$match[2]] = true;
            }
        }

        $inserts = [];
        $appended = [];
        foreach ($wanted as $name => $keys) {
            $missing = [];
            foreach ($keys as $key => $value) {
                if (!isset($found[$name][$key])) {
                    $missing[] = self::assignment($key, $value);
                }
            }
            if ($missing === []) {
                continue;
            }
            if (isset($firstHeader[$name])) {
                $inserts[$firstHeader[$name]] = $missing;
            } else {
                $appended[] = '';
                $appended[] = '[' . $name . ']';
                array_push($appended, ...$missing);
            }
        }
        krsort($inserts);
        foreach ($inserts as $after => $added) {
            array_splice($lines, $after + 1, 0, $added);
        }
        array_push($lines, ...$appended);

        return implode($eol, $lines) . $eol;
    }

    private static function assignment(string $key, mixed $value): string
    {
        return $key . ' = ' . (is_bool($value) ? ($value ? 'true' : 'false') : json_encode($value, JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR));
    }

    /** @param resource $out @param resource $err */
    public static function run(string $projectRoot, array $args, $out, $err): int
    {
        $sqlitePath = null;
        $dryRun = false;
        for ($i = 0; $i < count($args); $i++) {
            if ($args[$i] === '--dry-run') {
                $dryRun = true;
            } elseif ($args[$i] === '--sqlite-path') {
                $sqlitePath = (string) ($args[++$i] ?? '');
                if ($sqlitePath === '' || $sqlitePath[0] !== '/' || preg_match('#^[A-Za-z0-9._/~+-]+$#', $sqlitePath) !== 1) {
                    fwrite($err, "switch-storage: --sqlite-path needs an absolute path of letters, digits and . _ / ~ + -\n");

                    return 1;
                }
            } else {
                fwrite($err, "switch-storage: unknown argument; usage: php index.php switch-storage [--sqlite-path <absolute path>] [--dry-run]\n");

                return 1;
            }
        }

        try {
            $configPath = Config::path($projectRoot);
        } catch (\Throwable) {
            fwrite($err, "switch-storage: no config file in the project root\n");

            return 1;
        }
        $configName = basename($configPath);
        if (pathinfo($configPath, PATHINFO_EXTENSION) !== 'toml') {
            fwrite($err, "switch-storage: the node reads {$configName}, which is PHP; this edits TOML only, so make that change by hand\n");

            return 1;
        }
        $before = Config::load($projectRoot);
        if (!array_key_exists('base_uri', $before['swoole'] ?? []) && (string) ($before['host_url'] ?? '') === '') {
            fwrite($err, "switch-storage: host_url is not set (and no swoole.base_uri): Passenger needs its path; nothing changed\n");

            return 1;
        }
        $original = (string) file_get_contents($configPath);
        $wanted = self::wanted($sqlitePath);
        $updated = self::rewrite($original, $wanted);
        $effectivePath = $sqlitePath ?? (string) ($before['storage']['sqlite_path'] ?? '');
        $realRoot = realpath($projectRoot) ?: $projectRoot;

        fwrite($out, "config file: {$configName}\n");
        fwrite($out, 'storage.backend was sqlite already: ' . (($before['storage']['backend'] ?? '') === 'sqlite' ? 'yes' : 'no') . "\n");
        fwrite($out, 'swoole.enable_swoole was on already: ' . (SwooleSetup::enabled($before) ? 'yes' : 'no') . "\n");
        fwrite($out, 'storage.sqlite_path: ' . ($sqlitePath === null ? 'left as it is' : 'set') . '; inside the web root: '
            . (str_starts_with($effectivePath, rtrim($realRoot, '/') . '/') || str_starts_with($effectivePath, rtrim($projectRoot, '/') . '/') ? 'yes (refused by the .htaccess block only)' : 'no') . "\n");
        fwrite($out, 'a database file is there already: ' . (is_file($effectivePath) ? 'yes (it is used as it is)' : 'no (it starts empty)') . "\n");
        if ($updated === $original) {
            fwrite($out, "switch-storage: nothing to change\n");

            return 0;
        }
        if ($dryRun) {
            fwrite($out, "switch-storage: --dry-run, nothing written\n");

            return 0;
        }

        $home = getenv('HOME');
        if (!is_string($home) || $home === '') {
            fwrite($err, "switch-storage: HOME is unknown, so there is nowhere to keep the copy; nothing changed\n");

            return 1;
        }
        $backupDir = rtrim($home, '/') . '/reticulum-config-backup';
        $backup = $backupDir . '/' . $configName . '.' . date('Ymd-His') . '.before-sqlite';
        $mode = fileperms($configPath) & 0777;
        try {
            if (!is_dir($backupDir) && !@mkdir($backupDir, 0700, true) && !is_dir($backupDir)) {
                throw new \RuntimeException('could not create ' . $backupDir);
            }
            self::writeAtomically($backup, $original, 0600);
            fwrite($out, "copy of the old config: {$backup}\n");
            if ($sqlitePath !== null && !is_dir(dirname($sqlitePath)) && !@mkdir(dirname($sqlitePath), 0700, true) && !is_dir(dirname($sqlitePath))) {
                throw new \RuntimeException('could not create the sqlite_path directory');
            }
            self::writeAtomically($configPath, $updated, $mode);
        } catch (\Throwable $error) {
            fwrite($err, 'switch-storage: ' . $error->getMessage() . "; the config is unchanged\n");

            return 1;
        }

        $failed = [];
        try {
            $after = Config::load($projectRoot);
            foreach ($wanted as $name => $keys) {
                foreach ($keys as $key => $value) {
                    if (($after[$name][$key] ?? null) !== $value) {
                        $failed[] = $name . '.' . $key;
                    }
                }
            }
        } catch (\Throwable) {
            $failed[] = 'the file no longer loads';
        }
        if ($failed !== []) {
            self::writeAtomically($configPath, $original, $mode);
            fwrite($err, 'switch-storage: after the edit ' . implode(', ', $failed) . " did not read back as written; the old config is back\n");

            return 1;
        }
        fwrite($out, "switched: storage.backend, swoole.enable_swoole" . ($sqlitePath === null ? '' : ', storage.sqlite_path') . " read back as written\n");
        fwrite($out, "next: php index.php runtime\n");

        return 0;
    }

    private static function writeAtomically(string $path, string $content, int $mode): void
    {
        // 0600 while it holds the secrets under a name no rule refuses: the
        // config sits in the web root.
        $tmp = $path . '.' . bin2hex(random_bytes(4)) . '.tmp';
        if (!@touch($tmp) || !@chmod($tmp, 0600) || @file_put_contents($tmp, $content) !== strlen($content) || !@chmod($tmp, $mode) || !@rename($tmp, $path)) {
            @unlink($tmp);
            throw new \RuntimeException('could not write ' . $path);
        }
    }
}
