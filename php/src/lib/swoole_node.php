<?php

declare(strict_types=1);

namespace ReticulumPhp;

use PDO;

// As every lib file that calls EmptyPoll does (deploy.sh swaps lib/ first).
require_once __DIR__ . '/empty_poll.php';

/**
 * One Swoole worker's node: how swoole_server.php answers a request the way
 * index.php does under Apache, in a process that answers many.
 *
 * Under Apache every request starts from nothing: config, connection, the
 * Storage traits' caches, the query log tally and PHP's stat cache. Here the
 * code, the config and the database connection outlive the request, and
 * everything else must not:
 *   - a new Storage per request, so the traits' caches start empty;
 *   - the connection is the worker's, so after each request an open
 *     transaction is rolled back and (MySQL) advisory locks, which belong
 *     to the connection and not the request, are released; a MySQL
 *     connection the server closed while idle is replaced;
 *   - $_SERVER is the request's, for the code that reads it;
 *   - the stat cache is cleared, so EmptyPoll's filemtime() sees other
 *     processes' idle marks (PHP clears it at the end of a web request);
 *   - the query log tally is flushed per request.
 *
 * A worker answers one request at a time: swoole_server.php turns Swoole's
 * coroutine hooks off, so PDO, curl and file calls block as they do under
 * Apache. With hooks on, a second request would start in the same worker
 * while the first waits on I/O and share its connection, HttpIo's exchange
 * and $_SERVER, so answer() refuses to be entered twice.
 */
final class SwooleNode
{
    private ?PDO $db = null;
    private bool $answering = false;

    /** @param array $config the node's config, loaded once at start */
    public function __construct(
        private readonly array $config,
        private readonly LoadedCode $code,
    ) {
    }

    /**
     * Answer one request: its $_SERVER (see serverVars()) and body in; the
     * status, headers ([name, value], keyed by lower-case name) and body out.
     *
     * @return array{0: int, 1: array<string, array{0: string, 1: string}>, 2: string}
     */
    public function answer(array $server, string $body): array
    {
        if ($this->answering) {
            throw new \LogicException('SwooleNode::answer() entered while answering: coroutine hooks must be off');
        }
        $this->answering = true;
        $method = (string) ($server['REQUEST_METHOD'] ?? 'GET');
        $uri = (string) ($server['REQUEST_URI'] ?? '/');
        $exchange = new HttpExchange($body);
        $startedAt = microtime(true);
        $workerServer = $_SERVER;
        $_SERVER = $server;
        clearstatcache();
        HttpIo::begin($exchange);
        ob_start();
        try {
            EmptyPoll::answer($this->config, $method, $uri, $server);
            $storage = new Storage($this->config, $this->connection());
            (new HttpApi($this->config, $storage, loaded: $this->code))->handle($method, $uri, $server);
        } catch (\Swoole\ExitException) {
            // respond() and EmptyPoll::answer() end with exit, which Swoole
            // turns into this exception: the answer is in the buffer.
        } catch (\Throwable $error) {
            // index.php's last resort under Apache, the same answer.
            error_log('Reticulum-php: ' . $method . ' ' . $uri . ' failed: ' . get_class($error) . ': ' . $error->getMessage());
            ob_clean();
            $exchange->headers = [];
            HttpIo::sendHeaders(500);
            echo json_encode(['error' => 'internal error', 'message' => 'The PHP node failed to answer this request.'], JSON_THROW_ON_ERROR);
        } finally {
            $output = (string) ob_get_clean();
            HttpIo::finish();
            $this->afterRequest($startedAt);
            $_SERVER = $workerServer;
            $this->answering = false;
        }

        return [$exchange->status, $exchange->headers, $output];
    }

    /**
     * The worker's connection, opened (and the schema brought up to date, as
     * index.php does on every request) the first time and after a MySQL
     * server closed it while idle.
     */
    private function connection(): PDO
    {
        if ($this->db !== null && Database::backend($this->config) === 'mysql') {
            try {
                @$this->db->query('SELECT 1');
            } catch (\PDOException $error) {
                error_log('Reticulum-php: the MySQL connection was closed while idle (' . $error->getMessage() . '); opening a new one');
                $this->db = null;
            }
        }
        if ($this->db === null) {
            Config::ensureDirectories($this->config);
            Environment::verify();
            $db = Database::connect($this->config);
            (new Storage($this->config, $db))->migrateIfNeeded();
            $this->db = $db;
        }

        return $this->db;
    }

    /** What a web request's end does for free. */
    private function afterRequest(float $startedAt): void
    {
        if ($this->db !== null) {
            try {
                if ($this->db->inTransaction()) {
                    error_log('Reticulum-php: a request left a transaction open; rolled back');
                    $this->db->rollBack();
                }
                if (Database::backend($this->config) === 'mysql') {
                    $this->db->exec('DO RELEASE_ALL_LOCKS()');
                }
            } catch (\Throwable $error) {
                error_log('Reticulum-php: dropping the connection after a request: ' . $error->getMessage());
                $this->db = null;
            }
        }
        $queryLog = Database::queryLogPath($this->config);
        if ($queryLog !== '') {
            CountingPdo::flush($queryLog, $startedAt);
        }
    }

    /**
     * A request's $_SERVER from Swoole's request: $swooleServer is
     * Swoole\Http\Request::$server, $headers its ::$header (lower-case
     * names). SCRIPT_NAME is $baseUri/index.php, so HttpIo::normalizedPath()
     * strips the base path as it does under Apache (Passenger passes the
     * full path). $dropHeaders are not passed on.
     *
     * @param list<string> $dropHeaders lower-case names
     */
    public static function serverVars(array $swooleServer, array $headers, string $baseUri, array $dropHeaders = []): array
    {
        $path = (string) ($swooleServer['request_uri'] ?? '/');
        $query = (string) ($swooleServer['query_string'] ?? '');
        $server = [
            'REQUEST_METHOD' => strtoupper((string) ($swooleServer['request_method'] ?? 'GET')),
            'REQUEST_URI' => $query === '' ? $path : $path . '?' . $query,
            'QUERY_STRING' => $query,
            'SCRIPT_NAME' => rtrim($baseUri, '/') . '/index.php',
            'SERVER_PROTOCOL' => (string) ($swooleServer['server_protocol'] ?? 'HTTP/1.1'),
            'REQUEST_TIME' => (int) ($swooleServer['request_time'] ?? time()),
            'REQUEST_TIME_FLOAT' => (float) ($swooleServer['request_time_float'] ?? microtime(true)),
            'REMOTE_ADDR' => (string) ($swooleServer['remote_addr'] ?? ''),
        ];
        foreach ($headers as $name => $value) {
            $name = strtolower((string) $name);
            if (in_array($name, $dropHeaders, true)) {
                continue;
            }
            $key = strtoupper(str_replace('-', '_', $name));
            if ($key !== 'CONTENT_TYPE' && $key !== 'CONTENT_LENGTH') {
                $key = 'HTTP_' . $key;
            }
            $server[$key] = (string) $value;
        }

        return $server;
    }
}

/**
 * The code a resident process loaded, and the build stamp /health may give
 * for it. deploy.sh replaces the files under the running process and writes
 * the stamp only after it has proved them, so the stamp on disk names the
 * code on disk: true for this process only while that is still the code it
 * loaded. Once any file has been replaced (another inode, size or time), the
 * stamp is unknown until the process restarts on the new code.
 */
final class LoadedCode
{
    /** @var array<string, string> */
    private array $fingerprint;
    /** Unix time the code was loaded: /health's runtime.started_at. */
    public readonly int $loadedAt;

    public function __construct(private readonly string $dir)
    {
        $this->fingerprint = self::fingerprint($dir);
        $this->loadedAt = time();
    }

    /** @return array{commit: ?string, stamped_at: ?string} */
    public function buildStamp(): array
    {
        clearstatcache();

        return self::fingerprint($this->dir) === $this->fingerprint
            ? BuildStamp::read($this->dir)
            : ['commit' => null, 'stamped_at' => null];
    }

    /** @return array<string, string> */
    private static function fingerprint(string $dir): array
    {
        $files = array_merge([$dir . '/index.php', $dir . '/swoole_server.php'], glob($dir . '/lib/*.php') ?: []);
        $fingerprint = [];
        foreach ($files as $file) {
            $stat = @stat($file);
            $fingerprint[$file] = $stat === false ? '-' : $stat['ino'] . ':' . $stat['size'] . ':' . $stat['mtime'];
        }
        ksort($fingerprint);

        return $fingerprint;
    }
}

/**
 * `php index.php runtime`: makes Apache route the node the way the config
 * says, and checks that it does. deploy.sh runs it after every swap.
 *
 * swoole.enable_swoole on: writes the Passenger app root (outside the web
 * root: Passengerfile.json, the front secret, tmp/), the block between
 * BEGIN and END in the web directory's .htaccess that hands its requests to
 * Passenger, and tmp/restart.txt, so Passenger starts swoole_server.php on
 * the code now on disk at the next request. Off: removes that block, and
 * Apache serves index.php again; the app root stays, unused.
 * Then GET host_url/health must say runtime.server is swoole, or php.
 * Everything else in .htaccess is left as it is, but while the block stands
 * mod_rewrite is off in that directory (index.php's rewrite would take every
 * request from Passenger), so the block refuses the config, error_log and
 * SQLite files itself.
 */
final class SwooleSetup
{
    public const BEGIN = '# BEGIN Reticulum Swoole: written by `php index.php runtime` from swoole.enable_swoole';
    public const END = '# END Reticulum Swoole';

    public static function enabled(array $config): bool
    {
        return ($config['swoole']['enable_swoole'] ?? false) === true;
    }

    /** The Passenger app root: swoole.app_root, or ~/reticulum-swoole. */
    public static function appRoot(array $config): string
    {
        $configured = (string) ($config['swoole']['app_root'] ?? '');
        if ($configured !== '') {
            return rtrim($configured, '/');
        }
        $home = getenv('HOME');
        if (!is_string($home) || $home === '') {
            throw new \RuntimeException('swoole.app_root is not set and HOME is unknown');
        }

        return rtrim($home, '/') . '/reticulum-swoole';
    }

    /** $htaccess with the block replaced by $block (null: removed), or appended. */
    public static function withBlock(string $htaccess, ?string $block): string
    {
        $pattern = '/\n?' . preg_quote(self::BEGIN, '/') . '\n.*?' . preg_quote(self::END, '/') . '\n?/s';
        $without = preg_replace($pattern, "\n", $htaccess, -1, $found);
        $without = $found > 0 ? $without : $htaccess;
        $without = rtrim((string) $without, "\n");
        if ($block === null) {
            return $without === '' ? '' : $without . "\n";
        }

        return ($without === '' ? '' : $without . "\n\n") . $block;
    }

    /** @param resource $out @param resource $err */
    public static function apply(array $config, string $webDir, bool $verify, $out, $err): int
    {
        $enabled = self::enabled($config);
        $htaccessPath = $webDir . '/.htaccess';
        $htaccess = is_file($htaccessPath) ? (string) file_get_contents($htaccessPath) : '';
        try {
            if ($enabled) {
                $block = self::enable($config, $webDir, $out);
            } else {
                $block = null;
            }
            $updated = self::withBlock($htaccess, $block);
            if ($updated !== $htaccess) {
                self::writeAtomically($htaccessPath, $updated, is_file($htaccessPath) ? (fileperms($htaccessPath) & 0777) : 0644);
                fwrite($out, ($enabled ? 'routed to Passenger in ' : 'Passenger block removed from ') . $htaccessPath . "\n");
            } else {
                fwrite($out, $htaccessPath . ($enabled ? ' already routes to Passenger' : ' has no Passenger block') . "\n");
            }
            $touchedAt = time();
            if ($enabled) {
                $restart = self::appRoot($config) . '/tmp/restart.txt';
                if (!@touch($restart)) {
                    throw new \RuntimeException('could not touch ' . $restart);
                }
                fwrite($out, 'touched ' . $restart . ': Passenger starts swoole_server.php on this code at the next request' . "\n");
            }
        } catch (\Throwable $error) {
            fwrite($err, 'runtime: ' . $error->getMessage() . "\n");

            return 1;
        }

        $expected = $enabled ? 'swoole' : 'php';
        $hostUrl = (string) ($config['host_url'] ?? '');
        if (!$verify || $hostUrl === '') {
            fwrite($out, 'runtime: ' . $expected . ' configured; not checked over HTTP' . ($verify ? ' (no host_url)' : '') . "\n");

            return 0;
        }
        // Apache reads .htaccess per request, so php answers at once; Passenger
        // notices restart.txt within its stat throttle (seconds on selectiv)
        // and keeps the old process until then, so swoole must answer from a
        // process started after the touch. This is an operator's command, not
        // a request: it may wait, within a bound.
        $deadline = microtime(true) + self::RESTART_WAIT_SECONDS;
        do {
            [$status, $server, $startedAt] = self::healthRuntime($hostUrl . '/health');
            $current = $status === 200 && $server === $expected && ($expected === 'php' || ($startedAt ?? 0) >= $touchedAt);
            if ($current) {
                fwrite($out, 'runtime: ' . $hostUrl . '/health answers from ' . $server
                    . ($expected === 'swoole' ? ', started ' . (time() - (int) $startedAt) . ' s ago, after the restart' : '') . "\n");

                return 0;
            }
            usleep(500_000);
        } while (microtime(true) < $deadline);
        fwrite($err, 'runtime: ' . $expected . ' configured, but after ' . self::RESTART_WAIT_SECONDS . ' s ' . $hostUrl . '/health answered '
            . ($status === 0 ? 'nothing' : $status . ' from ' . ($server ?? 'an unknown server')
                . ($server === 'swoole' && $expected === 'swoole' ? ' started before the restart' : '')) . "\n");

        return 1;
    }

    /** How long `runtime` waits for Passenger to restart the app. */
    private const RESTART_WAIT_SECONDS = 30;

    /** Writes the app root and returns the .htaccess block. */
    private static function enable(array $config, string $webDir, $out): string
    {
        $appRoot = self::appRoot($config);
        $baseUri = rtrim((string) ($config['swoole']['base_uri'] ?? (parse_url((string) ($config['host_url'] ?? ''), PHP_URL_PATH) ?? '')), '/');
        if (!array_key_exists('base_uri', $config['swoole'] ?? []) && (string) ($config['host_url'] ?? '') === '') {
            throw new \RuntimeException('enable_swoole needs host_url (or swoole.base_uri): PassengerBaseURI is its path');
        }
        $phpBinary = (string) ($config['swoole']['php_binary'] ?? '/usr/local/bin/php');
        $extension = (string) ($config['swoole']['extension'] ?? 'swoole.so');
        $server = $webDir . '/swoole_server.php';
        $secretPath = $appRoot . '/front_secret';
        foreach (['swoole.app_root' => $appRoot, 'swoole.base_uri' => $baseUri, 'swoole.php_binary' => $phpBinary, 'swoole.extension' => $extension, 'the web directory' => $webDir] as $what => $value) {
            // Passenger runs app_start_command, and .htaccess quotes values:
            // nothing that would need escaping in either.
            if (preg_match('#^[A-Za-z0-9._/~+-]*$#', $value) !== 1) {
                throw new \RuntimeException($what . ' may hold only letters, digits and . _ / ~ + -: ' . $value);
            }
        }
        if ($appRoot === '' || $appRoot[0] !== '/') {
            throw new \RuntimeException('swoole.app_root must be an absolute path: ' . $appRoot);
        }
        $realWeb = realpath($webDir) ?: $webDir;
        if (str_starts_with($appRoot . '/', rtrim($realWeb, '/') . '/') || str_starts_with($appRoot . '/', rtrim($webDir, '/') . '/')) {
            throw new \RuntimeException('swoole.app_root must be outside the web directory, which Apache serves: ' . $appRoot);
        }
        if (!is_file($server)) {
            throw new \RuntimeException($server . ' is missing');
        }
        // Apache (Passenger's core) reads Passengerfile.json and tmp/: the
        // directories may be passed through, not listed. Only the app, as
        // this account, reads the secret.
        if (!is_dir($appRoot . '/tmp') && !@mkdir($appRoot . '/tmp', 0711, true) && !is_dir($appRoot . '/tmp')) {
            throw new \RuntimeException('could not create ' . $appRoot . '/tmp');
        }
        if (!@chmod($appRoot, 0711) || !@chmod($appRoot . '/tmp', 0711)) {
            throw new \RuntimeException('could not make ' . $appRoot . ' and its tmp/ passable (0711)');
        }
        if (!is_file($secretPath)) {
            self::writeAtomically($secretPath, bin2hex(random_bytes(32)), 0600);
            fwrite($out, 'wrote a new front secret to ' . $secretPath . "\n");
        }
        $secret = trim((string) file_get_contents($secretPath));
        if (preg_match('/^[0-9a-f]{64}$/', $secret) !== 1) {
            throw new \RuntimeException($secretPath . ' does not hold a front secret (64 hex digits); remove it to have one made');
        }
        $command = $phpBinary . ($extension === '' ? '' : ' -d extension=' . $extension) . ' ' . $server . ' ' . $secretPath;
        $passengerfile = json_encode(['app_start_command' => $command], JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR) . "\n";
        if (!is_file($appRoot . '/Passengerfile.json') || file_get_contents($appRoot . '/Passengerfile.json') !== $passengerfile) {
            self::writeAtomically($appRoot . '/Passengerfile.json', $passengerfile, 0644);
            fwrite($out, 'wrote ' . $appRoot . '/Passengerfile.json: ' . $command . "\n");
        }

        // index.php's rewrite would hand every request to PHP before
        // Passenger sees it, so mod_rewrite is off here while this block
        // stands. A file that exists is still served by Apache itself, not
        // Passenger, so the config, logs and databases are refused here
        // rather than by a rewrite rule that is now off.
        return self::BEGIN . "\n"
            . 'RewriteEngine Off' . "\n"
            . '<FilesMatch "^(config(\.local)?\.(toml|php)|error_log)$|\.sqlite">' . "\n"
            . '    Require all denied' . "\n"
            . '</FilesMatch>' . "\n"
            . 'PassengerAppRoot "' . $appRoot . '"' . "\n"
            . 'PassengerBaseURI "' . ($baseUri === '' ? '/' : $baseUri) . '"' . "\n"
            . 'RequestHeader set X-Front-Secret "' . $secret . '"' . "\n"
            . self::END . "\n";
    }

    /** @return array{0: int, 1: ?string, 2: ?int} the status, runtime.server and runtime.started_at */
    private static function healthRuntime(string $url): array
    {
        $curl = curl_init($url);
        curl_setopt_array($curl, [CURLOPT_RETURNTRANSFER => true, CURLOPT_TIMEOUT => 10, CURLOPT_CONNECTTIMEOUT => 5]);
        $body = curl_exec($curl);
        $status = (int) curl_getinfo($curl, CURLINFO_RESPONSE_CODE);
        $decoded = is_string($body) ? json_decode($body, true) : null;
        $server = is_array($decoded) && is_string($decoded['runtime']['server'] ?? null) ? $decoded['runtime']['server'] : null;
        $startedAt = is_array($decoded) && is_int($decoded['runtime']['started_at'] ?? null) ? $decoded['runtime']['started_at'] : null;

        return [$status, $server, $startedAt];
    }

    private static function writeAtomically(string $path, string $content, int $mode): void
    {
        $tmp = $path . '.' . bin2hex(random_bytes(4)) . '.tmp';
        if (@file_put_contents($tmp, $content) !== strlen($content) || !@chmod($tmp, $mode) || !@rename($tmp, $path)) {
            @unlink($tmp);
            throw new \RuntimeException('could not write ' . $path);
        }
    }
}
