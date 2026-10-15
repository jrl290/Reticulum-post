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

    /**
     * @param array $config the node's config, loaded once at start
     * @param array $build  the build stamp of the loaded code (see HttpApi)
     */
    public function __construct(
        private readonly array $config,
        private readonly array $build,
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
            (new HttpApi($this->config, $storage, build: $this->build))->handle($method, $uri, $server);
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
