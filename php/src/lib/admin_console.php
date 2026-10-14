<?php

declare(strict_types=1);

namespace ReticulumPhp;

// Loaded here as well as by index.php, like every lib file that calls
// EmptyPoll: deploy.sh renames lib/ before index.php, and a request between
// the two runs the old index.php.
require_once __DIR__ . '/empty_poll.php';

use PDO;
use RuntimeException;

/*
 * The admin page: <host_url>/admin, the node's only operator console.
 *
 * It answers 404, like any unknown path, until an operator on the host has
 * run `php index.php admin-setup <username>`, which stores the username and a
 * bcrypt hash of the password outside the web root (AdminCredentials). After
 * that it asks for them, and a signed-in browser gets a live view of the
 * connections, peers, queues and storage, the peering actions (reconnect,
 * rotate) and the maintenance actions (flush, debug report).
 *
 * Until 2026-10-14 the console was /v1/monitor, /v1/monitor/data|json, POST
 * /v1/monitor/clear, POST /v1/maintenance/flush, /debug and monitor.php, none
 * of which authenticated: every node answered them until 2026-09-30, then
 * only where config debug.enabled was true. They are gone, and the clear-all
 * button with them.
 *
 * - Sessions are stateless: a cookie holding the username and an expiry,
 *   signed with a key derived from the stored hash, so admin-setup (a new
 *   salt) signs every session out. HttpOnly, SameSite=Strict, Secure over
 *   HTTPS, and scoped to <base>/admin.
 * - Every POST must come from this origin (Origin, Sec-Fetch-Site), and every
 *   action also carries a token derived from the session (X-Admin-Csrf).
 * - Sign-in attempts are counted in transport_state before the password is
 *   checked: five per address in 15 minutes, a hundred per hour from all
 *   addresses together. Past the second limit only an address that has signed
 *   in before may try. admin-setup clears the counts.
 * - Answers carry no CORS headers, a nonce-based Content-Security-Policy, no
 *   caching and no framing. Plain HTTP is refused except from loopback.
 * - Nothing here starts a process (tests/only_storage_reclaim_starts_a_process_test.php).
 *
 * Pinned by tests/admin_console_test.php.
 */

/** The username and password hash admin-setup stored, and where they live. */
final class AdminCredentials
{
    public const VERSION = 1;
    public const MIN_PASSWORD_BYTES = 12;
    // bcrypt reads only the first 72 bytes: a longer password would be
    // checked by its first 72 alone, so admin-setup refuses one.
    public const MAX_PASSWORD_BYTES = 72;

    private function __construct(
        public readonly string $username,
        public readonly string $passwordHash
    ) {
    }

    public static function validUsername(string $username): bool
    {
        return preg_match('/^[A-Za-z0-9._@-]{1,64}$/', $username) === 1;
    }

    /**
     * admin.credentials_file when set; otherwise .reticulum-post/admin.json
     * in the home directory of the account PHP runs as. The command on the
     * host and the web server must find the same file, so the home directory
     * comes from the account (posix) before $HOME, which a web server may not
     * set. Null when neither is known.
     */
    public static function path(array $config): ?string
    {
        $configured = $config['admin']['credentials_file'] ?? null;
        if (is_string($configured) && $configured !== '') {
            return $configured;
        }

        $home = self::homeDirectory();
        return $home === null ? null : $home . '/.reticulum-post/admin.json';
    }

    public static function homeFromAccount(): bool
    {
        return function_exists('posix_getpwuid') && function_exists('posix_geteuid');
    }

    private static function homeDirectory(): ?string
    {
        if (self::homeFromAccount()) {
            $account = posix_getpwuid(posix_geteuid());
            $dir = is_array($account) ? ($account['dir'] ?? null) : null;
            if (is_string($dir) && $dir !== '' && $dir !== '/') {
                return rtrim($dir, '/');
            }
        }

        $home = getenv('HOME');
        return is_string($home) && $home !== '' && $home !== '/' ? rtrim($home, '/') : null;
    }

    /**
     * Why $path must not hold the credentials, or null when it may. It must
     * be outside every directory the web server serves: $servedDirs are the
     * ones known (the node's own directory, the document root), and a
     * directory named public_html, cPanel's web root, counts as one wherever
     * it is.
     */
    public static function placementProblem(string $path, array $servedDirs): ?string
    {
        if (!str_starts_with($path, '/')) {
            return 'is not an absolute path';
        }

        $resolved = self::resolve($path);
        if (in_array('public_html', explode('/', $resolved), true)) {
            return 'is inside public_html, the web root';
        }

        foreach ($servedDirs as $dir) {
            if (!is_string($dir) || $dir === '') {
                continue;
            }
            $served = rtrim(self::resolve($dir), '/');
            if ($served !== '' && ($resolved === $served || str_starts_with($resolved, $served . '/'))) {
                return 'is inside ' . $served . ', which the web server serves';
            }
        }

        return null;
    }

    /** $path with its deepest existing directory resolved, so a symlink cannot hide where it is. */
    private static function resolve(string $path): string
    {
        $rest = '';
        $dir = $path;
        while ($dir !== '/' && $dir !== '' && realpath($dir) === false) {
            $rest = '/' . basename($dir) . $rest;
            $dir = dirname($dir);
        }
        $real = realpath($dir);
        return ($real === false || $real === '/' ? '' : $real) . $rest;
    }

    public static function load(string $path): ?self
    {
        if (!is_file($path)) {
            return null;
        }

        $raw = @file_get_contents($path);
        $data = is_string($raw) ? json_decode($raw, true) : null;
        if (
            !is_array($data)
            || ($data['version'] ?? null) !== self::VERSION
            || !is_string($data['username'] ?? null)
            || !self::validUsername($data['username'])
            || !is_string($data['password_hash'] ?? null)
            || password_get_info($data['password_hash'])['algo'] === null
        ) {
            error_log('ReticulumPhp: ' . $path . ' holds no admin credentials admin-setup wrote; the admin page stays closed');
            return null;
        }

        return new self($data['username'], $data['password_hash']);
    }

    /**
     * Write the credentials (mode 0600, by rename) and say whether a file was
     * replaced. A directory it has to create is made 0700; an existing one is
     * left as it is, since it may be the home directory the web server needs
     * to traverse.
     */
    public static function save(string $path, string $username, string $password): bool
    {
        $dir = dirname($path);
        if (!is_dir($dir)) {
            if (!@mkdir($dir, 0700, true) && !is_dir($dir)) {
                throw new RuntimeException('Unable to create ' . $dir);
            }
            @chmod($dir, 0700);
        }

        $json = json_encode([
            'version' => self::VERSION,
            'username' => $username,
            'password_hash' => password_hash($password, PASSWORD_BCRYPT, ['cost' => 12]),
            'created_at' => gmdate('Y-m-d\TH:i:s\Z'),
        ], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR) . "\n";

        $replaced = is_file($path);
        $temp = @tempnam($dir, '.admin-');
        // tempnam() falls back to the system's temp directory when $dir is not
        // writable; the hash must never pass through there.
        if ($temp === false || realpath(dirname($temp)) !== realpath($dir)) {
            if (is_string($temp)) {
                @unlink($temp);
            }
            throw new RuntimeException('Unable to write in ' . $dir);
        }

        try {
            chmod($temp, 0600);
            if (file_put_contents($temp, $json) !== strlen($json) || !rename($temp, $path)) {
                throw new RuntimeException('Unable to write ' . $path);
            }
        } finally {
            if (is_file($temp)) {
                @unlink($temp);
            }
        }

        return $replaced;
    }

    /**
     * The key sessions and action tokens are signed with. It follows the
     * hash, so a new admin-setup (a new salt) signs out every session.
     */
    public function sessionKey(): string
    {
        return hash_hmac('sha256', 'reticulum-post admin session v1', $this->passwordHash, true);
    }
}

/** `php index.php admin-setup <username>` and `php index.php admin-remove`, on the host. */
final class AdminSetup
{
    public static function run(array $config, Storage $storage, array $servedDirs, array $argv): int
    {
        $path = AdminCredentials::path($config);
        if ($path === null) {
            fwrite(STDERR, "This account has no home directory PHP can see. Set [admin] credentials_file in the node's config to an absolute path outside the web root, then run admin-setup again.\n");
            return 1;
        }

        $problem = AdminCredentials::placementProblem($path, $servedDirs);
        if ($problem !== null) {
            fwrite(STDERR, "The admin credentials cannot go at {$path}: it {$problem}. Set [admin] credentials_file to a path outside the web root.\n");
            return 1;
        }

        $interactive = stream_isatty(STDIN);
        $username = $argv[2] ?? null;
        if ($username === null) {
            if (!$interactive) {
                fwrite(STDERR, "Usage: php index.php admin-setup <username>, with the password as the first line of standard input.\n");
                return 1;
            }
            fwrite(STDOUT, 'Admin username: ');
            $line = fgets(STDIN);
            $username = $line === false ? '' : trim($line);
        }

        if (!AdminCredentials::validUsername($username)) {
            fwrite(STDERR, "A username is 1 to 64 letters, digits and . _ @ -. Nothing was changed.\n");
            return 1;
        }

        if ($interactive) {
            if (!function_exists('readline_callback_handler_install')) {
                fwrite(STDERR, "This PHP cannot read a password without showing it. Pipe it in instead:\n"
                    . "  read -rs -p 'Password: ' P; echo; printf '%s\\n' \"\$P\" | php index.php admin-setup {$username}; unset P\n");
                return 1;
            }
            $password = self::readHidden('Password (not shown; Ctrl-C cancels): ');
            $repeat = $password === null ? null : self::readHidden('Same password again: ');
            if ($password === null || $repeat === null) {
                fwrite(STDERR, "Cancelled. Nothing was changed.\n");
                return 1;
            }
            if (!hash_equals($password, $repeat)) {
                fwrite(STDERR, "The two passwords differ. Nothing was changed.\n");
                return 1;
            }
        } else {
            $line = fgets(STDIN);
            $password = $line === false ? '' : rtrim($line, "\r\n");
        }

        $length = strlen($password);
        if ($length < AdminCredentials::MIN_PASSWORD_BYTES || $length > AdminCredentials::MAX_PASSWORD_BYTES || str_contains($password, "\0")) {
            fwrite(STDERR, 'A password is ' . AdminCredentials::MIN_PASSWORD_BYTES . ' to ' . AdminCredentials::MAX_PASSWORD_BYTES . " bytes. Nothing was changed.\n");
            return 1;
        }

        $replaced = AdminCredentials::save($path, $username, $password);
        $storage->clearAdminSignInState();

        $page = isset($config['host_url']) && is_string($config['host_url']) ? $config['host_url'] . '/admin' : '<host_url>/admin';
        fwrite(STDOUT, ($replaced ? 'Replaced' : 'Stored') . " the admin sign-in for {$username} in {$path} (mode 0600, a bcrypt hash, never the password).\n");
        fwrite(STDOUT, "Sign in at {$page}." . ($replaced ? ' Every earlier session is signed out.' : '') . "\n");
        if (($config['admin']['credentials_file'] ?? null) === null && !AdminCredentials::homeFromAccount()) {
            fwrite(STDOUT, "This PHP has no posix extension, so the web server finds its home directory by \$HOME, which it may not set. If {$page} still answers 404, set [admin] credentials_file to {$path}.\n");
        }

        return 0;
    }

    public static function remove(array $config): int
    {
        $path = AdminCredentials::path($config);
        if ($path === null || !is_file($path)) {
            fwrite(STDOUT, 'No admin credentials' . ($path === null ? '' : ' at ' . $path) . "; the admin page already answers 404.\n");
            return 0;
        }

        if (!@unlink($path)) {
            fwrite(STDERR, "Unable to remove {$path}.\n");
            return 1;
        }

        fwrite(STDOUT, "Removed {$path}. The admin page answers 404 until admin-setup runs again.\n");
        return 0;
    }

    /**
     * Read a line without showing it. readline's callback mode turns the
     * terminal's echo off; reading STDIN directly instead of through readline
     * keeps it off, so what is typed never reaches the screen, with no stty
     * process (the node starts none but the storage reclaim).
     */
    private static function readHidden(string $prompt): ?string
    {
        fwrite(STDOUT, $prompt);
        readline_callback_handler_install('', static function (): void {
        });
        // Ctrl-C would otherwise end the process with echo still off.
        if (function_exists('pcntl_async_signals') && function_exists('pcntl_signal') && defined('SIGINT')) {
            pcntl_async_signals(true);
            pcntl_signal(SIGINT, static function (): void {
                readline_callback_handler_remove();
                fwrite(STDERR, "\nCancelled. Nothing was changed.\n");
                exit(130);
            });
        }

        $value = '';
        try {
            while (true) {
                $char = fgetc(STDIN);
                if ($char === false || $char === "\x03" || ($char === "\x04" && $value === '')) {
                    return null;
                }
                if ($char === "\r" || $char === "\n") {
                    return $value;
                }
                if ($char === "\x7f" || $char === "\x08") {
                    $value = self::withoutLastCharacter($value);
                    continue;
                }
                if ($char === "\e") {
                    // An arrow key, or the brackets a terminal puts round a
                    // paste: not part of the password.
                    self::skipEscapeSequence();
                    continue;
                }
                $value .= $char;
            }
        } finally {
            readline_callback_handler_remove();
            if (function_exists('pcntl_signal') && defined('SIGINT') && defined('SIG_DFL')) {
                pcntl_signal(SIGINT, SIG_DFL);
            }
            fwrite(STDOUT, PHP_EOL);
        }
    }

    private static function skipEscapeSequence(): void
    {
        $next = fgetc(STDIN);
        if ($next !== '[' && $next !== 'O') {
            return;
        }
        // Parameters, then one final byte from @ to ~.
        while (($char = fgetc(STDIN)) !== false) {
            $code = ord($char);
            if ($code >= 0x40 && $code <= 0x7e) {
                return;
            }
        }
    }

    private static function withoutLastCharacter(string $value): string
    {
        $end = strlen($value) - 1;
        while ($end > 0 && (ord($value[$end]) & 0xC0) === 0x80) {
            $end--;
        }
        return $end <= 0 ? '' : substr($value, 0, $end);
    }
}

/**
 * The sign-in counts AdminConsole keeps in transport_state. Storage uses it,
 * beside the other state the node keeps there.
 */
trait RequestAdminStateTrait
{
    /**
     * Count one sign-in attempt from $addressKey and one from all addresses,
     * each in its own window, before the password is checked. The counts are
     * added up in SQL, so attempts sent in parallel cannot all read a count
     * below the limit.
     *
     * @return array{address: array{count: int, since: int}, all: array{count: int, since: int}, known: bool}
     */
    public function adminSignInAttempt(string $addressKey, int $now, int $addressWindow, int $allWindow, int $knownFor): array
    {
        $prune = $this->db->prepare(
            "DELETE FROM transport_state
             WHERE (state_key LIKE 'admin-signin:tries:%' AND updated_at < :tries_before)
                OR (state_key LIKE 'admin-signin:known:%' AND updated_at < :known_before)"
        );
        $prune->bindValue(':tries_before', $now - max($addressWindow, $allWindow), PDO::PARAM_INT);
        $prune->bindValue(':known_before', $now - $knownFor, PDO::PARAM_INT);
        Database::executeWithRetry($prune, 'pruneAdminSignIn');

        $known = $this->db->prepare('SELECT updated_at FROM transport_state WHERE state_key = :k');
        $known->bindValue(':k', 'admin-signin:known:' . $addressKey, PDO::PARAM_STR);
        $known->execute();
        $knownAt = $known->fetchColumn();

        return [
            'address' => $this->countAdminSignIn('admin-signin:tries:' . $addressKey, $now, $addressWindow),
            'all' => $this->countAdminSignIn('admin-signin:tries:all', $now, $allWindow),
            'known' => $knownAt !== false && (int) $knownAt >= $now - $knownFor,
        ];
    }

    /** A good sign-in: the address's count starts again, and the address is remembered. */
    public function adminSignInSucceeded(string $addressKey, int $now): void
    {
        $delete = $this->db->prepare('DELETE FROM transport_state WHERE state_key = :k');
        $delete->bindValue(':k', 'admin-signin:tries:' . $addressKey, PDO::PARAM_STR);
        Database::executeWithRetry($delete, 'adminSignInSucceeded');

        $this->storageStateSet('admin-signin:known:' . $addressKey, (string) $now);
    }

    /** admin-setup: every count and every remembered address goes. */
    public function clearAdminSignInState(): void
    {
        $delete = $this->db->prepare("DELETE FROM transport_state WHERE state_key LIKE 'admin-signin:%'");
        Database::executeWithRetry($delete, 'clearAdminSignInState');
    }

    /**
     * Add one to the count under $key, starting it again at 1 when its window
     * has passed. state_value is the count; updated_at is when the window
     * started.
     *
     * @return array{count: int, since: int}
     */
    private function countAdminSignIn(string $key, int $now, int $window): array
    {
        // MySQL assigns left to right, so state_value is decided while
        // updated_at still holds the window's start; SQLite reads the old row
        // for every assignment.
        $sql = $this->backend === 'mysql'
            ? "INSERT INTO transport_state (state_key, state_value, updated_at) VALUES (:k, '1', :now1)
               ON DUPLICATE KEY UPDATE
                 state_value = IF(updated_at < :start1, '1', CAST(CAST(state_value AS UNSIGNED) + 1 AS CHAR)),
                 updated_at = IF(updated_at < :start2, :now2, updated_at)"
            : "INSERT INTO transport_state (state_key, state_value, updated_at) VALUES (:k, '1', :now1)
               ON CONFLICT(state_key) DO UPDATE SET
                 state_value = CASE WHEN updated_at < :start1 THEN '1' ELSE CAST(CAST(state_value AS INTEGER) + 1 AS TEXT) END,
                 updated_at = CASE WHEN updated_at < :start2 THEN :now2 ELSE updated_at END";
        $count = $this->db->prepare($sql);
        $count->bindValue(':k', $key, PDO::PARAM_STR);
        $count->bindValue(':now1', $now, PDO::PARAM_INT);
        $count->bindValue(':now2', $now, PDO::PARAM_INT);
        $count->bindValue(':start1', $now - $window, PDO::PARAM_INT);
        $count->bindValue(':start2', $now - $window, PDO::PARAM_INT);
        Database::executeWithRetry($count, 'countAdminSignIn');

        $read = $this->db->prepare('SELECT state_value, updated_at FROM transport_state WHERE state_key = :k');
        $read->bindValue(':k', $key, PDO::PARAM_STR);
        $read->execute();
        $row = $read->fetch(PDO::FETCH_ASSOC);

        return [
            'count' => is_array($row) ? (int) $row['state_value'] : 1,
            'since' => is_array($row) ? (int) $row['updated_at'] : $now,
        ];
    }
}

/** The /admin routes. HttpApi hands every /admin path here. */
final class AdminConsole
{
    private const COOKIE = 'reticulum_admin';
    // Short: the page shares its origin with anything else the host serves.
    private const SESSION_SECONDS = 7200;
    private const TRIES_PER_ADDRESS = 5;
    private const ADDRESS_WINDOW_SECONDS = 900;
    private const TRIES_PER_HOUR = 100;
    private const KNOWN_ADDRESS_SECONDS = 30 * 86400;
    private const ACTIONS = [
        'GET /admin/data',
        'GET /admin/debug',
        'POST /admin/maintenance',
        'POST /admin/peers/reconnect',
        'POST /admin/peers/rotate',
    ];

    public function __construct(
        private readonly array $config,
        private readonly Storage $storage,
        private readonly string $codeDir
    ) {
    }

    public function handle(string $method, string $path, string $uri, array $server): never
    {
        $credentials = $this->credentials($server);
        if ($credentials === null) {
            // Not set up: the same 404 as any unknown path, so nobody can tell
            // the page is there, let alone claim it.
            throw new ApiError(404, 'Not found', ['error' => 'not found']);
        }

        if (!self::secureRequest($server)) {
            self::sendHeaders(403, 'text/plain; charset=utf-8');
            echo "The admin page answers over HTTPS only.\n";
            exit;
        }

        $admin = self::basePath($uri, $path) . '/admin';
        $session = $this->session($credentials, $server);

        if ($method === 'GET' && $path === '/admin') {
            if ($session === null) {
                $this->loginPage(200, $admin, null, '');
            }
            $this->consolePage($credentials, $session, $admin);
        }

        if ($method === 'POST' && $path === '/admin/login') {
            $this->login($credentials, $server, $admin);
        }

        if ($method === 'POST' && $path === '/admin/logout') {
            if (!self::sameOrigin($server)) {
                self::json(403, ['error' => 'not from this page']);
            }
            setcookie(self::cookieName($server), '', self::cookieOptions($server, $admin, 1));
            self::redirect($admin);
        }

        $route = $method . ' ' . $path;
        if (!in_array($route, self::ACTIONS, true)) {
            self::json(404, ['error' => 'not found']);
        }
        if ($session === null) {
            self::json(401, ['error' => 'signed out']);
        }
        if ($method === 'POST' && (!self::sameOrigin($server) || !$this->tokenValid($credentials, $session, $server))) {
            self::json(403, ['error' => 'not from this page']);
        }

        match ($route) {
            'GET /admin/data' => $this->liveData(),
            'GET /admin/debug' => $this->debugReport(),
            'POST /admin/maintenance' => $this->maintenance(),
            'POST /admin/peers/reconnect' => $this->peerAction('reconnect'),
            'POST /admin/peers/rotate' => $this->peerAction('rotate'),
        };
    }

    private function credentials(array $server): ?AdminCredentials
    {
        $path = AdminCredentials::path($this->config);
        if ($path === null) {
            return null;
        }

        $problem = AdminCredentials::placementProblem($path, [$this->codeDir, $server['DOCUMENT_ROOT'] ?? null]);
        if ($problem !== null) {
            if (is_file($path)) {
                error_log("ReticulumPhp: the admin credentials at {$path} are not used: it {$problem}");
            }
            return null;
        }

        return AdminCredentials::load($path);
    }

    // ─── Requests ────────────────────────────────────────────────────────

    private static function https(array $server): bool
    {
        $https = strtolower((string) ($server['HTTPS'] ?? ''));
        return ($https !== '' && $https !== 'off') || strtolower((string) ($server['REQUEST_SCHEME'] ?? '')) === 'https';
    }

    /** HTTPS, or plain HTTP from this machine (a local node, the tests). */
    public static function secureRequest(array $server): bool
    {
        if (self::https($server)) {
            return true;
        }

        $remote = (string) ($server['REMOTE_ADDR'] ?? '');
        return $remote === '::1' || str_starts_with($remote, '127.') || str_starts_with($remote, '::ffff:127.');
    }

    /**
     * A browser's POST names its origin; it must be this one. A client that
     * sends neither header is no browser, and still needs the session and,
     * for an action, the token.
     */
    public static function sameOrigin(array $server): bool
    {
        $site = $server['HTTP_SEC_FETCH_SITE'] ?? null;
        if (is_string($site) && $site !== 'same-origin') {
            return false;
        }

        $origin = $server['HTTP_ORIGIN'] ?? null;
        if (!is_string($origin)) {
            return true;
        }

        $own = (self::https($server) ? 'https://' : 'http://') . strtolower((string) ($server['HTTP_HOST'] ?? ''));
        return hash_equals($own, strtolower($origin));
    }

    /** The path the node is served under: '/reticulum' for /reticulum/admin. */
    private static function basePath(string $uri, string $path): string
    {
        $requestPath = parse_url($uri, PHP_URL_PATH);
        $requestPath = is_string($requestPath) ? rtrim($requestPath, '/') : '';
        return str_ends_with($requestPath, $path) ? substr($requestPath, 0, strlen($requestPath) - strlen($path)) : '';
    }

    private static function requestBody(): array
    {
        $raw = file_get_contents('php://input', false, null, 0, 8192);
        $decoded = is_string($raw) && $raw !== '' ? json_decode($raw, true) : null;
        return is_array($decoded) ? $decoded : [];
    }

    // ─── Sessions ────────────────────────────────────────────────────────

    private static function cookieName(array $server): string
    {
        return (self::https($server) ? '__Secure-' : '') . self::COOKIE;
    }

    private static function cookieOptions(array $server, string $admin, int $expires): array
    {
        return [
            'expires' => $expires,
            'path' => $admin,
            'secure' => self::https($server),
            'httponly' => true,
            'samesite' => 'Strict',
        ];
    }

    private static function base64Url(string $bytes): string
    {
        return rtrim(strtr(base64_encode($bytes), '+/', '-_'), '=');
    }

    private function sign(AdminCredentials $credentials, string $purpose, string $payload): string
    {
        return self::base64Url(hash_hmac('sha256', $purpose . '|' . $payload, $credentials->sessionKey(), true));
    }

    /** @return ?array{payload: string, expires_at: int} */
    private function session(AdminCredentials $credentials, array $server): ?array
    {
        $cookie = $_COOKIE[self::cookieName($server)] ?? null;
        if (!is_string($cookie) || strlen($cookie) > 512 || substr_count($cookie, '.') !== 1) {
            return null;
        }

        [$payload, $signature] = explode('.', $cookie);
        if (!hash_equals($this->sign($credentials, 'session', $payload), $signature)) {
            return null;
        }

        $decoded = base64_decode(strtr($payload, '-_', '+/'), true);
        $claims = is_string($decoded) ? json_decode($decoded, true) : null;
        $now = time();
        if (
            !is_array($claims)
            || ($claims['u'] ?? null) !== $credentials->username
            || !is_int($claims['exp'] ?? null) || $claims['exp'] <= $now
            || !is_int($claims['iat'] ?? null) || $claims['iat'] > $now + 60
        ) {
            return null;
        }

        return ['payload' => $payload, 'expires_at' => $claims['exp']];
    }

    private function tokenValid(AdminCredentials $credentials, array $session, array $server): bool
    {
        $token = $server['HTTP_X_ADMIN_CSRF'] ?? null;
        return is_string($token) && hash_equals($this->sign($credentials, 'csrf', $session['payload']), $token);
    }

    // ─── Sign-in ─────────────────────────────────────────────────────────

    /** One /64 is one IPv6 address here; keyed with the session key, so no address is stored. */
    private function addressKey(AdminCredentials $credentials, array $server): string
    {
        $address = (string) ($server['REMOTE_ADDR'] ?? '');
        $packed = @inet_pton($address);
        if (is_string($packed) && strlen($packed) === 16) {
            $packed = str_starts_with($packed, str_repeat("\0", 10) . "\xff\xff") ? substr($packed, 12) : substr($packed, 0, 8);
        }

        return substr(hash_hmac('sha256', 'address|' . (is_string($packed) ? $packed : $address), $credentials->sessionKey()), 0, 32);
    }

    private function login(AdminCredentials $credentials, array $server, string $admin): never
    {
        $username = $_POST['username'] ?? '';
        $username = is_string($username) ? substr($username, 0, 64) : '';
        if (!self::sameOrigin($server)) {
            $this->loginPage(403, $admin, 'That sign-in did not come from this page.', $username);
        }

        $now = time();
        $addressKey = $this->addressKey($credentials, $server);
        $attempt = $this->storage->adminSignInAttempt(
            $addressKey,
            $now,
            self::ADDRESS_WINDOW_SECONDS,
            3600,
            self::KNOWN_ADDRESS_SECONDS
        );

        $retryAt = null;
        if ($attempt['address']['count'] > self::TRIES_PER_ADDRESS) {
            $retryAt = $attempt['address']['since'] + self::ADDRESS_WINDOW_SECONDS;
        } elseif ($attempt['all']['count'] > self::TRIES_PER_HOUR && !$attempt['known']) {
            $retryAt = $attempt['all']['since'] + 3600;
        }
        if ($retryAt !== null) {
            if ($attempt['address']['count'] === self::TRIES_PER_ADDRESS + 1 || $attempt['all']['count'] === self::TRIES_PER_HOUR + 1) {
                error_log('ReticulumPhp: admin sign-in paused after too many attempts');
            }
            header('Retry-After: ' . max(1, $retryAt - $now));
            $this->loginPage(429, $admin, 'Too many sign-in attempts. Try again after ' . gmdate('H:i', $retryAt) . ' UTC; running admin-setup on the host lifts this at once.', $username);
        }

        $password = $_POST['password'] ?? '';
        $password = is_string($password) ? substr($password, 0, 1024) : '';
        // Both checks always run, so a wrong username takes as long as a
        // wrong password.
        $passwordRight = password_verify($password, $credentials->passwordHash);
        $usernameRight = hash_equals($credentials->username, $username);
        if (!$passwordRight || !$usernameRight) {
            $this->loginPage(401, $admin, 'Wrong username or password.', $username);
        }

        $this->storage->adminSignInSucceeded($addressKey, $now);
        $payload = self::base64Url(json_encode([
            'u' => $credentials->username,
            'iat' => $now,
            'exp' => $now + self::SESSION_SECONDS,
            'n' => bin2hex(random_bytes(8)),
        ], JSON_THROW_ON_ERROR));
        setcookie(
            self::cookieName($server),
            $payload . '.' . $this->sign($credentials, 'session', $payload),
            self::cookieOptions($server, $admin, $now + self::SESSION_SECONDS)
        );
        self::redirect($admin);
    }

    // ─── Actions ─────────────────────────────────────────────────────────

    private function liveData(): never
    {
        self::json(200, [
            'status' => 'ok',
            'generated_at' => microtime(true),
            'node' => [
                'host_url' => $this->config['host_url'] ?? null,
                'backend' => $this->config['storage']['backend'] ?? null,
                'php_version' => PHP_VERSION,
                'build' => BuildStamp::read($this->codeDir),
            ],
        ] + $this->storage->adminLiveData());
    }

    private function debugReport(): never
    {
        $maxRows = (int) ($this->config['debug']['max_rows'] ?? 20);
        self::json(200, [
            'status' => 'ok',
            'transport_basis' => requestTransportMechanism(),
            'environment' => Environment::verify(),
            'queues' => $this->storage->healthSummary(),
            'max_rows' => $maxRows,
            'report' => $this->storage->debugReport($maxRows),
        ]);
    }

    /**
     * Flush stale sessions: maintenance now, not at the next request's turn.
     * Forced, every interface but the PHP peers counts as stale at once, so
     * every browser must register again at its next exchange.
     */
    private function maintenance(): never
    {
        $force = (self::requestBody()['force'] ?? false) === true;
        $maintenance = $this->config['maintenance'] ?? [];
        $results = $this->storage->runMaintenance(
            $force ? 0 : (int) ($maintenance['interface_stale_after_seconds'] ?? 15),
            (int) ($maintenance['batch_ttl_seconds'] ?? 86400),
        );
        if ($force) {
            // Every client is stale now; its next poll must say so.
            EmptyPoll::clearAll($this->config);
        }

        self::json(200, ['status' => 'ok', 'force' => $force, 'flushed' => $results]);
    }

    /** A configured peer, by its [interfaces] name: never a URL the request names. */
    private function peerAction(string $action): never
    {
        $name = self::requestBody()['peer'] ?? null;
        if (!is_string($name) || $name === '') {
            self::json(400, ['error' => 'peer is required']);
        }

        $result = $action === 'rotate'
            ? $this->storage->rotateConfiguredPeer($name)
            : $this->storage->reconnectConfiguredPeer($name);
        $status = $result['status'] ?? '';
        $code = match (true) {
            in_array($status, ['connected', 'already_connected'], true) => 200,
            $status === 'not_configured' => 404,
            in_array($status, ['no_host_url', 'refused_duplicate_rows'], true) => 409,
            default => 502,
        };
        error_log(sprintf('[peer] admin %s %s -> %s', $action, json_encode($name, JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE), $status));

        self::json($code, ['action' => $action] + $result);
    }

    // ─── Answers ─────────────────────────────────────────────────────────

    /** No CORS, no caching, no framing; scripts and styles only with the page's nonce. */
    private static function sendHeaders(int $status, string $contentType, ?string $nonce = null): void
    {
        http_response_code($status);
        header('Content-Type: ' . $contentType);
        header('Cache-Control: no-store');
        header('X-Content-Type-Options: nosniff');
        header('X-Frame-Options: DENY');
        header('Referrer-Policy: no-referrer');
        header('Cross-Origin-Opener-Policy: same-origin');
        header('Cross-Origin-Resource-Policy: same-origin');
        header('X-Robots-Tag: noindex, nofollow');
        $sources = $nonce === null ? '' : "script-src 'nonce-{$nonce}'; style-src 'nonce-{$nonce}'; ";
        header("Content-Security-Policy: default-src 'none'; {$sources}img-src 'self' data:; connect-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'");
    }

    private static function json(int $status, array $payload): never
    {
        self::sendHeaders($status, 'application/json; charset=utf-8');
        echo json_encode($payload, JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE | JSON_PARTIAL_OUTPUT_ON_ERROR);
        exit;
    }

    private static function redirect(string $location): never
    {
        self::sendHeaders(303, 'text/plain; charset=utf-8');
        header('Location: ' . $location);
        exit;
    }

    private function loginPage(int $status, string $admin, ?string $error, string $username): never
    {
        $nonce = base64_encode(random_bytes(18));
        self::sendHeaders($status, 'text/html; charset=utf-8', $nonce);
        echo AdminPage::login($nonce, $admin, (string) ($this->config['host_url'] ?? ''), $error, $username);
        exit;
    }

    private function consolePage(AdminCredentials $credentials, array $session, string $admin): never
    {
        $nonce = base64_encode(random_bytes(18));
        self::sendHeaders(200, 'text/html; charset=utf-8', $nonce);
        echo AdminPage::console(
            $nonce,
            $admin,
            $this->sign($credentials, 'csrf', $session['payload']),
            (string) ($this->config['host_url'] ?? ''),
            $credentials->username,
            $session['expires_at']
        );
        exit;
    }
}

/** The two pages. Everything a client or peer wrote reaches them as text (textContent), never as markup. */
final class AdminPage
{
    private const STYLE = <<<'CSS'
:root { color-scheme: light dark; --bg: #f5f6f8; --panel: #fff; --text: #1c2230; --muted: #667085; --line: #e3e6eb;
  --accent: #2563eb; --good: #15803d; --warn: #b45309; --bad: #b91c1c; --in: #2563eb; --out: #c026d3; }
@media (prefers-color-scheme: dark) {
  :root { --bg: #0e1117; --panel: #161a22; --text: #e5e8ee; --muted: #98a2b3; --line: #29303b;
    --accent: #60a5fa; --good: #4ade80; --warn: #fbbf24; --bad: #f87171; --in: #60a5fa; --out: #e879f9; }
}
* { box-sizing: border-box; }
body { margin: 0; font: 14px/1.45 system-ui, -apple-system, "Segoe UI", Roboto, sans-serif; background: var(--bg); color: var(--text); }
h1 { font-size: 16px; margin: 0; }
h2 { font-size: 12px; text-transform: uppercase; letter-spacing: .06em; color: var(--muted); margin: 0 0 10px; font-weight: 600; }
button { font: inherit; padding: 5px 12px; border-radius: 6px; border: 1px solid var(--line); background: var(--bg); color: var(--text); cursor: pointer; }
button:hover:not(:disabled) { border-color: var(--accent); }
button:disabled { opacity: .5; cursor: default; }
button.danger { color: var(--bad); }
input { font: inherit; width: 100%; padding: 8px 10px; border-radius: 6px; border: 1px solid var(--line); background: var(--bg); color: var(--text); }
.muted { color: var(--muted); }
.good { color: var(--good); } .warn { color: var(--warn); } .bad { color: var(--bad); }
.signin { max-width: 340px; margin: 12vh auto; padding: 24px; background: var(--panel); border: 1px solid var(--line); border-radius: 12px; }
.signin form { display: grid; gap: 12px; margin-top: 16px; }
.signin label { display: grid; gap: 4px; font-size: 13px; color: var(--muted); }
.signin .error { color: var(--bad); margin: 0; min-height: 1.4em; }
header { display: flex; flex-wrap: wrap; gap: 8px 16px; align-items: center; justify-content: space-between; padding: 12px 20px;
  background: var(--panel); border-bottom: 1px solid var(--line); position: sticky; top: 0; z-index: 2; }
header .who { display: flex; gap: 10px; align-items: center; flex-wrap: wrap; }
header form { margin: 0; }
.banner { display: none; padding: 10px 20px; background: var(--bad); color: #fff; }
.banner a { color: #fff; }
main { max-width: 1240px; margin: 0 auto; padding: 16px 20px 48px; display: grid; gap: 16px; }
section, details { background: var(--panel); border: 1px solid var(--line); border-radius: 10px; padding: 14px 16px; min-width: 0; }
details > summary { cursor: pointer; font-weight: 600; }
details[open] > summary { margin-bottom: 10px; }
.cards { display: grid; grid-template-columns: repeat(auto-fit, minmax(170px, 1fr)); gap: 12px; }
.card { background: var(--panel); border: 1px solid var(--line); border-radius: 10px; padding: 12px 14px; }
.card .label { color: var(--muted); font-size: 12px; }
.card .value { font-size: 22px; font-weight: 600; font-variant-numeric: tabular-nums; }
.card .sub { color: var(--muted); font-size: 12px; font-variant-numeric: tabular-nums; }
.bar { height: 6px; background: var(--line); border-radius: 3px; overflow: hidden; margin-top: 6px; }
.bar > span { display: block; height: 100%; width: 0; background: var(--accent); }
.bar.full > span { background: var(--bad); }
.scroll { overflow-x: auto; }
table { border-collapse: collapse; width: 100%; font-variant-numeric: tabular-nums; }
th, td { text-align: left; padding: 6px 8px; border-bottom: 1px solid var(--line); white-space: nowrap; vertical-align: top; }
th { color: var(--muted); font-weight: 500; font-size: 12px; }
td.num, th.num { text-align: right; }
td.empty { color: var(--muted); text-align: center; }
.badge { display: inline-block; padding: 0 8px; border-radius: 999px; font-size: 12px; border: 1px solid currentColor; }
.id { color: var(--muted); font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 12px; }
.actions { display: flex; gap: 8px; flex-wrap: wrap; align-items: center; }
.grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(260px, 1fr)); gap: 2px 24px; margin: 0; }
.grid div { display: flex; justify-content: space-between; gap: 12px; border-bottom: 1px dashed var(--line); padding: 3px 0; }
.grid dt { color: var(--muted); } .grid dd { margin: 0; font-variant-numeric: tabular-nums; }
pre { background: var(--bg); border: 1px solid var(--line); border-radius: 6px; padding: 10px; overflow: auto; max-height: 440px; font-size: 12px; margin: 10px 0 0; }
pre:empty { display: none; }
svg.spark { width: 100%; height: 120px; display: block; }
svg.spark polyline { fill: none; stroke-width: 2; vector-effect: non-scaling-stroke; }
svg.spark .in { stroke: var(--in); } svg.spark .out { stroke: var(--out); }
.legend { display: flex; flex-wrap: wrap; gap: 6px 18px; font-size: 12px; color: var(--muted); margin-top: 6px; }
.legend .in::before, .legend .out::before { content: ''; display: inline-block; width: 12px; height: 3px; margin-right: 6px; vertical-align: middle; }
.legend .in::before { background: var(--in); } .legend .out::before { background: var(--out); }
.hint { color: var(--muted); font-size: 12px; margin: 8px 0 0; }
CSS;

    private const SCRIPT = <<<'JS'
'use strict';
(() => {
  const ADMIN = document.body.dataset.admin;
  const TOKEN = document.body.dataset.token;
  const POLL_MS = 5000;
  const KEEP = 120;
  let timer = null;
  let paused = false;
  let busy = false;
  let previous = null;
  let updatedAt = null;
  let failure = null;
  const history = [];

  const $ = (id) => document.getElementById(id);
  const h = (tag, props, ...kids) => {
    const node = document.createElement(tag);
    for (const [key, value] of Object.entries(props || {})) {
      if (value === null || value === undefined || value === false) continue;
      if (key === 'class') node.className = value;
      else if (key === 'text') node.textContent = value;
      else if (key === 'onclick') node.addEventListener('click', value);
      else node.setAttribute(key, value === true ? '' : String(value));
    }
    for (const kid of kids.flat()) {
      if (kid !== null && kid !== undefined && kid !== false) node.append(kid instanceof Node ? kid : String(kid));
    }
    return node;
  };
  const num = (value) => Number(value) || 0;
  const count = (value) => num(value).toLocaleString();
  const bytes = (value) => {
    let n = num(value);
    const units = ['B', 'kB', 'MB', 'GB', 'TB'];
    let unit = 0;
    while (Math.abs(n) >= 1000 && unit < units.length - 1) { n /= 1000; unit++; }
    return (unit === 0 ? String(Math.round(n)) : n.toFixed(Math.abs(n) < 10 ? 1 : 0)) + ' ' + units[unit];
  };
  const rate = (value) => (value === null || value === undefined ? '–' : bytes(value) + '/s');
  const ago = (ts, now) => {
    if (!num(ts)) return '–';
    const s = Math.max(0, Math.round(now - num(ts)));
    if (s < 60) return s + ' s ago';
    if (s < 3600) return Math.floor(s / 60) + ' min ago';
    if (s < 86400) return Math.floor(s / 3600) + ' h ago';
    return Math.floor(s / 86400) + ' d ago';
  };
  const short = (value) => {
    const text = value === null || value === undefined ? '' : String(value);
    return text.length > 18 ? h('span', { title: text, text: text.slice(0, 16) + '…' }) : text;
  };
  const replace = (id, ...kids) => $(id).replaceChildren(...kids.flat());
  const cell = (value, cls) => h('td', { class: cls }, value);
  const emptyRow = (columns, text) => h('tr', {}, h('td', { class: 'empty', colspan: columns, text }));

  function setStatus() {
    const status = $('status');
    if (failure) { status.className = 'bad'; status.textContent = failure; return; }
    if (paused) { status.className = 'warn'; status.textContent = 'Paused'; return; }
    status.className = 'muted';
    status.textContent = updatedAt === null ? 'Loading…' : 'Updated ' + ago(updatedAt / 1000, Date.now() / 1000);
  }

  function signedOut() {
    clearTimeout(timer);
    paused = true;
    $('banner').style.display = 'block';
    failure = 'Signed out';
    setStatus();
  }

  async function request(path, options) {
    const response = await fetch(ADMIN + path, Object.assign({ credentials: 'same-origin', cache: 'no-store' }, options || {}));
    if (response.status === 401) { signedOut(); throw new Error('signed out'); }
    const text = await response.text();
    let body;
    try { body = JSON.parse(text); } catch (error) { body = { error: text.slice(0, 200) || 'HTTP ' + response.status }; }
    return { status: response.status, body };
  }

  async function poll() {
    clearTimeout(timer);
    try {
      const { status, body } = await request('/data', { headers: { Accept: 'application/json' } });
      if (status !== 200) throw new Error(body.error || 'HTTP ' + status);
      render(body);
      failure = null;
      updatedAt = Date.now();
    } catch (error) {
      if (error.message === 'signed out') return;
      failure = 'Update failed: ' + error.message;
    }
    setStatus();
    schedule();
  }

  function schedule() {
    clearTimeout(timer);
    if (!paused && document.visibilityState === 'visible') timer = setTimeout(poll, POLL_MS);
  }

  function render(d) {
    const now = num(d.generated_at);
    const rates = new Map();
    let rxRate = null;
    let txRate = null;
    if (previous && now > previous.at) {
      const dt = now - previous.at;
      rxRate = 0; txRate = 0;
      for (const iface of d.interfaces || []) {
        const before = previous.byId.get(iface.interface_id);
        if (!before) continue;
        const rx = (num(iface.rx_bytes) - num(before.rx_bytes)) / dt;
        const tx = (num(iface.tx_bytes) - num(before.tx_bytes)) / dt;
        if (rx < 0 || tx < 0) continue;
        rates.set(iface.interface_id, { rx, tx, rxp: (num(iface.rx_packets) - num(before.rx_packets)) / dt, txp: (num(iface.tx_packets) - num(before.tx_packets)) / dt });
        rxRate += rx; txRate += tx;
      }
      history.push({ at: now, rx: rxRate, tx: txRate });
      while (history.length > KEEP) history.shift();
    }
    previous = { at: now, byId: new Map((d.interfaces || []).map((iface) => [iface.interface_id, iface])) };

    const node = d.node || {};
    $('host').textContent = node.host_url || '';
    const commit = node.build && node.build.commit;
    $('build').textContent = commit ? 'build ' + commit.slice(0, 10) : 'build unknown';
    $('build').title = commit ? commit + (node.build.stamped_at ? ' · ' + node.build.stamped_at : '') : 'no verified deploy stamp';

    const pending = new Map((d.outbound_pending || []).map((row) => [row.interface_id, row]));
    renderCards(d, rxRate, txRate);
    renderSpark();
    renderPeers(d.peers || [], now, pending);
    renderInterfaces(d.interfaces || [], now, rates, pending);
    renderQueues(d.queues || {});
    renderTable('recent-inbound', d.recent_inbound || [], now);
    renderTable('recent-outbound', d.recent_outbound || [], now);
    renderTable('recent-batches', d.recent_batches || [], now);
  }

  function card(label, value, sub, cls, bar) {
    const parts = [h('div', { class: 'label', text: label }), h('div', { class: 'value ' + (cls || ''), text: value })];
    if (sub) parts.push(h('div', { class: 'sub', text: sub }));
    if (bar !== undefined) {
      const fill = h('span');
      fill.style.width = Math.min(100, Math.max(0, bar * 100)).toFixed(1) + '%';
      parts.push(h('div', { class: 'bar' + (bar >= 0.9 ? ' full' : '') }, fill));
    }
    return h('div', { class: 'card' }, parts);
  }

  function renderCards(d, rxRate, txRate) {
    const q = d.queues || {};
    const peers = d.peers || [];
    const live = peers.filter((peer) => peer.live).length;
    const browsers = (d.interfaces || []).filter((iface) => iface.status === 'online' && iface.metadata && iface.metadata.client === 'rns-js').length;
    const budget = num(q.storage_budget_bytes);
    replace('cards',
      card('Connections online', count(q.interfaces_online), 'of ' + count(q.interfaces) + ' rows · ' + browsers + ' browsers listed'),
      card('Peers live', peers.length ? live + ' / ' + peers.length : '–', peers.length ? 'configured in [interfaces]' : 'none configured', peers.length && live < peers.length ? 'warn' : ''),
      card('Traffic in', rate(rxRate), 'into this node'),
      card('Traffic out', rate(txRate), 'out of this node'),
      card('Queued outbound', count(q.outbound_packets_pending), 'packets · ' + count(q.outbound_batches_unacked) + ' batches unacknowledged'),
      card('Received, unprocessed', count(q.inbound_batches_pending), 'batches · ' + count(q.inbound_packets_failed) + ' packets failed'),
      card('Storage', bytes(q.storage_bytes), budget ? 'of ' + bytes(budget) + ' budget' : 'no budget', '', budget ? num(q.storage_bytes) / budget : undefined));
  }

  function renderSpark() {
    const svg = $('spark');
    const max = Math.max(1, ...history.map((point) => Math.max(point.rx, point.tx)));
    const width = 600;
    const height = 100;
    const step = width / (KEEP - 1);
    // Newest at the right edge, one step per update.
    const line = (key) => history.map((point, index) => {
      const x = width - (history.length - 1 - index) * step;
      const y = height - (point[key] / max) * (height - 4) - 2;
      return x.toFixed(1) + ',' + y.toFixed(1);
    }).join(' ');
    svg.querySelector('.in').setAttribute('points', line('rx'));
    svg.querySelector('.out').setAttribute('points', line('tx'));
    const last = history[history.length - 1];
    $('spark-legend').replaceChildren(
      h('span', { class: 'in', text: 'in ' + rate(last ? last.rx : null) }),
      h('span', { class: 'out', text: 'out ' + rate(last ? last.tx : null) }),
      h('span', { text: 'peak ' + rate(history.length ? max : null) + ' · last ' + Math.ceil(history.length * POLL_MS / 60000) + ' min' }));
  }

  function peerState(peer) {
    if (peer.rows > 1) return h('span', { class: 'badge bad', text: peer.rows + ' rows', title: 'More than one row names this peer: look before rotating.' });
    if (!peer.interface) return h('span', { class: 'badge bad', text: 'no row' });
    if (peer.live) return h('span', { class: 'badge good', text: 'live' });
    return h('span', { class: 'badge warn', text: peer.interface.status || 'not live', title: 'Not online in the last 15 minutes. A wake-based peer goes offline after a quiet spell.' });
  }

  function renderPeers(peers, now, pending) {
    const rows = peers.map((peer) => {
      const iface = peer.interface || {};
      const queued = pending.get(iface.interface_id);
      return h('tr', {},
        cell(h('strong', { text: peer.name })),
        cell(peer.node_url),
        cell(peerState(peer)),
        cell(ago(iface.last_seen_at, now)),
        cell(peer.interface ? count(iface.rx_packets) + ' · ' + bytes(iface.rx_bytes) : '–', 'num'),
        cell(peer.interface ? count(iface.tx_packets) + ' · ' + bytes(iface.tx_bytes) : '–', 'num'),
        cell(queued ? count(queued.pending) : '0', 'num'),
        cell(h('div', { class: 'actions' },
          h('button', { text: 'Reconnect', onclick: () => peerAction('reconnect', peer) }),
          h('button', { class: 'danger', text: 'Rotate…', onclick: () => peerAction('rotate', peer) }))));
    });
    replace('peers', rows.length ? rows : [emptyRow(8, 'No peers configured: [interfaces] in the config names none.')]);
  }

  function renderInterfaces(interfaces, now, rates, pending) {
    // PHP peer rows always; a client row only while it is online. Stale and
    // offline clients are noise here; the debug report lists them.
    const shown = interfaces.filter((iface) => iface.peer_url || iface.status === 'online');
    const sorted = shown.sort((a, b) => (a.status === 'online' ? 0 : 1) - (b.status === 'online' ? 0 : 1) || num(b.last_seen_at) - num(a.last_seen_at));
    const rows = sorted.map((iface) => {
      const meta = iface.metadata || {};
      const r = rates.get(iface.interface_id);
      const queued = pending.get(iface.interface_id);
      return h('tr', {},
        cell([h('div', { text: iface.name || '(unnamed)' }), h('div', { class: 'id', text: String(iface.interface_id || '').slice(0, 12) })]),
        cell([meta.client || '–', meta.mode !== undefined ? h('span', { class: 'muted', text: ' · mode ' + meta.mode }) : null, iface.peer_url ? h('div', { class: 'muted', text: iface.peer_url }) : null]),
        cell(h('span', { class: 'badge ' + (iface.status === 'online' ? 'good' : 'muted'), text: iface.status || '?' })),
        cell(ago(iface.last_seen_at, now)),
        cell(count(iface.rx_packets) + ' · ' + bytes(iface.rx_bytes), 'num'),
        cell(count(iface.tx_packets) + ' · ' + bytes(iface.tx_bytes), 'num'),
        cell(r ? rate(r.rx) : '–', 'num'),
        cell(r ? rate(r.tx) : '–', 'num'),
        cell(queued ? count(queued.pending) : '0', 'num'));
    });
    replace('interfaces', rows.length ? rows : [emptyRow(9, 'No connections online.')]);
  }

  function renderQueues(q) {
    replace('queues', Object.entries(q).map(([key, value]) => h('div', {},
      h('dt', { text: key.replace(/_/g, ' ') }),
      h('dd', { text: /bytes$/.test(key) ? bytes(value) : count(value) }))));
  }

  function renderTable(id, rows, now) {
    const table = $(id);
    if (!rows.length) { table.replaceChildren(h('tbody', {}, emptyRow(1, 'Nothing yet.'))); return; }
    const keys = Object.keys(rows[0]).filter((key) => typeof rows[0][key] !== 'object' || rows[0][key] === null);
    const format = (key, value) => {
      if (value === null || value === undefined || value === '') return '–';
      if (/_at$/.test(key)) return ago(value, now);
      return short(value);
    };
    table.replaceChildren(
      h('thead', {}, h('tr', {}, keys.map((key) => h('th', { text: key.replace(/_/g, ' ') })))),
      h('tbody', {}, rows.map((row) => h('tr', {}, keys.map((key) => h('td', {}, format(key, row[key])))))));
  }

  function setBusy(value) {
    busy = value;
    for (const button of document.querySelectorAll('main button')) button.disabled = value;
  }

  async function act(label, path, body) {
    if (busy) return;
    setBusy(true);
    $('result-title').textContent = label + ' — working…';
    $('result').textContent = '';
    try {
      const started = Date.now();
      const { status, body: answer } = await request(path, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-Admin-Csrf': TOKEN },
        body: JSON.stringify(body),
      });
      $('result-title').textContent = label + ' — HTTP ' + status + ' in ' + ((Date.now() - started) / 1000).toFixed(1) + ' s';
      $('result').textContent = JSON.stringify(answer, null, 2);
    } catch (error) {
      $('result-title').textContent = label + ' — ' + error.message;
    } finally {
      setBusy(false);
      if (!paused) poll();
    }
  }

  function peerAction(action, peer) {
    const text = action === 'rotate'
      ? 'Rotate the peering with ' + peer.name + '?\n\nThis node deletes its row for ' + peer.node_url + ' and registers there afresh: new credentials at both ends. '
        + 'Packets queued for the old row are lost, paths through it wait for the next announces, and links relayed across it drop, so their users should reload.'
      : 'Reconnect ' + peer.name + '?\n\nA live row is left alone. A row that is not online (a quiet spell is enough) is deleted and registered afresh, which issues new credentials at both ends, as rotating does.';
    if (!confirm(text)) return;
    act((action === 'rotate' ? 'Rotate ' : 'Reconnect ') + peer.name, '/peers/' + action, { peer: peer.name });
  }

  $('flush').addEventListener('click', () => act('Flush stale sessions', '/maintenance', { force: false }));
  $('force-flush').addEventListener('click', () => {
    if (confirm('Force a flush?\n\nEvery connection except the PHP peers is marked stale at once, so every browser and gateway must register again at its next exchange.')) {
      act('Forced flush', '/maintenance', { force: true });
    }
  });
  $('debug-load').addEventListener('click', async () => {
    $('debug-out').textContent = 'Loading…';
    try {
      const { status, body } = await request('/debug');
      $('debug-out').textContent = (status === 200 ? '' : 'HTTP ' + status + '\n') + JSON.stringify(body, null, 2);
    } catch (error) {
      $('debug-out').textContent = error.message;
    }
  });
  $('pause').addEventListener('click', () => {
    paused = !paused;
    $('pause').textContent = paused ? 'Resume' : 'Pause';
    if (paused) clearTimeout(timer); else poll();
    setStatus();
  });
  document.addEventListener('visibilitychange', () => {
    if (document.visibilityState === 'visible' && !paused) poll(); else clearTimeout(timer);
  });
  setInterval(setStatus, 1000);
  poll();
})();
JS;

    private static function escape(string $text): string
    {
        return htmlspecialchars($text, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
    }

    private static function head(string $nonce, string $title): string
    {
        return '<!doctype html><html lang="en"><head><meta charset="utf-8">'
            . '<meta name="viewport" content="width=device-width, initial-scale=1">'
            . '<meta name="robots" content="noindex, nofollow">'
            . '<title>' . self::escape($title) . '</title>'
            . '<style nonce="' . self::escape($nonce) . '">' . self::STYLE . '</style></head>';
    }

    public static function login(string $nonce, string $admin, string $host, ?string $error, string $username): string
    {
        $action = self::escape($admin . '/login');
        $hostText = self::escape($host);
        $errorText = self::escape($error ?? '');
        $usernameValue = self::escape($username);

        return self::head($nonce, 'Sign in · node admin') . <<<HTML
<body>
<main class="signin">
  <h1>Reticulum PHP node</h1>
  <div class="muted">{$hostText}</div>
  <form method="post" action="{$action}">
    <label>Username <input name="username" autocomplete="username" maxlength="64" required autofocus value="{$usernameValue}"></label>
    <label>Password <input name="password" type="password" autocomplete="current-password" required></label>
    <p class="error" role="alert">{$errorText}</p>
    <button type="submit">Sign in</button>
  </form>
</main>
</body></html>
HTML;
    }

    public static function console(string $nonce, string $admin, string $token, string $host, string $username, int $expiresAt): string
    {
        $adminAttr = self::escape($admin);
        $tokenAttr = self::escape($token);
        $hostText = self::escape($host);
        $who = self::escape($username);
        $until = self::escape(gmdate('H:i', $expiresAt) . ' UTC');
        $nonceAttr = self::escape($nonce);

        return self::head($nonce, 'Node admin') . <<<HTML
<body data-admin="{$adminAttr}" data-token="{$tokenAttr}">
<div class="banner" id="banner">Signed out: the session ended. <a href="{$adminAttr}">Sign in again</a></div>
<header>
  <div>
    <h1>Reticulum PHP node</h1>
    <div class="muted"><span id="host">{$hostText}</span> · <span id="build">build …</span></div>
  </div>
  <div class="who">
    <span id="status" class="muted">Loading…</span>
    <button id="pause" type="button">Pause</button>
    <span class="muted" title="Sessions last two hours">{$who}, until {$until}</span>
    <form method="post" action="{$adminAttr}/logout"><button type="submit">Sign out</button></form>
  </div>
</header>
<main>
  <div class="cards" id="cards"></div>
  <section>
    <h2>Traffic</h2>
    <svg class="spark" id="spark" viewBox="0 0 600 100" preserveAspectRatio="none" aria-label="Bytes per second in and out">
      <polyline class="in" points=""></polyline><polyline class="out" points=""></polyline>
    </svg>
    <div class="legend" id="spark-legend"></div>
    <p class="hint">Summed over the 50 connections seen most recently, from the change in their counters between updates (every 5 s while this tab is visible).</p>
  </section>
  <section>
    <h2>Peers</h2>
    <div class="scroll"><table>
      <thead><tr><th>Peer</th><th>Node URL</th><th>Row here</th><th>Last seen</th><th class="num">In (packets · bytes)</th><th class="num">Out</th><th class="num">Queued</th><th></th></tr></thead>
      <tbody id="peers"></tbody>
    </table></div>
    <p class="hint">Reconnect does what <code>php index.php initialize</code> does for one peer, without the migration. Rotate is README's "Rotating a PHP peering's credentials" step 2 in one action. Either can take up to 10 s when the peer is slow to answer.</p>
  </section>
  <section>
    <h2>Connections</h2>
    <div class="scroll"><table>
      <thead><tr><th>Name</th><th>Client</th><th>Status</th><th>Last seen</th><th class="num">In (packets · bytes)</th><th class="num">Out</th><th class="num">In/s</th><th class="num">Out/s</th><th class="num">Queued</th></tr></thead>
      <tbody id="interfaces"></tbody>
    </table></div>
    <p class="hint">Of the 50 rows seen most recently: the PHP peers, and the clients online now.</p>
  </section>
  <section>
    <h2>Queues and storage</h2>
    <dl class="grid" id="queues"></dl>
  </section>
  <section>
    <h2>Maintenance</h2>
    <div class="actions">
      <button id="flush" type="button">Flush stale sessions</button>
      <button id="force-flush" class="danger" type="button">Force flush…</button>
    </div>
    <p class="hint" id="result-title">Actions report here.</p>
    <pre id="result"></pre>
  </section>
  <details>
    <summary>Recent packets</summary>
    <h2>Received</h2><div class="scroll"><table id="recent-inbound"></table></div>
    <h2>Queued outbound</h2><div class="scroll"><table id="recent-outbound"></table></div>
    <h2>Received batches</h2><div class="scroll"><table id="recent-batches"></table></div>
  </details>
  <details>
    <summary>Debug report</summary>
    <button id="debug-load" type="button">Load</button>
    <pre id="debug-out"></pre>
  </details>
</main>
<script nonce="{$nonceAttr}">
HTML . self::SCRIPT . "\n</script>\n</body></html>\n";
    }
}
