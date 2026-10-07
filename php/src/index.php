<?php

declare(strict_types=1);

namespace ReticulumPhp;

use RuntimeException;
use PDO;

require_once __DIR__ . '/lib/request_runtime.php';
require_once __DIR__ . '/lib/database.php';
require_once __DIR__ . '/lib/request_control_plane_trait.php';
require_once __DIR__ . '/lib/request_debug_report_trait.php';
require_once __DIR__ . '/lib/request_http_api_helper_trait.php';
require_once __DIR__ . '/lib/request_interface_registry_trait.php';
require_once __DIR__ . '/lib/request_interface_runtime_trait.php';
require_once __DIR__ . '/lib/request_inbound_batch_trait.php';
require_once __DIR__ . '/lib/request_json_codec_trait.php';
require_once __DIR__ . '/lib/request_lxmf_handoff_trait.php';
require_once __DIR__ . '/lib/request_maintenance_trait.php';
require_once __DIR__ . '/lib/request_outbound_batch_trait.php';
require_once __DIR__ . '/lib/request_packet_ingest_trait.php';
require_once __DIR__ . '/lib/request_path_state_trait.php';
require_once __DIR__ . '/lib/request_relay_routing_trait.php';
require_once __DIR__ . '/lib/request_schema_trait.php';
require_once __DIR__ . '/lib/request_storage_budget_trait.php';
require_once __DIR__ . '/lib/request_php_wake_trait.php';
require_once __DIR__ . '/lib/empty_poll.php';

// Reticulum-php is request-operated. Queued transport bytes only move during
// authenticated request/response exchanges. Wake helpers exist to prompt the
// next request, not to create a second transport path.

final class Config
{
    private const CONFIG_CANDIDATES = [
        'config.local.toml',
        'config.local.php',
        'config.toml',
        'config.php',
    ];

    public static function load(string $projectRoot): array
    {
        $configPath = self::resolveConfigPath($projectRoot);

        $config = match (pathinfo($configPath, PATHINFO_EXTENSION)) {
            'php' => self::loadPhpConfig($configPath),
            'toml' => self::loadTomlConfig($projectRoot, $configPath),
            default => throw new RuntimeException('Unsupported configuration file type: ' . $configPath),
        };

        return self::normalizeConfig($config);
    }

    public static function hasConfigFile(string $projectRoot): bool
    {
        foreach (self::CONFIG_CANDIDATES as $candidate) {
            if (is_file($projectRoot . '/' . $candidate)) {
                return true;
            }
        }

        return false;
    }

    private static function resolveConfigPath(string $projectRoot): string
    {
        foreach (self::CONFIG_CANDIDATES as $candidate) {
            $candidatePath = $projectRoot . '/' . $candidate;
            if (file_exists($candidatePath)) {
                return $candidatePath;
            }
        }

        throw new RuntimeException('No configuration file found in project root: ' . $projectRoot);
    }

    private static function loadPhpConfig(string $configPath): array
    {
        $config = require $configPath;
        if (!is_array($config)) {
            throw new RuntimeException('Configuration file must return an array');
        }

        return $config;
    }

    private static function loadTomlConfig(string $projectRoot, string $configPath): array
    {
        $baseConfig = self::defaultConfig($projectRoot);

        $rawConfig = file_get_contents($configPath);
        if ($rawConfig === false) {
            throw new RuntimeException('Unable to read configuration file: ' . $configPath);
        }

        $parsedConfig = self::parseTomlConfig($rawConfig);
        $expandedConfig = self::expandStringPlaceholders($parsedConfig, [
            'project_root' => $projectRoot,
            'php_binary' => PHP_BINARY,
        ]);

        return self::mergeConfigTrees($baseConfig, $expandedConfig);
    }

    private static function defaultConfig(string $projectRoot): array
    {
        return [
            'storage' => [
                'backend' => 'mysql',
                'sqlite_path' => $projectRoot . '/var/reticulum-php.sqlite',
                'mysql_host' => '127.0.0.1',
                'mysql_port' => 3306,
                'mysql_dbname' => 'reticulum_php',
                'mysql_user' => 'reticulum',
                'mysql_pass' => '',
                'log_path' => $projectRoot . '/var/router.log',
            ],
            'php' => [
                'memory_limit' => '128M',
            ],
            'http' => [
                'idle_exchange_interval_ms' => 1000,
                'max_batch_packets' => 64,
                'max_packet_bytes' => 512,
                'min_wake_interval_ms' => 1000,
                'wake_timeout_ms' => 500,
            ],
            'maintenance' => [
                'interface_stale_after_seconds' => 300,
                'batch_ttl_seconds' => 86400,
                'packet_hash_ttl_seconds' => 86400,
                'path_request_tag_ttl_seconds' => 86400,
                'reverse_path_ttl_seconds' => 480,
                'link_transport_ttl_seconds' => 900,
                'inbound_packet_ttl_seconds' => 3600,
                'outbound_packet_ttl_seconds' => 86400,
                'packet_storage_max_bytes' => 300000000,
                // Total disk Reticulum-php may occupy: every table it owns plus
                // its log files. See RequestStorageBudgetTrait.
                'storage_max_bytes' => 300000000,
                'storage_log_max_bytes' => 16000000,
                'storage_check_interval_seconds' => 600,
                'storage_prune_max_rows_per_pass' => 200000,
                'storage_prune_min_age_seconds' => 300,
                'outbound_pending_max_age_seconds' => 86400,
                'storage_reclaim_min_free_bytes' => 64000000,
                'storage_reclaim_min_interval_seconds' => 3600,
            ],
            'transport' => [
                'rns_mtu' => 500,
                'pathfinder_max_hops' => 128,
                'path_expiry_default_seconds' => 604800,
                'path_expiry_access_point_seconds' => 86400,
                'path_expiry_roaming_seconds' => 21600,
                'max_random_blobs' => 64,
            ],
        ];
    }

    private static function parseTomlConfig(string $rawConfig): array
    {
        $config = [];
        $currentSection = [];
        $currentInterfaceName = null;
        $lines = preg_split('/\r\n|\n|\r/', $rawConfig) ?: [];

        foreach ($lines as $lineNumber => $rawLine) {
            $line = trim(self::stripLineComment($rawLine));
            if ($line === '') {
                continue;
            }

            if (preg_match('/^\[(.+)\]$/', $line, $matches) === 1 && !str_starts_with($line, '[[')) {
                $currentSection = self::parseSectionPath(trim($matches[1]), $lineNumber + 1);
                $currentInterfaceName = null;
                self::ensureSectionPath($config, $currentSection);
                continue;
            }

            if (preg_match('/^\[\[(.+)\]\]$/', $line, $matches) === 1) {
                if ($currentSection !== ['interfaces']) {
                    throw new RuntimeException('Invalid TOML config at line ' . ($lineNumber + 1) . ': [[...]] blocks are only supported inside [interfaces]');
                }

                $currentInterfaceName = trim($matches[1]);
                if ($currentInterfaceName === '') {
                    throw new RuntimeException('Invalid TOML config at line ' . ($lineNumber + 1) . ': interface name must not be empty');
                }

                if (!isset($config['interfaces'][$currentInterfaceName]) || !is_array($config['interfaces'][$currentInterfaceName])) {
                    $config['interfaces'][$currentInterfaceName] = [];
                }

                continue;
            }

            if (preg_match('/^([A-Za-z0-9_-]+)\s*=\s*(.+)$/', $line, $matches) !== 1) {
                throw new RuntimeException('Invalid TOML config at line ' . ($lineNumber + 1) . ': expected key = value');
            }

            $key = $matches[1];
            $value = self::parseTomlValue($matches[2], $lineNumber + 1);

            if ($currentSection === ['interfaces']) {
                if ($currentInterfaceName === null) {
                    throw new RuntimeException('Invalid TOML config at line ' . ($lineNumber + 1) . ': interface properties require a preceding [[Interface Name]] block');
                }

                $config['interfaces'][$currentInterfaceName][$key] = $value;
                continue;
            }

            $target =& self::sectionReference($config, $currentSection);
            $target[$key] = $value;
        }

        return $config;
    }

    private static function stripLineComment(string $line): string
    {
        $length = strlen($line);
        $quote = null;
        $bracketDepth = 0;

        for ($index = 0; $index < $length; $index++) {
            $char = $line[$index];
            $previous = $index > 0 ? $line[$index - 1] : null;

            if ($quote !== null) {
                if ($char === $quote && $previous !== '\\') {
                    $quote = null;
                }
                continue;
            }

            if ($char === '"' || $char === '\'') {
                $quote = $char;
                continue;
            }

            if ($char === '[') {
                $bracketDepth++;
                continue;
            }

            if ($char === ']' && $bracketDepth > 0) {
                $bracketDepth--;
                continue;
            }

            if ($char === '#' && $bracketDepth === 0) {
                return substr($line, 0, $index);
            }
        }

        return $line;
    }

    private static function parseSectionPath(string $sectionPath, int $lineNumber): array
    {
        if ($sectionPath === '') {
            throw new RuntimeException('Invalid TOML config at line ' . $lineNumber . ': section name must not be empty');
        }

        $segments = array_map('trim', explode('.', $sectionPath));
        foreach ($segments as $segment) {
            if ($segment === '' || preg_match('/^[A-Za-z0-9_-]+$/', $segment) !== 1) {
                throw new RuntimeException('Invalid TOML config at line ' . $lineNumber . ': invalid section path ' . $sectionPath);
            }
        }

        return $segments;
    }

    private static function parseTomlValue(string $rawValue, int $lineNumber): mixed
    {
        $value = trim($rawValue);
        if ($value === '') {
            throw new RuntimeException('Invalid TOML config at line ' . $lineNumber . ': value must not be empty');
        }

        if ($value[0] === '[' && substr($value, -1) === ']') {
            $inner = trim(substr($value, 1, -1));
            if ($inner === '') {
                return [];
            }

            $items = [];
            foreach (self::splitTopLevelList($inner, $lineNumber) as $item) {
                $items[] = self::parseTomlValue($item, $lineNumber);
            }

            return $items;
        }

        if ($value[0] === '"' && substr($value, -1) === '"') {
            try {
                return json_decode($value, true, 512, JSON_THROW_ON_ERROR);
            } catch (\JsonException $error) {
                throw new RuntimeException('Invalid TOML config at line ' . $lineNumber . ': ' . $error->getMessage(), 0, $error);
            }
        }

        if ($value[0] === '\'' && substr($value, -1) === '\'') {
            return substr($value, 1, -1);
        }

        $normalized = strtolower($value);
        return match (true) {
            $normalized === 'true', $normalized === 'yes' => true,
            $normalized === 'false', $normalized === 'no' => false,
            $normalized === 'null' => null,
            preg_match('/^-?[0-9]+$/', $value) === 1 => (int) $value,
            preg_match('/^-?(?:[0-9]+\.[0-9]+|[0-9]+[eE][+-]?[0-9]+|[0-9]+\.[0-9]+[eE][+-]?[0-9]+)$/', $value) === 1 => (float) $value,
            default => $value,
        };
    }

    private static function splitTopLevelList(string $rawList, int $lineNumber): array
    {
        $items = [];
        $buffer = '';
        $quote = null;
        $bracketDepth = 0;
        $length = strlen($rawList);

        for ($index = 0; $index < $length; $index++) {
            $char = $rawList[$index];
            $previous = $index > 0 ? $rawList[$index - 1] : null;

            if ($quote !== null) {
                $buffer .= $char;
                if ($char === $quote && $previous !== '\\') {
                    $quote = null;
                }
                continue;
            }

            if ($char === '"' || $char === '\'') {
                $quote = $char;
                $buffer .= $char;
                continue;
            }

            if ($char === '[') {
                $bracketDepth++;
                $buffer .= $char;
                continue;
            }

            if ($char === ']') {
                if ($bracketDepth === 0) {
                    throw new RuntimeException('Invalid TOML config at line ' . $lineNumber . ': unmatched ] in array');
                }

                $bracketDepth--;
                $buffer .= $char;
                continue;
            }

            if ($char === ',' && $bracketDepth === 0) {
                $item = trim($buffer);
                if ($item === '') {
                    throw new RuntimeException('Invalid TOML config at line ' . $lineNumber . ': array items must not be empty');
                }

                $items[] = $item;
                $buffer = '';
                continue;
            }

            $buffer .= $char;
        }

        if ($quote !== null || $bracketDepth !== 0) {
            throw new RuntimeException('Invalid TOML config at line ' . $lineNumber . ': unterminated array value');
        }

        $item = trim($buffer);
        if ($item === '') {
            throw new RuntimeException('Invalid TOML config at line ' . $lineNumber . ': array items must not be empty');
        }

        $items[] = $item;

        return $items;
    }

    private static function ensureSectionPath(array &$config, array $sectionPath): void
    {
        $target =& self::sectionReference($config, $sectionPath);
        if (!is_array($target)) {
            $target = [];
        }
    }

    private static function &sectionReference(array &$config, array $sectionPath): array
    {
        $target =& $config;
        foreach ($sectionPath as $segment) {
            if (!isset($target[$segment]) || !is_array($target[$segment])) {
                $target[$segment] = [];
            }

            $target =& $target[$segment];
        }

        return $target;
    }

    private static function expandStringPlaceholders(mixed $value, array $context): mixed
    {
        if (is_string($value)) {
            return preg_replace_callback(
                '/\$\{([A-Za-z0-9_]+)\}/',
                static fn(array $matches): string => $context[$matches[1]] ?? $matches[0],
                $value,
            );
        }

        if (!is_array($value)) {
            return $value;
        }

        foreach ($value as $key => $nestedValue) {
            $value[$key] = self::expandStringPlaceholders($nestedValue, $context);
        }

        return $value;
    }

    private static function mergeConfigTrees(array $base, array $override): array
    {
        foreach ($override as $key => $overrideValue) {
            if (!array_key_exists($key, $base)) {
                $base[$key] = $overrideValue;
                continue;
            }

            $baseValue = $base[$key];
            if (is_array($baseValue) && is_array($overrideValue) && !array_is_list($baseValue) && !array_is_list($overrideValue)) {
                $base[$key] = self::mergeConfigTrees($baseValue, $overrideValue);
                continue;
            }

            $base[$key] = $overrideValue;
        }

        return $base;
    }

    private static function normalizeConfig(array $config): array
    {
        $httpConfig = $config['http'] ?? [];
        if (!is_array($httpConfig)) {
            throw new RuntimeException('http configuration must be an object');
        }

        if (array_key_exists('default_poll_interval_ms', $httpConfig)) {
            throw new RuntimeException('http.default_poll_interval_ms is no longer supported; use http.idle_exchange_interval_ms');
        }

        $httpConfig['idle_exchange_interval_ms'] = (int) (
            $httpConfig['idle_exchange_interval_ms']
                ?? 1000
        );
        $config['http'] = $httpConfig;

        $hostUrl = self::optionalConfigString($config, 'host_url')
            ?? self::optionalConfigString($httpConfig, 'advertise_url');
        if ($hostUrl !== null) {
            $hostUrl = rtrim($hostUrl, '/');
            if ($hostUrl === '') {
                throw new RuntimeException('host_url must not be empty when configured');
            }

            $config['host_url'] = $hostUrl;
        }

        $maintenanceConfig = $config['maintenance'] ?? $config['worker'] ?? [];
        if (!is_array($maintenanceConfig)) {
            throw new RuntimeException('maintenance configuration must be an object');
        }

        $config['maintenance'] = $maintenanceConfig;
        unset($config['worker']);

        $debugConfig = $config['debug'] ?? [];
        if (!is_array($debugConfig)) {
            throw new RuntimeException('debug configuration must be an object');
        }

        $debugConfig['enabled'] = self::configBoolOrDefault($debugConfig, 'enabled', 'debug.enabled', false);
        $debugConfig['max_rows'] = self::positiveConfigIntOrDefault($debugConfig, 'max_rows', 'debug.max_rows', 20);
        $config['debug'] = $debugConfig;

        // [interfaces] is the PHP peering (one [[Name]] per peer: type =
        // PostInterface, node_url, wake_url), read by initializeNode() and
        // ensureConfiguredPeerSessions(), which pass over an entry that is not
        // an object. A malformed block stops the node here instead of
        // silently leaving it unpeered.
        $interfaces = $config['interfaces'] ?? [];
        if (!is_array($interfaces)) {
            throw new RuntimeException('interfaces configuration must be an object');
        }

        foreach ($interfaces as $interfaceName => $interfaceConfig) {
            if (!is_array($interfaceConfig)) {
                throw new RuntimeException('interfaces.' . $interfaceName . ' must be an object');
            }
        }

        return $config;
    }

    private static function configBoolOrDefault(array $config, string $field, string $label, bool $default): bool
    {
        if (!array_key_exists($field, $config)) {
            return $default;
        }

        $value = $config[$field];
        if (is_bool($value)) {
            return $value;
        }

        if (is_int($value) || is_float($value)) {
            return (int) $value !== 0;
        }

        if (is_string($value)) {
            $normalized = strtolower(trim($value));
            return !in_array($normalized, ['', '0', 'false', 'no', 'off'], true);
        }

        throw new RuntimeException($label . ' must be a boolean-like value');
    }

    private static function optionalConfigString(array $config, string $field): ?string
    {
        if (!array_key_exists($field, $config)) {
            return null;
        }

        $value = $config[$field];
        if ($value === null) {
            return null;
        }

        if (!is_string($value)) {
            throw new RuntimeException($field . ' must be a string');
        }

        $value = trim($value);
        return $value === '' ? null : $value;
    }

    private static function optionalConfigInt(array $config, string $field): ?int
    {
        if (!array_key_exists($field, $config)) {
            return null;
        }

        $value = $config[$field];
        if (!is_int($value) && !is_float($value) && !is_string($value)) {
            throw new RuntimeException($field . ' must be numeric');
        }

        return (int) $value;
    }

    private static function requirePositiveConfigInt(array $config, string $field, string $label): int
    {
        $value = self::optionalConfigInt($config, $field);
        if ($value === null) {
            throw new RuntimeException($label . ' is required');
        }

        if ($value <= 0) {
            throw new RuntimeException($label . ' must be positive');
        }

        return $value;
    }

    private static function positiveConfigIntOrDefault(array $config, string $field, string $label, int $default): int
    {
        if (!array_key_exists($field, $config)) {
            return $default;
        }

        return self::requirePositiveConfigInt($config, $field, $label);
    }

    public static function ensureDirectories(array $config): void
    {
        $paths = [
            dirname((string) ($config['storage']['sqlite_path'] ?? '')),
            dirname((string) ($config['storage']['log_path'] ?? '')),
        ];

        foreach ($paths as $path) {
            if ($path === '' || $path === '.') {
                continue;
            }

            if (!is_dir($path) && !mkdir($path, 0775, true) && !is_dir($path)) {
                throw new RuntimeException('Unable to create directory: ' . $path);
            }
        }
    }
}

final class Environment
{
    public static function verify(): array
    {
        $status = [
            'php_version' => PHP_VERSION,
            'extensions' => [
                'json' => extension_loaded('json'),
                'sqlite3' => extension_loaded('sqlite3'),
                'sodium' => extension_loaded('sodium'),
            ],
            'random_bytes' => function_exists('random_bytes'),
        ];

        if (PHP_VERSION_ID < 80100) {
            throw new RuntimeException('PHP 8.1 or newer is required');
        }

        foreach ($status['extensions'] as $extension => $loaded) {
            if ($loaded !== true) {
                throw new RuntimeException('Required PHP extension missing: ' . $extension);
            }
        }

        if ($status['random_bytes'] !== true) {
            throw new RuntimeException('random_bytes() is required');
        }

        return $status;
    }
}

/**
 * The commit this node runs, as deploy.sh stamped it.
 *
 * Nodes are deployed from `git archive`, so there is no .git to ask. deploy.sh
 * (through write-build-stamp.sh) writes build.json next to index.php from the
 * ref it deploys, and uploads it last, after the code has landed and parsed.
 * A node without a stamp (staging's php -S, a hand copy, a deploy from before
 * 2026-09-30) reports null rather than a guess, and so does a malformed file:
 * nothing but a 40-hex commit and a UTC timestamp is ever echoed.
 */
final class BuildStamp
{
    public const FILE = 'build.json';

    /** @return array{commit: ?string, stamped_at: ?string} */
    public static function read(string $dir): array
    {
        $path = rtrim($dir, '/') . '/' . self::FILE;
        $raw = is_file($path) ? @file_get_contents($path) : false;
        $data = is_string($raw) ? json_decode($raw, true) : null;
        $commit = is_array($data) && is_string($data['commit'] ?? null)
            && preg_match('/^[0-9a-f]{40}$/', $data['commit']) === 1
            ? $data['commit'] : null;
        $stampedAt = $commit !== null && is_string($data['stamped_at'] ?? null)
            && preg_match('/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/', $data['stamped_at']) === 1
            ? $data['stamped_at'] : null;

        return ['commit' => $commit, 'stamped_at' => $stampedAt];
    }
}

final class ApiError extends RuntimeException
{
    public function __construct(
        public readonly int $statusCode,
        string $message,
        public readonly array $payload = []
    ) {
        parent::__construct($message);
    }
}

final class PacketParser
{
    private const HEADER_1 = 0;
    private const HEADER_2 = 1;
    private const DST_LEN = 16;
    private const HEADER_1_LEN = 19;
    private const HEADER_2_LEN = 35;

    public static function parseRaw(string $raw, ?array $ifacConfig = null): array
    {
        [$raw, $ifacFlag] = IfacCodec::unwrapForInterface($raw, $ifacConfig);
        $length = strlen($raw);
        if ($length < self::HEADER_1_LEN) {
            throw new RuntimeException('Packet is shorter than the minimum HEADER_1 length');
        }

        $flags = ord($raw[0]);
        if (($flags & 0x80) === 0x80) {
            throw new RuntimeException('Normalized packet still has IFAC flag set');
        }

        $hops = ord($raw[1]);
        $headerType = ($flags & 0b01000000) >> 6;
        $contextFlag = ($flags & 0b00100000) >> 5;
        $transportType = ($flags & 0b00010000) >> 4;
        $destinationType = ($flags & 0b00001100) >> 2;
        $packetType = ($flags & 0b00000011);

        if ($headerType === self::HEADER_2) {
            if ($length < self::HEADER_2_LEN) {
                throw new RuntimeException('Packet is shorter than the minimum HEADER_2 length');
            }

            $transportId = substr($raw, 2, self::DST_LEN);
            $destinationHash = substr($raw, self::DST_LEN + 2, self::DST_LEN);
            $context = ord($raw[(self::DST_LEN * 2) + 2]);
            $payload = substr($raw, (self::DST_LEN * 2) + 3);
        } else {
            $transportId = null;
            $destinationHash = substr($raw, 2, self::DST_LEN);
            $context = ord($raw[self::DST_LEN + 2]);
            $payload = substr($raw, self::DST_LEN + 3);
        }

        $packetHash = hash('sha256', self::hashablePart($raw, $headerType, $flags), true);

        return [
            'packet_hash_hex' => bin2hex($packetHash),
            'truncated_hash_hex' => bin2hex(substr($packetHash, 0, self::DST_LEN)),
            'packet_size' => $length,
            'ifac_flag' => $ifacFlag ? 1 : 0,
            'header_type' => $headerType,
            'transport_type' => $transportType,
            'destination_type' => $destinationType,
            'packet_type' => $packetType,
            'context_flag' => $contextFlag,
            'hops' => $hops,
            'context' => $context,
            'transport_id_hex' => $transportId === null ? null : bin2hex($transportId),
            'destination_hash_hex' => bin2hex($destinationHash),
            'payload_base64' => base64_encode($payload),
            'normalized_raw_base64' => base64_encode($raw),
        ];
    }

    /**
     * Compute the hashable part of a raw RNS packet for SHA-256 hashing.
     *
     * This MUST match the equivalent in every RNS implementation:
     *
     *   Python (RNS.Packet):
     *     hashable_part = bytes([flags & 0x0F]) + raw[2:]          # HEADER_1
     *     hashable_part = bytes([flags & 0x0F]) + raw[18:]         # HEADER_2
     *
     *   JavaScript (packet.js getHashablePart()):
     *     hashablePart = Buffer.from([raw[0] & 0x0F]);
     *     if (headerType === HEADER_2) {
     *       hashablePart = concat(hashablePart, raw.slice(16 + 2)); // byte 18
     *     } else {
     *       hashablePart = concat(hashablePart, raw.slice(2));
     *     }
     *
     *   HEADER_2 wire layout (35+ bytes):
     *     [0] flags  [1] hops  [2..17] transport_id (16 bytes)  [18..] dest+ctx+payload
     *
     *   HEADER_1 wire layout (19+ bytes):
     *     [0] flags  [1] hops  [2..] dest+ctx+payload
     *
     * REGRESSION GUARD (2026-07-19):
     *   Commit 92a7d48 (July 14) wrongly changed the HEADER_2 branch from
     *   `self::DST_LEN + 2` (=18) to just `2`, causing every HEADER_2
     *   inbound packet to get a wrong truncated_hash_hex. The mismatch
     *   broke proof relay because proofs arriving from the browser (JS)
     *   carry the correct hash and can't find the PHP-stored reverse path.
     *   Reverted in 4db3a7a. DO NOT change these offsets without updating
     *   php/tests/PacketParserHashTest.php and verifying against known-good
     *   JS output.
     *
     * @see php/tests/PacketParserHashTest.php
     * @see Retichat-js lib/rns/packet.js :: getHashablePart()
     * @see DESIGN_PRINCIPLES.md (cross-implementation hash parity)
     */
    private static function hashablePart(string $raw, int $headerType, int $flags): string
    {
        $hashablePart = chr($flags & 0b00001111);

        if ($headerType === self::HEADER_2) {
            // Skip flags(1) + hops(1) + transport_id(16) = 18 bytes
            return $hashablePart . substr($raw, self::DST_LEN + 2);
        }

        // Skip flags(1) + hops(1) = 2 bytes
        return $hashablePart . substr($raw, 2);
    }
}

final class IfacCodec
{
    public static function configFromMetadata(array $metadata): ?array
    {
        $ifacKeyHex = $metadata['ifac_key_hex'] ?? null;
        $ifacSize = $metadata['ifac_size'] ?? null;

        if ($ifacKeyHex === null && $ifacSize === null) {
            return null;
        }

        if (!is_string($ifacKeyHex) || trim($ifacKeyHex) === '') {
            throw new RuntimeException('IFAC metadata requires ifac_key_hex');
        }

        if (!is_int($ifacSize) && !is_string($ifacSize) && !is_float($ifacSize)) {
            throw new RuntimeException('IFAC metadata requires numeric ifac_size');
        }

        $ifacSize = (int) $ifacSize;
        if ($ifacSize < 1 || $ifacSize > SODIUM_CRYPTO_SIGN_BYTES) {
            throw new RuntimeException('IFAC metadata ifac_size must be between 1 and 64 bytes');
        }

        $ifacKeyHex = strtolower(trim($ifacKeyHex));
        if (!ctype_xdigit($ifacKeyHex) || strlen($ifacKeyHex) !== 128) {
            throw new RuntimeException('IFAC metadata ifac_key_hex must be 64 bytes of hex');
        }

        $ifacKey = hex2bin($ifacKeyHex);
        if (!is_string($ifacKey) || strlen($ifacKey) !== 64) {
            throw new RuntimeException('IFAC metadata ifac_key_hex is invalid');
        }

        return [
            'size' => $ifacSize,
            'key' => $ifacKey,
        ];
    }

    public static function packetSizeLimit(int $plainLimit, ?array $ifacConfig): int
    {
        if ($ifacConfig === null) {
            return $plainLimit;
        }

        return $plainLimit + (int) $ifacConfig['size'];
    }

    public static function unwrapForInterface(string $raw, ?array $ifacConfig): array
    {
        if (strlen($raw) <= 2) {
            return [$raw, false];
        }

        $hasIfacFlag = (ord($raw[0]) & 0x80) === 0x80;
        if ($ifacConfig === null) {
            if ($hasIfacFlag) {
                throw new RuntimeException('IFAC-wrapped packet received on interface without IFAC metadata');
            }

            return [$raw, false];
        }

        $ifacSize = (int) $ifacConfig['size'];
        $ifacKey = (string) $ifacConfig['key'];
        if (!$hasIfacFlag) {
            throw new RuntimeException('IFAC-enabled interface received packet without IFAC flag');
        }

        if (strlen($raw) <= 2 + $ifacSize) {
            throw new RuntimeException('IFAC-wrapped packet is shorter than IFAC header size');
        }

        $ifac = substr($raw, 2, $ifacSize);
        $mask = self::hkdf($ifac, $ifacKey, strlen($raw));
        $unmaskedRaw = '';
        $length = strlen($raw);
        for ($index = 0; $index < $length; $index++) {
            $byte = ord($raw[$index]);
            if ($index <= 1 || $index > $ifacSize + 1) {
                $unmaskedRaw .= chr($byte ^ ord($mask[$index]));
            } else {
                $unmaskedRaw .= $raw[$index];
            }
        }

        $normalizedRaw = chr(ord($unmaskedRaw[0]) & 0x7F) . $unmaskedRaw[1] . substr($unmaskedRaw, 2 + $ifacSize);
        $expectedIfac = substr(self::signature($normalizedRaw, $ifacKey), -$ifacSize);
        if (!hash_equals($ifac, $expectedIfac)) {
            throw new RuntimeException('IFAC authentication failed');
        }

        return [$normalizedRaw, true];
    }

    public static function wrapForInterface(string $raw, ?array $ifacConfig): string
    {
        if ($ifacConfig === null) {
            return $raw;
        }

        if (strlen($raw) < 2) {
            throw new RuntimeException('Packet is too short to apply IFAC');
        }

        $ifacSize = (int) $ifacConfig['size'];
        $ifacKey = (string) $ifacConfig['key'];
        $ifac = substr(self::signature($raw, $ifacKey), -$ifacSize);
        $mask = self::hkdf($ifac, $ifacKey, strlen($raw) + $ifacSize);
        $newHeader = chr((ord($raw[0]) | 0x80) & 0xFF) . $raw[1];
        $newRaw = $newHeader . $ifac . substr($raw, 2);

        $maskedRaw = '';
        $length = strlen($newRaw);
        for ($index = 0; $index < $length; $index++) {
            $byte = ord($newRaw[$index]);
            if ($index === 0) {
                $maskedRaw .= chr((($byte ^ ord($mask[$index])) | 0x80) & 0xFF);
            } elseif ($index === 1 || $index > $ifacSize + 1) {
                $maskedRaw .= chr($byte ^ ord($mask[$index]));
            } else {
                $maskedRaw .= $newRaw[$index];
            }
        }

        return $maskedRaw;
    }

    private static function hkdf(string $ifac, string $ifacKey, int $length): string
    {
        return hash_hkdf('sha256', $ifac, $length, '', $ifacKey);
    }

    private static function signature(string $raw, string $ifacKey): string
    {
        $ed25519Seed = substr($ifacKey, 32, 32);
        $keypair = sodium_crypto_sign_seed_keypair($ed25519Seed);
        $secretKey = sodium_crypto_sign_secretkey($keypair);

        return sodium_crypto_sign_detached($raw, $secretKey);
    }
}

final class AnnounceValidator
{
    /** Clock-skew allowance for an announce's self-reported emission time. */
    private const ANNOUNCE_EMITTED_SKEW_SECONDS = 86_400;

    private const KEY_SIZE = 64;
    private const NAME_HASH_LEN = 10;
    private const RANDOM_HASH_LEN = 10;
    private const RATCHET_SIZE = 32;
    private const SIGNATURE_LEN = 64;

    public static function validate(array $packet, ?string $knownPublicKeyHex): array
    {
        if ((int) ($packet['packet_type'] ?? -1) !== 1) {
            throw new RuntimeException('Packet is not an ANNOUNCE');
        }

        if ((int) ($packet['destination_type'] ?? -1) !== 0) {
            throw new RuntimeException('ANNOUNCE packet must target a SINGLE destination');
        }

        $payload = base64_decode((string) ($packet['payload_base64'] ?? ''), true);
        if (!is_string($payload)) {
            throw new RuntimeException('ANNOUNCE payload is not valid base64');
        }

        $contextFlag = (int) ($packet['context_flag'] ?? 0);
        $minimumLength = self::KEY_SIZE + self::NAME_HASH_LEN + self::RANDOM_HASH_LEN + self::SIGNATURE_LEN;
        if ($contextFlag === 1) {
            $minimumLength += self::RATCHET_SIZE;
        }

        if (strlen($payload) < $minimumLength) {
            throw new RuntimeException('ANNOUNCE payload is shorter than the minimum valid length');
        }

        $offset = 0;
        $publicKey = substr($payload, $offset, self::KEY_SIZE);
        $offset += self::KEY_SIZE;

        $nameHash = substr($payload, $offset, self::NAME_HASH_LEN);
        $offset += self::NAME_HASH_LEN;

        $randomHash = substr($payload, $offset, self::RANDOM_HASH_LEN);
        $offset += self::RANDOM_HASH_LEN;

        $ratchet = '';
        if ($contextFlag === 1) {
            $ratchet = substr($payload, $offset, self::RATCHET_SIZE);
            $offset += self::RATCHET_SIZE;
        }

        $signature = substr($payload, $offset, self::SIGNATURE_LEN);
        $offset += self::SIGNATURE_LEN;
        $appData = substr($payload, $offset);

        $destinationHash = hex2bin((string) $packet['destination_hash_hex']);
        if (!is_string($destinationHash) || strlen($destinationHash) !== 16) {
            throw new RuntimeException('ANNOUNCE destination hash is invalid');
        }

        $identityHash = substr(hash('sha256', $publicKey, true), 0, 16);
        $expectedHash = substr(hash('sha256', $nameHash . $identityHash, true), 0, 16);
        if (!hash_equals($destinationHash, $expectedHash)) {
            throw new RuntimeException('ANNOUNCE destination hash does not match signed identity');
        }

        if ($knownPublicKeyHex !== null && !hash_equals($knownPublicKeyHex, bin2hex($publicKey))) {
            throw new RuntimeException('ANNOUNCE public key conflicts with previously known destination key');
        }

        $ed25519PublicKey = substr($publicKey, 32, 32);
        $signedData = $destinationHash . $publicKey . $nameHash . $randomHash . $ratchet . $appData;
        if (!sodium_crypto_sign_verify_detached($signature, $signedData, $ed25519PublicKey)) {
            throw new RuntimeException('ANNOUNCE signature verification failed');
        }

        return [
            'public_key_hex' => bin2hex($publicKey),
            'identity_hash_hex' => bin2hex($identityHash),
            'name_hash_hex' => bin2hex($nameHash),
            'random_hash_hex' => bin2hex($randomHash),
            'announce_emitted' => self::announceEmitted($randomHash),
            'ratchet_hex' => $ratchet === '' ? null : bin2hex($ratchet),
            'app_data_base64' => $appData === '' ? null : base64_encode($appData),
        ];
    }

    private static function announceEmitted(string $randomHash): int
    {
        $timestampBytes = substr($randomHash, 5, 5);
        $emitted = unpack('J', "\x00\x00\x00" . $timestampBytes)[1];

        // The emission time is attacker- and bug-controlled input from the
        // network. It is only ever used to decide whether an announce is
        // fresher than what we already hold, so a value in the future would
        // pin the comparison baseline forever and make the destination
        // permanently unrefreshable. Treat anything beyond a small clock-skew
        // allowance as unusable rather than authoritative.
        $ceiling = time() + self::ANNOUNCE_EMITTED_SKEW_SECONDS;

        return $emitted > $ceiling ? 0 : $emitted;
    }
}

final class TransportConstants
{
    public const APP_NAME = 'rnstransport';
    public const PATH_REQUEST_ASPECT_1 = 'path';
    public const PATH_REQUEST_ASPECT_2 = 'request';
    public const DEFAULT_PER_HOP_TIMEOUT_SECONDS = 6;

    // Transport.py:81 — minimum interval between automated path requests.
    public const PATH_REQUEST_MI = 20;

    // Transport.py:78 — how long a discovery path request stays pending, i.e.
    // how long Transport.discovery_path_requests suppresses a repeat search.
    public const PATH_REQUEST_TIMEOUT = 15;
}

final class Storage
{
    use RequestControlPlaneTrait;
    use RequestDebugReportTrait;
    use RequestInterfaceRegistryTrait;
    use RequestInboundBatchTrait;
    use RequestInterfaceRuntimeTrait;
    use RequestJsonCodecTrait;
    use RequestLxmfHandoffTrait;
    use RequestMaintenanceTrait;
    use RequestOutboundBatchTrait;
    use RequestPacketIngestTrait;
    use RequestPathStateTrait;
    use RequestRelayRoutingTrait;
    use RequestSchemaTrait;
    use RequestStorageBudgetTrait;
    use RequestPhpWakeTrait;

    private PDO $db;
    private string $backend;

    public function __construct(private readonly array $config)
    {
        $this->backend = Database::backend($config);
        $this->db = Database::connect($config);
    }

}

final class HttpApi
{
    use RequestHttpApiHelperTrait;

    public function __construct(
        private readonly array $config,
        private readonly Storage $storage,
        private readonly string $buildStampDir = __DIR__
    ) {
    }

    /**
     * GET /health is public. Every key is named here; the interface rows are
     * nodes and gateways only (browsers are counted, not listed) and go
     * through Storage::publicInterfaceView(), an allowlist. 'build' is the
     * commit deploy.sh installed and verified (verify-live-stamp.sh compares
     * it with a ref, no credentials needed). Pinned by
     * tests/health_allowlist_test.php.
     */
    private function healthBody(): array
    {
        return [
            'status' => 'ok',
            'transport_basis' => requestTransportMechanism(),
            'environment' => Environment::verify(),
            'build' => BuildStamp::read($this->buildStampDir),
            'queues' => $this->storage->healthSummary(),
            'php_interface_registry' => $this->storage->healthInterfaceRegistry(5),
        ];
    }

    /**
     * Routes that only an operator should reach: the monitor page, its JSON,
     * its clear-all button and the forced maintenance flush. None of them
     * authenticates. Until 2026-09-30 they answered on every node: anyone
     * could POST /v1/monitor/clear {"confirm":"YES"} and delete every table
     * (the transport identity and every peer session included), or POST
     * /v1/maintenance/flush {"force":true} and drop every browser session.
     * They now answer only where config debug.enabled is true, the gate
     * /debug always had. Pinned by tests/operator_routes_gated_test.php.
     */
    private const OPERATOR_PATHS = ['/v1/monitor', '/v1/monitor/data', '/v1/monitor/json', '/v1/monitor/clear', '/v1/maintenance/flush'];

    private function debugRoutesEnabled(): bool
    {
        return ($this->config['debug']['enabled'] ?? false) === true;
    }

    public function handle(string $method, string $uri, array $server): never
    {
        try {
            $path = $this->normalizedPath($uri, $server);

            // Handle CORS preflight
            if ($method === 'OPTIONS') {
                $this->respond(204, []);
            }

            if ($method === 'GET' && $path === '/v1/initialize') {
                $t0 = microtime(true);
                $summary = $this->storage->initializeNode();

                // Clear opcache so the new code is picked up.
                if (function_exists('opcache_reset')) {
                    opcache_reset();
                }

                $elapsed = round((microtime(true) - $t0) * 1000);
                $this->log('debug', "[perf] initialize total={$elapsed}ms");

                $this->respond(200, $summary);
            }

            // The operator console and its buttons have no authentication, so
            // they answer only where debug.enabled is set, like /debug.
            if (in_array($path, self::OPERATOR_PATHS, true) && !$this->debugRoutesEnabled()) {
                throw new ApiError(404, 'Not found', ['error' => 'not found']);
            }

            if ($method === 'GET' && $path === '/v1/monitor') {
                $this->renderMonitorPage();
            }

            if ($method === 'GET' && ($path === '/v1/monitor/data' || $path === '/v1/monitor/json')) {
                $this->respond(200, $this->storage->monitorData());
            }

            if ($method === 'POST' && $path === '/v1/monitor/clear') {
                $body = $this->readJsonBody();
                if (($body['confirm'] ?? '') !== 'YES') {
                    $this->respond(400, ['status' => 'error', 'error' => 'Type YES to confirm']);
                }
                $this->storage->clearAllData();
                $this->respond(200, ['status' => 'ok']);
            }

            if ($method === 'POST' && $path === '/v1/maintenance/flush') {
                $body = $this->readJsonBody();
                $force = !empty($body['force']);

                if ($force) {
                    // Force: mark ALL non-peer interfaces as stale immediately
                    $interfaceStaleSeconds = 0;
                } else {
                    $interfaceStaleSeconds = $this->maintenanceInt('interface_stale_after_seconds', 15);
                }

                $results = $this->storage->runMaintenance(
                    $interfaceStaleSeconds,
                    $this->maintenanceInt('batch_ttl_seconds', 86400),
                );
                if ($force) {
                    // Every client is stale now; its next poll must say so.
                    EmptyPoll::clearAll($this->config);
                }
                $this->respond(200, ['status' => 'ok', 'force' => $force, 'flushed' => $results]);
            }

            if ($method === 'GET' && $path === '/health') {
                $this->respond(200, $this->healthBody());
            }

            if ($method === 'GET' && $path === '/debug') {
                if (!$this->debugRoutesEnabled()) {
                    throw new ApiError(404, 'Not found', ['error' => 'not found']);
                }

                $maxRows = (int) ($this->config['debug']['max_rows'] ?? 20);
                $this->respond(200, [
                    'status' => 'ok',
                    'transport_basis' => requestTransportMechanism(),
                    'environment' => Environment::verify(),
                    'queues' => $this->storage->healthSummary(),
                    'debug' => [
                        'enabled' => true,
                        'max_rows' => $maxRows,
                        'report' => $this->storage->debugReport($maxRows),
                    ],
                ]);
            }

            if ($method === 'POST' && $path === '/v1/interfaces/register') {
                $body = $this->readJsonBody();
                $name = $this->requireNonEmptyString($body, 'name');
                $bitrate = $this->requirePositiveInt($body, 'bitrate');
                $mtu = $this->requirePositiveInt($body, 'mtu');
                $metadata = $this->optionalArray($body, 'metadata');
                $isPhpPeer = ($metadata['client'] ?? null) === 'reticulum-php';

                if (!$isPhpPeer) {
                    try {
                        $maxPacketBytes = $this->storage->maxPacketBytesForMetadata($metadata);
                    } catch (RuntimeException $error) {
                        throw new ApiError(400, $error->getMessage(), ['error' => $error->getMessage()]);
                    }
                } else {
                    $maxPacketBytes = $this->storage->maxPacketBytesForMetadata($metadata);
                }

                $registration = $this->storage->registerInterface($name, $bitrate, $mtu, $metadata);
                // A re-registration can give an existing interface a new token.
                EmptyPoll::clear($this->config, (string) $registration['interface_id']);
                $response = [
                    'status' => 'registered',
                    'interface_id' => $registration['interface_id'],
                    'session_token' => $registration['session_token'],
                    'idle_exchange_interval_ms' => $this->idleExchangeIntervalMs(),
                    'max_batch_packets' => (int) $this->config['http']['max_batch_packets'],
                    'max_packet_bytes' => $maxPacketBytes,
                ];

                if (isset($registration['peer_interface_id'])) {
                    $response['peer_interface_id'] = $registration['peer_interface_id'];
                }
                if (isset($registration['peer_session_token'])) {
                    $response['peer_session_token'] = $registration['peer_session_token'];
                }

                $this->respond(200, $response);
            }

            if ($method === 'POST' && $path === '/v1/interfaces/goodbye') {
                // A page going away (pagehide beacon). Authenticate like an
                // exchange, then release the registration immediately instead
                // of holding it until the stale sweep.
                $body = $this->readJsonBody();
                [$interfaceId, $sessionToken] = $this->requireInterfaceCredentials($body);
                $this->storage->authenticateInterface($interfaceId, $sessionToken);
                $dropped = $this->storage->goodbyeInterface($interfaceId);
                // A page restored after its goodbye must take the full path,
                // which marks it online again.
                EmptyPoll::clear($this->config, $interfaceId);
                $this->respond(200, ['status' => 'offline', 'interface_id' => $interfaceId, 'dropped' => $dropped]);
            }

            if ($method === 'POST' && ($path === '/v1/interfaces/exchange' || $path === '/v1/interfaces/tx')) {
                $t0 = microtime(true);
                $body = $this->readJsonBody();
                [$interfaceId, $sessionToken] = $this->requireInterfaceCredentials($body);
                $this->storage->authenticateInterface($interfaceId, $sessionToken);

                $this->runInterfaceRequestPrelude();
                $t1 = microtime(true);
                $this->storage->seedInterfaceIfNew($interfaceId);
                $ackBatchIds = $this->optionalStringArray($body, 'ack_batch_ids');
                $requestedMaxPackets = $body['max_packets'] ?? (int) $this->config['http']['max_batch_packets'];
                $maxPackets = min($this->requirePositiveIntValue($requestedMaxPackets, 'max_packets'), (int) $this->config['http']['max_batch_packets']);
                $packets = $this->requirePacketArray($body, 'packets', $interfaceId);
                $batchId = $packets === []
                    ? $this->optionalNonEmptyString($body, 'batch_id')
                    : $this->requireNonEmptyString($body, 'batch_id');
                $acked = $this->storage->acknowledgeOutboundBatches($interfaceId, $ackBatchIds);
                $t2 = microtime(true);
                $processing = null;
                $processedInline = false;
                $tx = [
                    'duplicate_batch' => false,
                    'accepted_packets' => 0,
                    'accepted_bytes' => 0,
                ];

                if ($packets !== []) {
                    $tx = $this->storage->ingestInboundBatchInline($interfaceId, (string) $batchId, $packets);
                    $processing = $tx['processing'];
                    $processedInline = $tx['duplicate_batch'] !== true;
                }
                $t3 = microtime(true);

                $delivery = $this->storage->fetchOutboundBatch($interfaceId, $maxPackets);
                $t4 = microtime(true);
                $this->runInterfaceRequestEpilogue();
                $t5 = microtime(true);
                $this->markIdleIfNothingQueued($interfaceId, $sessionToken);


                $this->respond(200, [
                    'status' => 'accepted',
                    'batch_id' => $batchId,
                    'duplicate_batch' => $tx['duplicate_batch'],
                    'accepted_packets' => $tx['accepted_packets'],
                    'accepted_bytes' => $tx['accepted_bytes'],
                    'processed_inline' => $processedInline,
                    'processing' => $processing,
                    'acked_batches' => $acked,
                    'delivery_batch_id' => $delivery['batch_id'],
                    'delivery_packets' => $delivery['packets'],
                    'delivery_more' => $delivery['more'],
                    'idle_exchange_interval_ms' => $this->idleExchangeIntervalMs(),
                ]);
            }

            if ($method === 'POST' && $path === '/v1/wake') {
                $body = $this->readJsonBody();
                $wakerUrl = $this->optionalNonEmptyString($body, 'waker_url');
                if ($wakerUrl === null) {
                    throw new ApiError(400, 'wake requires waker_url', ['error' => 'wake requires waker_url']);
                }

                // Maintenance rides the request path, and a node whose only
                // traffic is wakes has no other request to ride. Until 2026-08-30
                // the prelude hung off /v1/interfaces/exchange, /tx and /poll
                // only, so selectivesubconscious.com — which serves wakes and
                // nothing else — ran no maintenance for 12.8 days while this
                // handler kept ingesting packets and appending to error_log. It
                // finished with 1,026 MB of freed-but-unreclaimed InnoDB pages
                // against a 1 GB account quota, and a 93 MB error_log, while its
                // own budget reported a healthy 135 MB. Wakes are the pulse of a
                // peer-only node; give them the same 2-second-rate-limited pass
                // every other packet-carrying endpoint gets.
                $this->runInterfaceRequestPrelude();

                // The wake caller has already dropped the connection.
                // We call the peer's exchange endpoint inline to pull any pending packets.
                try { $result = $this->storage->exchangeWithPhpPeer($wakerUrl); } catch (\Throwable $e) { $result = ["status" => "exchange_error", "message" => $e->getMessage(), "file" => $e->getFile(), "line" => $e->getLine()]; }

                $this->respond(200, [
                    'status' => 'ok',
                    'waker_url' => $wakerUrl,
                    'exchange' => $result,
                ]);
            }

            if ($method === 'POST' && $path === '/v1/interfaces/poll') {
                $body = $this->readJsonBody();
                [$interfaceId, $sessionToken] = $this->requireInterfaceCredentials($body);
                $this->storage->authenticateInterface($interfaceId, $sessionToken);
                $this->runInterfaceRequestPrelude();
                $ackBatchIds = $this->optionalStringArray($body, 'ack_batch_ids');
                $requestedMaxPackets = $body['max_packets'] ?? (int) $this->config['http']['max_batch_packets'];
                $maxPackets = min($this->requirePositiveIntValue($requestedMaxPackets, 'max_packets'), (int) $this->config['http']['max_batch_packets']);
                $acked = $this->storage->acknowledgeOutboundBatches($interfaceId, $ackBatchIds);
                $batch = $this->storage->fetchOutboundBatch($interfaceId, $maxPackets);
                $this->runInterfaceRequestEpilogue();
                $this->markIdleIfNothingQueued($interfaceId, $sessionToken);

                $this->respond(200, [
                    'status' => 'ok',
                    'idle_exchange_interval_ms' => $this->idleExchangeIntervalMs(),
                    'acked_batches' => $acked,
                    'batch_id' => $batch['batch_id'],
                    'packets' => $batch['packets'],
                    'more' => $batch['more'],
                ]);
            }

            throw new ApiError(404, 'Not found', ['error' => 'not found']);
        } catch (ApiError $error) {
            $payload = $error->payload;
            if ($payload === []) {
                $payload = ['error' => $error->getMessage()];
            }
            $this->respond($error->statusCode, $payload);
        } catch (\Throwable $error) {
            $this->log('error', 'Unhandled HTTP exception: ' . $error->getMessage());
            $this->respond(500, ['error' => 'internal error']);
        }
    }
}

function loadRuntimeConfig(string $projectRoot): array
{
    $reticulumPhpConfig = Config::load($projectRoot);

    // Enforce PHP memory limit from config (shared-hosting safety).
    $phpMemoryLimit = (string) ($reticulumPhpConfig['php']['memory_limit'] ?? '128M');
    if ($phpMemoryLimit !== '' && ini_set('memory_limit', $phpMemoryLimit) === false) {
        error_log('Reticulum-php: unable to set memory_limit=' . $phpMemoryLimit);
    }

    return $reticulumPhpConfig;
}

/** @return array{0: array, 1: Storage} */
function initializeRuntime(string $projectRoot, ?array $reticulumPhpConfig = null): array
{
    $reticulumPhpConfig ??= loadRuntimeConfig($projectRoot);

    Config::ensureDirectories($reticulumPhpConfig);
    Environment::verify();

    $reticulumPhpStorage = new Storage($reticulumPhpConfig);
    $reticulumPhpStorage->migrateIfNeeded();

    return [$reticulumPhpConfig, $reticulumPhpStorage];
}

function runIndexCli(string $projectRoot, array $argv): int
{
    [$reticulumPhpConfig, $reticulumPhpStorage] = initializeRuntime($projectRoot);
    $mode = $argv[1] ?? 'once';
    $maintenanceConfig = $reticulumPhpConfig['maintenance'] ?? $reticulumPhpConfig['worker'] ?? [];

    if ($mode === 'once') {
        // The CLI is the only caller allowed to rebuild tables. Deleting rows
        // hands InnoDB's pages back to the tablespace free list, not to the
        // filesystem, so without a rebuild here the account quota never falls
        // no matter how much history is pruned.
        //
        // Run this MANUALLY (`php index.php once`) when the quota needs
        // reclaiming — not from cron. This deployment deliberately has no
        // scheduler: every routine bound rides request traffic (the 2-second
        // prelude), and a cron entry is a second operational surface that can
        // be absent, misconfigured, or silently dead. The one case request
        // traffic cannot cover is a *decommissioned* node still holding data
        // (no requests → no maintenance), and that is a deliberate manual
        // decision anyway.
        $maintenance = $reticulumPhpStorage->runMaintenance(
            (int) ($maintenanceConfig['interface_stale_after_seconds'] ?? 15),
            (int) ($maintenanceConfig['batch_ttl_seconds'] ?? 86400),
            true,
        );

        $summary = [
            'status' => 'ok',
            'transport_basis' => requestTransportMechanism(),
            'maintenance' => $maintenance,
            'queues' => $reticulumPhpStorage->healthSummary(),
        ];

        fwrite(STDOUT, json_encode($summary, JSON_PRETTY_PRINT | JSON_THROW_ON_ERROR) . PHP_EOL);
        return 0;
    }

    if ($mode === 'reclaim') {
        // Spawned detached by the storage budget when freed pages need to be
        // returned to the filesystem. Rebuilding a table outlives a request, so
        // it happens here — but it is still triggered by the node's own
        // operation, not by a scheduler.
        $result = $reticulumPhpStorage->reclaimStorage();
        fwrite(STDOUT, json_encode($result, JSON_PRETTY_PRINT | JSON_THROW_ON_ERROR) . PHP_EOL);
        return 0;
    }

    fwrite(STDERR, "Unsupported index mode: {$mode}\n");
    return 1;
}

function runIndexHttp(string $projectRoot): never
{
    $method = $_SERVER['REQUEST_METHOD'] ?? 'GET';
    $uri = $_SERVER['REQUEST_URI'] ?? '/';
    $reticulumPhpConfig = loadRuntimeConfig($projectRoot);
    // An idle client's empty poll is answered here, before the database is
    // opened; anything else returns and takes the full path.
    EmptyPoll::answer($reticulumPhpConfig, $method, $uri, $_SERVER);

    [$reticulumPhpConfig, $reticulumPhpStorage] = initializeRuntime($projectRoot, $reticulumPhpConfig);
    $api = new HttpApi($reticulumPhpConfig, $reticulumPhpStorage);
    $api->handle($method, $uri, $_SERVER);
}

if (realpath($_SERVER['SCRIPT_FILENAME'] ?? '') === __FILE__) {
    $projectRoot = resolveRuntimeProjectRoot(__DIR__);

    try {
        if (PHP_SAPI === 'cli') {
            exit(runIndexCli($projectRoot, $argv));
        }

        runIndexHttp($projectRoot);
    } catch (\Throwable $error) {
        if (PHP_SAPI === 'cli') {
            fwrite(STDERR, $error->getMessage() . PHP_EOL);
            exit(1);
        }

        http_response_code(500);
        header('Content-Type: application/json');
        header('Access-Control-Allow-Origin: *');
        header('Access-Control-Allow-Methods: GET, POST, OPTIONS');
        header('Access-Control-Allow-Headers: Content-Type, X-Interface-Id, X-Session-Token');
        echo json_encode(['error' => 'internal error'], JSON_THROW_ON_ERROR);
        exit;
    }
}
