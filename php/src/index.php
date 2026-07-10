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
require_once __DIR__ . '/lib/request_wake_dispatch_trait.php';
require_once __DIR__ . '/lib/request_php_wake_trait.php';

// Reticulum-php is request-operated. Queued transport bytes only move during
// authenticated request/response exchanges. Wake and bridge helpers exist to
// prompt or sustain the next request, not to create a second transport path.

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

        return self::normalizeConfig($projectRoot, $config);
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
                'interface_stale_after_seconds' => 15,
                'batch_ttl_seconds' => 86400,
                'packet_hash_ttl_seconds' => 86400,
                'path_request_tag_ttl_seconds' => 86400,
                'reverse_path_ttl_seconds' => 480,
                'link_transport_ttl_seconds' => 900,
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

    private static function normalizeConfig(string $projectRoot, array $config): array
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

        $wakeConfig = $config['wake'] ?? [];
        if (!is_array($wakeConfig)) {
            throw new RuntimeException('wake configuration must be an object');
        }

        $wakeProfiles = $wakeConfig['profiles'] ?? [];
        if (!is_array($wakeProfiles)) {
            throw new RuntimeException('wake.profiles configuration must be an object');
        }

        $wakeConfig['profiles'] = $wakeProfiles;
        $config['wake'] = $wakeConfig;

        $config = self::normalizeTcpBridgeConfig($projectRoot, $config);
        return $config;
    }

    private static function normalizeTcpBridgeConfig(string $projectRoot, array $config): array
    {
        $interfaces = $config['interfaces'] ?? [];
        if (!is_array($interfaces)) {
            throw new RuntimeException('interfaces configuration must be an object');
        }

        $enabledBridgeInterfaces = [];
        foreach ($interfaces as $interfaceName => $interfaceConfig) {
            if (!is_array($interfaceConfig)) {
                throw new RuntimeException('interfaces.' . $interfaceName . ' must be an object');
            }

            $type = self::optionalConfigString($interfaceConfig, 'type');
            if ($type !== 'TcpBridgeInterface') {
                continue;
            }

            if (!self::interfaceEnabled($interfaceConfig)) {
                continue;
            }

            $enabledBridgeInterfaces[(string) $interfaceName] = $interfaceConfig;
        }

        if ($enabledBridgeInterfaces !== [] && isset($config['tcp_bridge']) && is_array($config['tcp_bridge'])) {
            throw new RuntimeException('Configure the TCP bridge either as tcp_bridge or as an enabled interfaces.* TcpBridgeInterface, not both');
        }

        if (count($enabledBridgeInterfaces) > 1) {
            throw new RuntimeException('Exactly one enabled TcpBridgeInterface is currently supported');
        }

        if ($enabledBridgeInterfaces !== []) {
            $bridgeName = (string) array_key_first($enabledBridgeInterfaces);
            $config['tcp_bridge'] = self::synthesizeTcpBridgeConfig($projectRoot, $bridgeName, $enabledBridgeInterfaces[$bridgeName], $config);
        }

        $legacyBridge = $config['tcp_bridge'] ?? null;
        if (!is_array($legacyBridge)) {
            return $config;
        }

        $bridgeName = self::optionalConfigString($legacyBridge, 'name') ?? 'shared-hosting-tcp-bridge';
        $bridgeSlug = self::slugify($bridgeName);
        $statePath = self::optionalConfigString($legacyBridge, 'control_state_path')
            ?? $projectRoot . '/var/tcp-bridge-' . $bridgeSlug . '.state.json';
        $wakeProfile = self::optionalConfigString($legacyBridge, 'wake_profile')
            ?? '__tcp_bridge_local__' . $bridgeSlug;

        $legacyBridge['name'] = $bridgeName;
        $legacyBridge['control_listen_host'] = self::optionalConfigString($legacyBridge, 'control_listen_host') ?? '127.0.0.1';
        $legacyBridge['control_listen_port'] = self::optionalConfigInt($legacyBridge, 'control_listen_port') ?? 0;
        $legacyBridge['control_state_path'] = $statePath;
        $legacyBridge['wake_profile'] = $wakeProfile;
        $legacyBridge['wake_target'] = self::optionalConfigString($legacyBridge, 'wake_target') ?? $bridgeName;
        $config['tcp_bridge'] = $legacyBridge;

        if (isset($config['wake']['profiles'][$wakeProfile])) {
            return $config;
        }

        $config['wake']['profiles'][$wakeProfile] = [
            'type' => 'command',
            'command' => [
                PHP_BINARY !== '' ? PHP_BINARY : 'php',
                resolveRuntimeScriptPath($projectRoot, 'tcp_bridge.php'),
                'wake',
                $statePath,
            ],
        ];

        return $config;
    }

    private static function synthesizeTcpBridgeConfig(string $projectRoot, string $bridgeName, array $interfaceConfig, array $config): array
    {
        $bridgeSlug = self::slugify($bridgeName);
        $baseUrl = rtrim(
            self::requireConfigString($interfaceConfig, 'base_url', 'interfaces.' . $bridgeName . '.base_url'),
            '/'
        );
        if ($baseUrl === '') {
            throw new RuntimeException('interfaces.' . $bridgeName . '.base_url must not be empty');
        }

        return [
            'name' => $bridgeName,
            'base_url' => $baseUrl,
            'target_host' => self::requireConfigString($interfaceConfig, 'target_host', 'interfaces.' . $bridgeName . '.target_host'),
            'target_port' => self::requirePositiveConfigInt($interfaceConfig, 'target_port', 'interfaces.' . $bridgeName . '.target_port'),
            'bitrate' => self::positiveConfigIntOrDefault($interfaceConfig, 'bitrate', 'interfaces.' . $bridgeName . '.bitrate', 62500),
            'mtu' => self::positiveConfigIntOrDefault($interfaceConfig, 'mtu', 'interfaces.' . $bridgeName . '.mtu', 500),
            'max_batch_packets' => self::positiveConfigIntOrDefault(
                $interfaceConfig,
                'max_batch_packets',
                'interfaces.' . $bridgeName . '.max_batch_packets',
                (int) ($config['http']['max_batch_packets'] ?? 64),
            ),
            'http_timeout_seconds' => self::positiveConfigIntOrDefault($interfaceConfig, 'http_timeout_seconds', 'interfaces.' . $bridgeName . '.http_timeout_seconds', 5),
            'connect_timeout_seconds' => self::positiveConfigIntOrDefault($interfaceConfig, 'connect_timeout_seconds', 'interfaces.' . $bridgeName . '.connect_timeout_seconds', 5),
            'read_chunk_bytes' => self::positiveConfigIntOrDefault($interfaceConfig, 'read_chunk_bytes', 'interfaces.' . $bridgeName . '.read_chunk_bytes', 4096),
            'control_listen_host' => '127.0.0.1',
            'control_listen_port' => 0,
            'control_state_path' => $projectRoot . '/var/tcp-bridge-' . $bridgeSlug . '.state.json',
            'wake_profile' => '__tcp_bridge_local__' . $bridgeSlug,
            'wake_target' => $bridgeName,
        ];
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

    private static function interfaceEnabled(array $config): bool
    {
        return self::configBoolOrDefault($config, 'enabled', 'interfaces.enabled', true);
    }

    private static function requireConfigString(array $config, string $field, string $label): string
    {
        $value = self::optionalConfigString($config, $field);
        if ($value === null) {
            throw new RuntimeException($label . ' is required');
        }

        return $value;
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

    private static function slugify(string $value): string
    {
        $slug = strtolower(trim(preg_replace('/[^A-Za-z0-9]+/', '-', $value) ?? ''));
        $slug = trim($slug, '-');
        return $slug === '' ? 'bridge' : $slug;
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

    private static function hashablePart(string $raw, int $headerType, int $flags): string
    {
        $hashablePart = chr($flags & 0b00001111);

        if ($headerType === self::HEADER_2) {
            return $hashablePart . substr($raw, self::DST_LEN + 2);
        }

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
        return unpack('J', "\x00\x00\x00" . $timestampBytes)[1];
    }
}

final class TransportConstants
{
    public const APP_NAME = 'rnstransport';
    public const PATH_REQUEST_ASPECT_1 = 'path';
    public const PATH_REQUEST_ASPECT_2 = 'request';
    public const DEFAULT_PER_HOP_TIMEOUT_SECONDS = 6;
}

final class WakeConfig
{
    public static function fromMetadata(array $metadata): ?array
    {
        $wakeUrl = $metadata['wake_url'] ?? null;
        if (!is_string($wakeUrl) || trim($wakeUrl) === '') {
            return null;
        }

        $wakeUrl = rtrim(trim($wakeUrl), '/');
        return [
            'profile' => '__http_wake__',
            'target' => $wakeUrl,
            'data' => ['wake_url' => $wakeUrl],
        ];
    }
}

// Wake is not a second transport path. Reticulum-php deliberately consolidates
// bidirectional transfer into a request/response exchange, so wake providers
// exist only to nudge a peer or local helper to originate the next request when
// queued data must reach an address we cannot directly push to, such as a node
// behind NAT.
interface WakeProvider
{
    public function dispatch(array $profile, array $event): array;
}

final class LogWakeProvider implements WakeProvider
{
    public function dispatch(array $profile, array $event): array
    {
        $logPath = $profile['log_path'] ?? null;
        if (!is_string($logPath) || trim($logPath) === '') {
            throw new RuntimeException('log wake profile requires a non-empty log_path');
        }

        $payload = [
            'wake_event' => $event,
            'dispatched_at' => time(),
        ];
        $line = json_encode($payload, JSON_THROW_ON_ERROR) . PHP_EOL;
        if (file_put_contents($logPath, $line, FILE_APPEND | LOCK_EX) === false) {
            throw new RuntimeException('failed to append wake event to log sink');
        }

        return [
            'type' => 'log',
            'log_path' => $logPath,
        ];
    }
}

final class CommandWakeProvider implements WakeProvider
{
    public function dispatch(array $profile, array $event): array
    {
        $command = $profile['command'] ?? null;
        if (!is_array($command) || $command === []) {
            throw new RuntimeException('command wake profile requires a non-empty command array');
        }

        foreach ($command as $part) {
            if (!is_string($part) || $part === '') {
                throw new RuntimeException('command wake profile command entries must be non-empty strings');
            }
        }

        $cwd = $profile['cwd'] ?? null;
        if ($cwd !== null && (!is_string($cwd) || trim($cwd) === '')) {
            throw new RuntimeException('command wake profile cwd must be a non-empty string when present');
        }

        $descriptors = [
            0 => ['pipe', 'r'],
            1 => ['pipe', 'w'],
            2 => ['pipe', 'w'],
        ];
        $process = proc_open($command, $descriptors, $pipes, $cwd ?: null);
        if (!is_resource($process)) {
            throw new RuntimeException('failed to start wake command');
        }

        fwrite($pipes[0], json_encode($event, JSON_THROW_ON_ERROR));
        fclose($pipes[0]);

        $stdout = stream_get_contents($pipes[1]);
        fclose($pipes[1]);

        $stderr = stream_get_contents($pipes[2]);
        fclose($pipes[2]);

        $exitCode = proc_close($process);
        if ($exitCode !== 0) {
            $stderr = trim((string) $stderr);
            throw new RuntimeException(
                $stderr === ''
                    ? 'wake command exited with status ' . $exitCode
                    : 'wake command exited with status ' . $exitCode . ': ' . $stderr
            );
        }

        return [
            'type' => 'command',
            'exit_code' => $exitCode,
            'stdout' => self::trimOutput((string) $stdout),
        ];
    }

    private static function trimOutput(string $output): ?string
    {
        $output = trim($output);
        if ($output === '') {
            return null;
        }

        if (strlen($output) > 512) {
            return substr($output, 0, 512);
        }

        return $output;
    }
}

final class HttpWakeProvider implements WakeProvider
{
    public function dispatch(array $profile, array $event): array
    {
        $wakeData = $event['wake_data'] ?? null;
        if (!is_array($wakeData)) {
            throw new RuntimeException('http wake requires wake_data with wake_url');
        }

        $wakeUrl = $wakeData['wake_url'] ?? null;
        if (!is_string($wakeUrl) || trim($wakeUrl) === '') {
            throw new RuntimeException('http wake requires wake_data.wake_url');
        }

        $url = rtrim(trim($wakeUrl), '/') . '/v1/wake';

        $hostUrl = $profile['host_url'] ?? null;
        if (!is_string($hostUrl) || trim($hostUrl) === '') {
            $hostUrl = $wakeData['host_url'] ?? $wakeUrl;
        }

        $payload = [
            'waker_url' => rtrim(trim((string) $hostUrl), '/'),
            'queue_reason' => (string) ($event['queue_reason'] ?? ''),
            'queued_packet_count' => (int) ($event['queued_packet_count'] ?? 0),
        ];

        $response = $this->requestJson(
            trim($url),
            $payload,
            (int) ($profile['http_timeout_seconds'] ?? 5),
            (int) ($profile['connect_timeout_seconds'] ?? 5),
        );

        return [
            'type' => 'http',
            'status' => (string) ($response['status'] ?? 'ok'),
            'response' => $response,
        ];
    }

    private function requestJson(string $url, array $payload, int $httpTimeoutSeconds, int $connectTimeoutSeconds): array
    {
        $headers = ['Content-Type: application/json'];
        $body = json_encode($payload, JSON_THROW_ON_ERROR);

        if (function_exists('curl_init')) {
            return $this->requestJsonWithCurl($url, $headers, $body, $httpTimeoutSeconds, $connectTimeoutSeconds);
        }

        return $this->requestJsonWithStreams($url, $headers, $body, $httpTimeoutSeconds);
    }

    private function requestJsonWithCurl(string $url, array $headers, string $body, int $httpTimeoutSeconds, int $connectTimeoutSeconds): array
    {
        $curl = curl_init($url);
        if ($curl === false) {
            throw new RuntimeException('Unable to initialise cURL for HTTP wake request');
        }

        curl_setopt($curl, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($curl, CURLOPT_CUSTOMREQUEST, 'POST');
        curl_setopt($curl, CURLOPT_HTTPHEADER, $headers);
        curl_setopt($curl, CURLOPT_TIMEOUT, $httpTimeoutSeconds);
        curl_setopt($curl, CURLOPT_CONNECTTIMEOUT, $connectTimeoutSeconds);
        curl_setopt($curl, CURLOPT_POSTFIELDS, $body);

        $responseBody = curl_exec($curl);
        if ($responseBody === false) {
            $error = curl_error($curl);
            throw new RuntimeException('HTTP wake request failed: ' . $error);
        }

        $statusCode = (int) curl_getinfo($curl, CURLINFO_RESPONSE_CODE);

        if ($statusCode < 200 || $statusCode >= 300) {
            throw new RuntimeException('HTTP wake request returned ' . $statusCode . ': ' . $responseBody);
        }

        $decoded = json_decode($responseBody, true, flags: JSON_THROW_ON_ERROR);
        if (!is_array($decoded)) {
            throw new RuntimeException('HTTP wake response was not a JSON object');
        }

        return $decoded;
    }

    private function requestJsonWithStreams(string $url, array $headers, string $body, int $httpTimeoutSeconds): array
    {
        $context = stream_context_create([
            'http' => [
                'method' => 'POST',
                'header' => implode("\r\n", $headers),
                'content' => $body,
                'timeout' => $httpTimeoutSeconds,
                'ignore_errors' => true,
            ],
        ]);

        $responseBody = @file_get_contents($url, false, $context);
        if ($responseBody === false) {
            $error = error_get_last();
            throw new RuntimeException('HTTP wake request failed: ' . ($error['message'] ?? 'unknown error'));
        }

        $headersResponse = $http_response_header ?? [];
        $statusCode = 0;
        if (isset($headersResponse[0]) && preg_match('/\s(\d{3})\s/', $headersResponse[0], $matches) === 1) {
            $statusCode = (int) $matches[1];
        }

        if ($statusCode < 200 || $statusCode >= 300) {
            throw new RuntimeException('HTTP wake request returned ' . $statusCode . ': ' . $responseBody);
        }

        $decoded = json_decode($responseBody, true, flags: JSON_THROW_ON_ERROR);
        if (!is_array($decoded)) {
            throw new RuntimeException('HTTP wake response was not a JSON object');
        }

        return $decoded;
    }
}

final class WakeDispatcher
{
    public function __construct(private readonly array $config)
    {
    }

    public static function validateMetadata(array $metadata, array $config): ?array
    {
        $wakeConfig = WakeConfig::fromMetadata($metadata);
        if ($wakeConfig === null) {
            return null;
        }

        return $wakeConfig;
    }

    public function dispatch(array $event): array
    {
        $profileName = (string) ($event['wake_profile'] ?? '');
        $profile = $this->profileConfig($profileName);

        return match ($profile['type']) {
            'log' => (new LogWakeProvider())->dispatch($profile, $event),
            'command' => (new CommandWakeProvider())->dispatch($profile, $event),
            'http' => (new HttpWakeProvider())->dispatch($profile, $event),
            default => throw new RuntimeException('unsupported wake provider type: ' . $profile['type']),
        };
    }

    private function profileConfig(string $profileName): array
    {
        if ($profileName === '__http_wake__') {
            $hostUrl = $this->config['host_url'] ?? ($this->config['http']['advertise_url'] ?? null);
            return [
                'type' => 'http',
                'host_url' => is_string($hostUrl) ? rtrim(trim($hostUrl), '/') : null,
                'http_timeout_seconds' => 5,
                'connect_timeout_seconds' => 5,
            ];
        }

        if ($profileName === '') {
            throw new RuntimeException('wake profile name is required');
        }

        $profiles = $this->config['wake']['profiles'] ?? [];
        if (!is_array($profiles) || !isset($profiles[$profileName]) || !is_array($profiles[$profileName])) {
            throw new RuntimeException('unknown wake profile: ' . $profileName);
        }

        $profile = $profiles[$profileName];
        $type = $profile['type'] ?? null;
        if (!is_string($type) || trim($type) === '') {
            throw new RuntimeException('wake profile ' . $profileName . ' requires a non-empty type');
        }

        $profile['type'] = trim($type);
        return $profile;
    }
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
    use RequestWakeDispatchTrait;
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
        private readonly Storage $storage
    ) {
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
                $summary = $this->storage->initializeNode();

                // Clear opcache so the new code is picked up.
                if (function_exists('opcache_reset')) {
                    opcache_reset();
                }

                $this->respond(200, $summary);
            }

            if ($method === 'GET' && $path === '/v1/monitor') {
                $this->renderMonitorPage();
            }

            if ($method === 'GET' && ($path === '/v1/monitor/data' || $path === '/v1/monitor/json')) {
                $this->respond(200, $this->storage->monitorData());
            }

            if ($method === 'GET' && $path === '/health') {
                $this->respond(200, [
                    'status' => 'ok',
                    'transport_basis' => requestTransportMechanism(),
                    'environment' => Environment::verify(),
                    'queues' => $this->storage->healthSummary(),
                    'php_interface_registry' => $this->storage->healthInterfaceRegistry(5),
                ]);
            }

            if ($method === 'GET' && $path === '/debug') {
                if (($this->config['debug']['enabled'] ?? false) !== true) {
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
                        WakeDispatcher::validateMetadata($metadata, $this->config);
                    } catch (RuntimeException $error) {
                        throw new ApiError(400, $error->getMessage(), ['error' => $error->getMessage()]);
                    }
                } else {
                    $maxPacketBytes = $this->storage->maxPacketBytesForMetadata($metadata);
                }

                $registration = $this->storage->registerInterface($name, $bitrate, $mtu, $metadata);
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

            if ($method === 'POST' && ($path === '/v1/interfaces/exchange' || $path === '/v1/interfaces/tx')) {
                $body = $this->readJsonBody();
                [$interfaceId, $sessionToken] = $this->requireInterfaceCredentials($body);
                $this->storage->authenticateInterface($interfaceId, $sessionToken);
                $this->runInterfaceRequestPrelude();
                $ackBatchIds = $this->optionalStringArray($body, 'ack_batch_ids');
                $requestedMaxPackets = $body['max_packets'] ?? (int) $this->config['http']['max_batch_packets'];
                $maxPackets = min($this->requirePositiveIntValue($requestedMaxPackets, 'max_packets'), (int) $this->config['http']['max_batch_packets']);
                $packets = $this->requirePacketArray($body, 'packets', $interfaceId);
                $batchId = $packets === []
                    ? $this->optionalNonEmptyString($body, 'batch_id')
                    : $this->requireNonEmptyString($body, 'batch_id');
                $acked = $this->storage->acknowledgeOutboundBatches($interfaceId, $ackBatchIds);
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

                $delivery = $this->storage->fetchOutboundBatch($interfaceId, $maxPackets);
                $this->runInterfaceRequestEpilogue();

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

                // The wake caller has already dropped the connection.
                // We call the peer's exchange endpoint inline to pull any pending packets.
                $result = $this->storage->exchangeWithPhpPeer($wakerUrl);

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

final class TcpBridgeConfig
{
    public function __construct(
        public readonly string $name,
        public readonly string $baseUrl,
        public readonly string $targetHost,
        public readonly int $targetPort,
        public readonly int $bitrate,
        public readonly int $mtu,
        public readonly int $maxBatchPackets,
        public readonly int $httpTimeoutSeconds,
        public readonly int $connectTimeoutSeconds,
        public readonly int $readChunkBytes,
        public readonly string $controlListenHost,
        public readonly int $controlListenPort,
        public readonly string $controlStatePath,
        public readonly string $wakeProfile,
        public readonly string $wakeTarget,
    ) {
    }

    public static function load(string $projectRoot): self
    {
        $config = Config::load($projectRoot);
        $bridge = $config['tcp_bridge'] ?? null;
        if (!is_array($bridge)) {
            throw new RuntimeException('TcpBridgeInterface or tcp_bridge configuration is required');
        }

        $name = self::optionalString($bridge, 'name') ?? 'shared-hosting-tcp-bridge';
        $baseUrl = rtrim(self::requireString($bridge, 'base_url'), '/');
        if ($baseUrl === '') {
            throw new RuntimeException('tcp_bridge.base_url must not be empty');
        }

        $wakeProfile = self::requireString($bridge, 'wake_profile');
        $wakeTarget = self::optionalString($bridge, 'wake_target') ?? $name;

        return new self(
            $name,
            $baseUrl,
            self::requireString($bridge, 'target_host'),
            self::requirePositiveInt($bridge, 'target_port'),
            self::positiveIntOrDefault($bridge, 'bitrate', 62500),
            self::positiveIntOrDefault($bridge, 'mtu', 500),
            self::positiveIntOrDefault($bridge, 'max_batch_packets', 64),
            self::positiveIntOrDefault($bridge, 'http_timeout_seconds', 5),
            self::positiveIntOrDefault($bridge, 'connect_timeout_seconds', 5),
            self::positiveIntOrDefault($bridge, 'read_chunk_bytes', 4096),
            self::optionalString($bridge, 'control_listen_host') ?? '127.0.0.1',
            (int) ($bridge['control_listen_port'] ?? 0),
            self::requireString($bridge, 'control_state_path'),
            $wakeProfile,
            $wakeTarget,
        );
    }

    public function interfaceMetadata(): array
    {
        return [
            'client' => 'reticulum-php',
            'implementation' => 'TcpBridge',
            'mode' => 'full',
            'wake' => [
                'profile' => $this->wakeProfile,
                'target' => $this->wakeTarget,
            ],
        ];
    }

    private static function requireString(array $config, string $field): string
    {
        $value = self::optionalString($config, $field);
        if ($value === null) {
            throw new RuntimeException('tcp_bridge.' . $field . ' is required');
        }

        return $value;
    }

    private static function optionalString(array $config, string $field): ?string
    {
        $value = $config[$field] ?? null;
        if ($value === null) {
            return null;
        }

        if (!is_string($value)) {
            throw new RuntimeException('tcp_bridge.' . $field . ' must be a string');
        }

        $value = trim($value);
        return $value === '' ? null : $value;
    }

    private static function requirePositiveInt(array $config, string $field): int
    {
        $value = $config[$field] ?? null;
        if (!is_int($value) && !is_string($value) && !is_float($value)) {
            throw new RuntimeException('tcp_bridge.' . $field . ' must be numeric');
        }

        $value = (int) $value;
        if ($value <= 0) {
            throw new RuntimeException('tcp_bridge.' . $field . ' must be positive');
        }

        return $value;
    }

    private static function positiveIntOrDefault(array $config, string $field, int $default): int
    {
        if (!array_key_exists($field, $config)) {
            return $default;
        }

        return self::requirePositiveInt($config, $field);
    }
}

final class TcpBridgeState
{
    public static function write(string $path, array $state): void
    {
        $directory = dirname($path);
        if (!is_dir($directory) && !mkdir($directory, 0775, true) && !is_dir($directory)) {
            throw new RuntimeException('Unable to create state directory: ' . $directory);
        }

        $temporaryPath = $path . '.tmp';
        file_put_contents($temporaryPath, json_encode($state, JSON_PRETTY_PRINT | JSON_THROW_ON_ERROR));
        rename($temporaryPath, $path);
    }

    public static function read(string $path): array
    {
        if (!is_file($path)) {
            throw new RuntimeException('tcp bridge state file not found: ' . $path);
        }

        $decoded = json_decode((string) file_get_contents($path), true, flags: JSON_THROW_ON_ERROR);
        if (!is_array($decoded)) {
            throw new RuntimeException('tcp bridge state file is invalid');
        }

        return $decoded;
    }
}

final class TcpBridgeHdlc
{
    private const FLAG = "\x7E";
    private const ESC = "\x7D";
    private const ESC_MASK = 0x20;

    public static function frame(string $packet): string
    {
        return self::FLAG . self::escape($packet) . self::FLAG;
    }

    public static function appendAndExtract(string &$buffer, string $chunk): array
    {
        $buffer .= $chunk;
        $frames = [];

        while (true) {
            $frameStart = strpos($buffer, self::FLAG);
            if ($frameStart === false) {
                $buffer = '';
                break;
            }

            if ($frameStart > 0) {
                $buffer = substr($buffer, $frameStart);
            }

            $frameEnd = strpos($buffer, self::FLAG, 1);
            if ($frameEnd === false) {
                break;
            }

            $frame = substr($buffer, 1, $frameEnd - 1);
            $frame = str_replace(self::ESC . chr(ord(self::FLAG) ^ self::ESC_MASK), self::FLAG, $frame);
            $frame = str_replace(self::ESC . chr(ord(self::ESC) ^ self::ESC_MASK), self::ESC, $frame);
            if ($frame !== '') {
                $frames[] = $frame;
            }

            $buffer = substr($buffer, $frameEnd);
        }

        return $frames;
    }

    private static function escape(string $packet): string
    {
        $packet = str_replace(self::ESC, self::ESC . chr(ord(self::ESC) ^ self::ESC_MASK), $packet);
        return str_replace(self::FLAG, self::ESC . chr(ord(self::FLAG) ^ self::ESC_MASK), $packet);
    }
}

final class TcpBridgeHttpClient
{
    private ?string $interfaceId = null;
    private ?string $sessionToken = null;
    private int $batchSequence = 0;
    private int $maxBatchPackets;
    private int $maxPacketBytes;

    public function __construct(private readonly TcpBridgeConfig $config)
    {
        $this->maxBatchPackets = $config->maxBatchPackets;
        $this->maxPacketBytes = $config->mtu;
    }

    public function registerInterface(): void
    {
        $response = $this->requestJson(
            'POST',
            '/v1/interfaces/register',
            [
                'name' => $this->config->name,
                'bitrate' => $this->config->bitrate,
                'mtu' => $this->config->mtu,
                'metadata' => $this->config->interfaceMetadata(),
            ],
            [],
        );

        $this->interfaceId = $this->requireResponseString($response, 'interface_id');
        $this->sessionToken = $this->requireResponseString($response, 'session_token');
        $this->maxBatchPackets = max(1, (int) ($response['max_batch_packets'] ?? $this->maxBatchPackets));
        $this->maxPacketBytes = max(1, (int) ($response['max_packet_bytes'] ?? $this->maxPacketBytes));
    }

    public function exchange(array $packets, array $ackBatchIds): array
    {
        if ($this->interfaceId === null || $this->sessionToken === null) {
            throw new RuntimeException('tcp bridge interface is not registered');
        }

        $payload = [
            'interface_id' => $this->interfaceId,
            'session_token' => $this->sessionToken,
            'ack_batch_ids' => array_values($ackBatchIds),
            'max_packets' => $this->maxBatchPackets,
            'packets' => array_map(static fn(string $packet): string => base64_encode($packet), $packets),
        ];
        if ($packets !== []) {
            $payload['batch_id'] = $this->nextBatchId();
        }

        $response = $this->requestJson('POST', '/v1/interfaces/exchange', $payload);
        if ($packets !== [] && (bool) ($response['duplicate_batch'] ?? false)) {
            throw new RuntimeException('tcp bridge unexpectedly reused an outbound batch id');
        }

        return $response;
    }

    public function maxBatchPackets(): int
    {
        return $this->maxBatchPackets;
    }

    public function maxPacketBytes(): int
    {
        return $this->maxPacketBytes;
    }

    private function nextBatchId(): string
    {
        $this->batchSequence++;
        return sprintf('%d-%08x', (int) (microtime(true) * 1000), $this->batchSequence);
    }

    private function requireResponseString(array $response, string $field): string
    {
        $value = $response[$field] ?? null;
        if (!is_string($value) || $value === '') {
            throw new RuntimeException('Bridge registration response is missing ' . $field);
        }

        return $value;
    }

    private function requestJson(string $method, string $path, ?array $payload = null, array $extraHeaders = []): array
    {
        $url = $this->config->baseUrl . $path;
        $headers = ['Content-Type: application/json'];
        foreach ($extraHeaders as $header) {
            $headers[] = $header;
        }

        $body = $payload === null ? null : json_encode($payload, JSON_THROW_ON_ERROR);
        if (function_exists('curl_init')) {
            $response = $this->requestJsonWithCurl($url, $method, $headers, $body);
        } else {
            $response = $this->requestJsonWithStreams($url, $method, $headers, $body);
        }

        if (!is_array($response)) {
            throw new RuntimeException('Unexpected bridge HTTP response payload');
        }

        return $response;
    }

    private function requestJsonWithCurl(string $url, string $method, array $headers, ?string $body): array
    {
        $curl = curl_init($url);
        if ($curl === false) {
            throw new RuntimeException('Unable to initialise cURL for bridge HTTP request');
        }

        curl_setopt($curl, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($curl, CURLOPT_CUSTOMREQUEST, $method);
        curl_setopt($curl, CURLOPT_HTTPHEADER, $headers);
        curl_setopt($curl, CURLOPT_TIMEOUT, $this->config->httpTimeoutSeconds);
        curl_setopt($curl, CURLOPT_CONNECTTIMEOUT, $this->config->connectTimeoutSeconds);
        if ($body !== null) {
            curl_setopt($curl, CURLOPT_POSTFIELDS, $body);
        }

        $responseBody = curl_exec($curl);
        if ($responseBody === false) {
            $error = curl_error($curl);
            throw new RuntimeException('Bridge HTTP request failed: ' . $error);
        }

        $statusCode = (int) curl_getinfo($curl, CURLINFO_RESPONSE_CODE);

        if ($statusCode < 200 || $statusCode >= 300) {
            throw new RuntimeException('Bridge HTTP request returned ' . $statusCode . ': ' . $responseBody);
        }

        $decoded = json_decode($responseBody, true, flags: JSON_THROW_ON_ERROR);
        if (!is_array($decoded)) {
            throw new RuntimeException('Bridge HTTP response was not a JSON object');
        }

        return $decoded;
    }

    private function requestJsonWithStreams(string $url, string $method, array $headers, ?string $body): array
    {
        $context = stream_context_create([
            'http' => [
                'method' => $method,
                'header' => implode("\r\n", $headers),
                'content' => $body ?? '',
                'timeout' => $this->config->httpTimeoutSeconds,
                'ignore_errors' => true,
            ],
        ]);

        $responseBody = @file_get_contents($url, false, $context);
        if ($responseBody === false) {
            $error = error_get_last();
            throw new RuntimeException('Bridge HTTP request failed: ' . ($error['message'] ?? 'unknown error'));
        }

        $headersResponse = $http_response_header ?? [];
        $statusCode = 0;
        if (isset($headersResponse[0]) && preg_match('/\s(\d{3})\s/', $headersResponse[0], $matches) === 1) {
            $statusCode = (int) $matches[1];
        }

        if ($statusCode < 200 || $statusCode >= 300) {
            throw new RuntimeException('Bridge HTTP request returned ' . $statusCode . ': ' . $responseBody);
        }

        $decoded = json_decode($responseBody, true, flags: JSON_THROW_ON_ERROR);
        if (!is_array($decoded)) {
            throw new RuntimeException('Bridge HTTP response was not a JSON object');
        }

        return $decoded;
    }
}

final class TcpBridgeDaemon
{
    /** @var resource|null */
    private $tcpSocket = null;
    /** @var resource|null */
    private $controlServer = null;
    private ?string $controlSocketPath = null;
    /** @var array<int, resource> */
    private array $controlClients = [];
    /** @var array<int, string> */
    private array $controlBuffers = [];
    /** @var list<string> */
    private array $pendingInboundPackets = [];
    /** @var list<string> */
    private array $pendingAckBatchIds = [];
    private bool $pendingWake = false;
    private string $tcpReadBuffer = '';
    private string $controlToken = '';

    public function __construct(
        private readonly TcpBridgeConfig $config,
        private readonly TcpBridgeHttpClient $httpClient,
    ) {
    }

    public function run(): never
    {
        $this->openControlServer();
        $this->connectTcp();
        $this->httpClient->registerInterface();

        try {
            while (true) {
                if ($this->hasPendingWork()) {
                    $this->processPendingWork();
                    continue;
                }

                $this->waitForEvents();
            }
        } finally {
            $this->cleanup();
        }
    }

    private function hasPendingWork(): bool
    {
        return $this->pendingInboundPackets !== [] || $this->pendingAckBatchIds !== [] || $this->pendingWake;
    }

    private function processPendingWork(): void
    {
        if ($this->pendingInboundPackets !== []) {
            $batch = array_splice($this->pendingInboundPackets, 0, $this->httpClient->maxBatchPackets());
            $this->pendingWake = false;
            $response = $this->exchange($batch);
            $this->drainExchangeResponses($response);
            return;
        }

        if ($this->pendingAckBatchIds !== [] || $this->pendingWake) {
            $this->pendingWake = false;
            $response = $this->exchange([]);
            $this->drainExchangeResponses($response);
        }
    }

    private function waitForEvents(): void
    {
        $readStreams = [];
        if (is_resource($this->tcpSocket)) {
            $readStreams[] = $this->tcpSocket;
        }
        if (is_resource($this->controlServer)) {
            $readStreams[] = $this->controlServer;
        }
        foreach ($this->controlClients as $client) {
            if (is_resource($client)) {
                $readStreams[] = $client;
            }
        }

        $writeStreams = [];
        $exceptStreams = [];
        $changed = stream_select($readStreams, $writeStreams, $exceptStreams, null);
        if ($changed === false) {
            throw new RuntimeException('stream_select failed in tcp bridge');
        }

        foreach ($readStreams as $stream) {
            if ($stream === $this->tcpSocket) {
                $this->readFromTcp();
                continue;
            }

            if ($stream === $this->controlServer) {
                $this->acceptControlClient();
                continue;
            }

            $this->readControlClient($stream);
        }
    }

    private function exchange(array $packets): array
    {
        $ackBatchIds = $this->pendingAckBatchIds;
        $response = $this->httpClient->exchange($packets, $ackBatchIds);
        $this->pendingAckBatchIds = [];

        return $response;
    }

    private function drainExchangeResponses(array $response): void
    {
        while (true) {
            $deliveryPackets = $response['delivery_packets'] ?? [];
            if (!is_array($deliveryPackets)) {
                throw new RuntimeException('Bridge received malformed delivery_packets');
            }

            $packets = [];
            foreach ($deliveryPackets as $packetBase64) {
                if (!is_string($packetBase64) || $packetBase64 === '') {
                    throw new RuntimeException('Bridge received malformed delivery packet');
                }

                $packet = base64_decode($packetBase64, true);
                if (!is_string($packet)) {
                    throw new RuntimeException('Bridge received invalid base64 delivery packet');
                }

                $packets[] = $packet;
            }

            $batchId = $response['delivery_batch_id'] ?? null;
            if ($batchId !== null && (!is_string($batchId) || $batchId === '')) {
                throw new RuntimeException('Bridge received malformed delivery_batch_id');
            }

            if ($packets !== []) {
                foreach ($packets as $packet) {
                    $this->writeToTcp($packet);
                }

                if (is_string($batchId) && $batchId !== '') {
                    $this->pendingAckBatchIds[] = $batchId;
                }
            }

            $more = (bool) ($response['delivery_more'] ?? false);
            if (!$more && $this->pendingAckBatchIds === []) {
                return;
            }

            $response = $this->exchange([]);
        }
    }

    private function openControlServer(): void
    {
        $this->controlToken = bin2hex(random_bytes(16));

        $unixSocketPath = $this->buildUnixControlSocketPath();
        $unixServer = @stream_socket_server('unix://' . $unixSocketPath, $unixErrorCode, $unixErrorMessage);
        if ($unixServer !== false) {
            stream_set_blocking($unixServer, false);
            TcpBridgeState::write($this->config->controlStatePath, [
                'transport' => 'unix',
                'socket_path' => $unixSocketPath,
                'token' => $this->controlToken,
                'pid' => getmypid(),
                'name' => $this->config->name,
            ]);

            $this->controlServer = $unixServer;
            $this->controlSocketPath = $unixSocketPath;
            return;
        }

        $endpoint = sprintf('tcp://%s:%d', $this->config->controlListenHost, $this->config->controlListenPort);
        $server = @stream_socket_server($endpoint, $errorCode, $errorMessage);
        if ($server === false) {
            throw new RuntimeException(
                'Unable to open tcp bridge control server; unix failed with ' . $unixErrorMessage . ' (' . $unixErrorCode . ')' .
                ', tcp failed with ' . $errorMessage . ' (' . $errorCode . ')'
            );
        }

        stream_set_blocking($server, false);
        $address = stream_socket_get_name($server, false);
        if (!is_string($address) || $address === '') {
            throw new RuntimeException('Unable to resolve tcp bridge control server address');
        }

        $separator = strrpos($address, ':');
        if ($separator === false) {
            throw new RuntimeException('Unable to parse tcp bridge control server address: ' . $address);
        }

        TcpBridgeState::write($this->config->controlStatePath, [
            'transport' => 'tcp',
            'host' => substr($address, 0, $separator),
            'port' => (int) substr($address, $separator + 1),
            'token' => $this->controlToken,
            'pid' => getmypid(),
            'name' => $this->config->name,
        ]);

        $this->controlServer = $server;
    }

    private function buildUnixControlSocketPath(): string
    {
        $baseDirectory = DIRECTORY_SEPARATOR === '/' && is_dir('/tmp') ? '/tmp' : rtrim(sys_get_temp_dir(), DIRECTORY_SEPARATOR);
        $pid = (int) (getmypid() ?: 0);
        $hash = substr(hash('sha256', $this->config->controlStatePath), 0, 12);
        $nonce = bin2hex(random_bytes(4));

        return $baseDirectory . DIRECTORY_SEPARATOR . 'rphp-bridge-' . $hash . '-' . $pid . '-' . $nonce . '.sock';
    }

    private function connectTcp(): void
    {
        $endpoint = sprintf('tcp://%s:%d', $this->config->targetHost, $this->config->targetPort);
        $socket = @stream_socket_client(
            $endpoint,
            $errorCode,
            $errorMessage,
            $this->config->connectTimeoutSeconds,
            STREAM_CLIENT_CONNECT
        );
        if ($socket === false) {
            throw new RuntimeException('Unable to connect bridge TCP socket: ' . $errorMessage . ' (' . $errorCode . ')');
        }

        stream_set_blocking($socket, true);
        stream_set_timeout($socket, 0);
        $this->tcpSocket = $socket;
    }

    private function readFromTcp(): void
    {
        if (!is_resource($this->tcpSocket)) {
            throw new RuntimeException('tcp bridge socket is unavailable');
        }

        $chunk = fread($this->tcpSocket, $this->config->readChunkBytes);
        if ($chunk === false || $chunk === '') {
            throw new RuntimeException('tcp bridge socket closed');
        }

        $frames = TcpBridgeHdlc::appendAndExtract($this->tcpReadBuffer, $chunk);
        foreach ($frames as $frame) {
            if (strlen($frame) > $this->httpClient->maxPacketBytes()) {
                throw new RuntimeException(
                    'tcp bridge received packet of ' . strlen($frame) . ' bytes, larger than PHP max_packet_bytes ' . $this->httpClient->maxPacketBytes()
                );
            }

            $this->pendingInboundPackets[] = $frame;
        }
    }

    private function writeToTcp(string $packet): void
    {
        if (!is_resource($this->tcpSocket)) {
            throw new RuntimeException('tcp bridge socket is unavailable');
        }

        $frame = TcpBridgeHdlc::frame($packet);
        $written = 0;
        $length = strlen($frame);
        while ($written < $length) {
            $count = fwrite($this->tcpSocket, substr($frame, $written));
            if (!is_int($count) || $count <= 0) {
                throw new RuntimeException('tcp bridge failed while writing to TCP socket');
            }

            $written += $count;
        }
    }

    private function acceptControlClient(): void
    {
        if (!is_resource($this->controlServer)) {
            return;
        }

        $client = @stream_socket_accept($this->controlServer, 0);
        if ($client === false) {
            return;
        }

        stream_set_blocking($client, false);
        $clientId = (int) $client;
        $this->controlClients[$clientId] = $client;
        $this->controlBuffers[$clientId] = '';
    }

    /** @param resource $client */
    private function readControlClient($client): void
    {
        $clientId = (int) $client;
        $chunk = fread($client, 4096);
        if ($chunk === false) {
            $this->closeControlClient($client);
            return;
        }

        $this->controlBuffers[$clientId] = ($this->controlBuffers[$clientId] ?? '') . $chunk;
        $buffer = $this->controlBuffers[$clientId];
        if (str_contains($buffer, "\n") || feof($client)) {
            $message = trim($buffer);
            if ($message !== '' && hash_equals($this->controlToken, $message)) {
                $this->pendingWake = true;
            }

            $this->closeControlClient($client);
        }
    }

    /** @param resource $client */
    private function closeControlClient($client): void
    {
        $clientId = (int) $client;
        unset($this->controlClients[$clientId], $this->controlBuffers[$clientId]);
        fclose($client);
    }

    private function cleanup(): void
    {
        foreach ($this->controlClients as $client) {
            if (is_resource($client)) {
                fclose($client);
            }
        }
        $this->controlClients = [];
        $this->controlBuffers = [];

        if (is_resource($this->controlServer)) {
            fclose($this->controlServer);
            $this->controlServer = null;
        }

        if ($this->controlSocketPath !== null) {
            @unlink($this->controlSocketPath);
            $this->controlSocketPath = null;
        }

        if (is_resource($this->tcpSocket)) {
            fclose($this->tcpSocket);
            $this->tcpSocket = null;
        }

        if (is_file($this->config->controlStatePath)) {
            @unlink($this->config->controlStatePath);
        }
    }
}

function runTcpBridge(string $projectRoot): never
{
    if (PHP_SAPI !== 'cli') {
        throw new RuntimeException('tcp bridge must be run from the PHP CLI');
    }

    if (PHP_VERSION_ID < 80100) {
        throw new RuntimeException('PHP 8.1 or newer is required for tcp bridge');
    }

    $config = TcpBridgeConfig::load($projectRoot);
    $bridge = new TcpBridgeDaemon($config, new TcpBridgeHttpClient($config));
    $bridge->run();
}

function wakeTcpBridge(string $projectRoot, ?string $statePath = null): int
{
    if (PHP_SAPI !== 'cli') {
        throw new RuntimeException('tcp bridge wake command must be run from the PHP CLI');
    }

    $config = TcpBridgeConfig::load($projectRoot);
    $state = TcpBridgeState::read($statePath ?? $config->controlStatePath);
    $socketPath = $state['socket_path'] ?? null;
    $transport = $state['transport'] ?? null;
    $token = $state['token'] ?? null;
    if (is_string($socketPath) && $socketPath !== '') {
        if (!is_string($token) || $token === '') {
            throw new RuntimeException('tcp bridge state file is missing token');
        }

        $socket = @stream_socket_client('unix://' . $socketPath, $errorCode, $errorMessage, 1);
        if ($socket === false) {
            throw new RuntimeException('Unable to reach tcp bridge unix control socket: ' . $errorMessage . ' (' . $errorCode . ')');
        }

        fwrite($socket, $token . "\n");
        fclose($socket);

        return 0;
    }

    $host = $state['host'] ?? null;
    $port = $state['port'] ?? null;
    if ($transport === 'unix') {
        throw new RuntimeException('tcp bridge state file is missing socket_path for unix control transport');
    }

    if (!is_string($host) || $host === '' || !is_int($port) && !is_string($port) || !is_string($token) || $token === '') {
        throw new RuntimeException('tcp bridge state file is missing host, port, or token');
    }

    $socket = @stream_socket_client(sprintf('tcp://%s:%d', $host, (int) $port), $errorCode, $errorMessage, 1);
    if ($socket === false) {
        throw new RuntimeException('Unable to reach tcp bridge control socket: ' . $errorMessage . ' (' . $errorCode . ')');
    }

    fwrite($socket, $token . "\n");
    fclose($socket);

    return 0;
}

/** @return array{0: array, 1: Storage} */
function initializeRuntime(string $projectRoot): array
{
    $reticulumPhpConfig = Config::load($projectRoot);

    // Enforce PHP memory limit from config (shared-hosting safety).
    $phpMemoryLimit = (string) ($reticulumPhpConfig['php']['memory_limit'] ?? '128M');
    if ($phpMemoryLimit !== '' && ini_set('memory_limit', $phpMemoryLimit) === false) {
        error_log('Reticulum-php: unable to set memory_limit=' . $phpMemoryLimit);
    }

    Config::ensureDirectories($reticulumPhpConfig);
    Environment::verify();

    $reticulumPhpStorage = new Storage($reticulumPhpConfig);
    $reticulumPhpStorage->migrate();

    return [$reticulumPhpConfig, $reticulumPhpStorage];
}

function runIndexCli(string $projectRoot, array $argv): int
{
    [$reticulumPhpConfig, $reticulumPhpStorage] = initializeRuntime($projectRoot);
    $mode = $argv[1] ?? 'once';
    $maintenanceConfig = $reticulumPhpConfig['maintenance'] ?? $reticulumPhpConfig['worker'] ?? [];

    if ($mode === 'once') {
        $maintenance = $reticulumPhpStorage->runMaintenance(
            (int) ($maintenanceConfig['interface_stale_after_seconds'] ?? 15),
            (int) ($maintenanceConfig['batch_ttl_seconds'] ?? 86400),
        );

        $wake = $reticulumPhpStorage->dispatchPendingWakeEvents(
            (int) ($reticulumPhpConfig['wake']['dispatch_limit'] ?? 32),
            new WakeDispatcher($reticulumPhpConfig),
        );

        $summary = [
            'status' => 'ok',
            'transport_basis' => requestTransportMechanism(),
            'wake' => $wake,
            'maintenance' => $maintenance,
            'queues' => $reticulumPhpStorage->healthSummary(),
        ];

        fwrite(STDOUT, json_encode($summary, JSON_PRETTY_PRINT | JSON_THROW_ON_ERROR) . PHP_EOL);
        return 0;
    }

    if ($mode === 'wake-event') {
        $wakeEventId = isset($argv[2]) ? (int) $argv[2] : 0;
        if ($wakeEventId <= 0) {
            fwrite(STDERR, "wake-event mode requires a positive wake event id\n");
            return 1;
        }

        $result = $reticulumPhpStorage->dispatchWakeEventById(
            $wakeEventId,
            (int) (getmypid() ?: 0),
            new WakeDispatcher($reticulumPhpConfig),
        );
        fwrite(STDOUT, json_encode($result, JSON_PRETTY_PRINT | JSON_THROW_ON_ERROR) . PHP_EOL);
        return ($result['status'] ?? null) === 'failed' ? 1 : 0;
    }

    fwrite(STDERR, "Unsupported index mode: {$mode}\n");
    return 1;
}

function runIndexHttp(string $projectRoot): never
{
    [$reticulumPhpConfig, $reticulumPhpStorage] = initializeRuntime($projectRoot);
    $api = new HttpApi($reticulumPhpConfig, $reticulumPhpStorage);
    $api->handle(
        $_SERVER['REQUEST_METHOD'] ?? 'GET',
        $_SERVER['REQUEST_URI'] ?? '/',
        $_SERVER,
    );
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
