<?php

declare(strict_types=1);

namespace ReticulumPhp;

// Reticulum-php is request-operated. These HTTP API helpers validate and
// complete one authenticated request at a time; they do not create a separate
// background transport path.

trait RequestHttpApiHelperTrait
{
    private function runInterfaceRequestPrelude(): void
    {
        $this->storage->runMaintenance(
            $this->maintenanceInt('interface_stale_after_seconds', 15),
            $this->maintenanceInt('batch_ttl_seconds', 86400),
        );
    }

    private function runInterfaceRequestEpilogue(): void
    {
        $wakeEventIds = $this->storage->pendingWakeEventIdsForSpawn(
            (int) ($this->config['wake']['dispatch_limit'] ?? 32),
        );

        foreach ($wakeEventIds as $wakeEventId) {
            try {
                $this->spawnDetachedWakeRunner((int) $wakeEventId);
            } catch (\Throwable $error) {
                $message = 'failed to spawn wake runner: ' . $error->getMessage();
                $this->storage->failWakeEvent((int) $wakeEventId, $message);
                $this->log('error', 'Wake runner spawn failed for wake_event_id ' . $wakeEventId . ': ' . $error->getMessage());
            }
        }
    }

    private function spawnDetachedWakeRunner(int $wakeEventId): void
    {
        $phpBinary = PHP_BINARY !== '' ? PHP_BINARY : 'php';
        $workerScript = dirname(__DIR__) . '/index.php';
        $command = sprintf(
            '%s %s wake-event %d > /dev/null 2>&1 &',
            escapeshellarg($phpBinary),
            escapeshellarg($workerScript),
            $wakeEventId,
        );

        $output = [];
        $exitCode = 0;
        exec($command, $output, $exitCode);
        if ($exitCode !== 0) {
            throw new \RuntimeException('wake runner spawn exited with status ' . $exitCode);
        }
    }

    private function idleExchangeIntervalMs(): int
    {
        return (int) (
            $this->config['http']['idle_exchange_interval_ms']
                ?? 1000
        );
    }

    private function maintenanceInt(string $field, int $default): int
    {
        $maintenance = $this->config['maintenance'] ?? $this->config['worker'] ?? [];
        return (int) ($maintenance[$field] ?? $default);
    }

    private function requireInterfaceCredentials(array $body): array
    {
        return [
            $this->requireNonEmptyString($body, 'interface_id'),
            $this->requireNonEmptyString($body, 'session_token'),
        ];
    }

    private function readJsonBody(): array
    {
        $raw = file_get_contents('php://input');
        if (!is_string($raw) || $raw === '') {
            throw new ApiError(400, 'Empty request body', ['error' => 'empty request body']);
        }

        $decoded = json_decode($raw, true);
        if (!is_array($decoded)) {
            throw new ApiError(400, 'Invalid JSON', ['error' => 'invalid json']);
        }

        return $decoded;
    }

    private function normalizedPath(string $uri, array $server): string
    {
        $path = parse_url($uri, PHP_URL_PATH);
        $path = is_string($path) ? $path : '/';

        $scriptName = $server['SCRIPT_NAME'] ?? $server['PHP_SELF'] ?? null;
        if (is_string($scriptName) && $scriptName !== '') {
            $path = $this->stripPathPrefix($path, rtrim($scriptName, '/'));

            $scriptDir = dirname($scriptName);
            if (is_string($scriptDir) && $scriptDir !== '' && $scriptDir !== '.' && $scriptDir !== DIRECTORY_SEPARATOR) {
                $path = $this->stripPathPrefix($path, rtrim(str_replace('\\', '/', $scriptDir), '/'));
            }
        }

        $path = rtrim($path, '/');
        return $path === '' ? '/' : $path;
    }

    private function stripPathPrefix(string $path, string $prefix): string
    {
        if ($prefix === '' || $prefix === '/') {
            return $path;
        }

        if ($path === $prefix) {
            return '/';
        }

        if (str_starts_with($path, $prefix . '/')) {
            return substr($path, strlen($prefix));
        }

        return $path;
    }

    private function requirePacketArray(array $body, string $field, ?string $interfaceId = null): array
    {
        $packets = $body[$field] ?? null;
        if (!is_array($packets)) {
            throw new ApiError(400, $field . ' must be an array', ['error' => $field . ' must be an array']);
        }

        $maxPackets = (int) $this->config['http']['max_batch_packets'];
        if (count($packets) > $maxPackets) {
            throw new ApiError(400, 'Too many packets', ['error' => 'batch exceeds max_batch_packets']);
        }

        $maxPacketBytes = $interfaceId === null
            ? (int) $this->config['http']['max_packet_bytes']
            : $this->storage->maxPacketBytesForInterface($interfaceId);
        foreach ($packets as $index => $packet) {
            if (!is_string($packet)) {
                throw new ApiError(400, 'Packet must be a base64 string', ['error' => 'invalid packet encoding', 'index' => $index]);
            }

            $decoded = base64_decode($packet, true);
            if (!is_string($decoded)) {
                throw new ApiError(400, 'Packet is not valid base64', ['error' => 'invalid packet base64', 'index' => $index]);
            }

            if (strlen($decoded) > $maxPacketBytes) {
                throw new ApiError(400, 'Packet exceeds max_packet_bytes', ['error' => 'packet too large', 'index' => $index]);
            }
        }

        return $packets;
    }

    private function requireNonEmptyString(array $body, string $field): string
    {
        $value = $body[$field] ?? null;
        if (!is_string($value) || trim($value) === '') {
            throw new ApiError(400, $field . ' must be a non-empty string', ['error' => $field . ' must be a non-empty string']);
        }

        return $value;
    }

    private function optionalNonEmptyString(array $body, string $field): ?string
    {
        $value = $body[$field] ?? null;
        if ($value === null) {
            return null;
        }

        if (!is_string($value) || trim($value) === '') {
            throw new ApiError(400, $field . ' must be a non-empty string', ['error' => $field . ' must be a non-empty string']);
        }

        return $value;
    }

    private function requirePositiveInt(array $body, string $field): int
    {
        return $this->requirePositiveIntValue($body[$field] ?? null, $field);
    }

    private function requirePositiveIntValue(mixed $value, string $field): int
    {
        if (!is_int($value) && !(is_string($value) && ctype_digit($value))) {
            throw new ApiError(400, $field . ' must be a positive integer', ['error' => $field . ' must be a positive integer']);
        }

        $integer = (int) $value;
        if ($integer < 1) {
            throw new ApiError(400, $field . ' must be greater than zero', ['error' => $field . ' must be greater than zero']);
        }

        return $integer;
    }

    private function optionalArray(array $body, string $field): array
    {
        $value = $body[$field] ?? [];
        if (!is_array($value)) {
            throw new ApiError(400, $field . ' must be an object or array', ['error' => $field . ' must be an object or array']);
        }

        return $value;
    }

    private function optionalStringArray(array $body, string $field): array
    {
        $value = $body[$field] ?? [];
        if (!is_array($value)) {
            throw new ApiError(400, $field . ' must be an array', ['error' => $field . ' must be an array']);
        }

        foreach ($value as $entry) {
            if (!is_string($entry) || $entry === '') {
                throw new ApiError(400, $field . ' must only contain strings', ['error' => $field . ' must only contain strings']);
            }
        }

        return $value;
    }

    private function respond(int $statusCode, array $payload): never
    {
        http_response_code($statusCode);
        header('Content-Type: application/json');
        echo json_encode($payload, JSON_THROW_ON_ERROR);
        exit;
    }

    private function log(string $level, string $message): void
    {
        $line = sprintf("[%s] [%s] %s\n", date('Y-m-d H:i:s'), strtoupper($level), $message);
        file_put_contents((string) $this->config['storage']['log_path'], $line, FILE_APPEND | LOCK_EX);
    }
}