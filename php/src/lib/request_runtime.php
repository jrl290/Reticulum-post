<?php

declare(strict_types=1);

namespace ReticulumPhp;

/**
 * Request Runtime — project bootstrap and environment helpers.
 *
 * Reticulum-php is request-operated. Every HTTP request creates a fresh
 * Config + Storage instance. There are no persistent workers or connection
 * pools — the PDO connection is created per-request and destroyed when the
 * request ends (PHP's request-scope lifecycle).
 *
 * Project root resolution:
 *   - CLI: uses the script's directory or its parent
 *   - Web: uses the document root or the script's parent directory
 *
 * This file is required FIRST by index.php (before any trait files)
 * because Database::connect() needs the project root resolved before
 * it can locate config.toml or the SQLite database path.
 */

/**
 * Resolve the project root directory.
 *
 * In the canonical layout, index.php lives in the project root.
 * In shared-hosting flat layouts, it may be one level deeper.
 *
 * @param  string $scriptDir  __DIR__ of the calling script
 * @return string Absolute path to the project root
 */
function resolveRuntimeProjectRoot(string $scriptDir): string
{
    // Check if we're in a subdirectory (e.g., chat-site/reticulum/)
    // by looking for config files in the parent.
    $candidates = [
        $scriptDir,
        dirname($scriptDir),
    ];

    foreach ($candidates as $dir) {
        if (Config::hasConfigFile($dir)) {
            return realpath($dir) ?: $dir;
        }
    }

    // Fallback: return the script directory
    return realpath($scriptDir) ?: $scriptDir;
}

/**
 * Return a human-readable transport mechanism label.
 *
 * Used in health/debug endpoints to indicate how this PHP node
 * communicates with the RNS network.
 */
function requestTransportMechanism(): string
{
    return 'http-exchange';
}
