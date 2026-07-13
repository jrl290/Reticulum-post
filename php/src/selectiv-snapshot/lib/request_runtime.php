<?php

declare(strict_types=1);

namespace ReticulumPhp;

// Reticulum-php is request-operated. Transport bytes only move inside
// authenticated request/response exchanges. Wake hooks and bridge helpers may
// prompt or sustain the next request, but they never form a second data path.

const REQUEST_TRANSPORT_MODEL = 'request_exchange';
const REQUEST_TRANSPORT_SUMMARY = 'Reticulum-php is operated on a request basis: transport bytes move only inside authenticated request/response exchanges. Wake hooks and bridge helpers only prompt or sustain the next request; they do not form a second data path.';

function requestTransportMechanism(): array
{
    return [
        'model' => REQUEST_TRANSPORT_MODEL,
        'summary' => REQUEST_TRANSPORT_SUMMARY,
    ];
}

function resolveRuntimeProjectRoot(string $entryDirectory): string
{
    $parentDirectory = dirname($entryDirectory);

    foreach ([$entryDirectory, $parentDirectory] as $candidateDirectory) {
        if (Config::hasConfigFile($candidateDirectory)) {
            return $candidateDirectory;
        }
    }

    return $parentDirectory;
}

function resolveRuntimeScriptPath(string $projectRoot, string $scriptName): string
{
    $rootScriptPath = $projectRoot . '/' . $scriptName;
    if (is_file($rootScriptPath)) {
        return $rootScriptPath;
    }

    $coreNodeScriptPath = $projectRoot . '/core-node/' . $scriptName;
    if (is_file($coreNodeScriptPath)) {
        return $coreNodeScriptPath;
    }

    return $rootScriptPath;
}