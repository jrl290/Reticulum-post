<?php

declare(strict_types=1);

/**
 * Regression test for per-destination path request throttling.
 *
 * Mirrors the two in-memory guards the Python daemon relies on:
 *   Transport.path_requests           + PATH_REQUEST_MI      (Transport.py:81)
 *   Transport.discovery_path_requests + PATH_REQUEST_TIMEOUT (Transport.py:78)
 *
 * Without these, tag deduplication is the only guard, and every retry carries a
 * fresh random tag, so an unreachable destination is re-flooded to every local
 * client on every retry.
 *
 * Run with: php tests/path_request_throttle_test.php
 */

require_once __DIR__ . '/../src/lib/database.php';
require_once __DIR__ . '/../src/lib/request_path_state_trait.php';

final class PathRequestThrottleHarness
{
    use \ReticulumPhp\RequestPathStateTrait;

    private PDO $db;
    private string $backend = 'sqlite';
    private array $config = [];

    public function __construct()
    {
        $this->db = new PDO('sqlite::memory:');
        $this->db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        $this->db->exec(
            'CREATE TABLE path_request_throttle (
                throttle_key VARCHAR(96) NOT NULL,
                last_requested_at INT NOT NULL DEFAULT 0,
                PRIMARY KEY (throttle_key)
            )'
        );
    }

    public function claim(string $key, int $interval): bool
    {
        return $this->claimPathRequestSlot($key, $interval);
    }

    /** Backdate a claim so the test does not have to sleep. */
    public function backdate(string $key, int $seconds): void
    {
        $stmt = $this->db->prepare(
            'UPDATE path_request_throttle SET last_requested_at = last_requested_at - ? WHERE throttle_key = ?'
        );
        $stmt->execute([$seconds, $key]);
    }
}

function assertSameValue(mixed $expected, mixed $actual, string $message): void
{
    if ($expected !== $actual) {
        fwrite(STDERR, "FAIL: {$message}\nExpected: " . var_export($expected, true) . "\nActual: " . var_export($actual, true) . "\n");
        exit(1);
    }
}

$dest = 'discovery:aabbccddeeff00112233445566778899';

$h = new PathRequestThrottleHarness();
assertSameValue(true, $h->claim($dest, 15), 'first request for a destination is allowed');
assertSameValue(false, $h->claim($dest, 15), 'an immediate repeat is suppressed');
assertSameValue(false, $h->claim($dest, 15), 'further repeats stay suppressed');

// A retry carrying a fresh tag must still be suppressed: the throttle is keyed
// on the destination alone, exactly like Transport.discovery_path_requests.
assertSameValue(false, $h->claim($dest, 15), 'a retry with a new tag is still suppressed');

$h->backdate($dest, 16);
assertSameValue(true, $h->claim($dest, 15), 'the destination is retryable once the interval elapses');
assertSameValue(false, $h->claim($dest, 15), 'and is immediately throttled again');

// Distinct destinations must not throttle each other.
$other = 'discovery:00112233445566778899aabbccddeeff';
assertSameValue(true, $h->claim($other, 15), 'a different destination is unaffected');

// The auto/discovery scopes are independent, so an automated relay request and
// a forwarded discovery for the same destination do not cancel each other.
$autoKey = 'auto:aabbccddeeff00112233445566778899';
assertSameValue(true, $h->claim($autoKey, 20), 'the auto scope is independent of the discovery scope');
assertSameValue(false, $h->claim($autoKey, 20), 'the auto scope throttles on its own interval');

$h->backdate($autoKey, 16);
assertSameValue(false, $h->claim($autoKey, 20), 'PATH_REQUEST_MI is longer than PATH_REQUEST_TIMEOUT');
$h->backdate($autoKey, 5);
assertSameValue(true, $h->claim($autoKey, 20), 'the auto scope reopens after PATH_REQUEST_MI');

echo "path_request_throttle_test: OK\n";
