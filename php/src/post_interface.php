<?php

declare(strict_types=1);

/**
 * PostInterface poll daemon for Reticulum-post.
 *
 * Registers this node as an interface on one or more remote Reticulum-post
 * nodes and runs a poll loop to exchange packets. Supports both poll mode
 * (periodic exchange) and wake mode (idle, waiting for remote to wake us).
 *
 * Usage:
 *   php post_interface.php [--once] [--peer=<peer_id>]
 *
 *   --once    Run a single exchange cycle and exit.
 *   --peer=   Only exchange with the named peer (otherwise all configured peers).
 *
 * Environment: requires ext-curl (preferred) or allow_url_fopen for HTTP.
 */

namespace ReticulumPhp;

require_once __DIR__ . '/index.php';

const MIN_POLL_INTERVAL_SECONDS = 2.0;
const DEFAULT_POLL_INTERVAL_SECONDS = 5.0;

function main(): never
{
    $options = getopt('', ['once', 'peer::']);
    $once = isset($options['once']);
    $filterPeerId = isset($options['peer']) ? (string) $options['peer'] : null;

    $projectRoot = resolveRuntimeProjectRoot(__DIR__);
    $config = Config::load($projectRoot);

    // Verify PHP environment.
    Environment::verify();

    $storage = new Storage($config);
    $storage->migrate();

    fwrite(STDERR, sprintf(
        "[post_interface] Starting%s. Peers configured: %d\n",
        $once ? ' (once)' : '',
        count($config['post_interface_peers'] ?? []),
    ));

    // Register all configured peers.
    $storage->ensurePostInterfacePeersRegistered();

    $peerIds = array_keys($config['post_interface_peers'] ?? []);
    if ($filterPeerId !== null) {
        $peerIds = array_intersect($peerIds, [$filterPeerId]);
    }

    if ($peerIds === []) {
        fwrite(STDERR, "[post_interface] No PostInterface peers configured. Exiting.\n");
        exit(0);
    }

    fwrite(STDERR, sprintf("[post_interface] Active peers: %s\n", implode(', ', $peerIds)));

    if ($once) {
        // Single exchange cycle.
        foreach ($peerIds as $peerId) {
            fwrite(STDERR, sprintf("[post_interface] Exchanging with %s...\n", $peerId));
            $result = $storage->exchangeWithPostInterfacePeer($peerId);
            fwrite(STDERR, sprintf(
                "[post_interface] %s: status=%s sent=%d recv=%d%s\n",
                $peerId,
                $result['status'] ?? '?',
                $result['outbound_packets_sent'] ?? 0,
                $result['delivery_packets_received'] ?? 0,
                isset($result['error']) ? ' error=' . $result['error'] : '',
            ));
        }
        exit(0);
    }

    // Continuous poll loop.
    fwrite(STDERR, "[post_interface] Entering poll loop.\n");

    $peerIntervals = [];
    foreach ($peerIds as $peerId) {
        $peerConfig = $config['post_interface_peers'][$peerId] ?? [];
        $wakeUrl = $peerConfig['wake_url'] ?? null;
        $pollInterval = isset($peerConfig['poll_interval_seconds'])
            ? max((float) $peerConfig['poll_interval_seconds'], MIN_POLL_INTERVAL_SECONDS)
            : DEFAULT_POLL_INTERVAL_SECONDS;

        $peerIntervals[$peerId] = [
            'poll_interval' => $pollInterval,
            'is_wake_mode' => is_string($wakeUrl) && trim($wakeUrl) !== '',
            'last_exchange' => 0.0,
        ];
    }

    while (true) {
        $now = microtime(true);

        foreach ($peerIds as $peerId) {
            $info = $peerIntervals[$peerId];

            // Wake-mode peers don't auto-poll; they wait for incoming wake.
            if ($info['is_wake_mode']) {
                continue;
            }

            if ($now - $info['last_exchange'] < $info['poll_interval']) {
                continue;
            }

            $result = $storage->exchangeWithPostInterfacePeer($peerId);
            $peerIntervals[$peerId]['last_exchange'] = $now;

            if (($result['status'] ?? '') !== 'skipped') {
                fwrite(STDERR, sprintf(
                    "[post_interface] %s: sent=%d recv=%d%s\n",
                    $peerId,
                    $result['outbound_packets_sent'] ?? 0,
                    $result['delivery_packets_received'] ?? 0,
                    isset($result['error']) ? ' error=' . $result['error'] : '',
                ));
            }

            // Flush after each exchange to keep logs current.
            if (($result['delivery_packets_received'] ?? 0) > 0) {
                fflush(STDERR);
            }
        }

        // Sleep a short interval between poll cycles.
        usleep(500000); // 0.5 seconds
    }
}

main();
