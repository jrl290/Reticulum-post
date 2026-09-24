<?php

declare(strict_types=1);

/**
 * A fire-and-forget wake to an http:// peer must actually leave.
 *
 * WHAT THIS EXISTS TO PREVENT
 * ===========================
 * fireAndForgetWakeWithSocket() opens its socket with
 * STREAM_CLIENT_ASYNC_CONNECT and, for plain TCP, wrote the request at once.
 * The handshake was still in flight, fwrite() returned false, the result was
 * ignored, and the wake was gone without a word. https peers were spared only
 * because the TLS branch blocks through its handshake first. On 2026-09-24 the
 * private staging gateway (wake_url http://127.0.0.1:4371) accepted ONE wake
 * in fifteen minutes; a browser's LINKREQUEST then sat in the PHP queue until
 * the gateway next exchanged for reasons of its own (~50 s), and every web
 * link through staging timed out.
 *
 * The fix waits for the socket to become writable before writing and reports
 * every wake that does not leave as [WAKE-DROP].
 */

$source = file_get_contents(dirname(__DIR__) . '/src/lib/request_php_wake_trait.php');
if (!preg_match('/    private function fireAndForgetWakeWithSocket\(.*?\n    \}\n/s', $source, $m)) {
    fwrite(STDERR, "FAIL: fireAndForgetWakeWithSocket missing from request_php_wake_trait.php\n");
    exit(1);
}
eval('final class WakeSocketProbe {
    public function send(string $url, string $body): void { $this->fireAndForgetWakeWithSocket($url, $body); }
' . $m[0] . '}');

$failures = 0;
$check = function (bool $ok, string $what) use (&$failures): void {
    echo ($ok ? "ok   " : "FAIL ") . $what . "\n";
    if (!$ok) { $failures++; }
};

$logFile = tempnam(sys_get_temp_dir(), 'wake-drop-');
ini_set('error_log', $logFile);

// 1. Every wake to a listening http:// peer arrives whole.
$server = stream_socket_server('tcp://127.0.0.1:0', $errno, $errstr);
$name = stream_socket_get_name($server, false);
$body = '{"waker_url":"http:\/\/127.0.0.1:8080"}';
$arrived = 0;
for ($i = 0; $i < 10; $i++) {
    (new WakeSocketProbe())->send("http://{$name}/v1/wake", $body);
    $conn = stream_socket_accept($server, 2);
    if ($conn === false) { continue; }
    stream_set_timeout($conn, 2);
    $got = (string) stream_get_contents($conn);
    fclose($conn);
    if (str_starts_with($got, 'POST /v1/wake HTTP/1.0') && str_ends_with($got, "\r\n\r\n" . $body)) {
        $arrived++;
    }
}
fclose($server);
$check($arrived === 10, "10 of 10 wakes to an http:// peer arrived whole (got {$arrived})");
$check(trim((string) file_get_contents($logFile)) === '', 'no [WAKE-DROP] logged for delivered wakes');

// 2. A wake that cannot leave says so.
$probe = stream_socket_server('tcp://127.0.0.1:0');
$deadName = stream_socket_get_name($probe, false);
fclose($probe); // nothing listens there now
(new WakeSocketProbe())->send("http://{$deadName}/v1/wake", $body);
$check(str_contains((string) file_get_contents($logFile), '[WAKE-DROP]'), 'a refused wake is logged as [WAKE-DROP]');

@unlink($logFile);
if ($failures > 0) {
    exit(1);
}
echo "PASS\n";
