<?php

declare(strict_types=1);

/**
 * A TLS wake that runs out of time says so, not "connect failed" (L75).
 *
 * WHAT THIS EXISTS TO PREVENT
 * ===========================
 * From ~10-01 retichat.com logged "[WAKE-DROP] selectivesubconscious.com:443
 * connect failed:  (115)" for its wakes to selectiv: no message, and errno 115,
 * EINPROGRESS. fireAndForgetWakeWithSocket() connects tls:// with
 * STREAM_CLIENT_ASYNC_CONNECT, and PHP finishes the TLS handshake inside
 * stream_socket_client within its 2 s; when TCP and TLS together take longer,
 * it gives up with the connect's EINPROGRESS still in errno. Run here, a peer
 * whose handshake finishes in time gets the wake (a connect in progress alone
 * loses nothing), and one that answers after 2 s loses it. The wake is gone
 * either way; the line must say the 2 s ran out, so it is not read as the
 * peer refusing, and a refusal must still say "connect failed", with how
 * long it took (PHP gives a tls:// one no reason either).
 */

$source = file_get_contents(dirname(__DIR__) . '/src/lib/request_php_wake_trait.php');
if (!preg_match('/    private function fireAndForgetWakeWithSocket\(.*?\n    \}\n/s', $source, $m)) {
    fwrite(STDERR, "FAIL: fireAndForgetWakeWithSocket missing from request_php_wake_trait.php\n");
    exit(1);
}
eval('final class WakeTlsProbe {
    public function send(string $url, string $body): void { $this->fireAndForgetWakeWithSocket($url, $body); }
' . $m[0] . '}');

$failures = 0;
$check = function (bool $ok, string $what, string $detail = '') use (&$failures): void {
    echo ($ok ? "ok   " : "FAIL ") . $what . ($ok || $detail === '' ? '' : " — {$detail}") . "\n";
    if (!$ok) { $failures++; }
};

// A self-signed certificate for the peer; the wake is not what checks it here.
$dir = sys_get_temp_dir() . '/wake-tls-' . bin2hex(random_bytes(4));
mkdir($dir);
$key = openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
$cert = openssl_csr_sign(openssl_csr_new(['commonName' => '127.0.0.1'], $key), null, $key, 2);
openssl_x509_export($cert, $certPem);
openssl_pkey_export($key, $keyPem);
file_put_contents("{$dir}/peer.pem", $certPem . $keyPem);
stream_context_set_default(['ssl' => ['verify_peer' => false, 'verify_peer_name' => false]]);

// The peer: accepts the TCP connection at once, waits $hold seconds, then
// does its side of the TLS handshake and prints the request line it was sent.
file_put_contents("{$dir}/peer.php", <<<'PHP'
<?php
[, $pem, $hold] = $argv;
$ctx = stream_context_create(['ssl' => ['local_cert' => $pem, 'verify_peer' => false]]);
$srv = stream_socket_server('tcp://127.0.0.1:0', $errno, $errstr, STREAM_SERVER_BIND | STREAM_SERVER_LISTEN, $ctx);
echo stream_socket_get_name($srv, false), "\n";
$c = @stream_socket_accept($srv, 10);
if ($c === false) { echo "no client\n"; exit; }
usleep((int) ((float) $hold * 1e6));
stream_set_timeout($c, 3);
if (@stream_socket_enable_crypto($c, true, STREAM_CRYPTO_METHOD_TLS_SERVER) !== true) { echo "no handshake\n"; exit; }
$got = '';
while (!str_contains($got, "\r\n\r\n")) {
    $chunk = fread($c, 4096);
    if ($chunk === '' || $chunk === false) { break; }
    $got .= $chunk;
}
echo 'REQUEST ', strtok($got, "\r\n"), "\n";
PHP);

/** One wake to a peer that holds its handshake $hold s; [what the peer saw, what was logged]. */
$wake = function (float $hold) use ($dir): array {
    $log = "{$dir}/log-{$hold}";
    ini_set('error_log', $log);
    $peer = proc_open([PHP_BINARY, "{$dir}/peer.php", "{$dir}/peer.pem", (string) $hold],
        [1 => ['pipe', 'w']], $pipes);
    $name = trim((string) fgets($pipes[1]));
    (new WakeTlsProbe())->send("https://{$name}/v1/wake", '{"waker_url":"https:\/\/a.test"}');
    $seen = trim((string) stream_get_contents($pipes[1]));
    proc_close($peer);

    return [$seen, trim((string) @file_get_contents($log))];
};

// 1. A handshake inside the 2 s: the wake arrives, nothing is logged.
[$seen, $logged] = $wake(0.3);
$check($seen === 'REQUEST POST /v1/wake HTTP/1.0', 'a peer whose TLS handshake finishes in time gets the wake', $seen);
$check($logged === '', 'and no [WAKE-DROP] is logged', $logged);

// 2. A handshake after the 2 s: the wake is lost, and the line says why.
[$seen, $logged] = $wake(2.6);
$check(!str_contains($seen, 'REQUEST'), 'a peer that answers the handshake after 2 s does not get the wake', $seen);
$check(str_contains($logged, '[WAKE-DROP]') && str_contains($logged, 'did not finish connecting (TCP and TLS) within 2 s'),
    'the drop says the 2 s ran out on TCP and TLS', $logged);
$check(!str_contains($logged, 'connect failed'), 'and does not say "connect failed"', $logged);

// 3. A refusal is still a failed connect, and says how long it took: PHP
// gives no reason for a tls:// one, only the same EINPROGRESS.
$probe = stream_socket_server('tcp://127.0.0.1:0');
$deadName = stream_socket_get_name($probe, false);
fclose($probe); // nothing listens there now
ini_set('error_log', "{$dir}/log-refused");
(new WakeTlsProbe())->send("https://{$deadName}/v1/wake", '{}');
$logged = trim((string) @file_get_contents("{$dir}/log-refused"));
$check(preg_match('/\[WAKE-DROP\] 127\.0\.0\.1:\d+ connect failed after (\d+) ms: /', $logged, $took) === 1
    && (int) $took[1] < 1000,
    'a refused TLS wake says "connect failed" and how soon', $logged);
$check(!str_contains($logged, 'did not finish connecting'), 'and is not taken for a timeout', $logged);

array_map('unlink', glob("{$dir}/*") ?: []);
rmdir($dir);
if ($failures > 0) {
    exit(1);
}
echo "PASS\n";
