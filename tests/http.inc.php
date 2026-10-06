<?php
/** Hilfsfunktionen für die HTTP-Ablauftests (webtest.php, installtest.php). */
declare(strict_types=1);

$fails = 0;
function ok(bool $c, string $m): void
{
    global $fails;
    echo ($c ? '[ok]   ' : '[FAIL] ') . $m . "\n";
    $fails += $c ? 0 : 1;
}

/** HTTP-Anfrage mit Cookie-Jar. Rückgabe: [Status, Header (lowercase => Wert), Body] */
function req(string $method, string $url, array $post = [], string $jar = '', array $hdr = []): array
{
    $ch = curl_init($url);
    $h = [];
    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER => true, CURLOPT_FOLLOWLOCATION => false, CURLOPT_TIMEOUT => 20,
        CURLOPT_HTTPHEADER => $hdr,
        CURLOPT_HEADERFUNCTION => function ($ch, $line) use (&$h) {
            $p = explode(':', $line, 2);
            if (count($p) === 2) {
                $h[strtolower(trim($p[0]))] = trim($p[1]);
            }
            return strlen($line);
        },
    ]);
    if ($jar !== '') {
        curl_setopt($ch, CURLOPT_COOKIEJAR, $jar);
        curl_setopt($ch, CURLOPT_COOKIEFILE, $jar);
    }
    if ($method === 'POST') {
        curl_setopt($ch, CURLOPT_POST, true);
        curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query($post));
    }
    $body = (string)curl_exec($ch);
    $code = (int)curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
    curl_close($ch);
    return [$code, $h, $body];
}

function csrf(string $html): string
{
    return preg_match('/name="_csrf" value="([0-9a-f]+)"/', $html, $m) ? $m[1] : '';
}

/** Noch nicht verwendeter TOTP-Code (Server erlaubt ±1 Zeitschritt, jeder Schritt nur einmal je Benutzer). */
function fresh_code(string $b32): string
{
    static $used = [];
    while (true) {
        $now = intdiv(time(), 30);
        foreach ([0, 1] as $off) { // nicht -1: an einer Schrittgrenze wäre der Code sonst schon zu alt
            if (!isset($used[$b32][$now + $off])) {
                $used[$b32][$now + $off] = true;
                return totp_now($b32, $off);
            }
        }
        sleep(1);
    }
}

function totp_now(string $b32, int $offset = 0): string
{
    $alpha = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    $bits = '';
    foreach (str_split($b32) as $c) {
        $bits .= str_pad(decbin(strpos($alpha, $c)), 5, '0', STR_PAD_LEFT);
    }
    $key = '';
    foreach (str_split($bits, 8) as $b) {
        if (strlen($b) === 8) {
            $key .= chr(bindec($b));
        }
    }
    $hm = hash_hmac('sha1', pack('J', intdiv(time(), 30) + $offset), $key, true);
    $o = ord($hm[19]) & 0x0f;
    return str_pad((string)((unpack('N', substr($hm, $o, 4))[1] & 0x7fffffff) % 1000000), 6, '0', STR_PAD_LEFT);
}


/** php -S mit eigener lokaler Konfiguration starten. Rückgabe: [Prozess, Basis-URL] */
function start_server(string $root, string $local, string $log): array
{
    $port = random_int(20000, 40000);
    $cmd = 'SBCM_LOCAL_CONFIG=' . escapeshellarg($local) . ' exec ' . escapeshellarg(PHP_BINARY)
        . " -S 127.0.0.1:$port -t " . escapeshellarg($root) . ' > ' . escapeshellarg($log) . ' 2>&1';
    $srv = proc_open($cmd, [], $pipes);
    for ($i = 0; $i < 50 && !@fsockopen('127.0.0.1', $port); $i++) {
        usleep(100000);
    }
    return [$srv, "http://127.0.0.1:$port"];
}
