<?php
/**
 * Ablauftest über HTTP (CLI):  php tests/webtest.php
 * Startet den eingebauten PHP-Webserver (php -S) mit temporärer Konfiguration (SQLite, Mail-Transport "log")
 * und spielt den kompletten Ablauf durch: Login Stufe 1/2, Vorschau, TOTP, Alarm-Mail, Cron per URL, Sperren.
 * Benötigt die curl-Erweiterung.
 */
declare(strict_types=1);

if (PHP_SAPI !== 'cli') {
    http_response_code(404);
    exit;
}
if (!function_exists('curl_init')) {
    fwrite(STDERR, "curl-Erweiterung fehlt – Test übersprungen.\n");
    exit(0);
}

$root = dirname(__DIR__);
$tmp = sys_get_temp_dir() . '/sbcm-webtest-' . bin2hex(random_bytes(4));
mkdir($tmp, 0700, true);
$local = $tmp . '/config.local.inc.php';
$secret = 'JBSWY3DPEHPK3PXP';
$cronToken = bin2hex(random_bytes(16));
$masterKey = base64_encode(random_bytes(32));
file_put_contents($local, "<?php\nreturn " . var_export([
    'app' => ['storage_dir' => $tmp . '/storage', 'base_url' => 'https://status.test'],
    // Standard: SQLite. MySQL/MariaDB wie in selftest.php über SBCM_TEST_DSN / SBCM_TEST_USER / SBCM_TEST_PASS
    'db' => ['dsn' => getenv('SBCM_TEST_DSN') ?: 'sqlite:{storage}/t.sqlite', 'user' => (string)getenv('SBCM_TEST_USER'),
        'pass' => (string)getenv('SBCM_TEST_PASS'), 'prefix' => $prefix = 'wt' . bin2hex(random_bytes(3)) . '_'],
    'mail' => ['transport' => 'log', 'from_email' => 'status@test.example', 'cc_default_mail1' => 'cc1@test.example',
        'recipients' => ['ziel1@ziel.example', 'ziel2@ziel.example']],
    'security' => ['master_key' => $masterKey],
    'auth' => ['stage1_hash' => password_hash('zugang-1234', PASSWORD_DEFAULT),
        'users' => ['anna' => ['name' => 'Anna Test', 'email' => 'anna@test.example',
            'hash' => password_hash('anna-passwort', PASSWORD_DEFAULT), 'totp_secret' => $secret]]],
    'cron' => ['token' => $cronToken],
], true) . ";\n");

$port = random_int(20000, 40000);
$base = "http://127.0.0.1:$port";
$cmd = 'SBCM_LOCAL_CONFIG=' . escapeshellarg($local) . ' exec ' . escapeshellarg(PHP_BINARY)
    . " -S 127.0.0.1:$port -t " . escapeshellarg($root) . ' > ' . escapeshellarg($tmp . '/server.log') . ' 2>&1';
$srv = proc_open($cmd, [], $pipes);
for ($i = 0; $i < 50 && !@fsockopen('127.0.0.1', $port); $i++) {
    usleep(100000);
}

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

try {
    $jar = $tmp . '/jar.txt';

    /* --- Öffentliche Seite / Crawlerschutz --- */
    [$c, $h, $b] = req('GET', "$base/index.php", [], $jar);
    ok($c === 200 && str_contains($b, 'Zugangspasswort'), 'index.php zeigt Login Stufe 1');
    ok(str_contains($h['x-robots-tag'] ?? '', 'noindex') && str_contains($b, 'name="robots" content="noindex'), 'noindex per Header und Meta');
    $csp = $h['content-security-policy'] ?? '';
    ok(str_contains($csp, "default-src 'none'") && !str_contains($csp, 'script-src') && !str_contains($b, '<script'),
        'Strenge CSP, kein JavaScript');
    ok(!str_contains($b, 'Regelbetrieb') && !str_contains($b, 'Standort'), 'Vor dem Login keine Statusinhalte');
    ok(str_contains($csp, "style-src 'self'") && !preg_match('/<style|style="/', $b), 'Keine Inline-Styles (CSP style-src self)');
    ok(str_contains($b, 'assets/bootstrap.min.css?v=') && str_contains($b, 'assets/app.css?v=') && str_contains($b, 'width=device-width'),
        'Lokales Bootstrap + app.css eingebunden, Viewport für Mobilgeräte');
    [$c, $h, $css] = req('GET', "$base/assets/bootstrap.min.css");
    ok($c === 200 && str_contains($css, 'Bootstrap  v5.3.8') && str_contains($h['content-type'] ?? '', 'text/css'), 'bootstrap.min.css wird lokal ausgeliefert');
    [$c, , $css] = req('GET', "$base/assets/app.css");
    ok($c === 200 && str_contains($css, '.status-card'), 'app.css wird ausgeliefert');
    ok(strlen($b) < 4000, 'Login-Seite ist schlank (' . strlen($b) . ' Byte HTML)');
    [$c, , $b] = req('GET', "$base/robots.txt");
    ok($c === 200 && str_contains($b, 'Disallow: /'), 'robots.txt sperrt alles');
    [$c] = req('GET', "$base/status.php", [], $jar);
    ok($c === 302, 'status.php ohne Login -> Umleitung');
    [$c] = req('GET', "$base/change.php", [], $jar);
    ok($c === 302, 'change.php ohne Stufe 1 -> Umleitung');
    foreach (['config.inc.php', 'lib.inc.php'] as $f) {
        [$c, , $b] = req('GET', "$base/$f");
        ok(in_array($c, [403, 404], true) && trim($b) === '', "$f liefert nichts aus ($c)");
    }
    [$c] = req('GET', "$base/setup.php");
    ok($c === 404, 'setup.php ist nur per CLI nutzbar');

    /* --- Login Stufe 1 --- */
    [, , $b] = req('GET', "$base/index.php", [], $jar);
    $t = csrf($b);
    [$c] = req('POST', "$base/index.php", ['password' => 'zugang-1234'], $jar);
    ok($c === 400, 'POST ohne CSRF-Token abgelehnt');
    [$c, , $b] = req('POST', "$base/index.php", ['_csrf' => $t, 'action' => 'login', 'password' => 'falsch'], $jar);
    ok($c === 200 && str_contains($b, 'Anmeldung fehlgeschlagen'), 'Falsches Zugangspasswort abgelehnt');
    [$c, , $b] = req('POST', "$base/index.php", ['_csrf' => $t, 'action' => 'login', 'password' => 'zugang-1234', 'website' => 'http://spam'], $jar);
    ok(str_contains($b, 'Anmeldung fehlgeschlagen'), 'Honeypot-Feld blockiert Bots');
    [$c, $h] = req('POST', "$base/index.php", ['_csrf' => $t, 'action' => 'login', 'password' => 'zugang-1234'], $jar);
    ok($c === 302 && ($h['location'] ?? '') === 'status.php', 'Login Stufe 1 erfolgreich');
    [$c, , $b] = req('GET', "$base/status.php", [], $jar);
    ok($c === 200 && str_contains($b, 'Regelbetrieb'), 'status.php zeigt Regelbetrieb');

    /* --- Login Stufe 2 --- */
    [$c, , $b] = req('GET', "$base/change.php", [], $jar);
    ok($c === 200 && str_contains($b, 'Anmeldung Stufe 2'), 'change.php verlangt Login Stufe 2');
    $t = csrf($b);
    [, , $b] = req('POST', "$base/change.php", ['_csrf' => $t, 'action' => 'login2', 'user' => 'anna', 'password' => 'falsch'], $jar);
    ok(str_contains($b, 'Anmeldung fehlgeschlagen'), 'Falsches persönliches Passwort abgelehnt');
    [$c] = req('POST', "$base/change.php", ['_csrf' => $t, 'action' => 'login2', 'user' => 'anna', 'password' => 'anna-passwort'], $jar);
    ok($c === 302, 'Login Stufe 2 erfolgreich');
    [, , $b] = req('GET', "$base/change.php", [], $jar);
    $t = csrf($b);
    ok(str_contains($b, 'Neuen Status setzen') && str_contains($b, 'Angemeldet als Anna Test'), 'Formular nach Stufe 2 sichtbar');
    ok(!str_contains($b, 'ziel1@') && !str_contains($b, 'ziel2@'), 'Ziel-Adressen erscheinen nicht in der Oberfläche');

    /* --- Formular -> Vorschau -> verbindlich setzen --- */
    [$c, , $b] = req('POST', "$base/change.php", ['_csrf' => $t, 'action' => 'preview', 'mode' => 'set', 'status_key' => 'SICHERHEITSMASSNAHME',
        'validity_type' => 'duration', 'duration' => '240'], $jar);
    ok($c === 200 && str_contains($b, 'mindestens einen Standort'), 'Validierung: Standort fehlt');
    [$c] = req('POST', "$base/change.php", ['_csrf' => $t, 'action' => 'preview', 'mode' => 'set', 'status_key' => 'SICHERHEITSMASSNAHME',
        'loc' => ['muc-sued', 'nue-mitte'], 'validity_type' => 'duration', 'duration' => '240', 'alarm_mail' => '1',
        'note' => 'Übung Leitstelle'], $jar);
    ok($c === 302, 'Vorschau angelegt');
    [, , $b] = req('GET', "$base/change.php", [], $jar);
    ok(str_contains($b, 'Vorschau') && str_contains($b, 'name="totp"') && str_contains($b, 'ALARM-Mail wird versendet'),
        'Vorschau mit TOTP-Feld und Alarm-Hinweis');
    preg_match('/name="pending_id" value="([0-9a-f]+)"/', $b, $m);
    $pid = $m[1] ?? '';
    $jar2 = $tmp . '/jar2.txt';
    [, , $b2] = req('GET', "$base/index.php", [], $jar2);
    req('POST', "$base/index.php", ['_csrf' => csrf($b2), 'action' => 'login', 'password' => 'zugang-1234'], $jar2);
    [, , $b2] = req('GET', "$base/status.php", [], $jar2);
    ok(str_contains($b2, 'Regelbetrieb'), 'Vor dem Bestätigen gilt weiter der alte Status');

    [, , $b] = req('POST', "$base/change.php", ['_csrf' => $t, 'action' => 'commit', 'pending_id' => $pid, 'totp' => '000000'], $jar);
    ok(str_contains($b, 'Bestätigungscode ist ungültig'), 'Falscher TOTP-Code abgelehnt');
    $code = fresh_code($secret);
    [$c] = req('POST', "$base/change.php", ['_csrf' => $t, 'action' => 'commit', 'pending_id' => $pid, 'totp' => $code], $jar);
    ok($c === 302, 'Mit gültigem TOTP verbindlich gesetzt');
    [, , $b] = req('GET', "$base/change.php", [], $jar);
    ok(str_contains($b, 'Status gesetzt: Sicherheitsmaßnahme') && str_contains($b, 'ALARM-Mail an 4 Adressen'), 'Rückmeldung inkl. Alarm-Versand');
    ok(str_contains($b, 'Integrität der Protokollkette: OK'), 'Audit-Kette im Protokoll OK');
    ok(!str_contains($b, 'ziel1@') && str_contains($b, 'recipients: 4'), 'Protokoll zeigt Empfänger nur als Anzahl');

    [, , $b2] = req('GET', "$base/status.php", [], $jar2);
    ok(str_contains($b2, 'Sicherheitsmaßnahme') && str_contains($b2, 'Standort München Süd') && str_contains($b2, '+49 89 12345-110'),
        'Statusseite zeigt neuen Status mit Standort und Durchwahl');
    ok(str_contains($b2, 'Standort Nürnberg Mitte') && str_contains($b2, '+49 30 12345-0'), 'Standort ohne Durchwahl zeigt default_phone');
    ok(!str_contains($b2, 'Übung Leitstelle'), 'Interne Notiz erscheint nicht auf der Statusseite');
    req('GET', "$base/status.php", [], $jar2);
    [, , $b] = req('GET', "$base/change.php", [], $jar);
    ok(str_contains($b, 'gelesen: 1'), 'Lesezähler zählt den Aufruf einmal je Sitzung');
    ok(preg_match('#Stufe 1 \(gemeinsames Passwort\)</td><td class="text-end">2</td>#', $b) === 1, 'Nutzung zeigt Anmeldungen Stufe 1');
    ok(str_contains($b, 'Stufe 2: Anna Test'), 'Nutzung zeigt Anmeldungen Stufe 2 je Benutzer');
    ok(!preg_match('/<style|style="/', $b), 'Auch Stufe 2 ohne Inline-Styles');

    // Replay: gleicher Code für die nächste Änderung
    req('POST', "$base/change.php", ['_csrf' => $t, 'action' => 'preview', 'mode' => 'extend', 'validity_type' => 'duration', 'duration' => '60'], $jar);
    [, , $b] = req('GET', "$base/change.php", [], $jar);
    preg_match('/name="pending_id" value="([0-9a-f]+)"/', $b, $m);
    [, , $b] = req('POST', "$base/change.php", ['_csrf' => $t, 'action' => 'commit', 'pending_id' => $m[1] ?? '', 'totp' => $code], $jar);
    ok(str_contains($b, 'bereits verwendet'), 'TOTP-Replay wird abgelehnt');
    req('POST', "$base/change.php", ['_csrf' => $t, 'action' => 'cancel'], $jar);

    // Beenden (ohne TOTP)
    req('POST', "$base/change.php", ['_csrf' => $t, 'action' => 'preview', 'mode' => 'end'], $jar);
    [, , $b] = req('GET', "$base/change.php", [], $jar);
    preg_match('/name="pending_id" value="([0-9a-f]+)"/', $b, $m);
    ok(!str_contains($b, 'name="totp"'), 'Beenden braucht kein TOTP');
    req('POST', "$base/change.php", ['_csrf' => $t, 'action' => 'commit', 'pending_id' => $m[1] ?? ''], $jar);
    [, , $b2] = req('GET', "$base/status.php", [], $jar2);
    ok(str_contains($b2, 'Regelbetrieb'), 'Status beendet -> Regelbetrieb');
    [, , $b] = req('GET', "$base/change.php", [], $jar);
    ok(substr_count($b, 'Sicherheitsmaßnahme') >= 2 && str_contains($b, 'Status beendet'), 'Historie und Protokoll vollständig');
    ok(str_contains($b, 'href="admin.php"'), 'Admin sieht den Menüpunkt Benutzer');

    /* --- Benutzerverwaltung --- */
    [$c, , $b] = req('GET', "$base/admin.php", [], $jar);
    ok($c === 200 && str_contains($b, 'Benutzerverwaltung') && str_contains($b, 'Anna Test'), 'admin.php für Admin erreichbar');
    $new = ['_csrf' => $t, 'action' => 'create', 'id' => 'carla', 'name' => 'Carla Redaktion', 'email' => 'carla@test.example', 'role' => 'editor'];
    [, , $b] = req('POST', "$base/admin.php", $new + ['totp' => '000000'], $jar);
    ok(str_contains($b, 'Bestätigungscode ist ungültig'), 'Benutzer anlegen ohne gültigen TOTP-Code abgelehnt');
    [$c] = req('POST', "$base/admin.php", $new + ['totp' => fresh_code($secret)], $jar);
    [, , $b] = req('GET', "$base/admin.php", [], $jar);
    preg_match('/Einmalpasswort für carla: ([A-Za-z0-9-]{19})/', $b, $m);
    $once = $m[1] ?? '';
    ok($c === 302 && $once !== '' && str_contains($b, 'Carla Redaktion') && str_contains($b, 'Einmalpasswort offen'), 'Benutzer angelegt, Einmalpasswort einmalig angezeigt');
    [, , $b] = req('GET', "$base/admin.php", [], $jar);
    ok(!str_contains($b, $once), 'Einmalpasswort wird nicht erneut angezeigt');

    $jar4 = $tmp . '/jar4.txt';
    [, , $b] = req('GET', "$base/index.php", [], $jar4);
    $t4 = csrf($b);
    req('POST', "$base/index.php", ['_csrf' => $t4, 'action' => 'login', 'password' => 'zugang-1234'], $jar4);
    [, , $b] = req('GET', "$base/change.php", [], $jar4);
    $t4 = csrf($b);
    [$c] = req('POST', "$base/change.php", ['_csrf' => $t4, 'action' => 'login2', 'user' => 'carla', 'password' => $once], $jar4);
    [, , $b] = req('GET', "$base/change.php", [], $jar4);
    ok($c === 302 && str_contains($b, 'Zugang einrichten') && !str_contains($b, 'Neuen Status setzen'), 'Erster Login: nur Einrichtung möglich');
    preg_match('/font-monospace text-break my-2">([A-Z2-7 ]+)</', $b, $m);
    $carlaSecret = str_replace(' ', '', $m[1] ?? '');
    [, , $b] = req('POST', "$base/change.php", ['_csrf' => $t4, 'action' => 'preview', 'mode' => 'end'], $jar4);
    ok(str_contains($b, 'Bitte zuerst Passwort'), 'Status ändern vor der Einrichtung gesperrt');
    [, , $b] = req('POST', "$base/change.php", ['_csrf' => $t4, 'action' => 'setup', 'old_password' => $once, 'new_password' => 'kurz',
        'new_password2' => 'kurz', 'totp' => '000000'], $jar4);
    ok(str_contains($b, 'mindestens 12 Zeichen') && str_contains($b, 'Authenticator-App ist ungültig'), 'Einrichtung prüft Passwortregeln und App-Code');
    [$c] = req('POST', "$base/change.php", ['_csrf' => $t4, 'action' => 'setup', 'old_password' => $once, 'new_password' => 'Ein langer Satz als Passwort',
        'new_password2' => 'Ein langer Satz als Passwort', 'totp' => fresh_code($carlaSecret)], $jar4);
    [, , $b] = req('GET', "$base/change.php", [], $jar4);
    ok($c === 302 && str_contains($b, 'Einrichtung abgeschlossen') && str_contains($b, 'Neuen Status setzen'), 'Einrichtung abgeschlossen, Status setzen freigeschaltet');
    ok(!str_contains($b, 'href="admin.php"'), 'Redaktion sieht keinen Menüpunkt Benutzer');
    [$c, , $b] = req('GET', "$base/admin.php", [], $jar4);
    ok($c === 403 && str_contains($b, 'Admins vorbehalten'), 'admin.php für Redaktion gesperrt');

    [$c] = req('POST', "$base/admin.php", ['_csrf' => $t, 'action' => 'disable', 'id' => 'carla', 'totp' => fresh_code($secret)], $jar);
    [, , $b] = req('GET', "$base/change.php", [], $jar4);
    ok($c === 302 && str_contains($b, 'Anmeldung Stufe 2'), 'Deaktivierter Benutzer verliert sofort den Zugang');
    [, , $b] = req('GET', "$base/change.php", [], $jar);
    ok(str_contains($b, 'Benutzer angelegt') && str_contains($b, 'TOTP gekoppelt') && str_contains($b, 'Benutzer deaktiviert')
        && str_contains($b, 'Integrität der Protokollkette: OK'), 'Benutzerverwaltung lückenlos im Protokoll');

    /* --- Alarm-Mail im Ausgang (BCC) --- */
    $alarm = '';
    foreach (glob($tmp . '/storage/outbox/*.eml') ?: [] as $f) {
        $x = (string)file_get_contents($f);
        if (str_contains($x, 'ziel1@ziel.example')) {
            $alarm = $x;
        }
    }
    $vis = preg_replace('/^X-Envelope-Rcpt:.*\r\n/', '', $alarm) ?? '';
    ok($alarm !== '' && str_contains($vis, 'To: undisclosed-recipients:;') && !str_contains($vis, 'ziel'), 'Alarm-Mail nur per BCC');

    /* --- Cron per URL --- */
    [$c] = req('GET', "$base/cron.php");
    ok($c === 403, 'cron.php ohne Token verboten');
    [$c] = req('GET', "$base/cron.php?t=falsch");
    ok($c === 403, 'cron.php mit falschem Token verboten');
    [$c, , $b] = req('GET', "$base/cron.php", [], '', ['X-Cron-Token: ' . $cronToken]);
    ok($c === 200 && trim($b) === 'ok', 'cron.php mit Token-Header läuft');

    /* --- Abmelden, Brute-Force-Sperre --- */
    [, , $b] = req('GET', "$base/status.php", [], $jar2);
    req('POST', "$base/index.php", ['_csrf' => csrf($b), 'action' => 'logout'], $jar2);
    [$c] = req('GET', "$base/status.php", [], $jar2);
    ok($c === 302, 'Nach Abmelden kein Zugriff mehr');
    $jar3 = $tmp . '/jar3.txt';
    [, , $b] = req('GET', "$base/index.php", [], $jar3);
    $t3 = csrf($b);
    for ($i = 0; $i < 4; $i++) {
        req('POST', "$base/index.php", ['_csrf' => $t3, 'action' => 'login', 'password' => 'falsch' . $i], $jar3);
    }
    [, , $b] = req('POST', "$base/index.php", ['_csrf' => $t3, 'action' => 'login', 'password' => 'zugang-1234'], $jar3);
    ok(str_contains($b, 'Zu viele Versuche'), 'Brute-Force-Sperre greift auch für das richtige Passwort');

    $log = (string)@file_get_contents($tmp . '/server.log');
    ok(!preg_match('/PHP (Warning|Notice|Deprecated|Fatal)/', $log), 'Keine PHP-Warnungen im Server-Log');
} finally {
    proc_terminate($srv);
    proc_close($srv);
    if ($fails > 0) {
        echo "\nServer-Log (Auszug):\n" . implode("\n", preg_grep('/PHP |\[(4|5)\d\d\]/', file($tmp . '/server.log', FILE_IGNORE_NEW_LINES) ?: []) ?: []) . "\n";
    }
    exec('rm -rf ' . escapeshellarg($tmp));
    if (str_starts_with((string)getenv('SBCM_TEST_DSN'), 'mysql:')) {
        $pdo = new PDO((string)getenv('SBCM_TEST_DSN'), (string)getenv('SBCM_TEST_USER'), (string)getenv('SBCM_TEST_PASS'));
        foreach (['audit_no_upd', 'audit_no_del', 'status_no_del', 'account_no_del'] as $tr) {
            $pdo->exec("DROP TRIGGER IF EXISTS {$prefix}$tr");
        }
        foreach (['status', 'audit', 'mail_log', 'login_attempt', 'totp_used', 'kv', 'view_count', 'account'] as $tb) {
            $pdo->exec("DROP TABLE IF EXISTS {$prefix}$tb");
        }
    }
}

echo $fails === 0 ? "\nAlle Ablauftests bestanden.\n" : "\n$fails Ablauftest(s) fehlgeschlagen.\n";
exit($fails === 0 ? 0 : 1);
