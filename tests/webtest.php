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
    'channels' => ['signal' => ['url' => 'https://signal.test/v2/send', 'number' => '+491700000000', 'token' => 'sig-geheim'],
        'groupalarm' => ['token' => 'ga-geheim', 'organization_id' => 4711]],
    'monitor' => ['health_token' => 'hc-token'],
], true) . ";\n");

$port = random_int(20000, 40000);
$base = "http://127.0.0.1:$port";
$cmd = 'SBCM_LOCAL_CONFIG=' . escapeshellarg($local) . ' exec ' . escapeshellarg(PHP_BINARY)
    . " -S 127.0.0.1:$port -t " . escapeshellarg($root) . ' > ' . escapeshellarg($tmp . '/server.log') . ' 2>&1';
$srv = proc_open($cmd, [], $pipes);
for ($i = 0; $i < 50 && !@fsockopen('127.0.0.1', $port); $i++) {
    usleep(100000);
}

require __DIR__ . '/http.inc.php';

try {
    $jar = $tmp . '/jar.txt';

    /* --- Öffentliche Seite / Crawlerschutz --- */
    [$c, $h, $b] = req('GET', "$base/index.php", [], $jar);
    ok($c === 200 && str_contains($b, 'Benutzername') && str_contains($b, 'Passwort'), 'index.php zeigt das Anmeldeformular');
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
    foreach (['config.inc.php', 'lib.inc.php', 'qr.inc.php', 'pdf.inc.php'] as $f) {
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
    [$c, , $b] = req('POST', "$base/index.php", ['_csrf' => $t, 'action' => 'login', 'user' => 'zugang', 'password' => 'falsch'], $jar);
    ok($c === 200 && str_contains($b, 'Anmeldung fehlgeschlagen'), 'Falsches Zugangspasswort abgelehnt');
    [$c, , $b] = req('POST', "$base/index.php", ['_csrf' => $t, 'action' => 'login', 'user' => 'zugang', 'password' => 'zugang-1234', 'website' => 'http://spam'], $jar);
    ok(str_contains($b, 'Anmeldung fehlgeschlagen'), 'Honeypot-Feld blockiert Bots');
    [$c, $h] = req('POST', "$base/index.php", ['_csrf' => $t, 'action' => 'login', 'user' => 'zugang', 'password' => 'zugang-1234'], $jar);
    ok($c === 302 && ($h['location'] ?? '') === 'status.php', 'Login Stufe 1 erfolgreich');
    $jarU = $tmp . '/jarU.txt';
    [, , $b] = req('GET', "$base/index.php", [], $jarU);
    ok(str_contains($b, 'name="user"') && str_contains($b, 'name="password"'), 'Startseite: ein Formular mit Benutzername und Passwort');
    $tU = csrf($b);
    [$c, , $b] = req('POST', "$base/index.php", ['_csrf' => $tU, 'action' => 'login', 'user' => 'anna', 'password' => 'zugang-1234'], $jarU);
    ok($c === 200 && str_contains($b, 'Anmeldung fehlgeschlagen'), 'Zugangspasswort mit persönlicher Kennung abgelehnt');
    [$c, $h] = req('POST', "$base/index.php", ['_csrf' => $tU, 'action' => 'login', 'user' => ' Zugang ', 'password' => 'zugang-1234'], $jarU);
    [, , $b] = req('GET', "$base/change.php", [], $jarU);
    ok($c === 302 && str_contains($b, 'Anmeldung Stufe 2'), 'Gemeinsamer Zugang (Groß-/Kleinschreibung egal) führt nur zum Lesen');
    $jarA = $tmp . '/jarA.txt';
    [, , $b] = req('GET', "$base/index.php", [], $jarA);
    [$c, , $b] = req('POST', "$base/index.php", ['_csrf' => csrf($b), 'action' => 'login', 'user' => 'Anna', 'password' => 'anna-passwort'], $jarA);
    ok($c === 200 && str_contains($b, 'name="totp"') && str_contains($b, 'value="login_totp"'), 'Persönliche Kennung: nach dem Passwort wird der TOTP-Code verlangt');
    [$c] = req('GET', "$base/status.php", [], $jarA);
    ok($c === 302, 'Ohne TOTP-Code noch kein Zugriff auf die Statusseite');
    // (falsche Codes zählen gemeinsam für die TOTP-Sperre; abgelehnte Codes prüfen Commit und Benutzerverwaltung)
    [$c, $h] = req('POST', "$base/index.php", ['_csrf' => csrf($b), 'action' => 'login_totp', 'totp' => fresh_code($secret)], $jarA);
    [, , $b] = req('GET', "$base/change.php", [], $jarA);
    ok($c === 302 && ($h['location'] ?? '') === 'status.php' && str_contains($b, 'Neue Meldung') && str_contains($b, 'Angemeldet als Anna Test'),
        'Persönliche Kennung auf der Startseite: mit TOTP direkt mit Einstellungen angemeldet');
    [$c, , $b] = req('GET', "$base/status.php", [], $jar);
    ok($c === 200 && str_contains($b, 'Regelbetrieb'), 'status.php zeigt Regelbetrieb');

    /* --- Login Stufe 2 --- */
    [$c, , $b] = req('GET', "$base/change.php", [], $jar);
    ok($c === 200 && str_contains($b, 'Anmeldung Stufe 2'), 'change.php verlangt Login Stufe 2');
    $t = csrf($b);
    [, , $b] = req('POST', "$base/change.php", ['_csrf' => $t, 'action' => 'login2', 'user' => 'anna', 'password' => 'falsch'], $jar);
    ok(str_contains($b, 'Anmeldung fehlgeschlagen'), 'Falsches persönliches Passwort abgelehnt');
    [$c, , $b] = req('POST', "$base/change.php", ['_csrf' => $t, 'action' => 'login2', 'user' => 'anna', 'password' => 'anna-passwort'], $jar);
    ok($c === 200 && str_contains($b, 'value="login_totp"') && !str_contains($b, 'Neue Meldung'), 'Login Stufe 2 verlangt nach dem Passwort den TOTP-Code');
    [$c] = req('POST', "$base/change.php", ['_csrf' => csrf($b), 'action' => 'login_totp', 'totp' => fresh_code($secret)], $jar);
    ok($c === 302, 'Login Stufe 2 mit TOTP erfolgreich');
    [, , $b] = req('GET', "$base/change.php", [], $jar);
    $t = csrf($b);
    ok(str_contains($b, 'Neue Meldung') && str_contains($b, 'Angemeldet als Anna Test'), 'Formular nach Stufe 2 sichtbar');
    ok(!str_contains($b, 'ziel1@') && !str_contains($b, 'ziel2@'), 'Ziel-Adressen erscheinen nicht in der Oberfläche');

    /* --- Formular -> Vorschau -> verbindlich setzen --- */
    [$c, , $b] = req('POST', "$base/change.php", ['_csrf' => $t, 'action' => 'preview', 'mode' => 'set', 'status_key' => 'SICHERHEITSMASSNAHME',
        'validity_type' => 'duration', 'duration' => '240'], $jar);
    ok($c === 200 && str_contains($b, 'mindestens einen Standort'), 'Validierung: Standort fehlt');
    [$c] = req('POST', "$base/change.php", ['_csrf' => $t, 'action' => 'preview', 'mode' => 'set', 'status_key' => 'SICHERHEITSMASSNAHME',
        'loc' => ['muc-sued', 'nue-mitte'], 'validity_type' => 'duration', 'duration' => '240', 'alarm_mail' => '1', 'circles' => ['allgemein'],
        'note' => 'Übung Leitstelle'], $jar);
    ok($c === 302, 'Vorschau angelegt');
    [, , $b] = req('GET', "$base/change.php", [], $jar);
    ok(str_contains($b, 'Vorschau') && str_contains($b, 'name="totp"') && str_contains($b, 'ALARM-Mail wird versendet'),
        'Vorschau mit TOTP-Feld und Alarm-Hinweis');
    preg_match('/name="pending_id" value="([0-9a-f]+)"/', $b, $m);
    $pid = $m[1] ?? '';
    $jar2 = $tmp . '/jar2.txt';
    [, , $b2] = req('GET', "$base/index.php", [], $jar2);
    req('POST', "$base/index.php", ['_csrf' => csrf($b2), 'action' => 'login', 'user' => 'zugang', 'password' => 'zugang-1234'], $jar2);
    [, , $b2] = req('GET', "$base/status.php", [], $jar2);
    ok(str_contains($b2, 'Regelbetrieb'), 'Vor dem Bestätigen gilt weiter der alte Status');

    [, , $b] = req('POST', "$base/change.php", ['_csrf' => $t, 'action' => 'commit', 'pending_id' => $pid, 'totp' => '000000'], $jar);
    ok(str_contains($b, 'Bestätigungscode ist ungültig'), 'Falscher TOTP-Code abgelehnt');
    $code = fresh_code($secret);
    [$c] = req('POST', "$base/change.php", ['_csrf' => $t, 'action' => 'commit', 'pending_id' => $pid, 'totp' => $code], $jar);
    ok($c === 302, 'Mit gültigem TOTP verbindlich gesetzt');
    [, , $b] = req('GET', "$base/change.php", [], $jar);
    ok(str_contains($b, 'Meldung gesetzt: Sicherheitsmaßnahme') && str_contains($b, 'ALARM-Mail an 4 Adressen'), 'Rückmeldung inkl. Alarm-Versand');
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
    ok(preg_match('#Stufe 1 \(gemeinsames Passwort\)</td><td class="text-end">3</td>#', $b) === 1, 'Nutzung zeigt Anmeldungen Stufe 1');
    ok(str_contains($b, 'Stufe 2: Anna Test'), 'Nutzung zeigt Anmeldungen Stufe 2 je Benutzer');
    ok(!preg_match('/<style|style="/', $b), 'Auch Stufe 2 ohne Inline-Styles');

    preg_match('/name="target" value="(\d+)"/', $b, $m);
    $tgt = $m[1] ?? '';
    // Replay: gleicher Code für die nächste Änderung
    req('POST', "$base/change.php", ['_csrf' => $t, 'action' => 'preview', 'mode' => 'extend', 'target' => $tgt, 'validity_type' => 'duration', 'duration' => '60'], $jar);
    [, , $b] = req('GET', "$base/change.php", [], $jar);
    preg_match('/name="pending_id" value="([0-9a-f]+)"/', $b, $m);
    [, , $b] = req('POST', "$base/change.php", ['_csrf' => $t, 'action' => 'commit', 'pending_id' => $m[1] ?? '', 'totp' => $code], $jar);
    ok(str_contains($b, 'bereits verwendet'), 'TOTP-Replay wird abgelehnt');
    req('POST', "$base/change.php", ['_csrf' => $t, 'action' => 'cancel'], $jar);

    // Zweite Meldung gleichzeitig (Hinweis, ohne TOTP)
    [$c] = req('POST', "$base/change.php", ['_csrf' => $t, 'action' => 'preview', 'mode' => 'set', 'status_key' => 'HINWEIS',
        'validity_type' => 'duration', 'duration' => '60'], $jar);
    [, , $b] = req('GET', "$base/change.php", [], $jar);
    preg_match('/name="pending_id" value="([0-9a-f]+)"/', $b, $m);
    req('POST', "$base/change.php", ['_csrf' => $t, 'action' => 'commit', 'pending_id' => $m[1] ?? ''], $jar);
    [, , $b2] = req('GET', "$base/status.php", [], $jar2);
    ok(str_contains($b2, 'Sicherheitsmaßnahme') && str_contains($b2, 'Organisatorischer Hinweis') && strpos($b2, 'Sicherheitsmaßnahme') < strpos($b2, 'Organisatorischer Hinweis'),
        'Zwei Meldungen gleichzeitig, kritische zuerst');
    [, , $b] = req('GET', "$base/change.php", [], $jar);
    ok(str_contains($b, 'Aktuelle Meldungen (2)'), 'Einstellungen zeigen beide Meldungen zur Bearbeitung');

    // Beenden einer Warnung: TOTP wie beim Setzen
    req('POST', "$base/change.php", ['_csrf' => $t, 'action' => 'preview', 'mode' => 'end', 'target' => $tgt, 'note' => 'gelöst'], $jar);
    [, , $b] = req('GET', "$base/change.php", [], $jar);
    preg_match('/name="pending_id" value="([0-9a-f]+)"/', $b, $m);
    ok(str_contains($b, 'name="totp"'), 'Beenden einer Warnung verlangt TOTP');
    req('POST', "$base/change.php", ['_csrf' => $t, 'action' => 'commit', 'pending_id' => $m[1] ?? '', 'totp' => fresh_code($secret)], $jar);
    [, , $b2] = req('GET', "$base/status.php", [], $jar2);
    ok(!str_contains($b2, 'Regelbetrieb') && str_contains($b2, 'Zurückgenommen / gelöst') && str_contains($b2, 'status-gone'),
        'Beendete Meldung bleibt ausgegraut sichtbar, die andere gilt weiter');
    [, , $b] = req('GET', "$base/change.php", [], $jar);
    ok(substr_count($b, 'Sicherheitsmaßnahme') >= 2 && str_contains($b, 'Meldung beendet') && str_contains($b, 'Aktuelle Meldungen (1)'),
        'Historie und Protokoll vollständig');
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
    req('POST', "$base/index.php", ['_csrf' => $t4, 'action' => 'login', 'user' => 'zugang', 'password' => 'zugang-1234'], $jar4);
    [, , $b] = req('GET', "$base/change.php", [], $jar4);
    $t4 = csrf($b);
    [$c] = req('POST', "$base/change.php", ['_csrf' => $t4, 'action' => 'login2', 'user' => 'carla', 'password' => $once], $jar4);
    [, , $b] = req('GET', "$base/change.php", [], $jar4);
    ok($c === 302 && str_contains($b, 'Zugang einrichten') && !str_contains($b, 'Neue Meldung'), 'Erster Login: nur Einrichtung möglich');
    ok(str_contains($b, 'class="qr-code" src="data:image/svg+xml;base64,'), 'QR-Code für die Authenticator-App wird angezeigt');
    preg_match('/font-monospace text-break my-1">([A-Z2-7 ]+)</', $b, $m);
    $carlaSecret = str_replace(' ', '', $m[1] ?? '');
    [, , $b] = req('POST', "$base/change.php", ['_csrf' => $t4, 'action' => 'preview', 'mode' => 'end'], $jar4);
    ok(str_contains($b, 'Bitte zuerst Passwort'), 'Status ändern vor der Einrichtung gesperrt');
    [, , $b] = req('POST', "$base/change.php", ['_csrf' => $t4, 'action' => 'setup', 'old_password' => $once, 'new_password' => 'kurz',
        'new_password2' => 'kurz', 'totp' => '000000'], $jar4);
    ok(str_contains($b, 'mindestens 12 Zeichen') && str_contains($b, 'Authenticator-App ist ungültig'), 'Einrichtung prüft Passwortregeln und App-Code');
    [$c] = req('POST', "$base/change.php", ['_csrf' => $t4, 'action' => 'setup', 'old_password' => $once, 'new_password' => 'Ein langer Satz als Passwort',
        'new_password2' => 'Ein langer Satz als Passwort', 'totp' => fresh_code($carlaSecret)], $jar4);
    [, , $b] = req('GET', "$base/change.php", [], $jar4);
    ok($c === 302 && str_contains($b, 'Einrichtung abgeschlossen') && str_contains($b, 'Neue Meldung'), 'Einrichtung abgeschlossen, Status setzen freigeschaltet');
    ok(!str_contains($b, 'href="admin.php"'), 'Redaktion sieht keinen Menüpunkt Benutzer');
    [$c, , $b] = req('GET', "$base/admin.php", [], $jar4);
    ok($c === 403 && str_contains($b, 'Admins vorbehalten'), 'admin.php für Redaktion gesperrt');
    [$c, , $b] = req('GET', "$base/system.php", [], $jar4);
    ok($c === 403 && str_contains($b, 'Admins vorbehalten'), 'system.php für Redaktion gesperrt');

    [$c] = req('POST', "$base/admin.php", ['_csrf' => $t, 'action' => 'disable', 'id' => 'carla', 'totp' => fresh_code($secret)], $jar);
    [, , $b] = req('GET', "$base/change.php", [], $jar4);
    ok($c === 302 && str_contains($b, 'Anmeldung Stufe 2'), 'Deaktivierter Benutzer verliert sofort den Zugang');
    [, , $b] = req('GET', "$base/change.php", [], $jar);
    ok(str_contains($b, 'Benutzer angelegt') && str_contains($b, 'TOTP gekoppelt') && str_contains($b, 'Benutzer deaktiviert')
        && str_contains($b, 'Integrität der Protokollkette: OK'), 'Benutzerverwaltung lückenlos im Protokoll');

    /* --- System: Alarmkreise, Standort-Adressen, Kontakte, Präfixe --- */
    [$c, , $b] = req('GET', "$base/system.php", [], $jar);
    ok($c === 200 && str_contains($b, 'Alarmkreise (1)') && str_contains($b, 'Allgemein') && !str_contains($b, 'ziel1@'), 'System zeigt bisherige Empfänger als Kreis "Allgemein", maskiert');
    [$c] = req('POST', "$base/system.php", ['_csrf' => $t, 'action' => 'circle_create', 'name' => 'IT', 'emails' => "it@ziel.example", 'totp' => fresh_code($secret)], $jar);
    [$c2] = req('POST', "$base/system.php", ['_csrf' => $t, 'action' => 'location_save', 'id' => 'ham-hafen', 'name' => 'Standort Hamburg Hafen',
        'phone' => '', 'emails' => 'verwaltung.ham@ziel.example', 'totp' => fresh_code($secret)], $jar);
    [$c3] = req('POST', "$base/system.php", ['_csrf' => $t, 'action' => 'contact_save', 'id' => '', 'name' => 'Krisenstab-Konferenz', 'platform' => 'Teams',
        'url' => 'https://teams.example/meet/1', 'totp' => fresh_code($secret)], $jar);
    [$c4] = req('POST', "$base/system.php", ['_csrf' => $t, 'action' => 'prefix', 'new' => '[NOTFALL]', 'update' => '[Update]', 'end' => '[Entwarnung]',
        'totp' => fresh_code($secret)], $jar);
    [, , $b] = req('GET', "$base/system.php", [], $jar);
    ok($c === 302 && $c2 === 302 && $c3 === 302 && $c4 === 302 && str_contains($b, 'Alarmkreise (2)') && str_contains($b, 'Kontakte für Meldungen (1)')
        && str_contains($b, 'value="[NOTFALL]"'), 'Kreis, Standort-Adresse, Kontakt und Präfixe gespeichert');
    ok(!str_contains($b, 'verwaltung.ham@') && !str_contains($b, 'it@ziel') && preg_match('/v\*+@z\*+\.example/', $b) === 1,
        'Standort- und Kreisadressen nur maskiert');
    [, , $b2] = req('GET', "$base/status.php", [], $jar2);
    ok(!str_contains($b2, 'verwaltung') && !str_contains($b2, 'ziel.example'), 'Statusseite zeigt keine Verteiler-Adressen');
    [, , $b] = req('GET', "$base/change.php", [], $jar);
    ok(str_contains($b, 'name="circles[]" value="it"') && str_contains($b, 'Krisenstab-Konferenz'), 'Kreise und Kontakte im Meldungsformular wählbar');
    [, , $b] = req('GET', "$base/change.php", [], $jar);
    ok(str_contains($b, 'Alarmkreis angelegt') && str_contains($b, 'Betreff-Präfixe geändert') && str_contains($b, 'Integrität der Protokollkette: OK'),
        'Systemänderungen im Protokoll');

    /* --- Signal und GroupAlarm je Kreis --- */
    [, , $b] = req('POST', "$base/system.php", ['_csrf' => $t, 'action' => 'circle_channels', 'id' => 'it', 'signal' => "0170 123", 'groupalarm' => '',
        'totp' => fresh_code($secret)], $jar);
    ok(str_contains($b, 'alert-danger'), 'Ungültige Signal-Nummer abgelehnt');
    [$c] = req('POST', "$base/system.php", ['_csrf' => $t, 'action' => 'circle_channels', 'id' => 'it', 'signal' => "+49 170 1234567\ngroup.YWJjZGVmZ2hpams=",
        'groupalarm' => '42', 'totp' => fresh_code($secret)], $jar);
    [, , $b] = req('GET', "$base/system.php", [], $jar);
    ok($c === 302 && str_contains($b, '2 Signal, GroupAlarm-Szenario 42') && !str_contains($b, '1234567'), 'Signal-Empfänger und GroupAlarm-Szenario gespeichert, Nummern maskiert');
    [$c] = req('POST', "$base/system.php", ['_csrf' => $t, 'action' => 'signal_test', 'id' => 'it', 'totp' => fresh_code($secret)], $jar);
    $sig = '';
    foreach (glob($tmp . '/storage/outbox/*-signal-*.json') ?: [] as $f) {
        $sig = (string)file_get_contents($f);
    }
    $sj = json_decode($sig, true) ?: [];
    ok($c === 302 && ($sj['url'] ?? '') === 'https://signal.test/v2/send' && ($sj['body']['recipients'] ?? []) === ['+491701234567', 'group.YWJjZGVmZ2hpams=']
        && !str_contains($sig, 'sig-geheim'), 'Signal-Testnachricht an signal-cli-rest-api übergeben, Token nicht im Ausgang');
    ok(glob($tmp . '/storage/outbox/*-groupalarm-*.json') === [], 'Testnachricht löst kein GroupAlarm aus');

    /* --- Aushang, Protokoll-Export, Gesundheitsprüfung --- */
    [$c, , $b] = req('GET', "$base/aushang.php?kennung=1&hinweis=Passwort+im+Notfallordner", [], $jar);
    ok($c === 200 && str_contains($b, 'class="qr-code aushang-qr" src="data:image/svg+xml;base64,') && str_contains($b, 'https://status.test/')
        && str_contains($b, 'Benutzernamen <strong>zugang</strong>') && str_contains($b, 'Passwort im Notfallordner') && !str_contains($b, 'zugang-1234'),
        'Aushang mit QR-Code, Adresse und Benutzername, ohne Passwort');
    [$c] = req('GET', "$base/aushang.php", [], $jar2);
    ok($c === 302, 'Aushang nur mit persönlicher Anmeldung');
    [$c, $h, $csv] = req('POST', "$base/export.php", ['_csrf' => $t, 'format' => 'csv'], $jar);
    ok($c === 200 && str_contains($h['content-type'] ?? '', 'text/csv') && str_contains($csv, 'Meldung gesetzt') && str_contains($csv, 'Integrität der Protokollkette: OK')
        && !str_contains($csv, '127.0.0.1'), 'CSV-Export mit Integritätsprüfung, ohne IP-Adressen');
    [$c, , $csv] = req('POST', "$base/export.php", ['_csrf' => $t, 'format' => 'csv', 'with_ip' => '1', 'from' => date('Y-m-d'), 'to' => date('Y-m-d')], $jar);
    ok($c === 200 && str_contains($csv, '127.0.0.1'), 'CSV-Export auf Wunsch mit IP-Adressen');
    [$c, $h, $pdf] = req('POST', "$base/export.php", ['_csrf' => $t, 'format' => 'pdf'], $jar);
    ok($c === 200 && str_starts_with($pdf, '%PDF-1.4') && str_contains($h['content-type'] ?? '', 'application/pdf') && str_contains($pdf, '%%EOF'), 'PDF-Export');
    [$c] = req('POST', "$base/export.php", ['_csrf' => $t, 'format' => 'csv'], $jar2);
    ok($c === 302, 'Export nur für Admins');
    [, , $b] = req('GET', "$base/change.php", [], $jar);
    ok(str_contains($b, 'Protokoll exportiert') && str_contains($b, 'Integrität der Protokollkette: OK'), 'Export im Protokoll vermerkt');
    [$c, , $b] = req('GET', "$base/health.php");
    ok($c === 403, 'health.php ohne Token verboten (wenn Token gesetzt)');
    [$c, , $b] = req('GET', "$base/health.php?t=hc-token");
    ok($c === 503 && trim($b) === 'cron', 'health.php meldet 503, solange der Cron nie lief');

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
    [$c, , $b] = req('GET', "$base/health.php", [], '', ['X-Health-Token: hc-token']);
    ok($c === 200 && trim($b) === 'ok', 'health.php meldet ok nach Cron-Lauf');

    /* --- Abmelden, Brute-Force-Sperre --- */
    [, , $b] = req('GET', "$base/status.php", [], $jar2);
    req('POST', "$base/index.php", ['_csrf' => csrf($b), 'action' => 'logout'], $jar2);
    [$c] = req('GET', "$base/status.php", [], $jar2);
    ok($c === 302, 'Nach Abmelden kein Zugriff mehr');
    $jar3 = $tmp . '/jar3.txt';
    [, , $b] = req('GET', "$base/index.php", [], $jar3);
    $t3 = csrf($b);
    for ($i = 0; $i < 4; $i++) {
        req('POST', "$base/index.php", ['_csrf' => $t3, 'action' => 'login', 'user' => 'zugang', 'password' => 'falsch' . $i], $jar3);
    }
    [, , $b] = req('POST', "$base/index.php", ['_csrf' => $t3, 'action' => 'login', 'user' => 'zugang', 'password' => 'zugang-1234'], $jar3);
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
