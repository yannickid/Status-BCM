<?php
/**
 * Ablauftest Einrichtung ohne Kommandozeile (CLI):  php tests/installtest.php
 * Startet php -S mit leerer Konfiguration und spielt install.php, die erste Anmeldung mit QR-Kopplung und die
 * Seite System (Empfänger, Kopie-Adresse, Zugangspasswort, Cron, Testmail) durch. Benötigt die curl-Erweiterung.
 * Datenbank: SQLite, oder MySQL/MariaDB über SBCM_TEST_DSN (mysql:host=…;dbname=…), SBCM_TEST_USER, SBCM_TEST_PASS.
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

require __DIR__ . '/http.inc.php';

$root = dirname(__DIR__);
$tmp = sys_get_temp_dir() . '/sbcm-install-' . bin2hex(random_bytes(4));
mkdir($tmp . '/storage', 0700, true);
$local = $tmp . '/config.local.inc.php';
// Vorgabe wie bei einem Webspace, auf dem nur der Speicherort angepasst wurde – alles andere erledigt der Assistent.
file_put_contents($local, "<?php\nreturn " . var_export(['app' => ['storage_dir' => $tmp . '/storage']], true) . ";\n");
$prefix = 'it' . bin2hex(random_bytes(3)) . '_';
$dsn = (string)getenv('SBCM_TEST_DSN');

[$srv, $base] = start_server($root, $local, $tmp . '/server.log');

try {
    $jar = $tmp . '/jar.txt';

    /* --- Noch nicht eingerichtet: Weiterleitung zum Assistenten --- */
    [$c, $h] = req('GET', "$base/index.php", [], $jar);
    ok($c === 302 && ($h['location'] ?? '') === 'install.php', 'Ohne Einrichtung leitet die Startseite zu install.php');

    /* --- Schritt 1: Code --- */
    [$c, , $b] = req('GET', "$base/install.php", [], $jar);
    $files = glob($tmp . '/storage/install-code-*.txt') ?: [];
    preg_match('/[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}/', (string)@file_get_contents($files[0] ?? ''), $m);
    $code = $m[0] ?? '';
    ok($c === 200 && $code !== '' && str_contains($b, basename($files[0] ?? 'x')), 'Code-Datei in storage/ angelegt, Dateiname wird genannt');
    ok(!str_contains($b, $code), 'Code selbst steht nicht auf der Seite');
    $t = csrf($b);
    [, , $b] = req('POST', "$base/install.php", ['_csrf' => $t, 'action' => 'code', 'code' => '0000-0000-0000'], $jar);
    ok(str_contains($b, 'Einrichtungscode ist falsch'), 'Falscher Code abgelehnt');
    [, , $b] = req('POST', "$base/install.php", ['_csrf' => $t, 'action' => 'config', 'base_url' => 'https://x.example'], $jar);
    ok(!str_contains($b, 'Schritt 2'), 'Ohne Code kein Zugriff auf die Formulare');
    [$c] = req('POST', "$base/install.php", ['_csrf' => $t, 'action' => 'code', 'code' => strtoupper($code) . ' '], $jar);
    [, , $b] = req('GET', "$base/install.php", [], $jar);
    ok($c === 302 && str_contains($b, 'Schritt 2 von 3'), 'Richtiger Code öffnet Schritt 2');
    $t = csrf($b);

    /* --- Schritt 2: Server-Daten --- */
    $cfg = ['_csrf' => $t, 'action' => 'config', 'base_url' => 'https://status.test', 'db_prefix' => $prefix,
        'mail_transport' => 'log', 'mail_host' => 'smtp.test.example', 'mail_port' => '587', 'mail_secure' => 'starttls',
        'mail_user' => '', 'mail_pass' => '', 'mail_from' => 'status@test.example', 'mail_from_name' => 'Status'];
    if (str_starts_with($dsn, 'mysql:')) {
        preg_match('/host=([^;]+)/', $dsn, $mh);
        preg_match('/dbname=([^;]+)/', $dsn, $md);
        $cfg += ['driver' => 'mysql', 'db_host' => $mh[1] ?? 'localhost', 'db_port' => '', 'db_name' => $md[1] ?? '',
            'db_user' => (string)getenv('SBCM_TEST_USER'), 'db_pass' => (string)getenv('SBCM_TEST_PASS')];
    } else {
        $cfg += ['driver' => 'sqlite'];
    }
    [, , $b] = req('POST', "$base/install.php", ['driver' => 'mysql', 'db_host' => 'bad;host', 'db_name' => 'x'] + $cfg, $jar);
    ok(str_contains($b, 'Datenbank-Server, Port oder Datenbankname ungültig'), 'Ungültige Datenbankangaben abgelehnt');
    [$c] = req('POST', "$base/install.php", $cfg, $jar);
    $written = is_file($local) ? (string)file_get_contents($local) : '';
    ok($c === 302 && str_contains($written, "'master_key'") && str_contains($written, "'token'") && str_contains($written, 'status.test'),
        'config.local.inc.php mit Master-Key, Cron-Token und Adresse geschrieben');
    $lc = (function () use ($local) {
        define('SBCM', true);
        return require $local;
    })();
    $cronToken = (string)($lc['cron']['token'] ?? '');

    /* --- Schritt 3: Zugänge --- */
    [, , $b] = req('GET', "$base/install.php", [], $jar);
    ok(str_contains($b, 'Schritt 3 von 3'), 'Schritt 3 erreicht');
    $t = csrf($b);
    $fin = ['_csrf' => $t, 'action' => 'finish', 's1' => 'Zugang fuer alle 2026', 's1b' => 'Zugang fuer alle 2026',
        'admin_id' => 'chef', 'admin_name' => 'Chefin Test', 'admin_email' => 'chef@test.example',
        'admin_pw' => 'Mein Kaffee ist um 7 Uhr kalt', 'admin_pw2' => 'Mein Kaffee ist um 7 Uhr kalt',
        'cc1' => 'isb@test.example', 'recipients' => "ziel1@ziel.example\nziel2@ziel.example"];
    [, , $b] = req('POST', "$base/install.php", ['admin_pw' => 'kurz', 'admin_pw2' => 'kurz'] + $fin, $jar);
    ok(str_contains($b, 'mindestens 12 Zeichen'), 'Passwortregeln gelten auch im Assistenten');
    [, , $b] = req('POST', "$base/install.php", ['recipients' => "ok@ziel.example\nkaputt"] + $fin, $jar);
    [, , $b2] = req('GET', "$base/install.php", [], $jar);
    ok(str_contains($b, 'Ungültige Adresse') && str_contains($b2, 'Schritt 3 von 3'), 'Fehlerhafte Empfänger: nichts gespeichert, Assistent bleibt offen');
    [$c, , $b] = req('POST', "$base/install.php", $fin, $jar);
    ok($c === 200 && str_contains($b, 'Fertig!') && str_contains($b, 'cron.php?t=' . $cronToken), 'Einrichtung abgeschlossen, Cron-Adresse angezeigt');
    ok(!glob($tmp . '/storage/install-code-*.txt'), 'Code-Datei gelöscht');
    [$c, , $b] = req('GET', "$base/install.php", [], $tmp . '/jar-fremd.txt');
    ok($c === 403 && str_contains($b, 'Assistent ist gesperrt'), 'Assistent danach gesperrt');
    [$c, , $b] = req('POST', "$base/install.php", $fin, $jar);
    ok($c === 403, 'Auch mit alter Sitzung gesperrt');

    /* --- Erste Anmeldung, QR-Kopplung --- */
    [, , $b] = req('GET', "$base/index.php", [], $jar);
    $t = csrf($b);
    [$c, $h] = req('POST', "$base/index.php", ['_csrf' => $t, 'action' => 'login', 'password' => 'Zugang fuer alle 2026'], $jar);
    ok($c === 302 && ($h['location'] ?? '') === 'status.php', 'Zugangspasswort aus dem Assistenten gilt');
    [, , $b] = req('GET', "$base/change.php", [], $jar);
    $t = csrf($b);
    req('POST', "$base/change.php", ['_csrf' => $t, 'action' => 'login2', 'user' => 'chef', 'password' => 'Mein Kaffee ist um 7 Uhr kalt'], $jar);
    [, , $b] = req('GET', "$base/change.php", [], $jar);
    preg_match('/font-monospace text-break my-1">([A-Z2-7 ]+)</', $b, $m);
    $secret = str_replace(' ', '', $m[1] ?? '');
    ok(str_contains($b, 'Zugang einrichten') && str_contains($b, 'data:image/svg+xml;base64,') && !str_contains($b, 'Bisheriges Passwort'),
        'Erster Login: nur App koppeln (QR-Code), kein Passwortwechsel');
    preg_match('/src="data:image\/svg\+xml;base64,([^"]+)"/', $b, $m);
    $svg = base64_decode($m[1] ?? '');
    ok(str_starts_with($svg, '<svg') && str_contains($svg, '<path d="M'), 'QR-Code ist ein gültiges SVG');
    [$c] = req('POST', "$base/change.php", ['_csrf' => $t, 'action' => 'setup', 'totp' => fresh_code($secret)], $jar);
    [, , $b] = req('GET', "$base/change.php", [], $jar);
    ok($c === 302 && str_contains($b, 'Neuen Status setzen') && str_contains($b, 'href="system.php"'), 'Kopplung abgeschlossen, Menü System sichtbar');

    /* --- System-Seite --- */
    [$c, , $b] = req('GET', "$base/system.php", [], $jar);
    $t = csrf($b);
    ok($c === 200 && str_contains($b, 'ALARM-Empfänger (2)') && str_contains($b, 'z****@z***.example') && !str_contains($b, 'ziel1@')
        && str_contains($b, 'i**@t***.example'), 'System zeigt Empfänger und Kopie-Adresse nur maskiert');
    ok(str_contains($b, 'Cron läuft (letzter Lauf: noch nie)') && str_contains($b, 'cron.php?t=' . $cronToken), 'Prüfung meldet fehlenden Cron, Cron-Adresse sichtbar');
    [, , $b] = req('POST', "$base/system.php", ['_csrf' => $t, 'action' => 'recipient_add', 'emails' => 'neu@ziel.example', 'totp' => '000000'], $jar);
    ok(str_contains($b, 'Bestätigungscode ist ungültig'), 'Änderung ohne gültigen TOTP-Code abgelehnt');
    [$c] = req('POST', "$base/system.php", ['_csrf' => $t, 'action' => 'recipient_add', 'emails' => "neu@ziel.example, ziel1@ziel.example", 'totp' => fresh_code($secret)], $jar);
    [, , $b] = req('GET', "$base/system.php", [], $jar);
    ok($c === 302 && str_contains($b, '1 Empfänger hinzugefügt') && str_contains($b, 'ALARM-Empfänger (3)'), 'Empfänger hinzugefügt, Doppelte ignoriert');
    [$c] = req('POST', "$base/system.php", ['_csrf' => $t, 'action' => 'recipient_remove', 'nr' => '0', 'totp' => fresh_code($secret)], $jar);
    [, , $b] = req('GET', "$base/system.php", [], $jar);
    ok($c === 302 && str_contains($b, 'ALARM-Empfänger (2)'), 'Empfänger entfernt');
    [$c] = req('POST', "$base/system.php", ['_csrf' => $t, 'action' => 'cc1', 'email' => 'notfall@test.example', 'totp' => fresh_code($secret)], $jar);
    [, , $b] = req('GET', "$base/system.php", [], $jar);
    ok($c === 302 && str_contains($b, 'n******@t***.example'), 'Kopie-Adresse geändert');
    [$c] = req('POST', "$base/system.php", ['_csrf' => $t, 'action' => 'cron_run'], $jar);
    [, , $b] = req('GET', "$base/system.php", [], $jar);
    ok($c === 302 && str_contains($b, 'Cron ausgeführt') && !str_contains($b, 'noch nie'), 'Cron manuell ausgeführt');
    [$c] = req('GET', "$base/cron.php?t=" . $cronToken);
    ok($c === 200, 'cron.php mit Token aus dem Assistenten läuft');
    [$c] = req('POST', "$base/system.php", ['_csrf' => $t, 'action' => 'mail_test'], $jar);
    [, , $b] = req('GET', "$base/system.php", [], $jar);
    $test = '';
    foreach (glob($tmp . '/storage/outbox/*.eml') ?: [] as $f) {
        $x = (string)file_get_contents($f);
        if (str_contains($x, 'Testnachricht')) {
            $test = $x;
        }
    }
    ok($c === 302 && str_contains($b, 'Testmail an') && str_contains($test, 'chef@test.example'), 'Testmail an den Admin versendet');
    [, , $b] = req('POST', "$base/system.php", ['_csrf' => $t, 'action' => 'stage1', 'pw' => 'Neuer Zugang 2027', 'pw2' => 'anders', 'totp' => fresh_code($secret)], $jar);
    ok(str_contains($b, 'stimmen nicht überein'), 'Zugangspasswort: Wiederholung wird geprüft');
    [$c] = req('POST', "$base/system.php", ['_csrf' => $t, 'action' => 'stage1', 'pw' => 'Neuer Zugang 2027', 'pw2' => 'Neuer Zugang 2027', 'totp' => fresh_code($secret)], $jar);
    $jar2 = $tmp . '/jar2.txt';
    [, , $b] = req('GET', "$base/index.php", [], $jar2);
    $t2 = csrf($b);
    [$c1] = req('POST', "$base/index.php", ['_csrf' => $t2, 'action' => 'login', 'password' => 'Zugang fuer alle 2026'], $jar2);
    [$c2] = req('POST', "$base/index.php", ['_csrf' => $t2, 'action' => 'login', 'password' => 'Neuer Zugang 2027'], $jar2);
    ok($c === 302 && $c1 === 200 && $c2 === 302, 'Neues Zugangspasswort gilt sofort, altes nicht mehr');

    /* --- Protokoll --- */
    [, , $b] = req('GET', "$base/change.php", [], $jar);
    ok(str_contains($b, 'Einrichtung abgeschlossen (install.php)') && str_contains($b, 'ALARM-Empfänger hinzugefügt') && str_contains($b, 'ALARM-Empfänger entfernt')
        && str_contains($b, 'Kopie-Adresse (cc_default_mail1) geändert') && str_contains($b, 'Zugangspasswort Stufe 1 geändert')
        && str_contains($b, 'Integrität der Protokollkette: OK'), 'Einrichtung und Systemänderungen lückenlos im Protokoll');

    /* --- Einstellungen in der DB sind verschlüsselt und manipulationsgeschützt --- */
    $pdo = str_starts_with($dsn, 'mysql:') ? new PDO($dsn, (string)getenv('SBCM_TEST_USER'), (string)getenv('SBCM_TEST_PASS'))
        : new PDO('sqlite:' . $tmp . '/storage/status.sqlite');
    $rows = $pdo->query("SELECT k, v FROM {$prefix}kv WHERE k LIKE 'set:%'")->fetchAll(PDO::FETCH_KEY_PAIR);
    ok(count($rows) === 3 && !preg_grep('/ziel|test\.example|\$2y\$/', $rows), 'Einstellungen nur verschlüsselt in der Datenbank');
    $pdo->prepare("UPDATE {$prefix}kv SET v = ? WHERE k = 'set:recipients'")->execute([$rows['set:cc1']]);
    [, , $b] = req('GET', "$base/system.php", [], $jar);
    ok(str_contains($b, 'Einstellung recipients nicht lesbar'), 'Vertauschte Einstellung wird erkannt');

    /* --- Notfallzugang (storage/notfall.txt) --- */
    [$c] = req('GET', "$base/install.php", [], $tmp . '/jar-nf.txt');
    ok($c === 403, 'Ohne notfall.txt kein Notfallzugang');
    file_put_contents($tmp . '/storage/notfall.txt', "chef\r\nNotfall Passphrase 42\r\n");
    [$c, , $b] = req('GET', "$base/install.php", [], $tmp . '/jar-nf.txt');
    $tn = csrf($b);
    [, , $b] = req('POST', "$base/install.php", ['_csrf' => $tn, 'id' => 'chef', 'pass' => 'falsch falsch falsch'], $tmp . '/jar-nf.txt');
    ok($c === 200 && str_contains($b, 'Kennung oder Passphrase falsch'), 'Notfallzugang: falsche Passphrase abgelehnt');
    [, , $b] = req('POST', "$base/install.php", ['_csrf' => $tn, 'id' => 'chef', 'pass' => 'Notfall Passphrase 42'], $tmp . '/jar-nf.txt');
    preg_match('/fs-5">([A-Za-z0-9-]{19})</', $b, $m);
    $once = $m[1] ?? '';
    ok($once !== '' && !is_file($tmp . '/storage/notfall.txt'), 'Notfallzugang: Einmalpasswort erzeugt, Datei gelöscht');
    $jar5 = $tmp . '/jar5.txt';
    [, , $b] = req('GET', "$base/index.php", [], $jar5);
    $t5 = csrf($b);
    req('POST', "$base/index.php", ['_csrf' => $t5, 'action' => 'login', 'password' => 'Neuer Zugang 2027'], $jar5);
    [, , $b] = req('GET', "$base/change.php", [], $jar5);
    req('POST', "$base/change.php", ['_csrf' => csrf($b), 'action' => 'login2', 'user' => 'chef', 'password' => $once], $jar5);
    [, , $b] = req('GET', "$base/change.php", [], $jar5);
    ok(str_contains($b, 'Einmalpasswort erhalten') && str_contains($b, 'data:image/svg+xml'), 'Login mit Einmalpasswort: neues Passwort und neue App-Kopplung');
    $acts = $pdo->query("SELECT action FROM {$prefix}audit WHERE actor = 'system:emergency' ORDER BY seq")->fetchAll(PDO::FETCH_COLUMN);
    ok($acts === ['user.reset_totp', 'user.reset_pw'], 'Notfallzugang im Protokoll (Akteur system:emergency)');

    $log = (string)@file_get_contents($tmp . '/server.log');
    ok(!preg_match('/PHP (Warning|Notice|Deprecated|Fatal)/', $log), 'Keine PHP-Warnungen im Server-Log');
} finally {
    proc_terminate($srv);
    proc_close($srv);
    if ($fails > 0) {
        echo "\nServer-Log (Auszug):\n" . implode("\n", preg_grep('/PHP |\[(4|5)\d\d\]/', file($tmp . '/server.log', FILE_IGNORE_NEW_LINES) ?: []) ?: []) . "\n";
    }
    exec('rm -rf ' . escapeshellarg($tmp));
    if (str_starts_with($dsn, 'mysql:')) {
        $pdo = new PDO($dsn, (string)getenv('SBCM_TEST_USER'), (string)getenv('SBCM_TEST_PASS'));
        foreach (['audit_no_upd', 'audit_no_del', 'status_no_del', 'account_no_del'] as $tr) {
            $pdo->exec("DROP TRIGGER IF EXISTS {$prefix}$tr");
        }
        foreach (['status', 'audit', 'mail_log', 'login_attempt', 'totp_used', 'kv', 'view_count', 'account'] as $tb) {
            $pdo->exec("DROP TABLE IF EXISTS {$prefix}$tb");
        }
    }
}

echo $fails === 0 ? "\nAlle Einrichtungstests bestanden.\n" : "\n$fails Einrichtungstest(s) fehlgeschlagen.\n";
exit($fails === 0 ? 0 : 1);
