<?php
/**
 * Einrichtungsassistent im Browser – für Webspaces ohne Kommandozeile.
 *
 * Schutz: Der Assistent verlangt einen Einrichtungscode, den er beim ersten Aufruf in storage/install-code-….txt
 * ablegt. Nur wer per FTP/Dateimanager Zugriff auf den Webspace hat, kann ihn lesen. Sobald Master-Key, Datenbank
 * und ein Admin vorhanden sind, sperrt sich der Assistent dauerhaft; die Code-Datei wird gelöscht.
 *
 * Danach dient die Datei nur noch als Notfallzugang (storage/notfall.txt, siehe unten).
 *
 * Schritte: 1. Code  2. Datenbank, Adresse, Mailserver → config.local.inc.php (schreiben oder herunterladen)
 *           3. Zugangspasswort, erster Admin, Kopie-Adresse, ALARM-Empfänger → Datenbank
 */
declare(strict_types=1);
define('SBCM', true);
require __DIR__ . '/lib.inc.php';
bootstrap();

function inst_head(string $title): void
{
    page_start($title);
    echo '<header class="mb-3 pb-2 border-bottom"><p class="app-title fw-bold">Einrichtung</p></header>';
}

function inst_field(string $label, string $name, string $value = '', string $type = 'text', string $attrs = '', string $help = ''): string
{
    $id = 'f_' . $name;
    return '<div class="mb-2"><label class="form-label" for="' . $id . '">' . h($label) . '</label>'
        . '<input class="form-control" id="' . $id . '" type="' . $type . '" name="' . h($name) . '" value="' . h($value) . '" ' . $attrs . '>'
        . ($help !== '' ? '<div class="form-text">' . $help . '</div>' : '') . '</div>';
}

/** Code-Datei in storage/ (nicht per Web abrufbar). null = storage nicht beschreibbar. */
function inst_code_file(): ?string
{
    $d = storage_dir();
    if (!is_dir($d) || !is_writable($d)) {
        return null;
    }
    $f = glob($d . '/install-code-*.txt') ?: [];
    if ($f) {
        return $f[0];
    }
    $code = implode('-', str_split(bin2hex(random_bytes(6)), 4));
    $p = $d . '/install-code-' . bin2hex(random_bytes(8)) . '.txt';
    file_put_contents($p, "Status-BCM Einrichtungscode: $code\r\n\r\nDiesen Code im Einrichtungsassistenten (install.php) eingeben.\r\n"
        . "Die Datei wird nach der Einrichtung automatisch gelöscht.\r\n", LOCK_EX);
    return $p;
}

function inst_code(string $file): string
{
    return preg_match('/[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}/', (string)@file_get_contents($file), $m) ? $m[0] : '';
}

/** Einfache Sperre gegen Durchprobieren (ohne Datenbank): max. 10 Fehlversuche je 15 Minuten. */
function inst_fail_count(bool $add = false): int
{
    $p = storage_dir() . '/install-fails.json';
    $now = time();
    $list = array_values(array_filter((array)json_decode((string)@file_get_contents($p), true), fn($t) => is_int($t) && $now - $t < 900));
    if ($add) {
        $list[] = $now;
        @file_put_contents($p, json_encode($list), LOCK_EX);
    }
    return count($list);
}

function inst_requirements(): array
{
    $local = local_config_path();
    $localWritable = is_file($local) ? is_writable($local) : is_writable(dirname($local));
    $sd = storage_dir();
    return [
        ['PHP ' . PHP_VERSION . ' (mindestens 8.0)', PHP_VERSION_ID >= 80000, true],
        ['Erweiterung openssl (Verschlüsselung)', extension_loaded('openssl'), true],
        ['Erweiterung PDO MySQL' . (extension_loaded('pdo_mysql') ? '' : ' (oder SQLite)'), extension_loaded('pdo_mysql') || extension_loaded('pdo_sqlite'), true],
        ['Erweiterung mbstring', extension_loaded('mbstring'), true],
        ['Ordner storage/ beschreibbar', is_dir($sd) && is_writable($sd), true],
        ['config.local.inc.php kann geschrieben werden' . ($localWritable ? '' : ' (sonst: Datei herunterladen und per FTP hochladen)'), $localWritable, false],
        ['HTTPS', is_https(), false],
        ['config.json lesbar', is_readable((string)cfg('app.json_path')), true],
    ];
}

/* ---------------------------------------------------------------- gesperrt? */
if (is_installed()) {
    /*
     * Notfallzugang ohne Kommandozeile (z. B. einziger Admin hat Passwort und Smartphone verloren): Wer per FTP die Datei
     * storage/notfall.txt anlegt (Zeile 1: Benutzerkennung, Zeile 2: selbst gewählte Passphrase, mind. 12 Zeichen), kann
     * hier mit derselben Passphrase ein Einmalpasswort erzeugen. Die App wird neu gekoppelt, die Datei gelöscht.
     */
    $nf = storage_dir() . '/notfall.txt';
    $lines = is_file($nf) ? array_values(array_filter(array_map('trim', preg_split('/\R/', (string)@file_get_contents($nf)) ?: []), 'strlen')) : [];
    $nfId = strtolower($lines[0] ?? '');
    $nfPass = $lines[1] ?? '';
    if ($nfId !== '' && mb_strlen($nfPass) >= 12) {
        $msg = null;
        $once = null;
        if (($_SERVER['REQUEST_METHOD'] ?? 'GET') === 'POST') {
            csrf_verify();
            if (inst_fail_count() >= 10) {
                $msg = 'Zu viele Fehlversuche. Bitte in 15 Minuten erneut versuchen.';
            } elseif (!hash_equals($nfPass, (string)($_POST['pass'] ?? '')) || $nfId !== strtolower(trim((string)($_POST['id'] ?? '')))) {
                inst_fail_count(true);
                fail_delay();
                $msg = 'Kennung oder Passphrase falsch.';
            } else {
                try {
                    $u = users(true)[$nfId] ?? null;
                    if (!$u || $u['source'] !== 'db') {
                        throw new InvalidArgumentException('Benutzer unbekannt oder nicht in der Datenbank.');
                    }
                    $once = tx(function () use ($nfId, $u) {
                        if (!$u['active']) {
                            account_action('enable', $nfId, [], 'system:emergency', ['emergency' => true]);
                        }
                        account_action('reset_totp', $nfId, [], 'system:emergency', ['emergency' => true]);
                        return account_action('reset_pw', $nfId, [], 'system:emergency', ['emergency' => true]);
                    });
                    @unlink($nf);
                } catch (Throwable $e) {
                    $msg = $e->getMessage();
                }
            }
        }
        inst_head('Notfallzugang');
        if ($once !== null) {
            echo '<div class="alert alert-success">Einmalpasswort für <strong>' . h($nfId) . '</strong>: <span class="font-monospace fs-5">' . h($once)
                . '</span><br>Nur jetzt sichtbar. Beim nächsten Login werden ein eigenes Passwort und die Authenticator-App neu eingerichtet. '
                . 'Die Datei notfall.txt wurde gelöscht.</div><p><a class="btn btn-primary" href="index.php">Zur Anmeldung</a></p>';
        } else {
            echo '<h1 class="h4">Notfallzugang</h1>' . ($msg ? '<div class="alert alert-danger">' . h($msg) . '</div>' : '')
                . '<p class="small">Erzeugt ein Einmalpasswort und setzt die Authenticator-App zurück. Wird protokolliert.</p>'
                . '<form method="post" action="install.php" autocomplete="off">' . csrf_field()
                . inst_field('Benutzerkennung (Zeile 1 der Datei)', 'id', '', 'text', 'required autocapitalize="none"')
                . inst_field('Passphrase (Zeile 2 der Datei)', 'pass', '', 'password', 'required')
                . '<button class="btn btn-danger" type="submit">Einmalpasswort erzeugen</button></form>';
        }
        page_end();
        exit;
    }
    http_response_code(403);
    inst_head('Einrichtung abgeschlossen');
    echo '<div class="alert alert-success">Die Einrichtung ist abgeschlossen. Dieser Assistent ist gesperrt.</div>'
        . '<p>Änderungen nehmen Admins nach der Anmeldung unter <strong>System</strong> und <strong>Benutzer</strong> vor. '
        . 'Die Datei <code>install.php</code> kann vom Webspace gelöscht werden.</p><p><a class="btn btn-primary" href="index.php">Zur Anmeldung</a></p>';
    page_end();
    exit;
}

$errors = [];
$codeFile = inst_code_file();
$method = $_SERVER['REQUEST_METHOD'] ?? 'GET';
$act = $method === 'POST' ? (string)($_POST['action'] ?? '') : '';
if ($method === 'POST') {
    csrf_verify();
}

/* ---------------------------------------------------------------- Schritt 1: Code */
if ($act === 'code' && $codeFile) {
    if (inst_fail_count() >= 10) {
        $errors[] = 'Zu viele Fehlversuche. Bitte in 15 Minuten erneut versuchen.';
    } elseif (hash_equals(inst_code($codeFile), strtolower(trim((string)($_POST['code'] ?? ''))))) {
        session_regenerate_id(true);
        $_SESSION['inst'] = true;
        redirect('install.php');
    } else {
        inst_fail_count(true);
        fail_delay();
        $errors[] = 'Der Einrichtungscode ist falsch.';
    }
}

if (empty($_SESSION['inst'])) {
    inst_head('Einrichtung');
    echo '<h1 class="h4">Willkommen</h1><p>Dieser Assistent richtet die Statusseite ein, ganz ohne Kommandozeile.</p>';
    foreach ($errors as $e) {
        echo '<div class="alert alert-danger">' . h($e) . '</div>';
    }
    echo '<div class="card shadow-sm mb-3"><div class="card-body"><h2 class="h5">Voraussetzungen</h2><ul class="list-unstyled small mb-0">';
    $blocked = false;
    foreach (inst_requirements() as [$label, $ok, $must]) {
        $blocked = $blocked || (!$ok && $must);
        echo '<li class="py-1 border-bottom"><span class="badge ' . ($ok ? 'text-bg-success">ok' : ($must ? 'text-bg-danger">fehlt' : 'text-bg-warning">Hinweis'))
            . '</span> ' . h($label) . '</li>';
    }
    echo '</ul></div></div>';
    if (!$codeFile) {
        echo '<div class="alert alert-danger">Der Ordner <code>storage</code> fehlt oder ist nicht beschreibbar. Legen Sie ihn per FTP neben '
            . '<code>index.php</code> an und geben Sie ihm Schreibrechte (z. B. 0755 oder 0775). Dann diese Seite neu laden.</div>';
    } elseif ($blocked) {
        echo '<div class="alert alert-danger">Bitte zuerst die fehlenden Voraussetzungen beim Hoster aktivieren (meist im Kundenmenü unter PHP-Einstellungen).</div>';
    } else {
        echo '<div class="card shadow-sm"><div class="card-body"><h2 class="h5">Einrichtungscode</h2>'
            . '<p class="small">Zum Schutz vor Fremden steht der Code in einer Datei auf Ihrem Webspace. Öffnen Sie per FTP oder im Dateimanager des Hosters '
            . 'den Ordner <code>storage</code> und darin die Datei <code>' . h(basename($codeFile)) . '</code>.</p>'
            . '<form method="post" action="install.php" autocomplete="off">' . csrf_field() . '<input type="hidden" name="action" value="code">'
            . inst_field('Einrichtungscode', 'code', '', 'text', 'required autocapitalize="none" placeholder="xxxx-xxxx-xxxx"')
            . '<button class="btn btn-primary" type="submit">Weiter</button></form></div></div>';
    }
    page_end();
    exit;
}

/* ---------------------------------------------------------------- Download der Konfiguration */
if ($act === 'download' && !empty($_SESSION['inst_dl'])) {
    header('Content-Type: application/octet-stream');
    header('Content-Disposition: attachment; filename="config.local.inc.php"');
    echo $_SESSION['inst_dl'];
    exit;
}

$local = local_config_load();
$keyOk = false;
try {
    master_key();
    $keyOk = true;
} catch (Throwable $e) {
}
$dbErr = null;
if ($keyOk) {
    try {
        db();
    } catch (Throwable $e) {
        $dbErr = $e->getMessage();
    }
}
$editCfg = !$keyOk || $dbErr !== null || isset($_GET['edit']) || $act === 'config';

/* ---------------------------------------------------------------- Schritt 2: config.local.inc.php */
if ($act === 'config') {
    $in = fn(string $k) => trim((string)($_POST[$k] ?? ''));
    $driver = $in('driver') === 'sqlite' ? 'sqlite' : 'mysql';
    $base = rtrim($in('base_url'), '/');
    if (!preg_match('#^https?://[A-Za-z0-9.\-]+(:\d+)?(/[A-Za-z0-9._~\-/]*)?$#', $base)) {
        $errors[] = 'Adresse der Seite ungültig (Beispiel: https://status.example.org).';
    }
    $db = ['prefix' => $in('db_prefix')];
    if (!preg_match('/^[A-Za-z0-9_]{0,20}$/', $db['prefix'])) {
        $errors[] = 'Tabellen-Präfix: nur Buchstaben, Ziffern und _ (max. 20).';
    }
    if ($driver === 'mysql') {
        $host = $in('db_host');
        $port = $in('db_port');
        $name = $in('db_name');
        if (!preg_match('/^[A-Za-z0-9.\-]{1,253}$/', $host) || ($port !== '' && !ctype_digit($port)) || !preg_match('/^[A-Za-z0-9_\-$]{1,64}$/', $name)) {
            $errors[] = 'Datenbank-Server, Port oder Datenbankname ungültig.';
        }
        $db['dsn'] = 'mysql:host=' . $host . ($port !== '' ? ';port=' . (int)$port : '') . ';dbname=' . $name . ';charset=utf8mb4';
        $db['user'] = $in('db_user');
        $db['pass'] = (string)($_POST['db_pass'] ?? '');
        if ($db['pass'] === '' && !empty($local['db']['pass'])) {
            $db['pass'] = (string)$local['db']['pass'];
        }
    } else {
        $db += ['dsn' => 'sqlite:{storage}/status.sqlite', 'user' => '', 'pass' => ''];
    }
    $mail = ['transport' => $in('mail_transport') === 'log' ? 'log' : 'smtp', 'host' => $in('mail_host'), 'port' => (int)$in('mail_port'),
        'secure' => in_array($in('mail_secure'), ['starttls', 'ssl', 'none'], true) ? $in('mail_secure') : 'starttls',
        'user' => $in('mail_user'), 'pass' => (string)($_POST['mail_pass'] ?? ''), 'from_email' => strtolower($in('mail_from')),
        'from_name' => preg_replace('/[\r\n]+/', ' ', $in('mail_from_name')) ?: 'Status'];
    if ($mail['pass'] === '' && !empty($local['mail']['pass'])) {
        $mail['pass'] = (string)$local['mail']['pass'];
    }
    if ($mail['transport'] === 'smtp' && (!preg_match('/^[A-Za-z0-9.\-]{1,253}$/', $mail['host']) || $mail['port'] < 1 || $mail['port'] > 65535)) {
        $errors[] = 'Mailserver oder Port ungültig.';
    }
    if (!filter_var($mail['from_email'], FILTER_VALIDATE_EMAIL)) {
        $errors[] = 'Absenderadresse ungültig.';
    }
    if (!$errors) {
        try {
            $dsn = str_replace('{storage}', storage_dir(), $db['dsn']);
            new PDO($dsn, $db['user'], $db['pass'], [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION, PDO::ATTR_TIMEOUT => 5]);
        } catch (Throwable $e) {
            $errors[] = 'Verbindung zur Datenbank fehlgeschlagen: ' . $e->getMessage();
        }
    }
    if (!$errors) {
        $local['app']['base_url'] = $base;
        $local['db'] = array_replace((array)($local['db'] ?? []), $db);
        $local['mail'] = array_replace((array)($local['mail'] ?? []), $mail);
        $local['security']['master_key'] = !empty($local['security']['master_key']) ? $local['security']['master_key'] : base64_encode(random_bytes(32));
        $local['cron']['token'] = !empty($local['cron']['token']) ? $local['cron']['token'] : bin2hex(random_bytes(24));
        if (local_config_write($local)) {
            unset($_SESSION['inst_dl']);
            flash('ok', 'config.local.inc.php gespeichert.');
            redirect('install.php');
        }
        $_SESSION['inst_dl'] = local_config_code($local);
        inst_head('Einrichtung');
        echo '<h1 class="h4">Konfiguration herunterladen</h1>'
            . '<div class="alert alert-info">PHP darf auf diesem Webspace keine Dateien im Programmordner anlegen. Das ist sicherer, deshalb so:</div>'
            . '<ol><li>Datei herunterladen.</li><li>Per FTP oder Dateimanager unter dem Namen <code>config.local.inc.php</code> neben <code>index.php</code> hochladen.</li>'
            . '<li><strong>Eine Kopie sicher aufbewahren</strong> (enthält den Master-Key; ohne ihn sind Status und Protokoll nicht mehr lesbar).</li>'
            . '<li>Hier auf "Weiter" tippen.</li></ol>'
            . '<form method="post" action="install.php" class="mb-2">' . csrf_field() . '<input type="hidden" name="action" value="download">'
            . '<button class="btn btn-primary" type="submit">config.local.inc.php herunterladen</button></form>'
            . '<a class="btn btn-outline-secondary" href="install.php">Weiter</a>';
        page_end();
        exit;
    }
}

/* ---------------------------------------------------------------- Schritt 3: Zugänge */
if ($act === 'finish' && !$editCfg) {
    $in = fn(string $k) => trim((string)($_POST[$k] ?? ''));
    $aid = strtolower($in('admin_id'));
    $apw = (string)($_POST['admin_pw'] ?? '');
    if (!preg_match('/^[a-z0-9_-]{2,32}$/', $aid)) {
        $errors[] = 'Benutzerkennung: 2–32 Zeichen a–z, 0–9, _ und -.';
    }
    if ($in('admin_name') === '' || !filter_var($in('admin_email'), FILTER_VALIDATE_EMAIL)) {
        $errors[] = 'Name und gültige E-Mail-Adresse des Admins angeben.';
    }
    if (!hash_equals($apw, (string)($_POST['admin_pw2'] ?? ''))) {
        $errors[] = 'Die Admin-Passwörter stimmen nicht überein.';
    }
    $errors = array_merge($errors, password_policy($apw, $aid));
    $s1 = (string)($_POST['s1'] ?? '');
    if (mb_strlen($s1) < 10 || !hash_equals($s1, (string)($_POST['s1b'] ?? ''))) {
        $errors[] = 'Zugangspasswort: mindestens 10 Zeichen, beide Eingaben gleich.';
    } elseif (hash_equals($s1, $apw)) {
        $errors[] = 'Zugangspasswort und Admin-Passwort müssen verschieden sein.';
    }
    if (!filter_var($in('cc1'), FILTER_VALIDATE_EMAIL)) {
        $errors[] = 'Kopie-Adresse (cc_default_mail1) ungültig.';
    }
    if (!$errors) {
        try {
            install_schema(db());
            tx(function () use ($aid, $apw, $in, $s1) {
                account_action('create', $aid, ['name' => $in('admin_name'), 'email' => $in('admin_email'), 'role' => 'admin', 'password' => $apw], 'system:install');
                if ($e = stage1_change($s1, $s1, 'system:install')) {
                    throw new InvalidArgumentException(implode(' ', $e));
                }
                if ($e = cc1_change($in('cc1'), 'system:install')) {
                    throw new InvalidArgumentException($e);
                }
                if (trim((string)($_POST['recipients'] ?? '')) !== '') {
                    [, $e] = recipients_add((string)$_POST['recipients'], 'system:install');
                    if ($e) {
                        throw new InvalidArgumentException('ALARM-Empfänger: ' . $e);
                    }
                }
                audit('system.install', 'system', ['version' => SBCM_VERSION, 'user' => $aid, 'how' => ['installer' => true]], 'system:install', 0);
            });
        } catch (InvalidArgumentException $e) {
            $errors[] = $e->getMessage();
        }
    }
    if (!$errors) {
        if ($codeFile) {
            @unlink($codeFile);
        }
        @unlink(storage_dir() . '/install-fails.json');
        unset($_SESSION['inst'], $_SESSION['inst_dl']);
        $cron = rtrim((string)cfg('app.base_url'), '/') . '/cron.php?t=' . (string)cfg('cron.token', '');
        inst_head('Einrichtung abgeschlossen');
        echo '<div class="alert alert-success">Fertig! Die Statusseite ist eingerichtet, dieser Assistent ist ab jetzt gesperrt.</div>';
        echo '<h2 class="h5">Noch drei Schritte</h2><ol>'
            . '<li class="mb-2"><strong>Cron einrichten:</strong> Im Kundenmenü des Hosters unter "Cronjobs" (oder bei einem Cron-Dienst) diese Adresse '
            . '<strong>alle 5 Minuten</strong> aufrufen lassen. Ohne Cron gibt es keine Erinnerungsmails.'
            . '<div class="font-monospace small break-all border rounded p-2 my-1 bg-body">' . h($cron) . '</div>'
            . '<span class="small text-body-secondary">Sie finden die Adresse später auch unter System.</span></li>'
            . '<li class="mb-2"><strong>Anmelden und Authenticator-App koppeln:</strong> Zur Anmeldung, Zugangspasswort eingeben, dann '
            . '"Einstellungen" mit Kennung <code>' . h($aid) . '</code> und Ihrem Passwort. Dort den QR-Code mit der Authenticator-App scannen.</li>'
            . '<li class="mb-2"><strong>Sichern:</strong> <code>config.local.inc.php</code> per FTP herunterladen und getrennt sicher aufbewahren '
            . '(enthält den Master-Key). Danach unter System die Prüfung ansehen.</li></ol>'
            . '<p><a class="btn btn-primary" href="index.php">Zur Anmeldung</a></p>';
        page_end();
        exit;
    }
}

/* ---------------------------------------------------------------- Formulare */
inst_head('Einrichtung');
render_flash();
foreach ($errors as $e) {
    echo '<div class="alert alert-danger">' . h($e) . '</div>';
}

if ($editCfg) {
    $dsn = (string)($local['db']['dsn'] ?? '');
    preg_match('/host=([^;]+)/', $dsn, $mh);
    preg_match('/port=(\d+)/', $dsn, $mp);
    preg_match('/dbname=([^;]+)/', $dsn, $md);
    $v = fn(string $k, string $d = '') => (string)($_POST[$k] ?? $d);
    $guess = (is_https() ? 'https' : 'http') . '://' . preg_replace('/[^A-Za-z0-9.\-:]/', '', (string)($_SERVER['HTTP_HOST'] ?? 'localhost'))
        . rtrim(str_replace('\\', '/', dirname((string)($_SERVER['SCRIPT_NAME'] ?? '/'))), '/');
    $isSqlite = $v('driver', str_starts_with($dsn, 'sqlite:') ? 'sqlite' : 'mysql') === 'sqlite';
    $mailCur = (array)($local['mail'] ?? []);
    echo '<h1 class="h4">Schritt 2 von 3: Server-Daten</h1>';
    if ($dbErr !== null && $act !== 'config') {
        echo '<div class="alert alert-warning">Die Datenbank ist mit den gespeicherten Daten nicht erreichbar: ' . h($dbErr) . '</div>';
    }
    echo '<p class="small text-body-secondary">Die Angaben finden Sie im Kundenmenü Ihres Hosters (Datenbanken, E-Mail-Postfächer). '
        . 'Sie werden in <code>config.local.inc.php</code> gespeichert, die nicht im Web abrufbar ist.</p>';
    echo '<form method="post" action="install.php" autocomplete="off">' . csrf_field() . '<input type="hidden" name="action" value="config">';
    echo '<div class="card shadow-sm mb-3"><div class="card-body"><h2 class="h5">Adresse der Seite</h2>'
        . inst_field('Öffentliche Adresse', 'base_url', $v('base_url', (string)($local['app']['base_url'] ?? $guess)), 'url', 'required',
            'So, wie Beschäftigte die Seite aufrufen. Wird in E-Mails verlinkt.') . '</div></div>';
    echo '<div class="card shadow-sm mb-3"><div class="card-body"><h2 class="h5">Datenbank</h2>'
        . '<div class="mb-2"><label class="form-label" for="f_driver">Art</label><select class="form-select" id="f_driver" name="driver">'
        . '<option value="mysql"' . ($isSqlite ? '' : ' selected') . '>MySQL / MariaDB (empfohlen)</option>'
        . '<option value="sqlite"' . ($isSqlite ? ' selected' : '') . '>SQLite-Datei (nur zum Ausprobieren)</option></select></div>'
        . inst_field('Server', 'db_host', $v('db_host', $mh[1] ?? 'localhost'), 'text', 'autocapitalize="none"')
        . inst_field('Port (leer = Standard)', 'db_port', $v('db_port', $mp[1] ?? ''), 'text', 'inputmode="numeric"')
        . inst_field('Datenbankname', 'db_name', $v('db_name', $md[1] ?? ''), 'text', 'autocapitalize="none"')
        . inst_field('Benutzer', 'db_user', $v('db_user', (string)($local['db']['user'] ?? '')), 'text', 'autocapitalize="none"')
        . inst_field('Passwort', 'db_pass', '', 'password', 'autocomplete="new-password"', !empty($local['db']['pass']) ? 'Leer lassen = unverändert.' : '')
        . inst_field('Tabellen-Präfix', 'db_prefix', $v('db_prefix', (string)($local['db']['prefix'] ?? 'sbcm_')), 'text', 'autocapitalize="none"')
        . '</div></div>';
    $sel = fn(string $cur, array $opts) => implode('', array_map(fn($k, $l) => '<option value="' . $k . '"' . ($cur === $k ? ' selected' : '') . '>' . h($l) . '</option>', array_keys($opts), $opts));
    echo '<div class="card shadow-sm mb-3"><div class="card-body"><h2 class="h5">Mailserver (Postausgang)</h2>'
        . '<div class="mb-2"><label class="form-label" for="f_mt">Versand</label><select class="form-select" id="f_mt" name="mail_transport">'
        . $sel($v('mail_transport', (string)($mailCur['transport'] ?? 'smtp')), ['smtp' => 'SMTP (normal)', 'log' => 'Nur Testmodus: Mails als Datei in storage/outbox'])
        . '</select></div>'
        . inst_field('SMTP-Server', 'mail_host', $v('mail_host', (string)($mailCur['host'] ?? '')), 'text', 'autocapitalize="none"')
        . inst_field('Port', 'mail_port', $v('mail_port', (string)($mailCur['port'] ?? '587')), 'text', 'inputmode="numeric"')
        . '<div class="mb-2"><label class="form-label" for="f_ms">Verschlüsselung</label><select class="form-select" id="f_ms" name="mail_secure">'
        . $sel($v('mail_secure', (string)($mailCur['secure'] ?? 'starttls')), ['starttls' => 'STARTTLS (Port 587)', 'ssl' => 'SSL/TLS (Port 465)', 'none' => 'keine (nur localhost)'])
        . '</select></div>'
        . inst_field('SMTP-Benutzer', 'mail_user', $v('mail_user', (string)($mailCur['user'] ?? '')), 'text', 'autocapitalize="none"')
        . inst_field('SMTP-Passwort', 'mail_pass', '', 'password', 'autocomplete="new-password"', !empty($mailCur['pass']) ? 'Leer lassen = unverändert.' : '')
        . inst_field('Absenderadresse', 'mail_from', $v('mail_from', (string)($mailCur['from_email'] ?? '')), 'email', 'required')
        . inst_field('Absendername', 'mail_from_name', $v('mail_from_name', (string)($mailCur['from_name'] ?? 'Status')), 'text', 'maxlength="60"', 'Neutral halten, z. B. "Status".')
        . '</div></div>';
    echo '<div class="d-grid"><button class="btn btn-primary btn-lg" type="submit">Prüfen und speichern</button></div></form>';
    page_end();
    exit;
}

$p = fn(string $k) => h((string)($_POST[$k] ?? ''));
echo '<h1 class="h4">Schritt 3 von 3: Zugänge</h1>';
echo '<p class="small"><a href="install.php?edit=1">Server-Daten ändern</a></p>';
echo '<form method="post" action="install.php" autocomplete="off">' . csrf_field() . '<input type="hidden" name="action" value="finish">';
echo '<div class="card shadow-sm mb-3"><div class="card-body"><h2 class="h5">Zugangspasswort für alle (Stufe 1)</h2>'
    . '<p class="small text-body-secondary">Ein gemeinsames Passwort zum Lesen des Status. Es schützt vor Suchmaschinen und Zufallsbesuchern und wird intern bekannt gegeben.</p>'
    . inst_field('Zugangspasswort (mind. 10 Zeichen)', 's1', '', 'password', 'required autocomplete="new-password"')
    . inst_field('Wiederholen', 's1b', '', 'password', 'required autocomplete="new-password"') . '</div></div>';
echo '<div class="card shadow-sm mb-3"><div class="card-body"><h2 class="h5">Erster Admin (persönlicher Zugang)</h2>'
    . '<p class="small text-body-secondary">Darf den Status setzen und Benutzer verwalten. Die Authenticator-App wird beim ersten Login gekoppelt.</p>'
    . '<div class="mb-2"><label class="form-label" for="f_admin_id">Benutzerkennung</label><input class="form-control" id="f_admin_id" name="admin_id" value="' . $p('admin_id')
    . '" pattern="[a-z0-9_\-]{2,32}" maxlength="32" autocapitalize="none" required><div class="form-text">Kleinbuchstaben, Ziffern, _ und -, z. B. mmuster</div></div>'
    . inst_field('Name', 'admin_name', (string)($_POST['admin_name'] ?? ''), 'text', 'required maxlength="100"')
    . inst_field('E-Mail (für Erinnerungen)', 'admin_email', (string)($_POST['admin_email'] ?? ''), 'email', 'required')
    . inst_field('Passwort (mind. ' . max(12, (int)cfg('auth.password_min_length', 12)) . ' Zeichen, gern ein Satz)', 'admin_pw', '', 'password', 'required autocomplete="new-password"')
    . inst_field('Passwort wiederholen', 'admin_pw2', '', 'password', 'required autocomplete="new-password"') . '</div></div>';
echo '<div class="card shadow-sm mb-3"><div class="card-body"><h2 class="h5">E-Mail-Adressen</h2>'
    . inst_field('Kopie-Adresse (cc_default_mail1)', 'cc1', (string)($_POST['cc1'] ?? ''), 'email', 'required',
        'Erhält Erinnerungen, Kopien der ALARM-Mails und täglich den Audit-Anker, z. B. die Informationssicherheit.')
    . '<div class="mb-2"><label class="form-label" for="f_rcpt">ALARM-Empfänger (optional, eine Adresse je Zeile)</label>'
    . '<textarea class="form-control" id="f_rcpt" name="recipients" rows="4">' . $p('recipients') . '</textarea>'
    . '<div class="form-text">Werden nur per BCC angeschrieben und verschlüsselt gespeichert. Später unter System änderbar.</div></div>'
    . '</div></div>';
echo '<div class="d-grid"><button class="btn btn-primary btn-lg" type="submit">Einrichtung abschließen</button></div></form>';
page_end();
