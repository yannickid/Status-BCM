<?php
/**
 * Selbsttest (CLI):  php tests/selftest.php
 * Arbeitet in einem temporären Verzeichnis mit SQLite und Mail-Transport "log" – berührt keine echte Konfiguration.
 */
declare(strict_types=1);

if (PHP_SAPI !== 'cli') {
    http_response_code(404);
    exit;
}

$tmp = sys_get_temp_dir() . '/sbcm-selftest-' . bin2hex(random_bytes(4));
mkdir($tmp, 0700, true);
ini_set('error_log', $tmp . '/php-error.log'); // erwartete Integritätsmeldungen nicht auf die Konsole
$local = $tmp . '/config.local.inc.php';
$totpSecret = b32_for_test();
file_put_contents($local, "<?php\nreturn " . var_export([
    'app' => ['storage_dir' => $tmp . '/storage', 'base_url' => 'https://status.test'],
    // Standard: SQLite. MySQL/MariaDB: SBCM_TEST_DSN="mysql:host=localhost;dbname=test" SBCM_TEST_USER=... SBCM_TEST_PASS=...
    'db' => ['dsn' => getenv('SBCM_TEST_DSN') ?: 'sqlite:{storage}/t.sqlite', 'user' => (string)getenv('SBCM_TEST_USER'),
        'pass' => (string)getenv('SBCM_TEST_PASS'), 'prefix' => 'st' . bin2hex(random_bytes(3)) . '_'],
    'mail' => ['transport' => 'log', 'from_email' => 'status@test.example', 'cc_default_mail1' => 'cc1@test.example', 'recipients' => []],
    'security' => ['master_key' => base64_encode(random_bytes(32))],
    'auth' => ['users' => ['anna' => ['name' => 'Anna Test', 'email' => 'anna@test.example',
        'hash' => password_hash('pw', PASSWORD_DEFAULT), 'totp_secret' => $totpSecret]]],
    'reminder' => ['repeat_minutes' => 60, 'max_count' => 3],
], true) . ";\n");
putenv('SBCM_LOCAL_CONFIG=' . $local);

define('SBCM', true);
require __DIR__ . '/../lib.inc.php';
date_default_timezone_set('UTC');

function b32_for_test(): string
{
    return 'JBSWY3DPEHPK3PXP';
}

$fails = 0;
function ok(bool $c, string $m): void
{
    global $fails;
    echo ($c ? '[ok]   ' : '[FAIL] ') . $m . "\n";
    $fails += $c ? 0 : 1;
}
function throws(callable $f): bool
{
    try {
        $f();
    } catch (Throwable $e) {
        return true;
    }
    return false;
}

/* --- config.json --- */
$j = json_decode((string)file_get_contents(__DIR__ . '/../config.json'), true);
ok(bcm_validate($j) === [], 'config.json ist strukturell gültig');
ok(bcm_lint($j) === [], 'Meldungstexte bestehen die Pressetauglichkeits-Prüfung: ' . implode('; ', bcm_lint($j)));
$bad = $j;
$bad['statuses'][1]['text'] = 'Wegen eines Hackerangriffs sind Daten kompromittiert.';
ok(count(bcm_lint($bad)) >= 3, 'Lint erkennt kritische Begriffe');
$bad = $j;
$bad['statuses'][0]['audience'] = 'X';
ok(bcm_validate($bad) !== [], 'Validierung erkennt ungültige audience');
ok(critical_terms_in('Nach einem Hackerangriff', $j) === ['angriff', 'hacker'], 'Kritische Begriffe werden gefunden');
$bad = $j;
$bad['mail_templates']['alarm']['subject'] = 'Panne: {label}';
ok(count(bcm_lint($bad)) === 1, 'Lint prüft auch Mail-Vorlagen');

$bad = $j;
$bad['statuses'][0]['phone'] = 'bitte anrufen';
ok(bcm_validate($bad) !== [], 'Validierung erkennt ungültige Status-Rufnummer');
$tel = build_payload(bcm()['by_key']['TELEFON_EINGESCHRAENKT'], []);
ok($tel['default_phone'] === '+49 151 12345678', 'Status-eigene Ausweichrufnummer ersetzt default_phone');
ok(build_payload(bcm()['by_key']['MAIL_EINGESCHRAENKT'], [])['default_phone'] === $j['default_phone'], 'Ohne Status-Rufnummer gilt default_phone');
ok(critical_terms_in('Ausfall Netzwerk', $j) === ['ausfall'], '"Ausfall" gilt als kritischer Begriff');

/* --- Krypto --- */
$c = enc('Standort München Süd', 'ctx');
ok(dec($c, 'ctx') === 'Standort München Süd', 'AES-GCM Roundtrip');
ok(throws(fn() => dec($c, 'anderer-kontext')), 'Falscher Kontext (AAD) wird abgelehnt');
$t = $c;
$t[10] = $t[10] === 'A' ? 'B' : 'A';
ok(throws(fn() => dec($t, 'ctx')), 'Manipuliertes Chiffrat wird abgelehnt');
ok(cfg_secret(cfg_encrypt('geheim@test.example')) === 'geheim@test.example', 'Verschlüsselte Config-Werte');

/* --- TOTP (RFC 6238 Testvektor, SHA1, 8 Stellen: T=59 -> 94287082) --- */
ok(totp_at('12345678901234567890', 1, 8) === '94287082', 'TOTP RFC-6238-Testvektor');
ok(b32_decode(b32_encode("hello world!")) === 'hello world!', 'Base32 Roundtrip');
$u = ['id' => 'anna', 'totp_secret' => $totpSecret];
$now = 1760000000;
$code = totp_at(b32_decode($totpSecret), intdiv($now, 30));
ok(totp_verify_user($u, $code, $now), 'TOTP korrekter Code akzeptiert');
ok(!totp_verify_user($u, $code, $now), 'TOTP Replay (gleicher Code) abgelehnt');
ok(!totp_verify_user($u, '000000', $now), 'TOTP falscher Code abgelehnt');
ok(totp_verify_user($u, totp_at(b32_decode($totpSecret), intdiv($now, 30) + 1), $now), 'TOTP ±1 Schritt Toleranz');
ok(!totp_verify_user($u, totp_at(b32_decode($totpSecret), intdiv($now, 30) + 5), $now), 'TOTP außerhalb des Fensters abgelehnt');

/* --- Status + Audit --- */
$_SERVER['REMOTE_ADDR'] = '203.0.113.9';
ok(status_current() === null, 'Zu Beginn kein Status');
[$spec, $errs] = parse_change_request(['mode' => 'set', 'status_key' => 'SICHERHEITSMASSNAHME', 'validity_type' => 'duration', 'duration' => '240'], null);
ok($spec === null && $errs !== [], 'Standortliste ist Pflicht bei ALLE_UND_ADRESSLISTE');
[$spec, $errs] = parse_change_request(['mode' => 'set', 'status_key' => 'SICHERHEITSMASSNAHME', 'loc' => ['muc-sued', 'nue-mitte', 'evil'],
    'validity_type' => 'duration', 'duration' => '240'], null);
ok($spec !== null && $spec['loc_ids'] === ['muc-sued', 'nue-mitte'], 'Unbekannte Standorte werden verworfen');
ok(spec_needs_totp($spec), 'TOTP bei kritischem Status erforderlich');
[$s2, ] = parse_change_request(['mode' => 'set', 'status_key' => 'NORMAL', 'validity_type' => 'unlimited'], null);
ok($s2 !== null && !spec_needs_totp($s2), 'Regelbetrieb ohne TOTP');
[$s3, $e3] = parse_change_request(['mode' => 'set', 'status_key' => 'HINWEIS', 'validity_type' => 'unlimited'], null);
ok($s3 === null, 'Unbefristet nicht erlaubt bei Hinweis');
[$s4, ] = parse_change_request(['mode' => 'set', 'status_key' => 'HINWEIS', 'validity_type' => 'duration', 'duration' => '999'], null);
ok($s4 === null, 'Dauer nur aus der Liste erlaubt');
[$s5, $e5] = parse_change_request(['mode' => 'set', 'status_key' => 'HINWEIS', 'alarm_mail' => '1', 'validity_type' => 'duration', 'duration' => '60'], null);
ok($s5 === null, 'ALARM-Mail ohne Empfänger wird abgelehnt: ' . implode(' ', $e5));

$res = status_create($spec, 'anna', ['totp' => true]);
$cur = status_current();
ok($cur && $cur['mac_ok'] && $cur['payload']['label'] === 'Sicherheitsmaßnahme', 'Status gesetzt, lesbar, MAC ok');
ok($cur['payload']['locations'][1]['phone'] === $j['default_phone'] && $cur['payload']['locations'][1]['default_phone'], 'Default-Rufnummer, wenn keine hinterlegt');
ok($cur['payload']['locations'][0]['phone'] === '+49 89 12345-110', 'Eigene Standort-Rufnummer');
$raw = db()->query('SELECT payload_enc FROM ' . t('status'))->fetchColumn();
ok(!str_contains((string)$raw, 'Standort') && !str_contains((string)$raw, 'Sicherheits'), 'Nutzdaten (Text/Standorte) liegen verschlüsselt in der DB');

[$ext, ] = parse_change_request(['mode' => 'extend', 'validity_type' => 'duration', 'duration' => '60'], $cur);
status_create($ext, 'anna');
ok(count(status_history()) === 2 && status_current()['payload']['locations'][0]['id'] === 'muc-sued', 'Verlängerung: neue Zeile, Standorte übernommen, Historie vollständig');
[$end, ] = parse_change_request(['mode' => 'end'], status_current());
status_create($end, 'anna');
ok(status_current()['status_key'] === 'NORMAL', 'Beenden setzt Regelbetrieb');

$v = audit_verify();
ok($v['ok'] && $v['count'] === 3, 'Audit-Kette intakt (' . $v['count'] . ' Einträge)');
$rec = audit_recent(1)[0];
ok($rec['actor'] === 'anna' && $rec['details']['mode'] === 'end' && $rec['details']['how'] === [] && isset($rec['details']['_ctx']['sapi']), 'Audit: wer/was/wann/wie entschlüsselbar');
$rawAudit = db()->query('SELECT details_enc FROM ' . t('audit') . ' ORDER BY seq LIMIT 1')->fetchColumn();
ok(!str_contains((string)$rawAudit, 'status.') && !str_contains((string)$rawAudit, 'before'), 'Audit-Details (Klartext-Felder) nicht in der DB lesbar');
ok(throws(fn() => db()->exec('UPDATE ' . t('audit') . " SET actor = 'x' WHERE seq = 1")), 'DB-Trigger blockiert UPDATE auf Audit');
ok(throws(fn() => db()->exec('DELETE FROM ' . t('audit'))), 'DB-Trigger blockiert DELETE auf Audit');

// Manipulation simulieren (Trigger entfernen = Angreifer mit DB-Vollzugriff)
db()->exec('DROP TRIGGER ' . t('audit') . '_no_upd');
db()->exec('UPDATE ' . t('audit') . " SET actor = 'mallory' WHERE seq = 2");
$v = audit_verify();
ok(!$v['ok'] && str_contains((string)$v['error'], '#2'), 'Manipulierter Audit-Eintrag wird erkannt: ' . $v['error']);
db()->exec('UPDATE ' . t('audit') . " SET actor = 'anna' WHERE seq = 2");
ok(audit_verify()['ok'], 'Nach Rückgängigmachen wieder intakt');

db()->exec('UPDATE ' . t('status') . " SET severity = 'ok' WHERE id = 1");
ok(!status_decode(db()->query('SELECT * FROM ' . t('status') . ' WHERE id = 1')->fetch())['mac_ok'], 'Manipulierte Status-Zeile wird per MAC erkannt');

db()->exec('UPDATE ' . t('status') . " SET state = 'superseded' WHERE id = 3");
db()->exec('UPDATE ' . t('status') . " SET state = 'active' WHERE id = 2");
ok(status_current()['id'] == 2 && !status_current()['mac_ok'], 'Reaktivierte alte Status-Zeile wird erkannt (Abgleich mit Audit)');
db()->exec('UPDATE ' . t('status') . " SET state = 'superseded' WHERE id = 2");
db()->exec('UPDATE ' . t('status') . " SET state = 'active' WHERE id = 3");
ok(status_current()['mac_ok'], 'Aktueller Status wieder konsistent');
ok(throws(fn() => db()->exec('DELETE FROM ' . t('status'))), 'DB-Trigger blockiert DELETE in der Status-Historie');

/* --- Cron: Erinnerung / Wiederholung / Limit --- */
$spec['valid_until'] = gmdate('Y-m-d H:i:s', time() - 600);
status_create($spec, 'anna');
$log = run_cron();
ok(count(array_filter($log, fn($l) => str_contains($l, 'Erinnerung'))) === 1, 'Cron sendet Erinnerung nach Ablauf');
$eml = glob(storage_dir() . '/outbox/*.eml');
$remind = null;
foreach ($eml as $f) {
    $c = (string)file_get_contents($f);
    if (str_contains($c, 'X-Envelope-Rcpt: anna@test.example')) {
        $remind = $c;
    }
}
ok($remind !== null && str_contains($remind, 'cc1@test.example'), 'Erinnerung geht an Autor + cc_default_mail1');
ok(count(array_filter(run_cron(), fn($l) => str_contains($l, 'Erinnerung'))) === 0, 'Keine Doppel-Erinnerung innerhalb des Intervalls');
ok(count(array_filter(run_cron(time() + 3700), fn($l) => str_contains($l, 'Erinnerung'))) === 1, 'Wiederholung nach Intervall');
run_cron(time() + 7400);
ok(count(array_filter(run_cron(time() + 11100), fn($l) => str_contains($l, 'Erinnerung'))) === 0, 'Optionales Limit (max_count = 3) greift');
ok(kv_get('anchor_day') === gmdate('Y-m-d'), 'Täglicher Audit-Anker wurde versendet');
ok(db()->query('SELECT content_enc FROM ' . t('mail_log') . " WHERE kind = 'reminder' LIMIT 1")->fetchColumn() !== false, 'Mail-Inhalt wird protokolliert');
$mc = (string)db()->query('SELECT content_enc FROM ' . t('mail_log') . ' LIMIT 1')->fetchColumn();
ok(!str_contains($mc, 'Statusmeldung'), 'Mail-Inhalte liegen verschlüsselt in der DB');

/* --- Alarm-Mail: BCC, Empfänger geschützt --- */
$rl = file_get_contents($local);
$cfgArr = require $local;
$cfgArr['mail']['recipients'] = [cfg_encrypt('geheim1@ziel.example'), 'geheim2@ziel.example'];
$cfgArr['mail']['cc_default_mail1'] = cfg_encrypt('cc1@test.example');
file_put_contents($local, "<?php\nreturn " . var_export($cfgArr, true) . ";\n");
// cfg() ist gecacht -> frischer Prozess für den Alarm-Test
$php = escapeshellarg(PHP_BINARY);
$code = <<<'PHP'
define('SBCM', true); require $argv[1] . '/lib.inc.php';
$_SERVER['REMOTE_ADDR'] = '203.0.113.9';
$c = status_current(); $p = $c['payload'];
$r = send_alarm_mail((int)$c['id'], $p, $c['valid_until'], 'anna');
echo json_encode($r);
PHP;
$o = shell_exec('SBCM_LOCAL_CONFIG=' . escapeshellarg($local) . " $php -r " . escapeshellarg($code) . ' ' . escapeshellarg(dirname(__DIR__)));
$sum = json_decode((string)$o, true);
ok(is_array($sum) && $sum['total'] === 4 && $sum['ok'] === 4, 'ALARM-Mail: 2 Ziel-Adressen + Autor + CC = 4 Empfänger: ' . trim((string)$o));
$latest = '';
foreach (glob(storage_dir() . '/outbox/*.eml') as $f) {
    $c = (string)file_get_contents($f);
    if (str_contains($c, 'geheim1@ziel.example')) {
        $latest = $c;
    }
}
$headers = explode("\r\n\r\n", $latest)[0] ?? '';
ok($latest !== '', 'Alarm-Mail wurde an die Ziel-Adressen übergeben (Envelope)');
$visible = preg_replace('/^X-Envelope-Rcpt:.*\r\n/', '', $latest) ?? '';
ok(str_contains($visible, 'To: undisclosed-recipients:;') && !str_contains($visible, 'geheim'),
    'Ziel-Adressen stehen nicht in den sichtbaren Mail-Headern (BCC)');
$lastMail = db()->query('SELECT result_enc FROM ' . t('mail_log') . " WHERE kind = 'alarm'")->fetchColumn();
ok(!str_contains((string)$lastMail, 'geheim1') && str_contains(dec((string)$lastMail, 'mail.result'), 'g******@z***.example'), 'Protokoll speichert nur maskierte Adressen, verschlüsselt');

/* --- Nutzung: Lesezähler und Login-Statistik --- */
$sid = (int)status_current()['id'];
$_SESSION = [];
view_count($sid);
view_count($sid);
$_SESSION = [];
view_count($sid);
ok(view_totals([$sid]) === [$sid => 2], 'Lesezähler: einmal je Sitzung und Status');
ok(!str_contains(json_encode(db()->query('SELECT * FROM ' . t('view_count'))->fetchAll()), '203.0.113'), 'Lesezähler speichert keine IP');
audit('login1.ok', 'session', [], 'stage1', 1);
audit('login1.ok', 'session', [], 'stage1', 1);
audit('login2.ok', 'session', [], 'anna', 2);
audit('login2.fail', 'session', ['user' => 'x'], 'anonymous', 1);
$st = login_stats(30);
ok($st['periods']['heute']['s1'] === 2 && $st['periods']['heute']['s2'] === ['anna' => 1] && $st['periods']['30 Tage']['fail'] === 1,
    'Login-Statistik zählt Stufe 1, Stufe 2 je Benutzer und Fehlversuche');
ok($st['last']['anna'] !== null && count($st['days']) === 1, 'Login-Statistik: letzte Anmeldung und Tageswerte');
ok(audit_verify()['ok'], 'Audit-Kette nach Statistik-Einträgen intakt');

/* --- Benutzerverwaltung (DB-Benutzer, Zeilen-MAC, Passwort-Gültigkeit) --- */
$once = account_action('create', 'bert', ['name' => 'Bert Redaktion', 'email' => 'bert@test.example', 'role' => 'editor'], 'anna', ['totp' => true]);
$bert = users()['bert'] ?? null;
ok(is_string($once) && strlen($once) === 19 && $bert && $bert['role'] === 'editor' && $bert['must_change'], 'Benutzer angelegt: Einmalpasswort, Rolle Redaktion, Wechselpflicht');
ok(user_needs_setup(['id' => 'bert'] + $bert) && verify_user('bert', $once) !== null, 'Einmalpasswort gilt nur für die Ersteinrichtung');
ok(throws(fn() => account_action('create', 'bert', ['name' => 'X', 'email' => 'x@test.example'], 'anna')), 'Doppelte Kennung abgelehnt');
ok(password_policy('kurz', 'bert') !== [] && password_policy('bert-ist-super-123', 'bert') !== [] && password_policy('Sonnenblume am Fenster 7', 'bert') === [],
    'Passwortregeln: Länge, kein Benutzername');
account_action('set_pw', 'bert', ['hash' => password_hash('Sonnenblume am Fenster 7', PASSWORD_DEFAULT)], 'bert');
account_action('set_totp', 'bert', ['totp_b32' => 'JBSWY3DPEHPK3PXQ'], 'bert');
$bert = users()['bert'];
ok(!$bert['must_change'] && !user_needs_setup($bert) && $bert['pw_valid_until'] !== null && pw_state($bert) === 'ok', 'Nach Einrichtung: gültiges Passwort mit Ablaufdatum');
$rawAcc = (string)json_encode(db()->query('SELECT * FROM ' . t('account'))->fetchAll());
ok(!str_contains($rawAcc, 'bert@test.example') && !str_contains($rawAcc, 'JBSWY3DPEHPK3PXQ'), 'E-Mail und TOTP-Secret liegen verschlüsselt in der DB');
db()->exec('UPDATE ' . t('account') . " SET role = 'admin' WHERE id = 'bert'");
ok(!isset(users(false, true)['bert']) && !users(true)['bert']['mac_ok'], 'Rolle direkt in der DB geändert -> Benutzer gesperrt (MAC)');
db()->exec('UPDATE ' . t('account') . " SET role = 'editor' WHERE id = 'bert'");
ok(isset(users(false, true)['bert']), 'Nach Rückgängigmachen wieder gültig');
ok(throws(fn() => db()->exec('DELETE FROM ' . t('account'))), 'DB-Trigger verhindert das Löschen von Benutzern');
account_action('disable', 'bert', [], 'anna');
ok(verify_user('bert', 'Sonnenblume am Fenster 7') === null, 'Deaktivierter Benutzer kann sich nicht anmelden');
account_action('enable', 'bert', [], 'anna');
ok(throws(fn() => account_action('reset_pw', 'anna', [], 'bert')), 'Konfig-Benutzer sind in der Weboberfläche nicht änderbar');
$rec = audit_recent(1)[0];
ok($rec['action'] === 'user.enable' && $rec['actor'] === 'anna' && audit_verify()['ok'], 'Benutzeränderungen im Audit-Log');
// Ablauf und Erinnerung: Gültigkeit künstlich (mit gültigem MAC) auf morgen setzen
account_write('bert', ['pw_valid_until' => gmdate('Y-m-d H:i:s', time() + 86400)], false, 'test');
ok(pw_state(users()['bert']) === 'soon', 'Passwort läuft bald ab');
$pl = password_reminders(time());
ok(count(array_filter($pl, fn($l) => str_contains($l, 'Passwort-Erinnerung bert'))) === 1, 'Cron: Passwort-Erinnerung versendet');
ok(password_reminders(time() + 3600) === [], 'Keine Wiederholung vor Ablauf des Intervalls');
ok(count(password_reminders(time() + 8 * 86400)) === 1 && pw_state(users()['bert'], time() + 2 * 86400) === 'expired', 'Wiederholung nach 7 Tagen, danach abgelaufen');
account_write('bert', ['pw_valid_until' => gmdate('Y-m-d H:i:s', time() - 60)], false, 'test');
ok(user_needs_setup(users()['bert']) && verify_user('bert', 'Sonnenblume am Fenster 7') !== null, 'Abgelaufen: Login möglich, aber Wechsel erzwungen');

/* --- Throttle --- */
for ($i = 0; $i < 5; $i++) {
    throttle_record('s2', 'anna', false);
}
ok(throttle_locked('s2', 'anna') > 0, 'Brute-Force-Sperre nach 5 Fehlversuchen');
ok(throttle_locked('s1') === 0, 'Sperre gilt nur für den betroffenen Bereich');

/* --- Aufräumen --- */
if (db_driver() === 'mysql') {
    foreach (['audit_no_upd', 'audit_no_del', 'status_no_del', 'account_no_del'] as $tr) {
        try { db()->exec('DROP TRIGGER ' . t($tr)); } catch (Throwable $e) { }
    }
    foreach (['status', 'audit', 'mail_log', 'login_attempt', 'totp_used', 'kv', 'view_count', 'account'] as $tb) {
        db()->exec('DROP TABLE IF EXISTS ' . t($tb));
    }
}
exec('rm -rf ' . escapeshellarg($tmp));
echo $fails === 0 ? "\nAlle Tests bestanden.\n" : "\n$fails Test(s) fehlgeschlagen.\n";
exit($fails === 0 ? 0 : 1);
