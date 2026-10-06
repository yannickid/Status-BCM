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
    'channels' => ['signal' => ['url' => 'https://signal.test/v2/send', 'number' => '+491700000000', 'token' => 'sig-geheim'],
        'groupalarm' => ['token' => 'ga-geheim', 'organization_id' => 4711]],
], true) . ";\n");
putenv('SBCM_LOCAL_CONFIG=' . $local);

define('SBCM', true);
require __DIR__ . '/../lib.inc.php';
require __DIR__ . '/../qr.inc.php';
require __DIR__ . '/../pdf.inc.php';
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

/* --- Meldungen + Audit --- */
$_SERVER['REMOTE_ADDR'] = '203.0.113.9';
ok(status_current() === null && status_board()['live'] === [], 'Zu Beginn keine Meldung');
[$spec, $errs] = parse_change_request(['mode' => 'set', 'status_key' => 'SICHERHEITSMASSNAHME', 'validity_type' => 'duration', 'duration' => '240'], null);
ok($spec === null && $errs !== [], 'Standortliste ist Pflicht bei ALLE_UND_ADRESSLISTE');
[$spec, $errs] = parse_change_request(['mode' => 'set', 'status_key' => 'SICHERHEITSMASSNAHME', 'loc' => ['muc-sued', 'nue-mitte', 'evil'],
    'validity_type' => 'duration', 'duration' => '240'], null);
ok($spec !== null && $spec['loc_ids'] === ['muc-sued', 'nue-mitte'], 'Unbekannte Standorte werden verworfen');
ok(spec_needs_totp($spec), 'TOTP bei kritischem Status erforderlich');
[$s2, ] = parse_change_request(['mode' => 'set', 'status_key' => 'NORMAL', 'validity_type' => 'unlimited'], null);
ok($s2 === null, 'Regelbetrieb ist keine eigene Meldung (wird angezeigt, wenn nichts gilt)');
[$s3, $e3] = parse_change_request(['mode' => 'set', 'status_key' => 'HINWEIS', 'validity_type' => 'unlimited'], null);
ok($s3 === null, 'Unbefristet nicht erlaubt bei Hinweis');
[$s4, ] = parse_change_request(['mode' => 'set', 'status_key' => 'HINWEIS', 'validity_type' => 'duration', 'duration' => '999'], null);
ok($s4 === null, 'Dauer nur aus der Liste erlaubt');
[$s5, $e5] = parse_change_request(['mode' => 'set', 'status_key' => 'HINWEIS', 'alarm_mail' => '1', 'validity_type' => 'duration', 'duration' => '60'], null);
ok($s5 === null, 'ALARM-Mail ohne Empfänger wird abgelehnt: ' . implode(' ', $e5));

$res = status_create($spec, 'anna', ['totp' => true]);
$cur = status_current();
ok($cur && $cur['mac_ok'] && $cur['payload']['label'] === 'Sicherheitsmaßnahme' && $res['msg'] === 1, 'Meldung gesetzt, lesbar, MAC ok');
ok($cur['payload']['locations'][1]['phone'] === $j['default_phone'] && $cur['payload']['locations'][1]['default_phone'], 'Default-Rufnummer, wenn keine hinterlegt');
ok($cur['payload']['locations'][0]['phone'] === '+49 89 12345-110', 'Eigene Standort-Rufnummer');
$raw = db()->query('SELECT payload_enc FROM ' . t('status'))->fetchColumn();
ok(!str_contains((string)$raw, 'Standort') && !str_contains((string)$raw, 'Sicherheits'), 'Nutzdaten (Text/Standorte) liegen verschlüsselt in der DB');

// Zweite, gleichzeitige Meldung an einem anderen Standort
[$specB, ] = parse_change_request(['mode' => 'set', 'status_key' => 'NETZ_EINGESCHRAENKT', 'loc' => ['ham-hafen'],
    'validity_type' => 'duration', 'duration' => '120'], null);
$resB = status_create($specB, 'anna');
$bd = status_board();
ok(count($bd['live']) === 2 && $bd['live'][0]['status_key'] === 'SICHERHEITSMASSNAHME' && $bd['live'][1]['status_key'] === 'NETZ_EINGESCHRAENKT',
    'Zwei Meldungen gleichzeitig, kritische zuerst');

[$ext, ] = parse_change_request(['mode' => 'extend', 'validity_type' => 'duration', 'duration' => '60'], status_target($res['id']));
$resA2 = status_create($ext, 'anna');
$bd = status_board();
ok(count(status_history()) === 3 && count($bd['live']) === 2 && $resA2['msg'] === $res['id']
    && $bd['live'][0]['id'] == $resA2['id'] && $bd['live'][0]['payload']['locations'][0]['id'] === 'muc-sued',
    'Verlängerung: neue Version derselben Meldung, Standorte übernommen, andere Meldung unberührt');
ok(status_target($res['id']) === null && throws(fn() => status_create($ext, 'anna')), 'Abgelöste Version kann nicht erneut geändert werden');
[$upd, $ue] = parse_change_request(['mode' => 'update', 'loc' => ['ber-nord'], 'validity_type' => 'duration', 'duration' => '240'], status_target($resB['id']));
$resB2 = status_create($upd, 'anna');
$b2 = array_values(array_filter(status_board()['live'], fn($r) => $r['msg'] === $resB['id']));
ok(count($b2) === 1 && $b2[0]['payload']['locations'][0]['id'] === 'ber-nord', 'Ändern: Standorte einer Meldung angepasst');
[$end, $ee] = parse_change_request(['mode' => 'end'], status_target($resB2['id']));
ok($end !== null && spec_needs_totp($end), 'Beenden einer Meldung der Stufe "Hinweis" verlangt TOTP wie das Setzen');
ok(!spec_needs_totp(['mode' => 'end', 'key' => 'HINWEIS']) && spec_needs_totp(['mode' => 'end', 'key' => 'STANDORT_GESPERRT']),
    'Beenden: "Information" ohne TOTP, "Wichtiger Hinweis" mit TOTP');
status_end($resB2['id'], 'anna', [], 'gelöst');
$bd = status_board();
ok(count($bd['live']) === 1 && count($bd['recent']) === 1 && $bd['recent'][0]['gone'] === 'ended' && $bd['recent'][0]['mac_ok'],
    'Beendet: bleibt ausgegraut als "zurückgenommen / gelöst" sichtbar');
$later = status_board(time() + 2 * 3600);
ok(count($later['live']) === 0 && count(array_filter($later['recent'], fn($r) => $r['gone'] === 'expired')) === 1, 'Abgelaufen: ausgegraut als "nicht mehr gültig"');
$much = status_board(time() + 49 * 3600);
ok($much['recent'] === [] && count($much['stale']) === 1, 'Nach 48 Stunden nicht mehr angezeigt');
ob_start();
render_board($bd, false);
$html = (string)ob_get_clean();
ok(str_contains($html, 'Zurückgenommen / gelöst') && str_contains($html, 'status-gone'), 'Anzeige: beendete Meldung ausgegraut mit Vermerk');

$v = audit_verify();
ok($v['ok'] && $v['count'] === 5, 'Audit-Kette intakt (' . $v['count'] . ' Einträge)');
$rec = audit_recent(1)[0];
ok($rec['actor'] === 'anna' && $rec['action'] === 'status.end' && $rec['details']['msg'] === $resB['id'] && $rec['details']['note'] === 'gelöst'
    && isset($rec['details']['_ctx']['sapi']), 'Audit: wer/was/wann/wie entschlüsselbar');
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
db()->exec('UPDATE ' . t('status') . " SET severity = 'critical' WHERE id = 1");
db()->exec('UPDATE ' . t('status') . " SET msg_id = NULL WHERE id = " . $resA2['id']);
ok(!status_board()['live'][0]['mac_ok'] || status_board()['unverified'] !== [], 'Umgehängte Meldungsnummer wird per MAC erkannt');
db()->exec('UPDATE ' . t('status') . ' SET msg_id = ' . $res['id'] . ' WHERE id = ' . $resA2['id']);

db()->exec('UPDATE ' . t('status') . " SET state = 'active' WHERE id = 1");
$bd = status_board();
ok(count($bd['unverified']) === 1 && $bd['unverified'][0]['id'] == 1 && count($bd['live']) === 1 && $bd['live'][0]['mac_ok'],
    'Reaktivierte alte Version wird erkannt (Abgleich mit Audit)');
db()->exec('UPDATE ' . t('status') . " SET state = 'superseded' WHERE id = 1");
db()->exec('UPDATE ' . t('status') . " SET state = 'active' WHERE id = " . $resB2['id']);
ok(count(status_board()['unverified']) === 1, 'Wieder aktivierte beendete Meldung wird erkannt');
db()->exec('UPDATE ' . t('status') . " SET state = 'ended' WHERE id = " . $resB2['id']);
$bd = status_board();
ok($bd['unverified'] === [] && $bd['live'][0]['mac_ok'] && $bd['recent'][0]['mac_ok'], 'Meldungen wieder konsistent');
ok(throws(fn() => db()->exec('DELETE FROM ' . t('status'))), 'DB-Trigger blockiert DELETE in der Status-Historie');

/* --- Umstieg von Version 1.2 (eine Meldung, keine Spalte msg_id) --- */
$cfgOld = require $local;
$cfgOld['db']['prefix'] = 'su' . bin2hex(random_bytes(3)) . '_';
$localOld = $tmp . '/config.old.inc.php';
file_put_contents($localOld, "<?php\nreturn " . var_export($cfgOld, true) . ";\n");
$codeOld = <<<'PHP'
define('SBCM', true); require $argv[1] . '/lib.inc.php';
$_SERVER['REMOTE_ADDR'] = '203.0.113.9';
$mk = function (string $key, array $locs) {
    $r = status_create(['mode' => 'set', 'key' => $key, 'loc_ids' => $locs, 'valid_until' => gmdate('Y-m-d H:i:s', time() + 3600)], 'anna');
    return $r['id'];
};
// Zustand wie in 1.2: jede Meldung löste die vorige ab, "Ende" setzte Regelbetrieb
$a = $mk('SICHERHEITSMASSNAHME', ['muc-sued']);
db()->exec('UPDATE ' . t('status') . " SET state = 'superseded' WHERE id = $a");
$b = $mk('HINWEIS', []);
$o = [];
db()->exec('ALTER TABLE ' . t('status') . ' DROP COLUMN msg_id');
db()->prepare('DELETE FROM ' . t('kv') . ' WHERE k = ?')->execute(['multi_since_seq']);
schema_upgrade(db());
$bd = status_board();
$o['hint'] = count($bd['live']) === 1 && $bd['live'][0]['id'] == $b && $bd['unverified'] === [];
$o['since'] = (int)kv_get('multi_since_seq') === 2;
// zweiter Fall: zuletzt Regelbetrieb gesetzt
db()->exec('UPDATE ' . t('status') . " SET state = 'superseded' WHERE id = $b");
status_create(['mode' => 'set', 'key' => 'NORMAL', 'loc_ids' => [], 'valid_until' => null], 'anna');
db()->exec('ALTER TABLE ' . t('status') . ' DROP COLUMN msg_id');
db()->prepare('DELETE FROM ' . t('kv') . ' WHERE k = ?')->execute(['multi_since_seq']);
schema_upgrade(db());
$bd = status_board();
$o['normal'] = $bd['live'] === [] && $bd['unverified'] === [];
$mk('NETZ_EINGESCHRAENKT', ['ham-hafen']);
$mk('HINWEIS', []);
$o['multi'] = count(status_board()['live']) === 2;
if (db_driver() === 'mysql') {
    foreach (['audit_no_upd', 'audit_no_del', 'status_no_del', 'account_no_del'] as $tr) {
        try { db()->exec('DROP TRIGGER ' . t($tr)); } catch (Throwable $e) { }
    }
    foreach (['status', 'audit', 'mail_log', 'login_attempt', 'totp_used', 'kv', 'view_count', 'account'] as $tb) {
        db()->exec('DROP TABLE IF EXISTS ' . t($tb));
    }
}
echo json_encode($o);
PHP;
$o = json_decode((string)shell_exec('SBCM_LOCAL_CONFIG=' . escapeshellarg($localOld) . ' ' . escapeshellarg(PHP_BINARY) . ' -r '
    . escapeshellarg($codeOld) . ' ' . escapeshellarg(dirname(__DIR__)) . ' 2>&1'), true);
ok(($o['since'] ?? false) && ($o['hint'] ?? false), 'Umstieg 1.2: Spalte nachgerüstet, bisherige Meldung bleibt die einzige gültige');
ok($o['normal'] ?? false, 'Umstieg 1.2: früherer Regelbetrieb erscheint nicht als Meldung');
ok($o['multi'] ?? false, 'Nach dem Umstieg gelten mehrere Meldungen gleichzeitig');

/* --- Cron: Erinnerung / Wiederholung / Limit --- */
status_end($resA2['id'], 'anna');
$spec['valid_until'] = gmdate('Y-m-d H:i:s', time() - 600);
$resC = status_create($spec, 'anna');
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

/* --- Alarmkreise, Standort-Adressen, Kontakte, Präfixe --- */
$cfgArr = require $local;
$cfgArr['mail']['cc_default_mail1'] = cfg_encrypt('cc1@test.example');
file_put_contents($local, "<?php\nreturn " . var_export($cfgArr, true) . ";\n");
ok(circle_update('allgemein', "geheim1@ziel.example\ngeheim2@ziel.example", [], 'system:test') === null, 'Bisheriger Kreis "Allgemein" übernommen');
ok(circle_create('IT', "it1@ziel.example\nit2@ziel.example; it1@ziel.example", 'system:test') === null, 'Alarmkreis IT angelegt');
ok(circle_create('it', 'x@ziel.example', 'system:test') !== null && circle_create('Leitung', 'kaputt', 'system:test') !== null, 'Doppelter Name und ungültige Adresse abgelehnt');
ok(circle_create('BOA/Krisenstab', 'boa@ziel.example', 'system:test') === null, 'Alarmkreis BOA/Krisenstab angelegt');
$circ = array_column(alarm_circles(), null, 'id');
ok(array_keys($circ) === ['allgemein', 'it', 'boa-krisenstab'] && $circ['it']['emails'] === ['it1@ziel.example', 'it2@ziel.example'],
    'Kreise mit eindeutiger Kennung, Doppelte entfernt');
ok(circle_update('it', 'it3@ziel.example', [0], 'system:test') === null && array_column(alarm_circles(), null, 'id')['it']['emails'] === ['it2@ziel.example', 'it3@ziel.example'],
    'Kreis: Adresse ergänzt und entfernt');
ok(circle_update('it', 'it3@ziel.example', [], 'system:test') !== null, 'Kreis: keine Änderung wird gemeldet');
ok(circle_create('Leitung', 'chef@ziel.example', 'system:test') === null && circle_delete('leitung', 'system:test') === null
    && count(alarm_circles()) === 3, 'Kreis gelöscht');
$rawC = (string)kv_get('set:circles');
ok($rawC !== '' && !str_contains($rawC, 'ziel') && !str_contains($rawC, 'Krisenstab'), 'Alarmkreise verschlüsselt gespeichert');

ok(location_save('ham-hafen', 'Hamburg Hafen', '+49 40 1234-0', 'verwaltung.ham@ziel.example', [], 'system:test') === null
    && location_emails('ham-hafen') === ['verwaltung.ham@ziel.example'], 'Standort: E-Mail der Standortverwaltung hinterlegt');
ok(!isset(bcm()['locations_by_id']['ham-hafen']['emails']) && bcm()['locations_by_id']['ham-hafen']['phone'] === '+49 40 1234-0',
    'Standort-Adressen sind nicht Teil der Anzeigedaten');
ok(location_save('', 'Köln Süd', '', 'koeln@ziel.example', [], 'system:test') === null && isset(bcm()['locations_by_id']['koeln-sued']), 'Standort angelegt');
ok(location_save('', 'Standort mit Hackerangriff', '', '', [], 'system:test') !== null, 'Standortname mit kritischem Begriff abgelehnt');
ok(location_delete('koeln-sued', 'system:test') === null && !isset(bcm()['locations_by_id']['koeln-sued']), 'Standort gelöscht');
ok(!str_contains((string)kv_get('set:locations'), 'verwaltung'), 'Standort-Adressen verschlüsselt gespeichert');

ok(contact_save('', ['name' => 'Krisenstab-Konferenz', 'platform' => 'Teams', 'url' => 'https://teams.example/meet/1', 'meeting' => '123 456#'], 'system:test') === null,
    'Kontakt (Videokonferenz) angelegt');
ok(contact_save('', ['name' => 'Leer'], 'system:test') !== null && contact_save('', ['name' => 'X', 'url' => 'http://unsicher.example'], 'system:test') !== null
    && contact_save('', ['name' => 'X', 'url' => 'javascript:alert(1)'], 'system:test') !== null, 'Kontakt ohne Angabe oder ohne https abgelehnt');
ok(contact_save('', ['name' => 'Notfallnummer IT', 'phone' => '+49 30 999-0'], 'system:test') === null && count(contacts_all()) === 2, 'Notfallnummer angelegt');
ok(mail_prefixes() === SBCM_PREFIX_DEFAULTS && mail_prefixes_set(['new' => 'Ausfall!', 'update' => '', 'end' => ''], 'system:test') !== null,
    'Präfixe: Standardwerte, kritische Begriffe abgelehnt');
ok(mail_prefixes_set(['new' => '[NOTFALL]', 'update' => '[Update]', 'end' => '[Entwarnung]'], 'system:test') === null && mail_prefixes()['new'] === '[NOTFALL]',
    'Präfixe gespeichert');

[$sp, $se] = parse_change_request(['mode' => 'set', 'status_key' => 'NETZ_EINGESCHRAENKT', 'loc' => ['ham-hafen'], 'contacts' => ['krisenstab-konferenz', 'gibts-nicht'],
    'validity_type' => 'duration', 'duration' => '60', 'alarm_mail' => '1', 'circles' => ['it', 'evil'], 'notify_loc' => '1'], null);
ok($sp !== null && $sp['circles'] === ['it'] && $sp['contact_ids'] === ['krisenstab-konferenz'], 'Meldung mit Kreis und Kontakt: Unbekanntes verworfen');
[$to, $names, $lc] = alarm_targets($sp, ['locations' => [['id' => 'ham-hafen']]]);
ok(count($to) === 3 && $names === ['IT'] && $lc === 1, 'Empfänger: gewählter Kreis + Standortverwaltung des betroffenen Standorts');
[$to2] = alarm_targets(['circles' => [], 'notify_locations' => true], ['locations' => []]);
ok($to2 === ['verwaltung.ham@ziel.example'], 'Meldung ohne Standortliste: alle Standortverwaltungen');
$resM = status_create($sp, 'anna', ['totp' => true]);
ok(($resM['payload']['contacts'][0]['url'] ?? '') === 'https://teams.example/meet/1', 'Kontakt wird mit der Meldung gespeichert');

/* --- Alarm-Mail: BCC, Empfänger geschützt --- */
// cfg() ist gecacht -> frischer Prozess für den Alarm-Test
$php = escapeshellarg(PHP_BINARY);
$code = <<<'PHP'
define('SBCM', true); require $argv[1] . '/lib.inc.php';
$_SERVER['REMOTE_ADDR'] = '203.0.113.9';
$id = (int)$argv[2];
$c = null;
foreach (status_board()['live'] as $r) { if ((int)$r['id'] === $id) { $c = $r; } }
$spec = ['circles' => ['allgemein', 'it'], 'notify_locations' => true];
$r = send_alarm_mail('new', $id, $c['payload'], $c['valid_until'], 'anna', $spec);
$r2 = send_alarm_mail('end', $id, $c['payload'], null, 'anna', ['circles' => ['boa-krisenstab'], 'notify_locations' => false]);
echo json_encode([$r, $r2]);
PHP;
$o = shell_exec('SBCM_LOCAL_CONFIG=' . escapeshellarg($local) . " $php -r " . escapeshellarg($code) . ' ' . escapeshellarg(dirname(__DIR__)) . ' ' . (int)$resM['id']);
[$sum, $sum2] = json_decode((string)$o, true) ?: [null, null];
ok(is_array($sum) && $sum['total'] === 8 && $sum['ok'] === 8, 'ALARM-Mail: An-Feld (Absender) + 2 (Allgemein) + 2 (IT) + 1 Standort + Autor + CC = 8 Empfänger: ' . trim((string)$o));
ok(is_array($sum2) && $sum2['total'] === 4, 'Ende-Mail nur an An-Feld + gewählten Kreis + Autor + CC');
$latest = '';
$endMail = '';
foreach (glob(storage_dir() . '/outbox/*.eml') as $f) {
    $c = (string)file_get_contents($f);
    if (str_contains($c, 'geheim1@ziel.example')) {
        $latest = $c;
    }
    if (str_contains($c, 'boa@ziel.example')) {
        $endMail = $c;
    }
}
ok($latest !== '' && str_contains($latest, 'verwaltung.ham@ziel.example'), 'Alarm-Mail wurde an Kreise und Standortverwaltung übergeben (Envelope)');
$visible = preg_replace('/^X-Envelope-Rcpt:.*\r\n/m', '', $latest) ?? '';
ok(str_contains($visible, 'To: status@test.example') && !str_contains($visible, 'undisclosed') && !str_contains($visible, 'geheim') && !str_contains($visible, 'verwaltung'),
    'An-Feld = Absender, Ziel-Adressen nur als BCC (nicht in den sichtbaren Headern)');
$plain = function (string $eml): string {
    [$head, $body] = explode("\r\n\r\n", $eml, 2) + ['', ''];
    return iconv_mime_decode_headers($head, 0, 'UTF-8')['Subject'] . "\n" . base64_decode(str_replace("\r\n", '', $body));
};
ok(str_starts_with($plain($latest), '[NOTFALL] Statusmeldung') && str_contains($plain($latest), 'https://teams.example/meet/1, Konferenz-ID 123 456#'),
    'Betreff-Präfix und Kontakt in der ALARM-Mail');
ok(str_starts_with($plain($endMail), '[Entwarnung] Statusmeldung beendet') && str_contains($plain($endMail), 'nicht mehr gültig'), 'Ende-Mail mit eigenem Präfix');
$lastMail = db()->query('SELECT result_enc FROM ' . t('mail_log') . " WHERE kind = 'alarm'")->fetchColumn();
ok(!str_contains((string)$lastMail, 'geheim1') && str_contains(dec((string)$lastMail, 'mail.result'), 'g******@z***.example'), 'Protokoll speichert nur maskierte Adressen, verschlüsselt');

/* --- Weitere Alarmkanäle: Signal, GroupAlarm --- */
ok(signal_recipient('+49 170 123-4567') === '+491701234567' && signal_recipient('0049 (171) 7654321') === '+491717654321'
    && signal_recipient('0170 1234567') === null && signal_recipient('group.abc') === null && signal_recipient('group.YWJjZGVmZ2hpams=') === 'group.YWJjZGVmZ2hpams=',
    'Signal-Empfänger: internationale Rufnummer oder Gruppen-ID, sonst abgelehnt');
ok(mask_phone('+491701234567') === '+491*******67' && !str_contains(mask_phone('+491701234567'), '1234'), 'Rufnummern nur maskiert');
ok(circle_channels_set('it', "+49 170 1234567\n0170 kaputt", [], '', 'system:test') !== null, 'Ungültige Signal-Nummer: nichts gespeichert');
ok(circle_channels_set('it', "+49 170 1234567\n+49 171 7654321", [], '42', 'system:test') === null
    && circle_channels_set('boa-krisenstab', '+49 170 1234567', [], 'x1', 'system:test') !== null, 'Signal und GroupAlarm-Szenario je Kreis, Szenario nur numerisch');
$ct = channel_targets(['circles' => ['it', 'allgemein']]);
ok($ct['signal'] === ['+491701234567', '+491717654321'] && array_keys($ct['groupalarm']) === [42], 'Kanalziele aus den gewählten Kreisen');
ok(!str_contains((string)kv_get('set:circles'), '1701234567'), 'Signal-Nummern verschlüsselt gespeichert');
array_map('unlink', glob(storage_dir() . '/outbox/*.json') ?: []);
$rt = send_alarm_channels('test', 0, 'Test', 'Text', 'system:test', ['circles' => ['it']]);
ok($rt === ['signal' => [2, 0]] && count(glob(storage_dir() . '/outbox/*-groupalarm-*.json') ?: []) === 0, 'Testnachricht nur über Signal, kein GroupAlarm');
array_map('unlink', glob(storage_dir() . '/outbox/*.json') ?: []);
$rc = send_alarm_channels('new', (int)$resM['id'], '[NOTFALL] Statusmeldung', 'Bitte Hinweise beachten.', 'anna', ['circles' => ['it']]);
$ga = json_decode((string)file_get_contents((glob(storage_dir() . '/outbox/*-groupalarm-*.json') ?: [''])[0]), true) ?: [];
$sg = (string)file_get_contents((glob(storage_dir() . '/outbox/*-signal-*.json') ?: [''])[0]);
ok($rc === ['signal' => [2, 0], 'groupalarm' => [1, 0]] && ($ga['body']['scenarioID'] ?? 0) === 42 && ($ga['body']['organizationID'] ?? 0) === 4711
    && ($ga['headers'] ?? []) === ['Personal-Access-Token: ***'], 'Alarm über Signal und GroupAlarm (Szenario, Organisation), Token nicht im Ausgang');
ok(str_contains($sg, '"message": "[NOTFALL] Statusmeldung') && !str_contains($sg, 'sig-geheim'), 'Signal-Nachricht = Betreff + Text, Token geschwärzt');
ok(in_array('channel.alarm', db()->query('SELECT action FROM ' . t('audit'))->fetchAll(PDO::FETCH_COLUMN), true), 'Kanal-Alarm protokolliert (nur Anzahlen)');
ok(http_post_json('http://extern.example/x', [], []) === [0, '', 'nur https:// erlaubt'], 'Kanäle nur über https');

/* --- Selbstüberwachung --- */
kv_set('cron_last', (string)(time() - 3 * 60));
ok(!cron_stale() && cron_age_minutes() === 3, 'Cron vor 3 Minuten: in Ordnung');
kv_set('cron_last', (string)(time() - 20 * 60));
ok(cron_stale(), 'Cron seit 20 Minuten nicht gelaufen: überfällig');
monitor_tick();
monitor_tick();
ok((int)db()->query('SELECT COUNT(*) FROM ' . t('mail_log') . " WHERE kind = 'monitor'")->fetchColumn() === 1, 'Warnmail bei Cron-Ausfall, höchstens einmal je Stunde');
kv_set('cron_last', (string)time());

/* --- Protokoll-Export --- */
$all = iterator_to_array(audit_range(null, null), false);
ok(count($all) === audit_verify()['count'] && count(iterator_to_array(audit_range('2000-01-01 00:00:00', '2000-12-31 23:59:59'), false)) === 0,
    'Export-Zeitraum: alle bzw. keine Einträge');
$pdf = pdf_table('Änderungsprotokoll', ['Kopf-Hash x'], [['Nr.', 40], ['Beschreibung', 700]],
    array_map(fn($i) => [(string)$i, str_repeat('Längerer Text mit Umlauten äöü ß → ', 5)], range(1, 150)));
ok(str_starts_with($pdf, '%PDF-1.4') && str_ends_with($pdf, "%%EOF\n") && str_contains($pdf, "\xC4nderungsprotokoll") && preg_match('#/Count (\d+)#', $pdf, $pm) && (int)$pm[1] > 1,
    'PDF: mehrseitig, Umlaute in Windows-1252');
preg_match('/startxref\n(\d+)/', $pdf, $xm);
preg_match_all('/^(\d{10}) 00000 n $/m', $pdf, $offs);
ok(substr($pdf, (int)$xm[1], 4) === 'xref' && array_reduce(array_keys($offs[1]), fn($c, $i) => $c && str_starts_with(substr($pdf, (int)$offs[1][$i]), ($i + 1) . ' 0 obj'), true),
    'PDF: Querverweistabelle stimmt');

/* --- Nutzung: Lesezähler und Login-Statistik --- */
$sid = (int)$resM['id'];
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

/* --- Einstellungen aus dem Browser (System-Seite) --- */
ok(cc_default_mail1() === 'cc1@test.example' && stage1_hash() === '', 'Ohne Browser-Einstellungen gelten die Werte der Konfigurationsdatei');
ok(stage1_change('kurz', 'kurz', 'system:test') !== [] && stage1_change('Zugang fuer alle', 'anders', 'system:test') !== [], 'Zugangspasswort: Länge und Wiederholung geprüft');
ok(stage1_change('Zugang fuer alle', 'Zugang fuer alle', 'system:test') === [] && verify_stage1('Zugang fuer alle') && stage1_set_at() !== '', 'Zugangspasswort gesetzt, Datum gespeichert');
ok(stage1_change('Zugang fuer alle', 'Zugang fuer alle', 'system:test') !== [], 'Gleiches Zugangspasswort wird abgelehnt');
ok(stage1_user() === 'zugang' && stage1_user_change('Anna', 'system:test') !== null && stage1_user_change('mit leer', 'system:test') !== null,
    'Gemeinsamer Zugang: Standardname, Kollision mit persönlicher Kennung und ungültige Namen abgelehnt');
ok(stage1_user_change('Unternehmen', 'system:test') === null && login_name_key(stage1_user()) === 'unternehmen'
    && throws(fn() => account_action('create', 'unternehmen', ['name' => 'X', 'email' => 'x@test.example'], 'anna')),
    'Gemeinsamer Zugang umbenannt; gleichnamige persönliche Kennung wird abgelehnt');
ok(cc1_change('kaputt', 'system:test') !== null && cc1_change('Neu@Test.example', 'system:test') === null && cc_default_mail1() === 'neu@test.example', 'Kopie-Adresse ersetzt den Konfigurationswert');
// Zusätzliche Empfänger je Stufe, An-Feld, Standard-Rufnummer
ok(level_cc_update('gibtsnicht', 'a@test.example', [], 'system:test') !== null && level_cc_update('critical', 'kaputt', [], 'system:test') !== null,
    'Stufen-Empfänger: unbekannte Stufe und ungültige Adresse abgelehnt');
ok(level_cc_update('critical', "Leitung@Test.example\nisb@test.example", [], 'system:test') === null && level_cc()['critical'] === ['leitung@test.example', 'isb@test.example']
    && level_cc()['warn'] === [] && level_cc_update('critical', 'isb@test.example', [], 'system:test') !== null, 'Stufen-Empfänger je Stufe gespeichert, Dubletten abgelehnt');
ok(!str_contains((string)kv_get('set:level_cc'), 'test.example'), 'Stufen-Empfänger verschlüsselt gespeichert');
[$lt] = alarm_targets(['circles' => []], ['severity' => 'critical']);
[$lw] = alarm_targets(['circles' => []], ['severity' => 'warn']);
ok($lt === ['leitung@test.example', 'isb@test.example'] && $lw === [], 'Stufen-Empfänger nur bei ihrer Stufe im Verteiler');
ok(level_cc_update('critical', '', [1], 'system:test') === null && level_cc()['critical'] === ['leitung@test.example'], 'Stufen-Empfänger entfernt');
$la = db()->query('SELECT seq, details_enc FROM ' . t('audit') . " WHERE action = 'setting.level_cc' ORDER BY seq DESC LIMIT 1")->fetch(PDO::FETCH_NUM);
$laPlain = $la ? dec((string)$la[1], 'audit:' . $la[0]) : '';
ok(str_contains($laPlain, 'Wichtiger Hinweis') && str_contains($laPlain, '-i**@') && !str_contains($laPlain, 'isb@'), 'Protokoll der Stufen-Empfänger mit Stufe, nur maskiert');
ok(alarm_to_address() === 'status@test.example', 'An-Feld: ohne Eintrag die Absenderadresse');
ok(alarm_to_change('kaputt', 'system:test') !== null && alarm_to_change('Verteiler@Test.example', 'system:test') === null && alarm_to_address() === 'verteiler@test.example'
    && alarm_to_change('', 'system:test') === null && alarm_to_address() === 'status@test.example', 'An-Feld: hinterlegte Adresse, leer = zurück auf Absender');
ok(default_phone_change('abc', 'system:test') !== null && default_phone_change('+49 800 1234', 'system:test') === null && bcm()['default_phone'] === '+49 800 1234',
    'Standard-Rufnummer unter System geändert');
ok(build_payload(bcm()['by_key']['ok'] ?? array_values(bcm()['by_key'])[0], ['nue-mitte'])['locations'][0]['phone'] === '+49 800 1234', 'Standort ohne Rufnummer zeigt die Standard-Rufnummer');
ok(default_phone_change('', 'system:test') === null && bcm()['default_phone'] === $j['default_phone'], 'Standard-Rufnummer leer = Wert aus config.json');
$allIds = array_column(bcm()['locations'], 'id');
ok(status_for_all(['audience' => 'ALLE', 'locations' => [['id' => 'muc-sued']]]) && status_for_all(['locations' => []])
    && status_for_all(['locations' => array_map(fn($i) => ['id' => $i], $allIds)]) && !status_for_all(['locations' => [['id' => 'muc-sued']]]), '"Für alle" bei allen Standorten');
ob_start();
render_status_card(['payload' => ['audience' => 'ALLE'] + build_payload(bcm()['by_key']['MAIL_EINGESCHRAENKT'], [])]);
$card = (string)ob_get_clean();
ok(strpos($card, 'Für alle:') !== false && strpos($card, 'Für alle:') < strpos($card, 'status-label'), '"Für alle:" steht über dem Status-Titel');
$raw = kv_get('set:cc1');
ok(!str_contains((string)$raw, 'test.example') && !setting_broken('circles'), 'Einstellungen verschlüsselt gespeichert');
kv_set('set:circles', (string)kv_get('set:cc1'));
setting_get('circles', true);
ok(setting_broken('circles') && alarm_circles()[0]['id'] === 'allgemein', 'Vertauschte Einstellung wird erkannt und nicht verwendet');
$chk = system_check();
ok(count(array_filter($chk, fn($c) => str_contains($c[1], 'Einstellung circles nicht lesbar') && !$c[0])) === 1, 'Systemprüfung meldet die Manipulation');
$labels = array_column(audit_recent(80), 'action');
ok(!array_diff(['setting.stage1', 'setting.cc1', 'setting.circle_update', 'setting.circle_delete', 'setting.location_update', 'setting.contact_create',
    'setting.mail_prefix', 'mail.alarm', 'status.end'], $labels), 'Einstellungsänderungen im Audit-Log');
ok(audit_verify()['ok'], 'Audit-Kette nach allen Änderungen intakt');

/* --- config.local.inc.php (Installer) --- */
$code = local_config_code(['db' => ['pass' => "a'b\\c"], 'security' => ['master_key' => 'k']]);
$f = $tmp . '/roundtrip.php';
file_put_contents($f, $code);
ok((require $f)['db']['pass'] === "a'b\\c" && str_contains($code, "if (!defined('SBCM'))"), 'Konfigurationsdatei: Sonderzeichen sicher, Direktaufruf gesperrt');

/* --- QR-Code --- */
$m = qr_matrix(totp_uri('anna', 'JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP'));
ok(count($m) >= 21 && count($m) === count($m[0]) && $m[0][0] && $m[0][6] && !$m[1][1] && $m[3][3], 'QR-Matrix mit Finder-Muster');
ok(count(qr_matrix(str_repeat('x', 213))) === 57 && throws(fn() => qr_matrix(str_repeat('x', 214))), 'QR bis Version 10, längere Daten abgelehnt');
ok(str_starts_with(qr_svg_data_uri('test'), 'data:image/svg+xml;base64,'), 'QR als SVG-Daten-URI');

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
