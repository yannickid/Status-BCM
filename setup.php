<?php
/**
 * Status-BCM – Einrichtung per Kommandozeile (nur CLI). OPTIONAL: Ohne SSH-Zugang erledigen install.php
 * (Ersteinrichtung) sowie die Seiten "System" und "Benutzer" dasselbe im Browser.
 *
 *   php setup.php init                          Master-Key + Cron-Token erzeugen (config.local.inc.php)
 *   php setup.php set-stage1                    Zugangspasswort Stufe 1 setzen
 *   php setup.php add-user <id> "<Name>" <mail> [admin|editor] [--config]
 *                                               Benutzer Stufe 2 anlegen (Passwort + TOTP-Secret), Standard: admin.
 *                                               --config: in config.local.inc.php statt in die DB (Webspace ohne SSH:
 *                                               lokal ausführen, Datei per FTP hochladen)
 *   php setup.php list-users                    Benutzer mit Rolle, Passwortalter und Gültigkeit
 *   php setup.php reset-password <id>           Einmalpasswort erzeugen (Notfall, z. B. letzter Admin ausgesperrt)
 *   php setup.php disable-user <id> | enable-user <id>
 *   php setup.php migrate-users                 Benutzer aus config.local.inc.php in die Datenbank übernehmen
 *   php setup.php add-recipient <mail> [kreis]  Adresse in Alarmkreis (verschlüsselt); neuer Kreis wird angelegt
 *   php setup.php list-circles | remove-recipient <kreis> <nr>
 *   php setup.php set-cc1 <mail>                cc_default_mail1 (Erinnerungen, Audit-Anker) verschlüsselt setzen
 *   php setup.php encrypt-value <text>          beliebigen Konfigurationswert als enc:... verschlüsseln
 *   php setup.php install-db                    Tabellen anlegen
 *   php setup.php check                         Konfiguration + Meldungstexte prüfen
 *   php setup.php verify-audit                  Hash-Kette des Protokolls prüfen
 *   php setup.php stats [Tage]                  Anmeldungen je Tag/Benutzer und Lesezähler (Standard 30 Tage)
 *   php setup.php totp-check <id> <code>        TOTP-Einrichtung testen (verbraucht den Code)
 */
declare(strict_types=1);

if (PHP_SAPI !== 'cli') {
    http_response_code(404);
    exit;
}
define('SBCM', true);
require __DIR__ . '/lib.inc.php';

function out(string $s = ''): void
{
    fwrite(STDOUT, $s . "\n");
}

function fail(string $s): void
{
    fwrite(STDERR, "FEHLER: $s\n");
    exit(1);
}

function local_path(): string
{
    return local_config_path();
}

function local_load(): array
{
    return local_config_load();
}

function local_save(array $a): void
{
    if (!local_config_write($a)) {
        fail('config.local.inc.php nicht schreibbar');
    }
}

function prompt_secret(string $q): string
{
    fwrite(STDERR, $q);
    $tty = DIRECTORY_SEPARATOR === '/' && function_exists('posix_isatty') && posix_isatty(STDIN);
    if ($tty) {
        shell_exec('stty -echo');
    }
    $l = fgets(STDIN);
    if ($tty) {
        shell_exec('stty echo');
        fwrite(STDERR, "\n");
    }
    return rtrim((string)$l, "\r\n");
}

function new_password(int $min): string
{
    $a = prompt_secret('Passwort: ');
    if (mb_strlen($a) < $min) {
        fail("Passwort zu kurz (mindestens $min Zeichen).");
    }
    $b = prompt_secret('Passwort wiederholen: ');
    if (!hash_equals($a, $b)) {
        fail('Eingaben stimmen nicht überein.');
    }
    return $a;
}

$cmd = $argv[1] ?? 'help';
$args = array_values(array_filter(array_slice($argv, 2), fn($a) => !str_starts_with($a, '--')));
$flags = array_values(array_filter(array_slice($argv, 2), fn($a) => str_starts_with($a, '--')));

switch ($cmd) {
    case 'init':
        $l = local_load();
        if (!empty($l['security']['master_key']) && !in_array('--force', $flags, true)) {
            fail('master_key existiert bereits. Ein Wechsel macht verschlüsselte Daten unlesbar (--force nur für Neuinstallationen).');
        }
        $l['security']['master_key'] = base64_encode(random_bytes(32));
        if (empty($l['cron']['token'])) {
            $l['cron']['token'] = bin2hex(random_bytes(24));
        }
        local_save($l);
        out('config.local.inc.php erzeugt: ' . local_path());
        out('Cron-Token (für cron.php?t=...): ' . $l['cron']['token']);
        out('SICHERN Sie config.local.inc.php separat (Master-Key!). Ohne den Key sind Status/Protokoll nicht lesbar.');
        out('Nächste Schritte: set-stage1, add-user, add-recipient, set-cc1, check (Tabellen entstehen automatisch)');
        break;

    case 'set-stage1':
        $pw = new_password(10);
        if ($e = stage1_change($pw, $pw, 'system:cli')) {
            fail(implode(' ', $e));
        }
        out('Zugangspasswort Stufe 1 gesetzt (verschlüsselt in der Datenbank, wie über System im Browser).');
        break;

    case 'add-user':
        [$id, $name, $mail] = [strtolower((string)($args[0] ?? '')), (string)($args[1] ?? ''), (string)($args[2] ?? '')];
        $role = (string)($args[3] ?? 'admin');
        if (!preg_match('/^[a-z0-9_-]{2,32}$/', $id) || $name === '' || !filter_var($mail, FILTER_VALIDATE_EMAIL) || !in_array($role, ['admin', 'editor'], true)) {
            fail('Aufruf: php setup.php add-user <id [a-z0-9_-]> "<Name>" <email> [admin|editor]');
        }
        $pw = new_password(max(12, (int)cfg('auth.password_min_length', 12)));
        if ($pe = password_policy($pw, $id)) {
            fail(implode(' ', $pe));
        }
        $secret = b32_encode(random_bytes(20));
        if (in_array('--config', $flags, true)) {
            $l = local_load();
            $l['auth']['users'][$id] = ['name' => $name, 'email' => cfg_encrypt(strtolower($mail)), 'hash' => password_hash($pw, PASSWORD_DEFAULT),
                'totp_secret' => cfg_encrypt($secret), 'pw_set_at' => now_utc()];
            local_save($l);
        } else {
            try {
                account_action('create', $id, ['name' => $name, 'email' => $mail, 'role' => $role, 'password' => $pw, 'totp_b32' => $secret], 'system:cli');
            } catch (InvalidArgumentException $e) {
                fail($e->getMessage());
            }
        }
        $uri = 'otpauth://totp/' . rawurlencode('Status-BCM:' . $id) . '?secret=' . $secret . '&issuer=Status-BCM&algorithm=SHA1&digits=6&period=30';
        out("Benutzer $id ($role) angelegt.");
        out("TOTP-Secret (in Authenticator-App manuell eintragen): $secret");
        out("otpauth-URI: $uri");
        out('QR-Code lokal erzeugen (Secret nie an Online-Dienste geben):  qrencode -t ANSIUTF8 \'' . $uri . '\'');
        out("Danach testen mit: php setup.php totp-check $id <Code>");
        out('Weitere Benutzer am besten über admin.php anlegen (Einmalpasswort, eigene App-Kopplung).');
        break;

    case 'list-users':
        foreach (users(true) as $id => $u) {
            out(sprintf('%-16s %-22s %-6s %-6s %s  TOTP:%s  PW gesetzt: %s  gültig bis: %s  [%s%s%s]', $id, mb_substr($u['name'], 0, 22), $u['role'],
                $u['source'], mask_email($u['email'] ?: 'x@x.x'), $u['totp_secret'] !== '' ? 'ja' : 'NEIN', fmt_local($u['pw_set_at'] ?? null),
                empty($u['pw_valid_until']) ? 'unbefristet' : fmt_local($u['pw_valid_until']), $u['active'] ? pw_state($u) : 'deaktiviert',
                $u['must_change'] ? ', Einmalpasswort' : '', $u['mac_ok'] ? '' : ', INTEGRITÄTSFEHLER'));
        }
        break;

    case 'reset-password':
    case 'disable-user':
    case 'enable-user':
        $id = strtolower((string)($args[0] ?? ''));
        $map = ['reset-password' => 'reset_pw', 'disable-user' => 'disable', 'enable-user' => 'enable'];
        try {
            $once = account_action($map[$cmd], $id, [], 'system:cli');
        } catch (Throwable $e) {
            fail($e->getMessage());
        }
        out($once !== null ? "Einmalpasswort für $id: $once  (beim Login muss ein eigenes Passwort gesetzt werden)" : 'Erledigt.');
        break;

    case 'remove-user':
        fail('Benutzer werden nicht gelöscht (Nachvollziehbarkeit). Stattdessen: php setup.php disable-user <id>');
        break;

    case 'migrate-users':
        $l = local_load();
        $n = 0;
        foreach ((array)($l['auth']['users'] ?? []) as $id => $u) {
            $id = strtolower((string)$id);
            if (account_get_row($id)) {
                out("$id existiert bereits in der Datenbank – übersprungen.");
                continue;
            }
            $now = time();
            tx(function () use ($id, $u, $now) {
                account_write($id, ['name' => (string)($u['name'] ?? $id), 'email' => strtolower(cfg_secret((string)($u['email'] ?? ''))),
                    'hash' => (string)($u['hash'] ?? ''), 'totp_b32' => cfg_secret((string)($u['totp_secret'] ?? '')), 'role' => 'admin',
                    'must_change' => false, 'active' => true, 'pw_set_at' => (string)($u['pw_set_at'] ?? gmdate('Y-m-d H:i:s', $now)),
                    'pw_valid_until' => pw_valid_until_from($now)], true, 'system:cli');
                audit('user.create', 'user:' . $id, ['user' => $id, 'role' => 'admin', 'migrated' => true], 'system:cli', 0);
            });
            unset($l['auth']['users'][$id]);
            $n++;
            out("$id übernommen (Rolle admin).");
        }
        local_save($l);
        out("$n Benutzer migriert und aus config.local.inc.php entfernt.");
        break;

    case 'add-recipient':
        $cid = (string)($args[1] ?? (alarm_circles()[0]['id'] ?? 'allgemein'));
        $known = array_column(alarm_circles(), 'id');
        $e = in_array($cid, $known, true) ? circle_update($cid, (string)($args[0] ?? ''), [], 'system:cli')
            : circle_create($cid, (string)($args[0] ?? ''), 'system:cli');
        if ($e) {
            fail($e);
        }
        out('Empfänger gespeichert (verschlüsselt) im Kreis ' . $cid . ': ' . mask_email(strtolower((string)$args[0])));
        break;

    case 'list-recipients':
    case 'list-circles':
        foreach (alarm_circles() as $c) {
            out($c['id'] . '  (' . $c['name'] . ')');
            foreach ($c['emails'] as $i => $r) {
                out(sprintf('  %2d  %s', $i + 1, mask_email($r)));
            }
        }
        break;

    case 'remove-recipient':
        if (count($args) < 2) {
            fail('Aufruf: remove-recipient <kreis-id> <nr>  (Nummern aus list-circles)');
        }
        if ($e = circle_update((string)$args[0], '', [(int)$args[1] - 1], 'system:cli')) {
            fail($e);
        }
        out('Empfänger entfernt.');
        break;

    case 'set-cc1':
        if ($e = cc1_change((string)($args[0] ?? ''), 'system:cli')) {
            fail($e);
        }
        out('cc_default_mail1 gespeichert (verschlüsselt): ' . mask_email(strtolower((string)$args[0])));
        break;

    case 'encrypt-value':
        if (!isset($args[0])) {
            fail('Aufruf: php setup.php encrypt-value <text>');
        }
        out(cfg_encrypt($args[0]));
        break;

    case 'install-db':
        install_schema(db());
        out('Tabellen sind vorhanden.');
        break;

    case 'check':
        $problems = 0;
        foreach (system_check() as [$ok, $msg]) {
            out(($ok ? '[ok]   ' : '[OFFEN] ') . $msg);
            $problems += $ok ? 0 : 1;
        }
        out($problems === 0 ? 'Alles in Ordnung.' : "$problems Punkt(e) offen.");
        exit($problems === 0 ? 0 : 2);

    case 'verify-audit':
        $v = audit_verify();
        out(($v['ok'] ? 'OK' : 'FEHLER: ' . $v['error']) . " – {$v['count']} Einträge, Kopf-Hash {$v['head']}");
        exit($v['ok'] ? 0 : 2);

    case 'stats':
        $days = max(1, min(366, (int)($args[0] ?? 30)));
        $st = login_stats($days);
        out('Anmeldungen         ' . implode('  ', array_map(fn($k) => str_pad($k, 8, ' ', STR_PAD_LEFT), array_keys($st['periods']))));
        out('Stufe 1 (gemeinsam) ' . implode('  ', array_map(fn($p) => str_pad((string)$p['s1'], 8, ' ', STR_PAD_LEFT), $st['periods'])));
        foreach (users() as $id => $u) {
            out(str_pad("Stufe 2: $id", 20) . implode('  ', array_map(fn($p) => str_pad((string)($p['s2'][$id] ?? 0), 8, ' ', STR_PAD_LEFT), $st['periods']))
                . '   zuletzt: ' . fmt_local($st['last'][$id] ?? null));
        }
        out('Fehlgeschlagen S2   ' . implode('  ', array_map(fn($p) => str_pad((string)$p['fail'], 8, ' ', STR_PAD_LEFT), $st['periods'])));
        out('');
        out('Tag          Stufe 1  Stufe 2  Fehlgeschl.');
        foreach ($st['days'] as $d => $c) {
            out(sprintf('%s %8d %8d %12d', $d, $c['s1'], $c['s2'], $c['fail']));
        }
        out('');
        out('Lesezähler (Sitzungen je Status, anonym):');
        $hist = status_history(15);
        $views = view_totals(array_column($hist, 'id'));
        foreach ($hist as $r) {
            out(sprintf('%s  %-40s %6d', fmt_local($r['created_at']), mb_substr((string)($r['payload']['label'] ?? $r['status_key']), 0, 40), $views[(int)$r['id']] ?? 0));
        }
        break;

    case 'totp-check':
        $u = users()[strtolower((string)($args[0] ?? ''))] ?? null;
        if (!$u) {
            fail('Benutzer unbekannt.');
        }
        $u['id'] = strtolower((string)$args[0]);
        out(totp_verify_user($u, (string)($args[1] ?? '')) ? 'Code gültig.' : 'Code ungültig (Uhrzeit des Servers prüfen).');
        break;

    default:
        $doc = file_get_contents(__FILE__);
        if (preg_match('/\/\*\*(.*?)\*\//s', (string)$doc, $m)) {
            out(trim(preg_replace('/^\s*\* ?/m', '', $m[1]) ?? ''));
        }
}
