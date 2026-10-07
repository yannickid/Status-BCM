<?php
/**
 * System – nur Login Stufe 2 mit Rolle "admin". Ersetzt die Kommandozeile für den laufenden Betrieb:
 * Systemprüfung, Cron, Alarmkreise, Standorte, Kontakte, Betreff-Präfixe, Kopie-Adresse (cc_default_mail1), Zugangspasswort Stufe 1, Testmail, Nutzung.
 * Jede Änderung verlangt den TOTP-Code des Admins und wird im Audit-Log protokolliert.
 */
declare(strict_types=1);
define('SBCM', true);
require __DIR__ . '/lib.inc.php';
bootstrap();

if (!stage1_ok()) {
    redirect('index.php');
}
$user = stage2_user();
if (!$user || user_needs_setup($user)) {
    redirect('change.php');
}
if ($user['role'] !== 'admin') {
    http_response_code(403);
    page_start('System');
    nav('system');
    echo '<div class="alert alert-warning">Die Systemverwaltung ist Admins vorbehalten.</div>';
    page_end();
    exit;
}

monitor_tick();
$errors = [];
if (($_SERVER['REQUEST_METHOD'] ?? 'GET') === 'POST') {
    csrf_verify();
    $act = (string)($_POST['action'] ?? '');
    $how = ['totp' => true];
    if ($act === 'cron_run') {
        $lock = @fopen(storage_dir() . '/cron.lock', 'c');
        if (!$lock || !flock($lock, LOCK_EX | LOCK_NB)) {
            flash('warn', 'Cron läuft gerade. Bitte kurz warten.');
        } else {
            try {
                audit('system.cron_manual', 'cron', []);
                $log = run_cron();
                flash('ok', 'Cron ausgeführt' . ($log ? ': ' . implode(' · ', $log) : ' – nichts zu tun.'));
            } finally {
                flock($lock, LOCK_UN);
                fclose($lock);
            }
        }
        redirect('system.php');
    } elseif ($act === 'mail_test') {
        $subject = 'Testnachricht ' . (string)cfg('app.title', 'Status');
        $body = "Diese Testnachricht bestätigt, dass der Mailversand funktioniert.\n\n" . rtrim((string)cfg('app.base_url'), '/') . "\n";
        $sum = mail_record('test', null, $subject, $body, mail_deliver(['to' => [$user['email']], 'subject' => $subject, 'body' => $body]));
        audit('mail.test', 'mail', ['recipients' => $sum['total'], 'ok' => $sum['ok'], 'failed' => $sum['failed']]);
        flash($sum['ok'] > 0 ? 'ok' : 'err', $sum['ok'] > 0 ? 'Testmail an ' . mask_email($user['email']) . ' übergeben. Bitte Posteingang prüfen.'
            : 'Testmail fehlgeschlagen. SMTP-Daten in config.local.inc.php prüfen (Fehlerdetails im Server-Fehlerlog).');
        redirect('system.php');
    } elseif (!in_array($act, ['circle_create', 'circle_update', 'circle_delete', 'circle_channels', 'signal_test', 'location_save', 'location_delete',
        'contact_save', 'contact_delete', 'prefix', 'cc1', 'alarm_to', 'level_cc', 'default_phone', 'stage1', 'stage1_user'], true)) {
        $errors[] = 'Ungültige Aktion.';
    } elseif ($err = admin_totp_check($user, 'system', $act)) {
        $errors[] = $err;
    } else {
        $id = (string)($_POST['id'] ?? '');
        $rm = array_map('intval', (array)($_POST['rm'] ?? []));
        $ok = [
            'circle_create' => 'Alarmkreis angelegt.', 'circle_update' => 'Alarmkreis geändert.', 'circle_delete' => 'Alarmkreis gelöscht.',
            'location_save' => 'Standort gespeichert.', 'location_delete' => 'Standort gelöscht.',
            'contact_save' => 'Kontakt gespeichert.', 'contact_delete' => 'Kontakt gelöscht.',
            'prefix' => 'Betreff-Präfixe gespeichert.', 'cc1' => 'Kopie-Adresse gespeichert.',
            'alarm_to' => 'Adresse im An-Feld gespeichert.', 'level_cc' => 'Zusätzliche Empfänger der Stufe gespeichert.',
            'default_phone' => 'Standard-Rufnummer gespeichert.',
            'stage1_user' => 'Benutzername des gemeinsamen Zugangs geändert. Bitte allen Beschäftigten bekannt geben.',
            'circle_channels' => 'Signal/GroupAlarm des Kreises gespeichert.', 'signal_test' => 'Signal-Testnachricht übergeben. Bitte Empfang prüfen.',
            'stage1' => 'Zugangspasswort geändert. Bitte allen Beschäftigten auf dem üblichen internen Weg bekannt geben.',
        ][$act];
        $del = ($_POST['confirm'] ?? '') === 'ja';
        switch ($act) {
            case 'circle_create':
                $err = circle_create((string)($_POST['name'] ?? ''), (string)($_POST['emails'] ?? ''), $user['id'], $how);
                break;
            case 'circle_update':
                $err = circle_update($id, (string)($_POST['emails'] ?? ''), $rm, $user['id'], $how);
                break;
            case 'circle_channels':
                $err = circle_channels_set($id, (string)($_POST['signal'] ?? ''), array_map('intval', (array)($_POST['rm_sig'] ?? [])),
                    (string)($_POST['groupalarm'] ?? ''), $user['id'], $how);
                break;
            case 'signal_test':
                $c = array_column(alarm_circles(), null, 'id')[$id] ?? null;
                if (!$c || !$c['signal']) {
                    $err = 'Für diesen Kreis sind keine Signal-Empfänger hinterlegt.';
                } elseif (!channel_enabled('signal')) {
                    $err = 'Signal ist in config.local.inc.php nicht eingerichtet (channels.signal).';
                } else {
                    $r = send_alarm_channels('test', 0, 'Testnachricht ' . (string)cfg('app.title', 'Status'),
                        "Diese Testnachricht bestätigt, dass die Alarmierung über Signal für den Kreis \"" . $c['name'] . "\" funktioniert.",
                        $user['id'], ['circles' => [$id]]);
                    $err = ($r['signal'][1] ?? 1) > 0 ? 'Signal-Testnachricht fehlgeschlagen (Details im Server-Fehlerlog).' : null;
                }
                break;
            case 'circle_delete':
                $err = $del ? circle_delete($id, $user['id'], $how) : 'Bitte das Löschen bestätigen.';
                break;
            case 'location_save':
                $err = location_save($id, (string)($_POST['name'] ?? ''), (string)($_POST['phone'] ?? ''), (string)($_POST['emails'] ?? ''), $rm, $user['id'], $how);
                break;
            case 'location_delete':
                $err = $del ? location_delete($id, $user['id'], $how) : 'Bitte das Löschen bestätigen.';
                break;
            case 'contact_save':
                $err = contact_save($id, $_POST, $user['id'], $how);
                break;
            case 'contact_delete':
                $err = $del ? contact_delete($id, $user['id'], $how) : 'Bitte das Löschen bestätigen.';
                break;
            case 'prefix':
                $err = mail_prefixes_set($_POST, $user['id'], $how);
                break;
            case 'stage1_user':
                $err = stage1_user_change((string)($_POST['name'] ?? ''), $user['id'], $how);
                break;
            case 'alarm_to':
                $err = alarm_to_change((string)($_POST['email'] ?? ''), $user['id'], $how);
                break;
            case 'level_cc':
                $err = level_cc_update((string)($_POST['level'] ?? ''), (string)($_POST['emails'] ?? ''),
                    array_map('intval', (array)($_POST['rm'] ?? [])), $user['id'], $how);
                break;
            case 'default_phone':
                $err = default_phone_change((string)($_POST['phone'] ?? ''), $user['id'], $how);
                break;
            case 'cc1':
                $err = cc1_change((string)($_POST['email'] ?? ''), $user['id'], $how);
                break;
            default:
                $e = stage1_change((string)($_POST['pw'] ?? ''), (string)($_POST['pw2'] ?? ''), $user['id'], $how);
                $err = $e ? implode(' ', $e) : null;
        }
        if ($err) {
            $errors[] = $err;
        } else {
            flash('ok', $ok);
        }
    }
    if (!$errors) {
        redirect('system.php');
    }
}

page_start('System');
nav('system');
echo '<h1 class="h4 mb-3">System</h1>';
render_flash();
foreach ($errors as $e) {
    echo '<div class="alert alert-danger" role="alert">' . h($e) . '</div>';
}

/* Systemprüfung */
$checks = system_check();
$open = count(array_filter($checks, fn($c) => !$c[0]));
echo '<div class="card shadow-sm mb-3"><div class="card-body"><h2 class="h5">Prüfung '
    . ($open ? '<span class="badge text-bg-warning">' . $open . ' offen</span>' : '<span class="badge text-bg-success">alles in Ordnung</span>') . '</h2>';
echo '<ul class="list-unstyled small mb-0">';
foreach ($checks as [$ok, $msg]) {
    echo '<li class="py-1 border-bottom"><span class="badge ' . ($ok ? 'text-bg-success">ok' : 'text-bg-warning">offen') . '</span> ' . h($msg) . '</li>';
}
echo '</ul></div></div>';

/* Cron */
$token = (string)cfg('cron.token', '');
$cronUrl = rtrim((string)cfg('app.base_url'), '/') . '/cron.php?t=' . $token;
echo '<div class="card shadow-sm mb-3"><div class="card-body"><h2 class="h5">Cron (Erinnerungen, Audit-Anker)</h2>';
echo '<p class="small">Diese Adresse muss <strong>alle 5 Minuten</strong> aufgerufen werden: im Kundenmenü des Hosters unter "Cronjobs" '
    . '(Typ "URL aufrufen") oder bei einem externen Cron-Dienst. Die Adresse enthält ein Geheimnis: nur dort eintragen, nicht weitergeben.</p>';
echo $token !== '' ? '<div class="font-monospace small break-all border rounded p-2 mb-2 bg-body">' . h($cronUrl) . '</div>'
    : '<div class="alert alert-warning small">Kein Cron-Token gesetzt (cron.token in config.local.inc.php).</div>';
echo '<form method="post" action="system.php" class="d-grid d-sm-block">' . csrf_field() . '<input type="hidden" name="action" value="cron_run">'
    . '<button class="btn btn-outline-secondary btn-sm" type="submit">Jetzt einmal ausführen</button></form>';
$age = cron_age_minutes();
echo '<p class="small mt-2 mb-1">Letzter Lauf: ' . ($age === null ? 'noch nie' : 'vor ' . $age . ' Minuten')
    . (cron_stale() ? ' <span class="badge text-bg-warning">überfällig</span>' : '') . '. Läuft der Cron länger als '
    . max(5, (int)cfg('monitor.cron_stale_minutes', 15)) . ' Minuten nicht, geht eine Warnmail an die Kopie-Adresse (höchstens stündlich) und angemeldete Nutzer sehen einen Hinweis.</p>';
$healthUrl = rtrim((string)cfg('app.base_url'), '/') . '/health.php' . ((string)cfg('monitor.health_token', '') !== '' ? '?t=' . (string)cfg('monitor.health_token') : '');
echo '<p class="small mb-1">Externe Überwachung (z. B. UptimeRobot, Uptime Kuma): diese Adresse alle 5 Minuten abfragen. '
    . 'Antwort 200 "ok" = Seite, Datenbank und Cron in Ordnung, sonst 503 mit Grund. Alarm des Dienstes bitte an eine Adresse außerhalb der eigenen Mail-Infrastruktur (z. B. SMS/App).</p>'
    . '<div class="font-monospace small break-all border rounded p-2 bg-body">' . h($healthUrl) . '</div>';
echo '</div></div>';

/** Liste maskierter Adressen mit Auswahl zum Entfernen (Positionen als rm[]). */
function email_remove_list(array $emails, string $sfx): string
{
    if (!$emails) {
        return '<p class="small text-body-secondary mb-2">Keine Adressen hinterlegt.</p>';
    }
    $o = '<fieldset class="mb-2"><legend class="small mb-1">Adressen (maskiert), Haken = entfernen</legend>';
    foreach ($emails as $i => $e) {
        $o .= '<div class="form-check"><input class="form-check-input" type="checkbox" name="rm[]" value="' . (int)$i . '" id="rm' . h($sfx) . '_' . (int)$i . '">'
            . '<label class="form-check-label small font-monospace" for="rm' . h($sfx) . '_' . (int)$i . '">' . h(mask_email($e)) . '</label></div>';
    }
    return $o . '</fieldset>';
}

function delete_form(string $action, string $id, string $sfx, string $what): string
{
    return '<details class="mt-2"><summary class="small text-danger">' . h($what) . ' löschen</summary>'
        . '<form method="post" action="system.php" class="mt-2" autocomplete="off">' . csrf_field()
        . '<input type="hidden" name="action" value="' . h($action) . '"><input type="hidden" name="id" value="' . h($id) . '">'
        . '<div class="form-check mb-2"><input class="form-check-input" type="checkbox" name="confirm" value="ja" id="cf' . h($sfx) . '" required>'
        . '<label class="form-check-label small" for="cf' . h($sfx) . '">Ja, endgültig löschen</label></div>'
        . totp_input('d' . $sfx) . '<button class="btn btn-sm btn-outline-danger" type="submit">Löschen</button></form></details>';
}

/* Alarmkreise */
$circles = alarm_circles();
$stored = is_array(setting_get('circles'));
echo '<div class="card shadow-sm mb-3"><div class="card-body"><h2 class="h5">Alarmkreise (' . count($circles) . ')</h2>';
echo '<p class="small text-body-secondary">Beim Setzen einer Meldung wählen Sie, welche Kreise die ALARM-Mail erhalten, z. B. IT, BOA/Krisenstab, Leitung. '
    . 'Versand ausschließlich per BCC. Adressen werden verschlüsselt gespeichert und nur maskiert angezeigt.</p>'
    . '<p class="small">Weitere Kanäle: Signal ' . (channel_enabled('signal') ? '<span class="badge text-bg-success">eingerichtet</span>' : '<span class="badge text-bg-secondary">nicht eingerichtet</span>')
    . ' · GroupAlarm ' . (channel_enabled('groupalarm') ? '<span class="badge text-bg-success">eingerichtet</span>' : '<span class="badge text-bg-secondary">nicht eingerichtet</span>')
    . ' <span class="text-body-secondary">(Zugangsdaten in config.local.inc.php, siehe Doku)</span></p>';
if (!$stored && $circles[0]['emails']) {
    echo '<div class="alert alert-info small">Die bisherigen ALARM-Empfänger stehen im Kreis "Allgemein". Mit der ersten Änderung werden sie in die Kreisverwaltung übernommen.</div>';
}
foreach ($circles as $n => $c) {
    $sfx = 'c' . $n;
    echo '<details class="border rounded p-2 mb-2"><summary><strong>' . h($c['name']) . '</strong> <span class="badge text-bg-secondary">'
        . count($c['emails']) . '</span></summary>';
    echo '<form method="post" action="system.php" class="mt-2" autocomplete="off">' . csrf_field()
        . '<input type="hidden" name="action" value="circle_update"><input type="hidden" name="id" value="' . h($c['id']) . '">'
        . email_remove_list($c['emails'], $sfx)
        . '<label class="form-label small" for="ce' . $sfx . '">Adressen hinzufügen (eine je Zeile)</label>'
        . '<textarea class="form-control mb-2" id="ce' . $sfx . '" name="emails" rows="2"></textarea>'
        . totp_input('u' . $sfx) . '<button class="btn btn-sm btn-primary" type="submit">Speichern</button></form>';
    $sigList = '';
    foreach ($c['signal'] as $i => $r) {
        $sigList .= '<div class="form-check"><input class="form-check-input" type="checkbox" name="rm_sig[]" value="' . (int)$i . '" id="rs' . $sfx . '_' . (int)$i . '">'
            . '<label class="form-check-label small font-monospace" for="rs' . $sfx . '_' . (int)$i . '">' . h(mask_phone($r)) . '</label></div>';
    }
    echo '<details class="mt-2"><summary class="small">Signal und GroupAlarm (' . count($c['signal']) . ' Signal'
        . ($c['groupalarm'] !== '' ? ', GroupAlarm-Szenario ' . h($c['groupalarm']) : '') . ')</summary>'
        . '<form method="post" action="system.php" class="mt-2" autocomplete="off">' . csrf_field()
        . '<input type="hidden" name="action" value="circle_channels"><input type="hidden" name="id" value="' . h($c['id']) . '">'
        . ($sigList !== '' ? '<fieldset class="mb-2"><legend class="small mb-1">Signal-Empfänger (maskiert), Haken = entfernen</legend>' . $sigList . '</fieldset>' : '')
        . '<label class="form-label small" for="cs' . $sfx . '">Signal-Empfänger hinzufügen: Rufnummer +49… oder Gruppen-ID group.… (eine je Zeile)</label>'
        . '<textarea class="form-control mb-2" id="cs' . $sfx . '" name="signal" rows="2"></textarea>'
        . '<label class="form-label small" for="cg' . $sfx . '">GroupAlarm-Szenario-ID (leer = kein GroupAlarm)</label>'
        . '<input class="form-control mb-2" id="cg' . $sfx . '" name="groupalarm" inputmode="numeric" maxlength="12" value="' . h($c['groupalarm']) . '">'
        . totp_input('ch' . $sfx) . '<button class="btn btn-sm btn-primary" type="submit">Speichern</button></form>';
    if ($c['signal']) {
        echo '<form method="post" action="system.php" class="mt-2" autocomplete="off">' . csrf_field()
            . '<input type="hidden" name="action" value="signal_test"><input type="hidden" name="id" value="' . h($c['id']) . '">'
            . totp_input('st' . $sfx) . '<button class="btn btn-sm btn-outline-secondary" type="submit">Signal-Testnachricht an diesen Kreis</button></form>';
    }
    echo '</details>';
    echo delete_form('circle_delete', $c['id'], $sfx, 'Kreis');
    echo '</details>';
}
echo '<details class="mt-2"><summary class="small">Neuen Alarmkreis anlegen</summary>'
    . '<form method="post" action="system.php" class="mt-2" autocomplete="off">' . csrf_field() . '<input type="hidden" name="action" value="circle_create">'
    . '<label class="form-label small" for="cn">Name, z. B. "BOA/Krisenstab"</label><input class="form-control mb-2" id="cn" name="name" maxlength="40" required>'
    . '<label class="form-label small" for="cnm">Adressen (eine je Zeile)</label><textarea class="form-control mb-2" id="cnm" name="emails" rows="3"></textarea>'
    . totp_input('cn') . '<button class="btn btn-sm btn-primary" type="submit">Anlegen</button></form></details>';
echo '</div></div>';

/* Standorte */
$locs = locations_all();
echo '<div class="card shadow-sm mb-3"><div class="card-body"><h2 class="h5">Standorte (' . count($locs) . ')</h2>';
echo '<p class="small text-body-secondary">Name und Durchwahl erscheinen auf der Statusseite. Die E-Mail-Adressen der Standortverwaltung sind nicht einsehbar '
    . '(verschlüsselt, maskiert) und erhalten die ALARM-Mail per BCC, wenn der Standort betroffen ist.'
    . (is_array(setting_get('locations')) ? '' : ' Aktuell aus config.json; mit der ersten Änderung übernimmt die Systemverwaltung die Liste.') . '</p>';
$locForm = function (array $l, string $sfx): string {
    return '<form method="post" action="system.php" class="mt-2" autocomplete="off">' . csrf_field()
        . '<input type="hidden" name="action" value="location_save"><input type="hidden" name="id" value="' . h($l['id']) . '">'
        . '<label class="form-label small" for="ln' . $sfx . '">Name</label><input class="form-control mb-2" id="ln' . $sfx . '" name="name" maxlength="80" value="' . h($l['name']) . '" required>'
        . '<label class="form-label small" for="lp' . $sfx . '">Durchwahl (optional; leer = Standard-Rufnummer)</label><input class="form-control mb-2" id="lp' . $sfx . '" name="phone" type="tel" maxlength="40" value="' . h($l['phone']) . '">'
        . ($l['id'] !== '' ? email_remove_list($l['emails'], $sfx) : '')
        . '<label class="form-label small" for="le' . $sfx . '">E-Mail Standortverwaltung hinzufügen (eine je Zeile)</label>'
        . '<textarea class="form-control mb-2" id="le' . $sfx . '" name="emails" rows="2"></textarea>'
        . totp_input('l' . $sfx) . '<button class="btn btn-sm btn-primary" type="submit">' . ($l['id'] !== '' ? 'Speichern' : 'Anlegen') . '</button></form>';
};
foreach ($locs as $n => $l) {
    echo '<details class="border rounded p-2 mb-2"><summary><strong>' . h($l['name']) . '</strong>'
        . ($l['emails'] ? ' <span class="badge text-bg-secondary">' . count($l['emails']) . ' Adr.</span>' : ' <span class="badge text-bg-warning">keine Adresse</span>')
        . '</summary>' . $locForm($l, 'l' . $n) . delete_form('location_delete', $l['id'], 'l' . $n, 'Standort') . '</details>';
}
echo '<details class="mt-2"><summary class="small">Neuen Standort anlegen</summary>'
    . $locForm(['id' => '', 'name' => '', 'phone' => '', 'emails' => []], 'new') . '</details>';
echo '</div></div>';

/* Kontakte */
$contacts = contacts_all();
echo '<div class="card shadow-sm mb-3"><div class="card-body"><h2 class="h5">Kontakte für Meldungen (' . count($contacts) . ')</h2>';
echo '<p class="small text-body-secondary">Notfallnummer, Funktionspostfach oder Videokonferenz. Beim Setzen einer Meldung auswählbar; '
    . 'erscheinen dann für alle Beschäftigten sichtbar auf der Statusseite und in der ALARM-Mail.</p>';
$conForm = function (array $c, string $sfx): string {
    $f = fn($k, $label, $type, $max) => '<label class="form-label small" for="k' . $k . $sfx . '">' . $label . '</label>'
        . '<input class="form-control mb-2" id="k' . $k . $sfx . '" name="' . $k . '" type="' . $type . '" maxlength="' . $max . '" value="' . h((string)($c[$k] ?? '')) . '"'
        . ($k === 'name' ? ' required' : '') . '>';
    return '<form method="post" action="system.php" class="mt-2" autocomplete="off">' . csrf_field()
        . '<input type="hidden" name="action" value="contact_save"><input type="hidden" name="id" value="' . h((string)($c['id'] ?? '')) . '">'
        . $f('name', 'Bezeichnung, z. B. "Krisenstab-Konferenz"', 'text', 60)
        . $f('phone', 'Rufnummer (optional)', 'tel', 40)
        . $f('email', 'E-Mail (optional)', 'email', 120)
        . $f('platform', 'Plattform, z. B. "Teams", "Webex" (optional)', 'text', 40)
        . $f('url', 'Link, nur https:// (optional)', 'url', 300)
        . $f('meeting', 'Konferenz-ID / PIN (optional)', 'text', 80)
        . totp_input('k' . $sfx) . '<button class="btn btn-sm btn-primary" type="submit">' . (($c['id'] ?? '') !== '' ? 'Speichern' : 'Anlegen') . '</button></form>';
};
foreach ($contacts as $n => $c) {
    echo '<details class="border rounded p-2 mb-2"><summary><strong>' . h($c['name']) . '</strong></summary>'
        . $conForm($c, 'k' . $n) . delete_form('contact_delete', $c['id'], 'k' . $n, 'Kontakt') . '</details>';
}
echo '<details class="mt-2"><summary class="small">Neuen Kontakt anlegen</summary>' . $conForm([], 'new') . '</details>';
echo '</div></div>';

/* Betreff-Präfixe */
$pre = mail_prefixes();
echo '<div class="card shadow-sm mb-3"><div class="card-body"><h2 class="h5">Betreff-Präfixe der ALARM-Mail</h2>';
echo '<p class="small text-body-secondary">Steht vor dem Betreff, z. B. "[ALARM] Netzwerkstörung". Leer lassen = kein Präfix.</p>';
echo '<form method="post" action="system.php" autocomplete="off">' . csrf_field() . '<input type="hidden" name="action" value="prefix">';
foreach (['new' => 'Neuer Alarm', 'update' => 'Aktualisierung (Ändern, Verlängern)', 'end' => 'Ende (zurückgenommen / gelöst)'] as $k => $label) {
    echo '<label class="form-label small" for="px' . $k . '">' . h($label) . '</label>'
        . '<input class="form-control mb-2" id="px' . $k . '" name="' . $k . '" maxlength="30" value="' . h($pre[$k]) . '">';
}
echo totp_input('px') . '<button class="btn btn-sm btn-primary" type="submit">Speichern</button></form>';
echo '</div></div>';

/* Kopie-Adresse */
$cc1 = cc_default_mail1();
echo '<div class="card shadow-sm mb-3"><div class="card-body"><h2 class="h5">Kopie-Adresse (cc_default_mail1)</h2>';
echo '<p class="small text-body-secondary">Erhält Erinnerungen bei Ablauf, Kopien der ALARM-Mails und täglich den Audit-Anker. '
    . 'Aktuell: <strong>' . h($cc1 !== '' ? mask_email($cc1) : 'nicht gesetzt') . '</strong></p>';
echo '<form method="post" action="system.php" autocomplete="off">' . csrf_field() . '<input type="hidden" name="action" value="cc1">'
    . '<label class="form-label small" for="cc">Neue Adresse</label><input class="form-control mb-2" id="cc" type="email" name="email" required>'
    . totp_input('cc') . '<button class="btn btn-sm btn-primary" type="submit">Speichern</button></form>';
echo '</div></div>';

/* An-Feld der ALARM-Mail */
$to = alarm_to_address();
echo '<div class="card shadow-sm mb-3"><div class="card-body"><h2 class="h5">Adresse im An-Feld der ALARM-Mail</h2>';
echo '<p class="small text-body-secondary">ALARM-Mails gehen <strong>an</strong> diese Adresse; alle Empfänger aus Kreisen, Stufen und Standorten stehen nur im '
    . '<strong>BCC</strong> und sehen sich gegenseitig nicht. Leer = Absenderadresse. Aktuell: <strong>' . h($to !== '' ? mask_email($to) : 'keine') . '</strong>'
    . (is_string(setting_get('alarm_to')) && setting_get('alarm_to') !== '' ? '' : ' (Absenderadresse)') . '</p>';
echo '<form method="post" action="system.php" autocomplete="off">' . csrf_field() . '<input type="hidden" name="action" value="alarm_to">'
    . '<label class="form-label small" for="at">Neue Adresse (leer = Absenderadresse)</label><input class="form-control mb-2" id="at" type="email" name="email">'
    . totp_input('at') . '<button class="btn btn-sm btn-primary" type="submit">Speichern</button></form>';
echo '</div></div>';

/* Zusätzliche Empfänger je Stufe */
$lcc = level_cc();
echo '<div class="card shadow-sm mb-3" id="stufen"><div class="card-body"><h2 class="h5">Zusätzliche Empfänger je Stufe</h2>';
echo '<p class="small text-body-secondary">Diese Adressen erhalten jede ALARM-Mail einer Meldung dieser Stufe zusätzlich zu den gewählten Alarmkreisen '
    . '(per BCC, verschlüsselt gespeichert, nur maskiert sichtbar).</p>';
foreach (SBCM_LEVELS as $lv => $lvName) {
    echo '<details class="mt-2"><summary>' . h($lvName) . ' (' . count($lcc[$lv]) . ')</summary>'
        . '<form method="post" action="system.php" class="mt-2" autocomplete="off">' . csrf_field()
        . '<input type="hidden" name="action" value="level_cc"><input type="hidden" name="level" value="' . h($lv) . '">'
        . email_remove_list($lcc[$lv], 'lv' . $lv)
        . '<label class="form-label small" for="lv' . h($lv) . '">Adressen hinzufügen (eine je Zeile)</label>'
        . '<textarea class="form-control mb-2" id="lv' . h($lv) . '" name="emails" rows="2"></textarea>'
        . totp_input('lv' . $lv) . '<button class="btn btn-sm btn-primary" type="submit">Speichern</button></form></details>';
}
echo '</div></div>';

/* Standard-Rufnummer */
echo '<div class="card shadow-sm mb-3"><div class="card-body"><h2 class="h5">Standard-Rufnummer</h2>';
echo '<p class="small text-body-secondary">Erscheint bei Meldungen ohne Standortliste und bei jedem Standort ohne eigene Durchwahl. Gilt für neue und geänderte Meldungen; bereits gesetzte bleiben, wie sie veröffentlicht wurden. '
    . 'Aktuell: <strong>' . h(bcm()['default_phone']) . '</strong>' . (is_string(setting_get('default_phone')) && setting_get('default_phone') !== '' ? '' : ' (aus config.json)') . '</p>';
echo '<form method="post" action="system.php" autocomplete="off">' . csrf_field() . '<input type="hidden" name="action" value="default_phone">'
    . '<label class="form-label small" for="dp">Neue Rufnummer (leer = Wert aus config.json)</label><input class="form-control mb-2" id="dp" type="tel" name="phone" maxlength="40">'
    . totp_input('dp') . '<button class="btn btn-sm btn-primary" type="submit">Speichern</button></form>';
echo '</div></div>';

/* Zugangspasswort Stufe 1 */
$s1 = stage1_set_at();
$s1max = (int)cfg('auth.stage1_max_age_days', 0);
echo '<div class="card shadow-sm mb-3"><div class="card-body"><h2 class="h5">Gemeinsamer Zugang für alle (Stufe 1)</h2>';
echo '<p class="small text-body-secondary">Anmeldung auf der Startseite mit Benutzername <strong>' . h(stage1_user()) . '</strong> und dem Zugangspasswort: '
    . 'nur Lesen. Persönliche Kennungen melden sich im selben Formular an und gelangen direkt in die Einstellungen.</p>';
echo '<form method="post" action="system.php" class="mb-3" autocomplete="off">' . csrf_field() . '<input type="hidden" name="action" value="stage1_user">'
    . '<label class="form-label small" for="s1u">Benutzername (z. B. Unternehmen; Groß-/Kleinschreibung egal)</label>'
    . '<input class="form-control mb-2" id="s1u" name="name" maxlength="40" value="' . h(stage1_user()) . '" autocapitalize="none" required>'
    . totp_input('s1u') . '<button class="btn btn-sm btn-primary" type="submit">Benutzername ändern</button></form>';
echo '<p class="small text-body-secondary">Zuletzt gesetzt: ' . h($s1 !== '' ? fmt_local($s1) : 'unbekannt')
    . ($s1max > 0 && $s1 !== '' ? ' · Wechsel empfohlen bis ' . h(fmt_local(gmdate('Y-m-d H:i:s', utc_ts($s1) + $s1max * 86400))) : '')
    . '. Nach dem Wechsel gilt das neue Passwort sofort für neue Anmeldungen.</p>';
echo '<form method="post" action="system.php" autocomplete="off">' . csrf_field() . '<input type="hidden" name="action" value="stage1">'
    . '<label class="form-label small" for="p1">Neues Zugangspasswort (mind. 10 Zeichen)</label><input class="form-control mb-2" id="p1" type="password" name="pw" autocomplete="new-password" required>'
    . '<label class="form-label small" for="p2">Wiederholen</label><input class="form-control mb-2" id="p2" type="password" name="pw2" autocomplete="new-password" required>'
    . totp_input('s1') . '<button class="btn btn-sm btn-primary" type="submit">Ändern</button></form>';
echo '</div></div>';

/* Protokoll-Export und Aushang */
echo '<div class="card shadow-sm mb-3" id="export"><div class="card-body"><h2 class="h5">Protokoll-Export (Revision, ISB)</h2>'
    . '<p class="small">Export des Änderungsprotokolls mit Integritätsprüfung und Kopf-Hash. Der Export wird selbst protokolliert. '
    . 'Die Datei enthält personenbezogene Daten: nur verschlüsselt weitergeben und nach Zweck löschen.</p>'
    . '<form method="post" action="export.php" autocomplete="off">' . csrf_field()
    . '<div class="row g-2"><div class="col-6"><label class="form-label small" for="exf">von (leer = Beginn)</label><input class="form-control" type="date" id="exf" name="from"></div>'
    . '<div class="col-6"><label class="form-label small" for="ext">bis (leer = heute)</label><input class="form-control" type="date" id="ext" name="to"></div></div>'
    . '<div class="form-check mt-2"><input class="form-check-input" type="checkbox" name="with_ip" value="1" id="exip">'
    . '<label class="form-check-label small" for="exip">IP-Adressen mit exportieren (nur wenn für den Zweck nötig)</label></div>'
    . '<div class="d-flex flex-wrap gap-2 mt-2"><button class="btn btn-outline-primary btn-sm" type="submit" name="format" value="csv">CSV herunterladen</button>'
    . '<button class="btn btn-outline-primary btn-sm" type="submit" name="format" value="pdf">PDF herunterladen</button></div></form>'
    . '<p class="small mt-3 mb-0">Aushang mit QR-Code für Schwarzes Brett und Notfallordner: <a href="aushang.php">Aushang drucken</a></p></div></div>';

/* Testmail */
echo '<div class="card shadow-sm mb-3"><div class="card-body"><h2 class="h5">Mailversand testen</h2>';
echo '<form method="post" action="system.php" class="d-grid d-sm-block">' . csrf_field() . '<input type="hidden" name="action" value="mail_test">'
    . '<button class="btn btn-outline-secondary btn-sm" type="submit">Testmail an ' . h(mask_email($user['email'] ?: 'x@x.x')) . ' senden</button></form>';
echo '</div></div>';

/* Nutzung je Tag */
$st = login_stats(30);
echo '<details class="card shadow-sm mb-3"><summary class="card-header">Anmeldungen je Tag (30 Tage)</summary><div class="card-body table-wrap">';
echo '<table class="table table-sm small mb-0"><thead><tr><th>Tag</th><th>Stufe 1</th><th>Stufe 2</th><th>Fehlgeschl.</th></tr></thead><tbody>';
foreach ($st['days'] as $d => $c) {
    echo '<tr><td>' . h($d) . '</td><td>' . (int)$c['s1'] . '</td><td>' . (int)$c['s2'] . '</td><td>' . (int)$c['fail'] . '</td></tr>';
}
echo '</tbody></table></div></details>';

echo '<p class="small text-body-secondary">Version ' . h(SBCM_VERSION) . '</p>';
page_end();
