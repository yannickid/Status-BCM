<?php
/**
 * System – nur Login Stufe 2 mit Rolle "admin". Ersetzt die Kommandozeile für den laufenden Betrieb:
 * Systemprüfung, Cron, ALARM-Empfänger, Kopie-Adresse (cc_default_mail1), Zugangspasswort Stufe 1, Testmail, Nutzung.
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
    } elseif (!in_array($act, ['recipient_add', 'recipient_remove', 'cc1', 'stage1'], true)) {
        $errors[] = 'Ungültige Aktion.';
    } elseif ($err = admin_totp_check($user, 'system', $act)) {
        $errors[] = $err;
    } elseif ($act === 'recipient_add') {
        [$n, $err] = recipients_add((string)($_POST['emails'] ?? ''), $user['id'], $how);
        if ($err) {
            $errors[] = $err;
        } else {
            flash('ok', $n > 0 ? "$n Empfänger hinzugefügt." : 'Die Adresse(n) waren bereits eingetragen.');
        }
    } elseif ($act === 'recipient_remove') {
        if (recipients_remove((int)($_POST['nr'] ?? -1), $user['id'], $how)) {
            flash('ok', 'Empfänger entfernt.');
        } else {
            $errors[] = 'Empfänger nicht gefunden.';
        }
    } elseif ($act === 'cc1') {
        if ($err = cc1_change((string)($_POST['email'] ?? ''), $user['id'], $how)) {
            $errors[] = $err;
        } else {
            flash('ok', 'Kopie-Adresse gespeichert.');
        }
    } elseif ($act === 'stage1') {
        $e = stage1_change((string)($_POST['pw'] ?? ''), (string)($_POST['pw2'] ?? ''), $user['id'], $how);
        if ($e) {
            $errors = array_merge($errors, $e);
        } else {
            flash('ok', 'Zugangspasswort geändert. Bitte allen Beschäftigten auf dem üblichen internen Weg bekannt geben.');
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
echo '</div></div>';

/* ALARM-Empfänger */
$web = recipients_web();
$fromCfg = array_values(array_diff(alarm_recipients(), $web));
echo '<div class="card shadow-sm mb-3"><div class="card-body"><h2 class="h5">ALARM-Empfänger (' . count(alarm_recipients()) . ')</h2>';
echo '<p class="small text-body-secondary">Erhalten die ALARM-Mail ausschließlich per BCC. Gespeichert verschlüsselt, angezeigt nur maskiert.</p>';
echo '<ul class="list-group mb-2">';
foreach ($web as $i => $r) {
    echo '<li class="list-group-item"><details><summary class="small">' . h(mask_email($r)) . '</summary>'
        . '<form method="post" action="system.php" class="mt-2" autocomplete="off">' . csrf_field()
        . '<input type="hidden" name="action" value="recipient_remove"><input type="hidden" name="nr" value="' . $i . '">'
        . totp_input('rr' . $i) . '<button class="btn btn-sm btn-outline-danger" type="submit">Entfernen</button></form></details></li>';
}
foreach ($fromCfg as $r) {
    echo '<li class="list-group-item small">' . h(mask_email($r)) . ' <span class="text-body-secondary">(aus config.local.inc.php)</span></li>';
}
if (!$web && !$fromCfg) {
    echo '<li class="list-group-item small text-body-secondary">Noch keine Empfänger.</li>';
}
echo '</ul>';
echo '<form method="post" action="system.php" autocomplete="off">' . csrf_field() . '<input type="hidden" name="action" value="recipient_add">'
    . '<label class="form-label small" for="em">Neue Adresse(n), eine je Zeile</label>'
    . '<textarea class="form-control mb-2" id="em" name="emails" rows="3" required></textarea>'
    . totp_input('ra') . '<button class="btn btn-sm btn-primary" type="submit">Hinzufügen</button></form>';
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

/* Zugangspasswort Stufe 1 */
$s1 = stage1_set_at();
$s1max = (int)cfg('auth.stage1_max_age_days', 0);
echo '<div class="card shadow-sm mb-3"><div class="card-body"><h2 class="h5">Zugangspasswort für alle (Stufe 1)</h2>';
echo '<p class="small text-body-secondary">Zuletzt gesetzt: ' . h($s1 !== '' ? fmt_local($s1) : 'unbekannt')
    . ($s1max > 0 && $s1 !== '' ? ' · Wechsel empfohlen bis ' . h(fmt_local(gmdate('Y-m-d H:i:s', utc_ts($s1) + $s1max * 86400))) : '')
    . '. Nach dem Wechsel gilt das neue Passwort sofort für neue Anmeldungen.</p>';
echo '<form method="post" action="system.php" autocomplete="off">' . csrf_field() . '<input type="hidden" name="action" value="stage1">'
    . '<label class="form-label small" for="p1">Neues Zugangspasswort (mind. 10 Zeichen)</label><input class="form-control mb-2" id="p1" type="password" name="pw" autocomplete="new-password" required>'
    . '<label class="form-label small" for="p2">Wiederholen</label><input class="form-control mb-2" id="p2" type="password" name="pw2" autocomplete="new-password" required>'
    . totp_input('s1') . '<button class="btn btn-sm btn-primary" type="submit">Ändern</button></form>';
echo '</div></div>';

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
