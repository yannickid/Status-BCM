<?php
/**
 * Einstellungen – nach Login Stufe 2 (personenbezogen).
 * Ablauf: Formular -> Vorschau -> verbindlich setzen (TOTP bei Alarm-/kritischen Änderungen).
 */
declare(strict_types=1);
define('SBCM', true);
require __DIR__ . '/lib.inc.php';
bootstrap();

if (!stage1_ok()) {
    redirect('index.php');
}

$bcm = bcm();
$user = stage2_user();
$errors = [];
$old = [];
$method = $_SERVER['REQUEST_METHOD'] ?? 'GET';
$current = $user ? status_current() : null;

if ($method === 'POST') {
    csrf_verify();
    $act = (string)($_POST['action'] ?? '');

    if ($act === 'login2') {
        $uid = strtolower(trim((string)($_POST['user'] ?? '')));
        $wait = throttle_locked('s2', $uid);
        if ($wait > 0) {
            $errors[] = 'Zu viele Fehlversuche. Bitte in ca. ' . (int)ceil($wait / 60) . ' Minute(n) erneut versuchen.';
        } else {
            $u = verify_user($uid, (string)($_POST['password'] ?? ''));
            throttle_record('s2', $uid, $u !== null);
            if ($u) {
                session_regenerate_id(true);
                $_SESSION['s2'] = ['u' => $u['id'], 't' => time()];
                audit('login2.ok', 'session', [], $u['id'], 2);
                redirect('change.php');
            }
            fail_delay();
            audit('login2.fail', 'session', ['user' => mb_substr(preg_replace('/[^\w.@-]/u', '?', $uid) ?? '', 0, 32)], 'anonymous', 1);
            $errors[] = 'Anmeldung fehlgeschlagen.';
        }
    } elseif ($act === 'logout2') {
        unset($_SESSION['s2'], $_SESSION['pending']);
        redirect('change.php');
    } elseif (!$user) {
        $errors[] = 'Bitte erneut anmelden.';
    } elseif ($act === 'cancel') {
        unset($_SESSION['pending']);
        redirect('change.php');
    } elseif ($act === 'preview') {
        [$spec, $errs] = parse_change_request($_POST, $current);
        if ($errs) {
            $errors = $errs;
            $old = $_POST;
        } else {
            $_SESSION['pending'] = ['id' => bin2hex(random_bytes(16)), 'spec' => $spec, 'user' => $user['id'], 't' => time()];
            redirect('change.php');
        }
    } elseif ($act === 'commit') {
        $p = $_SESSION['pending'] ?? null;
        $ttl = (int)cfg('auth.pending_ttl_seconds', 300);
        if (!is_array($p) || !hash_equals((string)$p['id'], (string)($_POST['pending_id'] ?? ''))
            || $p['user'] !== $user['id'] || time() - (int)$p['t'] > $ttl) {
            unset($_SESSION['pending']);
            $errors[] = 'Die Vorschau ist abgelaufen. Bitte die Änderung erneut vorbereiten.';
        } else {
            $spec = $p['spec'];
            $needs = spec_needs_totp($spec);
            $ok = true;
            if ($needs) {
                $wait = throttle_locked('s2t', $user['id']);
                if ($wait > 0) {
                    $ok = false;
                    $errors[] = 'Zu viele ungültige Codes. Bitte in ca. ' . (int)ceil($wait / 60) . ' Minute(n) erneut versuchen.';
                } else {
                    $good = totp_verify_user($user, (string)($_POST['totp'] ?? ''));
                    throttle_record('s2t', $user['id'], $good);
                    if (!$good) {
                        $ok = false;
                        fail_delay();
                        audit('totp.fail', 'status:' . $spec['key'], ['mode' => $spec['mode']]);
                        $errors[] = 'Der Bestätigungscode ist ungültig oder bereits verwendet.';
                    }
                }
            }
            if ($ok) {
                unset($_SESSION['pending']);
                $res = status_create($spec, $user['id'], ['totp' => $needs, 'preview_confirmed' => true]);
                flash('ok', 'Status gesetzt: ' . $res['payload']['label'] . '.');
                if (!empty($spec['alarm_mail'])) {
                    try {
                        $m = send_alarm_mail((int)$res['id'], $res['payload'], $res['valid_until'], $user['id']);
                        if ($m['failed'] > 0) {
                            flash('warn', 'ALARM-Mail: ' . $m['ok'] . ' von ' . $m['total'] . ' Adressen zugestellt – Details im Protokoll.');
                        } else {
                            flash('ok', 'ALARM-Mail an ' . $m['ok'] . ' Adressen versendet.');
                        }
                    } catch (Throwable $e) {
                        error_log('Status-BCM: Alarm-Mail: ' . $e->getMessage());
                        flash('err', 'Der Status wurde gesetzt, die ALARM-Mail konnte NICHT versendet werden.');
                    }
                }
                redirect('change.php');
            }
        }
    }
    $current = $user ? status_current() : null;
}

/* ------------------------------------------------------------------ Ausgabe */

page_start('Einstellungen');
nav('change');
echo '<h1>Einstellungen</h1>';
render_flash();
foreach ($errors as $e) {
    echo '<div class="msg err" role="alert">' . h($e) . '</div>';
}

if (!$user) {
    echo '<div class="card"><h2>Anmeldung Stufe 2</h2><p class="muted">Für Änderungen ist eine persönliche Anmeldung erforderlich.</p>';
    echo '<form method="post" action="change.php" autocomplete="off">' . csrf_field() . '<input type="hidden" name="action" value="login2">';
    echo '<label for="u">Benutzer</label><input id="u" type="text" name="user" autocomplete="username" required>';
    echo '<label for="p">Passwort</label><input id="p" type="password" name="password" autocomplete="current-password" required>';
    echo '<button class="primary" type="submit">Anmelden</button></form></div>';
    page_end();
    exit;
}

echo '<div class="muted">Angemeldet als ' . h($user['name']) . ' (' . h($user['id']) . ')';
echo '<form method="post" action="change.php">' . csrf_field()
    . '<input type="hidden" name="action" value="logout2"><button type="submit">Stufe 2 beenden</button></form></div>';

/* Systemhinweise */
$notes = [];
if (!totp_secret_of($user)) {
    $notes[] = 'Für Ihren Benutzer ist kein TOTP-Secret hinterlegt – ALARM-Änderungen sind nicht möglich.';
}
if (str_contains((string)cfg('app.base_url'), 'example.invalid')) {
    $notes[] = 'app.base_url ist noch ein Platzhalter (Links in E-Mails falsch).';
}
if ((string)cfg('mail.transport') === 'log') {
    $notes[] = 'Mail-Transport steht auf "log" – es werden keine E-Mails versendet.';
}
if (!alarm_recipients()) {
    $notes[] = 'Keine ALARM-Empfänger konfiguriert.';
}
foreach (bcm_lint($bcm) as $w) {
    $notes[] = 'Textprüfung: ' . $w;
}
if ($notes) {
    echo '<div class="msg warn"><strong>Systemhinweise</strong><ul>';
    foreach ($notes as $n) {
        echo '<li>' . h($n) . '</li>';
    }
    echo '</ul></div>';
}

/* Vorschau (zweiter Schritt) */
$pending = $_SESSION['pending'] ?? null;
$ttl = (int)cfg('auth.pending_ttl_seconds', 300);
if (is_array($pending) && ($pending['user'] ?? '') === $user['id'] && time() - (int)$pending['t'] <= $ttl) {
    $spec = $pending['spec'];
    $def = $bcm['by_key'][$spec['key']];
    $payload = build_payload($def, $spec['loc_ids'], $spec['note']);
    $needs = spec_needs_totp($spec);
    echo '<h2>Vorschau – bitte prüfen</h2>';
    echo '<p class="muted">So sehen alle Personen mit Zugang die Meldung:</p>';
    render_status_card(['payload' => $payload, 'created_at' => now_utc(), 'valid_until' => $spec['valid_until'],
        'mac_ok' => true, 'author' => $user['id'], 'alarm_mail' => $spec['alarm_mail'] ? 1 : 0], true);
    if ($spec['alarm_mail']) {
        $n = count(alarm_recipients());
        echo '<div class="msg warn"><strong>ALARM-Mail wird versendet</strong> an ' . (int)$n . ' hinterlegte Empfänger (BCC) sowie an Sie und die Standard-CC-Adresse.</div>';
    } elseif ($def['alarm_mail_default']) {
        echo '<div class="msg warn">Für diesen Status ist üblicherweise eine ALARM-Mail vorgesehen – es wird <strong>keine</strong> gesendet. Mit "Abbrechen" können Sie das ändern.</div>';
    }
    echo '<form method="post" action="change.php" autocomplete="off">' . csrf_field()
        . '<input type="hidden" name="pending_id" value="' . h($pending['id']) . '">';
    if ($needs) {
        echo '<label for="totp">Bestätigungscode (TOTP-App, 6 Stellen)</label>'
            . '<input id="totp" type="text" name="totp" inputmode="numeric" pattern="[0-9 ]{6,7}" maxlength="7" autocomplete="one-time-code" required autofocus>';
    }
    echo '<button class="primary" type="submit" name="action" value="commit">Verbindlich setzen</button>'
        . '<button type="submit" name="action" value="cancel">Abbrechen</button></form>';
    page_end();
    exit;
}

/* Aktueller Status + Schnellaktionen */
echo '<h2>Aktueller Status</h2>';
render_status_card($current, true);
if ($current && $current['payload'] && $current['status_key'] !== $bcm['default_status']) {
    echo '<div class="card"><h2>Ist der Status noch gültig?</h2>';
    echo '<form method="post" action="change.php">' . csrf_field() . '<input type="hidden" name="validity_type" value="duration">';
    echo '<label for="dur_e">Weiterhin gültig – verlängern um</label><select id="dur_e" name="duration">';
    foreach ($bcm['validity_options_minutes'] as $min) {
        echo '<option value="' . (int)$min . '">' . h(fmt_minutes($min)) . '</option>';
    }
    echo '</select>';
    echo '<input type="hidden" name="mode" value="extend">';
    echo '<button class="primary" type="submit" name="action" value="preview">Verlängern</button>';
    echo '</form>';
    echo '<form method="post" action="change.php">' . csrf_field() . '<input type="hidden" name="mode" value="end">';
    echo '<button class="danger" type="submit" name="action" value="preview">Status beenden (zurück auf ' . h($bcm['by_key'][$bcm['default_status']]['label']) . ')</button>';
    echo '</form></div>';
}

/* Neuer Status */
$o = fn(string $k, $d = '') => $old[$k] ?? $d;
echo '<div class="card"><h2>Neuen Status setzen</h2>';
echo '<form method="post" action="change.php">' . csrf_field() . '<input type="hidden" name="mode" value="set">';
echo '<label for="sk">Status</label><select id="sk" name="status_key" required><option value="">– bitte wählen –</option>';
foreach ($bcm['statuses'] as $s) {
    $tag = $s['audience'] === 'ALLE_UND_ADRESSLISTE' ? ' · mit Standortliste' : '';
    echo '<option value="' . h($s['key']) . '"' . ($o('status_key') === $s['key'] ? ' selected' : '') . '>'
        . h($s['label'] . ' (' . severity_label($s['severity']) . ')' . $tag) . '</option>';
}
echo '</select>';

echo '<label>Betroffene Standorte <span class="muted">(nur bei Status "mit Standortliste")</span></label>';
echo '<label class="inl"><input type="checkbox" name="loc_all" value="1"' . ($o('loc_all') ? ' checked' : '') . '>Alle Standorte der Liste</label>';
$sel = (array)($old['loc'] ?? []);
foreach ($bcm['locations'] as $l) {
    echo '<label class="inl"><input type="checkbox" name="loc[]" value="' . h($l['id']) . '"' . (in_array($l['id'], $sel, true) ? ' checked' : '') . '>'
        . h($l['name']) . ' <span class="muted">(' . h(trim((string)$l['phone']) !== '' ? $l['phone'] : 'Standard: ' . $bcm['default_phone']) . ')</span></label>';
}

$vt = $o('validity_type', 'duration');
echo '<label>Gültigkeit</label>';
echo '<label class="inl"><input type="radio" name="validity_type" value="duration"' . ($vt === 'duration' ? ' checked' : '') . '>Dauer: '
    . '<select name="duration" class="auto">';
foreach ($bcm['validity_options_minutes'] as $min) {
    echo '<option value="' . (int)$min . '"' . ((int)$o('duration', 240) === $min ? ' selected' : '') . '>' . h(fmt_minutes($min)) . '</option>';
}
echo '</select></label>';
echo '<label class="inl"><input type="radio" name="validity_type" value="until"' . ($vt === 'until' ? ' checked' : '') . '>Gültig bis: '
    . '<input type="datetime-local" name="until" value="' . h((string)$o('until')) . '" class="auto"> <span class="muted">(' . h((string)cfg('app.timezone')) . ')</span></label>';
echo '<label class="inl"><input type="radio" name="validity_type" value="unlimited"' . ($vt === 'unlimited' ? ' checked' : '') . '>Unbefristet <span class="muted">(nur wo zulässig)</span></label>';

echo '<label class="inl gap"><input type="checkbox" name="alarm_mail" value="1"' . ($o('alarm_mail') ? ' checked' : '') . '><strong>ALARM-Mail senden</strong> <span class="muted">(erfordert TOTP-Bestätigung)</span></label>';
echo '<label for="note">Interne Notiz / Anlass <span class="muted">(nur im Protokoll, nicht auf der Statusseite, max. 200 Zeichen)</span></label>';
echo '<input id="note" type="text" name="note" maxlength="200" value="' . h((string)$o('note')) . '">';
echo '<button class="primary" type="submit" name="action" value="preview">Vorschau</button></form></div>';

/* Meldungstexte */
echo '<div class="card"><h2>Hinterlegte Meldungstexte</h2><table><thead><tr><th>Status</th><th>Text (wie angezeigt)</th></tr></thead><tbody>';
foreach ($bcm['statuses'] as $s) {
    echo '<tr><td>' . h($s['label']) . '<br><span class="muted">' . h($s['key']) . ' · ' . h($s['audience'] === 'ALLE' ? 'Alle' : 'Alle + Standorte')
        . ($s['alarm_mail_allowed'] ? ' · Alarm möglich' : '') . ($s['require_totp'] ? ' · TOTP' : '') . '</span></td><td>' . h($s['text']) . '</td></tr>';
}
echo '</tbody></table></div>';

/* Verlauf */
echo '<div class="card"><h2>Statusverlauf</h2><table><thead><tr><th>Zeit</th><th>Status</th><th>Von</th><th>Gültig bis</th><th>Alarm</th></tr></thead><tbody>';
foreach (status_history(15) as $r) {
    $lbl = $r['payload']['label'] ?? $r['status_key'];
    $locs = $r['payload'] ? implode(', ', array_column($r['payload']['locations'] ?? [], 'name')) : '';
    echo '<tr><td>' . h(fmt_local($r['created_at'])) . '</td><td>' . h($lbl) . ($locs !== '' ? '<br><span class="muted">' . h($locs) . '</span>' : '')
        . ($r['mac_ok'] ? '' : ' <strong>(Integritätsfehler)</strong>') . '</td><td>' . h($r['author']) . '</td><td>'
        . h(fmt_local($r['valid_until'])) . '</td><td>' . ($r['alarm_mail'] ? 'ja' : 'nein') . '</td></tr>';
}
echo '</tbody></table></div>';

/* Audit-Protokoll */
$v = audit_verify();
echo '<div class="card"><h2>Änderungsprotokoll</h2>';
echo '<div class="msg ' . ($v['ok'] ? 'ok' : 'err') . '">Integrität der Protokollkette: ' . ($v['ok'] ? 'OK' : 'FEHLER – ' . h((string)$v['error']))
    . ' · ' . (int)$v['count'] . ' Einträge</div>';
echo '<table><thead><tr><th>#</th><th>Zeit</th><th>Wer</th><th>Was / Wie</th></tr></thead><tbody>';
foreach (audit_recent(30) as $r) {
    echo '<tr><td>' . (int)$r['seq'] . '</td><td>' . h(fmt_local($r['ts'])) . '</td><td>' . h($r['actor']) . '</td><td>'
        . h(audit_describe((string)$r['action'], (array)$r['details'])) . '</td></tr>';
}
echo '</tbody></table></div>';
page_end();
