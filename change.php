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
echo '<h1 class="h4 mb-3">Einstellungen</h1>';
render_flash();
foreach ($errors as $e) {
    echo '<div class="alert alert-danger" role="alert">' . h($e) . '</div>';
}

if (!$user) {
    echo '<div class="card shadow-sm"><div class="card-body"><h2 class="h5">Anmeldung Stufe 2</h2>'
        . '<p class="text-body-secondary small">Für Änderungen ist eine persönliche Anmeldung erforderlich.</p>';
    echo '<form method="post" action="change.php" autocomplete="off">' . csrf_field() . '<input type="hidden" name="action" value="login2">';
    echo '<label class="form-label" for="u">Benutzer</label><input class="form-control mb-3" id="u" type="text" name="user" autocomplete="username" autocapitalize="none" required>';
    echo '<label class="form-label" for="p">Passwort</label><input class="form-control mb-3" id="p" type="password" name="password" autocomplete="current-password" required>';
    echo '<div class="d-grid"><button class="btn btn-primary btn-lg" type="submit">Anmelden</button></div></form></div></div>';
    page_end();
    exit;
}

echo '<div class="d-flex flex-wrap align-items-center gap-2 mb-3 small text-body-secondary">'
    . '<span class="me-auto">Angemeldet als ' . h($user['name']) . ' (' . h($user['id']) . ')</span>'
    . '<form method="post" action="change.php" class="m-0">' . csrf_field()
    . '<input type="hidden" name="action" value="logout2"><button class="btn btn-outline-secondary btn-sm" type="submit">Stufe 2 beenden</button></form></div>';

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
    echo '<div class="alert alert-warning"><strong>Systemhinweise</strong><ul class="mb-0">';
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
    echo '<h2 class="h5">Vorschau – bitte prüfen</h2>';
    echo '<p class="text-body-secondary small">So sehen alle Personen mit Zugang die Meldung:</p>';
    render_status_card(['payload' => $payload, 'created_at' => now_utc(), 'valid_until' => $spec['valid_until'],
        'mac_ok' => true, 'author' => $user['id'], 'alarm_mail' => $spec['alarm_mail'] ? 1 : 0], true);
    if ($spec['alarm_mail']) {
        $n = count(alarm_recipients());
        echo '<div class="alert alert-warning"><strong>ALARM-Mail wird versendet</strong> an ' . (int)$n . ' hinterlegte Empfänger (BCC) sowie an Sie und die Standard-CC-Adresse.</div>';
    } elseif ($def['alarm_mail_default']) {
        echo '<div class="alert alert-warning">Für diesen Status ist üblicherweise eine ALARM-Mail vorgesehen – es wird <strong>keine</strong> gesendet. Mit "Abbrechen" können Sie das ändern.</div>';
    }
    echo '<form method="post" action="change.php" autocomplete="off" class="card shadow-sm"><div class="card-body">' . csrf_field()
        . '<input type="hidden" name="pending_id" value="' . h($pending['id']) . '">';
    if ($needs) {
        echo '<label class="form-label" for="totp">Bestätigungscode (TOTP-App, 6 Stellen)</label>'
            . '<input class="form-control form-control-lg mb-3" id="totp" type="text" name="totp" inputmode="numeric" pattern="[0-9 ]{6,7}" maxlength="7" autocomplete="one-time-code" required autofocus>';
    }
    echo '<div class="d-grid gap-2 d-sm-flex">'
        . '<button class="btn btn-danger btn-lg" type="submit" name="action" value="commit">Verbindlich setzen</button>'
        . '<button class="btn btn-outline-secondary btn-lg" type="submit" name="action" value="cancel" formnovalidate>Abbrechen</button></div></div></form>';
    page_end();
    exit;
}

/* Aktueller Status + Schnellaktionen */
echo '<h2 class="h5">Aktueller Status</h2>';
render_status_card($current, true);
if ($current && $current['payload'] && $current['status_key'] !== $bcm['default_status']) {
    echo '<div class="card shadow-sm mb-3"><div class="card-body"><h2 class="h5">Ist der Status noch gültig?</h2>';
    echo '<form method="post" action="change.php">' . csrf_field() . '<input type="hidden" name="validity_type" value="duration">';
    echo '<input type="hidden" name="mode" value="extend">';
    echo '<label class="form-label" for="dur_e">Weiterhin gültig – verlängern um</label><select class="form-select mb-2" id="dur_e" name="duration">';
    foreach ($bcm['validity_options_minutes'] as $min) {
        echo '<option value="' . (int)$min . '">' . h(fmt_minutes($min)) . '</option>';
    }
    echo '</select>';
    echo '<div class="d-grid d-sm-block mb-3"><button class="btn btn-primary" type="submit" name="action" value="preview">Verlängern</button></div>';
    echo '</form>';
    echo '<form method="post" action="change.php">' . csrf_field() . '<input type="hidden" name="mode" value="end">';
    echo '<div class="d-grid d-sm-block"><button class="btn btn-outline-danger" type="submit" name="action" value="preview">Status beenden (zurück auf '
        . h($bcm['by_key'][$bcm['default_status']]['label']) . ')</button></div>';
    echo '</form></div></div>';
}

/* Neuer Status */
$o = fn(string $k, $d = '') => $old[$k] ?? $d;
echo '<div class="card shadow-sm mb-3"><div class="card-body"><h2 class="h5">Neuen Status setzen</h2>';
echo '<form method="post" action="change.php">' . csrf_field() . '<input type="hidden" name="mode" value="set">';
echo '<label class="form-label" for="sk">Status</label><select class="form-select mb-3" id="sk" name="status_key" required><option value="">– bitte wählen –</option>';
foreach ($bcm['statuses'] as $s) {
    $tag = $s['audience'] === 'ALLE_UND_ADRESSLISTE' ? ' · mit Standortliste' : '';
    echo '<option value="' . h($s['key']) . '"' . ($o('status_key') === $s['key'] ? ' selected' : '') . '>'
        . h($s['label'] . ' (' . severity_label($s['severity']) . ')' . $tag) . '</option>';
}
echo '</select>';

echo '<fieldset class="mb-3"><legend class="form-label fs-6 fw-semibold mb-1">Betroffene Standorte <span class="text-body-secondary small fw-normal">(nur bei Status "mit Standortliste")</span></legend>';
echo '<div class="form-check"><input class="form-check-input" type="checkbox" id="loc_all" name="loc_all" value="1"' . ($o('loc_all') ? ' checked' : '')
    . '><label class="form-check-label" for="loc_all">Alle Standorte der Liste</label></div>';
$sel = (array)($old['loc'] ?? []);
foreach ($bcm['locations'] as $i => $l) {
    echo '<div class="form-check"><input class="form-check-input" type="checkbox" id="loc' . (int)$i . '" name="loc[]" value="' . h($l['id']) . '"'
        . (in_array($l['id'], $sel, true) ? ' checked' : '') . '><label class="form-check-label" for="loc' . (int)$i . '">' . h($l['name'])
        . ' <span class="text-body-secondary small">(' . h(trim((string)$l['phone']) !== '' ? $l['phone'] : 'Standard: ' . $bcm['default_phone']) . ')</span></label></div>';
}
echo '</fieldset>';

$vt = $o('validity_type', 'duration');
echo '<fieldset class="mb-3"><legend class="form-label fs-6 fw-semibold mb-1">Gültigkeit</legend>';
echo '<div class="form-check"><input class="form-check-input" type="radio" id="vt_d" name="validity_type" value="duration"' . ($vt === 'duration' ? ' checked' : '')
    . '><label class="form-check-label" for="vt_d">Dauer</label></div>';
echo '<select class="form-select mb-2" name="duration" aria-label="Dauer">';
foreach ($bcm['validity_options_minutes'] as $min) {
    echo '<option value="' . (int)$min . '"' . ((int)$o('duration', 240) === $min ? ' selected' : '') . '>' . h(fmt_minutes($min)) . '</option>';
}
echo '</select>';
echo '<div class="form-check"><input class="form-check-input" type="radio" id="vt_u" name="validity_type" value="until"' . ($vt === 'until' ? ' checked' : '')
    . '><label class="form-check-label" for="vt_u">Gültig bis <span class="text-body-secondary small">(' . h((string)cfg('app.timezone')) . ')</span></label></div>';
echo '<input class="form-control mb-2" type="datetime-local" name="until" aria-label="Gültig bis" value="' . h((string)$o('until')) . '">';
echo '<div class="form-check"><input class="form-check-input" type="radio" id="vt_x" name="validity_type" value="unlimited"' . ($vt === 'unlimited' ? ' checked' : '')
    . '><label class="form-check-label" for="vt_x">Unbefristet <span class="text-body-secondary small">(nur wo zulässig)</span></label></div>';
echo '</fieldset>';

echo '<div class="form-check mb-3"><input class="form-check-input" type="checkbox" id="am" name="alarm_mail" value="1"' . ($o('alarm_mail') ? ' checked' : '')
    . '><label class="form-check-label" for="am"><strong>ALARM-Mail senden</strong> <span class="text-body-secondary small">(erfordert TOTP-Bestätigung)</span></label></div>';
echo '<label class="form-label" for="note">Interne Notiz / Anlass <span class="text-body-secondary small">(nur im Protokoll, nicht auf der Statusseite, max. 200 Zeichen)</span></label>';
echo '<input class="form-control mb-3" id="note" type="text" name="note" maxlength="200" value="' . h((string)$o('note')) . '">';
echo '<div class="d-grid d-sm-block"><button class="btn btn-primary btn-lg" type="submit" name="action" value="preview">Vorschau</button></div></form></div></div>';

/* Nutzung */
$st = login_stats(30);
$hist = status_history(15);
$views = view_totals(array_column($hist, 'id'));
echo '<details class="card shadow-sm mb-3"><summary class="card-header fw-semibold">Nutzung (Anmeldungen, Lesezähler)</summary><div class="card-body">';
echo '<div class="table-responsive table-wrap"><table class="table table-sm align-top"><thead><tr><th>Anmeldungen</th>';
foreach (array_keys($st['periods']) as $k) {
    echo '<th class="text-end">' . h($k) . '</th>';
}
echo '</tr></thead><tbody><tr><td>Stufe 1 (gemeinsames Passwort)</td>';
foreach ($st['periods'] as $p) {
    echo '<td class="text-end">' . (int)$p['s1'] . '</td>';
}
echo '</tr>';
foreach (users() as $id => $u) {
    echo '<tr><td>Stufe 2: ' . h($u['name']) . '<br><span class="small text-body-secondary">zuletzt: ' . h(fmt_local($st['last'][$id] ?? null)) . '</span></td>';
    foreach ($st['periods'] as $p) {
        echo '<td class="text-end">' . (int)($p['s2'][$id] ?? 0) . '</td>';
    }
    echo '</tr>';
}
echo '<tr><td>Fehlgeschlagen Stufe 2</td>';
foreach ($st['periods'] as $p) {
    echo '<td class="text-end">' . (int)$p['fail'] . '</td>';
}
echo '</tr></tbody></table></div>';
echo '<p class="small text-body-secondary">Stufe 1 zählt Anmeldungen (Sitzungen), nicht Personen – das Passwort ist gemeinsam. '
    . 'Der Lesezähler im Statusverlauf zählt je Status einmal pro Sitzung, ohne IP oder Person. Tageswerte: <code>php setup.php stats</code>.</p>';
echo '</div></details>';

/* Meldungstexte */
echo '<details class="card shadow-sm mb-3"><summary class="card-header fw-semibold">Hinterlegte Meldungstexte</summary><ul class="list-group list-group-flush">';
foreach ($bcm['statuses'] as $s) {
    echo '<li class="list-group-item"><div class="fw-semibold">' . h($s['label']) . '</div><div class="small text-body-secondary mb-1">' . h($s['key'])
        . ' · ' . h($s['audience'] === 'ALLE' ? 'Alle' : 'Alle + Standorte') . ($s['alarm_mail_allowed'] ? ' · Alarm möglich' : '')
        . ($s['require_totp'] ? ' · TOTP' : '') . '</div>' . h($s['text']) . '</li>';
}
echo '</ul></details>';

/* Verlauf */
echo '<div class="card shadow-sm mb-3"><div class="card-body"><h2 class="h5">Statusverlauf</h2><ul class="list-group list-group-flush">';
foreach ($hist as $r) {
    $lbl = $r['payload']['label'] ?? $r['status_key'];
    $locs = $r['payload'] ? implode(', ', array_column($r['payload']['locations'] ?? [], 'name')) : '';
    echo '<li class="list-group-item px-0"><div class="d-flex flex-wrap justify-content-between gap-1"><strong>' . h($lbl) . '</strong>'
        . '<span class="small text-body-secondary">' . h(fmt_local($r['created_at'])) . '</span></div>'
        . ($locs !== '' ? '<div class="small">' . h($locs) . '</div>' : '')
        . ($r['mac_ok'] ? '' : '<div class="text-danger fw-semibold">Integritätsfehler</div>')
        . '<div class="small text-body-secondary">von ' . h($r['author']) . ' · gültig bis ' . h(fmt_local($r['valid_until']))
        . ' · Alarm: ' . ($r['alarm_mail'] ? 'ja' : 'nein') . ' · gelesen: ' . (int)($views[(int)$r['id']] ?? 0) . '</div></li>';
}
echo '</ul></div></div>';

/* Audit-Protokoll */
$v = audit_verify();
echo '<div class="card shadow-sm mb-3"><div class="card-body"><h2 class="h5">Änderungsprotokoll</h2>';
echo '<div class="alert alert-' . ($v['ok'] ? 'success' : 'danger') . ' py-2">Integrität der Protokollkette: ' . ($v['ok'] ? 'OK' : 'FEHLER – ' . h((string)$v['error']))
    . ' · ' . (int)$v['count'] . ' Einträge</div>';
echo '<ul class="list-group list-group-flush small">';
foreach (audit_recent(30) as $r) {
    echo '<li class="list-group-item px-0"><span class="text-body-secondary">#' . (int)$r['seq'] . ' · ' . h(fmt_local($r['ts'])) . ' · ' . h($r['actor']) . '</span><br>'
        . h(audit_describe((string)$r['action'], (array)$r['details'])) . '</li>';
}
echo '</ul></div></div>';
page_end();
