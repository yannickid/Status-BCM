<?php
/**
 * Einstellungen – nach Login Stufe 2 (personenbezogen).
 * Ablauf: Formular -> Vorschau -> verbindlich setzen (TOTP bei Alarm-/kritischen Änderungen).
 */
declare(strict_types=1);
define('SBCM', true);
require __DIR__ . '/lib.inc.php';
require __DIR__ . '/qr.inc.php';
bootstrap();

if (!stage1_ok()) {
    redirect('index.php');
}

monitor_tick();
$bcm = bcm();
$user = stage2_user();
$errors = [];
$old = [];
$method = $_SERVER['REQUEST_METHOD'] ?? 'GET';
if ($method === 'POST') {
    csrf_verify();
    $act = (string)($_POST['action'] ?? '');

    if ($act === 'login2') {
        $uid = strtolower(trim((string)($_POST['user'] ?? '')));
        if ($e = personal_login_start($uid, (string)($_POST['password'] ?? ''))) {
            $errors[] = $e;
        } elseif (personal_login_pending() === null) {
            redirect('change.php');
        }
    } elseif ($act === 'login_totp') {
        if ($e = personal_login_totp((string)($_POST['totp'] ?? ''))) {
            $errors[] = $e;
        } else {
            redirect('change.php');
        }
    } elseif ($act === 'login_cancel') {
        unset($_SESSION['login_totp']);
        redirect('change.php');
    } elseif (!$user) {
        $errors[] = 'Bitte erneut anmelden.';
    } elseif ($act === 'setup' || $act === 'pw_change') {
        // Ersteinrichtung (Einmalpasswort, abgelaufenes Passwort, fehlendes TOTP) bzw. Passwortwechsel
        $needSetup = user_needs_setup($user);
        $needPw = $act === 'pw_change' || $user['must_change'] || pw_state($user) === 'expired';
        $needTotp = $act === 'setup' && $user['totp_secret'] === '';
        $new = (string)($_POST['new_password'] ?? '');
        if ($user['source'] !== 'db') {
            $errors[] = 'Dieser Benutzer steht in config.local.inc.php und wird dort verwaltet.';
        } elseif ($act === 'pw_change' && $needSetup) {
            $errors[] = 'Bitte zuerst die Einrichtung abschließen.';
        } elseif (($wait = throttle_locked('s2', $user['id'])) > 0) {
            $errors[] = 'Zu viele Fehlversuche. Bitte in ca. ' . (int)ceil($wait / 60) . ' Minute(n) erneut versuchen.';
        } else {
            if ($needPw) {
                $oldOk = password_verify((string)($_POST['old_password'] ?? ''), $user['hash']);
                if (!$oldOk) {
                    throttle_record('s2', $user['id'], false);
                    fail_delay();
                    $errors[] = 'Das bisherige Passwort ist falsch.';
                }
                if (!hash_equals($new, (string)($_POST['new_password2'] ?? ''))) {
                    $errors[] = 'Die neuen Passwörter stimmen nicht überein.';
                }
                $errors = array_merge($errors, password_policy($new, $user['id'], $user['hash']));
            }
            $enroll = $_SESSION['enroll'] ?? null;
            if ($needTotp && (!is_array($enroll) || $enroll['u'] !== $user['id']
                || !totp_verify_user(['id' => $user['id'], 'totp_secret' => (string)$enroll['s']], (string)($_POST['totp'] ?? '')))) {
                throttle_record('s2t', $user['id'], false);
                $errors[] = 'Der Code aus der Authenticator-App ist ungültig. Bitte Uhrzeit des Smartphones prüfen und neuen Code eingeben.';
            }
            if (!$errors) {
                if ($needPw) {
                    account_action('set_pw', $user['id'], ['hash' => password_hash($new, PASSWORD_DEFAULT)], $user['id'], ['self' => true]);
                }
                if ($needTotp) {
                    account_action('set_totp', $user['id'], ['totp_b32' => (string)$enroll['s']], $user['id'], ['self' => true, 'totp_confirmed' => true]);
                    unset($_SESSION['enroll']);
                }
                flash('ok', $act === 'setup' ? 'Einrichtung abgeschlossen.' : 'Passwort geändert.');
                redirect('change.php');
            }
        }
        $user = stage2_user();
    } elseif (user_needs_setup($user)) {
        $errors[] = 'Bitte zuerst Passwort und Authenticator-App einrichten.';
    } elseif ($act === 'cancel') {
        unset($_SESSION['pending']);
        redirect('change.php');
    } elseif ($act === 'preview') {
        $target = ($_POST['mode'] ?? 'set') === 'set' ? null : status_target((int)($_POST['target'] ?? 0));
        [$spec, $errs] = parse_change_request($_POST, $target);
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
                $how = ['totp' => $needs, 'preview_confirmed' => true];
                try {
                    if ($spec['mode'] === 'end') {
                        $res = status_end((int)$spec['target'], $user['id'], $how, (string)$spec['note']);
                        flash('ok', 'Meldung beendet: ' . $res['payload']['label'] . '.');
                    } else {
                        $res = status_create($spec, $user['id'], $how);
                        flash('ok', ['set' => 'Meldung gesetzt: ', 'extend' => 'Meldung verlängert: ', 'update' => 'Meldung geändert: '][$spec['mode']]
                            . $res['payload']['label'] . '.');
                    }
                } catch (InvalidArgumentException $e) {
                    flash('err', $e->getMessage());
                    redirect('change.php');
                }
                if (!empty($res['payload']['apps'])) {
                    // Fachverfahren: Pflicht-Mails an alle hinterlegten Stellen, unabhängig von der ALARM-Mail
                    $kind = ['set' => 'new', 'extend' => 'update', 'update' => 'update', 'end' => 'end'][$spec['mode']];
                    try {
                        $m = send_app_notices($kind, (int)$res['id'], $res['payload'], $res['valid_until'], $user['id']);
                        if ($m['failed'] > 0) {
                            flash('warn', 'Benachrichtigung Fachverfahren: ' . $m['ok'] . ' von ' . $m['total'] . ' Adressen zugestellt – Details im Protokoll.');
                        } else {
                            flash('ok', 'Benachrichtigung Fachverfahren an ' . $m['ok'] . ' Adressen versendet.');
                        }
                        if ($m['missing']) {
                            flash('warn', 'Keine Zieladresse hinterlegt für: ' . implode(', ', $m['missing']) . ' (System → Fachverfahren).');
                        }
                    } catch (Throwable $e) {
                        error_log('Status-BCM: Benachrichtigung Fachverfahren: ' . $e->getMessage());
                        flash('err', 'Die Meldung wurde gespeichert, die Benachrichtigung zum Fachverfahren konnte NICHT versendet werden.');
                    }
                }
                if (!empty($spec['alarm_mail'])) {
                    $kind = ['set' => 'new', 'extend' => 'update', 'update' => 'update', 'end' => 'end'][$spec['mode']];
                    try {
                        $m = send_alarm_mail($kind, (int)$res['id'], $res['payload'], $res['valid_until'], $user['id'], $spec);
                        if ($m['failed'] > 0) {
                            flash('warn', 'ALARM-Mail: ' . $m['ok'] . ' von ' . $m['total'] . ' Adressen zugestellt – Details im Protokoll.');
                        } else {
                            flash('ok', 'ALARM-Mail an ' . $m['ok'] . ' Adressen versendet.');
                        }
                        foreach ($m['channels'] ?? [] as $ch => [$cok, $cfail]) {
                            $lbl = $ch === 'signal' ? 'Signal' : 'GroupAlarm';
                            flash($cfail > 0 ? 'warn' : 'ok', $cfail > 0 ? "$lbl: $cok erfolgreich, $cfail fehlgeschlagen – Details im Server-Fehlerlog."
                                : ($ch === 'signal' ? "Signal an $cok Empfänger versendet." : "GroupAlarm ausgelöst ($cok Szenario/Szenarien)."));
                        }
                    } catch (Throwable $e) {
                        error_log('Status-BCM: Alarm-Mail: ' . $e->getMessage());
                        flash('err', 'Die Meldung wurde gespeichert, die ALARM-Mail konnte NICHT versendet werden.');
                    }
                }
                redirect('change.php');
            }
        }
    }
}

/* ------------------------------------------------------------------ Ausgabe */

page_start('Einstellungen');
nav('change');
echo '<h1 class="h4 mb-3">Einstellungen</h1>';
render_flash();
foreach ($errors as $e) {
    echo '<div class="alert alert-danger" role="alert">' . h($e) . '</div>';
}

if (!$user && ($pendingId = personal_login_pending()) !== null) {
    echo '<div class="card shadow-sm"><div class="card-body"><h2 class="h5">Anmeldung Stufe 2</h2>';
    render_login_totp('change.php', $pendingId);
    echo '</div></div>';
    page_end();
    exit;
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

echo '<p class="mb-3 small text-body-secondary">Angemeldet als ' . h($user['name']) . ' (' . h($user['id']) . '). Abmelden oben rechts.</p>';

/* Ersteinrichtung: Einmalpasswort ersetzen, abgelaufenes Passwort erneuern, Authenticator-App koppeln */
if (user_needs_setup($user)) {
    $needPw = $user['must_change'] || pw_state($user) === 'expired';
    $needTotp = $user['totp_secret'] === '';
    echo '<div class="card shadow-sm"><div class="card-body"><h2 class="h5">Zugang einrichten</h2>';
    echo '<p class="small text-body-secondary">'
        . ($user['must_change'] ? 'Sie haben ein Einmalpasswort erhalten. Bitte legen Sie ein eigenes Passwort fest. '
            : (pw_state($user) === 'expired' ? 'Ihr Passwort ist abgelaufen. Bitte legen Sie ein neues fest. ' : ''))
        . ($needTotp ? 'Koppeln Sie außerdem Ihre Authenticator-App (z. B. Microsoft/Google Authenticator, FreeOTP).' : '') . '</p>';
    echo '<form method="post" action="change.php" autocomplete="off">' . csrf_field() . '<input type="hidden" name="action" value="setup">';
    if ($needPw) {
        echo '<label class="form-label" for="op">Bisheriges Passwort / Einmalpasswort</label><input class="form-control mb-3" id="op" type="password" name="old_password" autocomplete="current-password" required>';
        echo '<label class="form-label" for="np">Neues Passwort <span class="small text-body-secondary">(mind. ' . max(12, (int)cfg('auth.password_min_length', 12))
            . ' Zeichen, gern ein Satz)</span></label><input class="form-control mb-3" id="np" type="password" name="new_password" autocomplete="new-password" required>';
        echo '<label class="form-label" for="np2">Neues Passwort wiederholen</label><input class="form-control mb-3" id="np2" type="password" name="new_password2" autocomplete="new-password" required>';
    }
    if ($needTotp) {
        $en = $_SESSION['enroll'] ?? null;
        if (!is_array($en) || $en['u'] !== $user['id']) {
            $en = $_SESSION['enroll'] = ['u' => $user['id'], 's' => b32_encode(random_bytes(20))];
        }
        $uri = totp_uri($user['id'], $en['s']);
        echo '<div class="alert alert-info"><strong>Authenticator-App koppeln:</strong> In der App (z. B. Microsoft/Google Authenticator, FreeOTP) '
            . '"Konto hinzufügen" wählen und diesen QR-Code scannen.'
            . '<div class="text-center my-2"><img class="qr-code" src="' . h(qr_svg_data_uri($uri)) . '" alt="QR-Code für die Authenticator-App" width="220" height="220"></div>'
            . '<div class="small">Ohne Kamera (z. B. am selben Smartphone): Konto manuell anlegen, Typ "zeitbasiert", Schlüssel:</div>'
            . '<div class="fs-5 font-monospace text-break my-1">' . h(trim(chunk_split($en['s'], 4, ' '))) . '</div>'
            . '<div class="small text-break">oder diesen Link antippen: <a href="' . h($uri) . '">in Authenticator-App öffnen</a></div></div>';
        echo '<label class="form-label" for="tc">Aktueller 6-stelliger Code aus der App</label>'
            . '<input class="form-control form-control-lg mb-3" id="tc" type="text" name="totp" inputmode="numeric" pattern="[0-9 ]{6,7}" maxlength="7" autocomplete="one-time-code" required>';
    }
    echo '<div class="d-grid"><button class="btn btn-primary btn-lg" type="submit">Speichern</button></div></form></div></div>';
    page_end();
    exit;
}

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
if (pw_state($user) === 'soon') {
    $notes[] = 'Ihr Passwort läuft am ' . fmt_local($user['pw_valid_until']) . ' Uhr ab – bitte unter "Mein Zugang" ändern.';
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

/* Formular-Bausteine (ohne JavaScript; $sfx macht die Feld-IDs je Formular eindeutig) */
function form_locations(array $bcm, array $sel, bool $all, string $sfx): string
{
    $h = '<fieldset class="mb-3"><legend class="form-label fs-6 fw-semibold mb-1">Betroffene Standorte <span class="text-body-secondary small fw-normal">(nur bei Status "mit Standortliste")</span></legend>'
        . '<div class="form-check"><input class="form-check-input" type="checkbox" id="la' . $sfx . '" name="loc_all" value="1"' . ($all ? ' checked' : '')
        . '><label class="form-check-label" for="la' . $sfx . '">Alle Standorte der Liste</label></div>';
    foreach ($bcm['locations'] as $i => $l) {
        $h .= '<div class="form-check"><input class="form-check-input" type="checkbox" id="l' . $sfx . '_' . (int)$i . '" name="loc[]" value="' . h($l['id']) . '"'
            . (in_array($l['id'], $sel, true) ? ' checked' : '') . '><label class="form-check-label" for="l' . $sfx . '_' . (int)$i . '">' . h($l['name'])
            . ' <span class="text-body-secondary small">(' . h(trim((string)$l['phone']) !== '' ? $l['phone'] : 'Standard: ' . $bcm['default_phone']) . ')</span></label></div>';
    }
    return $h . '</fieldset>';
}

function form_apps(array $sel, string $sfx): string
{
    $list = apps_all();
    if (!$list) {
        return '';
    }
    $h = '<fieldset class="mb-3"><legend class="form-label fs-6 fw-semibold mb-1">Betroffene Fachverfahren <span class="text-body-secondary small fw-normal">(nur bei Status "Fachverfahren")</span></legend>';
    foreach ($list as $i => $a) {
        $h .= '<div class="form-check"><input class="form-check-input" type="checkbox" id="f' . $sfx . '_' . (int)$i . '" name="app[]" value="' . h($a['id']) . '"'
            . (in_array($a['id'], $sel, true) ? ' checked' : '') . '><label class="form-check-label" for="f' . $sfx . '_' . (int)$i . '">' . h($a['name'])
            . ($a['short'] !== '' ? ' <span class="text-body-secondary small">(' . h($a['short']) . ')</span>' : '')
            . (($fl = app_flags($a)) ? ' <span class="small text-body-secondary">· ' . h(implode(' · ', $fl)) . '</span>' : '') . '</label></div>';
    }
    return $h . '</fieldset>';
}

function form_contacts(array $sel, string $sfx): string
{
    $list = contacts_all();
    if (!$list) {
        return '';
    }
    $h = '<fieldset class="mb-3"><legend class="form-label fs-6 fw-semibold mb-1">Kontakt anzeigen <span class="text-body-secondary small fw-normal">(optional; Pflege unter System)</span></legend>';
    foreach ($list as $i => $c) {
        $info = implode(' · ', array_filter([$c['phone'], $c['email'], $c['platform'], $c['meeting'] !== '' ? 'ID ' . $c['meeting'] : '']));
        $h .= '<div class="form-check"><input class="form-check-input" type="checkbox" id="c' . $sfx . '_' . (int)$i . '" name="contacts[]" value="' . h($c['id']) . '"'
            . (in_array($c['id'], $sel, true) ? ' checked' : '') . '><label class="form-check-label" for="c' . $sfx . '_' . (int)$i . '">' . h($c['name'])
            . ' <span class="text-body-secondary small">(' . h($info) . ')</span></label></div>';
    }
    return $h . '</fieldset>';
}

function form_validity(array $bcm, array $old, string $sfx): string
{
    $vt = (string)($old['validity_type'] ?? 'duration');
    $h = '<fieldset class="mb-3"><legend class="form-label fs-6 fw-semibold mb-1">Gültigkeit</legend>'
        . '<div class="form-check"><input class="form-check-input" type="radio" id="vd' . $sfx . '" name="validity_type" value="duration"' . ($vt === 'duration' ? ' checked' : '')
        . '><label class="form-check-label" for="vd' . $sfx . '">Dauer</label></div><select class="form-select mb-2" name="duration" aria-label="Dauer">';
    foreach ($bcm['validity_options_minutes'] as $min) {
        $h .= '<option value="' . (int)$min . '"' . ((int)($old['duration'] ?? 240) === $min ? ' selected' : '') . '>' . h(fmt_minutes($min)) . '</option>';
    }
    return $h . '</select>'
        . '<div class="form-check"><input class="form-check-input" type="radio" id="vu' . $sfx . '" name="validity_type" value="until"' . ($vt === 'until' ? ' checked' : '')
        . '><label class="form-check-label" for="vu' . $sfx . '">Gültig bis <span class="text-body-secondary small">(' . h((string)cfg('app.timezone')) . ')</span></label></div>'
        . '<input class="form-control mb-2" type="datetime-local" name="until" aria-label="Gültig bis" value="' . h((string)($old['until'] ?? '')) . '">'
        . '<div class="form-check"><input class="form-check-input" type="radio" id="vx' . $sfx . '" name="validity_type" value="unlimited"' . ($vt === 'unlimited' ? ' checked' : '')
        . '><label class="form-check-label" for="vx' . $sfx . '">Unbefristet <span class="text-body-secondary small">(nur wo zulässig)</span></label></div></fieldset>';
}

function form_alarm(array $old, string $sfx, string $label, bool $apps = true): string
{
    $sel = array_map('strval', (array)($old['circles'] ?? []));
    $h = '<fieldset class="mb-3 border rounded p-2"><div class="form-check"><input class="form-check-input" type="checkbox" id="am' . $sfx . '" name="alarm_mail" value="1"'
        . (!empty($old['alarm_mail']) ? ' checked' : '') . '><label class="form-check-label" for="am' . $sfx . '"><strong>' . h($label) . '</strong>'
        . ' <span class="text-body-secondary small">(erfordert TOTP-Bestätigung)</span></label></div>'
        . '<div class="small text-body-secondary mt-1 mb-1">An welche Alarmkreise?</div>';
    foreach (alarm_circles() as $i => $c) {
        $h .= '<div class="form-check"><input class="form-check-input" type="checkbox" id="k' . $sfx . '_' . (int)$i . '" name="circles[]" value="' . h($c['id']) . '"'
            . (in_array($c['id'], $sel, true) ? ' checked' : '') . '><label class="form-check-label" for="k' . $sfx . '_' . (int)$i . '">' . h($c['name'])
            . ' <span class="text-body-secondary small">(' . count($c['emails']) . ' Adressen)</span></label></div>';
    }
    if ($apps && apps_all()) {
        $roles = array_key_exists('alarm_mail', $old) ? array_map('strval', (array)($old['app_role'] ?? [])) : SBCM_APP_ROLES_DEFAULT;
        $h .= '<div class="small text-body-secondary mt-2 mb-1">Bei Fachverfahren zusätzlich die Kreise dieser Rollen alarmieren (Signal, GroupAlarm; '
            . 'die E-Mail erhalten sie ohnehin als Pflicht-Benachrichtigung):</div><div class="d-flex flex-wrap gap-3">';
        foreach (SBCM_APP_ROLES as $r => $rl) {
            $h .= '<div class="form-check"><input class="form-check-input" type="checkbox" id="ar' . $sfx . $r . '" name="app_role[]" value="' . h($r) . '"'
                . (in_array($r, $roles, true) ? ' checked' : '') . '><label class="form-check-label" for="ar' . $sfx . $r . '">' . h($rl) . '</label></div>';
        }
        $h .= '</div>';
    }
    $nl = !array_key_exists('alarm_mail', $old) || !empty($old['notify_loc']);
    return $h . '<div class="form-check"><input class="form-check-input" type="checkbox" id="nl' . $sfx . '" name="notify_loc" value="1"' . ($nl ? ' checked' : '')
        . '><label class="form-check-label" for="nl' . $sfx . '">Standortverwaltungen informieren <span class="text-body-secondary small">(betroffene Standorte; bei Meldungen für alle: alle Standorte; nicht bei Fachverfahren)</span></label></div></fieldset>';
}

function form_note(array $old, string $sfx): string
{
    return '<label class="form-label" for="n' . $sfx . '">Interne Notiz / Anlass <span class="text-body-secondary small">(nur im Protokoll, max. 200 Zeichen)</span></label>'
        . '<input class="form-control mb-3" id="n' . $sfx . '" type="text" name="note" maxlength="200" value="' . h((string)($old['note'] ?? '')) . '">';
}

/* Vorschau (zweiter Schritt) */
$pending = $_SESSION['pending'] ?? null;
$ttl = (int)cfg('auth.pending_ttl_seconds', 300);
if (is_array($pending) && ($pending['user'] ?? '') === $user['id'] && time() - (int)$pending['t'] <= $ttl) {
    $spec = $pending['spec'];
    $def = $bcm['by_key'][$spec['key']];
    $target = $spec['target'] ? status_target((int)$spec['target']) : null;
    $needs = spec_needs_totp($spec);
    $title = ['set' => 'Neue Meldung', 'extend' => 'Meldung verlängern', 'update' => 'Meldung ändern', 'end' => 'Meldung beenden'][$spec['mode']];
    echo '<h2 class="h5">Vorschau: ' . h($title) . ' – bitte prüfen</h2>';
    echo '<p class="small text-body-secondary">Diese Vorschau gilt bis <strong>'
        . h((new DateTimeImmutable('@' . ((int)$pending['t'] + $ttl)))->setTimezone(app_tz())->format('H:i')) . ' Uhr</strong> ('
        . (int)ceil($ttl / 60) . ' Minuten). Danach bitte neu vorbereiten.</p>';
    if ($spec['mode'] === 'end') {
        echo '<p class="text-body-secondary small">Die Meldung wird beendet und bleibt ' . (int)cfg('display.keep_hours', 48)
            . ' Stunden ausgegraut mit dem Vermerk "zurückgenommen / gelöst" sichtbar:</p>';
        render_status_card(($target ?? ['payload' => build_payload($def, $spec['loc_ids'], '', [], $spec['app_ids'] ?? []), 'created_at' => null, 'valid_until' => null, 'mac_ok' => true])
            + ['gone' => 'ended', 'gone_at' => now_utc()], true);
        $payload = $target['payload'] ?? build_payload($def, $spec['loc_ids']);
    } else {
        $payload = build_payload($def, $spec['loc_ids'], $spec['note'], $spec['contact_ids'], $spec['app_ids'] ?? []);
        echo '<p class="text-body-secondary small">So sehen alle Personen mit Zugang die Meldung:</p>';
        render_status_card(['payload' => $payload, 'created_at' => now_utc(), 'valid_until' => $spec['valid_until'],
            'mac_ok' => true, 'author' => $user['id'], 'alarm_mail' => $spec['alarm_mail'] ? 1 : 0], true);
    }
    // Fachverfahren: Hinweise aus der internen Einstufung (Meldepflichten, DSGVO-Referenz) und Wirkung auf der externen Seite
    $selApps = array_values(array_filter(apps_all(), fn($a) => in_array($a['id'], (array)($spec['app_ids'] ?? []), true)));
    $appNotes = [];
    foreach ($selApps as $a) {
        $n = [];
        if ($a['kritis']) {
            $n[] = 'KRITIS: Meldepflichten (z. B. BSI) prüfen';
        }
        if ($a['vsa']) {
            $n[] = 'VSA: Geheimschutzbeauftragte informieren';
        }
        if ($a['dsb'] !== '') {
            $n[] = 'DSB-Sensibilität ' . SBCM_APP_DSB[$a['dsb']] . ': ' . dsgvo_refs()[$a['dsb']];
        }
        if ($n) {
            $appNotes[] = '<li><strong>' . h($a['name']) . ':</strong> ' . h(implode('; ', $n)) . '</li>';
        }
    }
    if ($appNotes) {
        echo '<div class="alert alert-info"><strong>Hinweise zu den Fachverfahren (nur intern)</strong><ul class="mb-0">' . implode('', $appNotes) . '</ul></div>';
    }
    $ext = array_filter($selApps, fn($a) => $a['external']);
    if ($selApps) {
        $kind = ['set' => 'new', 'extend' => 'update', 'update' => 'update', 'end' => 'end'][$spec['mode']];
        $plan = app_notice_plan($kind, $payload, $spec['valid_until']);
        echo '<div class="alert alert-warning"><strong>Benachrichtigung zu den Fachverfahren wird versendet</strong> (Pflicht, je Gruppe eine eigene Mail mit Infotext, Empfänger per BCC):<ul class="mb-0">';
        foreach ($plan as $p) {
            echo '<li>' . h($p['title']) . ': ' . ($p['missing'] ? '<strong>keine Zieladresse hinterlegt</strong> (System → Fachverfahren)'
                : (count($p['emails']) ? (int)count($p['emails']) . ' Adresse(n)' : 'keine Adressen hinterlegt')) . '</li>';
        }
        if (!empty($payload['exercise'])) {
            echo '<li>Übung: Unternehmen und Behörden werden nicht benachrichtigt.</li>';
        }
        echo '</ul></div>';
    }
    if ($ext && public_page()['enabled'] && $spec['mode'] !== 'end') {
        echo '<p class="small text-body-secondary">Auf der externen Statusseite erscheint für ' . h(implode(', ', array_map('app_public_name', $ext))) . ' nur: "'
            . h((string)($payload['public_label'] ?? '')) . '" mit dem Text "' . h((string)($payload['public_text'] ?? '')) . '"' . (!empty($payload['exercise']) ? ' (Übungen nicht)' : '') . '.</p>';
    }
    if ($spec['alarm_mail']) {
        [$to, $names, $locCount] = alarm_targets($spec, $payload);
        $kind = ['set' => 'new', 'extend' => 'update', 'update' => 'update', 'end' => 'end'][$spec['mode']];
        echo '<div class="alert alert-warning"><strong>ALARM-Mail wird versendet</strong> (Betreff beginnt mit "' . h(mail_prefixes()[$kind]) . '") an '
            . (int)count($to) . ' Adressen per BCC: ' . h($names ? implode(', ', $names) : 'kein Kreis')
            . ($locCount ? ' sowie ' . (int)$locCount . ' Adresse(n) der Standortverwaltung' : '') . '. Kopie an Sie und die Standard-CC-Adresse.';
        $ct = channel_targets($spec);
        if ($ct['signal'] && channel_enabled('signal')) {
            echo ' Zusätzlich <strong>Signal</strong> an ' . count($ct['signal']) . ' Empfänger.';
        }
        if ($ct['groupalarm'] && channel_enabled('groupalarm') && in_array($kind, (array)cfg('channels.groupalarm.kinds', ['new', 'update', 'end']), true)) {
            echo ' Zusätzlich <strong>GroupAlarm</strong> (Szenario ' . h(implode(', ', array_keys($ct['groupalarm']))) . ').';
        }
        echo '</div>';
    } elseif ($def['alarm_mail_default'] && $spec['mode'] === 'set') {
        echo '<div class="alert alert-warning">Für diesen Status ist üblicherweise eine ALARM-Mail vorgesehen – es wird <strong>keine</strong> gesendet. Mit "Abbrechen" können Sie das ändern.</div>';
    }
    echo '<form method="post" action="change.php" autocomplete="off" class="card shadow-sm"><div class="card-body">' . csrf_field()
        . '<input type="hidden" name="pending_id" value="' . h($pending['id']) . '">';
    if ($needs) {
        echo '<label class="form-label" for="totp">Bestätigungscode (TOTP-App, 6 Stellen)</label>'
            . '<input class="form-control form-control-lg mb-3" id="totp" type="text" name="totp" inputmode="numeric" pattern="[0-9 ]{6,7}" maxlength="7" autocomplete="one-time-code" required autofocus>';
    }
    echo '<div class="d-grid gap-2 d-sm-flex">'
        . '<button class="btn btn-danger btn-lg" type="submit" name="action" value="commit">Verbindlich ' . ($spec['mode'] === 'end' ? 'beenden' : 'setzen') . '</button>'
        . '<button class="btn btn-outline-secondary btn-lg" type="submit" name="action" value="cancel" formnovalidate>Abbrechen</button></div></div></form>';
    page_end();
    exit;
}

/* Aktuelle Meldungen mit Aktionen */
$board = status_board();
$open = array_merge($board['live'], array_filter($board['recent'], fn($r) => $r['gone'] === 'expired'), $board['stale']);
$oldT = (int)($old['target'] ?? 0);
echo '<h2 class="h5">Aktuelle Meldungen (' . count($open) . ')</h2>';
foreach ($board['unverified'] as $r) {
    if ($r['payload']) {
        render_status_card($r, true);
    }
}
if (!$open) {
    render_status_card(null, false);
}
foreach ($open as $r) {
    $id = (int)$r['id'];
    $sfx = 'm' . $id;
    $def = $bcm['by_key'][$r['status_key']] ?? null;
    render_status_card($r, true);
    if (!$def) {
        continue;
    }
    $o = $oldT === $id ? $old : [];
    $hidden = csrf_field() . '<input type="hidden" name="target" value="' . $id . '">';
    echo '<div class="card shadow-sm mb-4 ms-2"><div class="card-body">';
    if (($r['gone'] ?? '') === 'expired') {
        echo '<div class="alert alert-warning py-2 small">Abgelaufen – bitte verlängern oder beenden.</div>';
    }
    echo '<form method="post" action="change.php" class="mb-2">' . $hidden . '<input type="hidden" name="mode" value="extend"><input type="hidden" name="validity_type" value="duration">'
        . '<label class="form-label" for="de' . $sfx . '">Weiterhin gültig – verlängern um</label><div class="d-flex gap-2"><select class="form-select" id="de' . $sfx . '" name="duration">';
    foreach ($bcm['validity_options_minutes'] as $min) {
        echo '<option value="' . (int)$min . '">' . h(fmt_minutes($min)) . '</option>';
    }
    echo '</select><button class="btn btn-primary" type="submit" name="action" value="preview">Verlängern</button></div></form>';
    $locSel = array_column($r['payload']['locations'] ?? [], 'id');
    $conSel = array_column($r['payload']['contacts'] ?? [], 'id');
    $appSel = array_column($r['payload']['apps'] ?? [], 'id');
    $isApp = $def['audience'] === 'FACHVERFAHREN';
    echo '<details class="mb-2"' . ($o && ($o['mode'] ?? '') === 'update' ? ' open' : '') . '><summary>Ändern (Standorte, Kontakt, Gültigkeit, ALARM-Mail)</summary>'
        . '<form method="post" action="change.php" class="mt-2">' . $hidden . '<input type="hidden" name="mode" value="update">'
        . ($def['audience'] === 'ALLE_UND_ADRESSLISTE' ? form_locations($bcm, array_map('strval', (array)($o['loc'] ?? $locSel)), !empty($o['loc_all']), 'u' . $sfx) : '')
        . ($isApp ? form_apps(array_map('strval', (array)($o['app'] ?? $appSel)), 'u' . $sfx) : '')
        . form_contacts(array_map('strval', (array)($o['contacts'] ?? $conSel)), 'u' . $sfx) . form_validity($bcm, $o, 'u' . $sfx)
        . ($def['alarm_mail_allowed'] ? form_alarm($o, 'u' . $sfx, 'ALARM-Mail "Aktualisierung" senden', $isApp) : '') . form_note($o, 'u' . $sfx)
        . '<button class="btn btn-outline-primary" type="submit" name="action" value="preview">Vorschau</button></form></details>';
    echo '<details' . ($o && ($o['mode'] ?? '') === 'end' ? ' open' : '') . '><summary class="text-danger">Beenden (zurückgenommen / gelöst)</summary>'
        . '<form method="post" action="change.php" class="mt-2">' . $hidden . '<input type="hidden" name="mode" value="end">'
        . ($def['alarm_mail_allowed'] ? form_alarm($o, 'e' . $sfx, 'ALARM-Mail "Ende" senden', $isApp) : '') . form_note($o, 'e' . $sfx)
        . '<button class="btn btn-outline-danger" type="submit" name="action" value="preview">Vorschau</button></form></details>';
    echo '</div></div>';
}
$ended = array_filter($board['recent'], fn($r) => $r['gone'] === 'ended');
if ($ended) {
    echo '<h2 class="h6 text-body-secondary mt-3">Beendet (letzte ' . (int)cfg('display.keep_hours', 48) . ' Stunden)</h2>';
    foreach ($ended as $r) {
        render_status_card($r, true);
    }
}

/* Neue Meldung */
$o = !$oldT ? $old : [];
echo '<div class="card shadow-sm mb-3 mt-4"><div class="card-body"><h2 class="h5">Neue Meldung</h2>';
echo '<p class="small text-body-secondary">Bestehende Meldungen bleiben dabei bestehen.</p>';
echo '<form method="post" action="change.php">' . csrf_field() . '<input type="hidden" name="mode" value="set">';
echo '<label class="form-label" for="sk">Status</label><select class="form-select mb-3" id="sk" name="status_key" required><option value="">– bitte wählen –</option>';
foreach ($bcm['statuses'] as $s) {
    if ($s['key'] === $bcm['default_status']) {
        continue;
    }
    $tag = ['ALLE_UND_ADRESSLISTE' => ' · mit Standortliste', 'FACHVERFAHREN' => ' · Fachverfahren'][$s['audience']] ?? '';
    echo '<option value="' . h($s['key']) . '"' . (($o['status_key'] ?? '') === $s['key'] ? ' selected' : '') . '>'
        . h($s['label'] . ' (' . severity_label($s['severity']) . ')' . $tag) . '</option>';
}
echo '</select>';
echo form_locations($bcm, array_map('strval', (array)($o['loc'] ?? [])), !empty($o['loc_all']), 'n');
echo form_apps(array_map('strval', (array)($o['app'] ?? [])), 'n');
echo form_contacts(array_map('strval', (array)($o['contacts'] ?? [])), 'n');
echo form_validity($bcm, $o, 'n');
echo form_alarm($o, 'n', 'ALARM-Mail senden');
echo form_note($o, 'n');
echo '<div class="d-grid d-sm-block"><button class="btn btn-primary btn-lg" type="submit" name="action" value="preview">Vorschau</button></div></form></div></div>';

/* Mein Zugang */
echo '<details class="card shadow-sm mb-3"><summary class="card-header fw-semibold">Mein Zugang (Passwort ändern)</summary><div class="card-body">';
echo '<p class="small mb-2">Passwort gesetzt: ' . h(fmt_local($user['pw_set_at'] ?? null)) . ' · gültig bis: '
    . h(empty($user['pw_valid_until']) ? 'unbefristet' : fmt_local($user['pw_valid_until'])) . ' · Rolle: ' . h($user['role']) . '</p>';
if ($user['source'] === 'db') {
    echo '<form method="post" action="change.php" autocomplete="off">' . csrf_field() . '<input type="hidden" name="action" value="pw_change">';
    echo '<label class="form-label" for="cp0">Bisheriges Passwort</label><input class="form-control mb-2" id="cp0" type="password" name="old_password" autocomplete="current-password" required>';
    echo '<label class="form-label" for="cp1">Neues Passwort</label><input class="form-control mb-2" id="cp1" type="password" name="new_password" autocomplete="new-password" required>';
    echo '<label class="form-label" for="cp2">Neues Passwort wiederholen</label><input class="form-control mb-3" id="cp2" type="password" name="new_password2" autocomplete="new-password" required>';
    echo '<div class="d-grid d-sm-block"><button class="btn btn-outline-primary" type="submit">Passwort ändern</button></div></form>';
} else {
    echo '<p class="small text-body-secondary mb-0">Dieser Benutzer steht noch in config.local.inc.php und wird dort verwaltet (älterer Weg; Übernahme per <code>php setup.php migrate-users</code>).</p>';
}
echo '</div></details>';

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
    . 'Der Lesezähler im Statusverlauf zählt je Status einmal pro Sitzung, ohne IP oder Person. Tageswerte unter <a href="system.php">System</a> (Admins).</p>';
echo '</div></details>';

/* Meldungstexte */
echo '<details class="card shadow-sm mb-3"><summary class="card-header fw-semibold">Hinterlegte Meldungstexte</summary><ul class="list-group list-group-flush">';
foreach ($bcm['statuses'] as $s) {
    echo '<li class="list-group-item"><div class="fw-semibold">' . h($s['label']) . '</div><div class="small text-body-secondary mb-1">' . h($s['key'])
        . ' · ' . h($s['audience'] === 'ALLE' ? 'Alle' : 'Alle + Standorte') . ($s['alarm_mail_allowed'] ? ' · Alarm möglich' : '')
        . ($s['require_totp'] ? ' · TOTP' : '') . (!empty($s['phone']) ? ' · Rufnummer: ' . h($s['phone']) : '') . '</div>' . h($s['text']) . '</li>';
}
echo '</ul></details>';

/* Verlauf */
echo '<div class="card shadow-sm mb-3"><div class="card-body"><h2 class="h5">Verlauf aller Meldungen</h2><ul class="list-group list-group-flush">';
foreach ($hist as $r) {
    $lbl = $r['payload']['label'] ?? $r['status_key'];
    $locs = $r['payload'] ? implode(', ', array_column($r['payload']['locations'] ?? [], 'name')) : '';
    echo '<li class="list-group-item px-0"><div class="d-flex flex-wrap justify-content-between gap-1"><strong>' . h($lbl) . '</strong>'
        . '<span class="small text-body-secondary">' . h(fmt_local($r['created_at'])) . '</span></div>'
        . ($locs !== '' ? '<div class="small">' . h($locs) . '</div>' : '')
        . ($r['mac_ok'] ? '' : '<div class="text-danger fw-semibold">Integritätsfehler</div>')
        . '<div class="small text-body-secondary">#' . (int)status_msg($r) . ' · ' . h(['active' => 'aktiv', 'superseded' => 'abgelöst', 'ended' => 'beendet'][$r['state']] ?? $r['state'])
        . ' · von ' . h($r['author']) . ' · gültig bis ' . h(fmt_local($r['valid_until']))
        . ' · Alarm: ' . ($r['alarm_mail'] ? 'ja' : 'nein') . ' · gelesen: ' . (int)($views[(int)$r['id']] ?? 0) . '</div></li>';
}
echo '</ul></div></div>';

/* Audit-Protokoll */
echo '<p class="small"><a href="aushang.php">Aushang mit QR-Code drucken</a>' . ($user['role'] === 'admin' ? ' · <a href="system.php#export">Protokoll exportieren (CSV/PDF)</a>' : '') . '</p>';
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
