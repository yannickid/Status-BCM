<?php
/**
 * Hauptseite: ein Anmeldeformular für beide Stufen.
 * Benutzername des gemeinsamen Zugangs + Zugangspasswort -> Statusseite (Stufe 1, Crawler-/Zufallsschutz).
 * Persönliche Kennung + Passwort -> zusätzlich Einstellungen (Stufe 2); kritische Änderungen verlangen weiterhin TOTP.
 */
declare(strict_types=1);
define('SBCM', true);
require __DIR__ . '/lib.inc.php';
bootstrap();

// Noch nicht eingerichtet: zum Einrichtungsassistenten
if (stage1_hash() === '' && is_file(__DIR__ . '/install.php') && !is_installed()) {
    redirect('install.php');
}

$method = $_SERVER['REQUEST_METHOD'] ?? 'GET';
$err = null;

if ($method === 'POST') {
    csrf_verify();
    $act = (string)($_POST['action'] ?? 'login');

    if ($act === 'logout') {
        if (stage1_ok()) {
            audit('logout', 'session');
        }
        logout_all();
        redirect('index.php');
    }

    $name = (string)($_POST['user'] ?? '');
    $key = login_name_key($name);
    $pw = (string)($_POST['password'] ?? '');
    $wait = throttle_locked('s1');
    if ($wait === 0 && $key !== login_name_key(stage1_user())) {
        $wait = throttle_locked('s2', $key);
    }
    if ($wait > 0) {
        $err = 'Zu viele Versuche. Bitte in ca. ' . (int)ceil($wait / 60) . ' Minute(n) erneut versuchen.';
    } elseif (!empty($_POST['website'])) {
        // Honeypot (für Bots sichtbar, für Menschen nicht)
        throttle_record('s1', null, false);
        fail_delay();
        $err = 'Anmeldung fehlgeschlagen.';
    } elseif ($key === login_name_key(stage1_user())) {
        // gemeinsamer Zugang: nur lesen
        $ok = verify_stage1($pw);
        throttle_record('s1', null, $ok);
        if ($ok) {
            session_regenerate_id(true);
            $_SESSION['s1'] = time();
            audit('login1.ok', 'session', [], 'stage1', 1);
            redirect('status.php');
        }
        fail_delay();
        $err = 'Anmeldung fehlgeschlagen.';
    } else {
        // persönlicher Zugang: Lesen und Einstellungen in einem Schritt; kritische Änderungen verlangen weiter TOTP
        $u = verify_user($key, $pw);
        throttle_record('s1', null, $u !== null);
        throttle_record('s2', $key, $u !== null);
        if ($u) {
            session_regenerate_id(true);
            $_SESSION['s1'] = time();
            $_SESSION['s2'] = ['u' => $u['id'], 't' => time()];
            audit('login2.ok', 'session', [], $u['id'], 2);
            redirect(user_needs_setup($u) ? 'change.php' : 'status.php');
        }
        fail_delay();
        audit('login2.fail', 'session', ['user' => mb_substr(preg_replace('/[^\w.@-]/u', '?', $key) ?? '', 0, 32)], 'anonymous', 1);
        $err = 'Anmeldung fehlgeschlagen.';
    }
}

if (stage1_ok()) {
    redirect('status.php');
}

$title = (string)cfg('app.title', 'Status');
page_start($title);
echo '<div class="row justify-content-center"><div class="col-12 col-sm-10 col-md-8">';
echo '<h1 class="h3 my-3">' . h($title) . '</h1>';
echo '<div class="card shadow-sm"><div class="card-body">';
echo '<form method="post" action="index.php" autocomplete="off">';
echo csrf_field() . '<input type="hidden" name="action" value="login">';
if ($err) {
    echo '<div class="alert alert-danger" role="alert">' . h($err) . '</div>';
}
echo '<label class="form-label" for="us">Benutzername</label>';
echo '<input class="form-control form-control-lg mb-3" id="us" type="text" name="user" value="' . h((string)($_POST['user'] ?? '')) . '" autocomplete="username" autocapitalize="none" spellcheck="false" maxlength="64" required autofocus>';
echo '<label class="form-label" for="pw">Passwort</label>';
echo '<input class="form-control form-control-lg mb-3" id="pw" type="password" name="password" autocomplete="current-password" required>';
echo '<div class="hp" aria-hidden="true"><label>Website<input type="text" name="website" tabindex="-1" autocomplete="off"></label></div>';
echo '<div class="d-grid"><button class="btn btn-primary btn-lg" type="submit">Anmelden</button></div>';
echo '</form><p class="small text-body-secondary mt-3 mb-0">Gemeinsamen Zugang oder persönliche Kennung verwenden.</p></div></div></div></div>';
page_end();
