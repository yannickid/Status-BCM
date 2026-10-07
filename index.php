<?php
/**
 * Hauptseite: ein Anmeldeformular für beide Stufen.
 * Benutzername des gemeinsamen Zugangs + Zugangspasswort -> Statusseite (Stufe 1, Crawler-/Zufallsschutz).
 * Persönliche Kennung + Passwort + TOTP-Code -> zusätzlich Einstellungen (Stufe 2); kritische Änderungen verlangen
 * zusätzlich je Aktion einen TOTP-Code.
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

    if ($act === 'login_cancel') {
        unset($_SESSION['login_totp']);
        redirect('index.php');
    }
    if ($act === 'login_totp') {
        $err = personal_login_totp((string)($_POST['totp'] ?? ''));
        if ($err === null) {
            $u = stage2_user();
            redirect($u && user_needs_setup($u) ? 'change.php' : 'status.php');
        }
    } elseif ($act === 'logout') {
        if (stage1_ok()) {
            audit('logout', 'session');
        }
        logout_all();
        redirect('index.php');
    } else {
        $name = (string)($_POST['user'] ?? '');
        $key = login_name_key($name);
        $pw = (string)($_POST['password'] ?? '');
        $wait = throttle_locked('s1');
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
                unset($_SESSION['login_totp']);
                $_SESSION['s1'] = time();
                audit('login1.ok', 'session', [], 'stage1', 1);
                redirect('status.php');
            }
            fail_delay();
            $err = 'Anmeldung fehlgeschlagen.';
        } else {
            // persönlicher Zugang: Passwort, dann TOTP-Code; danach Lesen und Einstellungen
            $err = personal_login_start($key, $pw);
            if ($err === null && personal_login_pending() === null) {
                $u = stage2_user();
                redirect($u && user_needs_setup($u) ? 'change.php' : 'status.php');
            }
        }
    }
}

$pending = personal_login_pending();
if (stage1_ok() && $pending === null && !isset($_GET['anmelden'])) {
    redirect('status.php');
}
if ($pending === null && stage2_user()) {
    redirect('status.php');
}

$title = (string)cfg('app.title', 'Status');
page_start($title);
echo '<div class="row justify-content-center"><div class="col-12 col-sm-10 col-md-8">';
echo '<h1 class="h3 my-3">' . h($title) . '</h1>';
echo '<div class="card shadow-sm"><div class="card-body">';
if ($err) {
    echo '<div class="alert alert-danger" role="alert">' . h($err) . '</div>';
}
if ($pending !== null) {
    render_login_totp('index.php', $pending);
    echo '</div></div></div></div>';
    page_end();
    exit;
}
echo '<form method="post" action="index.php" autocomplete="off">';
echo csrf_field() . '<input type="hidden" name="action" value="login">';
echo '<label class="form-label" for="us">Benutzername</label>';
echo '<input class="form-control form-control-lg mb-3" id="us" type="text" name="user" value="' . h((string)($_POST['user'] ?? '')) . '" autocomplete="username" autocapitalize="none" spellcheck="false" maxlength="64" required autofocus>';
echo '<label class="form-label" for="pw">Passwort</label>';
echo '<input class="form-control form-control-lg mb-3" id="pw" type="password" name="password" autocomplete="current-password" required>';
echo '<div class="hp" aria-hidden="true"><label>Website<input type="text" name="website" tabindex="-1" autocomplete="off"></label></div>';
echo '<div class="d-grid"><button class="btn btn-primary btn-lg" type="submit">Anmelden</button></div>';
echo '</form></div></div>';
if (is_installed() && public_page()['enabled']) {
    echo '<p class="small mt-3"><a href="extern.php">' . h(public_page()['title']) . '</a> (ohne Anmeldung)</p>';
}
echo '</div></div>';
page_end();
