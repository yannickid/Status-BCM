<?php
/**
 * Hauptseite: Login Stufe 1 (gemeinsames Zugangspasswort – Crawler-/Zufallsschutz).
 */
declare(strict_types=1);
define('SBCM', true);
require __DIR__ . '/lib.inc.php';
bootstrap();

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

    $wait = throttle_locked('s1');
    if ($wait > 0) {
        $err = 'Zu viele Versuche. Bitte in ca. ' . (int)ceil($wait / 60) . ' Minute(n) erneut versuchen.';
    } elseif (!empty($_POST['website'])) {
        // Honeypot (für Bots sichtbar, für Menschen nicht)
        throttle_record('s1', null, false);
        fail_delay();
        $err = 'Anmeldung fehlgeschlagen.';
    } else {
        $ok = verify_stage1((string)($_POST['password'] ?? ''));
        throttle_record('s1', null, $ok);
        if ($ok) {
            session_regenerate_id(true);
            $_SESSION['s1'] = time();
            audit('login1.ok', 'session', [], 'stage1', 1);
            redirect('status.php');
        }
        fail_delay();
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
echo '<label class="form-label" for="pw">Zugangspasswort</label>';
echo '<input class="form-control form-control-lg mb-3" id="pw" type="password" name="password" autocomplete="current-password" required autofocus>';
echo '<div class="hp" aria-hidden="true"><label>Website<input type="text" name="website" tabindex="-1" autocomplete="off"></label></div>';
echo '<div class="d-grid"><button class="btn btn-primary btn-lg" type="submit">Anmelden</button></div>';
echo '</form></div></div></div></div>';
page_end();
