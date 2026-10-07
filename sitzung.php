<?php
/**
 * Abmeldezeit bei Untätigkeit, eingebettet oben in jeder angemeldeten Seite (iframe, kein JavaScript).
 * Zwei Minuten vor Ablauf schaltet ein zeitgesteuertes Stylesheet auf eine Warnung um, bei Ablauf auf
 * "abgemeldet". "Verlängern" lädt nur diesen Rahmen neu; Eingaben auf der Seite bleiben erhalten.
 * GET zählt nicht als Aktivität (sonst würde das Anzeigen allein die Sitzung verlängern).
 */
declare(strict_types=1);
define('SBCM', true);
define('SBCM_SESSION_PEEK', ($_SERVER['REQUEST_METHOD'] ?? 'GET') !== 'POST');
define('SBCM_FRAMEABLE', true);
require __DIR__ . '/lib.inc.php';

const SESSION_WARN_SECONDS = 120;

// Zeitsteuerung als Stylesheet (CSP erlaubt keine Inline-Styles): ?css=<Sekunden bis Warnung>-<Sekunden bis Ablauf>
if (isset($_GET['css'])) {
    if (!preg_match('/^(\d{1,6})-(\d{1,6})$/', (string)$_GET['css'], $m)) {
        http_response_code(400);
        exit;
    }
    header('Content-Type: text/css; charset=utf-8');
    header('Cache-Control: public, max-age=86400');
    header('X-Content-Type-Options: nosniff');
    [$w, $e] = [(int)$m[1], max((int)$m[1], (int)$m[2])];
    echo ".sess-normal{animation:sbcm-off .01s linear {$w}s forwards}\n"
        . ".sess-warn{animation:sbcm-on .01s linear {$w}s forwards,sbcm-off .01s linear {$e}s forwards}\n"
        . ".sess-gone{animation:sbcm-on .01s linear {$e}s forwards}\n";
    exit;
}

bootstrap();
if (($_SERVER['REQUEST_METHOD'] ?? 'GET') === 'POST') {
    csrf_verify();
    if (stage1_ok()) {
        stage2_user();      // frischt auch die persönliche Anmeldung auf
    }
    redirect('sitzung.php?verlaengert=1');
}

$d = session_deadline();
echo "<!doctype html>\n<html lang=\"de\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">"
    . '<meta name="robots" content="noindex,nofollow"><title>Sitzung</title>'
    . '<link rel="stylesheet" href="' . h(asset_url('bootstrap.min.css')) . '"><link rel="stylesheet" href="' . h(asset_url('app.css')) . '">';
if ($d) {
    $left = max(0, $d['end'] - time());
    echo '<link rel="stylesheet" href="sitzung.php?css=' . max(0, $left - SESSION_WARN_SECONDS) . '-' . $left . '">';
}
echo '</head><body class="session-body">';
if (!$d) {
    echo '<main><h1 class="visually-hidden">Abmeldung bei Untätigkeit</h1><div class="sess-msg">Nicht angemeldet. <a href="index.php" target="_top">Anmelden</a></div></main></body></html>';
    exit;
}
$at = (new DateTimeImmutable('@' . $d['end']))->setTimezone(app_tz())->format('H:i');
$who = $d['stage2'] ? 'Persönliche Anmeldung' : 'Anmeldung';
$btn = fn(string $label) => '<form method="post" action="sitzung.php" class="d-inline">' . csrf_field()
    . '<button class="btn btn-sm btn-outline-primary py-0 ms-1" type="submit">' . $label . '</button></form>';
echo '<main><h1 class="visually-hidden">Abmeldung bei Untätigkeit</h1><div class="sess-stack">';
echo '<div class="sess-msg sess-normal">' . (!empty($_GET['verlaengert']) ? 'Verlängert. ' : '') . h($who) . ' endet bei Untätigkeit um <strong>' . h($at) . ' Uhr</strong>.'
    . $btn('Verlängern') . '</div>';
echo '<div class="sess-msg sess-warn bg-warning-subtle text-warning-emphasis" role="alert"><strong>Achtung: Abmeldung um ' . h($at)
    . ' Uhr.</strong> Ungesicherte Eingaben gehen verloren.' . $btn('Jetzt verlängern') . '</div>';
echo '<div class="sess-msg sess-gone bg-danger-subtle text-danger-emphasis" role="alert"><strong>'
    . ($d['stage2'] ? 'Persönliche Anmeldung beendet' : 'Abgemeldet') . ' seit ' . h($at) . ' Uhr.</strong> Eingaben kopieren, dann <a href="index.php" target="_top">neu anmelden</a>.</div>';
echo '</div></main></body></html>';
