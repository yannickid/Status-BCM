<?php
/**
 * Externe Statusseite ohne Login (standardmäßig aus; einschalten unter Fachverfahren → Externe Statusseite).
 * Dieselbe Ansicht steht auf der Startseite. Zeigt nur Fachverfahren mit "extern sichtbar", nur die je Verfahren
 * freigegebenen Felder und nur die allgemeine Textfassung: keine Ursachen, keine internen Angaben, keine Meldungen zu
 * Standorten. Keine Sitzung, kein Cookie. Telefon, E-Mail und Ticket-Link stehen erst nach "Kontakt anzeigen"
 * (POST mit zeitgebundenem Token) in der Antwort, nie im Quelltext der Seite (Schutz vor Adress-Sammlern).
 */
declare(strict_types=1);
define('SBCM', true);
define('SBCM_NO_SESSION', true);
require __DIR__ . '/lib.inc.php';
bootstrap();

$pp = is_installed() ? public_page() : ['enabled' => false];
if (!$pp['enabled']) {
    http_response_code(404);
    header('Content-Type: text/plain; charset=utf-8');
    echo "Nicht gefunden.\n";
    exit;
}

$reveal = false;
$hint = '';
if (($_SERVER['REQUEST_METHOD'] ?? 'GET') === 'POST') {
    // Honeypot-Feld leer, Token gültig und mindestens 2 Sekunden alt: sonst wie ein normaler Aufruf ohne Kontaktdaten
    if (($_POST['website'] ?? '') === '' && public_reveal_ok((string)($_POST['t'] ?? ''))) {
        $reveal = true;
    } else {
        $hint = 'Bitte laden Sie die Seite neu und versuchen Sie es noch einmal.';
    }
}

page_start($pp['title']);
echo '<header class="mb-3 pb-2 border-bottom"><p class="app-title fw-bold mb-0">' . h((string)cfg('app.title', 'Status')) . '</p></header>';
render_public_status($pp, public_rows(), 1);
render_public_contact($pp, $reveal, $hint);
echo '<p class="small text-body-secondary">Stand der Seite: ' . h(fmt_local(now_utc())) . ' Uhr · <a href="index.php">Anmeldung</a></p>';
page_end();
