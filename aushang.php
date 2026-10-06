<?php
/**
 * Aushang: druckbare Seite mit QR-Code zur Statusseite (Schwarzes Brett, Notfallordner).
 * Nur Login Stufe 2. Das Zugangspasswort wird nie gedruckt; der Benutzername des gemeinsamen Zugangs und
 * Notfallrufnummern nur, wenn ausdrücklich gewählt. Die Auswahl wird nicht gespeichert.
 */
declare(strict_types=1);
define('SBCM', true);
require __DIR__ . '/lib.inc.php';
require __DIR__ . '/qr.inc.php';
bootstrap();

if (!stage1_ok()) {
    redirect('index.php');
}
$user = stage2_user();
if (!$user || user_needs_setup($user)) {
    redirect('change.php');
}

$title = (string)cfg('app.title', 'Status');
$url = rtrim((string)cfg('app.base_url'), '/') . '/';
$showUser = !empty($_GET['kennung']);
$pickContacts = array_map('strval', (array)($_GET['kontakt'] ?? []));
$note = trim(preg_replace('/[\x00-\x1F\x7F]+/u', ' ', mb_substr((string)($_GET['hinweis'] ?? ''), 0, 200)) ?? '');
$contacts = array_values(array_filter(contacts_all(), fn($c) => in_array((string)$c['id'], $pickContacts, true) && $c['phone'] !== ''));

page_start('Aushang – ' . $title);
echo '<div class="no-print">';
nav('aushang');
echo '<div class="card shadow-sm mb-3"><div class="card-body"><h1 class="h5">Aushang für Schwarzes Brett und Notfallordner</h1>'
    . '<p class="small mb-2">Unten steht die Druckansicht. Drucken über das Browser-Menü (Strg+P bzw. Teilen → Drucken). '
    . 'Das Zugangspasswort wird nie gedruckt. Bitte geben Sie es auf anderem Weg bekannt (z. B. Unterweisung, Notfallordner im verschlossenen Teil).</p>'
    . '<form method="get" action="aushang.php">'
    . '<div class="form-check"><input class="form-check-input" type="checkbox" name="kennung" value="1" id="ak"' . ($showUser ? ' checked' : '') . '>'
    . '<label class="form-check-label" for="ak">Benutzernamen des gemeinsamen Zugangs aufdrucken ("' . h(stage1_user()) . '")</label></div>';
$withPhone = array_filter(contacts_all(), fn($c) => $c['phone'] !== '');
if ($withPhone) {
    echo '<fieldset class="mt-2"><legend class="small mb-1">Notfallrufnummern aufdrucken (nur Bezeichnung und Rufnummer)</legend>';
    foreach ($withPhone as $c) {
        $id = 'kc' . substr(hash('sha256', (string)$c['id']), 0, 8);
        echo '<div class="form-check"><input class="form-check-input" type="checkbox" name="kontakt[]" value="' . h((string)$c['id']) . '" id="' . $id . '"'
            . (in_array((string)$c['id'], $pickContacts, true) ? ' checked' : '') . '>'
            . '<label class="form-check-label" for="' . $id . '">' . h($c['name']) . ' (' . h($c['phone']) . ')</label></div>';
    }
    echo '</fieldset>';
}
echo '<label class="form-label mt-2" for="ah">Zusätzlicher Hinweis (optional, max. 200 Zeichen)</label>'
    . '<input class="form-control mb-2" id="ah" name="hinweis" maxlength="200" value="' . h($note) . '" placeholder="z. B. Passwort: siehe Notfallordner, Register 1">'
    . '<button class="btn btn-primary" type="submit">Vorschau aktualisieren</button></form></div></div></div>';

echo '<section class="aushang card"><div class="card-body text-center">';
echo '<p class="aushang-kicker">Im Notfall und bei IT-Störungen</p>';
echo '<h1 class="aushang-title">' . h($title) . '</h1>';
echo '<p class="aushang-lead">Aktuelle Lage, Hinweise und Ansprechpartner – auch vom privaten Smartphone abrufbar.</p>';
echo '<img class="qr-code aushang-qr" src="' . h(qr_svg_data_uri($url)) . '" alt="QR-Code zur Statusseite" width="320" height="320">';
echo '<p class="aushang-url break-all">' . h($url) . '</p>';
echo '<ol class="aushang-steps text-start">'
    . '<li>QR-Code mit der Kamera scannen oder Adresse eingeben.</li>'
    . '<li>Anmelden' . ($showUser ? ' mit dem Benutzernamen <strong>' . h(stage1_user()) . '</strong>' : '') . ' und dem Zugangspasswort.</li>'
    . '<li>Die Seite zeigt den aktuellen Status. Bei einer Warnung bitte den Anweisungen folgen.</li></ol>';
if ($contacts) {
    echo '<div class="aushang-contacts text-start"><p class="fw-bold mb-1">Notfallrufnummern</p><ul class="list-unstyled mb-0">';
    foreach ($contacts as $c) {
        echo '<li>' . h($c['name']) . ': <span class="tel">' . h($c['phone']) . '</span></li>';
    }
    echo '</ul></div>';
}
if ($note !== '') {
    echo '<p class="aushang-note">' . h($note) . '</p>';
}
echo '<p class="aushang-foot">Stand: ' . h((new DateTimeImmutable('now', app_tz()))->format('d.m.Y')) . '</p>';
echo '</div></section>';
page_end();
