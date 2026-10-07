<?php
/**
 * Externe Statusseite ohne Login (standardmäßig aus; einschalten unter Fachverfahren → Externe Statusseite).
 * Zeigt nur Fachverfahren mit "extern sichtbar" und nur die allgemeine Textfassung: keine Ursachen, keine internen
 * Angaben, keine Meldungen zu Standorten. Keine Sitzung, kein Cookie. Telefon, E-Mail und Ticket-Link stehen erst nach
 * "Kontakt anzeigen" (POST mit zeitgebundenem Token) in der Antwort, nie im Quelltext der Seite (Schutz vor Adress-Sammlern).
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

$board = status_board();
$states = app_states($board, true);
$rows = [];
$rank = ['critical' => 0, 'warn' => 1, 'info' => 2];
foreach (apps_all() as $a) {
    if (!$a['external']) {
        continue;
    }
    $st = $states[$a['id']] ?? null;
    if ($st || $a['green_ext']) {
        $rows[] = [$st ? ($rank[$st['severity']] ?? 3) : 9, $a, $st];
    }
}
usort($rows, fn($x, $y) => [$x[0], $x[1]['name']] <=> [$y[0], $y[1]['name']]);

page_start($pp['title']);
echo '<header class="mb-3 pb-2 border-bottom"><p class="app-title fw-bold mb-0">' . h((string)cfg('app.title', 'Status')) . '</p></header>';
echo '<h1 class="h4 mb-2">' . h($pp['title']) . '</h1>';
if ($pp['intro'] !== '') {
    echo '<p>' . h($pp['intro']) . '</p>';
}
if (!array_filter($rows, fn($r) => $r[2] !== null)) {
    echo '<section class="card shadow-sm mb-3 status-card sev-ok"><div class="card-body"><p class="mb-0">Derzeit liegen keine Meldungen zu unseren Anwendungen vor.</p></div></section>';
}
$texts = [];
if ($rows) {
    echo '<ul class="list-group mb-3">';
    foreach ($rows as [, $a, $st]) {
        echo '<li class="list-group-item app-row' . ($st ? ' sev-' . h($st['severity']) : ' app-ok') . '"><div class="d-flex flex-wrap justify-content-between gap-2">'
            . '<span class="fw-semibold">' . h($a['name']) . ($a['short'] !== '' ? ' <span class="text-body-secondary">(' . h($a['short']) . ')</span>' : '') . '</span>';
        if ($st) {
            $p = $st['payload'];
            $label = (string)($p['public_label'] ?? $p['label']);
            echo '<span class="badge ' . ($st['severity'] === 'critical' ? 'text-bg-danger' : ($st['severity'] === 'warn' ? 'text-bg-warning' : 'text-bg-primary')) . '">' . h($label) . '</span>';
            $texts[(string)($p['public_text'] ?? '')] = true;
            echo '</div><div class="small text-body-secondary">Stand: ' . h(fmt_local((string)$st['created_at'])) . ' Uhr</div>';
        } else {
            echo '<span class="badge text-bg-success">Verfügbar</span></div>';
        }
        echo '</li>';
    }
    echo '</ul>';
}
foreach (array_keys(array_filter($texts)) as $t) {
    echo '<p>' . h($t) . '</p>';
}

/* Kontakt */
$hasContact = $pp['phone'] !== '' || $pp['email'] !== '' || $pp['ticket_url'] !== '';
if ($hasContact) {
    echo '<section class="card shadow-sm mb-3"><div class="card-body"><h2 class="h5">Kontakt</h2>';
    if ($pp['hours'] !== '') {
        echo '<p class="small">Erreichbarkeit: ' . h($pp['hours']) . '</p>';
    }
    if ($reveal) {
        echo '<ul class="list-unstyled mb-0">';
        if ($pp['phone'] !== '') {
            echo '<li>Telefon: <a class="tel" href="' . h(tel_href($pp['phone'])) . '">' . h($pp['phone']) . '</a></li>';
        }
        if ($pp['email'] !== '') {
            echo '<li>E-Mail: <a href="mailto:' . h($pp['email']) . '">' . h($pp['email']) . '</a></li>';
        }
        if ($pp['ticket_url'] !== '') {
            echo '<li><a href="' . h($pp['ticket_url']) . '" rel="nofollow noopener noreferrer">' . h($pp['ticket_label'] ?: 'Ticketsystem') . '</a></li>';
        }
        echo '</ul>';
    } else {
        if ($hint !== '') {
            echo '<div class="alert alert-warning py-2 small" role="alert">' . h($hint) . '</div>';
        }
        echo '<form method="post" action="extern.php"><input type="hidden" name="t" value="' . h(public_reveal_token()) . '">'
            . '<div class="hp" aria-hidden="true"><label>Website<input type="text" name="website" tabindex="-1" autocomplete="off"></label></div>'
            . '<button class="btn btn-outline-primary" type="submit">Kontakt anzeigen</button></form>'
            . '<p class="small text-body-secondary mt-2 mb-0">Die Kontaktdaten werden zum Schutz vor automatischem Auslesen erst auf Klick angezeigt.</p>';
    }
    echo '</div></section>';
}
echo '<p class="small text-body-secondary">Stand der Seite: ' . h(fmt_local(now_utc())) . ' Uhr</p>';
page_end();
