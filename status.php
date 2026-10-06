<?php
/**
 * Aktuelle Meldungen – nach Login Stufe 1. Mehrere Meldungen gleichzeitig möglich; abgelaufene bzw. beendete bleiben
 * 48 Stunden ausgegraut sichtbar.
 */
declare(strict_types=1);
define('SBCM', true);
require __DIR__ . '/lib.inc.php';
bootstrap();

if (!stage1_ok()) {
    redirect('index.php');
}

$board = status_board();
foreach ($board['live'] as $r) {
    view_count((int)$r['id']); // anonym: einmal je Sitzung und Meldung
}

page_start('Status', ['refresh' => 120]);
nav('status');
echo '<h1 class="visually-hidden">Aktuelle Meldungen</h1>';
render_flash();
render_board($board, false);
echo '<p class="small text-body-secondary">Diese Seite aktualisiert sich automatisch alle 2 Minuten.</p>';
page_end();
