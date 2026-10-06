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

monitor_tick();
$board = status_board();
foreach ($board['live'] as $r) {
    view_count((int)$r['id']); // anonym: einmal je Sitzung und Meldung
}

// Automatische Aktualisierung abschaltbar (WCAG 2.2.1/2.2.2: Screenreader verlieren sonst alle 2 Minuten die Position)
if (isset($_GET['auto'])) {
    $_SESSION['no_refresh'] = $_GET['auto'] === '0';
}
$auto = empty($_SESSION['no_refresh']);
page_start('Status', $auto ? ['refresh' => 120] : []);
nav('status');
echo '<h1 class="visually-hidden">Aktuelle Meldungen</h1>';
// Hinweis vor den Meldungen, damit er vor der nächsten Aktualisierung erreichbar ist
echo '<p class="small text-body-secondary">' . ($auto
    ? 'Diese Seite aktualisiert sich alle 2 Minuten. <a href="status.php?auto=0">Automatische Aktualisierung ausschalten</a>'
    : 'Automatische Aktualisierung ist aus. <a href="status.php">Seite neu laden</a> · <a href="status.php?auto=1">Wieder einschalten</a>') . '</p>';
render_flash();
render_board($board, false);
page_end();
