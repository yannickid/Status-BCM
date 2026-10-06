<?php
/**
 * Aktueller Status – nach Login Stufe 1.
 */
declare(strict_types=1);
define('SBCM', true);
require __DIR__ . '/lib.inc.php';
bootstrap();

if (!stage1_ok()) {
    redirect('index.php');
}

$row = status_current();
if ($row) {
    view_count((int)$row['id']); // anonym: einmal je Sitzung und Status
}

page_start('Status', ['refresh' => 120]);
nav('status');
echo '<h1 class="visually-hidden">Aktueller Status</h1>';
render_flash();
render_status_card($row, false);
echo '<p class="small text-body-secondary">Diese Seite aktualisiert sich automatisch alle 2 Minuten.</p>';
page_end();
