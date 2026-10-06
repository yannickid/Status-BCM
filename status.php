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

page_start('Status', ['refresh' => 60]);
nav('status');
echo '<h1>Aktueller Status</h1>';
render_flash();
render_status_card($row, false);
echo '<p class="muted">Diese Seite aktualisiert sich automatisch.</p>';
page_end();
