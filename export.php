<?php
/**
 * Protokoll-Export (CSV oder PDF) für Revision und Informationssicherheitsbeauftragte.
 * Nur Admins, nur per POST mit CSRF-Token. Jeder Export wird selbst im Audit-Log vermerkt (audit.export)
 * und enthält Prüfergebnis und Kopf-Hash der Protokollkette, damit spätere Exporte vergleichbar sind.
 */
declare(strict_types=1);
define('SBCM', true);
require __DIR__ . '/lib.inc.php';
require __DIR__ . '/pdf.inc.php';
bootstrap();

if (!stage1_ok()) {
    redirect('index.php');
}
$user = stage2_user();
if (!$user || user_needs_setup($user)) {
    redirect('change.php');
}
if ($user['role'] !== 'admin' || ($_SERVER['REQUEST_METHOD'] ?? 'GET') !== 'POST') {
    redirect('system.php');
}
csrf_verify();

$format = ($_POST['format'] ?? '') === 'pdf' ? 'pdf' : 'csv';
$withIp = !empty($_POST['with_ip']);
$from = trim((string)($_POST['from'] ?? ''));
$to = trim((string)($_POST['to'] ?? ''));
$fromUtc = $from !== '' ? local_to_utc($from . 'T00:00') : null;
$toUtc = $to !== '' ? local_to_utc($to . 'T23:59') : null;
if (($from !== '' && $fromUtc === null) || ($to !== '' && $toUtc === null)) {
    flash('err', 'Zeitraum ungültig. Bitte Datum im Format TT.MM.JJJJ wählen.');
    redirect('system.php#export');
}
if ($toUtc !== null) {
    $toUtc = substr($toUtc, 0, 17) . '59';
}
$range = ($from !== '' ? date('d.m.Y', (int)strtotime($from)) : 'Beginn') . ' bis ' . ($to !== '' ? date('d.m.Y', (int)strtotime($to)) : 'heute');

audit('audit.export', 'audit', ['format' => $format, 'range' => $range, 'with_ip' => $withIp]);
$v = audit_verify();

$title = 'Änderungsprotokoll ' . (string)cfg('app.title', 'Status');
$now = (new DateTimeImmutable('now', app_tz()))->format('d.m.Y H:i');
$meta = [
    'Erstellt: ' . $now . ' von ' . $user['id'] . ' · Zeitraum: ' . $range . ' · IP-Adressen: ' . ($withIp ? 'enthalten' : 'entfernt'),
    'Integrität der Protokollkette: ' . ($v['ok'] ? 'OK' : 'FEHLER – ' . (string)$v['error']) . ' · ' . (int)$v['count'] . ' Einträge gesamt',
    'Kopf-Hash (HMAC-SHA256) zum Zeitpunkt des Exports: ' . $v['head'],
    'Version ' . SBCM_VERSION . ' · Zeiten in ' . app_tz()->getName(),
];
$levels = [0 => 'System', 1 => 'Stufe 1', 2 => 'Stufe 2'];
$rows = [];
foreach (audit_range($fromUtc, $toUtc) as $r) {
    $d = (array)$r['details'];
    $ip = (string)($d['_ctx']['ip'] ?? '');
    unset($d['_ctx']);
    $rows[] = [(string)(int)$r['seq'], fmt_local((string)$r['ts']), (string)$r['actor'], $levels[(int)$r['level']] ?? (string)$r['level'],
        (string)$r['action'], audit_describe((string)$r['action'], $d), $withIp ? $ip : '', (string)$r['ts'], (string)$r['object'], (string)$r['hash']];
}

$fname = 'protokoll-' . (new DateTimeImmutable('now', app_tz()))->format('Ymd-Hi');
header('X-Content-Type-Options: nosniff');
header('Cache-Control: no-store');
if ($format === 'pdf') {
    $cols = [['Nr.', 34], ['Zeit', 72], ['Akteur', 80], ['Stufe', 40], ['Beschreibung', $withIp ? 480 : 560]];
    if ($withIp) {
        $cols[] = ['IP', 80];
    }
    $pdfRows = array_map(fn($r) => $withIp ? [$r[0], $r[1], $r[2], $r[3], $r[5], $r[6]] : [$r[0], $r[1], $r[2], $r[3], $r[5]], $rows);
    $pdf = pdf_table($title, $meta, $cols, $pdfRows, $title . ' · Kopf-Hash ' . substr($v['head'], 0, 16) . '…');
    header('Content-Type: application/pdf');
    header('Content-Disposition: attachment; filename="' . $fname . '.pdf"');
    header('Content-Length: ' . strlen($pdf));
    echo $pdf;
    exit;
}

/** CSV-Zelle gegen Formel-Injektion in Tabellenkalkulationen schützen */
function csv_cell(string $s): string
{
    $s = preg_replace('/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]+/u', ' ', $s) ?? '';
    if ($s !== '' && strpbrk($s[0], "=+-@\t\r") !== false) {
        $s = "'" . $s;
    }
    return '"' . str_replace('"', '""', $s) . '"';
}

header('Content-Type: text/csv; charset=utf-8');
header('Content-Disposition: attachment; filename="' . $fname . '.csv"');
$out = "\xEF\xBB\xBF";
foreach ($meta as $m) {
    $out .= csv_cell('# ' . $m) . "\r\n";
}
$out .= implode(';', array_map('csv_cell', ['Nr', 'Zeit (lokal)', 'Akteur', 'Stufe', 'Aktion', 'Beschreibung', 'IP', 'Zeit (UTC)', 'Objekt', 'Hash'])) . "\r\n";
foreach ($rows as $r) {
    $out .= implode(';', array_map('csv_cell', $r)) . "\r\n";
}
echo $out;
