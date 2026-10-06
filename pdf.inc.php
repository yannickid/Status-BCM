<?php
/**
 * Minimaler PDF-Schreiber ohne Bibliotheken: Tabellen in Helvetica (Standardschrift, nicht eingebettet),
 * Zeichensatz Windows-1252, A4 quer, mehrseitig mit wiederholtem Tabellenkopf. Genug für Protokoll-Exporte.
 */
declare(strict_types=1);
if (!defined('SBCM')) {
    http_response_code(403);
    exit;
}

/** Zeichenbreiten von Helvetica (1/1000 em) für ASCII 32–126 */
const PDF_HELV_W = [278, 278, 355, 556, 556, 889, 667, 191, 333, 333, 389, 584, 278, 333, 278, 278,
    556, 556, 556, 556, 556, 556, 556, 556, 556, 556, 278, 278, 584, 584, 584, 556,
    1015, 667, 667, 722, 722, 667, 611, 778, 722, 278, 500, 667, 556, 833, 722, 778,
    667, 778, 722, 667, 611, 722, 667, 944, 667, 667, 611, 278, 278, 278, 469, 556,
    333, 556, 556, 500, 556, 556, 278, 556, 556, 222, 222, 500, 222, 833, 556, 556,
    556, 556, 333, 500, 278, 556, 500, 722, 500, 500, 500, 334, 260, 334, 584];

function pdf_enc(string $s): string
{
    $s = preg_replace('/[\x00-\x1F\x7F]+/u', ' ', $s) ?? '';
    $s = strtr($s, ['→' => '->', '–' => '-', '…' => '...', '•' => '-']);
    return (string)mb_convert_encoding($s, 'Windows-1252', 'UTF-8');
}

function pdf_width(string $cp1252, float $size, bool $bold = false): float
{
    $w = 0;
    $len = strlen($cp1252);
    for ($i = 0; $i < $len; $i++) {
        $o = ord($cp1252[$i]);
        $w += ($o >= 32 && $o <= 126) ? PDF_HELV_W[$o - 32] : 556;
    }
    return $w * $size / 1000 * ($bold ? 1.06 : 1.0);
}

/** Bricht Text (cp1252) auf die Breite um; überlange Wörter werden zeichenweise getrennt. */
function pdf_wrap(string $s, float $width, float $size, bool $bold = false): array
{
    $lines = [];
    $cur = '';
    foreach (preg_split('/ +/', $s) ?: [] as $word) {
        $try = $cur === '' ? $word : $cur . ' ' . $word;
        if (pdf_width($try, $size, $bold) <= $width) {
            $cur = $try;
            continue;
        }
        if ($cur !== '') {
            $lines[] = $cur;
        }
        $cur = '';
        while ($word !== '' && pdf_width($word, $size, $bold) > $width) {
            $n = 1;
            while ($n < strlen($word) && pdf_width(substr($word, 0, $n + 1), $size, $bold) <= $width) {
                $n++;
            }
            $lines[] = substr($word, 0, $n);
            $word = substr($word, $n);
        }
        $cur = $word;
    }
    if ($cur !== '' || !$lines) {
        $lines[] = $cur;
    }
    return $lines;
}

function pdf_str(string $cp1252): string
{
    return '(' . strtr($cp1252, ['\\' => '\\\\', '(' => '\\(', ')' => '\\)']) . ')';
}

/**
 * Erzeugt ein PDF mit Titel, Kopfzeilen (Metadaten) und einer Tabelle.
 * $cols: [[Überschrift, Breite in pt], …] (Summe ≤ 786 pt bei A4 quer), $rows: Liste von Zeilen (Strings, UTF-8).
 */
function pdf_table(string $title, array $meta, array $cols, array $rows, string $footer = ''): string
{
    $W = 842.0;
    $H = 595.0;
    $M = 28.0;
    $fs = 7.5;
    $lh = 9.0;
    $pages = [];
    $page = '';
    $y = 0.0;
    $text = function (float $x, float $yy, string $s, bool $bold = false, float $size = 7.5) use (&$page): void {
        $page .= 'BT /' . ($bold ? 'F2' : 'F1') . ' ' . $size . ' Tf ' . round($x, 2) . ' ' . round($yy, 2) . ' Td ' . pdf_str($s) . " Tj ET\n";
    };
    $hline = function (float $yy) use (&$page, $M, $W): void {
        $page .= '0.6 G 0.4 w ' . $M . ' ' . round($yy, 2) . ' m ' . ($W - $M) . ' ' . round($yy, 2) . " l S 0 G\n";
    };
    $newPage = function (bool $first) use (&$pages, &$page, &$y, $title, $meta, $cols, $text, $hline, $H, $M, $lh, $fs, $footer): void {
        if ($page !== '') {
            $pages[] = $page;
        }
        $page = '';
        $y = $H - $M - 12;
        $text($M, $y, pdf_enc($title), true, $first ? 13 : 9);
        $y -= $first ? 16 : 12;
        if ($first) {
            foreach ($meta as $line) {
                $text($M, $y, pdf_enc((string)$line), false, 8);
                $y -= 10;
            }
            $y -= 4;
        }
        $x = $M;
        foreach ($cols as [$head, $w]) {
            $text($x + 2, $y, pdf_enc($head), true, $fs);
            $x += $w;
        }
        $y -= 3;
        $hline($y);
        $y -= $lh;
        $text($M, $M - 14, pdf_enc(trim($footer . '  Seite ' . (count($pages) + 1))), false, 7);
    };
    $newPage(true);
    foreach ($rows as $row) {
        $cells = [];
        $n = 1;
        foreach ($cols as $i => [, $w]) {
            $cells[$i] = array_slice(pdf_wrap(pdf_enc((string)($row[$i] ?? '')), $w - 4, $fs), 0, 40);
            $n = max($n, count($cells[$i]));
        }
        if ($y - ($n - 1) * $lh < $M + 6) {
            $newPage(false);
        }
        $x = $M;
        foreach ($cols as $i => [, $w]) {
            foreach ($cells[$i] as $k => $line) {
                $text($x + 2, $y - $k * $lh, $line, false, $fs);
            }
            $x += $w;
        }
        $y -= ($n - 1) * $lh + 3;
        $hline($y);
        $y -= $lh;
    }
    $pages[] = $page;

    // Objekte: 1 Katalog, 2 Seitenbaum, 3/4 Schriften, danach je Seite Inhalt + Seite
    $objs = [];
    $objs[1] = '<< /Type /Catalog /Pages 2 0 R >>';
    $objs[3] = '<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>';
    $objs[4] = '<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold /Encoding /WinAnsiEncoding >>';
    $kids = [];
    $id = 5;
    foreach ($pages as $content) {
        $objs[$id] = '<< /Length ' . strlen($content) . " >>\nstream\n" . $content . "endstream";
        $objs[$id + 1] = '<< /Type /Page /Parent 2 0 R /MediaBox [0 0 ' . $W . ' ' . $H . '] /Resources << /Font << /F1 3 0 R /F2 4 0 R >> >> /Contents ' . $id . ' 0 R >>';
        $kids[] = ($id + 1) . ' 0 R';
        $id += 2;
    }
    $objs[2] = '<< /Type /Pages /Kids [' . implode(' ', $kids) . '] /Count ' . count($kids) . ' >>';
    $objs[$id] = '<< /Producer ' . pdf_str('Status-BCM') . ' /Title ' . pdf_str(pdf_enc($title))
        . ' /CreationDate ' . pdf_str('D:' . gmdate('YmdHis') . 'Z') . ' >>';
    ksort($objs);
    $out = "%PDF-1.4\n%\xE2\xE3\xCF\xD3\n";
    $off = [];
    foreach ($objs as $n => $o) {
        $off[$n] = strlen($out);
        $out .= $n . " 0 obj\n" . $o . "\nendobj\n";
    }
    $xref = strlen($out);
    $out .= "xref\n0 " . ($id + 1) . "\n0000000000 65535 f \n";
    for ($n = 1; $n <= $id; $n++) {
        $out .= sprintf("%010d 00000 n \n", $off[$n]);
    }
    return $out . "trailer\n<< /Size " . ($id + 1) . ' /Root 1 0 R /Info ' . $id . " 0 R >>\nstartxref\n" . $xref . "\n%%EOF\n";
}
