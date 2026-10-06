<?php
/**
 * PDF-Schreiber ohne Bibliotheken für Protokoll-Exporte: getaggtes PDF nach PDF/UA-1 (ISO 14289-1).
 *  - Strukturbaum: Dokument → Überschrift (H1), Absätze (P), Tabelle (THead/TBody, TR, TH mit Scope, TD)
 *  - Lesereihenfolge = Strukturbaum; Linien, Seitenzahlen und wiederholte Kopfzeilen sind Artefakte
 *  - Sprache de-DE, Titel in Info und XMP, Titel statt Dateiname in der Fensterleiste
 *  - Schrift Liberation Sans (SIL OFL, assets/fonts), eingebettet, Zeichensatz Windows-1252
 * A4 quer, mehrseitig. Zeichen außerhalb von Windows-1252 werden als "?" ausgegeben.
 */
declare(strict_types=1);
if (!defined('SBCM')) {
    http_response_code(403);
    exit;
}

const PDF_FONT_DIR = __DIR__ . '/assets/fonts';

/** Liest aus einer TrueType-Datei, was ein eingebetteter einfacher Font braucht (Breiten für Windows-1252, Maße). */
function pdf_font(bool $bold): array
{
    static $cache = [];
    if (isset($cache[$bold])) {
        return $cache[$bold];
    }
    $file = PDF_FONT_DIR . '/LiberationSans-' . ($bold ? 'Bold' : 'Regular') . '.ttf';
    $d = @file_get_contents($file);
    if ($d === false) {
        throw new RuntimeException('Schriftdatei fehlt: ' . $file);
    }
    $u16 = fn(int $o) => unpack('n', $d, $o)[1];
    $s16 = fn(int $o) => ($v = unpack('n', $d, $o)[1]) >= 0x8000 ? $v - 0x10000 : $v;
    $u32 = fn(int $o) => unpack('N', $d, $o)[1];
    $tab = [];
    for ($i = 0, $n = $u16(4); $i < $n; $i++) {
        $tab[substr($d, 12 + 16 * $i, 4)] = $u32(12 + 16 * $i + 8);
    }
    foreach (['head', 'hhea', 'hmtx', 'cmap', 'OS/2', 'post'] as $t) {
        if (!isset($tab[$t])) {
            throw new RuntimeException('Schriftdatei unvollständig: ' . $t);
        }
    }
    $upm = $u16($tab['head'] + 18);
    $sc = fn(int $v) => (int)round($v * 1000 / $upm);
    $bbox = [$sc($s16($tab['head'] + 36)), $sc($s16($tab['head'] + 38)), $sc($s16($tab['head'] + 40)), $sc($s16($tab['head'] + 42))];
    $nh = $u16($tab['hhea'] + 34);
    $adv = fn(int $g) => $u16($tab['hmtx'] + 4 * min($g, $nh - 1));
    // cmap Format 4 (Plattform 3, Kodierung 1)
    $sub = null;
    for ($i = 0, $n = $u16($tab['cmap'] + 2); $i < $n; $i++) {
        $o = $tab['cmap'] + 4 + 8 * $i;
        if ($u16($o) === 3 && $u16($o + 2) === 1) {
            $sub = $tab['cmap'] + $u32($o + 4);
        }
    }
    if ($sub === null || $u16($sub) !== 4) {
        throw new RuntimeException('Schriftdatei ohne Unicode-Tabelle');
    }
    $seg = $u16($sub + 6) / 2;
    $glyph = function (int $cp) use ($u16, $sub, $seg): int {
        for ($i = 0; $i < $seg; $i++) {
            $end = $u16($sub + 14 + 2 * $i);
            if ($cp > $end) {
                continue;
            }
            $start = $u16($sub + 16 + 2 * $seg + 2 * $i);
            if ($cp < $start) {
                return 0;
            }
            $delta = $u16($sub + 16 + 4 * $seg + 2 * $i);
            $roOff = $sub + 16 + 6 * $seg + 2 * $i;
            $ro = $u16($roOff);
            if ($ro === 0) {
                return ($cp + $delta) & 0xFFFF;
            }
            $g = $u16($roOff + $ro + 2 * ($cp - $start));
            return $g === 0 ? 0 : ($g + $delta) & 0xFFFF;
        }
        return 0;
    };
    $w = [];
    for ($c = 32; $c <= 255; $c++) {
        $u = mb_convert_encoding(chr($c), 'UTF-8', 'Windows-1252');
        $cp = ($u === '' || $u === '?') && $c !== 63 ? 0 : mb_ord($u, 'UTF-8');
        $w[$c] = $sc($adv($cp ? $glyph((int)$cp) : 0));
    }
    $post = $tab['post'];
    return $cache[$bold] = [
        'name' => $bold ? 'LiberationSans-Bold' : 'LiberationSans',
        'data' => $d, 'w' => $w, 'bbox' => $bbox,
        'ascent' => $sc($s16($tab['hhea'] + 4)), 'descent' => $sc($s16($tab['hhea'] + 6)),
        'cap' => $u16($tab['OS/2']) >= 2 ? $sc($s16($tab['OS/2'] + 88)) : $sc($s16($tab['hhea'] + 4)),
        'italic' => $s16($post + 4), 'stemv' => $bold ? 140 : 80,
    ];
}

function pdf_enc(string $s): string
{
    $s = preg_replace('/[\x00-\x1F\x7F]+/u', ' ', $s) ?? '';
    $s = strtr($s, ['→' => '->', '…' => '...', '•' => '-']);
    return (string)mb_convert_encoding($s, 'Windows-1252', 'UTF-8');
}

function pdf_width(string $cp1252, float $size, bool $bold = false): float
{
    $fw = pdf_font($bold)['w'];
    $w = 0;
    $len = strlen($cp1252);
    for ($i = 0; $i < $len; $i++) {
        $w += $fw[ord($cp1252[$i])] ?? 556;
    }
    return $w * $size / 1000;
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
    return '(' . strtr($cp1252, ['\\' => '\\\\', '(' => '\\(', ')' => '\\)', "\r" => '\\r']) . ')';
}

/** Textstring für Info/Struktur: UTF-16BE mit BOM (beliebige Unicode-Zeichen) */
function pdf_ustr(string $utf8): string
{
    return '<FEFF' . strtoupper(bin2hex((string)mb_convert_encoding($utf8, 'UTF-16BE', 'UTF-8'))) . '>';
}

function pdf_stream(string $dict, string $data): string
{
    if (function_exists('gzcompress')) {
        $data = (string)gzcompress($data, 6);
        $dict .= ' /Filter /FlateDecode';
    }
    return '<< ' . $dict . ' /Length ' . strlen($data) . " >>\nstream\n" . $data . "\nendstream";
}

/**
 * Erzeugt ein getaggtes PDF mit Titel (H1), Metadaten-Absätzen (P) und einer Tabelle.
 * $cols: [[Überschrift, Breite in pt], …] (Summe ≤ 786 pt bei A4 quer), $rows: Liste von Zeilen (Strings, UTF-8).
 */
function pdf_table(string $title, array $meta, array $cols, array $rows, string $footer = ''): string
{
    $W = 842.0;
    $H = 595.0;
    $M = 28.0;
    $fs = 7.5;
    $lh = 9.0;
    $pages = [];    // je Seite: ['c' => Inhalt, 'mcid' => [MCID => Struktur-Schlüssel]]
    $page = '';
    $mc = [];
    $elems = [];    // Struktur-Schlüssel => ['type', 'parent', 'page', 'mcid' => [], 'attr' => '']
    $y = 0.0;
    $tj = function (float $x, float $yy, string $s, bool $bold, float $size): string {
        return 'BT /' . ($bold ? 'F2' : 'F1') . ' ' . $size . ' Tf ' . round($x, 2) . ' ' . round($yy, 2) . ' Td ' . pdf_str($s) . " Tj ET\n";
    };
    // Inhalt als markierter Inhalt eines Strukturelements
    $tagged = function (string $key, string $ops) use (&$page, &$mc, &$elems, &$pages): void {
        $id = count($mc);
        $mc[$id] = $key;
        $elems[$key]['mcid'][] = [count($pages), $id];
        $page .= '/' . $elems[$key]['type'] . ' << /MCID ' . $id . " >> BDC\n" . $ops . "EMC\n";
    };
    $artifact = function (string $ops, string $kind = '') use (&$page): void {
        $page .= ($kind !== '' ? '/Artifact << /Type /Pagination /Subtype /' . $kind . ' >> BDC' : '/Artifact BMC') . "\n" . $ops . "EMC\n";
    };
    $el = function (string $key, string $type, ?string $parent, string $attr = '') use (&$elems): void {
        $elems[$key] = ['type' => $type, 'parent' => $parent, 'mcid' => [], 'attr' => $attr, 'kids' => []];
        if ($parent !== null) {
            $elems[$parent]['kids'][] = $key;
        }
    };
    $hline = function (float $yy) use ($artifact, $M, $W): void {
        $artifact('0.6 G 0.4 w ' . $M . ' ' . round($yy, 2) . ' m ' . ($W - $M) . ' ' . round($yy, 2) . " l S 0 G\n");
    };
    $el('doc', 'Document', null);
    $el('h1', 'H1', 'doc');
    foreach ($meta as $i => $_) {
        $el('p' . $i, 'P', 'doc');
    }
    $el('table', 'Table', 'doc');
    $el('thead', 'THead', 'table');
    $el('tbody', 'TBody', 'table');
    $el('hr', 'TR', 'thead');
    foreach ($cols as $i => $_) {
        $el('th' . $i, 'TH', 'hr', '/A << /O /Table /Scope /Column >>');
    }

    $newPage = function (bool $first) use (&$pages, &$page, &$mc, &$y, $title, $meta, $cols, $tj, $tagged, $artifact, $hline, $H, $M, $lh, $fs, $footer): void {
        if ($page !== '') {
            $pages[] = ['c' => $page, 'mcid' => $mc];
        }
        $page = '';
        $mc = [];
        $y = $H - $M - 12;
        if ($first) {
            $tagged('h1', $tj($M, $y, pdf_enc($title), true, 13));
            $y -= 16;
            foreach ($meta as $i => $line) {
                $tagged('p' . $i, $tj($M, $y, pdf_enc((string)$line), false, 8));
                $y -= 10;
            }
            $y -= 4;
        } else {
            $artifact($tj($M, $y, pdf_enc($title), true, 9), 'Header');
            $y -= 12;
        }
        $x = $M;
        foreach ($cols as $i => [$head, $w]) {
            $ops = $tj($x + 2, $y, pdf_enc($head), true, $fs);
            $first ? $tagged('th' . $i, $ops) : $artifact($ops, 'Header');
            $x += $w;
        }
        $y -= 3;
        $hline($y);
        $y -= $lh;
        $artifact($tj($M, $M - 14, pdf_enc(trim($footer . '  Seite ' . (count($pages) + 1))), false, 7), 'Footer');
    };
    $newPage(true);
    foreach ($rows as $r => $row) {
        $cells = [];
        $n = 1;
        foreach ($cols as $i => [, $w]) {
            $cells[$i] = array_slice(pdf_wrap(pdf_enc((string)($row[$i] ?? '')), $w - 4, $fs), 0, 40);
            $n = max($n, count($cells[$i]));
        }
        if ($y - ($n - 1) * $lh < $M + 6) {
            $newPage(false);
        }
        $el('r' . $r, 'TR', 'tbody');
        $x = $M;
        foreach ($cols as $i => [, $w]) {
            $el('r' . $r . 'c' . $i, 'TD', 'r' . $r);
            $ops = '';
            $last = count($cells[$i]) - 1;
            foreach ($cells[$i] as $k => $line) {
                // Leerzeichen am Zeilenende, damit Vorlese- und Kopierfunktionen umbrochene Wörter trennen
                $ops .= $line === '' ? '' : $tj($x + 2, $y - $k * $lh, $line . ($k < $last ? ' ' : ''), false, $fs);
            }
            if ($ops !== '') {
                $tagged('r' . $r . 'c' . $i, $ops);
            }
            $x += $w;
        }
        $y -= ($n - 1) * $lh + 3;
        $hline($y);
        $y -= $lh;
    }
    $pages[] = ['c' => $page, 'mcid' => $mc];

    // Objektnummern: 1 Katalog, 2 Seitenbaum, 3–8 Schriften, 9 Metadaten, 10 Strukturwurzel, 11 ParentTree, 12 Info
    $objs = [];
    $next = 13;
    $pageObj = [];
    foreach ($pages as $p => $_) {
        $pageObj[$p] = $next++;
        $next++;    // Inhalt
    }
    $elObj = [];
    foreach (array_keys($elems) as $k) {
        $elObj[$k] = $next++;
    }

    foreach ([false, true] as $bold) {
        $f = pdf_font($bold);
        $base = $bold ? 6 : 3;  // Font, Deskriptor, Datei
        $objs[$base] = '<< /Type /Font /Subtype /TrueType /BaseFont /' . $f['name'] . ' /FirstChar 32 /LastChar 255 /Widths ['
            . implode(' ', $f['w']) . '] /Encoding /WinAnsiEncoding /FontDescriptor ' . ($base + 1) . ' 0 R >>';
        $objs[$base + 1] = '<< /Type /FontDescriptor /FontName /' . $f['name'] . ' /Flags 32 /FontBBox [' . implode(' ', $f['bbox']) . ']'
            . ' /ItalicAngle ' . $f['italic'] . ' /Ascent ' . $f['ascent'] . ' /Descent ' . $f['descent'] . ' /CapHeight ' . $f['cap']
            . ' /StemV ' . $f['stemv'] . ($bold ? ' /FontWeight 700' : ' /FontWeight 400') . ' /FontFile2 ' . ($base + 2) . ' 0 R >>';
        $objs[$base + 2] = pdf_stream('/Length1 ' . strlen($f['data']), $f['data']);
    }

    $kids = [];
    $parentNums = [];
    foreach ($pages as $p => $pg) {
        $po = $pageObj[$p];
        $objs[$po + 1] = pdf_stream('', $pg['c']);
        $objs[$po] = '<< /Type /Page /Parent 2 0 R /MediaBox [0 0 ' . $W . ' ' . $H . '] /Resources << /Font << /F1 3 0 R /F2 6 0 R >> >>'
            . ' /Contents ' . ($po + 1) . ' 0 R /StructParents ' . $p . ' /Tabs /S >>';
        $kids[] = $po . ' 0 R';
        $parentNums[] = $p . ' [' . implode(' ', array_map(fn($k) => $elObj[$k] . ' 0 R', $pg['mcid'])) . ']';
    }
    foreach ($elems as $k => $e) {
        $kidRefs = [];
        $pg = null;
        foreach ($e['mcid'] as [$p, $id]) {
            $kidRefs[] = '<< /Type /MCR /Pg ' . $pageObj[$p] . ' 0 R /MCID ' . $id . ' >>';
            $pg ??= $p;
        }
        foreach ($e['kids'] as $c) {
            $kidRefs[] = $elObj[$c] . ' 0 R';
        }
        $objs[$elObj[$k]] = '<< /Type /StructElem /S /' . $e['type'] . ' /P ' . ($e['parent'] === null ? 10 : $elObj[$e['parent']]) . ' 0 R'
            . ($k === 'doc' ? ' /Lang (de-DE)' : '') . ($k === 'h1' ? ' /T ' . pdf_ustr($title) : '')
            . ($e['attr'] !== '' ? ' ' . $e['attr'] : '') . ($pg !== null ? ' /Pg ' . $pageObj[$pg] . ' 0 R' : '')
            . ' /K [' . implode(' ', $kidRefs) . '] >>';
    }
    $objs[10] = '<< /Type /StructTreeRoot /K [' . $elObj['doc'] . ' 0 R] /ParentTree 11 0 R /ParentTreeNextKey ' . count($pages) . ' >>';
    $objs[11] = '<< /Nums [' . implode(' ', $parentNums) . '] >>';

    $now = gmdate('Y-m-d\TH:i:s\Z');
    $x = static fn(string $s) => htmlspecialchars($s, ENT_XML1 | ENT_QUOTES, 'UTF-8');
    $xmp = '<?xpacket begin="' . "\u{FEFF}" . '" id="W5M0MpCehiHzreSzNTczkc9d"?>' . "\n"
        . '<x:xmpmeta xmlns:x="adobe:ns:meta/"><rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#">'
        . '<rdf:Description rdf:about="" xmlns:dc="http://purl.org/dc/elements/1.1/" xmlns:pdf="http://ns.adobe.com/pdf/1.3/"'
        . ' xmlns:xmp="http://ns.adobe.com/xap/1.0/" xmlns:pdfuaid="http://www.aiim.org/pdfua/ns/id/">'
        . '<dc:format>application/pdf</dc:format>'
        . '<dc:title><rdf:Alt><rdf:li xml:lang="x-default">' . $x($title) . '</rdf:li></rdf:Alt></dc:title>'
        . '<dc:language><rdf:Bag><rdf:li>de-DE</rdf:li></rdf:Bag></dc:language>'
        . '<pdf:Producer>Status-BCM</pdf:Producer><xmp:CreateDate>' . $now . '</xmp:CreateDate><xmp:CreatorTool>Status-BCM</xmp:CreatorTool>'
        . '<pdfuaid:part>1</pdfuaid:part></rdf:Description></rdf:RDF></x:xmpmeta>' . "\n" . '<?xpacket end="w"?>';
    $objs[9] = '<< /Type /Metadata /Subtype /XML /Length ' . strlen($xmp) . " >>\nstream\n" . $xmp . "\nendstream";
    $objs[1] = '<< /Type /Catalog /Pages 2 0 R /Lang (de-DE) /MarkInfo << /Marked true >> /StructTreeRoot 10 0 R /Metadata 9 0 R'
        . ' /ViewerPreferences << /DisplayDocTitle true >> >>';
    $objs[2] = '<< /Type /Pages /Kids [' . implode(' ', $kids) . '] /Count ' . count($kids) . ' >>';
    $objs[12] = '<< /Producer (Status-BCM) /Creator (Status-BCM) /Title ' . pdf_ustr($title)
        . ' /CreationDate (D:' . gmdate('YmdHis') . "Z) >>";
    ksort($objs);
    $out = "%PDF-1.7\n%\xE2\xE3\xCF\xD3\n";
    $off = [];
    foreach ($objs as $n => $o) {
        $off[$n] = strlen($out);
        $out .= $n . " 0 obj\n" . $o . "\nendobj\n";
    }
    $size = max(array_keys($objs)) + 1;
    $xref = strlen($out);
    $out .= "xref\n0 " . $size . "\n0000000000 65535 f \n";
    for ($n = 1; $n < $size; $n++) {
        $out .= sprintf("%010d 00000 n \n", $off[$n]);
    }
    $fid = bin2hex(random_bytes(16));
    return $out . "trailer\n<< /Size " . $size . ' /Root 1 0 R /Info 12 0 R /ID [<' . $fid . '> <' . $fid . ">] >>\nstartxref\n" . $xref . "\n%%EOF\n";
}
