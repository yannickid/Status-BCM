<?php
/**
 * Status-BCM – minimaler QR-Code-Erzeuger (ISO/IEC 18004), nur für die Kopplung der Authenticator-App.
 * Byte-Modus, Fehlerkorrektur M, Versionen 1–10 (bis 213 Byte). Ausgabe als SVG, ohne JavaScript und ohne
 * externe Dienste: Das TOTP-Secret verlässt den Server nicht.
 * Aufbau angelehnt an den QR-Code-Generator von Project Nayuki (MIT-Lizenz).
 */
declare(strict_types=1);

if (!defined('SBCM')) {
    http_response_code(403);
    exit;
}

/** Version => [EC-Codewörter je Block, [[Blöcke, Datencodewörter je Block], ...]] für Stufe M */
const SBCM_QR_M = [
    1 => [10, [[1, 16]]], 2 => [16, [[1, 28]]], 3 => [26, [[1, 44]]], 4 => [18, [[2, 32]]], 5 => [24, [[2, 43]]],
    6 => [16, [[4, 27]]], 7 => [18, [[4, 31]]], 8 => [22, [[2, 38], [2, 39]]], 9 => [22, [[3, 36], [2, 37]]],
    10 => [26, [[4, 43], [1, 44]]],
];
const SBCM_QR_ALIGN = [1 => [], 2 => [6, 18], 3 => [6, 22], 4 => [6, 26], 5 => [6, 30], 6 => [6, 34], 7 => [6, 22, 38],
    8 => [6, 24, 42], 9 => [6, 26, 46], 10 => [6, 28, 50]];

/** Liefert die Modulmatrix (true = dunkel) oder wirft bei zu langen Daten. */
function qr_matrix(string $data): array
{
    $len = strlen($data);
    $ver = 0;
    foreach (SBCM_QR_M as $v => [$ec, $groups]) {
        $cap = 0;
        foreach ($groups as [$n, $k]) {
            $cap += $n * $k;
        }
        if (4 + ($v < 10 ? 8 : 16) + 8 * $len <= 8 * $cap) {
            $ver = $v;
            break;
        }
    }
    if ($ver === 0) {
        throw new InvalidArgumentException('QR-Daten zu lang');
    }
    [$ecLen, $groups] = SBCM_QR_M[$ver];
    $capBytes = 0;
    foreach ($groups as [$n, $k]) {
        $capBytes += $n * $k;
    }

    // Bitstrom: Modus 0100 (Byte), Länge, Daten, Terminator, Auffüllen
    $bits = '0100' . str_pad(decbin($len), $ver < 10 ? 8 : 16, '0', STR_PAD_LEFT);
    for ($i = 0; $i < $len; $i++) {
        $bits .= str_pad(decbin(ord($data[$i])), 8, '0', STR_PAD_LEFT);
    }
    $bits .= str_repeat('0', min(4, 8 * $capBytes - strlen($bits)));
    $bits .= str_repeat('0', (8 - strlen($bits) % 8) % 8);
    $cw = array_map('bindec', str_split($bits, 8));
    for ($pad = 0xEC; count($cw) < $capBytes; $pad ^= 0xEC ^ 0x11) {
        $cw[] = $pad;
    }

    // Blöcke + Reed-Solomon, dann verschränken
    $div = qr_rs_divisor($ecLen);
    $blocks = [];
    $off = 0;
    foreach ($groups as [$n, $k]) {
        for ($b = 0; $b < $n; $b++) {
            $d = array_slice($cw, $off, $k);
            $off += $k;
            $blocks[] = [$d, qr_rs_remainder($d, $div)];
        }
    }
    $final = [];
    $maxK = max(array_map(fn($b) => count($b[0]), $blocks));
    for ($i = 0; $i < $maxK; $i++) {
        foreach ($blocks as [$d]) {
            if ($i < count($d)) {
                $final[] = $d[$i];
            }
        }
    }
    for ($i = 0; $i < $ecLen; $i++) {
        foreach ($blocks as [, $e]) {
            $final[] = $e[$i];
        }
    }

    // Funktionsmuster
    $size = 4 * $ver + 17;
    $m = array_fill(0, $size, array_fill(0, $size, false));
    $fn = $m;
    $set = function (int $x, int $y, bool $dark) use (&$m, &$fn): void {
        $m[$y][$x] = $dark;
        $fn[$y][$x] = true;
    };
    for ($i = 0; $i < $size; $i++) {
        $set(6, $i, $i % 2 === 0);
        $set($i, 6, $i % 2 === 0);
    }
    foreach ([[3, 3], [$size - 4, 3], [3, $size - 4]] as [$cx, $cy]) {
        for ($dy = -4; $dy <= 4; $dy++) {
            for ($dx = -4; $dx <= 4; $dx++) {
                $x = $cx + $dx;
                $y = $cy + $dy;
                if ($x >= 0 && $x < $size && $y >= 0 && $y < $size) {
                    $dist = max(abs($dx), abs($dy));
                    $set($x, $y, $dist !== 2 && $dist !== 4);
                }
            }
        }
    }
    $al = SBCM_QR_ALIGN[$ver];
    $na = count($al);
    for ($i = 0; $i < $na; $i++) {
        for ($j = 0; $j < $na; $j++) {
            if (($i === 0 && $j === 0) || ($i === 0 && $j === $na - 1) || ($i === $na - 1 && $j === 0)) {
                continue;
            }
            for ($dy = -2; $dy <= 2; $dy++) {
                for ($dx = -2; $dx <= 2; $dx++) {
                    $set($al[$i] + $dx, $al[$j] + $dy, max(abs($dx), abs($dy)) !== 1);
                }
            }
        }
    }
    qr_format_bits($set, $size, 0);
    if ($ver >= 7) {
        $rem = $ver;
        for ($i = 0; $i < 12; $i++) {
            $rem = ($rem << 1) ^ (($rem >> 11) * 0x1F25);
        }
        $vb = ($ver << 12) | $rem;
        for ($i = 0; $i < 18; $i++) {
            $bit = (($vb >> $i) & 1) === 1;
            $a = $size - 11 + $i % 3;
            $b = intdiv($i, 3);
            $set($a, $b, $bit);
            $set($b, $a, $bit);
        }
    }

    // Daten im Zickzack platzieren
    $i = 0;
    $total = count($final) * 8;
    for ($right = $size - 1; $right >= 1; $right -= 2) {
        if ($right === 6) {
            $right = 5;
        }
        for ($vert = 0; $vert < $size; $vert++) {
            for ($j = 0; $j < 2; $j++) {
                $x = $right - $j;
                $y = (($right + 1) & 2) === 0 ? $size - 1 - $vert : $vert;
                if (!$fn[$y][$x] && $i < $total) {
                    $m[$y][$x] = (($final[$i >> 3] >> (7 - ($i & 7))) & 1) === 1;
                    $i++;
                }
            }
        }
    }

    // Maske mit geringster Strafpunktzahl wählen
    $best = null;
    $bestScore = PHP_INT_MAX;
    for ($mask = 0; $mask < 8; $mask++) {
        $t = $m;
        for ($y = 0; $y < $size; $y++) {
            for ($x = 0; $x < $size; $x++) {
                if (!$fn[$y][$x] && qr_mask_bit($mask, $x, $y)) {
                    $t[$y][$x] = !$t[$y][$x];
                }
            }
        }
        $setT = function (int $x, int $y, bool $dark) use (&$t): void {
            $t[$y][$x] = $dark;
        };
        qr_format_bits($setT, $size, $mask);
        $score = qr_penalty($t, $size);
        if ($score < $bestScore) {
            $bestScore = $score;
            $best = $t;
        }
    }
    return $best;
}

function qr_format_bits(callable $set, int $size, int $mask): void
{
    $data = (0 << 3) | $mask; // Stufe M = 00
    $rem = $data;
    for ($i = 0; $i < 10; $i++) {
        $rem = ($rem << 1) ^ (($rem >> 9) * 0x537);
    }
    $bits = (($data << 10) | $rem) ^ 0x5412;
    $g = fn(int $i): bool => (($bits >> $i) & 1) === 1;
    for ($i = 0; $i <= 5; $i++) {
        $set(8, $i, $g($i));
    }
    $set(8, 7, $g(6));
    $set(8, 8, $g(7));
    $set(7, 8, $g(8));
    for ($i = 9; $i < 15; $i++) {
        $set(14 - $i, 8, $g($i));
    }
    for ($i = 0; $i < 8; $i++) {
        $set($size - 1 - $i, 8, $g($i));
    }
    for ($i = 8; $i < 15; $i++) {
        $set(8, $size - 15 + $i, $g($i));
    }
    $set(8, $size - 8, true);
}

function qr_mask_bit(int $mask, int $x, int $y): bool
{
    switch ($mask) {
        case 0: return ($x + $y) % 2 === 0;
        case 1: return $y % 2 === 0;
        case 2: return $x % 3 === 0;
        case 3: return ($x + $y) % 3 === 0;
        case 4: return (intdiv($x, 3) + intdiv($y, 2)) % 2 === 0;
        case 5: return ($x * $y) % 2 + ($x * $y) % 3 === 0;
        case 6: return (($x * $y) % 2 + ($x * $y) % 3) % 2 === 0;
        default: return (($x + $y) % 2 + ($x * $y) % 3) % 2 === 0;
    }
}

function qr_penalty(array $t, int $size): int
{
    $score = 0;
    $dark = 0;
    $lines = [];
    for ($y = 0; $y < $size; $y++) {
        $row = '';
        $col = '';
        for ($x = 0; $x < $size; $x++) {
            $row .= $t[$y][$x] ? '1' : '0';
            $col .= $t[$x][$y] ? '1' : '0';
            $dark += $t[$y][$x] ? 1 : 0;
            if ($x < $size - 1 && $y < $size - 1 && $t[$y][$x] === $t[$y][$x + 1] && $t[$y][$x] === $t[$y + 1][$x] && $t[$y][$x] === $t[$y + 1][$x + 1]) {
                $score += 3;
            }
        }
        $lines[] = $row;
        $lines[] = $col;
    }
    foreach ($lines as $l) {
        if (preg_match_all('/0{5,}|1{5,}/', $l, $mm)) {
            foreach ($mm[0] as $run) {
                $score += 3 + strlen($run) - 5;
            }
        }
        $score += 40 * (substr_count('0000' . $l . '0000', '10111010000') + substr_count('0000' . $l . '0000', '00001011101'));
    }
    $score += 10 * intdiv(abs($dark * 20 - $size * $size * 10), $size * $size);
    return $score;
}

function qr_gf_mul(int $x, int $y): int
{
    $z = 0;
    for ($i = 7; $i >= 0; $i--) {
        $z = ($z << 1) ^ (($z >> 7) * 0x11D);
        $z ^= (($y >> $i) & 1) * $x;
    }
    return $z;
}

function qr_rs_divisor(int $degree): array
{
    $r = array_fill(0, $degree, 0);
    $r[$degree - 1] = 1;
    $root = 1;
    for ($i = 0; $i < $degree; $i++) {
        for ($j = 0; $j < $degree; $j++) {
            $r[$j] = qr_gf_mul($r[$j], $root);
            if ($j + 1 < $degree) {
                $r[$j] ^= $r[$j + 1];
            }
        }
        $root = qr_gf_mul($root, 0x02);
    }
    return $r;
}

function qr_rs_remainder(array $data, array $div): array
{
    $r = array_fill(0, count($div), 0);
    foreach ($data as $b) {
        $f = $b ^ array_shift($r);
        $r[] = 0;
        foreach ($div as $i => $c) {
            $r[$i] ^= qr_gf_mul($c, $f);
        }
    }
    return $r;
}

/** QR-Code als SVG-Daten-URI (für <img src>, erlaubt durch die CSP img-src data:). */
function qr_svg_data_uri(string $data): string
{
    $m = qr_matrix($data);
    $size = count($m);
    $q = 4;
    $path = '';
    foreach ($m as $y => $row) {
        foreach ($row as $x => $dark) {
            if ($dark) {
                $path .= 'M' . ($x + $q) . ' ' . ($y + $q) . 'h1v1h-1z';
            }
        }
    }
    $n = $size + 2 * $q;
    $svg = '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ' . $n . ' ' . $n . '" shape-rendering="crispEdges">'
        . '<rect width="' . $n . '" height="' . $n . '" fill="#fff"/><path d="' . $path . '" fill="#000"/></svg>';
    return 'data:image/svg+xml;base64,' . base64_encode($svg);
}
