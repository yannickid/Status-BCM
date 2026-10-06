<?php
/**
 * Status-BCM – Bibliothek (Konfiguration, Krypto, DB, Audit, Auth, TOTP, SMTP, Cron-Logik).
 * Nicht direkt aufrufbar.
 */
declare(strict_types=1);

if (!defined('SBCM')) {
    http_response_code(403);
    exit;
}

const SBCM_VERSION = '1.0.0';
define('SBCM_ZERO', str_repeat('0', 64));

/* ====================================================================== */
/* Konfiguration                                                          */
/* ====================================================================== */

function cfg(string $path, $default = null)
{
    static $c = null;
    if ($c === null) {
        $c = require __DIR__ . '/config.inc.php';
    }
    $v = $c;
    foreach (explode('.', $path) as $seg) {
        if (!is_array($v) || !array_key_exists($seg, $v)) {
            return $default;
        }
        $v = $v[$seg];
    }
    return $v;
}

function storage_dir(): string
{
    static $d = null;
    if ($d !== null) {
        return $d;
    }
    $d = rtrim((string)cfg('app.storage_dir', __DIR__ . '/storage'), '/');
    if (!is_dir($d)) {
        @mkdir($d, 0700, true);
    }
    $ht = $d . '/.htaccess';
    if (is_dir($d) && !is_file($ht)) {
        @file_put_contents($ht, "Require all denied\n<IfModule !mod_authz_core.c>\nOrder deny,allow\nDeny from all\n</IfModule>\n");
    }
    return $d;
}

/** Status-Katalog aus config.json – validiert und normalisiert. */
function bcm(): array
{
    static $b = null;
    if ($b !== null) {
        return $b;
    }
    $path = (string)cfg('app.json_path', __DIR__ . '/config.json');
    $raw = @file_get_contents($path);
    if ($raw === false) {
        throw new RuntimeException('config.json nicht lesbar');
    }
    $j = json_decode($raw, true, 64, JSON_THROW_ON_ERROR);
    $errs = bcm_validate($j);
    if ($errs) {
        throw new RuntimeException('config.json ungültig: ' . implode('; ', $errs));
    }
    $j['by_key'] = [];
    foreach ($j['statuses'] as $s) {
        $sev = $s['severity'];
        $s['exercise']           = !empty($s['exercise']);
        $s['alarm_mail_allowed'] = $s['alarm_mail_allowed'] ?? ($sev !== 'ok');
        $s['alarm_mail_default'] = $s['alarm_mail_default'] ?? false;
        $s['require_validity']   = $s['require_validity'] ?? ($sev !== 'ok');
        $s['allow_unlimited']    = $s['allow_unlimited'] ?? ($sev === 'ok');
        $s['require_totp']       = $s['require_totp'] ?? in_array($sev, ['warn', 'critical'], true);
        $j['by_key'][$s['key']]  = $s;
    }
    $j['locations_by_id'] = [];
    foreach ($j['locations'] ?? [] as $l) {
        $l['phone'] = trim((string)($l['phone'] ?? ''));
        $j['locations_by_id'][$l['id']] = $l;
    }
    return $b = $j;
}

/** Strukturprüfung der config.json (Fehler = Liste von Texten). */
function bcm_validate($j): array
{
    $e = [];
    if (!is_array($j)) {
        return ['Wurzel ist kein Objekt'];
    }
    if (empty($j['statuses']) || !is_array($j['statuses'])) {
        $e[] = 'statuses fehlt';
        return $e;
    }
    if (trim((string)($j['default_phone'] ?? '')) === '') {
        $e[] = 'default_phone fehlt';
    }
    $sevs = ['ok', 'info', 'warn', 'critical'];
    $keys = [];
    foreach ($j['statuses'] as $i => $s) {
        $k = (string)($s['key'] ?? '');
        if (!preg_match('/^[A-Z0-9_]{2,32}$/', $k)) {
            $e[] = "Status #$i: ungültiger key";
            continue;
        }
        if (isset($keys[$k])) {
            $e[] = "Status $k doppelt";
        }
        $keys[$k] = true;
        if (!in_array($s['severity'] ?? '', $sevs, true)) {
            $e[] = "$k: severity ungültig";
        }
        if (!in_array($s['audience'] ?? '', ['ALLE', 'ALLE_UND_ADRESSLISTE'], true)) {
            $e[] = "$k: audience muss ALLE oder ALLE_UND_ADRESSLISTE sein";
        }
        $label = trim((string)($s['label'] ?? ''));
        $text  = trim((string)($s['text'] ?? ''));
        if ($label === '' || mb_strlen($label) > 60) {
            $e[] = "$k: label leer oder > 60 Zeichen";
        }
        if ($text === '' || mb_strlen($text) > 500) {
            $e[] = "$k: text leer oder > 500 Zeichen";
        }
    }
    $def = (string)($j['default_status'] ?? '');
    if (!isset($keys[$def])) {
        $e[] = 'default_status verweist auf unbekannten Status';
    }
    $ids = [];
    foreach ($j['locations'] ?? [] as $l) {
        $id = (string)($l['id'] ?? '');
        if (!preg_match('/^[a-z0-9_-]{2,32}$/', $id)) {
            $e[] = 'Standort: ungültige id';
            continue;
        }
        if (isset($ids[$id])) {
            $e[] = "Standort $id doppelt";
        }
        $ids[$id] = true;
        if (trim((string)($l['name'] ?? '')) === '') {
            $e[] = "Standort $id: name fehlt";
        }
    }
    foreach ($j['statuses'] as $s) {
        if (($s['audience'] ?? '') === 'ALLE_UND_ADRESSLISTE' && !$ids) {
            $e[] = ($s['key'] ?? '?') . ': Standortliste benötigt, aber keine locations definiert';
        }
    }
    foreach ($j['validity_options_minutes'] ?? [] as $m) {
        if (!is_int($m) || $m < 5) {
            $e[] = 'validity_options_minutes: nur ganze Zahlen >= 5';
        }
    }
    if (empty($j['validity_options_minutes'])) {
        $e[] = 'validity_options_minutes fehlt';
    }
    return $e;
}

/** Kritische Begriffe (aus forbidden_terms), die im Text vorkommen. */
function critical_terms_in(string $text, array $j): array
{
    $v = mb_strtolower($text);
    $hits = [];
    foreach ((array)($j['forbidden_terms'] ?? []) as $t) {
        $t = mb_strtolower(trim((string)$t));
        if ($t !== '' && mb_strpos($v, $t) !== false) {
            $hits[] = $t;
        }
    }
    return $hits;
}

/** Pressetauglichkeit: Warnungen (kritische Begriffe, Länge, Satzende) für Status, Standorte, Mail-Vorlagen. */
function bcm_lint(array $j): array
{
    $w = [];
    foreach ($j['statuses'] ?? [] as $s) {
        foreach (['label', 'text'] as $f) {
            foreach (critical_terms_in((string)($s[$f] ?? ''), $j) as $t) {
                $w[] = ($s['key'] ?? '?') . ".$f enthält kritischen Begriff \"$t\"";
            }
        }
        $text = trim((string)($s['text'] ?? ''));
        if ($text !== '' && !preg_match('/[.!]$/u', $text)) {
            $w[] = ($s['key'] ?? '?') . ': Text endet nicht mit Satzzeichen';
        }
        if (mb_strlen($text) > 320) {
            $w[] = ($s['key'] ?? '?') . ': Text sehr lang (> 320 Zeichen) – kürzer = weniger Angriffsfläche';
        }
    }
    foreach ($j['locations'] ?? [] as $l) {
        foreach (critical_terms_in((string)($l['name'] ?? ''), $j) as $t) {
            $w[] = 'Standort ' . ($l['id'] ?? '?') . " enthält kritischen Begriff \"$t\"";
        }
    }
    foreach ((array)($j['mail_templates'] ?? []) as $name => $tpl) {
        $all = (string)($tpl['subject'] ?? '') . "\n" . implode("\n", (array)($tpl['body'] ?? []));
        foreach (critical_terms_in($all, $j) as $t) {
            $w[] = "Mail-Vorlage $name enthält kritischen Begriff \"$t\"";
        }
    }
    return $w;
}

/* ====================================================================== */
/* Allgemeine Helfer                                                      */
/* ====================================================================== */

function h(?string $s): string
{
    return htmlspecialchars((string)$s, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

function now_utc(): string
{
    return gmdate('Y-m-d H:i:s');
}

function utc_ts(string $s): int
{
    return (int)strtotime($s . ' UTC');
}

function app_tz(): DateTimeZone
{
    return new DateTimeZone((string)cfg('app.timezone', 'Europe/Berlin'));
}

function fmt_local(?string $utc): string
{
    if (!$utc) {
        return '–';
    }
    $d = new DateTimeImmutable($utc, new DateTimeZone('UTC'));
    return $d->setTimezone(app_tz())->format('d.m.Y H:i');
}

/** "2026-10-06T14:30" (datetime-local, App-Zeitzone) -> UTC "Y-m-d H:i:s" */
function local_to_utc(string $local): ?string
{
    $d = DateTimeImmutable::createFromFormat('Y-m-d\TH:i', $local, app_tz());
    $err = DateTimeImmutable::getLastErrors();
    if (!$d || ($err && ($err['warning_count'] > 0 || $err['error_count'] > 0))) {
        return null;
    }
    return $d->setTimezone(new DateTimeZone('UTC'))->format('Y-m-d H:i:s');
}

function json_enc($v): string
{
    return json_encode($v, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR);
}

function mask_email(string $e): string
{
    $p = explode('@', $e, 2);
    if (count($p) !== 2) {
        return '***';
    }
    $dom = explode('.', $p[1]);
    $tld = array_pop($dom);
    $host = implode('.', $dom);
    return mb_substr($p[0], 0, 1) . str_repeat('*', max(2, mb_strlen($p[0]) - 1)) . '@'
        . mb_substr($host, 0, 1) . str_repeat('*', max(2, mb_strlen($host) - 1)) . '.' . $tld;
}

function render_tpl($tpl, array $vars): string
{
    if (is_array($tpl)) {
        $tpl = implode("\n", $tpl);
    }
    $repl = [];
    foreach ($vars as $k => $v) {
        $repl['{' . $k . '}'] = (string)$v;
    }
    $out = strtr((string)$tpl, $repl);
    $out = preg_replace("/\n{3,}/", "\n\n", $out) ?? $out;
    return trim($out) . "\n";
}

function fmt_minutes(int $m): string
{
    if ($m % 1440 === 0) {
        return ($m / 1440) . ' Tag(e)';
    }
    if ($m % 60 === 0) {
        return ($m / 60) . ' Stunde(n)';
    }
    return $m . ' Minuten';
}

function tel_href(string $phone): string
{
    return 'tel:' . preg_replace('/[^0-9+]/', '', $phone);
}

/* ====================================================================== */
/* Kryptografie (AES-256-GCM, HKDF-Teilschlüssel)                         */
/* ====================================================================== */

function master_key(): string
{
    static $k = null;
    if ($k !== null) {
        return $k;
    }
    $bin = base64_decode((string)cfg('security.master_key', ''), true);
    if ($bin === false || strlen($bin) !== 32) {
        throw new RuntimeException('security.master_key fehlt/ungültig – "php setup.php init" ausführen');
    }
    return $k = $bin;
}

function subkey(string $purpose): string
{
    static $cache = [];
    return $cache[$purpose] ??= hash_hkdf('sha256', master_key(), 32, 'status-bcm/v1/' . $purpose);
}

function enc(string $plain, string $context, string $purpose = 'data'): string
{
    $iv = random_bytes(12);
    $tag = '';
    $ct = openssl_encrypt($plain, 'aes-256-gcm', subkey($purpose), OPENSSL_RAW_DATA, $iv, $tag, $context, 16);
    if ($ct === false) {
        throw new RuntimeException('Verschlüsselung fehlgeschlagen');
    }
    return 'v1:' . base64_encode($iv . $tag . $ct);
}

function dec(string $blob, string $context, string $purpose = 'data'): string
{
    if (strncmp($blob, 'v1:', 3) !== 0) {
        throw new RuntimeException('Unbekanntes Verschlüsselungsformat');
    }
    $raw = base64_decode(substr($blob, 3), true);
    if ($raw === false || strlen($raw) < 28) {
        throw new RuntimeException('Beschädigte Daten');
    }
    $pt = openssl_decrypt(substr($raw, 28), 'aes-256-gcm', subkey($purpose), OPENSSL_RAW_DATA,
        substr($raw, 0, 12), substr($raw, 12, 16), $context);
    if ($pt === false) {
        throw new RuntimeException('Entschlüsselung fehlgeschlagen (Schlüssel/Kontext/Manipulation)');
    }
    return $pt;
}

function mac(string $purpose, string $data): string
{
    return hash_hmac('sha256', $data, subkey('mac-' . $purpose));
}

/** Konfigurationswerte dürfen "enc:v1:..." sein. */
function cfg_secret(string $v): string
{
    if (strncmp($v, 'enc:', 4) === 0) {
        return dec(substr($v, 4), 'cfg', 'config');
    }
    return $v;
}

function cfg_encrypt(string $plain): string
{
    return 'enc:' . enc($plain, 'cfg', 'config');
}

/* ====================================================================== */
/* Datenbank                                                              */
/* ====================================================================== */

function t(string $name): string
{
    $p = (string)cfg('db.prefix', 'sbcm_');
    if (!preg_match('/^[A-Za-z0-9_]{0,20}$/', $p)) {
        throw new RuntimeException('db.prefix ungültig');
    }
    return $p . $name;
}

function db(): PDO
{
    static $pdo = null;
    if ($pdo !== null) {
        return $pdo;
    }
    $dsn = str_replace('{storage}', storage_dir(), (string)cfg('db.dsn'));
    $p = new PDO($dsn, (string)cfg('db.user', ''), (string)cfg('db.pass', ''), [
        PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
        PDO::ATTR_EMULATE_PREPARES   => false,
    ]);
    $drv = $p->getAttribute(PDO::ATTR_DRIVER_NAME);
    if ($drv === 'mysql') {
        $p->exec("SET time_zone = '+00:00'");
        $p->exec('SET NAMES utf8mb4');
    } elseif ($drv === 'sqlite') {
        $p->exec('PRAGMA busy_timeout = 5000');
    }
    $pdo = $p;
    if (cfg('db.auto_install', true)) {
        try {
            // jüngste Tabelle prüfen – fehlt sie, werden fehlende Tabellen ergänzt (alles IF NOT EXISTS)
            $pdo->query('SELECT 1 FROM ' . t('view_count') . ' LIMIT 1')->fetchAll();
        } catch (Throwable $e) {
            install_schema($pdo);
        }
    }
    return $pdo;
}

function db_driver(): string
{
    return db()->getAttribute(PDO::ATTR_DRIVER_NAME);
}

function lock_clause(): string
{
    return db_driver() === 'mysql' ? ' FOR UPDATE' : '';
}

function tx(callable $fn)
{
    static $depth = 0;
    $pdo = db();
    if ($depth > 0) {
        return $fn();
    }
    $sqlite = db_driver() === 'sqlite';
    $depth++;
    try {
        $sqlite ? $pdo->exec('BEGIN IMMEDIATE') : $pdo->beginTransaction();
        $r = $fn();
        $sqlite ? $pdo->exec('COMMIT') : $pdo->commit();
        return $r;
    } catch (Throwable $e) {
        try {
            if ($sqlite) {
                $pdo->exec('ROLLBACK');
            } elseif ($pdo->inTransaction()) {
                $pdo->rollBack();
            }
        } catch (Throwable $e2) {
            // ignorieren
        }
        throw $e;
    } finally {
        $depth--;
    }
}

function install_schema(PDO $pdo): void
{
    $drv = $pdo->getAttribute(PDO::ATTR_DRIVER_NAME);
    $s = t('status');
    $a = t('audit');
    $m = t('mail_log');
    $l = t('login_attempt');
    $u = t('totp_used');
    $k = t('kv');
    $vc = t('view_count');

    if ($drv === 'mysql') {
        $tail = ' ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci';
        $sql = [
            "CREATE TABLE IF NOT EXISTS $s (
                id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
                status_key VARCHAR(40) NOT NULL, severity VARCHAR(12) NOT NULL, author VARCHAR(64) NOT NULL,
                created_at CHAR(19) NOT NULL, valid_until CHAR(19) NULL, alarm_mail TINYINT NOT NULL DEFAULT 0,
                audience VARCHAR(24) NOT NULL, state VARCHAR(12) NOT NULL DEFAULT 'active',
                payload_enc MEDIUMTEXT NOT NULL, row_mac CHAR(64) NOT NULL DEFAULT '',
                reminder_count INT NOT NULL DEFAULT 0, last_reminder_at CHAR(19) NULL,
                closed_at CHAR(19) NULL, closed_by VARCHAR(64) NULL,
                PRIMARY KEY (id), KEY idx_state (state), KEY idx_created (created_at)
            )$tail",
            "CREATE TABLE IF NOT EXISTS $a (
                seq BIGINT NOT NULL, ts CHAR(19) NOT NULL, actor VARCHAR(64) NOT NULL, level TINYINT NOT NULL,
                action VARCHAR(48) NOT NULL, object VARCHAR(64) NOT NULL, details_enc MEDIUMTEXT NOT NULL,
                prev_hash CHAR(64) NOT NULL, hash CHAR(64) NOT NULL, PRIMARY KEY (seq)
            )$tail",
            "CREATE TABLE IF NOT EXISTS $m (
                id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT, ts CHAR(19) NOT NULL, status_id BIGINT NULL,
                kind VARCHAR(16) NOT NULL, rcpt_count INT NOT NULL, ok_count INT NOT NULL,
                content_enc MEDIUMTEXT NOT NULL, result_enc MEDIUMTEXT NOT NULL, PRIMARY KEY (id)
            )$tail",
            "CREATE TABLE IF NOT EXISTS $l (
                id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT, ts INT NOT NULL, scope VARCHAR(12) NOT NULL,
                subj CHAR(64) NOT NULL, ip CHAR(64) NOT NULL, ok TINYINT NOT NULL,
                PRIMARY KEY (id), KEY idx_scope_ts (scope, ts)
            )$tail",
            "CREATE TABLE IF NOT EXISTS $u (
                user VARCHAR(64) NOT NULL, step BIGINT NOT NULL, PRIMARY KEY (user, step)
            )$tail",
            "CREATE TABLE IF NOT EXISTS $k (
                k VARCHAR(64) NOT NULL, v TEXT NOT NULL, PRIMARY KEY (k)
            )$tail",
            "CREATE TABLE IF NOT EXISTS $vc (
                status_id BIGINT NOT NULL, day CHAR(10) NOT NULL, n INT NOT NULL DEFAULT 0, PRIMARY KEY (status_id, day)
            )$tail",
        ];
        $triggers = [
            "CREATE TRIGGER {$a}_no_upd BEFORE UPDATE ON $a FOR EACH ROW SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'audit is append-only'",
            "CREATE TRIGGER {$a}_no_del BEFORE DELETE ON $a FOR EACH ROW SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'audit is append-only'",
            "CREATE TRIGGER {$s}_no_del BEFORE DELETE ON $s FOR EACH ROW SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'status history is append-only'",
        ];
    } else {
        $sql = [
            "CREATE TABLE IF NOT EXISTS $s (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                status_key TEXT NOT NULL, severity TEXT NOT NULL, author TEXT NOT NULL,
                created_at TEXT NOT NULL, valid_until TEXT NULL, alarm_mail INTEGER NOT NULL DEFAULT 0,
                audience TEXT NOT NULL, state TEXT NOT NULL DEFAULT 'active',
                payload_enc TEXT NOT NULL, row_mac TEXT NOT NULL DEFAULT '',
                reminder_count INTEGER NOT NULL DEFAULT 0, last_reminder_at TEXT NULL,
                closed_at TEXT NULL, closed_by TEXT NULL
            )",
            "CREATE INDEX IF NOT EXISTS {$s}_state ON $s (state)",
            "CREATE TABLE IF NOT EXISTS $a (
                seq INTEGER NOT NULL PRIMARY KEY, ts TEXT NOT NULL, actor TEXT NOT NULL, level INTEGER NOT NULL,
                action TEXT NOT NULL, object TEXT NOT NULL, details_enc TEXT NOT NULL,
                prev_hash TEXT NOT NULL, hash TEXT NOT NULL
            )",
            "CREATE TABLE IF NOT EXISTS $m (
                id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT NOT NULL, status_id INTEGER NULL,
                kind TEXT NOT NULL, rcpt_count INTEGER NOT NULL, ok_count INTEGER NOT NULL,
                content_enc TEXT NOT NULL, result_enc TEXT NOT NULL
            )",
            "CREATE TABLE IF NOT EXISTS $l (
                id INTEGER PRIMARY KEY AUTOINCREMENT, ts INTEGER NOT NULL, scope TEXT NOT NULL,
                subj TEXT NOT NULL, ip TEXT NOT NULL, ok INTEGER NOT NULL
            )",
            "CREATE INDEX IF NOT EXISTS {$l}_scope_ts ON $l (scope, ts)",
            "CREATE TABLE IF NOT EXISTS $u (user TEXT NOT NULL, step INTEGER NOT NULL, PRIMARY KEY (user, step))",
            "CREATE TABLE IF NOT EXISTS $k (k TEXT NOT NULL PRIMARY KEY, v TEXT NOT NULL)",
            "CREATE TABLE IF NOT EXISTS $vc (status_id INTEGER NOT NULL, day TEXT NOT NULL, n INTEGER NOT NULL DEFAULT 0, PRIMARY KEY (status_id, day))",
        ];
        $triggers = [
            "CREATE TRIGGER {$a}_no_upd BEFORE UPDATE ON $a BEGIN SELECT RAISE(ABORT, 'audit is append-only'); END",
            "CREATE TRIGGER {$a}_no_del BEFORE DELETE ON $a BEGIN SELECT RAISE(ABORT, 'audit is append-only'); END",
            "CREATE TRIGGER {$s}_no_del BEFORE DELETE ON $s BEGIN SELECT RAISE(ABORT, 'status history is append-only'); END",
        ];
    }
    foreach ($sql as $q) {
        $pdo->exec($q);
    }
    foreach ($triggers as $q) {
        try {
            $pdo->exec($q);
        } catch (Throwable $e) {
            // existiert bereits oder fehlende TRIGGER-Rechte (Shared Hosting) – die Hash-Kette schützt trotzdem
        }
    }
}

function kv_get(string $k): ?string
{
    $q = db()->prepare('SELECT v FROM ' . t('kv') . ' WHERE k = ?');
    $q->execute([$k]);
    $r = $q->fetch();
    return $r ? (string)$r['v'] : null;
}

function kv_set(string $k, string $v): void
{
    $q = db()->prepare('DELETE FROM ' . t('kv') . ' WHERE k = ?');
    $q->execute([$k]);
    $q = db()->prepare('INSERT INTO ' . t('kv') . ' (k, v) VALUES (?, ?)');
    $q->execute([$k, $v]);
}

/* ====================================================================== */
/* Request-Kontext, Session, Auth                                         */
/* ====================================================================== */

function client_ip(): string
{
    $remote = (string)($_SERVER['REMOTE_ADDR'] ?? '0.0.0.0');
    $trusted = (array)cfg('net.trusted_proxies', []);
    if ($trusted && in_array($remote, $trusted, true)) {
        $hdr = (string)($_SERVER[(string)cfg('net.proxy_header', 'HTTP_X_FORWARDED_FOR')] ?? '');
        $list = array_reverse(array_map('trim', explode(',', $hdr)));
        foreach ($list as $ip) {
            if (filter_var($ip, FILTER_VALIDATE_IP) && !in_array($ip, $trusted, true)) {
                return $ip;
            }
        }
    }
    return $remote;
}

function is_https(): bool
{
    $h = $_SERVER['HTTPS'] ?? '';
    if ($h !== '' && strtolower((string)$h) !== 'off') {
        return true;
    }
    $remote = (string)($_SERVER['REMOTE_ADDR'] ?? '');
    return in_array($remote, (array)cfg('net.trusted_proxies', []), true)
        && strtolower((string)($_SERVER['HTTP_X_FORWARDED_PROTO'] ?? '')) === 'https';
}

function req_ctx(): array
{
    if (PHP_SAPI === 'cli') {
        return ['sapi' => 'cli', 'user' => get_current_user()];
    }
    return [
        'ip'     => client_ip(),
        'ua'     => mb_substr((string)($_SERVER['HTTP_USER_AGENT'] ?? ''), 0, 200),
        'script' => basename((string)($_SERVER['SCRIPT_NAME'] ?? '')),
    ];
}

function send_security_headers(): void
{
    header('X-Robots-Tag: noindex, nofollow, noarchive, nosnippet');
    header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
    header('Pragma: no-cache');
    header('X-Content-Type-Options: nosniff');
    header('X-Frame-Options: DENY');
    header('Referrer-Policy: no-referrer');
    header('Cross-Origin-Opener-Policy: same-origin');
    header('Permissions-Policy: geolocation=(), camera=(), microphone=()');
    // Nur eigene Stylesheets (Bootstrap + app.css), data:-SVGs für Bootstrap-Formularsymbole, kein JavaScript.
    header("Content-Security-Policy: default-src 'none'; style-src 'self'; img-src 'self' data:; form-action 'self'; frame-ancestors 'none'; base-uri 'none'");
    if (is_https()) {
        header('Strict-Transport-Security: max-age=31536000');
    }
}

function sess_start(): void
{
    if (session_status() === PHP_SESSION_ACTIVE) {
        return;
    }
    ini_set('session.use_strict_mode', '1');
    ini_set('session.use_only_cookies', '1');
    $path = rtrim(dirname((string)($_SERVER['SCRIPT_NAME'] ?? '/')), '/\\') . '/';
    session_name('SBCMSID');
    session_set_cookie_params([
        'lifetime' => 0, 'path' => $path, 'secure' => is_https(),
        'httponly' => true, 'samesite' => 'Strict',
    ]);
    session_start();
    $now = time();
    $idle = (int)cfg('auth.idle_minutes', 30) * 60;
    $abs  = (int)cfg('auth.absolute_hours', 10) * 3600;
    if (isset($_SESSION['last'], $_SESSION['born'])
        && ($now - (int)$_SESSION['last'] > $idle || $now - (int)$_SESSION['born'] > $abs)) {
        $_SESSION = [];
        session_regenerate_id(true);
    }
    $_SESSION['born'] ??= $now;
    $_SESSION['last'] = $now;
}

function bootstrap(): void
{
    error_reporting(E_ALL);
    ini_set('display_errors', '0');
    ini_set('log_errors', '1');
    date_default_timezone_set('UTC');
    mb_internal_encoding('UTF-8');
    set_exception_handler(function (Throwable $e): void {
        error_log(sprintf('Status-BCM: %s in %s:%d', $e->getMessage(), $e->getFile(), $e->getLine()));
        if (!headers_sent()) {
            http_response_code(500);
            header('Content-Type: text/plain; charset=utf-8');
        }
        echo "Interner Fehler. Bitte später erneut versuchen.\n";
    });
    send_security_headers();
    sess_start();
}

function redirect(string $to): void
{
    header('Location: ' . $to);
    exit;
}

function flash(string $type, string $msg): void
{
    $_SESSION['flash'][] = [$type, $msg];
}

function flash_take(): array
{
    $f = $_SESSION['flash'] ?? [];
    unset($_SESSION['flash']);
    return $f;
}

function csrf_token(): string
{
    return $_SESSION['csrf'] ??= bin2hex(random_bytes(32));
}

function csrf_field(): string
{
    return '<input type="hidden" name="_csrf" value="' . h(csrf_token()) . '">';
}

function csrf_verify(): void
{
    if (!hash_equals(csrf_token(), (string)($_POST['_csrf'] ?? ''))) {
        http_response_code(400);
        exit("Ungültige Anfrage.\n");
    }
}

function fail_delay(): void
{
    usleep(random_int(250000, 600000));
}

function stage1_ok(): bool
{
    return !empty($_SESSION['s1']);
}

function users(): array
{
    $out = [];
    foreach ((array)cfg('auth.users', []) as $id => $u) {
        $id = strtolower((string)$id);
        if (!preg_match('/^[a-z0-9_-]{2,32}$/', $id) || !is_array($u)) {
            continue;
        }
        try {
            $email = cfg_secret((string)($u['email'] ?? ''));
        } catch (Throwable $e) {
            $email = '';
        }
        $out[$id] = [
            'name'        => (string)($u['name'] ?? $id),
            'email'       => $email,
            'hash'        => (string)($u['hash'] ?? ''),
            'totp_secret' => (string)($u['totp_secret'] ?? ''),
        ];
    }
    return $out;
}

function stage2_user(): ?array
{
    $s = $_SESSION['s2'] ?? null;
    if (!is_array($s) || empty($s['u'])) {
        return null;
    }
    $idle = (int)cfg('auth.stage2_idle_minutes', 15) * 60;
    $u = users()[$s['u']] ?? null;
    if (!$u || time() - (int)$s['t'] > $idle) {
        unset($_SESSION['s2'], $_SESSION['pending']);
        return null;
    }
    $_SESSION['s2']['t'] = time();
    return ['id' => (string)$s['u']] + $u;
}

function auth_actor(): array
{
    if (PHP_SAPI === 'cli') {
        return ['system:cli', 0];
    }
    if (session_status() === PHP_SESSION_ACTIVE) {
        $u = stage2_user();
        if ($u) {
            return [$u['id'], 2];
        }
        if (stage1_ok()) {
            return ['stage1', 1];
        }
    }
    return ['anonymous', 0];
}

function logout_all(): void
{
    $_SESSION = [];
    session_regenerate_id(true);
}

function verify_stage1(string $pw): bool
{
    $hash = (string)cfg('auth.stage1_hash', '');
    if ($hash === '' || strlen($pw) > 1000) {
        password_verify('x', password_hash('dummy', PASSWORD_DEFAULT));
        return false;
    }
    return password_verify($pw, $hash);
}

function verify_user(string $id, string $pw): ?array
{
    static $dummy = null;
    $dummy ??= password_hash('dummy-password', PASSWORD_DEFAULT);
    $id = strtolower(trim($id));
    $u = users()[$id] ?? null;
    $hash = ($u && $u['hash'] !== '') ? $u['hash'] : $dummy;
    $ok = strlen($pw) <= 1000 && password_verify($pw, $hash);
    return ($ok && $u && $u['hash'] !== '') ? (['id' => $id] + $u) : null;
}

/* --- Brute-Force-Bremse --- */

function throttle_locked(string $scope, ?string $subject = null): int
{
    $win     = (int)cfg('auth.window_seconds', 900);
    $maxIp   = (int)cfg('auth.max_failures', 5);
    $maxUser = (int)cfg('auth.max_failures_user', 10);
    $since   = time() - $win;
    $wait = 0;
    $checks = [['ip', mac('ip', client_ip()), $maxIp]];
    if ($subject !== null) {
        $checks[] = ['subj', mac('subj', strtolower($subject)), $maxUser];
    }
    foreach ($checks as [$col, $val, $max]) {
        $q = db()->prepare('SELECT COUNT(*) AS c, MIN(ts) AS m FROM ' . t('login_attempt')
            . " WHERE scope = ? AND $col = ? AND ok = 0 AND ts >= ?");
        $q->execute([$scope, $val, $since]);
        $r = $q->fetch();
        if ((int)$r['c'] >= $max) {
            $wait = max($wait, (int)$r['m'] + $win - time());
        }
    }
    return $wait > 0 ? $wait : 0;
}

function throttle_record(string $scope, ?string $subject, bool $ok): void
{
    $q = db()->prepare('INSERT INTO ' . t('login_attempt') . ' (ts, scope, subj, ip, ok) VALUES (?, ?, ?, ?, ?)');
    $q->execute([time(), $scope, mac('subj', strtolower((string)$subject)), mac('ip', client_ip()), $ok ? 1 : 0]);
}

/* ====================================================================== */
/* TOTP (RFC 6238, HMAC-SHA1, 6 Stellen, 30 s) – ohne SMS/Mail            */
/* ====================================================================== */

const SBCM_B32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

function b32_encode(string $bin): string
{
    $bits = '';
    foreach (str_split($bin) as $c) {
        $bits .= str_pad(decbin(ord($c)), 8, '0', STR_PAD_LEFT);
    }
    $out = '';
    foreach (str_split($bits, 5) as $chunk) {
        $out .= SBCM_B32[bindec(str_pad($chunk, 5, '0', STR_PAD_RIGHT))];
    }
    return $out;
}

function b32_decode(string $s): string
{
    $s = strtoupper(preg_replace('/[\s=-]/', '', $s) ?? '');
    $bits = '';
    foreach (str_split($s) as $c) {
        $p = strpos(SBCM_B32, $c);
        if ($p === false) {
            return '';
        }
        $bits .= str_pad(decbin($p), 5, '0', STR_PAD_LEFT);
    }
    $out = '';
    foreach (str_split($bits, 8) as $byte) {
        if (strlen($byte) === 8) {
            $out .= chr(bindec($byte));
        }
    }
    return $out;
}

function totp_at(string $secretBin, int $step, int $digits = 6): string
{
    $h = hash_hmac('sha1', pack('J', $step), $secretBin, true);
    $o = ord($h[19]) & 0x0f;
    $n = unpack('N', substr($h, $o, 4))[1] & 0x7fffffff;
    return str_pad((string)($n % (10 ** $digits)), $digits, '0', STR_PAD_LEFT);
}

function totp_secret_of(array $user): string
{
    $raw = $user['totp_secret'] ?? '';
    return $raw === '' ? '' : b32_decode(cfg_secret($raw));
}

/** Prüft den Code, verbraucht den Zeitschritt (Replay-Schutz). Ohne konfiguriertes Secret: immer false. */
function totp_verify_user(array $user, string $code, ?int $nowTs = null): bool
{
    $code = preg_replace('/\D/', '', $code) ?? '';
    $secret = totp_secret_of($user);
    if ($secret === '' || strlen($code) !== 6) {
        return false;
    }
    $now = intdiv($nowTs ?? time(), 30);
    $win = (int)cfg('auth.totp_window', 1);
    $hit = null;
    for ($d = -$win; $d <= $win; $d++) {
        if (hash_equals(totp_at($secret, $now + $d), $code)) {
            $hit = $now + $d;
        }
    }
    if ($hit === null) {
        return false;
    }
    $pdo = db(); // Verbindungsfehler sollen nicht als "Code bereits verwendet" erscheinen
    try {
        $q = $pdo->prepare('INSERT INTO ' . t('totp_used') . ' (user, step) VALUES (?, ?)');
        $q->execute([$user['id'], $hit]);
    } catch (PDOException $e) {
        return false; // Code bereits verwendet
    }
    return true;
}

/* ====================================================================== */
/* Audit-Log (Hash-Kette + HMAC, verschlüsselte Details, append-only)     */
/* ====================================================================== */

function audit(string $action, string $object, array $details = [], ?string $actor = null, ?int $level = null): int
{
    if ($actor === null || $level === null) {
        [$a, $l] = auth_actor();
        $actor ??= $a;
        $level ??= $l;
    }
    $details['_ctx'] = req_ctx();
    $pdo = db();
    for ($try = 0; $try < 8; $try++) {
        $last = $pdo->query('SELECT seq, hash FROM ' . t('audit') . ' ORDER BY seq DESC LIMIT 1' . lock_clause())->fetch();
        $seq  = $last ? (int)$last['seq'] + 1 : 1;
        $prev = $last ? (string)$last['hash'] : SBCM_ZERO;
        $ts   = now_utc();
        $encd = enc(json_enc($details), 'audit:' . $seq);
        $hash = mac('audit', implode('|', [$seq, $prev, $ts, $actor, $level, $action, $object, $encd]));
        try {
            $q = $pdo->prepare('INSERT INTO ' . t('audit')
                . ' (seq, ts, actor, level, action, object, details_enc, prev_hash, hash) VALUES (?,?,?,?,?,?,?,?,?)');
            $q->execute([$seq, $ts, $actor, $level, $action, $object, $encd, $prev, $hash]);
            return $seq;
        } catch (PDOException $e) {
            if ((string)$e->getCode() !== '23000') {
                throw $e;
            }
        }
    }
    throw new RuntimeException('Audit-Kette ausgelastet');
}

function audit_verify(): array
{
    $prev = SBCM_ZERO;
    $expect = 1;
    $n = 0;
    $err = null;
    $st = db()->query('SELECT * FROM ' . t('audit') . ' ORDER BY seq ASC');
    foreach ($st as $r) {
        if ((int)$r['seq'] !== $expect) {
            $err = "Lücke in der Sequenz bei #$expect";
            break;
        }
        if (!hash_equals($prev, (string)$r['prev_hash'])) {
            $err = "Verkettung gebrochen bei #{$r['seq']}";
            break;
        }
        $calc = mac('audit', implode('|', [$r['seq'], $r['prev_hash'], $r['ts'], $r['actor'], $r['level'],
            $r['action'], $r['object'], $r['details_enc']]));
        if (!hash_equals($calc, (string)$r['hash'])) {
            $err = "Prüfsumme falsch bei #{$r['seq']} (Eintrag verändert)";
            break;
        }
        $prev = (string)$r['hash'];
        $expect++;
        $n++;
    }
    return ['ok' => $err === null, 'count' => $n, 'head' => $prev, 'error' => $err];
}

function audit_recent(int $limit = 30): array
{
    $q = db()->query('SELECT * FROM ' . t('audit') . ' ORDER BY seq DESC LIMIT ' . (int)$limit);
    $out = [];
    foreach ($q as $r) {
        try {
            $r['details'] = json_decode(dec((string)$r['details_enc'], 'audit:' . $r['seq']), true, 32, JSON_THROW_ON_ERROR);
        } catch (Throwable $e) {
            $r['details'] = ['_error' => 'nicht entschlüsselbar'];
        }
        unset($r['details_enc']);
        $out[] = $r;
    }
    return $out;
}

function audit_describe(string $action, array $d): string
{
    $labels = [
        'login1.ok' => 'Anmeldung Stufe 1', 'login2.ok' => 'Anmeldung Stufe 2',
        'login2.fail' => 'Fehlgeschlagene Anmeldung Stufe 2', 'totp.fail' => 'Ungültiger TOTP-Code',
        'status.set' => 'Status gesetzt', 'status.extend' => 'Status verlängert',
        'status.end' => 'Status beendet', 'status.auto_end' => 'Status automatisch zurückgesetzt',
        'mail.alarm' => 'ALARM-Mail versendet', 'mail.reminder' => 'Erinnerung versendet',
        'mail.anchor' => 'Audit-Anker versendet', 'mail.autorevert' => 'Hinweis Rücksetzung versendet',
        'logout' => 'Abmeldung',
    ];
    $s = $labels[$action] ?? $action;
    $parts = [];
    if (isset($d['after']['key'])) {
        $parts[] = ($d['before']['key'] ?? '–') . ' → ' . $d['after']['key'];
        if (array_key_exists('valid_until', $d['after'])) {
            $parts[] = 'gültig bis ' . fmt_local($d['after']['valid_until']);
        }
        if (!empty($d['after']['locations'])) {
            $parts[] = 'Standorte: ' . implode(', ', $d['after']['locations']);
        }
        $parts[] = 'ALARM-Mail: ' . (!empty($d['after']['alarm_mail']) ? 'ja' : 'nein');
    }
    if (isset($d['how']['totp'])) {
        $parts[] = 'TOTP: ' . ($d['how']['totp'] ? 'ja' : 'nein');
    }
    foreach (['recipients', 'ok', 'failed', 'status_id'] as $f) {
        if (isset($d[$f]) && is_scalar($d[$f])) {
            $parts[] = "$f: " . $d[$f];
        }
    }
    if (!empty($d['note'])) {
        $parts[] = 'Notiz: ' . $d['note'];
    }
    if (!empty($d['user'])) {
        $parts[] = 'Benutzer: ' . $d['user'];
    }
    if (!empty($d['_ctx']['ip'])) {
        $parts[] = 'IP ' . $d['_ctx']['ip'];
    }
    return $s . ($parts ? ' – ' . implode('; ', $parts) : '');
}

/* ====================================================================== */
/* Status (verschlüsselte Nutzdaten, Zeilen-MAC, lückenlose Historie)     */
/* ====================================================================== */

function build_payload(array $def, array $locIds, string $note = ''): array
{
    $b = bcm();
    $locs = [];
    foreach ($locIds as $id) {
        $l = $b['locations_by_id'][$id] ?? null;
        if (!$l) {
            continue;
        }
        $own = $l['phone'] !== '';
        $locs[] = ['id' => $id, 'name' => $l['name'], 'phone' => $own ? $l['phone'] : $b['default_phone'], 'default_phone' => !$own];
    }
    return [
        'label' => $def['label'], 'text' => $def['text'], 'severity' => $def['severity'],
        'exercise' => (bool)$def['exercise'], 'audience' => $def['audience'],
        'locations' => $locs, 'default_phone' => $b['default_phone'], 'note' => $note,
    ];
}

function status_row_mac(array $r, int $id): string
{
    return mac('row', implode('|', [$id, $r['status_key'], $r['severity'], $r['author'], $r['created_at'],
        $r['valid_until'] ?? '', (int)$r['alarm_mail'], $r['audience'], $r['payload_enc']]));
}

function status_decode(array $row): array
{
    $row['payload'] = null;
    $row['mac_ok'] = false;
    try {
        $row['mac_ok'] = hash_equals(status_row_mac($row, (int)$row['id']), (string)$row['row_mac']);
        $row['payload'] = json_decode(dec((string)$row['payload_enc'], 'status.payload'), true, 32, JSON_THROW_ON_ERROR);
    } catch (Throwable $e) {
        error_log('Status-BCM: Status #' . ($row['id'] ?? '?') . ': ' . $e->getMessage());
    }
    return $row;
}

function status_current(): ?array
{
    $r = db()->query('SELECT * FROM ' . t('status') . " WHERE state = 'active' ORDER BY id DESC LIMIT 1")->fetch();
    if (!$r) {
        return null;
    }
    $r = status_decode($r);
    // Der aktive Status muss der zuletzt im Audit-Log gesetzte sein (erkennt z. B. das "Reaktivieren" alter Zeilen).
    $q = db()->prepare('SELECT object FROM ' . t('audit') . ' WHERE action IN (?,?,?,?) ORDER BY seq DESC LIMIT 1');
    $q->execute(['status.set', 'status.extend', 'status.end', 'status.auto_end']);
    if ((string)$q->fetchColumn() !== 'status:' . $r['id']) {
        $r['mac_ok'] = false;
    }
    return $r;
}

function status_history(int $limit = 15): array
{
    $out = [];
    foreach (db()->query('SELECT * FROM ' . t('status') . ' ORDER BY id DESC LIMIT ' . (int)$limit) as $r) {
        $out[] = status_decode($r);
    }
    return $out;
}

/**
 * Setzt einen neuen Status (löst den bisherigen ab) und schreibt atomar das Audit-Log.
 * $spec: mode(set|extend|end), key, loc_ids[], valid_until (UTC|null), alarm_mail(bool), note
 */
function status_create(array $spec, string $author, array $how = []): array
{
    $def = bcm()['by_key'][$spec['key']] ?? null;
    if (!$def) {
        throw new InvalidArgumentException('Unbekannter Status');
    }
    $level = str_starts_with($author, 'system:') ? 0 : 2;
    $payload = build_payload($def, (array)$spec['loc_ids'], (string)($spec['note'] ?? ''));
    $now = now_utc();
    $pdo = db();

    return tx(function () use ($pdo, $spec, $def, $author, $level, $payload, $now, $how) {
        $cur = $pdo->query('SELECT id, status_key, valid_until FROM ' . t('status')
            . " WHERE state = 'active' ORDER BY id DESC" . lock_clause())->fetch();
        $before = null;
        if ($cur) {
            $pdo->prepare('UPDATE ' . t('status') . " SET state = 'superseded', closed_at = ?, closed_by = ? WHERE state = 'active'")
                ->execute([$now, $author]);
            $before = ['id' => (int)$cur['id'], 'key' => $cur['status_key'], 'valid_until' => $cur['valid_until']];
        }
        $row = [
            'status_key' => $def['key'], 'severity' => $def['severity'], 'author' => $author, 'created_at' => $now,
            'valid_until' => $spec['valid_until'] ?? null, 'alarm_mail' => !empty($spec['alarm_mail']) ? 1 : 0,
            'audience' => $def['audience'], 'payload_enc' => enc(json_enc($payload), 'status.payload'),
        ];
        $pdo->prepare('INSERT INTO ' . t('status')
            . ' (status_key, severity, author, created_at, valid_until, alarm_mail, audience, state, payload_enc, row_mac)'
            . " VALUES (?,?,?,?,?,?,?,'active',?,'')")
            ->execute([$row['status_key'], $row['severity'], $row['author'], $row['created_at'], $row['valid_until'],
                $row['alarm_mail'], $row['audience'], $row['payload_enc']]);
        $id = (int)$pdo->lastInsertId();
        $pdo->prepare('UPDATE ' . t('status') . ' SET row_mac = ? WHERE id = ?')->execute([status_row_mac($row, $id), $id]);

        $action = ['set' => 'status.set', 'extend' => 'status.extend', 'end' => 'status.end', 'auto_end' => 'status.auto_end'][$spec['mode']] ?? 'status.set';
        audit($action, 'status:' . $id, [
            'mode'   => $spec['mode'],
            'before' => $before,
            'after'  => ['id' => $id, 'key' => $def['key'], 'label' => $def['label'],
                'locations' => array_column($payload['locations'], 'id'),
                'valid_until' => $row['valid_until'], 'alarm_mail' => (bool)$row['alarm_mail']],
            'how'    => $how,
            'note'   => $spec['note'] ?? '',
        ], $author, $level);
        return ['id' => $id, 'payload' => $payload, 'valid_until' => $row['valid_until'], 'author' => $author];
    });
}

function spec_needs_totp(array $spec): bool
{
    if (cfg('auth.totp_enforce_all', false)) {
        return true;
    }
    if ($spec['mode'] === 'end') {
        return false;
    }
    $def = bcm()['by_key'][$spec['key']] ?? null;
    return !empty($spec['alarm_mail']) || ($def && $def['require_totp']);
}

/** Validiert Formulareingaben -> [spec|null, Fehlerliste] */
function parse_change_request(array $in, ?array $current): array
{
    $b = bcm();
    $mode = (string)($in['mode'] ?? 'set');
    if (!in_array($mode, ['set', 'extend', 'end'], true)) {
        return [null, ['Ungültige Aktion.']];
    }
    $note = preg_replace('/[\x00-\x1F\x7F]+/u', ' ', (string)($in['note'] ?? '')) ?? '';
    $note = mb_substr(trim($note), 0, 200);
    $spec = ['mode' => $mode, 'key' => '', 'loc_ids' => [], 'valid_until' => null, 'alarm_mail' => false, 'note' => $note];
    $errors = [];

    if ($mode === 'end') {
        $spec['key'] = $b['default_status'];
        return [$spec, []];
    }
    if ($mode === 'extend') {
        if (!$current || empty($current['payload'])) {
            return [null, ['Kein aktiver Status zum Verlängern.']];
        }
        $spec['key'] = (string)$current['status_key'];
        $spec['loc_ids'] = array_values(array_column($current['payload']['locations'] ?? [], 'id'));
        $def = $b['by_key'][$spec['key']] ?? null;
        if (!$def) {
            return [null, ['Der aktuelle Status ist in der config.json nicht mehr definiert.']];
        }
    } else {
        $def = $b['by_key'][(string)($in['status_key'] ?? '')] ?? null;
        if (!$def) {
            return [null, ['Bitte einen Status auswählen.']];
        }
        $spec['key'] = $def['key'];
        $hits = critical_terms_in($def['label'] . "\n" . $def['text'], $b);
        if ($hits) {
            return [null, ['Der Meldungstext dieses Status enthält kritische Begriffe (' . implode(', ', $hits)
                . ') und ist nicht pressetauglich. Bitte config.json korrigieren.']];
        }
        if ($def['audience'] === 'ALLE_UND_ADRESSLISTE') {
            $ids = !empty($in['loc_all']) ? array_keys($b['locations_by_id']) : array_map('strval', (array)($in['loc'] ?? []));
            $ids = array_values(array_unique(array_filter($ids, fn($i) => isset($b['locations_by_id'][$i]))));
            if (!$ids) {
                $errors[] = 'Bitte mindestens einen Standort auswählen.';
            }
            $spec['loc_ids'] = $ids;
        }
        if (!empty($in['alarm_mail'])) {
            if (!$def['alarm_mail_allowed']) {
                $errors[] = 'Für diesen Status ist keine ALARM-Mail vorgesehen.';
            } elseif (!alarm_recipients()) {
                $errors[] = 'Es sind keine ALARM-Empfänger konfiguriert.';
            } else {
                $spec['alarm_mail'] = true;
            }
        }
    }

    $vt = (string)($in['validity_type'] ?? 'duration');
    $now = time();
    $maxTs = $now + (int)cfg('limits.max_validity_days', 30) * 86400;
    if ($vt === 'unlimited') {
        if (!$def['allow_unlimited']) {
            $errors[] = 'Für diesen Status ist eine Befristung erforderlich.';
        }
    } elseif ($vt === 'until') {
        $u = local_to_utc((string)($in['until'] ?? ''));
        if ($u === null) {
            $errors[] = 'Ungültiges "Gültig bis"-Datum.';
        } elseif (utc_ts($u) < $now + 300) {
            $errors[] = '"Gültig bis" muss mindestens 5 Minuten in der Zukunft liegen.';
        } elseif (utc_ts($u) > $maxTs) {
            $errors[] = '"Gültig bis" liegt zu weit in der Zukunft (max. ' . (int)cfg('limits.max_validity_days', 30) . ' Tage).';
        } else {
            $spec['valid_until'] = $u;
        }
    } else {
        $min = (int)($in['duration'] ?? 0);
        if (!in_array($min, $b['validity_options_minutes'], true)) {
            $errors[] = 'Bitte eine Dauer auswählen.';
        } else {
            $spec['valid_until'] = gmdate('Y-m-d H:i:s', $now + $min * 60);
        }
    }
    if ($mode === 'extend' && $spec['valid_until'] === null && !$def['allow_unlimited']) {
        $errors[] = 'Bitte Dauer oder "Gültig bis" angeben.';
    }
    return [$errors ? null : $spec, $errors];
}

/* ====================================================================== */
/* Nutzung: anonymer Lesezähler, Login-Statistik aus dem Audit-Log        */
/* ====================================================================== */

/** Zählt eine Ansicht des Status – einmal je Sitzung und Status, ohne IP/Person (nur Status-ID + Tag). */
function view_count(int $statusId): void
{
    if (!empty($_SESSION['seen'][$statusId])) {
        return;
    }
    $_SESSION['seen'][$statusId] = 1;
    $day = (new DateTimeImmutable('now', app_tz()))->format('Y-m-d');
    $up = db()->prepare('UPDATE ' . t('view_count') . ' SET n = n + 1 WHERE status_id = ? AND day = ?');
    $up->execute([$statusId, $day]);
    if ($up->rowCount() === 0) {
        try {
            db()->prepare('INSERT INTO ' . t('view_count') . ' (status_id, day, n) VALUES (?, ?, 1)')->execute([$statusId, $day]);
        } catch (PDOException $e) {
            $up->execute([$statusId, $day]); // parallel angelegt
        }
    }
}

/** Ansichten je Status: [status_id => Summe] */
function view_totals(array $statusIds): array
{
    $out = array_fill_keys(array_map('intval', $statusIds), 0);
    if (!$out) {
        return [];
    }
    $q = db()->prepare('SELECT status_id, SUM(n) AS s FROM ' . t('view_count') . ' WHERE status_id IN ('
        . implode(',', array_fill(0, count($out), '?')) . ') GROUP BY status_id');
    $q->execute(array_keys($out));
    foreach ($q as $r) {
        $out[(int)$r['status_id']] = (int)$r['s'];
    }
    return $out;
}

/**
 * Login-Statistik aus dem Audit-Log (Aktion, Akteur und Zeit liegen unverschlüsselt, aber HMAC-gesichert vor).
 * Rückgabe: periods (heute / 7 Tage / $days Tage) mit s1, s2 [Benutzer => Anzahl], fail;
 *           last [Benutzer => letzte Anmeldung UTC|null]; days [Y-m-d => s1, s2, fail] (neueste zuerst).
 */
function login_stats(int $days = 30, ?int $nowTs = null): array
{
    $tz = app_tz();
    $today = (new DateTimeImmutable('@' . ($nowTs ?? time())))->setTimezone($tz)->setTime(0, 0);
    $cut = ['heute' => $today, '7 Tage' => $today->modify('-6 days'), "$days Tage" => $today->modify('-' . ($days - 1) . ' days')];
    $since = end($cut)->setTimezone(new DateTimeZone('UTC'))->format('Y-m-d H:i:s');
    $periods = [];
    foreach ($cut as $k => $_) {
        $periods[$k] = ['s1' => 0, 's2' => [], 'fail' => 0];
    }
    $daysOut = [];
    $q = db()->prepare('SELECT ts, action, actor FROM ' . t('audit') . ' WHERE ts >= ? AND action IN (?,?,?) ORDER BY seq');
    $q->execute([$since, 'login1.ok', 'login2.ok', 'login2.fail']);
    foreach ($q as $r) {
        $local = (new DateTimeImmutable((string)$r['ts'], new DateTimeZone('UTC')))->setTimezone($tz);
        $d = $local->format('Y-m-d');
        $daysOut[$d] ??= ['s1' => 0, 's2' => 0, 'fail' => 0];
        $kind = $r['action'] === 'login1.ok' ? 's1' : ($r['action'] === 'login2.ok' ? 's2' : 'fail');
        $daysOut[$d][$kind]++;
        foreach ($cut as $k => $from) {
            if ($local < $from) {
                continue;
            }
            if ($kind === 's2') {
                $periods[$k]['s2'][$r['actor']] = ($periods[$k]['s2'][$r['actor']] ?? 0) + 1;
            } else {
                $periods[$k][$kind]++;
            }
        }
    }
    $last = [];
    $q = db()->prepare('SELECT ts FROM ' . t('audit') . ' WHERE action = ? AND actor = ? ORDER BY seq DESC LIMIT 1');
    foreach (array_keys(users()) as $id) {
        $q->execute(['login2.ok', $id]);
        $last[$id] = $q->fetchColumn() ?: null;
    }
    krsort($daysOut);
    return ['periods' => $periods, 'last' => $last, 'days' => $daysOut];
}

/* ====================================================================== */
/* E-Mail (eigener SMTP-Client, keine Abhängigkeiten)                     */
/* ====================================================================== */

function alarm_recipients(): array
{
    $out = [];
    foreach ((array)cfg('mail.recipients', []) as $r) {
        try {
            $e = strtolower(trim(cfg_secret((string)$r)));
        } catch (Throwable $ex) {
            error_log('Status-BCM: Empfänger nicht entschlüsselbar');
            continue;
        }
        if (filter_var($e, FILTER_VALIDATE_EMAIL)) {
            $out[$e] = $e;
        }
    }
    return array_values($out);
}

/** cc_default_mail1 – darf wie die Empfänger als "enc:..." hinterlegt sein. */
function cc_default_mail1(): string
{
    try {
        $e = strtolower(trim(cfg_secret((string)cfg('mail.cc_default_mail1', ''))));
    } catch (Throwable $ex) {
        error_log('Status-BCM: cc_default_mail1 nicht entschlüsselbar');
        return '';
    }
    return filter_var($e, FILTER_VALIDATE_EMAIL) ? $e : '';
}

function mime_word(string $s): string
{
    if (preg_match('/^[\x20-\x7E]*$/', $s)) {
        return $s;
    }
    $words = [];
    $cur = '';
    foreach (preg_split('//u', $s, -1, PREG_SPLIT_NO_EMPTY) ?: [] as $ch) {
        if (strlen($cur . $ch) > 42) {
            $words[] = '=?UTF-8?B?' . base64_encode($cur) . '?=';
            $cur = '';
        }
        $cur .= $ch;
    }
    if ($cur !== '') {
        $words[] = '=?UTF-8?B?' . base64_encode($cur) . '?=';
    }
    return implode("\r\n ", $words);
}

function hdr_clean(string $s): string
{
    return trim(str_replace(["\r", "\n", "\0"], ' ', $s));
}

function mime_build(string $from, string $fromName, array $m): string
{
    $domain = substr(strrchr($from, '@') ?: '@localhost', 1);
    $h = [];
    $h[] = 'Date: ' . gmdate('D, d M Y H:i:s') . ' +0000';
    $h[] = 'From: ' . ($fromName !== '' ? mime_word(hdr_clean($fromName)) . ' ' : '') . '<' . hdr_clean($from) . '>';
    $h[] = !empty($m['to']) ? 'To: ' . implode(', ', array_map('hdr_clean', $m['to'])) : 'To: undisclosed-recipients:;';
    if (!empty($m['cc'])) {
        $h[] = 'Cc: ' . implode(', ', array_map('hdr_clean', $m['cc']));
    }
    $h[] = 'Subject: ' . mime_word(hdr_clean($m['subject']));
    $h[] = 'Message-ID: <' . bin2hex(random_bytes(12)) . '@' . $domain . '>';
    $h[] = 'MIME-Version: 1.0';
    $h[] = 'Content-Type: text/plain; charset=UTF-8';
    $h[] = 'Content-Transfer-Encoding: base64';
    $h[] = 'Auto-Submitted: auto-generated';
    if (!empty($m['priority'])) {
        $h[] = 'Importance: High';
        $h[] = 'X-Priority: 1';
    }
    $body = str_replace(["\r\n", "\r"], "\n", $m['body']);
    return implode("\r\n", $h) . "\r\n\r\n" . chunk_split(base64_encode($body), 76, "\r\n");
}

final class SbcmSmtp
{
    /** @var resource|null */
    private $fp = null;
    private array $c;

    public function __construct(array $c)
    {
        $this->c = $c;
    }

    public function send(string $from, array $rcpts, string $raw): array
    {
        $results = [];
        try {
            $this->connect();
            $this->cmd('MAIL FROM:<' . $this->addr($from) . '>', [250]);
            $accepted = 0;
            foreach ($rcpts as $r) {
                try {
                    $this->cmd('RCPT TO:<' . $this->addr($r) . '>', [250, 251]);
                    $results[] = ['addr' => $r, 'ok' => true, 'err' => ''];
                    $accepted++;
                } catch (RuntimeException $e) {
                    $results[] = ['addr' => $r, 'ok' => false, 'err' => $e->getMessage()];
                }
            }
            if ($accepted === 0) {
                throw new RuntimeException('Kein Empfänger akzeptiert');
            }
            $this->cmd('DATA', [354]);
            $data = preg_replace('/\r?\n/', "\r\n", $raw) ?? $raw;
            $data = preg_replace('/^\./m', '..', $data) ?? $data;
            $this->write($data . "\r\n.\r\n");
            [$code] = $this->read();
            if ($code !== 250) {
                throw new RuntimeException("SMTP DATA abgelehnt ($code)");
            }
            try {
                $this->cmd('QUIT', [221]);
            } catch (Throwable $e) {
            }
        } catch (Throwable $e) {
            $msg = $e->getMessage();
            $known = array_column($results, 'addr');
            foreach ($results as &$x) {
                if ($x['ok']) {
                    $x['ok'] = false;
                    $x['err'] = $msg;
                }
            }
            unset($x);
            foreach ($rcpts as $r) {
                if (!in_array($r, $known, true)) {
                    $results[] = ['addr' => $r, 'ok' => false, 'err' => $msg];
                }
            }
        } finally {
            if (is_resource($this->fp)) {
                @fclose($this->fp);
            }
            $this->fp = null;
        }
        return $results;
    }

    private function addr(string $a): string
    {
        $a = trim($a, " <>\t");
        if (!filter_var($a, FILTER_VALIDATE_EMAIL) || preg_match('/[\r\n]/', $a)) {
            throw new RuntimeException('Ungültige Adresse');
        }
        return $a;
    }

    private function connect(): void
    {
        $host = (string)$this->c['host'];
        $port = (int)$this->c['port'];
        $secure = (string)($this->c['secure'] ?? 'starttls');
        $timeout = (int)($this->c['timeout'] ?? 15);
        $vp = (bool)($this->c['verify_peer'] ?? true);
        $user = (string)($this->c['user'] ?? '');
        $local = in_array($host, ['localhost', '127.0.0.1', '::1'], true);
        if ($secure === 'none' && $user !== '' && !$local) {
            throw new RuntimeException('Zugangsdaten werden nicht unverschlüsselt übertragen');
        }
        $ctx = stream_context_create(['ssl' => [
            'verify_peer' => $vp, 'verify_peer_name' => $vp, 'peer_name' => $host,
            'SNI_enabled' => true, 'allow_self_signed' => !$vp,
        ]]);
        $fp = @stream_socket_client(($secure === 'ssl' ? 'ssl://' : 'tcp://') . $host . ':' . $port,
            $errno, $errstr, $timeout, STREAM_CLIENT_CONNECT, $ctx);
        if (!$fp) {
            throw new RuntimeException('SMTP-Verbindung fehlgeschlagen');
        }
        $this->fp = $fp;
        stream_set_timeout($fp, $timeout);
        [$code] = $this->read();
        if ($code !== 220) {
            throw new RuntimeException("SMTP Begrüßung ($code)");
        }
        $helo = (string)($this->c['helo'] ?? '');
        if ($helo === '') {
            $helo = (string)(parse_url((string)cfg('app.base_url'), PHP_URL_HOST) ?: 'localhost');
        }
        [, $caps] = $this->cmd('EHLO ' . $helo, [250]);
        if ($secure === 'starttls') {
            $this->cmd('STARTTLS', [220]);
            $ok = @stream_socket_enable_crypto($fp, true,
                STREAM_CRYPTO_METHOD_TLSv1_2_CLIENT | STREAM_CRYPTO_METHOD_TLSv1_3_CLIENT);
            if ($ok !== true) {
                throw new RuntimeException('STARTTLS fehlgeschlagen');
            }
            [, $caps] = $this->cmd('EHLO ' . $helo, [250]);
        }
        if ($user !== '') {
            $pass = (string)($this->c['pass'] ?? '');
            if (stripos($caps, 'AUTH') !== false && stripos($caps, 'PLAIN') === false && stripos($caps, 'LOGIN') !== false) {
                $this->cmd('AUTH LOGIN', [334]);
                $this->cmd(base64_encode($user), [334]);
                $this->cmd(base64_encode($pass), [235]);
            } else {
                $this->cmd('AUTH PLAIN ' . base64_encode("\0" . $user . "\0" . $pass), [235]);
            }
        }
    }

    private function write(string $s): void
    {
        $len = strlen($s);
        for ($off = 0; $off < $len;) {
            $n = @fwrite($this->fp, substr($s, $off, 8192));
            if ($n === false || $n === 0) {
                throw new RuntimeException('SMTP Schreibfehler');
            }
            $off += $n;
        }
    }

    private function read(): array
    {
        $text = '';
        while (true) {
            $l = fgets($this->fp, 2048);
            if ($l === false) {
                throw new RuntimeException('SMTP Verbindung unterbrochen');
            }
            $text .= $l;
            if (strlen($l) >= 4 && $l[3] === ' ') {
                return [(int)substr($l, 0, 3), trim($text)];
            }
            if (strlen($l) < 4) {
                return [0, trim($text)];
            }
        }
    }

    private function cmd(string $c, array $expect): array
    {
        $this->write($c . "\r\n");
        [$code, $txt] = $this->read();
        if (!in_array($code, $expect, true)) {
            throw new RuntimeException("SMTP Antwort $code");
        }
        return [$code, $txt];
    }
}

/** Versand. m: to[], cc[], bcc[], subject, body, priority. Rückgabe: Liste [addr, ok, err] je Empfänger. */
function mail_deliver(array $m): array
{
    $from = (string)cfg('mail.from_email');
    $fromName = (string)cfg('mail.from_name', '');
    $all = [];
    $bad = [];
    foreach (array_merge($m['to'] ?? [], $m['cc'] ?? [], $m['bcc'] ?? []) as $a) {
        $a = strtolower(trim((string)$a));
        if (filter_var($a, FILTER_VALIDATE_EMAIL)) {
            $all[$a] = $a;
        } elseif ($a !== '') {
            $bad[] = ['addr' => $a, 'ok' => false, 'err' => 'ungültige Adresse'];
        }
    }
    $all = array_values($all);
    if (!$all) {
        return $bad;
    }
    $raw = mime_build($from, $fromName, $m);
    if ((string)cfg('mail.transport', 'smtp') === 'log') {
        $dir = storage_dir() . '/outbox';
        @mkdir($dir, 0700, true);
        file_put_contents($dir . '/' . gmdate('Ymd-His') . '-' . bin2hex(random_bytes(3)) . '.eml',
            "X-Envelope-Rcpt: " . implode(', ', $all) . "\r\n" . $raw);
        return array_merge(array_map(fn($a) => ['addr' => $a, 'ok' => true, 'err' => ''], $all), $bad);
    }
    try {
        $res = (new SbcmSmtp((array)cfg('mail')))->send($from, $all, $raw);
    } catch (Throwable $e) {
        $res = array_map(fn($a) => ['addr' => $a, 'ok' => false, 'err' => $e->getMessage()], $all);
    }
    return array_merge($res, $bad);
}

function mail_record(string $kind, ?int $statusId, string $subject, string $body, array $results): array
{
    $ok = count(array_filter($results, fn($r) => $r['ok']));
    $fail = count($results) - $ok;
    $masked = array_map(fn($r) => ['m' => mask_email($r['addr']), 'ok' => $r['ok'], 'err' => $r['err']], $results);
    db()->prepare('INSERT INTO ' . t('mail_log') . ' (ts, status_id, kind, rcpt_count, ok_count, content_enc, result_enc) VALUES (?,?,?,?,?,?,?)')
        ->execute([now_utc(), $statusId, $kind, count($results), $ok, enc(json_enc(['subject' => $subject, 'body' => $body]), 'mail.content'),
            enc(json_enc($masked), 'mail.result')]);
    return ['total' => count($results), 'ok' => $ok, 'failed' => $fail];
}

function mail_vars_status(array $payload, ?string $validUntil): array
{
    $loc = '';
    if (!empty($payload['locations'])) {
        $loc = "Betroffene Standorte:\n";
        foreach ($payload['locations'] as $l) {
            $loc .= '- ' . $l['name'] . ' (Durchwahl: ' . $l['phone'] . ")\n";
        }
    }
    return [
        'prefix' => !empty($payload['exercise']) ? 'ÜBUNG – ' : '',
        'label' => $payload['label'], 'text' => $payload['text'], 'locations' => $loc,
        'phone' => $payload['default_phone'],
        'validity' => $validUntil ? 'Voraussichtlich gültig bis: ' . fmt_local($validUntil) . ' Uhr' : '',
        'url' => rtrim((string)cfg('app.base_url'), '/') . '/',
    ];
}

/** ALARM-Mail: alle Empfänger per BCC (+ Autor und cc_default_mail1 als Kopie). */
function send_alarm_mail(int $statusId, array $payload, ?string $validUntil, string $author): array
{
    $tpl = bcm()['mail_templates']['alarm'];
    $vars = mail_vars_status($payload, $validUntil);
    $subject = trim(render_tpl($tpl['subject'], $vars));
    $body = render_tpl($tpl['body'], $vars);
    $bcc = alarm_recipients();
    $u = users()[$author] ?? null;
    if ($u && filter_var($u['email'], FILTER_VALIDATE_EMAIL)) {
        $bcc[] = $u['email'];
    }
    $cc1 = cc_default_mail1();
    if ($cc1 !== '') {
        $bcc[] = $cc1;
    }
    $bcc = array_values(array_unique(array_map('strtolower', $bcc)));
    $sum = ['total' => 0, 'ok' => 0, 'failed' => 0];
    foreach (array_chunk($bcc, max(1, (int)cfg('mail.max_bcc_per_message', 50))) as $chunk) {
        $res = mail_deliver(['bcc' => $chunk, 'subject' => $subject, 'body' => $body, 'priority' => true]);
        $r = mail_record('alarm', $statusId, $subject, $body, $res);
        foreach ($sum as $k => $_) {
            $sum[$k] += $r[$k];
        }
    }
    audit('mail.alarm', 'status:' . $statusId, ['recipients' => $sum['total'], 'ok' => $sum['ok'], 'failed' => $sum['failed']], $author, 2);
    return $sum;
}

/* ====================================================================== */
/* Cron-Logik: Erinnerungen, Auto-Rücksetzung, Anker, Aufräumen           */
/* ====================================================================== */

function run_cron(?int $nowTs = null): array
{
    $now = $nowTs ?? time();
    $log = [];
    $b = bcm();
    $lead = (int)cfg('reminder.lead_minutes', 0) * 60;
    $repeat = (int)cfg('reminder.repeat_minutes', 60) * 60;
    $max = (int)cfg('reminder.max_count', 0);
    $auto = (int)cfg('reminder.auto_revert_after_minutes', 0) * 60;
    $base = rtrim((string)cfg('app.base_url'), '/');
    $cc1 = cc_default_mail1();

    $rows = db()->query('SELECT * FROM ' . t('status') . " WHERE state = 'active' AND valid_until IS NOT NULL")->fetchAll();
    foreach ($rows as $row) {
        $r = status_decode($row);
        if (!$r['payload']) {
            $log[] = 'Status #' . $r['id'] . ': Nutzdaten nicht lesbar – übersprungen';
            continue;
        }
        $vu = utc_ts((string)$r['valid_until']);
        $label = $r['payload']['label'];

        if ($auto > 0 && $now >= $vu + $auto) {
            $res = status_create(['mode' => 'auto_end', 'key' => $b['default_status'], 'loc_ids' => [], 'valid_until' => null,
                'alarm_mail' => false, 'note' => 'automatische Rücksetzung nach Ablauf ohne Bestätigung'], 'system:cron', ['cron' => true]);
            $to = [];
            $a = users()[$r['author']] ?? null;
            if ($a && filter_var($a['email'], FILTER_VALIDATE_EMAIL)) {
                $to[] = $a['email'];
            }
            $tpl = $b['mail_templates']['autorevert'];
            $vars = ['label' => $label, 'new_label' => $b['by_key'][$b['default_status']]['label'], 'change_url' => $base . '/change.php'];
            $subject = trim(render_tpl($tpl['subject'], $vars));
            $body = render_tpl($tpl['body'], $vars);
            $res2 = mail_deliver(['to' => $to, 'cc' => $cc1 !== '' ? [$cc1] : [], 'subject' => $subject, 'body' => $body]);
            $sum = mail_record('autorevert', (int)$res['id'], $subject, $body, $res2);
            audit('mail.autorevert', 'status:' . $res['id'], ['recipients' => $sum['total'], 'ok' => $sum['ok'], 'failed' => $sum['failed']], 'system:cron', 0);
            $log[] = "Status #{$r['id']} ($label) automatisch zurückgesetzt";
            continue;
        }

        if ($now < $vu - $lead || ($max > 0 && (int)$r['reminder_count'] >= $max)) {
            continue;
        }
        $last = $r['last_reminder_at'] ? utc_ts((string)$r['last_reminder_at']) : 0;
        if ($last && $now - $last < $repeat) {
            continue;
        }
        $a = users()[$r['author']] ?? null;
        $to = [];
        if ($a && filter_var($a['email'], FILTER_VALIDATE_EMAIL)) {
            $to[] = $a['email'];
        }
        $tpl = $b['mail_templates']['reminder'];
        $vars = [
            'author_name' => $a['name'] ?? (string)$r['author'], 'label' => $label,
            'created' => fmt_local((string)$r['created_at']),
            'expiry_phrase' => $now < $vu ? 'läuft am ' . fmt_local((string)$r['valid_until']) . ' Uhr ab'
                : 'ist seit ' . fmt_local((string)$r['valid_until']) . ' Uhr abgelaufen',
            'change_url' => $base . '/change.php',
        ];
        $subject = trim(render_tpl($tpl['subject'], $vars));
        $body = render_tpl($tpl['body'], $vars);
        $res = mail_deliver(['to' => $to, 'cc' => $cc1 !== '' ? [$cc1] : [], 'subject' => $subject, 'body' => $body, 'priority' => true]);
        $sum = mail_record('reminder', (int)$r['id'], $subject, $body, $res);
        $okNow = $sum['ok'] > 0;
        db()->prepare('UPDATE ' . t('status') . ' SET reminder_count = reminder_count + ?, last_reminder_at = ? WHERE id = ?')
            ->execute([$okNow ? 1 : 0, gmdate('Y-m-d H:i:s', $now), $r['id']]);
        audit('mail.reminder', 'status:' . $r['id'], ['recipients' => $sum['total'], 'ok' => $sum['ok'], 'failed' => $sum['failed'],
            'count' => (int)$r['reminder_count'] + ($okNow ? 1 : 0)], 'system:cron', 0);
        $log[] = "Erinnerung für Status #{$r['id']} ($label): {$sum['ok']}/{$sum['total']} zugestellt";
    }

    // Aufräumen
    db()->prepare('DELETE FROM ' . t('login_attempt') . ' WHERE ts < ?')->execute([$now - 2 * 86400]);
    db()->prepare('DELETE FROM ' . t('totp_used') . ' WHERE step < ?')->execute([intdiv($now, 30) - 120]);

    // Täglicher Audit-Anker
    if (cfg('reminder.anchor_mail', true) && $cc1 !== '') {
        $day = gmdate('Y-m-d', $now);
        if (kv_get('anchor_day') !== $day) {
            $v = audit_verify();
            $tpl = $b['mail_templates']['anchor'];
            $vars = ['date' => $day, 'verify' => $v['ok'] ? 'OK' : 'FEHLER: ' . $v['error'], 'count' => $v['count'], 'head' => $v['head']];
            $subject = trim(render_tpl($tpl['subject'], $vars));
            $body = render_tpl($tpl['body'], $vars);
            $res = mail_deliver(['to' => [$cc1], 'subject' => $subject, 'body' => $body]);
            $sum = mail_record('anchor', null, $subject, $body, $res);
            if ($sum['ok'] > 0) {
                kv_set('anchor_day', $day);
            }
            $log[] = 'Audit-Anker: ' . ($v['ok'] ? 'Kette OK' : 'KETTE DEFEKT') . " ({$v['count']} Einträge)";
        }
    }
    return $log;
}

/* ====================================================================== */
/* HTML-Layout (Bootstrap 5.3 lokal, nur CSS, ohne JavaScript)            */
/* ====================================================================== */

const SBCM_BOOTSTRAP = '5.3.8';

function asset_url(string $file): string
{
    $v = $file === 'bootstrap.min.css' ? SBCM_BOOTSTRAP : (string)(@filemtime(__DIR__ . '/assets/' . $file) ?: SBCM_VERSION);
    return 'assets/' . $file . '?v=' . rawurlencode($v);
}

function page_start(string $title, array $o = []): void
{
    echo "<!doctype html>\n<html lang=\"de\"><head><meta charset=\"utf-8\">";
    echo '<meta name="viewport" content="width=device-width, initial-scale=1">';
    echo '<meta name="robots" content="noindex,nofollow,noarchive,nosnippet">';
    if (!empty($o['refresh'])) {
        echo '<meta http-equiv="refresh" content="' . (int)$o['refresh'] . '">';
    }
    echo '<title>' . h($title) . '</title>';
    echo '<link rel="stylesheet" href="' . h(asset_url('bootstrap.min.css')) . '">';
    echo '<link rel="stylesheet" href="' . h(asset_url('app.css')) . '">';
    echo '</head><body class="bg-body-tertiary"><main class="container app-wrap py-3">';
}

function page_end(): void
{
    echo '</main></body></html>';
}

function nav(string $active, bool $showLogout = true): void
{
    echo '<header class="d-flex flex-wrap align-items-center gap-2 mb-3 pb-2 border-bottom">';
    echo '<p class="app-title fw-bold me-auto">' . h((string)cfg('app.title', 'Status')) . '</p>';
    echo '<nav class="nav nav-pills">';
    foreach (['status' => ['status.php', 'Status'], 'change' => ['change.php', 'Einstellungen']] as $k => [$href, $label]) {
        echo '<a class="nav-link py-1 px-2' . ($active === $k ? ' active" aria-current="page' : '') . '" href="' . $href . '">' . $label . '</a>';
    }
    echo '</nav>';
    if ($showLogout) {
        echo '<form method="post" action="index.php" class="m-0">' . csrf_field()
            . '<input type="hidden" name="action" value="logout"><button class="btn btn-outline-secondary btn-sm" type="submit">Abmelden</button></form>';
    }
    echo '</header>';
}

function alert_class(string $type): string
{
    return ['ok' => 'success', 'err' => 'danger', 'warn' => 'warning', 'info' => 'info'][$type] ?? 'secondary';
}

function render_flash(): void
{
    foreach (flash_take() as [$type, $msg]) {
        echo '<div class="alert alert-' . alert_class((string)$type) . '" role="status">' . h($msg) . '</div>';
    }
}

function severity_label(string $sev): string
{
    return (string)(bcm()['severity_labels'][$sev] ?? $sev);
}

function severity_badge(string $sev): string
{
    $c = ['ok' => 'success', 'info' => 'primary', 'warn' => 'warning', 'critical' => 'danger'][$sev] ?? 'secondary';
    return '<span class="badge text-bg-' . $c . ' text-uppercase">' . h(severity_label($sev)) . '</span>';
}

/** Statuskarte. $detail = true: zusätzlich Autor, ALARM-Mail, Notiz (nur Stufe 2). */
function render_status_card(?array $row, bool $detail = false): void
{
    $b = bcm();
    if (!$row || empty($row['payload'])) {
        $def = $b['by_key'][$b['default_status']];
        $p = build_payload($def, []);
        $row = ['payload' => $p, 'created_at' => null, 'valid_until' => null, 'mac_ok' => true, 'author' => '–', 'alarm_mail' => 0];
    }
    $p = $row['payload'];
    $sev = $p['severity'];
    echo '<section class="card shadow-sm mb-3 status-card sev-' . h($sev) . '"><div class="card-body">';
    echo '<div class="d-flex flex-wrap gap-1 mb-2">' . severity_badge($sev);
    if (!empty($p['exercise'])) {
        echo '<span class="badge text-bg-dark text-uppercase">Übung</span>';
    }
    echo '</div>';
    echo '<h2 class="status-label mb-2">' . h($p['label']) . '</h2>';
    echo '<p class="mb-3">' . nl2br(h($p['text'])) . '</p>';
    if (!empty($p['locations'])) {
        echo '<h3 class="h6 text-body-secondary mb-2">Betroffene Standorte · Rufnummer für Rückfragen</h3><ul class="list-group mb-3">';
        foreach ($p['locations'] as $l) {
            echo '<li class="list-group-item d-flex flex-wrap justify-content-between gap-1"><span>' . h($l['name']) . '</span>'
                . '<a class="tel" href="' . h(tel_href($l['phone'])) . '">' . h($l['phone']) . '</a></li>';
        }
        echo '</ul>';
    } elseif ($sev !== 'ok') {
        echo '<p>Rückfragen: <a class="tel" href="' . h(tel_href($p['default_phone'])) . '">' . h($p['default_phone']) . '</a></p>';
    }
    echo '<p class="small text-body-secondary mb-0">Stand: ' . h(fmt_local($row['created_at'])) . ' Uhr';
    if (!empty($row['valid_until'])) {
        echo '<br>Gültig bis: ' . h(fmt_local($row['valid_until'])) . ' Uhr';
    }
    echo '</p>';
    if (!empty($row['valid_until']) && utc_ts((string)$row['valid_until']) < time()) {
        echo '<div class="alert alert-warning mt-3 mb-0">Die angegebene Gültigkeit ist überschritten. Die Aktualität wird derzeit geprüft.</div>';
    }
    if (empty($row['mac_ok'])) {
        echo '<div class="alert alert-warning mt-3 mb-0">Diese Meldung konnte nicht verifiziert werden. Bitte nutzen Sie bei Fragen die Rufnummer '
            . h($p['default_phone']) . '.</div>';
    }
    if ($detail) {
        echo '<p class="small text-body-secondary mt-2 mb-0">Gesetzt von: ' . h((string)($row['author'] ?? '–')) . ' · ALARM-Mail: '
            . (!empty($row['alarm_mail']) ? 'ja' : 'nein');
        if (!empty($p['note'])) {
            echo ' · interne Notiz: ' . h($p['note']);
        }
        echo '</p>';
    }
    echo '</div></section>';
}
