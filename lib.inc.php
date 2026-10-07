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

const SBCM_VERSION = '1.5.0';
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

/**
 * Status-Katalog aus config.json – validiert und normalisiert. Standorte kommen aus dem Browser (System), sobald dort
 * welche gespeichert sind, sonst aus config.json. $raw = true: nur config.json (ohne Browser-Standorte).
 */
function bcm(bool $reload = false, bool $raw = false): array
{
    static $j = null;
    static $b = null;
    if ($reload) {
        $b = null;
    }
    if ($j === null) {
        $path = (string)cfg('app.json_path', __DIR__ . '/config.json');
        $rawText = @file_get_contents($path);
        if ($rawText === false) {
            throw new RuntimeException('config.json nicht lesbar');
        }
        $j = json_decode($rawText, true, 64, JSON_THROW_ON_ERROR);
        $errs = bcm_validate($j);
        if ($errs) {
            $j = null;
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
        // Vorlage für die Ende-Mail (ältere config.json haben sie noch nicht)
        $j['mail_templates']['alarm_end'] ??= ['subject' => '{prefix}Statusmeldung beendet: {label}', 'body' => [
            '{prefix}Die Statusmeldung "{label}" ist nicht mehr gültig (zurückgenommen bzw. gelöst).', '', '{locations}',
            'Aktuelle Informationen (Anmeldung erforderlich): {url}', '', 'Diese Nachricht wurde automatisch erstellt. Bitte nicht antworten.']];
        $j['locations_by_id'] = [];
        foreach ($j['locations'] ?? [] as $l) {
            $l['phone'] = trim((string)($l['phone'] ?? ''));
            $j['locations_by_id'][$l['id']] = $l;
        }
    }
    if ($raw) {
        return $j;
    }
    if ($b === null) {
        $b = $j;
        $dp = setting_get('default_phone');
        if (is_string($dp) && trim($dp) !== '') {
            $b['default_phone'] = trim($dp);
        }
        $web = setting_get('locations');
        if (is_array($web)) {
            $b['locations'] = [];
            $b['locations_by_id'] = [];
            foreach (locations_all() as $l) {
                unset($l['emails']); // Adressen nie über den Katalog weiterreichen
                $b['locations'][] = $l;
                $b['locations_by_id'][$l['id']] = $l;
            }
        }
    }
    return $b;
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
        if (isset($s['phone']) && (!is_string($s['phone']) || !preg_match('/^[0-9+ ()\/-]{3,40}$/', $s['phone']))) {
            $e[] = "$k: phone ungültig (nur Ziffern, +, Leerzeichen, ()/-)";
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
        throw new RuntimeException('security.master_key fehlt/ungültig – Einrichtung über install.php (oder "php setup.php init")');
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
            $pdo->query('SELECT 1 FROM ' . t('account') . ' LIMIT 1')->fetchAll();
        } catch (Throwable $e) {
            install_schema($pdo);
        }
        schema_upgrade($pdo);
    }
    return $pdo;
}

/**
 * Version 1.3: mehrere gleichzeitige Meldungen (Spalte msg_id). Beim Nachrüsten wird die bisherige Länge des
 * Protokolls gemerkt: Ältere Statuseinträge galten noch "einer löst den anderen ab" (siehe status_board()).
 */
function schema_upgrade(PDO $pdo): void
{
    try {
        $pdo->query('SELECT msg_id FROM ' . t('status') . ' LIMIT 1')->fetchAll();
    } catch (Throwable $e) {
        try {
            $pdo->exec('ALTER TABLE ' . t('status') . ' ADD COLUMN msg_id BIGINT NULL');
        } catch (Throwable $e2) {
            error_log('Status-BCM: ALTER TABLE fehlgeschlagen: ' . $e2->getMessage());
            throw new SbcmSetupError('Datenbank-Update auf Version ' . SBCM_VERSION . ' nicht möglich: Dem Datenbank-Benutzer fehlt das Recht ALTER. '
                . 'Bitte im Kundenmenü des Hosters für diesen Benutzer ALTER erlauben (oder in phpMyAdmin ausführen: ALTER TABLE '
                . t('status') . ' ADD COLUMN msg_id BIGINT NULL;) und die Seite neu laden.');
        }
    }
    // Stichtag nur einmal festhalten (auch wenn die Spalte von Hand angelegt wurde): Bis hier galt "eine Meldung"
    $q = $pdo->prepare('SELECT v FROM ' . t('kv') . ' WHERE k = ?');
    $q->execute(['multi_since_seq']);
    if ($q->fetchColumn() === false) {
        $seq = (int)$pdo->query('SELECT COALESCE(MAX(seq), 0) FROM ' . t('audit'))->fetchColumn();
        try {
            $pdo->prepare('INSERT INTO ' . t('kv') . ' (k, v) VALUES (?, ?)')->execute(['multi_since_seq', (string)$seq]);
        } catch (Throwable $e) {
            // gleichzeitiger Aufruf hat den Wert schon gesetzt
        }
    }
}

/** Fehler, deren Text Betreiber ohne Kommandozeile direkt im Browser sehen sollen (keine Geheimnisse darin). */
class SbcmSetupError extends RuntimeException
{
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
    $ac = t('account');

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
                closed_at CHAR(19) NULL, closed_by VARCHAR(64) NULL, msg_id BIGINT NULL,
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
            "CREATE TABLE IF NOT EXISTS $ac (
                id VARCHAR(32) NOT NULL, name VARCHAR(100) NOT NULL, email_enc TEXT NOT NULL, pw_hash VARCHAR(255) NOT NULL,
                totp_enc TEXT NOT NULL, role VARCHAR(12) NOT NULL, active TINYINT NOT NULL DEFAULT 1, must_change TINYINT NOT NULL DEFAULT 1,
                pw_set_at CHAR(19) NULL, pw_valid_until CHAR(19) NULL, pw_reminder_at CHAR(19) NULL,
                created_at CHAR(19) NOT NULL, created_by VARCHAR(64) NOT NULL, updated_at CHAR(19) NOT NULL, row_mac CHAR(64) NOT NULL,
                PRIMARY KEY (id)
            )$tail",
        ];
        $triggers = [
            "CREATE TRIGGER {$a}_no_upd BEFORE UPDATE ON $a FOR EACH ROW SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'audit is append-only'",
            "CREATE TRIGGER {$a}_no_del BEFORE DELETE ON $a FOR EACH ROW SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'audit is append-only'",
            "CREATE TRIGGER {$s}_no_del BEFORE DELETE ON $s FOR EACH ROW SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'status history is append-only'",
            "CREATE TRIGGER {$ac}_no_del BEFORE DELETE ON $ac FOR EACH ROW SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'accounts are deactivated, not deleted'",
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
                closed_at TEXT NULL, closed_by TEXT NULL, msg_id INTEGER NULL
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
            "CREATE TABLE IF NOT EXISTS $ac (
                id TEXT NOT NULL PRIMARY KEY, name TEXT NOT NULL, email_enc TEXT NOT NULL, pw_hash TEXT NOT NULL, totp_enc TEXT NOT NULL,
                role TEXT NOT NULL, active INTEGER NOT NULL DEFAULT 1, must_change INTEGER NOT NULL DEFAULT 1,
                pw_set_at TEXT NULL, pw_valid_until TEXT NULL, pw_reminder_at TEXT NULL,
                created_at TEXT NOT NULL, created_by TEXT NOT NULL, updated_at TEXT NOT NULL, row_mac TEXT NOT NULL
            )",
        ];
        $triggers = [
            "CREATE TRIGGER {$a}_no_upd BEFORE UPDATE ON $a BEGIN SELECT RAISE(ABORT, 'audit is append-only'); END",
            "CREATE TRIGGER {$a}_no_del BEFORE DELETE ON $a BEGIN SELECT RAISE(ABORT, 'audit is append-only'); END",
            "CREATE TRIGGER {$s}_no_del BEFORE DELETE ON $s BEGIN SELECT RAISE(ABORT, 'status history is append-only'); END",
            "CREATE TRIGGER {$ac}_no_del BEFORE DELETE ON $ac BEGIN SELECT RAISE(ABORT, 'accounts are deactivated, not deleted'); END",
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
/* Im Browser gepflegte Einstellungen                                     */
/* ====================================================================== */

/*
 * Werte, die Admins ohne Kommandozeile ändern (Zugangspasswort Stufe 1, ALARM-Empfänger, cc_default_mail1), liegen
 * in der Tabelle kv, verschlüsselt mit AES-256-GCM und dem Schlüsselnamen als Kontext. Wer nur die Datenbank
 * kontrolliert, kann sie weder lesen noch fälschen oder zwischen Schlüsseln vertauschen. Werte aus
 * config.local.inc.php gelten weiter als Rückfall (Empfänger: zusätzlich).
 */
function setting_get(string $k, bool $reload = false)
{
    static $cache = [];
    if ($reload) {
        $cache = [];
        return null;
    }
    if (array_key_exists($k, $cache)) {
        return $cache[$k];
    }
    try {
        $raw = kv_get('set:' . $k);
    } catch (Throwable $e) {
        return null; // Datenbank (noch) nicht erreichbar: Rückfall auf die Konfigurationsdatei
    }
    if ($raw === null) {
        return $cache[$k] = null;
    }
    try {
        $v = json_decode(dec($raw, 'setting:' . $k, 'settings'), true, 16, JSON_THROW_ON_ERROR);
    } catch (Throwable $e) {
        error_log('Status-BCM: Einstellung ' . $k . ' nicht lesbar (Integritätsfehler?)');
        $v = null;
    }
    return $cache[$k] = $v;
}

function setting_set(string $k, $v): void
{
    kv_set('set:' . $k, enc(json_enc($v), 'setting:' . $k, 'settings'));
    setting_get($k, true);
    if ($k === 'locations' || $k === 'default_phone') {
        bcm(true);
    }
}

/** Einstellung, deren Eintrag in kv vorhanden, aber nicht entschlüsselbar ist (Manipulation, falscher Master-Key). */
function setting_broken(string $k): bool
{
    try {
        $raw = kv_get('set:' . $k);
        if ($raw === null) {
            return false;
        }
        dec($raw, 'setting:' . $k, 'settings');
        return false;
    } catch (Throwable $e) {
        return true;
    }
}

function stage1_hash(): string
{
    $s = setting_get('stage1');
    return is_array($s) && !empty($s['hash']) ? (string)$s['hash'] : (string)cfg('auth.stage1_hash', '');
}

function stage1_set_at(): string
{
    $s = setting_get('stage1');
    return is_array($s) && !empty($s['hash']) ? (string)($s['set_at'] ?? '') : (string)cfg('auth.stage1_set_at', '');
}

/** Zugangspasswort Stufe 1 setzen (Browser oder CLI). Rückgabe: Fehlerliste. */
function stage1_change(string $pw, string $pw2, string $actor, array $how = []): array
{
    $e = [];
    if (mb_strlen($pw) < 10 || strlen($pw) > 1000) {
        $e[] = 'Das Zugangspasswort muss mindestens 10 Zeichen lang sein.';
    }
    if (!hash_equals($pw, $pw2)) {
        $e[] = 'Die Eingaben stimmen nicht überein.';
    }
    if (!$e && password_verify($pw, stage1_hash())) {
        $e[] = 'Das neue Zugangspasswort muss sich vom bisherigen unterscheiden.';
    }
    if ($e) {
        return $e;
    }
    tx(function () use ($pw, $actor, $how) {
        setting_set('stage1', ['hash' => password_hash($pw, PASSWORD_DEFAULT), 'set_at' => now_utc()]);
        kv_set('stage1_reminder_ts', '0');
        audit('setting.stage1', 'stage1', ['how' => $how], $actor, str_starts_with($actor, 'system:') ? 0 : 2);
    });
    return [];
}

/** Benutzername des gemeinsamen Zugangs (Stufe 1), z. B. "Unternehmen". Vergleich ohne Groß-/Kleinschreibung. */
function stage1_user(): string
{
    $v = setting_get('stage1_user');
    return is_string($v) && $v !== '' ? $v : (string)cfg('auth.stage1_user', 'zugang');
}

function login_name_key(string $name): string
{
    return mb_strtolower(trim($name));
}

/** Prüft einen Benutzernamen für den gemeinsamen Zugang. Rückgabe: Fehlermeldung oder null. */
function stage1_user_check(string $name): ?string
{
    $name = trim($name);
    if (!preg_match('/^[\p{L}0-9._-]{2,40}$/u', $name)) {
        return 'Benutzername für den gemeinsamen Zugang: 2 bis 40 Zeichen, Buchstaben, Ziffern, Punkt, _ und - (keine Leerzeichen).';
    }
    if (isset(users()[login_name_key($name)])) {
        return 'Diesen Namen trägt bereits ein persönlicher Zugang. Bitte einen anderen Namen wählen.';
    }
    return null;
}

function stage1_user_change(string $name, string $actor, array $how = []): ?string
{
    if ($err = stage1_user_check($name)) {
        return $err;
    }
    $name = trim($name);
    tx(function () use ($name, $actor, $how) {
        setting_set('stage1_user', $name);
        audit('setting.stage1_user', 'stage1', ['how' => $how], $actor, setting_level($actor));
    });
    return null;
}

/** ALARM-Empfänger der Version 1.2 aus dem Browser (werden beim ersten Speichern der Alarmkreise übernommen). */
function recipients_web(): array
{
    $v = setting_get('recipients');
    return is_array($v) ? array_values(array_filter(array_map('strval', $v), fn($e) => filter_var($e, FILTER_VALIDATE_EMAIL))) : [];
}

/** Bisherige Empfänger (Browser 1.2 + config.local.inc.php) ohne Doppelte. */
function legacy_recipients(): array
{
    $out = [];
    foreach (recipients_web() as $e) {
        $out[$e] = $e;
    }
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

/** E-Mail-Liste aus Freitext (Zeilen, Komma, Semikolon). Rückgabe: [gültige, ungültige] */
function parse_email_list(string $text): array
{
    $ok = [];
    $bad = [];
    foreach (preg_split('/[\s,;]+/', strtolower($text), -1, PREG_SPLIT_NO_EMPTY) ?: [] as $m) {
        if (filter_var($m, FILTER_VALIDATE_EMAIL)) {
            $ok[$m] = $m;
        } else {
            $bad[] = $m;
        }
    }
    return [array_values($ok), $bad];
}

function slug_id(string $name, array $taken, string $fallback): string
{
    $map = ['ä' => 'ae', 'ö' => 'oe', 'ü' => 'ue', 'ß' => 'ss'];
    $id = trim((string)preg_replace('/[^a-z0-9]+/', '-', strtr(mb_strtolower($name), $map)), '-');
    $id = substr($id, 0, 24) ?: $fallback;
    $base = $id;
    for ($i = 2; in_array($id, $taken, true); $i++) {
        $id = $base . '-' . $i;
    }
    return $id;
}

function setting_level(string $actor): int
{
    return str_starts_with($actor, 'system:') ? 0 : 2;
}

/* ---- Alarmkreise (z. B. IT, BOA/Krisenstab, Leitung) -------------------- */

/** Liste [id, name, emails[]]. Ohne gespeicherte Kreise: bisherige Empfänger als Kreis "Allgemein". */
function alarm_circles(): array
{
    $v = setting_get('circles');
    if (!is_array($v)) {
        return [['id' => 'allgemein', 'name' => 'Allgemein', 'emails' => legacy_recipients(), 'signal' => [], 'groupalarm' => '']];
    }
    $out = [];
    foreach ($v as $c) {
        if (is_array($c) && preg_match('/^[a-z0-9-]{1,32}$/', (string)($c['id'] ?? ''))) {
            $out[] = ['id' => (string)$c['id'], 'name' => (string)($c['name'] ?? $c['id']),
                'emails' => array_values(array_filter(array_map('strval', (array)($c['emails'] ?? [])), fn($e) => filter_var($e, FILTER_VALIDATE_EMAIL))),
                'signal' => array_values(array_filter(array_map(fn($r) => signal_recipient((string)$r), (array)($c['signal'] ?? [])))),
                'groupalarm' => preg_match('/^[0-9]{1,12}$/', (string)($c['groupalarm'] ?? '')) ? (string)$c['groupalarm'] : ''];
        }
    }
    return $out;
}

/** Alle ALARM-Adressen aller Kreise (für Prüfung und Hinweise). */
function alarm_recipients(): array
{
    $out = [];
    foreach (alarm_circles() as $c) {
        foreach ($c['emails'] as $e) {
            $out[$e] = $e;
        }
    }
    return array_values($out);
}

function circles_store(array $circles, string $action, array $details, string $actor, array $how): void
{
    tx(function () use ($circles, $action, $details, $actor, $how) {
        setting_set('circles', array_values($circles));
        audit('setting.' . $action, 'circles', $details + ['how' => $how], $actor, setting_level($actor));
    });
}

function circle_create(string $name, string $emails, string $actor, array $how = []): ?string
{
    $name = trim(preg_replace('/[\x00-\x1F\x7F]+/u', ' ', $name) ?? '');
    if ($name === '' || mb_strlen($name) > 40) {
        return 'Name des Kreises: 1 bis 40 Zeichen.';
    }
    [$ok, $bad] = parse_email_list($emails);
    if ($bad) {
        return 'Ungültige Adresse(n): ' . implode(', ', array_map('mask_email', $bad));
    }
    $c = alarm_circles();
    if (in_array(mb_strtolower($name), array_map(fn($x) => mb_strtolower($x['name']), $c), true)) {
        return 'Einen Kreis mit diesem Namen gibt es schon.';
    }
    $id = slug_id($name, array_column($c, 'id'), 'kreis');
    $c[] = ['id' => $id, 'name' => $name, 'emails' => $ok, 'signal' => [], 'groupalarm' => ''];
    circles_store($c, 'circle_create', ['circle' => $name, 'count' => count($ok)], $actor, $how);
    return null;
}

/** Adressen eines Kreises ergänzen ($add) bzw. entfernen ($remove = Positionen). */
function circle_update(string $id, string $add, array $remove, string $actor, array $how = []): ?string
{
    $c = alarm_circles();
    $i = array_search($id, array_column($c, 'id'), true);
    if ($i === false) {
        return 'Kreis nicht gefunden.';
    }
    [$ok, $bad] = parse_email_list($add);
    if ($bad) {
        return 'Ungültige Adresse(n): ' . implode(', ', array_map('mask_email', $bad));
    }
    $gone = [];
    foreach ($remove as $r) {
        if (isset($c[$i]['emails'][(int)$r])) {
            $gone[] = $c[$i]['emails'][(int)$r];
        }
    }
    $new = array_values(array_diff($ok, $c[$i]['emails']));
    if (!$new && !$gone) {
        return 'Keine Änderung (Adressen bereits vorhanden oder nichts ausgewählt).';
    }
    $c[$i]['emails'] = array_values(array_merge(array_diff($c[$i]['emails'], $gone), $new));
    circles_store($c, 'circle_update', ['circle' => $c[$i]['name'], 'masked' => array_merge(
        array_map(fn($e) => '+' . mask_email($e), $new), array_map(fn($e) => '-' . mask_email($e), $gone))], $actor, $how);
    return null;
}

function circle_delete(string $id, string $actor, array $how = []): ?string
{
    $c = alarm_circles();
    $i = array_search($id, array_column($c, 'id'), true);
    if ($i === false) {
        return 'Kreis nicht gefunden.';
    }
    $name = $c[$i]['name'];
    array_splice($c, $i, 1);
    circles_store($c, 'circle_delete', ['circle' => $name], $actor, $how);
    return null;
}

/* ====================================================================== */
/* Selbstüberwachung: Cron-Ausfall erkennen                               */
/* ====================================================================== */

/** Minuten seit dem letzten Cron-Lauf; null = noch nie gelaufen. */
function cron_age_minutes(?int $now = null): ?int
{
    $last = (int)(kv_get('cron_last') ?? 0);
    return $last > 0 ? intdiv(($now ?? time()) - $last, 60) : null;
}

function cron_stale(?int $now = null): bool
{
    $age = cron_age_minutes($now);
    return $age !== null && $age >= max(5, (int)cfg('monitor.cron_stale_minutes', 15));
}

/**
 * Wird bei Seitenaufrufen ausgeführt: Läuft der Cron nicht mehr, geht höchstens alle monitor.warn_repeat_minutes
 * eine Warnmail an cc_default_mail1 (der Cron selbst kann seinen eigenen Ausfall nicht melden).
 */
function monitor_tick(): void
{
    try {
        if (!cron_stale()) {
            return;
        }
        $repeat = max(10, (int)cfg('monitor.warn_repeat_minutes', 60)) * 60;
        $last = (int)(kv_get('cron_warn_ts') ?? 0);
        $cc1 = cc_default_mail1();
        if (time() - $last < $repeat || $cc1 === '') {
            return;
        }
        kv_set('cron_warn_ts', (string)time());
        $age = (int)cron_age_minutes();
        $subject = 'Warnung: Cron läuft nicht (' . (string)cfg('app.title', 'Status') . ')';
        $body = "Der Cron der Statusseite ist seit $age Minuten nicht gelaufen.\n"
            . "Ohne Cron gibt es keine Erinnerungen bei Ablauf von Meldungen und keinen täglichen Audit-Anker.\n\n"
            . "Bitte den Cronjob beim Hoster prüfen (Adresse unter System).\n" . rtrim((string)cfg('app.base_url'), '/') . "/system.php\n";
        $sum = mail_record('monitor', null, $subject, $body, mail_deliver(['to' => [$cc1], 'subject' => $subject, 'body' => $body, 'priority' => true]));
        audit('monitor.cron_stale', 'cron', ['minutes' => $age, 'ok' => $sum['ok'], 'failed' => $sum['failed']], 'system:monitor', 0);
    } catch (Throwable $e) {
        error_log('Status-BCM: Überwachung: ' . $e->getMessage());
    }
}

/* ====================================================================== */
/* Weitere Alarmkanäle: Signal (signal-cli-rest-api), GroupAlarm          */
/* ====================================================================== */

/** Normalisiert einen Signal-Empfänger (+49… oder group.…). null = ungültig. */
function signal_recipient(string $r): ?string
{
    $r = trim($r);
    if (str_starts_with($r, 'group.')) {
        return preg_match('/^group\.[A-Za-z0-9+\/=_-]{8,200}$/', $r) ? $r : null;
    }
    $n = preg_replace('/[\s\/()-]+/', '', $r) ?? '';
    if (str_starts_with($n, '00')) {
        $n = '+' . substr($n, 2);
    }
    return preg_match('/^\+[1-9][0-9]{6,14}$/', $n) ? $n : null;
}

function mask_phone(string $r): string
{
    if (str_starts_with($r, 'group.')) {
        return 'group.' . substr($r, 6, 3) . '…';
    }
    return substr($r, 0, 4) . str_repeat('*', max(2, strlen($r) - 6)) . substr($r, -2);
}

function channel_enabled(string $ch): bool
{
    if ($ch === 'signal') {
        return (string)cfg('channels.signal.url', '') !== '' && (string)cfg('channels.signal.number', '') !== '';
    }
    if ($ch === 'groupalarm') {
        return (string)cfg('channels.groupalarm.token', '') !== '' && (int)cfg('channels.groupalarm.organization_id', 0) > 0;
    }
    return false;
}

/** Signal-Empfänger und GroupAlarm-Szenarien der gewählten Kreise. */
function channel_targets(array $spec): array
{
    $sig = [];
    $ga = [];
    foreach (alarm_circles() as $c) {
        if (in_array($c['id'], (array)($spec['circles'] ?? []), true)) {
            foreach ($c['signal'] as $r) {
                $sig[$r] = $r;
            }
            if ($c['groupalarm'] !== '') {
                $ga[$c['groupalarm']] = $c['name'];
            }
        }
    }
    return ['signal' => array_values($sig), 'groupalarm' => $ga];
}

/** HTTPS-POST mit JSON (ohne Weiterleitungen, mit Zertifikatsprüfung). Rückgabe: [HTTP-Status, Antwort, Fehler] */
function http_post_json(string $url, array $body, array $headers): array
{
    $p = parse_url($url);
    $host = strtolower((string)($p['host'] ?? ''));
    $local = in_array($host, ['localhost', '127.0.0.1', '::1'], true);
    if (!$p || !in_array($p['scheme'] ?? '', $local ? ['https', 'http'] : ['https'], true)) {
        return [0, '', 'nur https:// erlaubt'];
    }
    $json = json_encode($body, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
    $headers[] = 'Content-Type: application/json';
    $timeout = max(2, (int)cfg('channels.timeout', 10));
    if (function_exists('curl_init')) {
        $ch = curl_init($url);
        curl_setopt_array($ch, [CURLOPT_POST => true, CURLOPT_POSTFIELDS => $json, CURLOPT_HTTPHEADER => $headers,
            CURLOPT_RETURNTRANSFER => true, CURLOPT_FOLLOWLOCATION => false, CURLOPT_TIMEOUT => $timeout, CURLOPT_CONNECTTIMEOUT => 5,
            CURLOPT_SSL_VERIFYPEER => true, CURLOPT_SSL_VERIFYHOST => 2, CURLOPT_PROTOCOLS => CURLPROTO_HTTPS | ($local ? CURLPROTO_HTTP : 0)]);
        $resp = curl_exec($ch);
        $code = (int)curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
        $err = $resp === false ? curl_error($ch) : '';
        curl_close($ch);
        return [$code, (string)$resp, $err];
    }
    $ctx = stream_context_create(['http' => ['method' => 'POST', 'header' => implode("\r\n", $headers), 'content' => $json,
        'timeout' => $timeout, 'follow_location' => 0, 'ignore_errors' => true], 'ssl' => ['verify_peer' => true, 'verify_peer_name' => true]]);
    $resp = @file_get_contents($url, false, $ctx);
    $code = 0;
    foreach ($http_response_header ?? [] as $h) {
        if (preg_match('#^HTTP/\S+ (\d{3})#', $h, $m)) {
            $code = (int)$m[1];
        }
    }
    return [$code, (string)$resp, $resp === false ? 'Verbindung fehlgeschlagen' : ''];
}

/** Ein Kanal-Aufruf: im Testmodus nur nach storage/outbox schreiben (Zugangsdaten geschwärzt). */
function channel_call(string $channel, string $url, array $body, array $headers): array
{
    $mode = (string)cfg('channels.transport', '');
    if ($mode === '') {
        $mode = (string)cfg('mail.transport', 'smtp') === 'log' ? 'log' : 'http';
    }
    if ($mode === 'log') {
        $dir = storage_dir() . '/outbox';
        @mkdir($dir, 0700, true);
        $red = array_map(fn($h) => preg_replace('/^([^:]+):.*$/', '$1: ***', $h), $headers);
        file_put_contents($dir . '/' . gmdate('Ymd-His') . '-' . $channel . '-' . bin2hex(random_bytes(4)) . '.json',
            json_encode(['channel' => $channel, 'url' => $url, 'headers' => $red, 'body' => $body], JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES));
        return [200, '', ''];
    }
    return http_post_json($url, $body, $headers);
}

/**
 * Alarm über Signal und GroupAlarm an die gewählten Kreise. Rückgabe je Kanal: [ok, failed] (nur eingerichtete Kanäle).
 * Inhalt wie die ALARM-Mail (Betreff + Text); Adressen/Nummern erscheinen im Protokoll nur als Anzahl.
 */
function send_alarm_channels(string $kind, int $statusId, string $subject, string $body, string $author, array $spec): array
{
    $t = channel_targets($spec);
    $out = [];
    $text = mb_substr($subject . "\n\n" . trim($body), 0, 2000);
    if ($t['signal'] && channel_enabled('signal')) {
        $h = [];
        if (($tok = cfg_secret((string)cfg('channels.signal.token', ''))) !== '') {
            $h[] = 'Authorization: Bearer ' . $tok;
        } elseif ((string)cfg('channels.signal.user', '') !== '') {
            $h[] = 'Authorization: Basic ' . base64_encode(cfg('channels.signal.user') . ':' . cfg_secret((string)cfg('channels.signal.pass', '')));
        }
        $ok = 0;
        $fail = 0;
        foreach (array_chunk($t['signal'], 20) as $chunk) {
            [$code, , $err] = channel_call('signal', (string)cfg('channels.signal.url'),
                ['message' => $text, 'number' => (string)cfg('channels.signal.number'), 'recipients' => $chunk], $h);
            if ($code >= 200 && $code < 300) {
                $ok += count($chunk);
            } else {
                $fail += count($chunk);
                error_log('Status-BCM: Signal-Versand fehlgeschlagen (HTTP ' . $code . ($err !== '' ? ', ' . $err : '') . ')');
            }
        }
        $out['signal'] = [$ok, $fail];
    }
    $kinds = (array)cfg('channels.groupalarm.kinds', ['new', 'update', 'end']);
    if ($t['groupalarm'] && channel_enabled('groupalarm') && in_array($kind, $kinds, true)) {
        $ok = 0;
        $fail = 0;
        foreach (array_keys($t['groupalarm']) as $scenario) {
            [$code, , $err] = channel_call('groupalarm', (string)cfg('channels.groupalarm.url', 'https://app.groupalarm.com/api/v1/alarm'), [
                'eventName' => mb_substr($subject, 0, 100), 'message' => $text, 'mode' => (string)cfg('channels.groupalarm.mode', 'best-effort'),
                'organizationID' => (int)cfg('channels.groupalarm.organization_id'), 'scenarioID' => (int)$scenario,
                'startTime' => gmdate('Y-m-d\TH:i:s\Z'),
            ], ['Personal-Access-Token: ' . cfg_secret((string)cfg('channels.groupalarm.token'))]);
            if ($code >= 200 && $code < 300) {
                $ok++;
            } else {
                $fail++;
                error_log('Status-BCM: GroupAlarm fehlgeschlagen (HTTP ' . $code . ($err !== '' ? ', ' . $err : '') . ')');
            }
        }
        $out['groupalarm'] = [$ok, $fail];
    }
    if ($out) {
        audit('channel.alarm', 'status:' . $statusId, ['kind' => $kind, 'channels' => array_map(fn($v) => ['ok' => $v[0], 'failed' => $v[1]], $out)],
            $author, setting_level($author));
    }
    return $out;
}

/** Signal-Empfänger und GroupAlarm-Szenario eines Kreises setzen. $removeSignal = Positionen. */
function circle_channels_set(string $id, string $addSignal, array $removeSignal, string $scenario, string $actor, array $how = []): ?string
{
    $c = alarm_circles();
    $i = array_search($id, array_column($c, 'id'), true);
    if ($i === false) {
        return 'Kreis nicht gefunden.';
    }
    $new = [];
    foreach (preg_split('/[\r\n,;]+/', $addSignal, -1, PREG_SPLIT_NO_EMPTY) ?: [] as $r) {
        if (trim($r) === '') {
            continue;
        }
        $n = signal_recipient($r);
        if ($n === null) {
            return 'Ungültiger Signal-Empfänger: Rufnummer im Format +49… oder Gruppen-ID group.…';
        }
        $new[$n] = $n;
    }
    $scenario = trim($scenario);
    if ($scenario !== '' && !preg_match('/^[0-9]{1,12}$/', $scenario)) {
        return 'GroupAlarm-Szenario: nur die Nummer (Ziffern).';
    }
    $gone = [];
    foreach ($removeSignal as $r) {
        if (isset($c[$i]['signal'][(int)$r])) {
            $gone[] = $c[$i]['signal'][(int)$r];
        }
    }
    $add = array_values(array_diff(array_values($new), $c[$i]['signal']));
    if (!$add && !$gone && $scenario === $c[$i]['groupalarm']) {
        return 'Keine Änderung.';
    }
    $c[$i]['signal'] = array_values(array_merge(array_diff($c[$i]['signal'], $gone), $add));
    $c[$i]['groupalarm'] = $scenario;
    circles_store($c, 'circle_channels', ['circle' => $c[$i]['name'], 'masked' => array_merge(
        array_map(fn($e) => '+' . mask_phone($e), $add), array_map(fn($e) => '-' . mask_phone($e), $gone)),
        'groupalarm' => $scenario], $actor, $how);
    return null;
}

/* ---- Standorte (Name, Durchwahl, E-Mail der Standortverwaltung) -------- */

/** Standorte inkl. E-Mail-Adressen: aus dem Browser (System) oder, solange dort nichts gespeichert ist, aus config.json. */
function locations_all(): array
{
    $v = setting_get('locations');
    $src = is_array($v) ? $v : (array)(bcm(false, true)['locations'] ?? []);
    $out = [];
    foreach ($src as $l) {
        if (!is_array($l) || !preg_match('/^[a-z0-9_-]{2,32}$/', (string)($l['id'] ?? '')) || trim((string)($l['name'] ?? '')) === '') {
            continue;
        }
        $out[] = ['id' => (string)$l['id'], 'name' => trim((string)$l['name']), 'phone' => trim((string)($l['phone'] ?? '')),
            'emails' => array_values(array_filter(array_map('strval', (array)($l['emails'] ?? [])), fn($e) => filter_var($e, FILTER_VALIDATE_EMAIL)))];
    }
    return $out;
}

function location_emails(string $id): array
{
    foreach (locations_all() as $l) {
        if ($l['id'] === $id) {
            return $l['emails'];
        }
    }
    return [];
}

function locations_store(array $locs, string $action, array $details, string $actor, array $how): void
{
    tx(function () use ($locs, $action, $details, $actor, $how) {
        setting_set('locations', array_values($locs));
        audit('setting.' . $action, 'locations', $details + ['how' => $how], $actor, setting_level($actor));
    });
    bcm(true);
}

/** Standort anlegen ($id = '') oder ändern. $remove = Positionen der zu entfernenden Adressen. */
function location_save(string $id, string $name, string $phone, string $add, array $remove, string $actor, array $how = []): ?string
{
    $name = trim(preg_replace('/[\x00-\x1F\x7F]+/u', ' ', $name) ?? '');
    $phone = trim($phone);
    if ($name === '' || mb_strlen($name) > 80) {
        return 'Name des Standorts: 1 bis 80 Zeichen.';
    }
    if ($hits = critical_terms_in($name, bcm())) {
        return 'Der Name enthält kritische Begriffe (' . implode(', ', $hits) . ').';
    }
    if ($phone !== '' && !preg_match('/^[0-9+ ()\/-]{3,40}$/', $phone)) {
        return 'Durchwahl: nur Ziffern, +, Leerzeichen, ( ) / -';
    }
    [$ok, $bad] = parse_email_list($add);
    if ($bad) {
        return 'Ungültige Adresse(n): ' . implode(', ', array_map('mask_email', $bad));
    }
    $locs = locations_all();
    if ($id === '') {
        $id = slug_id($name, array_column($locs, 'id'), 'standort');
        $id = strlen($id) < 2 ? $id . '-1' : $id;
        $locs[] = ['id' => $id, 'name' => $name, 'phone' => $phone, 'emails' => $ok];
        locations_store($locs, 'location_create', ['location' => $name, 'count' => count($ok)], $actor, $how);
        return null;
    }
    $i = array_search($id, array_column($locs, 'id'), true);
    if ($i === false) {
        return 'Standort nicht gefunden.';
    }
    $gone = [];
    foreach ($remove as $r) {
        if (isset($locs[$i]['emails'][(int)$r])) {
            $gone[] = $locs[$i]['emails'][(int)$r];
        }
    }
    $new = array_values(array_diff($ok, $locs[$i]['emails']));
    $before = $locs[$i]['name'];
    $locs[$i] = ['id' => $id, 'name' => $name, 'phone' => $phone,
        'emails' => array_values(array_merge(array_diff($locs[$i]['emails'], $gone), $new))];
    locations_store($locs, 'location_update', ['location' => $name, 'before' => $before !== $name ? $before : null, 'masked' => array_merge(
        array_map(fn($e) => '+' . mask_email($e), $new), array_map(fn($e) => '-' . mask_email($e), $gone))], $actor, $how);
    return null;
}

function location_delete(string $id, string $actor, array $how = []): ?string
{
    $locs = locations_all();
    $i = array_search($id, array_column($locs, 'id'), true);
    if ($i === false) {
        return 'Standort nicht gefunden.';
    }
    $name = $locs[$i]['name'];
    array_splice($locs, $i, 1);
    locations_store($locs, 'location_delete', ['location' => $name], $actor, $how);
    return null;
}

/* ---- Kontaktangaben (Notfallnummer, E-Mail, Videokonferenz) ------------- */

function contacts_all(): array
{
    $v = setting_get('contacts');
    return is_array($v) ? array_values(array_filter($v, fn($c) => is_array($c) && isset($c['id'], $c['name']))) : [];
}

/** Prüft und normalisiert eine Kontaktangabe. Rückgabe: [Kontakt|null, Fehler|null] */
function contact_normalize(array $in): array
{
    $c = [];
    foreach (['name' => 60, 'phone' => 40, 'email' => 120, 'platform' => 40, 'url' => 300, 'meeting' => 80] as $k => $max) {
        $c[$k] = trim(preg_replace('/[\x00-\x1F\x7F]+/u', ' ', (string)($in[$k] ?? '')) ?? '');
        if (mb_strlen($c[$k]) > $max) {
            return [null, "Feld $k ist zu lang (max. $max Zeichen)."];
        }
    }
    if ($c['name'] === '') {
        return [null, 'Bitte eine Bezeichnung angeben, z. B. "Krisenstab-Telefonkonferenz".'];
    }
    if ($c['phone'] === '' && $c['email'] === '' && $c['url'] === '' && $c['meeting'] === '') {
        return [null, 'Bitte mindestens Rufnummer, E-Mail, Link oder Konferenz-ID angeben.'];
    }
    if ($c['phone'] !== '' && !preg_match('/^[0-9+ ()\/-]{3,40}$/', $c['phone'])) {
        return [null, 'Rufnummer: nur Ziffern, +, Leerzeichen, ( ) / -'];
    }
    if ($c['email'] !== '' && !filter_var($c['email'], FILTER_VALIDATE_EMAIL)) {
        return [null, 'E-Mail-Adresse ungültig.'];
    }
    if ($c['url'] !== '' && (!str_starts_with(strtolower($c['url']), 'https://') || !filter_var($c['url'], FILTER_VALIDATE_URL))) {
        return [null, 'Link: nur vollständige https://-Adressen.'];
    }
    if ($c['meeting'] !== '' && !preg_match('/^[\p{L}0-9 #*:.,+\/_-]+$/u', $c['meeting'])) {
        return [null, 'Konferenz-ID/PIN: nur Buchstaben, Ziffern, Leerzeichen und # * : . , + / _ -'];
    }
    if ($hits = critical_terms_in($c['name'] . "\n" . $c['platform'], bcm())) {
        return [null, 'Die Bezeichnung enthält kritische Begriffe (' . implode(', ', $hits) . ').'];
    }
    $c['email'] = strtolower($c['email']);
    return [$c, null];
}

function contacts_store(array $list, string $action, array $details, string $actor, array $how): void
{
    tx(function () use ($list, $action, $details, $actor, $how) {
        setting_set('contacts', array_values($list));
        audit('setting.' . $action, 'contacts', $details + ['how' => $how], $actor, setting_level($actor));
    });
}

function contact_save(string $id, array $in, string $actor, array $how = []): ?string
{
    [$c, $err] = contact_normalize($in);
    if ($err) {
        return $err;
    }
    $list = contacts_all();
    if ($id === '') {
        $c['id'] = slug_id($c['name'], array_column($list, 'id'), 'kontakt');
        $list[] = $c;
        contacts_store($list, 'contact_create', ['contact' => $c['name']], $actor, $how);
        return null;
    }
    $i = array_search($id, array_column($list, 'id'), true);
    if ($i === false) {
        return 'Kontakt nicht gefunden.';
    }
    $c['id'] = $id;
    $list[$i] = $c;
    contacts_store($list, 'contact_update', ['contact' => $c['name']], $actor, $how);
    return null;
}

function contact_delete(string $id, string $actor, array $how = []): ?string
{
    $list = contacts_all();
    $i = array_search($id, array_column($list, 'id'), true);
    if ($i === false) {
        return 'Kontakt nicht gefunden.';
    }
    $name = $list[$i]['name'];
    array_splice($list, $i, 1);
    contacts_store($list, 'contact_delete', ['contact' => $name], $actor, $how);
    return null;
}

/* ---- Betreff-Präfixe der ALARM-Mail -------------------------------------- */

const SBCM_PREFIX_DEFAULTS = ['new' => '[ALARM]', 'update' => '[Aktualisierung]', 'end' => '[Ende]'];

function mail_prefixes(): array
{
    $v = setting_get('mail_prefix');
    $out = SBCM_PREFIX_DEFAULTS;
    foreach (array_keys($out) as $k) {
        if (is_array($v) && isset($v[$k]) && is_string($v[$k])) {
            $out[$k] = $v[$k];
        }
    }
    return $out;
}

function mail_prefixes_set(array $in, string $actor, array $how = []): ?string
{
    $new = [];
    foreach (array_keys(SBCM_PREFIX_DEFAULTS) as $k) {
        $p = trim(preg_replace('/[\x00-\x1F\x7F]+/u', ' ', (string)($in[$k] ?? '')) ?? '');
        if (mb_strlen($p) > 30) {
            return 'Präfixe: höchstens 30 Zeichen.';
        }
        if ($hits = critical_terms_in($p, bcm())) {
            return 'Präfix enthält kritische Begriffe (' . implode(', ', $hits) . ').';
        }
        $new[$k] = $p;
    }
    tx(function () use ($new, $actor, $how) {
        setting_set('mail_prefix', $new);
        audit('setting.mail_prefix', 'mail', ['prefixes' => $new, 'how' => $how], $actor, setting_level($actor));
    });
    return null;
}

/* ---- Versand: Adresse im An-Feld, zusätzliche Empfänger je Stufe, Standard-Rufnummer ---- */

const SBCM_LEVELS = ['info' => 'Information', 'warn' => 'Hinweis', 'critical' => 'Wichtiger Hinweis'];

/** Adresse im An-Feld der ALARM-Mails: unter System hinterlegt, sonst die Absenderadresse. Alle Kreise bekommen BCC. */
function alarm_to_address(): string
{
    $web = setting_get('alarm_to');
    if (is_string($web) && filter_var($web, FILTER_VALIDATE_EMAIL)) {
        return $web;
    }
    $from = strtolower(trim((string)cfg('mail.from_email', '')));
    return filter_var($from, FILTER_VALIDATE_EMAIL) ? $from : '';
}

/** Leere Eingabe = zurück auf die Absenderadresse. */
function alarm_to_change(string $mail, string $actor, array $how = []): ?string
{
    $mail = strtolower(trim($mail));
    if ($mail !== '' && !filter_var($mail, FILTER_VALIDATE_EMAIL)) {
        return 'Bitte eine gültige E-Mail-Adresse angeben (leer = Absenderadresse).';
    }
    tx(function () use ($mail, $actor, $how) {
        $before = alarm_to_address();
        setting_set('alarm_to', $mail);
        $after = alarm_to_address();
        audit('setting.alarm_to', 'mail', ['masked' => [$after !== '' ? mask_email($after) : '–'], 'before' => $before !== '' ? mask_email($before) : '–',
            'how' => $how], $actor, setting_level($actor));
    });
    return null;
}

/** Zusätzliche Empfänger (BCC) je Stufe: ['info' => [...], 'warn' => [...], 'critical' => [...]] */
function level_cc(): array
{
    $v = setting_get('level_cc');
    $out = [];
    foreach (SBCM_LEVELS as $k => $_) {
        $out[$k] = is_array($v) && is_array($v[$k] ?? null) ? array_values(array_filter($v[$k], fn($e) => is_string($e) && filter_var($e, FILTER_VALIDATE_EMAIL))) : [];
    }
    return $out;
}

function level_cc_update(string $sev, string $add, array $remove, string $actor, array $how = []): ?string
{
    if (!isset(SBCM_LEVELS[$sev])) {
        return 'Unbekannte Stufe.';
    }
    $all = level_cc();
    [$ok, $bad] = parse_email_list($add);
    if ($bad) {
        return 'Ungültige Adresse(n): ' . implode(', ', array_map('mask_email', $bad));
    }
    $gone = [];
    foreach ($remove as $r) {
        if (isset($all[$sev][(int)$r])) {
            $gone[] = $all[$sev][(int)$r];
        }
    }
    $new = array_values(array_diff($ok, $all[$sev]));
    if (!$new && !$gone) {
        return 'Keine Änderung (Adressen bereits vorhanden oder nichts ausgewählt).';
    }
    $all[$sev] = array_values(array_merge(array_diff($all[$sev], $gone), $new));
    tx(function () use ($all, $sev, $new, $gone, $actor, $how) {
        setting_set('level_cc', $all);
        audit('setting.level_cc', 'mail', ['level' => SBCM_LEVELS[$sev], 'masked' => array_merge(
            array_map(fn($e) => '+' . mask_email($e), $new), array_map(fn($e) => '-' . mask_email($e), $gone)), 'how' => $how], $actor, setting_level($actor));
    });
    return null;
}

/** Standard-Rufnummer: unter System hinterlegt, sonst default_phone aus config.json. */
function default_phone_change(string $phone, string $actor, array $how = []): ?string
{
    $phone = trim($phone);
    if ($phone !== '' && !preg_match('/^[0-9+ ()\/-]{3,40}$/', $phone)) {
        return 'Rufnummer: nur Ziffern, +, Leerzeichen, ( ) / -';
    }
    tx(function () use ($phone, $actor, $how) {
        $before = bcm()['default_phone'];
        setting_set('default_phone', $phone);
        audit('setting.default_phone', 'bcm', ['before' => $before, 'phone' => bcm()['default_phone'], 'how' => $how], $actor, setting_level($actor));
    });
    return null;
}

function cc1_change(string $mail, string $actor, array $how = []): ?string
{
    $mail = strtolower(trim($mail));
    if (!filter_var($mail, FILTER_VALIDATE_EMAIL)) {
        return 'Bitte eine gültige E-Mail-Adresse angeben.';
    }
    tx(function () use ($mail, $actor, $how) {
        $before = cc_default_mail1();
        setting_set('cc1', $mail);
        audit('setting.cc1', 'cc1', ['masked' => [mask_email($mail)], 'before' => $before !== '' ? mask_email($before) : '–', 'how' => $how],
            $actor, str_starts_with($actor, 'system:') ? 0 : 2);
    });
    return null;
}

/* ====================================================================== */
/* config.local.inc.php (Installer, CLI)                                  */
/* ====================================================================== */

function local_config_path(): string
{
    return getenv('SBCM_LOCAL_CONFIG') ?: (__DIR__ . '/config.local.inc.php');
}

function local_config_load(): array
{
    $p = local_config_path();
    if (!is_file($p)) {
        return [];
    }
    $a = require $p;
    return is_array($a) ? $a : [];
}

function local_config_code(array $a): string
{
    return "<?php\n// Status-BCM – lokale Konfiguration mit Geheimnissen (Master-Key!). NICHT committen, separat sichern, Rechte 0600.\n"
        . "if (!defined('SBCM')) { http_response_code(403); exit; }\nreturn " . var_export($a, true) . ";\n";
}

/** Schreibt config.local.inc.php atomar. false = Verzeichnis/Datei nicht beschreibbar (dann Download anbieten). */
function local_config_write(array $a): bool
{
    $p = local_config_path();
    $tmp = $p . '.tmp';
    if (@file_put_contents($tmp, local_config_code($a), LOCK_EX) === false) {
        return false;
    }
    @chmod($tmp, 0600);
    if (!@rename($tmp, $p)) {
        @unlink($tmp);
        return false;
    }
    if (function_exists('opcache_invalidate')) {
        @opcache_invalidate($p, true);
    }
    return true;
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
    // sitzung.php darf (nur) in eigene Seiten eingebettet werden: Anzeige der Abmeldezeit mit Verlängern-Knopf
    $frame = defined('SBCM_FRAMEABLE') && SBCM_FRAMEABLE;
    header('X-Frame-Options: ' . ($frame ? 'SAMEORIGIN' : 'DENY'));
    header('Referrer-Policy: no-referrer');
    header('Cross-Origin-Opener-Policy: same-origin');
    header('Permissions-Policy: geolocation=(), camera=(), microphone=()');
    // Nur eigene Stylesheets (Bootstrap + app.css), data:-SVGs für Bootstrap-Formularsymbole, kein JavaScript.
    header("Content-Security-Policy: default-src 'none'; style-src 'self'; img-src 'self' data:; form-action 'self'; frame-src 'self'; frame-ancestors " . ($frame ? "'self'" : "'none'") . "; base-uri 'none'");
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
    // Nur ansehen (sitzung.php per GET): zählt nicht als Aktivität
    if (!(defined('SBCM_SESSION_PEEK') && SBCM_SESSION_PEEK) || !isset($_SESSION['last'])) {
        $_SESSION['last'] = $now;
    }
}

/**
 * Wann endet die Anmeldung ohne weitere Aktivität? Liefert ['end' => Unix-Zeit, 'stage2' => bool] oder null.
 * Mit persönlicher Kennung zählt deren (kürzerer) Leerlauf, ohne die gemeinsame Anmeldung.
 */
function session_deadline(): ?array
{
    if (session_status() !== PHP_SESSION_ACTIVE || !stage1_ok() || !isset($_SESSION['last'], $_SESSION['born'])) {
        return null;
    }
    $end = min((int)$_SESSION['last'] + (int)cfg('auth.idle_minutes', 30) * 60, (int)$_SESSION['born'] + (int)cfg('auth.absolute_hours', 10) * 3600);
    $s2 = $_SESSION['s2'] ?? null;
    if (is_array($s2) && !empty($s2['u']) && isset($s2['t'])) {
        $e2 = (int)$s2['t'] + (int)cfg('auth.stage2_idle_minutes', 15) * 60;
        if ($e2 > time() && $e2 < $end) {
            return ['end' => $e2, 'stage2' => true];
        }
    }
    return ['end' => $end, 'stage2' => false];
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
        echo $e instanceof SbcmSetupError ? $e->getMessage() . "\n" : "Interner Fehler. Bitte später erneut versuchen.\n";
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

/**
 * Benutzer Stufe 2. Quellen:
 *  - Datenbank (Tabelle account; Verwaltung über admin.php bzw. `php setup.php add-user`). Jede Zeile trägt einen
 *    MAC mit dem Master-Key: Wer nur die Datenbank kontrolliert, kann keine Benutzer einschleusen oder Rollen ändern.
 *  - Altbestand aus config.local.inc.php (auth.users): immer Rolle admin, nur per CLI änderbar
 *    (`php setup.php migrate-users` überführt ihn in die Datenbank).
 * $all = true: auch deaktivierte Benutzer und Zeilen mit Integritätsfehler (nur für die Anzeige in admin.php).
 */
function users(bool $all = false, bool $reload = false): array
{
    static $cache = null;
    if ($cache === null || $reload) {
        $cache = [];
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
            $cache[$id] = [
                'name' => (string)($u['name'] ?? $id), 'email' => $email, 'hash' => (string)($u['hash'] ?? ''),
                'totp_secret' => (string)($u['totp_secret'] ?? ''), 'role' => 'admin', 'active' => true,
                'must_change' => false, 'pw_set_at' => ((string)($u['pw_set_at'] ?? '')) ?: null, 'pw_valid_until' => null,
                'pw_reminder_at' => null, 'source' => 'config', 'mac_ok' => true,
            ];
        }
        foreach (db()->query('SELECT * FROM ' . t('account') . ' ORDER BY id') as $r) {
            $id = (string)$r['id'];
            if (isset($cache[$id])) {
                continue; // Konfiguration hat Vorrang (Altbestand bis zur Migration)
            }
            $macOk = hash_equals(account_row_mac($r), (string)$r['row_mac']);
            try {
                $email = (string)$r['email_enc'] !== '' ? dec((string)$r['email_enc'], 'account.email:' . $id) : '';
            } catch (Throwable $e) {
                $email = '';
                $macOk = false;
            }
            if (!$macOk) {
                error_log('Status-BCM: Benutzer ' . $id . ': Integritätsfehler');
            }
            $cache[$id] = [
                'name' => (string)$r['name'], 'email' => $email, 'hash' => (string)$r['pw_hash'],
                'totp_secret' => (string)$r['totp_enc'], 'role' => (string)$r['role'], 'active' => (bool)(int)$r['active'],
                'must_change' => (bool)(int)$r['must_change'], 'pw_set_at' => $r['pw_set_at'], 'pw_valid_until' => $r['pw_valid_until'],
                'pw_reminder_at' => $r['pw_reminder_at'], 'source' => 'db', 'mac_ok' => $macOk,
            ];
        }
    }
    return $all ? $cache : array_filter($cache, fn($u) => $u['active'] && $u['mac_ok']);
}

function account_row_mac(array $r): string
{
    return mac('account', implode('|', [$r['id'], $r['name'], $r['email_enc'], $r['pw_hash'], $r['totp_enc'], $r['role'],
        (int)$r['active'], (int)$r['must_change'], $r['pw_set_at'] ?? '', $r['pw_valid_until'] ?? '']));
}

function account_get_row(string $id): ?array
{
    $q = db()->prepare('SELECT * FROM ' . t('account') . ' WHERE id = ?');
    $q->execute([$id]);
    $r = $q->fetch();
    return $r ?: null;
}

/** Gültigkeit eines neu gesetzten Passworts (UTC) oder null (keine Ablaufpflicht). */
function pw_valid_until_from(int $ts): ?string
{
    $days = (int)cfg('auth.password_max_age_days', 0);
    return $days > 0 ? gmdate('Y-m-d H:i:s', $ts + $days * 86400) : null;
}

/** ok | soon | expired | none */
function pw_state(array $u, ?int $now = null): string
{
    if (empty($u['pw_valid_until'])) {
        return 'none';
    }
    $now ??= time();
    $vu = utc_ts((string)$u['pw_valid_until']);
    if ($now >= $vu) {
        return 'expired';
    }
    return $now >= $vu - (int)cfg('auth.password_remind_days', 14) * 86400 ? 'soon' : 'ok';
}

/** Muss der Benutzer vor jeder Änderung erst Passwort/TOTP einrichten? */
function user_needs_setup(array $u): bool
{
    return $u['source'] === 'db' && ($u['must_change'] || pw_state($u) === 'expired' || $u['totp_secret'] === '');
}

/** Passwortregeln (BSI ORP.4: Länge vor Komplexität). Rückgabe: Fehlerliste. */
function password_policy(string $pw, string $userId, ?string $oldHash = null): array
{
    $e = [];
    $min = max(12, (int)cfg('auth.password_min_length', 12));
    if (mb_strlen($pw) < $min) {
        $e[] = "Das Passwort muss mindestens $min Zeichen lang sein.";
    }
    if (strlen($pw) > 1000) {
        $e[] = 'Das Passwort ist zu lang.';
    }
    if ($userId !== '' && mb_stripos($pw, $userId) !== false) {
        $e[] = 'Das Passwort darf den Benutzernamen nicht enthalten.';
    }
    if (preg_match('/^(.)\1+$/u', $pw) || count(array_unique(preg_split('//u', $pw, -1, PREG_SPLIT_NO_EMPTY) ?: [])) < 6) {
        $e[] = 'Das Passwort ist zu einfach (zu wenige verschiedene Zeichen).';
    }
    if ($oldHash !== null && $oldHash !== '' && password_verify($pw, $oldHash)) {
        $e[] = 'Das neue Passwort muss sich vom bisherigen unterscheiden.';
    }
    return $e;
}

function random_password(): string
{
    // 16 Zeichen ohne verwechselbare Zeichen (0/O, 1/l/I)
    $alpha = 'abcdefghijkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789';
    $out = '';
    for ($i = 0; $i < 16; $i++) {
        $out .= $alpha[random_int(0, strlen($alpha) - 1)];
    }
    return implode('-', str_split($out, 4));
}

/** Schreibt eine Benutzerzeile (Insert oder Update) inkl. MAC. $fields im Klartext: name, email, hash, totp_b32, role, active, must_change, pw_set_at, pw_valid_until */
function account_write(string $id, array $fields, bool $insert, string $actor): void
{
    $cur = $insert ? null : account_get_row($id);
    if (!$insert && !$cur) {
        throw new InvalidArgumentException('Benutzer unbekannt');
    }
    if (!$insert && !hash_equals(account_row_mac($cur), (string)$cur['row_mac'])) {
        throw new RuntimeException('Benutzerzeile hat einen Integritätsfehler – Änderung abgelehnt');
    }
    $r = $cur ?? ['id' => $id, 'name' => '', 'email_enc' => '', 'pw_hash' => '', 'totp_enc' => '', 'role' => 'editor',
        'active' => 1, 'must_change' => 1, 'pw_set_at' => null, 'pw_valid_until' => null, 'pw_reminder_at' => null];
    foreach (['name', 'role', 'pw_set_at', 'pw_valid_until'] as $f) {
        if (array_key_exists($f, $fields)) {
            $r[$f] = $fields[$f];
        }
    }
    foreach (['active', 'must_change'] as $f) {
        if (array_key_exists($f, $fields)) {
            $r[$f] = $fields[$f] ? 1 : 0;
        }
    }
    if (array_key_exists('email', $fields)) {
        $r['email_enc'] = $fields['email'] === '' ? '' : enc(strtolower((string)$fields['email']), 'account.email:' . $id);
    }
    if (array_key_exists('hash', $fields)) {
        $r['pw_hash'] = (string)$fields['hash'];
        $r['pw_reminder_at'] = null;
    }
    if (array_key_exists('totp_b32', $fields)) {
        $r['totp_enc'] = $fields['totp_b32'] === '' ? '' : cfg_encrypt((string)$fields['totp_b32']);
    }
    if (!in_array($r['role'], ['admin', 'editor'], true)) {
        throw new InvalidArgumentException('Rolle ungültig');
    }
    $r['row_mac'] = account_row_mac($r);
    $now = now_utc();
    if ($insert) {
        db()->prepare('INSERT INTO ' . t('account') . ' (id, name, email_enc, pw_hash, totp_enc, role, active, must_change, pw_set_at,'
            . ' pw_valid_until, pw_reminder_at, created_at, created_by, updated_at, row_mac) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)')
            ->execute([$id, $r['name'], $r['email_enc'], $r['pw_hash'], $r['totp_enc'], $r['role'], $r['active'], $r['must_change'],
                $r['pw_set_at'], $r['pw_valid_until'], null, $now, $actor, $now, $r['row_mac']]);
    } else {
        db()->prepare('UPDATE ' . t('account') . ' SET name = ?, email_enc = ?, pw_hash = ?, totp_enc = ?, role = ?, active = ?, must_change = ?,'
            . ' pw_set_at = ?, pw_valid_until = ?, pw_reminder_at = ?, updated_at = ?, row_mac = ? WHERE id = ?')
            ->execute([$r['name'], $r['email_enc'], $r['pw_hash'], $r['totp_enc'], $r['role'], $r['active'], $r['must_change'],
                $r['pw_set_at'], $r['pw_valid_until'], $r['pw_reminder_at'], $now, $r['row_mac'], $id]);
    }
    users(false, true);
}

/**
 * Benutzerverwaltung (Aktion + Audit in einer Transaktion). Rückgabe: ggf. Einmalpasswort.
 * Aktionen: create (name, email, role), reset_pw, reset_totp, disable, enable, role (role), set_pw (hash), set_totp (totp_b32)
 */
function account_action(string $action, string $id, array $in, string $actor, array $how = []): ?string
{
    $id = strtolower(trim($id));
    if (!preg_match('/^[a-z0-9_-]{2,32}$/', $id)) {
        throw new InvalidArgumentException('Benutzerkennung ungültig (2–32 Zeichen a–z, 0–9, _ und -)');
    }
    if ($action === 'create' && $id === login_name_key(stage1_user())) {
        throw new InvalidArgumentException('Diese Kennung ist der Benutzername des gemeinsamen Zugangs. Bitte eine andere Kennung wählen.');
    }
    $level = str_starts_with($actor, 'system:') ? 0 : 2;
    try {
        return tx(fn() => account_action_tx($action, $id, $in, $actor, $how, $level));
    } finally {
        users(false, true); // Cache auch nach einem Rollback neu laden
    }
}

function account_action_tx(string $action, string $id, array $in, string $actor, array $how, int $level): ?string
{
    $before = users(true, true)[$id] ?? null;
    if ($action !== 'create' && $before && $before['source'] === 'config') {
        throw new InvalidArgumentException('Dieser Benutzer steht in config.local.inc.php und wird per CLI verwaltet (php setup.php migrate-users).');
    }
    $once = null;
    $now = time();
    $details = ['user' => $id];
    switch ($action) {
        case 'create':
            if ($before || account_get_row($id)) {
                throw new InvalidArgumentException('Diese Benutzerkennung ist bereits vergeben.');
            }
            $name = trim((string)($in['name'] ?? ''));
            $email = strtolower(trim((string)($in['email'] ?? '')));
            if ($name === '' || mb_strlen($name) > 100 || !filter_var($email, FILTER_VALIDATE_EMAIL)) {
                throw new InvalidArgumentException('Name und gültige E-Mail-Adresse angeben.');
            }
            $once = (string)($in['password'] ?? '') ?: random_password();
            account_write($id, ['name' => $name, 'email' => $email, 'role' => (string)($in['role'] ?? 'editor'),
                'hash' => password_hash($once, PASSWORD_DEFAULT), 'totp_b32' => (string)($in['totp_b32'] ?? ''),
                'must_change' => !isset($in['password']), 'pw_set_at' => gmdate('Y-m-d H:i:s', $now),
                'pw_valid_until' => pw_valid_until_from($now), 'active' => true], true, $actor);
            $details += ['role' => (string)($in['role'] ?? 'editor'), 'email' => mask_email($email)];
            if (isset($in['password'])) {
                $once = null; // selbst gewähltes Passwort (CLI) wird nicht zurückgegeben
            }
            break;
        case 'reset_pw':
            $once = random_password();
            account_write($id, ['hash' => password_hash($once, PASSWORD_DEFAULT), 'must_change' => true,
                'pw_set_at' => gmdate('Y-m-d H:i:s', $now), 'pw_valid_until' => pw_valid_until_from($now)], false, $actor);
            break;
        case 'set_pw':
            account_write($id, ['hash' => (string)$in['hash'], 'must_change' => false,
                'pw_set_at' => gmdate('Y-m-d H:i:s', $now), 'pw_valid_until' => pw_valid_until_from($now)], false, $actor);
            break;
        case 'reset_totp':
            account_write($id, ['totp_b32' => ''], false, $actor);
            break;
        case 'set_totp':
            account_write($id, ['totp_b32' => (string)$in['totp_b32']], false, $actor);
            break;
        case 'disable':
        case 'enable':
            if ($action === 'disable' && $id === $actor) {
                throw new InvalidArgumentException('Sie können sich nicht selbst deaktivieren.');
            }
            account_write($id, ['active' => $action === 'enable'], false, $actor);
            break;
        case 'role':
            $role = (string)($in['role'] ?? '');
            if ($id === $actor && $role !== 'admin') {
                throw new InvalidArgumentException('Sie können sich die Admin-Rolle nicht selbst entziehen.');
            }
            account_write($id, ['role' => $role], false, $actor);
            $details += ['role_before' => $before['role'] ?? null, 'role' => $role];
            break;
        default:
            throw new InvalidArgumentException('Unbekannte Aktion');
    }
    if (in_array($action, ['disable', 'role'], true)) {
        $admins = array_filter(users(), fn($u) => $u['role'] === 'admin');
        if (!$admins) {
            throw new InvalidArgumentException('Es muss mindestens ein aktiver Admin bleiben.');
        }
    }
    audit('user.' . $action, 'user:' . $id, $details + ['how' => $how], $actor, $level);
    return $once;
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
    $hash = stage1_hash();
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

/* --- Persönliche Anmeldung: Kennung + Passwort, danach TOTP-Code (Startseite und Einstellungen) --- */

/**
 * Schritt 1. Rückgabe: Fehlermeldung oder null. Bei Erfolg ist entweder der TOTP-Schritt offen
 * (personal_login_pending()) oder – ohne gekoppelte App (Ersteinrichtung) – die Anmeldung abgeschlossen.
 */
function personal_login_start(string $key, string $pw): ?string
{
    $wait = max(throttle_locked('s1'), throttle_locked('s2', $key));
    if ($wait > 0) {
        return 'Zu viele Versuche. Bitte in ca. ' . (int)ceil($wait / 60) . ' Minute(n) erneut versuchen.';
    }
    $u = verify_user($key, $pw);
    throttle_record('s1', null, $u !== null);
    throttle_record('s2', $key, $u !== null);
    if (!$u) {
        fail_delay();
        audit('login2.fail', 'session', ['user' => mb_substr(preg_replace('/[^\w.@-]/u', '?', $key) ?? '', 0, 32)], 'anonymous', 1);
        return 'Anmeldung fehlgeschlagen.';
    }
    if ($u['totp_secret'] === '' || !cfg('auth.totp_at_login', true)) {
        // Noch keine App gekoppelt: Die Ersteinrichtung verlangt sie sofort, andere Aktionen sind bis dahin gesperrt.
        personal_login_finish($u, false);
        return null;
    }
    session_regenerate_id(true);
    $_SESSION['login_totp'] = ['u' => $u['id'], 't' => time(), 'n' => 0];
    return null;
}

/** Kennung, deren TOTP-Schritt offen ist (höchstens 5 Minuten), sonst null. */
function personal_login_pending(): ?string
{
    $p = $_SESSION['login_totp'] ?? null;
    if (!is_array($p) || time() - (int)$p['t'] > 300) {
        unset($_SESSION['login_totp']);
        return null;
    }
    return (string)$p['u'];
}

/** Schritt 2: TOTP-Code. Rückgabe: Fehlermeldung oder null (angemeldet). */
function personal_login_totp(string $code): ?string
{
    $id = personal_login_pending();
    if ($id === null) {
        return 'Die Anmeldung ist abgelaufen. Bitte erneut anmelden.';
    }
    if (($wait = throttle_locked('s2t', $id)) > 0) {
        unset($_SESSION['login_totp']);
        return 'Zu viele ungültige Codes. Bitte in ca. ' . (int)ceil($wait / 60) . ' Minute(n) erneut versuchen.';
    }
    $u = users()[$id] ?? null;
    $good = $u !== null && totp_verify_user(['id' => $id] + $u, $code);
    throttle_record('s2t', $id, $good);
    if (!$good) {
        fail_delay();
        audit('totp.fail', 'session', ['action' => 'login', 'user' => $id], 'anonymous', 1);
        if (++$_SESSION['login_totp']['n'] >= 5) {
            unset($_SESSION['login_totp']);
        }
        return 'Der Code aus der Authenticator-App ist ungültig oder bereits verwendet.';
    }
    unset($_SESSION['login_totp']);
    personal_login_finish(['id' => $id] + $u, true);
    return null;
}

function personal_login_finish(array $u, bool $totp): void
{
    session_regenerate_id(true);
    $_SESSION['s1'] = $_SESSION['s1'] ?? time();
    $_SESSION['s2'] = ['u' => $u['id'], 't' => time()];
    audit('login2.ok', 'session', ['how' => ['totp' => $totp]], $u['id'], 2);
}

/** Formular für den TOTP-Schritt der Anmeldung. */
function render_login_totp(string $action, string $userId): void
{
    echo '<form method="post" action="' . h($action) . '" autocomplete="off">' . csrf_field() . '<input type="hidden" name="action" value="login_totp">'
        . '<p class="small text-body-secondary">Angemeldet als <strong>' . h($userId) . '</strong>. Bitte den aktuellen Code aus der Authenticator-App eingeben.</p>'
        . '<label class="form-label" for="lt">Code aus der App (6 Stellen)</label>'
        . '<input class="form-control form-control-lg mb-3" id="lt" type="text" name="totp" inputmode="numeric" pattern="[0-9 ]{6,7}" maxlength="7" autocomplete="one-time-code" required autofocus>'
        . '<div class="d-grid gap-2"><button class="btn btn-primary btn-lg" type="submit">Bestätigen</button></div></form>'
        . '<form method="post" action="' . h($action) . '" class="mt-2 d-grid">' . csrf_field() . '<input type="hidden" name="action" value="login_cancel">'
        . '<button class="btn btn-outline-secondary" type="submit">Abbrechen</button></form>';
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

/** Audit-Einträge eines Zeitraums (UTC, jeweils einschließlich), aufsteigend, mit entschlüsselten Details. */
function audit_range(?string $fromUtc, ?string $toUtc): Generator
{
    $sql = 'SELECT * FROM ' . t('audit') . ' WHERE 1=1';
    $args = [];
    if ($fromUtc !== null) {
        $sql .= ' AND ts >= ?';
        $args[] = $fromUtc;
    }
    if ($toUtc !== null) {
        $sql .= ' AND ts <= ?';
        $args[] = $toUtc;
    }
    $q = db()->prepare($sql . ' ORDER BY seq ASC');
    $q->execute($args);
    foreach ($q as $r) {
        try {
            $r['details'] = json_decode(dec((string)$r['details_enc'], 'audit:' . $r['seq']), true, 32, JSON_THROW_ON_ERROR);
        } catch (Throwable $e) {
            $r['details'] = ['_error' => 'nicht entschlüsselbar'];
        }
        yield $r;
    }
}

function audit_describe(string $action, array $d): string
{
    $labels = [
        'login1.ok' => 'Anmeldung Stufe 1', 'login2.ok' => 'Anmeldung Stufe 2',
        'login2.fail' => 'Fehlgeschlagene Anmeldung Stufe 2', 'totp.fail' => 'Ungültiger TOTP-Code',
        'status.set' => 'Meldung gesetzt', 'status.extend' => 'Meldung verlängert',
        'status.end' => 'Meldung beendet', 'status.auto_end' => 'Meldung automatisch beendet', 'status.update' => 'Meldung geändert',
        'mail.alarm' => 'ALARM-Mail versendet', 'mail.reminder' => 'Erinnerung versendet',
        'mail.anchor' => 'Audit-Anker versendet', 'mail.autorevert' => 'Hinweis Rücksetzung versendet',
        'mail.pw_reminder' => 'Passwort-Erinnerung versendet', 'logout' => 'Abmeldung',
        'user.create' => 'Benutzer angelegt', 'user.reset_pw' => 'Passwort zurückgesetzt (Einmalpasswort)',
        'user.set_pw' => 'Passwort geändert', 'user.reset_totp' => 'TOTP zurückgesetzt', 'user.set_totp' => 'TOTP gekoppelt',
        'user.disable' => 'Benutzer deaktiviert', 'user.enable' => 'Benutzer aktiviert', 'user.role' => 'Rolle geändert',
        'system.install' => 'Einrichtung abgeschlossen (install.php)', 'system.cron_manual' => 'Cron manuell ausgeführt',
        'setting.stage1' => 'Zugangspasswort Stufe 1 geändert', 'setting.stage1_user' => 'Benutzername des gemeinsamen Zugangs geändert', 'setting.cc1' => 'Kopie-Adresse (cc_default_mail1) geändert',
        'setting.recipient_add' => 'ALARM-Empfänger hinzugefügt', 'setting.recipient_remove' => 'ALARM-Empfänger entfernt',
        'mail.test' => 'Testmail versendet',
        'setting.circle_create' => 'Alarmkreis angelegt', 'setting.circle_update' => 'Alarmkreis geändert', 'setting.circle_delete' => 'Alarmkreis gelöscht',
        'setting.location_create' => 'Standort angelegt', 'setting.location_update' => 'Standort geändert', 'setting.location_delete' => 'Standort gelöscht',
        'setting.contact_create' => 'Kontakt angelegt', 'setting.contact_update' => 'Kontakt geändert', 'setting.contact_delete' => 'Kontakt gelöscht',
        'setting.mail_prefix' => 'Betreff-Präfixe geändert',
        'setting.alarm_to' => 'Adresse im An-Feld der ALARM-Mail geändert', 'setting.level_cc' => 'Zusätzliche Empfänger je Stufe geändert',
        'setting.default_phone' => 'Standard-Rufnummer geändert', 'setting.circle_channels' => 'Alarmkreis: Signal/GroupAlarm geändert',
        'channel.alarm' => 'Alarm über Signal/GroupAlarm', 'audit.export' => 'Protokoll exportiert', 'monitor.cron_stale' => 'Warnung: Cron läuft nicht',
    ];
    $s = $labels[$action] ?? $action;
    $parts = [];
    if (isset($d['msg'])) {
        $parts[] = 'Meldung #' . (int)$d['msg'];
    }
    if (($d['mode'] ?? '') === 'end' && isset($d['before']['key'])) {
        $parts[] = (string)($d['before']['label'] ?? $d['before']['key']);
    }
    if (isset($d['kind'])) {
        $parts[] = ['new' => 'neu', 'update' => 'Aktualisierung', 'end' => 'Ende'][$d['kind']] ?? (string)$d['kind'];
    }
    if (!empty($d['circles']) && is_array($d['circles'])) {
        $parts[] = 'Kreise: ' . implode(', ', array_map('strval', $d['circles']));
    }
    if (!empty($d['channels']) && is_array($d['channels'])) {
        foreach ($d['channels'] as $ch => $r) {
            $parts[] = ($ch === 'signal' ? 'Signal' : 'GroupAlarm') . ': ' . (int)($r['ok'] ?? 0) . ' ok, ' . (int)($r['failed'] ?? 0) . ' fehlgeschlagen';
        }
    }
    if (!empty($d['groupalarm']) && is_string($d['groupalarm'])) {
        $parts[] = 'GroupAlarm-Szenario ' . $d['groupalarm'];
    }
    if (!empty($d['location_recipients'])) {
        $parts[] = 'Standortadressen: ' . (int)$d['location_recipients'];
    }
    if (!empty($d['level']) && is_string($d['level'])) {
        $parts[] = 'Stufe: ' . $d['level'];
    }
    if (isset($d['phone']) && is_string($d['phone'])) {
        $parts[] = 'Rufnummer: ' . ($d['before'] ?? '–') . ' → ' . $d['phone'];
    }
    foreach (['circle' => 'Kreis', 'location' => 'Standort', 'contact' => 'Kontakt'] as $f => $lbl) {
        if (!empty($d[$f]) && is_string($d[$f])) {
            $parts[] = $lbl . ': ' . $d[$f];
        }
    }
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
    if (!empty($d['how']['emergency'])) {
        $parts[] = 'Notfallzugang (storage/notfall.txt)';
    }
    if (isset($d['how']['totp'])) {
        $parts[] = 'TOTP: ' . ($d['how']['totp'] ? 'ja' : 'nein');
    }
    if (isset($d['role'])) {
        $parts[] = 'Rolle: ' . (isset($d['role_before']) ? $d['role_before'] . ' → ' : '') . $d['role'];
    }
    foreach (['recipients', 'ok', 'failed', 'status_id', 'state', 'count'] as $f) {
        if (isset($d[$f]) && is_scalar($d[$f])) {
            $parts[] = "$f: " . $d[$f];
        }
    }
    if (!empty($d['masked']) && is_array($d['masked'])) {
        $parts[] = 'Adresse: ' . implode(', ', array_map('strval', $d['masked']));
    }
    if (!empty($d['note'])) {
        $parts[] = 'Notiz: ' . $d['note'];
    }
    if (!empty($d['user'])) {
        $parts[] = 'Benutzer: ' . $d['user'];
    }
    if (!empty($d['format']) && is_string($d['format'])) {
        $parts[] = 'Format ' . strtoupper($d['format']) . (!empty($d['range']) ? ', Zeitraum ' . $d['range'] : '') . (isset($d['with_ip']) ? ', IP-Adressen: ' . ($d['with_ip'] ? 'ja' : 'nein') : '');
    }
    if (isset($d['minutes']) && is_int($d['minutes'])) {
        $parts[] = 'seit ' . $d['minutes'] . ' Minuten';
    }
    if (!empty($d['_error'])) {
        $parts[] = 'Details nicht entschlüsselbar';
    }
    if (!empty($d['_ctx']['ip'])) {
        $parts[] = 'IP ' . $d['_ctx']['ip'];
    }
    return $s . ($parts ? ' – ' . implode('; ', $parts) : '');
}

/* ====================================================================== */
/* Status (verschlüsselte Nutzdaten, Zeilen-MAC, lückenlose Historie)     */
/* ====================================================================== */

function build_payload(array $def, array $locIds, string $note = '', array $contactIds = []): array
{
    $b = bcm();
    // Optionale Ausweichrufnummer je Status (z. B. Mobilnummer bei eingeschränkter Festnetz-Erreichbarkeit)
    $fallback = trim((string)($def['phone'] ?? '')) ?: $b['default_phone'];
    $locs = [];
    foreach ($locIds as $id) {
        $l = $b['locations_by_id'][$id] ?? null;
        if (!$l) {
            continue;
        }
        $own = $l['phone'] !== '';
        $locs[] = ['id' => $id, 'name' => $l['name'], 'phone' => $own ? $l['phone'] : $fallback, 'default_phone' => !$own];
    }
    $contacts = [];
    foreach ($contactIds ? contacts_all() : [] as $c) {
        if (in_array($c['id'], $contactIds, true)) {
            $contacts[] = $c;
        }
    }
    return [
        'label' => $def['label'], 'text' => $def['text'], 'severity' => $def['severity'],
        'exercise' => (bool)$def['exercise'], 'audience' => $def['audience'],
        'locations' => $locs, 'default_phone' => $fallback, 'contacts' => $contacts, 'note' => $note,
    ];
}

/** Meldungs-Nummer: alle Versionen (Verlängerung, Änderung) einer Meldung teilen sie; die erste Zeile hat msg_id NULL. */
function status_msg(array $row): int
{
    return isset($row['msg_id']) && $row['msg_id'] !== null ? (int)$row['msg_id'] : (int)$row['id'];
}

function status_row_mac(array $r, int $id): string
{
    $parts = [$id, $r['status_key'], $r['severity'], $r['author'], $r['created_at'],
        $r['valid_until'] ?? '', (int)$r['alarm_mail'], $r['audience'], $r['payload_enc']];
    if (isset($r['msg_id']) && $r['msg_id'] !== null && (int)$r['msg_id'] !== $id) {
        $parts[] = 'msg:' . (int)$r['msg_id'];
    }
    return mac('row', implode('|', $parts));
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

const SBCM_STATUS_ACTIONS = ['status.set', 'status.extend', 'status.update', 'status.end', 'status.auto_end'];

/**
 * Alle Meldungen für die Anzeige. Maßgeblich ist das Audit-Log (HMAC-Kette), nicht die Spalte state: Es wird
 * nachgespielt, welche Meldungen gesetzt, verlängert/geändert und beendet wurden. Weicht die Datenbank davon ab
 * (z. B. eine alte Zeile wieder auf "active" gesetzt), erscheint die Meldung als "nicht verifiziert".
 *
 * Rückgabe: live (gültig, nach Schwere sortiert), recent (abgelaufen oder beendet, höchstens display.keep_hours
 * lang ausgegraut), stale (abgelaufen, aber nicht beendet und nicht mehr angezeigt), unverified.
 */
function status_board(?int $nowTs = null): array
{
    $now = $nowTs ?? time();
    $keep = max(0, (int)cfg('display.keep_hours', 48)) * 3600;
    $def = bcm()['default_status'];
    $rows = [];
    foreach (db()->query('SELECT * FROM ' . t('status')) as $r) {
        $rows[(int)$r['id']] = $r;
    }
    $since = (int)(kv_get('multi_since_seq') ?? 0);
    $active = [];
    $ended = [];
    $q = db()->prepare('SELECT seq, ts, action, object FROM ' . t('audit') . ' WHERE action IN (' . implode(',', array_fill(0, count(SBCM_STATUS_ACTIONS), '?'))
        . ') ORDER BY seq');
    $q->execute(SBCM_STATUS_ACTIONS);
    foreach ($q as $e) {
        $id = (int)substr((string)$e['object'], 7);
        if ((int)$e['seq'] <= $since) {
            // bis Version 1.2: genau ein Status, jeder Eintrag löst den vorigen ab
            $active = [$id => $id];
            $ended = [];
            continue;
        }
        $msg = isset($rows[$id]) ? status_msg($rows[$id]) : $id;
        if (in_array($e['action'], ['status.end', 'status.auto_end'], true)) {
            unset($active[$msg]);
            $ended[$msg] = [$id, (string)$e['ts']];
        } else {
            $active[$msg] = $id;
            unset($ended[$msg]);
        }
    }
    $out = ['live' => [], 'recent' => [], 'stale' => [], 'unverified' => []];
    $legacyNormal = fn(array $r) => $r['status_key'] === $def && $r['severity'] === 'ok';
    foreach ($active as $id) {
        if (!isset($rows[$id])) {
            continue;
        }
        $r = status_decode($rows[$id]);
        if ($legacyNormal($r)) {
            continue;
        }
        if ($r['state'] !== 'active' || !$r['payload'] || !$r['mac_ok']) {
            $r['mac_ok'] = false;
            $out['unverified'][] = $r;
            continue;
        }
        $r['msg'] = status_msg($r);
        if (!empty($r['valid_until']) && utc_ts((string)$r['valid_until']) <= $now) {
            $r['gone'] = 'expired';
            $r['gone_at'] = $r['valid_until'];
            $out[$now - utc_ts((string)$r['valid_until']) < $keep ? 'recent' : 'stale'][] = $r;
        } else {
            $out['live'][] = $r;
        }
    }
    foreach ($ended as [$id, $ts]) {
        if (!isset($rows[$id]) || $now - utc_ts($ts) >= $keep) {
            continue;
        }
        $r = status_decode($rows[$id]);
        if ($legacyNormal($r) || !$r['payload']) {
            continue;
        }
        $r['mac_ok'] = $r['mac_ok'] && $r['state'] === 'ended';
        $r['msg'] = status_msg($r);
        $r['gone'] = 'ended';
        $r['gone_at'] = $ts;
        $out['recent'][] = $r;
    }
    // Zeilen, die laut Datenbank aktiv sind, laut Protokoll aber nicht
    foreach ($rows as $id => $r) {
        if ($r['state'] === 'active' && !in_array($id, $active, true) && !$legacyNormal($r)) {
            $d = status_decode($r);
            $d['mac_ok'] = false;
            $out['unverified'][] = $d;
        }
    }
    $rank = ['critical' => 0, 'warn' => 1, 'info' => 2, 'ok' => 3];
    usort($out['live'], fn($x, $y) => [$rank[$x['severity']] ?? 9, $y['created_at']] <=> [$rank[$y['severity']] ?? 9, $x['created_at']]);
    usort($out['recent'], fn($x, $y) => strcmp((string)$y['gone_at'], (string)$x['gone_at']));
    return $out;
}

/** Erste gültige Meldung (wichtigste) oder null. */
function status_current(): ?array
{
    return status_board()['live'][0] ?? null;
}

/** Aktive Meldung (laut Protokoll), auf die sich Verlängern/Ändern/Beenden bezieht – gültig oder abgelaufen. */
function status_target(int $id): ?array
{
    $b = status_board();
    foreach (array_merge($b['live'], $b['recent'], $b['stale']) as $r) {
        if ((int)$r['id'] === $id && ($r['gone'] ?? '') !== 'ended') {
            return $r;
        }
    }
    return null;
}

function status_history(int $limit = 15): array
{
    $out = [];
    foreach (db()->query('SELECT * FROM ' . t('status') . ' ORDER BY id DESC LIMIT ' . (int)$limit) as $r) {
        $out[] = status_decode($r);
    }
    return $out;
}

function status_brief(array $row, array $payload): array
{
    return ['id' => (int)$row['id'], 'key' => $row['status_key'], 'valid_until' => $row['valid_until'],
        'locations' => array_column($payload['locations'] ?? [], 'id'), 'contacts' => array_column($payload['contacts'] ?? [], 'name')];
}

/**
 * Meldung setzen (set), verlängern (extend) oder ändern (update) und atomar protokollieren.
 * $spec: mode, key, target (Zeile bei extend/update), loc_ids[], contact_ids[], valid_until (UTC|null), alarm_mail, note
 */
function status_create(array $spec, string $author, array $how = []): array
{
    $def = bcm()['by_key'][$spec['key']] ?? null;
    if (!$def) {
        throw new InvalidArgumentException('Unbekannter Status');
    }
    $payload = build_payload($def, (array)$spec['loc_ids'], (string)($spec['note'] ?? ''), (array)($spec['contact_ids'] ?? []));
    $now = now_utc();
    $pdo = db();
    return tx(function () use ($pdo, $spec, $def, $author, $payload, $now, $how) {
        $before = null;
        $msg = null;
        if ($spec['mode'] !== 'set') {
            $q = $pdo->prepare('SELECT * FROM ' . t('status') . " WHERE id = ? AND state = 'active'" . lock_clause());
            $q->execute([(int)$spec['target']]);
            $cur = $q->fetch();
            if (!$cur || $cur['status_key'] !== $def['key']) {
                throw new InvalidArgumentException('Die Meldung wurde inzwischen geändert oder beendet. Bitte neu laden.');
            }
            $cd = status_decode($cur);
            $before = status_brief($cur, (array)$cd['payload']);
            $msg = status_msg($cur);
            $pdo->prepare('UPDATE ' . t('status') . " SET state = 'superseded', closed_at = ?, closed_by = ? WHERE id = ?")
                ->execute([$now, $author, (int)$cur['id']]);
        }
        $row = [
            'status_key' => $def['key'], 'severity' => $def['severity'], 'author' => $author, 'created_at' => $now,
            'valid_until' => $spec['valid_until'] ?? null, 'alarm_mail' => !empty($spec['alarm_mail']) ? 1 : 0,
            'audience' => $def['audience'], 'payload_enc' => enc(json_enc($payload), 'status.payload'), 'msg_id' => $msg,
        ];
        $pdo->prepare('INSERT INTO ' . t('status')
            . ' (status_key, severity, author, created_at, valid_until, alarm_mail, audience, state, payload_enc, row_mac, msg_id)'
            . " VALUES (?,?,?,?,?,?,?,'active',?,'',?)")
            ->execute([$row['status_key'], $row['severity'], $row['author'], $row['created_at'], $row['valid_until'],
                $row['alarm_mail'], $row['audience'], $row['payload_enc'], $msg]);
        $id = (int)$pdo->lastInsertId();
        $pdo->prepare('UPDATE ' . t('status') . ' SET row_mac = ? WHERE id = ?')->execute([status_row_mac($row, $id), $id]);
        $action = ['set' => 'status.set', 'extend' => 'status.extend', 'update' => 'status.update'][$spec['mode']] ?? 'status.set';
        audit($action, 'status:' . $id, [
            'mode' => $spec['mode'], 'msg' => $msg ?? $id, 'before' => $before,
            'after' => status_brief($row + ['id' => $id], $payload) + ['label' => $def['label'], 'alarm_mail' => (bool)$row['alarm_mail']],
            'how' => $how, 'note' => $spec['note'] ?? '',
        ], $author, setting_level($author));
        return ['id' => $id, 'msg' => $msg ?? $id, 'payload' => $payload, 'valid_until' => $row['valid_until'], 'author' => $author];
    });
}

/** Meldung beenden ("zurückgenommen/gelöst"). Die Zeile bleibt erhalten, sie wird nur als beendet markiert. */
function status_end(int $rowId, string $author, array $how = [], string $note = '', bool $auto = false): array
{
    $pdo = db();
    return tx(function () use ($pdo, $rowId, $author, $how, $note, $auto) {
        $q = $pdo->prepare('SELECT * FROM ' . t('status') . " WHERE id = ? AND state = 'active'" . lock_clause());
        $q->execute([$rowId]);
        $cur = $q->fetch();
        if (!$cur) {
            throw new InvalidArgumentException('Die Meldung wurde inzwischen geändert oder beendet. Bitte neu laden.');
        }
        $d = status_decode($cur);
        $now = now_utc();
        $pdo->prepare('UPDATE ' . t('status') . " SET state = 'ended', closed_at = ?, closed_by = ? WHERE id = ?")->execute([$now, $author, $rowId]);
        audit($auto ? 'status.auto_end' : 'status.end', 'status:' . $rowId, [
            'mode' => 'end', 'msg' => status_msg($cur), 'before' => status_brief($cur, (array)$d['payload']) + ['label' => $d['payload']['label'] ?? ''],
            'how' => $how, 'note' => $note,
        ], $author, setting_level($author));
        return ['id' => $rowId, 'msg' => status_msg($cur), 'payload' => (array)$d['payload'], 'valid_until' => $cur['valid_until'], 'author' => $author];
    });
}

function spec_needs_totp(array $spec): bool
{
    if (cfg('auth.totp_enforce_all', false)) {
        return true;
    }
    if (!empty($spec['alarm_mail'])) {
        return true;
    }
    // Beenden wie Setzen: Wer eine echte Warnung still beenden kann, erzeugt eine falsche Entwarnung.
    $def = bcm()['by_key'][$spec['key']] ?? null;
    return $def && $def['require_totp'];
}

/** Empfänger einer ALARM-Mail: gewählte Kreise + Standortverwaltungen. Rückgabe: [Adressen, Kreisnamen, Anzahl Standortadressen] */
function alarm_targets(array $spec, array $payload): array
{
    $mails = [];
    $names = [];
    foreach (alarm_circles() as $c) {
        if (in_array($c['id'], (array)($spec['circles'] ?? []), true)) {
            $names[] = $c['name'];
            foreach ($c['emails'] as $e) {
                $mails[$e] = $e;
            }
        }
    }
    $locMails = [];
    if (!empty($spec['notify_locations'])) {
        $ids = array_column($payload['locations'] ?? [], 'id');
        foreach (locations_all() as $l) {
            if (!$ids || in_array($l['id'], $ids, true)) {
                foreach ($l['emails'] as $e) {
                    $locMails[$e] = $e;
                }
            }
        }
    }
    // zusätzliche Empfänger der Stufe (System -> Zusätzliche Empfänger je Stufe)
    $sev = (string)($payload['severity'] ?? (bcm()['by_key'][(string)($spec['key'] ?? '')]['severity'] ?? ''));
    foreach (level_cc()[$sev] ?? [] as $e) {
        $mails[$e] = $e;
    }
    return [array_values(array_unique(array_merge(array_values($mails), array_values($locMails)))), $names, count($locMails)];
}

/** Validiert Formulareingaben -> [spec|null, Fehlerliste]. $target: betroffene Meldung bei extend/update/end. */
function parse_change_request(array $in, ?array $target): array
{
    $b = bcm();
    $mode = (string)($in['mode'] ?? 'set');
    if (!in_array($mode, ['set', 'extend', 'update', 'end'], true)) {
        return [null, ['Ungültige Aktion.']];
    }
    $note = preg_replace('/[\x00-\x1F\x7F]+/u', ' ', (string)($in['note'] ?? '')) ?? '';
    $note = mb_substr(trim($note), 0, 200);
    $spec = ['mode' => $mode, 'key' => '', 'target' => null, 'loc_ids' => [], 'contact_ids' => [], 'valid_until' => null,
        'alarm_mail' => false, 'circles' => [], 'notify_locations' => false, 'note' => $note];
    $errors = [];

    if ($mode === 'set') {
        $def = $b['by_key'][(string)($in['status_key'] ?? '')] ?? null;
        if (!$def || $def['key'] === $b['default_status']) {
            return [null, ['Bitte einen Status auswählen.']];
        }
    } else {
        if (!$target || empty($target['payload'])) {
            return [null, ['Diese Meldung ist nicht mehr aktiv. Bitte neu laden.']];
        }
        $def = $b['by_key'][(string)$target['status_key']] ?? null;
        if (!$def) {
            return [null, ['Diese Meldung ist in der config.json nicht mehr definiert.']];
        }
        $spec['target'] = (int)$target['id'];
        $spec['loc_ids'] = array_values(array_column($target['payload']['locations'] ?? [], 'id'));
        $spec['contact_ids'] = array_values(array_filter(array_column($target['payload']['contacts'] ?? [], 'id')));
    }
    $spec['key'] = $def['key'];
    if ($mode !== 'end') {
        $hits = critical_terms_in($def['label'] . "\n" . $def['text'], $b);
        if ($hits) {
            return [null, ['Der Meldungstext dieses Status enthält kritische Begriffe (' . implode(', ', $hits)
                . ') und ist nicht pressetauglich. Bitte config.json korrigieren.']];
        }
    }
    if (in_array($mode, ['set', 'update'], true)) {
        if ($def['audience'] === 'ALLE_UND_ADRESSLISTE') {
            $ids = !empty($in['loc_all']) ? array_keys($b['locations_by_id']) : array_map('strval', (array)($in['loc'] ?? []));
            $ids = array_values(array_unique(array_filter($ids, fn($i) => isset($b['locations_by_id'][$i]))));
            if (!$ids) {
                $errors[] = 'Bitte mindestens einen Standort auswählen.';
            }
            $spec['loc_ids'] = $ids;
        }
        $known = array_column(contacts_all(), 'id');
        $spec['contact_ids'] = array_values(array_intersect($known, array_map('strval', (array)($in['contacts'] ?? []))));
    }
    if (!empty($in['alarm_mail'])) {
        if (!$def['alarm_mail_allowed']) {
            $errors[] = 'Für diesen Status ist keine ALARM-Mail vorgesehen.';
        } else {
            $spec['alarm_mail'] = true;
            $spec['circles'] = array_values(array_intersect(array_column(alarm_circles(), 'id'), array_map('strval', (array)($in['circles'] ?? []))));
            $spec['notify_locations'] = !empty($in['notify_loc']);
            [$to] = alarm_targets($spec, ['locations' => array_map(fn($i) => ['id' => $i], $spec['loc_ids'])]);
            $ct = channel_targets($spec);
            if (!$to && !($ct['signal'] && channel_enabled('signal')) && !($ct['groupalarm'] && channel_enabled('groupalarm'))) {
                $errors[] = 'ALARM-Mail: Bitte mindestens einen Alarmkreis oder die Standortverwaltungen mit hinterlegten Adressen auswählen.';
            }
        }
    }
    if ($mode === 'end') {
        return [$errors ? null : $spec, $errors];
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

/** cc_default_mail1 – darf wie die Empfänger als "enc:..." hinterlegt sein. */
function cc_default_mail1(): string
{
    $web = setting_get('cc1');
    if (is_string($web) && filter_var($web, FILTER_VALIDATE_EMAIL)) {
        return $web;
    }
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

/** Kontaktangaben als Text (Mail) */
function contacts_text(array $contacts): string
{
    $out = '';
    foreach ($contacts as $c) {
        $parts = array_filter([
            $c['phone'] !== '' ? 'Tel. ' . $c['phone'] : '', $c['email'] !== '' ? 'E-Mail ' . $c['email'] : '',
            trim(($c['platform'] !== '' ? $c['platform'] . ' ' : '') . $c['url']),
            $c['meeting'] !== '' ? 'Konferenz-ID ' . $c['meeting'] : '',
        ]);
        $out .= '- ' . $c['name'] . ': ' . implode(', ', $parts) . "\n";
    }
    return $out !== '' ? "Kontakt:\n" . $out : '';
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
        'phone' => $payload['default_phone'], 'contacts' => contacts_text((array)($payload['contacts'] ?? [])),
        'validity' => $validUntil ? 'Voraussichtlich gültig bis: ' . fmt_local($validUntil) . ' Uhr' : '',
        'url' => rtrim((string)cfg('app.base_url'), '/') . '/',
    ];
}

/**
 * ALARM-Mail zu einer Meldung: $kind = new | update | end (Betreff-Präfix aus System). Empfänger: gewählte Alarmkreise
 * und Standortverwaltungen, ausschließlich per BCC, dazu Autor und cc_default_mail1.
 */
function send_alarm_mail(string $kind, int $statusId, array $payload, ?string $validUntil, string $author, array $spec): array
{
    $tpls = bcm()['mail_templates'];
    $tpl = $kind === 'end' ? $tpls['alarm_end'] : $tpls['alarm'];
    $vars = mail_vars_status($payload, $validUntil);
    $prefix = trim(mail_prefixes()[$kind] ?? '');
    $subject = trim($prefix . ' ' . trim(render_tpl($tpl['subject'], $vars)));
    $body = render_tpl($tpl['body'], $vars);
    $tplBody = is_array($tpl['body']) ? implode("\n", $tpl['body']) : (string)$tpl['body'];
    if ($kind !== 'end' && $vars['contacts'] !== '' && !str_contains($tplBody, '{contacts}')) {
        $body .= "\n" . $vars['contacts'];
    }
    [$bcc, $circles, $locCount] = alarm_targets($spec, $payload);
    $u = users()[$author] ?? null;
    if ($u && filter_var($u['email'], FILTER_VALIDATE_EMAIL)) {
        $bcc[] = $u['email'];
    }
    $cc1 = cc_default_mail1();
    if ($cc1 !== '') {
        $bcc[] = $cc1;
    }
    // An: Absender bzw. unter System hinterlegte Adresse; alle Empfänger der Kreise nur als BCC (sehen sich gegenseitig nicht)
    $to = alarm_to_address();
    $bcc = array_values(array_diff(array_unique(array_map('strtolower', $bcc)), [$to]));
    $sum = ['total' => 0, 'ok' => 0, 'failed' => 0];
    $logKind = ['new' => 'alarm', 'update' => 'alarm_upd', 'end' => 'alarm_end'][$kind] ?? 'alarm';
    foreach (array_chunk($bcc, max(1, (int)cfg('mail.max_bcc_per_message', 50))) ?: [[]] as $chunk) {
        $res = mail_deliver(['to' => $to !== '' ? [$to] : [], 'bcc' => $chunk, 'subject' => $subject, 'body' => $body, 'priority' => true]);
        $r = mail_record($logKind, $statusId, $subject, $body, $res);
        foreach ($sum as $k => $_) {
            $sum[$k] += $r[$k];
        }
    }
    $sum['channels'] = send_alarm_channels($kind, $statusId, $subject, $body, $author, $spec);
    audit('mail.alarm', 'status:' . $statusId, ['kind' => $kind, 'circles' => $circles, 'location_recipients' => $locCount,
        'recipients' => $sum['total'], 'ok' => $sum['ok'], 'failed' => $sum['failed']], $author, setting_level($author));
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

    $board = status_board($now);
    foreach ($board['unverified'] as $r) {
        $log[] = 'Meldung #' . $r['id'] . ': nicht verifiziert – übersprungen';
    }
    $open = array_filter(array_merge($board['live'], $board['recent'], $board['stale']), fn($r) => ($r['gone'] ?? '') !== 'ended' && !empty($r['valid_until']));
    foreach ($open as $r) {
        $vu = utc_ts((string)$r['valid_until']);
        $label = $r['payload']['label'];

        if ($auto > 0 && $now >= $vu + $auto) {
            $res = status_end((int)$r['id'], 'system:cron', ['cron' => true], 'automatisch beendet nach Ablauf ohne Bestätigung', true);
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
            $log[] = "Meldung #{$r['id']} ($label) automatisch beendet";
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

    kv_set('cron_last', (string)$now);

    // Passwort-Gültigkeit (Stufe 2 je Benutzer, Stufe 1 gemeinsam): Erinnerung vor/nach Ablauf
    $log = array_merge($log, password_reminders($now));

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

/** Erinnerungsmails zur Passwort-Gültigkeit. Wiederholung alle auth.password_reminder_repeat_days Tage. */
function password_reminders(int $now): array
{
    $log = [];
    $tpl = bcm()['mail_templates']['password'] ?? null;
    if (!$tpl) {
        return $log;
    }
    $repeat = max(1, (int)cfg('auth.password_reminder_repeat_days', 7)) * 86400;
    $cc1 = cc_default_mail1();
    $url = rtrim((string)cfg('app.base_url'), '/') . '/change.php';
    foreach (users() as $id => $u) {
        $state = pw_state($u, $now);
        if ($u['source'] !== 'db' || !in_array($state, ['soon', 'expired'], true)) {
            continue;
        }
        if (!empty($u['pw_reminder_at']) && $now - utc_ts((string)$u['pw_reminder_at']) < $repeat) {
            continue;
        }
        $vars = ['name' => $u['name'], 'what' => 'Ihr persönliches Passwort (Benutzer ' . $id . ')',
            'phrase' => $state === 'expired' ? 'ist seit ' . fmt_local($u['pw_valid_until']) . ' Uhr abgelaufen. Bei der nächsten Anmeldung muss es geändert werden'
                : 'läuft am ' . fmt_local($u['pw_valid_until']) . ' Uhr ab', 'url' => $url];
        $subject = trim(render_tpl($tpl['subject'], $vars));
        $body = render_tpl($tpl['body'], $vars);
        $res = mail_deliver(['to' => array_filter([$u['email']]), 'cc' => $cc1 !== '' ? [$cc1] : [], 'subject' => $subject, 'body' => $body]);
        $sum = mail_record('pw_reminder', null, $subject, $body, $res);
        db()->prepare('UPDATE ' . t('account') . ' SET pw_reminder_at = ? WHERE id = ?')->execute([gmdate('Y-m-d H:i:s', $now), $id]);
        audit('mail.pw_reminder', 'user:' . $id, ['state' => $state, 'recipients' => $sum['total'], 'ok' => $sum['ok'], 'failed' => $sum['failed']], 'system:cron', 0);
        $log[] = "Passwort-Erinnerung $id ($state): {$sum['ok']}/{$sum['total']} zugestellt";
    }
    users(false, true);

    $set = stage1_set_at();
    $max = (int)cfg('auth.stage1_max_age_days', 0);
    if ($set !== '' && $max > 0 && $cc1 !== '') {
        $due = utc_ts($set) + $max * 86400;
        $last = (int)(kv_get('stage1_reminder_ts') ?? 0);
        if ($now >= $due - (int)cfg('auth.password_remind_days', 14) * 86400 && $now - $last >= $repeat) {
            $vars = ['name' => 'Verantwortliche', 'what' => 'Das gemeinsame Zugangspasswort (Stufe 1)',
                'phrase' => ($now >= $due ? 'sollte seit ' : 'sollte bis ') . fmt_local(gmdate('Y-m-d H:i:s', $due))
                    . ' Uhr gewechselt werden (Menü System → Zugangspasswort)', 'url' => $url];
            $subject = trim(render_tpl($tpl['subject'], $vars));
            $body = render_tpl($tpl['body'], $vars);
            $sum = mail_record('pw_reminder', null, $subject, $body, mail_deliver(['to' => [$cc1], 'subject' => $subject, 'body' => $body]));
            kv_set('stage1_reminder_ts', (string)$now);
            audit('mail.pw_reminder', 'stage1', ['recipients' => $sum['total'], 'ok' => $sum['ok'], 'failed' => $sum['failed']], 'system:cron', 0);
            $log[] = 'Erinnerung Wechsel Zugangspasswort Stufe 1';
        }
    }
    return $log;
}

/* ====================================================================== */
/* Systemprüfung (System-Seite und `php setup.php check`)                 */
/* ====================================================================== */

/** Liste von [ok, Meldung]. */
function system_check(): array
{
    $r = [];
    $chk = function (bool $ok, string $msg) use (&$r): void {
        $r[] = [$ok, $msg];
    };
    $keyOk = false;
    try {
        master_key();
        $keyOk = true;
        $chk(true, 'Master-Key vorhanden');
    } catch (Throwable $e) {
        $chk(false, $e->getMessage());
    }
    $dbOk = false;
    try {
        db();
        $dbOk = true;
        $chk(true, 'Datenbank erreichbar, Tabellen vorhanden');
    } catch (Throwable $e) {
        $chk(false, 'Datenbank nicht erreichbar: ' . $e->getMessage());
    }
    $chk(stage1_hash() !== '', 'Zugangspasswort Stufe 1 gesetzt');
    $chk(stage1_set_at() !== '', 'Datum des Zugangspassworts bekannt (sonst einmal neu setzen)');
    $chk($dbOk && count(array_filter(users(), fn($u) => $u['role'] === 'admin')) > 0, 'Mindestens ein aktiver Admin');
    foreach ($dbOk ? users(true) : [] as $id => $u) {
        if (!$u['mac_ok']) {
            $chk(false, "Benutzer $id: Integritätsfehler (Zeile in der Datenbank verändert?)");
        }
    }
    foreach ($dbOk ? users() : [] as $id => $u) {
        if ($u['totp_secret'] === '') {
            $chk(false, "Benutzer $id: Authenticator-App noch nicht gekoppelt (passiert beim ersten Login)");
        }
    }
    foreach ($dbOk && $keyOk ? ['stage1', 'stage1_user', 'recipients', 'cc1', 'circles', 'locations', 'contacts', 'mail_prefix'] : [] as $k) {
        if (setting_broken($k)) {
            $chk(false, "Einstellung $k nicht lesbar – Datenbank verändert oder falscher Master-Key");
        }
    }
    $base = (string)cfg('app.base_url');
    $chk(!str_contains($base, 'example.invalid'), 'Adresse der Seite (app.base_url) gesetzt');
    $chk(str_starts_with($base, 'https://'), 'Adresse der Seite nutzt HTTPS');
    $n = $keyOk ? count(alarm_recipients()) : 0;
    $chk($n > 0, 'ALARM-Empfänger vorhanden (' . $n . ' in ' . ($keyOk ? count(alarm_circles()) : 0) . ' Alarmkreis(en))');
    if ($keyOk) {
        foreach (alarm_circles() as $c) {
            if (!$c['emails']) {
                $chk(false, 'Alarmkreis "' . $c['name'] . '" hat keine Adressen');
            }
        }
        $noMail = array_column(array_filter(locations_all(), fn($l) => !$l['emails']), 'name');
        $chk(!$noMail, 'E-Mail der Standortverwaltung hinterlegt' . ($noMail ? ' (fehlt bei: ' . implode(', ', $noMail) . ')' : ''));
    }
    $cc1 = $keyOk ? cc_default_mail1() : '';
    $chk($cc1 !== '' && !str_contains($cc1, 'example.invalid'), 'Kopie-Adresse (cc_default_mail1) gesetzt');
    $chk((string)cfg('mail.transport') === 'smtp', 'Mailversand per SMTP (nicht nur Testmodus "log")');
    $chk((string)cfg('cron.token', '') !== '', 'Cron-Token gesetzt (für den Aufruf per URL)');
    $last = $dbOk ? (int)(kv_get('cron_last') ?? 0) : 0;
    $chk($last > 0 && !cron_stale(), 'Cron läuft (letzter Lauf: ' . ($last ? fmt_local(gmdate('Y-m-d H:i:s', $last)) : 'noch nie') . ')');
    if ($dbOk && $keyOk) {
        $circ = alarm_circles();
        if (array_filter($circ, fn($c) => $c['signal'])) {
            $chk(channel_enabled('signal'), 'Signal: Empfänger hinterlegt, Gateway in config.local.inc.php ' . (channel_enabled('signal') ? 'eingerichtet' : 'NICHT eingerichtet (channels.signal)'));
        }
        if (array_filter($circ, fn($c) => $c['groupalarm'] !== '')) {
            $chk(channel_enabled('groupalarm'), 'GroupAlarm: Szenario hinterlegt, Zugang in config.local.inc.php ' . (channel_enabled('groupalarm') ? 'eingerichtet' : 'NICHT eingerichtet (channels.groupalarm)'));
        }
        $v = audit_verify();
        $chk($v['ok'], 'Protokoll-Kette ' . ($v['ok'] ? 'intakt' : 'DEFEKT: ' . $v['error']) . " ({$v['count']} Einträge, Kopf-Hash {$v['head']})");
    }
    $json = (string)cfg('app.json_path');
    $errs = bcm_validate(json_decode((string)@file_get_contents($json), true) ?? []);
    $chk(!$errs, 'config.json Struktur' . ($errs ? ': ' . implode('; ', $errs) : ''));
    $chk(!is_writable($json), 'config.json für PHP schreibgeschützt (Rechte 0444)');
    if (!$errs) {
        foreach (bcm_lint(bcm()) as $w) {
            $chk(false, 'Textprüfung: ' . $w);
        }
    }
    $chk(!is_file(__DIR__ . '/install.php') || is_installed(), 'Einrichtungsassistent gesperrt');
    return $r;
}

/** Eingerichtet = Master-Key, Datenbank und mindestens ein Admin. Sperrt install.php. */
function is_installed(): bool
{
    try {
        master_key();
        db();
        return count(array_filter(users(), fn($u) => $u['role'] === 'admin')) > 0;
    } catch (Throwable $e) {
        return false;
    }
}

/** Eingabefeld für den TOTP-Code eines Admins (Bestätigung einzelner Aktionen). */
function totp_input(string $idSuffix): string
{
    return '<label class="form-label small" for="t' . h($idSuffix) . '">Ihr TOTP-Code</label>'
        . '<input class="form-control mb-2" id="t' . h($idSuffix) . '" type="text" name="totp" inputmode="numeric" pattern="[0-9 ]{6,7}" maxlength="7" autocomplete="one-time-code" required>';
}

/** Prüft den TOTP-Code einer Admin-Aktion inkl. Sperre und Protokoll. Rückgabe: Fehlermeldung oder null. */
function admin_totp_check(array $user, string $object, string $action): ?string
{
    if (($wait = throttle_locked('s2t', $user['id'])) > 0) {
        return 'Zu viele ungültige Codes. Bitte in ca. ' . (int)ceil($wait / 60) . ' Minute(n) erneut versuchen.';
    }
    $good = totp_verify_user($user, (string)($_POST['totp'] ?? ''));
    throttle_record('s2t', $user['id'], $good);
    if (!$good) {
        fail_delay();
        audit('totp.fail', $object, ['action' => $action]);
        return 'Der Bestätigungscode ist ungültig oder bereits verwendet.';
    }
    return null;
}

/** otpauth-URI für Authenticator-Apps */
function totp_uri(string $userId, string $secretB32): string
{
    $issuer = (string)cfg('app.title', 'Status');
    return 'otpauth://totp/' . rawurlencode($issuer . ':' . $userId) . '?secret=' . $secretB32
        . '&issuer=' . rawurlencode($issuer) . '&algorithm=SHA1&digits=6&period=30';
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
    echo '<a class="visually-hidden-focusable" href="#inhalt">Zum Inhalt springen</a>';
    echo '<header class="d-flex flex-wrap align-items-center gap-2 mb-3 pb-2 border-bottom">';
    echo '<p class="app-title fw-bold me-auto">' . h((string)cfg('app.title', 'Status')) . '</p>';
    echo '<nav class="nav nav-pills">';
    $links = ['status' => ['status.php', 'Status'], 'change' => ['change.php', 'Einstellungen']];
    if (session_status() === PHP_SESSION_ACTIVE && (stage2_user()['role'] ?? '') === 'admin') {
        $links['admin'] = ['admin.php', 'Benutzer'];
        $links['system'] = ['system.php', 'System'];
    }
    foreach ($links as $k => [$href, $label]) {
        echo '<a class="nav-link py-1 px-2' . ($active === $k ? ' active" aria-current="page' : '') . '" href="' . $href . '">' . $label . '</a>';
    }
    echo '</nav>';
    $s2 = session_status() === PHP_SESSION_ACTIVE ? stage2_user() : null;
    if ($showLogout) {
        echo '<form method="post" action="index.php" class="m-0">' . csrf_field()
            . '<input type="hidden" name="action" value="logout"><button class="btn btn-outline-secondary btn-sm" type="submit">Abmelden</button></form>';
    }
    echo '</header>';
    if (session_status() === PHP_SESSION_ACTIVE && stage1_ok()) {
        // Abmeldezeit mit Vorwarnung und Verlängern-Knopf, ohne JavaScript: eigener Rahmen, damit Verlängern keine Eingaben verwirft
        echo '<iframe class="session-frame" name="sitzung" src="sitzung.php" title="Abmeldung bei Untätigkeit und Sitzung verlängern"></iframe>';
    }
    echo '<div id="inhalt" tabindex="-1"></div>';
    if ($s2 && cron_stale()) {
        echo '<div class="alert alert-warning" role="alert"><strong>Cron läuft nicht</strong> (letzter Lauf vor ' . (int)cron_age_minutes()
            . ' Minuten). Ohne Cron gibt es keine Erinnerungen und kein automatisches Ende von Meldungen. '
            . ($s2['role'] === 'admin' ? 'Bitte den Cronjob beim Hoster prüfen (<a href="system.php">System</a>).' : 'Bitte einen Admin informieren.') . '</div>';
    }
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

/** Kontaktangaben einer Meldung (Telefon, E-Mail, Videokonferenz) */
function render_contacts(array $contacts): void
{
    if (!$contacts) {
        return;
    }
    echo '<h3 class="h6 text-body-secondary mb-2">Kontakt</h3><ul class="list-group mb-3">';
    foreach ($contacts as $c) {
        echo '<li class="list-group-item"><div class="fw-semibold">' . h($c['name']) . '</div><div class="d-flex flex-wrap gap-3">';
        if ($c['phone'] !== '') {
            echo '<a class="tel" href="' . h(tel_href($c['phone'])) . '">' . h($c['phone']) . '</a>';
        }
        if ($c['email'] !== '') {
            echo '<a href="mailto:' . h($c['email']) . '">' . h($c['email']) . '</a>';
        }
        if ($c['url'] !== '') {
            $host = (string)parse_url($c['url'], PHP_URL_HOST);
            echo '<a href="' . h($c['url']) . '" rel="noopener noreferrer">' . h($c['platform'] !== '' ? $c['platform'] : 'Videokonferenz')
                . '</a> <span class="small text-body-secondary">(' . h($host) . ')</span>';
        } elseif ($c['platform'] !== '') {
            echo '<span>' . h($c['platform']) . '</span>';
        }
        if ($c['meeting'] !== '') {
            echo '<span>Konferenz-ID: <span class="font-monospace">' . h($c['meeting']) . '</span></span>';
        }
        echo '</div></li>';
    }
    echo '</ul>';
}

/**
 * Meldungskarte. $detail = true: zusätzlich Autor, ALARM-Mail, Notiz (nur Stufe 2). Ist $row['gone'] gesetzt
 * (expired | ended), wird die Karte ausgegraut mit "nicht mehr gültig" bzw. "zurückgenommen/gelöst" angezeigt.
 */
/** Gilt die Meldung für alle? Ja ohne Standortliste (Zielgruppe ALLE) oder wenn alle Standorte gewählt sind. */
function status_for_all(array $p): bool
{
    if (($p['audience'] ?? '') === 'ALLE' || empty($p['locations'])) {
        return true;
    }
    $all = array_column(bcm()['locations'] ?? [], 'id');
    return $all !== [] && !array_diff($all, array_column($p['locations'], 'id'));
}

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
    $gone = (string)($row['gone'] ?? '');
    echo '<section class="card shadow-sm mb-3 status-card sev-' . h($sev) . ($gone !== '' ? ' status-gone' : '') . '"><div class="card-body">';
    echo '<div class="d-flex flex-wrap gap-1 mb-2">';
    if ($gone === 'expired') {
        echo '<span class="badge text-bg-secondary text-uppercase">Nicht mehr gültig</span>';
    } elseif ($gone === 'ended') {
        echo '<span class="badge text-bg-secondary text-uppercase">Zurückgenommen / gelöst</span>';
    } else {
        echo severity_badge($sev);
    }
    if (!empty($p['exercise'])) {
        echo '<span class="badge text-bg-dark text-uppercase">Übung</span>';
    }
    echo '</div>';
    if ($sev !== 'ok' && status_for_all($p)) {
        echo '<p class="status-scope mb-1">Für alle:</p>';
    }
    echo '<h2 class="status-label mb-2">' . h($p['label']) . '</h2>';
    echo '<p class="mb-3">' . nl2br(h($p['text'])) . '</p>';
    if (!empty($p['locations'])) {
        echo '<h3 class="h6 text-body-secondary mb-2">Betroffene Standorte · Rufnummer für Rückfragen</h3><ul class="list-group mb-3">';
        foreach ($p['locations'] as $l) {
            echo '<li class="list-group-item d-flex flex-wrap justify-content-between gap-1"><span>' . h($l['name']) . '</span>'
                . '<span><a class="tel" href="' . h(tel_href($l['phone'])) . '">' . h($l['phone']) . '</a>'
                . (!empty($l['default_phone']) ? ' <span class="small text-body-secondary">(zentrale Rufnummer)</span>' : '') . '</span></li>';
        }
        echo '</ul>';
    } elseif ($sev !== 'ok') {
        echo '<p>Rückfragen: <a class="tel" href="' . h(tel_href($p['default_phone'])) . '">' . h($p['default_phone']) . '</a></p>';
    }
    if ($gone === '') {
        render_contacts((array)($p['contacts'] ?? []));
    }
    echo '<p class="small text-body-secondary mb-0">';
    echo $row['created_at'] ? 'Stand: ' . h(fmt_local($row['created_at'])) . ' Uhr' : 'Stand: ' . h(fmt_local(now_utc())) . ' Uhr';
    if ($gone === 'ended') {
        echo '<br>Beendet: ' . h(fmt_local((string)$row['gone_at'])) . ' Uhr';
    } elseif (!empty($row['valid_until'])) {
        echo '<br>' . ($gone === 'expired' ? 'Abgelaufen: ' : 'Gültig bis: ') . h(fmt_local($row['valid_until'])) . ' Uhr';
    }
    echo '</p>';
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

/** Alle Meldungen: gültige (oder "Regelbetrieb"), darunter ausgegraut die abgelaufenen/beendeten der letzten Stunden. */
function render_board(array $board, bool $detail = false): void
{
    foreach ($board['unverified'] as $r) {
        if ($r['payload']) {
            render_status_card($r, $detail);
        }
    }
    if (!$board['live']) {
        render_status_card(null, false);
    }
    foreach ($board['live'] as $r) {
        render_status_card($r, $detail);
    }
    if ($board['recent']) {
        echo '<h2 class="h6 text-body-secondary mt-4 mb-2">Nicht mehr gültig (letzte ' . (int)cfg('display.keep_hours', 48) . ' Stunden)</h2>';
        foreach ($board['recent'] as $r) {
            render_status_card($r, $detail);
        }
    }
}
