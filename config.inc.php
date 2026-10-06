<?php
/**
 * Status-BCM – zentrale Konfiguration (SQL, Mail, Sicherheit, Cron).
 *
 * WICHTIG:
 *  - Diese Datei ist Teil des Repos und enthält nur Platzhalter.
 *  - Alle echten Zugangsdaten/Geheimnisse gehören in `config.local.inc.php`
 *    (wird von `php setup.php ...` erzeugt, steht in .gitignore, Rechte 0600).
 *    Werte dort überschreiben die Werte hier (array_replace_recursive).
 *  - Die Datei gibt beim direkten Aufruf im Browser nichts aus (und wird
 *    zusätzlich per .htaccess gesperrt).
 */

if (!defined('SBCM')) {
    http_response_code(403);
    exit;
}

$config = [

    /* ---------------------------------------------------------------- App */
    'app' => [
        // Neutraler Titel (auf der Login-Seite sichtbar – keine Behörden-/Konzernnamen!)
        'title'       => 'Status',
        // Öffentliche URL ohne Slash am Ende (für Links in E-Mails)
        'base_url'    => 'https://status.example.invalid',
        'timezone'    => 'Europe/Berlin',
        // Pfad zur config.json (Status-Katalog, Standorte). Auf nginx-Hosting
        // besser außerhalb des Webroots ablegen und hier den Pfad eintragen.
        'json_path'   => __DIR__ . '/config.json',
        // Schreibbares Verzeichnis für Locks/Outbox/SQLite – möglichst außerhalb des Webroots.
        'storage_dir' => __DIR__ . '/storage',
    ],

    /* ---------------------------------------------------------------- SQL */
    'db' => [
        // MySQL/MariaDB (typisch für Mini-Webspace):
        'dsn'    => 'mysql:host=localhost;dbname=statusbcm;charset=utf8mb4',
        // Für lokale Tests: 'sqlite:{storage}/status.sqlite'
        'user'   => 'statusbcm',
        'pass'   => '',
        'prefix' => 'sbcm_',
        // Tabellen beim ersten Aufruf automatisch anlegen
        'auto_install' => true,
    ],

    /* ---------------------------------------------------------------- Mail (SMTP) */
    'mail' => [
        'transport'  => 'smtp',          // 'smtp' | 'log' (log = nur .eml in storage/outbox, für Tests)
        'host'       => 'smtp.example.invalid',
        'port'       => 587,
        'secure'     => 'starttls',      // 'starttls' | 'ssl' | 'none' (none nur für localhost)
        'user'       => '',
        'pass'       => '',
        'from_email' => 'status@example.invalid',
        'from_name'  => 'Status',
        'helo'       => '',              // leer = Hostname aus base_url
        'timeout'    => 15,
        'verify_peer'=> true,            // TLS-Zertifikat prüfen (nicht abschalten!)

        // "cc-default-Mail1": erhält Erinnerungen (zusammen mit dem Autor), Alarm-Kopien und den
        // täglichen Audit-Anker. Darf verschlüsselt sein (`php setup.php set-cc1 <mail>`).
        'cc_default_mail1' => 'isb@example.invalid',

        // ALARM-Empfänger: werden ausschließlich per BCC angeschrieben und nie in der
        // Oberfläche angezeigt. Einträge dürfen verschlüsselt sein (`php setup.php add-recipient`).
        'recipients' => [],
        'max_bcc_per_message' => 50,
    ],

    /* ---------------------------------------------------------------- Sicherheit */
    'security' => [
        // base64, 32 Byte – wird von `php setup.php init` erzeugt (config.local.inc.php)
        'master_key' => '',
    ],

    'auth' => [
        // Login Stufe 1 (gemeinsames Zugangspasswort, primär Crawler-/Zufallsschutz)
        // password_hash()-Wert – `php setup.php set-stage1`
        'stage1_hash' => '',

        // Login Stufe 2: Benutzer stehen in der Datenbank (admin.php, `php setup.php add-user`).
        // Hier nur für Webspaces ohne SSH der erste Admin (`php setup.php add-user ... --config` lokal ausführen):
        // id => [name, email, hash, totp_secret, pw_set_at]
        'users' => [],

        'max_failures'         => 5,     // Fehlversuche pro IP und Zeitfenster
        'max_failures_user'    => 10,    // Fehlversuche pro Benutzer und Zeitfenster
        'window_seconds'       => 900,
        'idle_minutes'         => 30,    // Session-Leerlauf Stufe 1
        'stage2_idle_minutes'  => 15,    // Session-Leerlauf Stufe 2
        'absolute_hours'       => 10,    // harte Session-Obergrenze
        'pending_ttl_seconds'  => 300,   // Gültigkeit der Vorschau vor dem Bestätigen
        'totp_window'          => 1,     // ±1 Zeitschritt (30 s) Toleranz
        // Passwörter Stufe 2 (Benutzerverwaltung admin.php). BSI IT-Grundschutz verlangt keinen regelmäßigen
        // Zwangswechsel mehr (Wechsel bei Anlass); 0 = unbefristet. Abgelaufen = Login möglich, aber sofortiger Wechsel
        // (keine Aussperrung im Ernstfall).
        'password_max_age_days'          => 365,
        'password_remind_days'           => 14,   // Erinnerung so viele Tage vor Ablauf
        'password_reminder_repeat_days'  => 7,    // Wiederholung bis geändert
        'password_min_length'            => 12,   // nie unter 12
        // Gemeinsames Passwort Stufe 1: Datum setzt `php setup.php set-stage1`; Erinnerung an cc_default_mail1
        'stage1_set_at'                  => '',
        'stage1_max_age_days'            => 365,
        // true = TOTP bei JEDER Änderung (auch Entwarnung); sonst nur lt. config.json / bei ALARM-Mail
        'totp_enforce_all'     => false,
        // true = persönliche Kennungen brauchen schon beim Login den TOTP-Code (gemeinsamer Lesezugang nie)
        'totp_at_login'        => true,
    ],

    /* ---------------------------------------------------------------- Cron */
    'cron' => [
        // Token für Aufruf per URL (cron.php?t=... oder Header X-Cron-Token). Leer = nur CLI.
        'token'        => '',
        'ip_allowlist' => [],            // optional: erlaubte Absender-IPs für den URL-Aufruf
    ],

    'reminder' => [
        'lead_minutes'      => 0,        // Erinnerung X Minuten VOR Ablauf (0 = zum Ablauf)
        'repeat_minutes'    => 60,       // Wiederholung bis bestätigt/beendet
        'max_count'         => 0,        // 0 = wiederholen, bis verlängert/beendet; >0 = Obergrenze
        // >0: Status nach so vielen Minuten nach Ablauf OHNE Bestätigung automatisch auf Regelbetrieb
        'auto_revert_after_minutes' => 0,
        // Täglich den aktuellen Audit-Hash an cc_default_mail1 mailen (erkennt Kürzen der Log-Tabelle)
        'anchor_mail'       => true,
    ],

    'limits' => [
        'max_validity_days' => 30,
    ],

    // Weitere Alarmkanäle neben der E-Mail. Empfänger (Signal) bzw. Szenario (GroupAlarm) je Alarmkreis unter System.
    // Zugangsdaten nur hier (per FTP), nie im Browser: Wer sie ändern kann, könnte Alarme umleiten.
    'channels' => [
        'transport' => '',               // '' = wie mail.transport ('log' schreibt nur nach storage/outbox), sonst 'http'
        'timeout'   => 10,               // Sekunden je Aufruf
        'signal' => [
            // signal-cli-rest-api (eigener Server, z. B. Docker), immer hinter HTTPS und Zugangsschutz
            'url'    => '',              // z. B. https://signal.ihre-domain.de/v2/send
            'number' => '',              // registrierte Absendernummer, z. B. +4915112345678
            'token'  => '',              // optional: "Authorization: Bearer …" (enc:v1:… möglich)
            'user'   => '', 'pass' => '', // optional: HTTP-Basic-Auth des vorgeschalteten Proxys
        ],
        'groupalarm' => [
            'url'             => 'https://app.groupalarm.com/api/v1/alarm',
            'token'           => '',     // Personal-Access-Token (enc:v1:… möglich)
            'organization_id' => 0,
            'mode'            => 'best-effort',
            'kinds'           => ['new', 'update', 'end'], // bei welchen ALARM-Mails auch GroupAlarm auslöst
        ],
    ],

    // Selbstüberwachung
    'monitor' => [
        'cron_stale_minutes' => 15,      // Cron länger nicht gelaufen -> Warnung (System, health.php, Mail an cc_default_mail1)
        'warn_repeat_minutes' => 60,     // Wiederholung der Warnmail
        'health_token' => '',            // optional: health.php nur mit ?t=<token> (für externe Uptime-Dienste)
    ],

    'net' => [
        // Nur setzen, wenn das Hosting hinter einem Reverse-Proxy sitzt
        'trusted_proxies' => [],
        'proxy_header'    => 'HTTP_X_FORWARDED_FOR',
    ],
];

$local = getenv('SBCM_LOCAL_CONFIG') ?: (__DIR__ . '/config.local.inc.php');
if (is_file($local)) {
    $override = require $local;
    if (is_array($override)) {
        $config = array_replace_recursive($config, $override);
    }
}

return $config;
