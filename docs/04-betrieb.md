# Betrieb

## Regelmäßige Aufgaben

| Wann | Was | Wer |
|---|---|---|
| alle 5 Min. | `cron.php` (Erinnerungen, Audit-Anker, Aufräumen) | automatisch |
| täglich | Audit-Anker-Mail prüfen und archivieren (Betreff "Status-BCM Audit-Anker"); "Audit-Kette: OK" muss darin stehen | ISB / `cc_default_mail1` |
| täglich | Datenbank-Backup | Hoster |
| monatlich | `php setup.php check`, `php setup.php list-users`: Wer braucht den Zugang noch? | Admin |
| halbjährlich | Übung mit Status "Übung" inkl. ALARM-Mail | Notfallorganisation |
| jährlich bzw. nach Erinnerung | Zugangspasswort Stufe 1 wechseln (`set-stage1`) und neu bekannt geben | Admin |
| bei Personalwechsel | Benutzer deaktivieren, Empfänger pflegen (`add-recipient` / `remove-recipient`) | Admin |

## Befehlsübersicht setup.php

```
php setup.php init                      Master-Key + Cron-Token erzeugen
php setup.php set-stage1                Zugangspasswort Stufe 1 setzen (Datum wird gespeichert)
php setup.php add-user <id> "<Name>" <mail> [admin|editor] [--config]
php setup.php list-users                Rollen, Passwortalter, Gültigkeit, TOTP, Integrität
php setup.php reset-password <id>       Einmalpasswort (Notfall, z. B. letzter Admin ausgesperrt)
php setup.php disable-user <id> | enable-user <id>
php setup.php migrate-users             Benutzer aus config.local.inc.php in die DB übernehmen
php setup.php add-recipient <mail> | list-recipients | remove-recipient <nr>
php setup.php set-cc1 <mail>            cc_default_mail1 verschlüsselt setzen
php setup.php encrypt-value <text>      beliebigen Konfigurationswert verschlüsseln
php setup.php install-db                Tabellen anlegen (passiert sonst automatisch)
php setup.php check                     Gesamtprüfung inkl. Meldungstexte
php setup.php verify-audit              Hash-Kette des Protokolls prüfen
php setup.php stats [Tage]              Anmeldungen und Lesezähler
php setup.php totp-check <id> <code>    TOTP-Einrichtung testen
```

## Update auf eine neue Version

1. Lokal `git pull`, dann `php tests/selftest.php` und `php tests/webtest.php`.
2. Backup von Datenbank und `config.local.inc.php`.
3. Geänderte Dateien hochladen. `config.local.inc.php` dabei **nicht** überschreiben.
4. Seite einmal aufrufen. Neue Tabellen legt die Anwendung selbst an.
5. `php setup.php check` (mit SSH) bzw. "Einstellungen" auf Systemhinweise prüfen.

## Datensicherung und Wiederherstellung

* **Datenbank:** `mysqldump --single-transaction --triggers statusbcm > sbcm-YYYYMMDD.sql` (oder über den Hoster).
* **config.local.inc.php:** bei jeder Änderung neu sichern, getrennt von der Datenbank.
* **Wiederherstellung:** Dump einspielen, `config.local.inc.php` zurücklegen, `php setup.php verify-audit`. Der
  Kopf-Hash muss zur Anker-Mail des Sicherungstags passen.

## Notfälle im Betrieb

| Problem | Lösung |
|---|---|
| Letzter Admin hat Passwort vergessen | Per SSH `php setup.php reset-password <id>`. Ohne SSH lokal `add-user <neu> … admin --config` ausführen und `config.local.inc.php` hochladen. |
| Smartphone mit TOTP-App verloren | Ein anderer Admin: **Benutzer → Authenticator-App neu koppeln**. Danach Passwort zurücksetzen, falls nötig. |
| "Zu viele Versuche" | Nach 15 Min. automatisch wieder frei. Fehlversuche erscheinen im Protokoll. |
| TOTP-Code wird immer abgelehnt | Uhrzeit auf dem Smartphone auf automatisch stellen; mit `php setup.php totp-check <id> <code>` testen. |
| Keine Mails | `mail.transport` = `smtp`? SMTP-Daten prüfen; im Protokoll steht die Zahl fehlgeschlagener Zustellungen. Testweise `transport` = `log`. |
| "Integritätsfehler" bei Benutzer oder Status | Datenbank wurde außerhalb der Anwendung verändert. Nicht reparieren, sondern Sicherheitsvorfall melden. Benutzer mit Fehler können sich nicht anmelden. |
| Protokoll meldet "FEHLER" | Sicherheitsvorfall. DB-Dump sichern, mit Anker-Mails vergleichen, ISB informieren. |
| Master-Key verloren | Gespeicherte Status und Protokolle sind nicht mehr lesbar. Neuinstallation (`init --force`), alte DB archivieren. |

## nginx

`.htaccess` wirkt auf nginx nicht. Sperren Sie die Dateien per `location`:

```nginx
location ~ /\.(?!well-known) { deny all; }
location ~ ^/(tests|docs|storage)/ { deny all; }
location ~ ^/(config\.inc\.php|config\.local\.inc\.php|lib\.inc\.php|setup\.php|config\.json)$ { deny all; }
location ~ \.(sqlite|db|log|eml|md)$ { deny all; }
location /assets/ { expires 1y; add_header Cache-Control "public, immutable"; }
```

Noch besser: `config.json` und `storage/` per `app.json_path` / `app.storage_dir` außerhalb des Webroots ablegen.

## Datenbank-Rechte härten (optional)

MySQL kann Rechte, die auf die ganze Datenbank vergeben wurden, nicht für einzelne Tabellen wieder entziehen. Wer das
Protokoll auch gegen die eigene Anwendung sperren will, vergibt die Rechte deshalb **je Tabelle**, nachdem die Tabellen
angelegt sind:

```sql
REVOKE ALL PRIVILEGES ON statusbcm.* FROM 'statusbcm'@'localhost';
GRANT SELECT, INSERT, UPDATE, DELETE ON statusbcm.sbcm_status        TO 'statusbcm'@'localhost';
GRANT SELECT, INSERT, UPDATE, DELETE ON statusbcm.sbcm_mail_log      TO 'statusbcm'@'localhost';
GRANT SELECT, INSERT, UPDATE, DELETE ON statusbcm.sbcm_login_attempt TO 'statusbcm'@'localhost';
GRANT SELECT, INSERT, UPDATE, DELETE ON statusbcm.sbcm_totp_used     TO 'statusbcm'@'localhost';
GRANT SELECT, INSERT, UPDATE, DELETE ON statusbcm.sbcm_kv            TO 'statusbcm'@'localhost';
GRANT SELECT, INSERT, UPDATE, DELETE ON statusbcm.sbcm_view_count    TO 'statusbcm'@'localhost';
GRANT SELECT, INSERT, UPDATE         ON statusbcm.sbcm_account       TO 'statusbcm'@'localhost';
GRANT SELECT, INSERT                 ON statusbcm.sbcm_audit         TO 'statusbcm'@'localhost';
GRANT LOCK TABLES                    ON statusbcm.*                  TO 'statusbcm'@'localhost'; -- für SELECT … FOR UPDATE (MySQL 8)
```

Danach kann selbst die Anwendung das Protokoll nicht mehr ändern, nur noch ergänzen. Vor einem Update mit neuen
Tabellen müssen die Rechte vorübergehend erweitert werden (CREATE).

## Tests

```bash
php tests/selftest.php      # Einheiten- und Integrationstest (SQLite)
php tests/webtest.php       # kompletter Ablauf per HTTP mit php -S (benötigt die curl-Erweiterung)
# gegen MySQL/MariaDB (legt Tabellen mit Zufallspräfix an und entfernt sie wieder):
SBCM_TEST_DSN="mysql:host=localhost;dbname=test;charset=utf8mb4" SBCM_TEST_USER=test SBCM_TEST_PASS=… php tests/selftest.php
```
