# Betrieb

## Regelmäßige Aufgaben

| Wann | Was | Wer |
|---|---|---|
| alle 5 Min. | `cron.php?t=…` (Erinnerungen, Audit-Anker, Aufräumen); Adresse unter **System** | automatisch (Hoster-Cron oder Cron-Dienst) |
| alle 5 Min. | externer Uptime-Check auf `health.php` (siehe [Überwachung](#überwachung)) | externer Dienst |
| täglich | Audit-Anker-Mail prüfen und archivieren (Betreff "Status-BCM Audit-Anker"); "Audit-Kette: OK" muss darin stehen | ISB / `cc_default_mail1` |
| täglich | Datenbank-Backup | Hoster |
| monatlich | **System → Prüfung** und Seite **Benutzer**: Wer braucht den Zugang noch? | Admin |
| halbjährlich | Übung mit Status "Übung" inkl. ALARM-Mail, Signal und GroupAlarm | Notfallorganisation |
| halbjährlich bzw. nach Bedarf | Protokoll-Export (PDF) für die Revision ablegen, Kopf-Hash mit dem Audit-Anker vergleichen | ISB |
| jährlich | Aushang (**System → Aushang**) prüfen und neu drucken, wenn sich Adresse oder Rufnummern geändert haben | Admin |
| jährlich bzw. nach Erinnerung | Zugangspasswort Stufe 1 wechseln (**System**) und neu bekannt geben | Admin |
| bei Personalwechsel | Benutzer deaktivieren (**Benutzer**), Alarmkreise und Standort-Adressen pflegen (**System**) | Admin |

## Was wo erledigt wird

| Aufgabe | Browser (ohne Kommandozeile) | Kommandozeile (optional) |
|---|---|---|
| Ersteinrichtung | `install.php` | `init`, `set-stage1`, `add-user`, … |
| Benutzer anlegen, zurücksetzen, deaktivieren, Rolle | **Benutzer** | `add-user`, `reset-password`, `disable-user`, `enable-user` |
| Gemeinsamer Zugang (Benutzername, Passwort) | **System** | `set-stage1-user`, `set-stage1` |
| Alarmkreise, Kopie-Adresse | **System** | `add-recipient`, `list-circles`, `remove-recipient`, `set-cc1` |
| Standorte (Name, Durchwahl, E-Mail Standortverwaltung), Kontakte, Betreff-Präfixe | **System** | – |
| Prüfung, Protokoll-Kette, Cron-Status | **System → Prüfung** | `check`, `verify-audit` |
| Protokoll exportieren (CSV/PDF) | **System → Protokoll-Export** | – |
| Aushang mit QR-Code | **System** oder **Einstellungen** | – |
| Signal-Empfänger, GroupAlarm-Szenario je Kreis | **System → Alarmkreise** | – |
| Zugangsdaten Signal-Gateway, GroupAlarm | `config.local.inc.php` per FTP | ebenso |
| Anmeldestatistik | **Einstellungen → Nutzung**, **System** | `stats` |
| Testmail, Cron einmal auslösen | **System** | `php cron.php` |
| Datenbank-, SMTP-Daten ändern | `config.local.inc.php` per FTP bearbeiten | ebenso |
| Meldungstexte, Mail-Vorlagen | `config.json` per FTP austauschen (bzw. Git) | ebenso |
| Letzter Admin ausgesperrt | Notfallzugang (unten) | `reset-password` |

Browser und Kommandozeile schreiben in dieselben Speicherorte und lassen sich mischen.

## Befehlsübersicht setup.php (optional)

```
php setup.php init                      Master-Key + Cron-Token erzeugen
php setup.php set-stage1                Zugangspasswort Stufe 1 setzen (Datum wird gespeichert)
php setup.php set-stage1-user <name>    Benutzername des gemeinsamen Zugangs (Standard: zugang)
php setup.php add-user <id> "<Name>" <mail> [admin|editor] [--config]
php setup.php list-users                Rollen, Passwortalter, Gültigkeit, TOTP, Integrität
php setup.php reset-password <id>       Einmalpasswort (Notfall, z. B. letzter Admin ausgesperrt)
php setup.php disable-user <id> | enable-user <id>
php setup.php migrate-users             Benutzer aus config.local.inc.php in die DB übernehmen
php setup.php add-recipient <mail> [kreis]   Adresse in Alarmkreis (Standard: erster Kreis; neuer Name legt Kreis an)
php setup.php list-circles | remove-recipient <kreis> <nr>
php setup.php set-cc1 <mail>            cc_default_mail1 verschlüsselt setzen
php setup.php encrypt-value <text>      beliebigen Konfigurationswert verschlüsseln
php setup.php install-db                Tabellen anlegen (passiert sonst automatisch)
php setup.php check                     Gesamtprüfung inkl. Meldungstexte
php setup.php verify-audit              Hash-Kette des Protokolls prüfen
php setup.php stats [Tage]              Anmeldungen und Lesezähler
php setup.php totp-check <id> <code>    TOTP-Einrichtung testen
```

## Überwachung

Die Seite überwacht sich selbst und lässt sich von außen überwachen.

**Cron-Ausfall:** Läuft der Cron länger als 15 Minuten nicht (`monitor.cron_stale_minutes`), dann

* sehen angemeldete Personen mit persönlicher Kennung oben einen gelben Hinweis,
* zeigt **System → Prüfung** "offen",
* geht beim nächsten Seitenaufruf eine Warnmail an `cc_default_mail1` (höchstens stündlich),
* antwortet `health.php` mit 503 `cron`.

Der Cron kann seinen eigenen Ausfall nicht melden. Deshalb prüfen die Seitenaufrufe. Ruft niemand die Seite auf,
merkt das nur der externe Check.

**Externer Uptime-Check:** `https://status.ihre-domain.de/health.php` (Adresse unter **System → Cron**). Antwort
200 `ok` heißt: Webserver, PHP, Datenbank und Cron laufen. 503 `db` oder `cron` nennt den Grund. Die Seite verrät
keine Inhalte. Mit `monitor.health_token` antwortet sie nur mit `?t=<token>` oder dem Header `X-Health-Token`.

Geeignete Dienste: UptimeRobot, Better Stack, Uptime Kuma (selbst betrieben, aber **nicht** in der eigenen IT, die
ja ausfallen kann), die Überwachung des Hosters. Einstellung: HTTP(S)-Check alle 5 Minuten, Schlüsselwort `ok`,
Alarm nach 2 Fehlschlägen. Der Alarm des Dienstes muss **außerhalb** der eigenen Mail-Infrastruktur ankommen (App,
SMS oder privates Postfach der Bereitschaft), sonst fällt er zusammen mit der Mail aus.

## Weitere Alarmkanäle: Signal und GroupAlarm

E-Mail fällt bei einem IT-Ausfall oft mit aus. Deshalb kann jede ALARM-Mail zusätzlich über **Signal** und
**GroupAlarm** gehen. Empfänger und Szenarien pflegen Admins je Alarmkreis unter **System**. Die Zugangsdaten stehen
nur in `config.local.inc.php`: Wer sie im Browser ändern könnte, könnte Alarme unbemerkt umleiten.

### Signal einrichten

Signal hat keine offizielle Schnittstelle für Organisationen. Der übliche Weg ist
[signal-cli-rest-api](https://github.com/bbernhard/signal-cli-rest-api) (Open Source, Docker) mit einer eigenen
Rufnummer. **Voraussetzungen und Grenzen, offen gesagt:**

* **Ein eigener Server ist nötig.** Ein einfacher PHP-Webspace kann signal-cli nicht ausführen (Java/Docker, ständig
  laufender Dienst). Geeignet ist ein kleiner vServer, ebenfalls außerhalb der eigenen IT.
* **Eine eigene Mobilfunk- oder Festnetznummer** nur für die Alarmierung (Registrierung per SMS oder Anruf).
* **HTTPS und Zugangsschutz davor.** Die API hat selbst keine Anmeldung. Sie muss hinter einem Reverse-Proxy
  (z. B. Caddy oder nginx) mit TLS und Bearer-Token oder Basic-Auth liegen. Ohne Schutz könnte jeder über Ihre Nummer
  Nachrichten senden. Status-BCM sendet nur über https (Ausnahme: localhost), folgt keinen Umleitungen und prüft das
  Zertifikat.
* **Pflege:** signal-cli muss aktuell gehalten werden, sonst lehnt Signal die Verbindung irgendwann ab. Die Nummer
  muss erreichbar bleiben.
* **Keine Zustellgarantie:** Signal meldet die Übergabe, nicht das Lesen. Signal ergänzt die Mail, es ersetzt keine
  Telefonkette.
* **Datenschutz:** Der Gateway-Server sieht die Nachrichten im Klartext (Ende-zu-Ende-Verschlüsselung erst ab dort).
  Die Rufnummern der Empfänger gelangen an den Signal-Dienst (Signal Technology Foundation, USA). Siehe
  [Governance → Datenschutz](06-governance.md#7-datenschutz).

Schritte:

1. signal-cli-rest-api auf dem Server installieren (Docker, `MODE=normal` oder `json-rpc`), die Nummer registrieren
   und verifizieren (Anleitung des Projekts).
2. Reverse-Proxy mit TLS und Token davor. Nur `POST /v2/send` freigeben.
3. In `config.local.inc.php`:

   ```php
   'channels' => [
       'signal' => [
           'url'    => 'https://signal.ihre-domain.de/v2/send',
           'number' => '+4915112345678',
           'token'  => 'langes-zufaelliges-token',   // wird als "Authorization: Bearer …" gesendet
       ],
   ],
   ```

4. Unter **System → Alarmkreise → Signal und GroupAlarm** die Empfänger eintragen: Rufnummern im Format `+49…` oder
   Signal-Gruppen als `group.…` (die ID liefert `GET /v1/groups/<nummer>` der API). Gruppen sind meist einfacher zu
   pflegen als einzelne Nummern.
5. **Signal-Testnachricht an diesen Kreis** senden und den Empfang prüfen.

### GroupAlarm einrichten

[GroupAlarm](https://www.groupalarm.com) ist ein Alarmierungsdienst (App, SMS, Anruf) mit Rückmeldefunktion.
Status-BCM löst über die REST-Schnittstelle ein **Szenario** aus; wer wie alarmiert wird, legen Sie in GroupAlarm fest.

1. In GroupAlarm ein Szenario je Alarmkreis anlegen (z. B. "IT-Bereitschaft").
2. Einen **Personal-Access-Token** mit Alarmierungsrecht erzeugen (Profil → Sicherheit) und die **Organisations-ID**
   notieren.
3. In `config.local.inc.php`:

   ```php
   'channels' => [
       'groupalarm' => [
           'token'           => 'token-aus-groupalarm',
           'organization_id' => 12345,
           'kinds'           => ['new', 'update', 'end'],   // bei welchen ALARM-Mails auslösen
       ],
   ],
   ```

4. Unter **System → Alarmkreise** die **Szenario-ID** beim passenden Kreis eintragen.
5. In einer Übung prüfen. Die Signal-Testnachricht löst GroupAlarm bewusst nicht aus.

Status-BCM sendet `POST https://app.groupalarm.com/api/v1/alarm` mit Header `Personal-Access-Token` und den Feldern
`eventName`, `message`, `organizationID`, `scenarioID`, `startTime`. *Bitte vor dem Echtbetrieb mit der aktuellen
API-Dokumentation von GroupAlarm abgleichen;* eine abweichende Adresse lässt sich über `channels.groupalarm.url`
einstellen.

**Für beide Kanäle gilt:** Zum Testen ohne echten Versand `channels.transport = 'log'` setzen; dann landen die Aufrufe
(ohne Zugangsdaten) als JSON in `storage/outbox`. Fehler stehen im Server-Fehlerlog und in der Rückmeldung nach dem
Setzen; im Protokoll steht je Kanal die Zahl erfolgreicher und fehlgeschlagener Zustellungen.

## Update auf eine neue Version

1. Neue Version herunterladen (Git oder ZIP). Wer lokal PHP hat: `php tests/selftest.php`, `php tests/webtest.php`,
   `php tests/installtest.php`.
2. Backup von Datenbank und `config.local.inc.php`.
3. Geänderte Dateien hochladen. `config.local.inc.php` dabei **nicht** überschreiben.
4. Seite einmal aufrufen. Neue Tabellen und Spalten legt die Anwendung selbst an. Für das Update auf 1.3 braucht der
   Datenbank-Benutzer einmalig das Recht `ALTER` (bei den meisten Hostern ohnehin vergeben). Fehlt es, nennt die Seite
   den SQL-Befehl, den Sie alternativ in phpMyAdmin ausführen. `install.php` nur hochladen, wenn Sie den
   Notfallzugang brauchen; eingerichtet ist es ohnehin gesperrt.
5. **System → Prüfung** ansehen (mit SSH auch `php setup.php check`).

## Datensicherung und Wiederherstellung

* **Datenbank:** über die Sicherung des Hosters (Kundenmenü) oder `mysqldump --single-transaction --triggers statusbcm > sbcm-YYYYMMDD.sql`.
  Die Datenbank enthält auch die im Browser gepflegten Einstellungen (verschlüsselt).
* **config.local.inc.php:** bei jeder Änderung neu sichern, getrennt von der Datenbank.
* **Wiederherstellung:** Dump einspielen, `config.local.inc.php` zurücklegen, **System → Prüfung** (bzw.
  `php setup.php verify-audit`). Der Kopf-Hash muss zur Anker-Mail des Sicherungstags passen.

## Notfälle im Betrieb

| Problem | Lösung |
|---|---|
| Einziger Admin hat Passwort und/oder Smartphone verloren | Gibt es einen zweiten Admin: **Benutzer → Passwort zurücksetzen / App neu koppeln**. Sonst **Notfallzugang**: per FTP die Datei `storage/notfall.txt` anlegen, Zeile 1 die Benutzerkennung, Zeile 2 eine selbst gewählte Passphrase (mind. 12 Zeichen). Dann `install.php` aufrufen (falls gelöscht, wieder hochladen), Kennung und Passphrase eingeben. Es erscheint ein Einmalpasswort, die App wird neu gekoppelt, die Datei gelöscht, der Vorgang protokolliert. Mit SSH: `php setup.php reset-password <id>`. |
| Smartphone mit TOTP-App verloren | Ein anderer Admin: **Benutzer → Authenticator-App neu koppeln**. Danach Passwort zurücksetzen, falls nötig. |
| "Zu viele Versuche" | Nach 15 Min. automatisch wieder frei. Fehlversuche erscheinen im Protokoll. |
| TOTP-Code wird immer abgelehnt | Uhrzeit auf dem Smartphone auf automatisch stellen. Hilft das nicht, App neu koppeln lassen (ein anderer Admin oder Notfallzugang). |
| Keine Mails | **System → Mailversand testen**. Schlägt das fehl: SMTP-Daten in `config.local.inc.php` prüfen (oder `install.php` ist gesperrt, also per FTP). Im Protokoll steht die Zahl fehlgeschlagener Zustellungen. |
| Keine Erinnerungen | **System → Prüfung**, Zeile "Cron läuft". Steht dort "noch nie" oder eine alte Uhrzeit, den Cronjob beim Hoster prüfen. |
| "Integritätsfehler" bei Benutzer oder Status | Datenbank wurde außerhalb der Anwendung verändert. Nicht reparieren, sondern Sicherheitsvorfall melden. Benutzer mit Fehler können sich nicht anmelden. |
| Protokoll meldet "FEHLER" | Sicherheitsvorfall. DB-Dump sichern, mit Anker-Mails vergleichen, ISB informieren. |
| Master-Key verloren | Gespeicherte Status, Protokolle und Einstellungen sind nicht mehr lesbar. Alte DB archivieren, `config.local.inc.php` entfernen, mit neuem Tabellen-Präfix neu einrichten (`install.php`). |

## nginx

`.htaccess` wirkt auf nginx nicht. Sperren Sie die Dateien per `location`:

```nginx
location ~ /\.(?!well-known) { deny all; }
location ~ ^/(tests|docs|storage)/ { deny all; }
location ~ ^/(config\.inc\.php|config\.local\.inc\.php|lib\.inc\.php|qr\.inc\.php|pdf\.inc\.php|setup\.php|config\.json)$ { deny all; }
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
Tabellen oder Spalten müssen die Rechte vorübergehend erweitert werden (`CREATE`, `ALTER`).

## Tests

```bash
php tests/selftest.php      # Einheiten- und Integrationstest (SQLite)
php tests/webtest.php       # kompletter Ablauf per HTTP mit php -S (benötigt die curl-Erweiterung)
php tests/installtest.php   # Einrichtung im Browser, System-Seite, Notfallzugang (php -S, curl)
# gegen MySQL/MariaDB (legt Tabellen mit Zufallspräfix an und entfernt sie wieder):
SBCM_TEST_DSN="mysql:host=localhost;dbname=test;charset=utf8mb4" SBCM_TEST_USER=test SBCM_TEST_PASS=… php tests/selftest.php
```
