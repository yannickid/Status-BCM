# Status-BCM

Mini-Statusseite für das Notfall-/Krisenmanagement (BCM): ein Status ("Regelbetrieb", "Standort vorübergehend nicht
zugänglich", …) wird zentral gepflegt, ist für Beschäftigte nach einem Zugangspasswort sichtbar und kann per
ALARM-Mail verteilt werden. Läuft auf einem einfachen PHP-Webspace (PHP ≥ 8.0, MySQL/MariaDB, `openssl`, `pdo_mysql`),
ohne Composer und ohne externe Dienste.

## Dateien

| Datei | Zweck |
|---|---|
| `config.inc.php` | SQL, SMTP, Sicherheit, Cron, Erinnerungen (nur Platzhalter; echte Werte in `config.local.inc.php`) |
| `config.json` | Status-Katalog (Texte, Schweregrad, Geltungsbereich, Alarm/TOTP-Regeln), Standorte mit Durchwahl, Mail-Vorlagen |
| `index.php` | Hauptseite mit **Login Stufe 1** (gemeinsames Zugangspasswort) |
| `status.php` | aktueller Status nach Login Stufe 1 |
| `change.php` | Einstellungen nach **Login Stufe 2** (persönlich), Vorschau, TOTP, Verlauf, Protokoll |
| `cron.php` | Erinnerungen bei abgelaufener Gültigkeit, Audit-Anker, Aufräumen |
| `lib.inc.php` | gesamte Logik (Krypto, DB, Audit, Auth, TOTP, SMTP, Nutzungsstatistik) |
| `assets/bootstrap.min.css` | Bootstrap 5.3.8, lokal (kein CDN, kein JavaScript), Lizenz in `assets/bootstrap.LICENSE` |
| `assets/app.css` | eigenes Design (Mobile First), ergänzt Bootstrap |
| `setup.php` | CLI-Einrichtung (Schlüssel, Passwörter, Benutzer, Empfänger, Prüfungen) |
| `tests/selftest.php` | automatischer Selbsttest (SQLite, optional MySQL/MariaDB) |
| `tests/webtest.php` | Ablauftest über HTTP mit dem eingebauten Webserver (`php -S`) |

## Einrichtung

```bash
php setup.php init                                   # Master-Key + Cron-Token -> config.local.inc.php
php setup.php set-stage1                             # Zugangspasswort Stufe 1
php setup.php add-user yannick "Vorname Nachname" name@example.org   # Passwort + TOTP-Secret
php setup.php totp-check yannick 123456              # TOTP-App testen
php setup.php add-recipient person@example.org       # ALARM-Empfänger (verschlüsselt gespeichert)
php setup.php set-cc1 isb@example.org                # cc_default_mail1 (Erinnerungen, Audit-Anker), verschlüsselt
php setup.php install-db                             # Tabellen (passiert sonst automatisch beim ersten Aufruf)
php setup.php check                                  # Gesamtprüfung inkl. Textprüfung
```

Danach in `config.local.inc.php` `app.base_url`, `db.*` und `mail.*` (SMTP) eintragen; `config.inc.php` bleibt
unverändert (nur Platzhalter, wird von der lokalen Datei überschrieben). Passwörter sowie E-Mail-Adressen und TOTP-Secrets
der Benutzer speichert `setup.php` als Hash bzw. verschlüsselt (`enc:v1:…`); weitere Werte (z. B. `mail.pass`) lassen sich mit
`php setup.php encrypt-value <text>` verschlüsseln. Auf dem Webspace nur die Dateien hochladen, **nicht** `tests/` und `.git`. `config.local.inc.php` separat
sichern: Ohne den Master-Key sind gespeicherte Status und Protokolle nicht mehr lesbar.

Cron (alle 5 Minuten), je nach Hoster eine der beiden Varianten:

```
*/5 * * * *  php /pfad/zu/cron.php
*/5 * * * *  curl -fsS -H "X-Cron-Token: <cron.token>" https://status.example.org/cron.php
```

## Bedienung

1. `index.php`: Zugangspasswort (Stufe 1) → `status.php` zeigt den aktuellen Status samt betroffener Standorte und Rufnummer.
2. `change.php`: persönlicher Login (Stufe 2). Status wählen, ggf. Standorte, Dauer **oder** "Gültig bis", optional
   "ALARM-Mail senden" → **Vorschau** (exakt so sehen es alle) → **Verbindlich setzen**. Bei Alarm und Status mit
   `require_totp` ist dabei der 6-stellige TOTP-Code der Authenticator-App nötig.
3. Läuft die Gültigkeit ab, erinnert `cron.php` den Autor und `cc_default_mail1` per Mail, alle
   `reminder.repeat_minutes` erneut, bis verlängert oder beendet wurde (`reminder.max_count` = 0: ohne Obergrenze). In `change.php` dann "Verlängern" oder "Status beenden".

### Geltungsbereich (`audience` in `config.json`)

* `ALLE` – die Meldung gilt für alle, keine Standortauswahl.
* `ALLE_UND_ADRESSLISTE` – gilt für alle, zusätzlich werden die betroffenen Standorte (Auswahl aus `locations`) mit
  ihrer Durchwahl genannt. Hat ein Standort keine `phone`, wird `default_phone` verwendet.

## Sicherheitskonzept

* **Zwei Stufen:** Stufe 1 ist ein gemeinsames Zugangspasswort (Crawler-/Zufallsschutz; `noindex`-Header, `robots.txt`,
  keine Inhalte vor dem Login, Honeypot). Stufe 2 ist persönlich (Benutzer + Passwort) und Voraussetzung für Änderungen.
* **Keine Falschmeldungen:** Änderungen laufen immer über Vorschau → Bestätigung. Alarm-Mails und Status mit
  `require_totp` verlangen zusätzlich **TOTP** (RFC 6238, Authenticator-App, ohne SMS/Mail, Replay-Schutz,
  ±30 s Toleranz). Optional `auth.totp_enforce_all` für jede Änderung.
* **Audit-sicher:** Jede Änderung (wer, was, wann, wie: Aktion, vorher/nachher, TOTP ja/nein, IP, Browser) wird in
  derselben Datenbanktransaktion protokolliert. Das Protokoll ist eine **Hash-Kette mit HMAC** (jede Zeile enthält den
  Hash der Vorgängerzeile), Details sind verschlüsselt, DB-Trigger verbieten UPDATE/DELETE (sofern der DB-Benutzer
  `TRIGGER` anlegen darf). Veränderungen werden in `change.php` und mit `php setup.php verify-audit` erkannt.
  Das Kürzen am Kettenende erkennt der **tägliche Audit-Anker** (Kopf-Hash per Mail an `cc_default_mail1`).
  Empfehlung: DB-Benutzer ohne UPDATE/DELETE auf `sbcm_audit`.
* **Verschlüsselte Ablage:** Meldungstext, Standortdaten, Mail-Inhalte, Empfänger-Ergebnisse und Audit-Details liegen
  mit AES-256-GCM (HKDF-Teilschlüssel, Bindung an Datensatzkontext) in der DB. Die Statuszeilen tragen zusätzlich einen MAC; der aktive Status wird gegen den letzten Audit-Eintrag abgeglichen.
* **Ziel-Adressen geschützt:** nur in `config.local.inc.php` (verschlüsselt per `add-recipient`), Versand ausschließlich
  per BCC, in der Oberfläche und im Protokoll nur maskiert (`m****@e***.de`) bzw. als Anzahl.
* **Brute-Force-Bremse** je IP und Benutzer, verzögerte Fehlantworten, Session-Cookie `HttpOnly`/`SameSite=Strict`/
  `Secure`, Session-Erneuerung beim Login, Leerlauf-Timeouts, CSRF-Token, strenge CSP ohne JavaScript (`style-src 'self'`, keine Inline-Styles).
* **SMTP:** eigener Client mit STARTTLS/SSL und Zertifikatsprüfung; Zugangsdaten gehen nie unverschlüsselt über das Netz.
* **Konfig-Schutz:** `.htaccess` sperrt `config*.php`, `lib.inc.php`, `config.json`, `setup.php`, versteckte Dateien sowie
  `tests/` und `storage/`; alle `.inc.php`-Dateien liefern bei Direktaufruf zusätzlich nur 403. **Auf nginx wirkt
  `.htaccess` nicht** – dort `config.json` und `storage/` per Pfad (`app.json_path`, `app.storage_dir`) aus dem Webroot
  verlegen.

## Design und Datenverbrauch

* **Mobile First** mit Bootstrap 5.3 (nur CSS). Basis ist die Smartphone-Ansicht, ab 576 px werden Schrift und Buttons
  angepasst. Keine Inline-Styles, kein JavaScript, keine externen Schriften oder CDNs.
* Bootstrap liegt unverändert in `assets/` (≈ 31 KB komprimiert) und wird per `.htaccess` gzip-komprimiert und ein Jahr
  gecacht (`?v=` im Link sorgt beim Update für Neuladen). Danach überträgt eine Statusseite nur noch ≈ 3 KB HTML.
* Die Statusseite lädt sich alle 2 Minuten neu.

## Nutzung auswerten

* **Login-Häufigkeit:** In `change.php` unter "Nutzung" (heute / 7 / 30 Tage) und per `php setup.php stats [Tage]`
  mit Tageswerten. Die Zahlen kommen aus dem Audit-Log (`login1.ok`, `login2.ok`, `login2.fail`), es wird nichts
  zusätzlich gespeichert. Stufe 1 zählt Anmeldungen, nicht Personen (gemeinsames Passwort); Stufe 2 zählt je Benutzer
  inkl. letzter Anmeldung.
* **Lesezähler:** Je Status wird gezählt, in wie vielen Sitzungen er angesehen wurde (einmal pro Sitzung, nur
  Status-ID + Tag, keine IP, kein Cookie über die Sitzung hinaus). Sichtbar im Statusverlauf ("gelesen: n").

## Pressetaugliche Meldungstexte

Statusmeldungen sollen auch dann tragbar sein, wenn sie öffentlich werden. Regeln für Texte in `config.json`:

* Keine Ursachen, Schuldzuweisungen, Spekulationen, Namen, Zahlen Betroffener oder technische Details.
* Ruhig, sachlich, Handlungsanweisung statt Lagebeschreibung ("aus Vorsorgegründen", "bitte beachten Sie …").
* Keine Versprechen ("in 1 Stunde behoben") und keine Superlative.
* Übungen immer eindeutig als **Übung** kennzeichnen (`"exercise": true` setzt das Etikett auch in der Mail).
* Freitext gibt es bewusst nicht – nur freigegebene Textbausteine. Die interne Notiz erscheint nie auf der Statusseite.

`forbidden_terms` in `config.json` wird für Status, Standorte und Mail-Vorlagen von `php setup.php check` und in
`change.php` geprüft. Ein Status, dessen Text einen kritischen Begriff enthält, lässt sich nicht setzen.

## Tests

```bash
php tests/selftest.php      # Einheiten-/Integrationstest mit SQLite
php tests/webtest.php       # kompletter Ablauf per HTTP über php -S (benötigt die curl-Erweiterung)

# optional gegen MySQL/MariaDB (legt Tabellen mit Zufallspräfix an und entfernt sie wieder):
SBCM_TEST_DSN="mysql:host=localhost;dbname=test;charset=utf8mb4" SBCM_TEST_USER=test SBCM_TEST_PASS=… php tests/selftest.php
```

Der Webtest spielt Login Stufe 1/2, CSRF, Honeypot, Vorschau, TOTP inkl. Replay, ALARM-Mail per BCC, Beenden, Cron per
Token-URL und die Brute-Force-Sperre durch. `selftest.php` prüft u. a. Verschlüsselung, TOTP (RFC-Testvektor), Audit-Kette inkl. Manipulation, Status-MAC, Cron-Erinnerungen,
BCC-Schutz der Empfänger und die Brute-Force-Sperre (SQLite, Mail-Transport `log`).

## Grenzen

Ein einzelner Webspace ist kein hochverfügbares Krisensystem: Fällt er aus, ist auch die Statusseite weg – für den
Ernstfall einen Rückfallweg (Telefonkette, Aushang) vorhalten. Die Tabellen verwenden das Präfix `sbcm_`.
