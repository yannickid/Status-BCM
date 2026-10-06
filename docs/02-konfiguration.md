# Konfiguration

Status-BCM hat drei Konfigurationsdateien:

| Datei | Inhalt | Im Git? |
|---|---|---|
| `config.inc.php` | alle Einstellungen mit Platzhaltern und Kommentaren | ja, **nicht bearbeiten** |
| `config.local.inc.php` | echte Werte und Geheimnisse; überschreibt `config.inc.php`. Wird vom Einrichtungsassistenten erzeugt | **nein** (`.gitignore`) |
| `config.json` | Status-Katalog, Standorte, Mail-Vorlagen, kritische Begriffe | ja |

Dazu kommen die Einstellungen, die Admins im Browser unter **System** pflegen: Zugangspasswort Stufe 1,
ALARM-Empfänger und Kopie-Adresse. Sie liegen verschlüsselt in der Datenbank und haben Vorrang vor
`auth.stage1_hash` und `mail.cc_default_mail1`; Empfänger aus der Datei gelten zusätzlich.

Zum Bearbeiten von `config.local.inc.php` (z. B. neues SMTP-Passwort): per FTP herunterladen, im Texteditor ändern,
wieder hochladen. Vorher eine Kopie sichern.

## config.local.inc.php – wichtige Schlüssel

| Schlüssel | Standard | Bedeutung |
|---|---|---|
| `app.title` | `Status` | Titel auf allen Seiten. Neutral halten, ohne Organisationsnamen. |
| `app.base_url` | – | Öffentliche URL ohne `/` am Ende, für Links in E-Mails |
| `app.timezone` | `Europe/Berlin` | Anzeige- und Eingabezeitzone (intern wird UTC gespeichert) |
| `app.json_path` / `app.storage_dir` | im Programmordner | besser außerhalb des Webroots |
| `db.dsn`, `db.user`, `db.pass`, `db.prefix` | – / `sbcm_` | Datenbankzugang |
| `mail.transport` | `smtp` | `log` schreibt Mails nur nach `storage/outbox` (zum Testen) |
| `mail.host`, `port`, `secure`, `user`, `pass` | 587 / `starttls` | SMTP; `secure` = `starttls`, `ssl` oder `none` (nur localhost) |
| `mail.cc_default_mail1` | – | Kopie von Erinnerungen, Alarm-Mails und täglichem Audit-Anker. Besser unter **System** pflegen |
| `mail.recipients` | `[]` | ALARM-Empfänger. Besser unter **System** pflegen |
| `auth.max_failures` / `max_failures_user` / `window_seconds` | 5 / 10 / 900 | Brute-Force-Sperre je IP / je Benutzer |
| `auth.idle_minutes` / `stage2_idle_minutes` / `absolute_hours` | 30 / 15 / 10 | Sitzungsdauer |
| `auth.totp_enforce_all` | `false` | `true` = TOTP bei **jeder** Änderung, auch beim Beenden |
| `auth.password_max_age_days` | 365 | Gültigkeit persönlicher Passwörter; 0 = unbefristet |
| `auth.password_remind_days` / `password_reminder_repeat_days` | 14 / 7 | Erinnerung vor Ablauf und deren Wiederholung |
| `auth.password_min_length` | 12 | Mindestlänge (nie unter 12) |
| `auth.stage1_max_age_days` | 365 | Erinnerung an `cc_default_mail1`, das Zugangspasswort zu wechseln |
| `cron.token` / `cron.ip_allowlist` | – / `[]` | Aufruf von `cron.php` per URL |
| `reminder.repeat_minutes` / `max_count` | 60 / 0 | Erinnerung bei abgelaufenem Status; 0 = wiederholen, bis erledigt |
| `reminder.auto_revert_after_minutes` | 0 | > 0: Status nach Ablauf ohne Reaktion automatisch auf Regelbetrieb |
| `reminder.anchor_mail` | `true` | täglicher Audit-Anker an `cc_default_mail1` |
| `limits.max_validity_days` | 30 | höchste Gültigkeitsdauer eines Status |
| `net.trusted_proxies` | `[]` | nur hinter einem Reverse-Proxy setzen |

Geheimnisse können überall als `enc:v1:…` stehen (erzeugt mit `php setup.php encrypt-value '<wert>'`, optional).

## config.json – Status-Katalog

```json
{
  "default_status": "NORMAL",
  "default_phone": "+49 30 12345-0",
  "validity_options_minutes": [60, 120, 240, 480, 1440, 2880],
  "forbidden_terms": ["angriff", "ausfall", "störung", "…"],
  "locations": [ { "id": "muc-sued", "name": "Standort München Süd", "phone": "+49 89 12345-110" } ],
  "statuses": [ { … } ],
  "mail_templates": { "alarm": {…}, "reminder": {…}, "autorevert": {…}, "password": {…}, "anchor": {…} }
}
```

### Felder eines Status

| Feld | Pflicht | Bedeutung |
|---|---|---|
| `key` | ja | Kennung, `A-Z0-9_` |
| `label` | ja | Überschrift, max. 60 Zeichen |
| `text` | ja | Meldungstext, max. 500 Zeichen (Prüfung warnt ab 320) |
| `severity` | ja | `ok`, `info`, `warn`, `critical` (Farbe und Etikett) |
| `audience` | ja | `ALLE` oder `ALLE_UND_ADRESSLISTE` (mit Auswahl betroffener Standorte samt Durchwahl) |
| `phone` | nein | eigene Rückrufnummer für diesen Status, ersetzt `default_phone` |
| `exercise` | nein | `true` = als **ÜBUNG** kennzeichnen (Seite und Mail) |
| `alarm_mail_allowed` | nein | ALARM-Mail möglich (Standard: alles außer `ok`) |
| `alarm_mail_default` | nein | Hinweis in der Vorschau, wenn keine Mail gewählt wurde |
| `require_validity` / `allow_unlimited` | nein | Befristung Pflicht / unbefristet erlaubt |
| `require_totp` | nein | TOTP-Bestätigung Pflicht (Standard: `warn` und `critical`) |

### Standorte

`id` (`a-z0-9_-`), `name`, `phone`. Ohne `phone` wird `default_phone` angezeigt, bzw. die `phone` des Status, falls
gesetzt.

### Regeln für Meldungstexte

* Nur Auswirkung und Handlungsanweisung nennen, nie Ursache, Umfang, Namen oder Zahlen.
* Ruhig und sachlich formulieren, keine Versprechen ("in einer Stunde behoben"), keine Superlative.
* Übungen immer kennzeichnen (`"exercise": true`).
* `forbidden_terms` ergänzen, wenn Begriffe in Ihrer Organisation heikel sind. Ein Status mit einem solchen Begriff
  lässt sich nicht setzen.
* Jede Textänderung per Pull Request, nach dem Upload **System → Prüfung** ansehen.

### Warum der Katalog in einer Datei liegt und nicht in der Datenbank

Die Datenbank ist auf einem Webspace die angreifbarere Stelle: Ein geleaktes DB-Passwort oder eine SQL-Lücke reicht
dort schon. Um `config.json` zu ändern, braucht ein Angreifer Dateizugriff. In Git ist außerdem jede Textänderung
nachvollziehbar. Die Datei schreibgeschützt (`0444`) und möglichst außerhalb des Webroots ablegen.

### Mail-Vorlagen

Platzhalter in geschweiften Klammern. Für `alarm`: `{prefix}` (ÜBUNG), `{label}`, `{text}`, `{locations}`, `{phone}`,
`{validity}`, `{url}`. Für `password`: `{name}`, `{what}`, `{phrase}`, `{url}`. Mail-Vorlagen werden ebenfalls auf
kritische Begriffe geprüft.
