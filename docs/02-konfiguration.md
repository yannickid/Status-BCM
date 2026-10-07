# Konfiguration

Status-BCM hat drei Konfigurationsdateien:

| Datei | Inhalt | Im Git? |
|---|---|---|
| `config.inc.php` | alle Einstellungen mit Platzhaltern und Kommentaren | ja, **nicht bearbeiten** |
| `config.local.inc.php` | echte Werte und Geheimnisse; überschreibt `config.inc.php`. Wird vom Einrichtungsassistenten erzeugt | **nein** (`.gitignore`) |
| `config.json` | Status-Katalog, Standorte, Mail-Vorlagen, kritische Begriffe | ja |

Dazu kommen die Einstellungen, die Admins im Browser unter **System** pflegen: Zugangspasswort Stufe 1,
Kopie-Adresse, Adresse im An-Feld, zusätzliche Empfänger je Stufe, Standard-Rufnummer, Alarmkreise, Standorte (mit E-Mail der Standortverwaltung), Kontakte für Meldungen und
Betreff-Präfixe. Sie liegen verschlüsselt in der Datenbank und haben Vorrang vor `auth.stage1_hash`,
`mail.cc_default_mail1` und den Standorten in `config.json`. Empfänger aus `mail.recipients` bilden den Kreis
"Allgemein", bis die Alarmkreise das erste Mal unter **System** gespeichert werden; dann werden sie übernommen.

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
| `mail.recipients` | `[]` | frühere ALARM-Empfänger (Kreis "Allgemein"). Besser unter **System → Alarmkreise** pflegen |
| `auth.max_failures` / `max_failures_user` / `window_seconds` | 5 / 10 / 900 | Brute-Force-Sperre je IP / je Benutzer |
| `auth.idle_minutes` / `stage2_idle_minutes` / `absolute_hours` | 30 / 15 / 10 | Sitzungsdauer |
| `auth.totp_enforce_all` | `false` | `true` = TOTP bei **jeder** Änderung, auch beim Beenden einer "Information" |
| `auth.totp_at_login` | `true` | persönliche Kennungen brauchen beim Login den TOTP-Code (der gemeinsame Lesezugang nie). Nur in begründeten Ausnahmen abschalten |
| `auth.password_max_age_days` | 365 | Gültigkeit persönlicher Passwörter; 0 = unbefristet |
| `auth.password_remind_days` / `password_reminder_repeat_days` | 14 / 7 | Erinnerung vor Ablauf und deren Wiederholung |
| `auth.password_min_length` | 12 | Mindestlänge (nie unter 12) |
| `auth.stage1_max_age_days` | 365 | Erinnerung an `cc_default_mail1`, das Zugangspasswort zu wechseln |
| `cron.token` / `cron.ip_allowlist` | – / `[]` | Aufruf von `cron.php` per URL |
| `reminder.repeat_minutes` / `max_count` | 60 / 0 | Erinnerung bei abgelaufenem Status; 0 = wiederholen, bis erledigt |
| `reminder.auto_revert_after_minutes` | 0 | > 0: Meldung nach Ablauf ohne Reaktion automatisch beenden |
| `display.keep_hours` | 48 | so lange bleiben abgelaufene oder beendete Meldungen ausgegraut sichtbar |
| `reminder.anchor_mail` | `true` | täglicher Audit-Anker an `cc_default_mail1` |
| `limits.max_validity_days` | 30 | höchste Gültigkeitsdauer einer Meldung |
| `net.trusted_proxies` | `[]` | nur hinter einem Reverse-Proxy setzen |
| `channels.signal.url` / `number` | – | Signal über eine eigene [signal-cli-rest-api](04-betrieb.md#signal-einrichten): volle Adresse von `/v2/send` und die registrierte Absendernummer |
| `channels.signal.token` oder `user`/`pass` | – | Zugangsschutz des vorgeschalteten Proxys (Bearer-Token bzw. Basic-Auth) |
| `channels.groupalarm.token` / `organization_id` | – / 0 | [GroupAlarm](04-betrieb.md#groupalarm-einrichten): Personal-Access-Token und Organisations-ID |
| `channels.groupalarm.kinds` | `new`, `update`, `end` | bei welchen ALARM-Mails GroupAlarm mit auslöst |
| `channels.transport` | wie `mail.transport` | `log` schreibt Signal/GroupAlarm-Aufrufe nur nach `storage/outbox` (Test) |
| `monitor.cron_stale_minutes` / `warn_repeat_minutes` | 15 / 60 | Cron gilt nach 15 Minuten als ausgefallen; Warnmail an `cc_default_mail1` höchstens stündlich |
| `monitor.health_token` | – | optional: `health.php` antwortet nur mit `?t=<token>` oder Header `X-Health-Token` |

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
  "mail_templates": { "alarm": {…}, "alarm_end": {…}, "reminder": {…}, "autorevert": {…}, "password": {…}, "anchor": {…} }
}
```

### Felder eines Status

| Feld | Pflicht | Bedeutung |
|---|---|---|
| `key` | ja | Kennung, `A-Z0-9_` |
| `label` | ja | Überschrift, max. 60 Zeichen |
| `text` | ja | Meldungstext, max. 500 Zeichen (Prüfung warnt ab 320) |
| `severity` | ja | `ok`, `info`, `warn`, `critical` (Farbe und Etikett) |
| `audience` | ja | `ALLE`, `ALLE_UND_ADRESSLISTE` (mit Auswahl betroffener Standorte samt Durchwahl) oder `FACHVERFAHREN` (mit Auswahl betroffener [Fachverfahren](08-fachverfahren.md)) |
| `public_label` / `public_text` | nein | nur bei `FACHVERFAHREN`: allgemeinere Fassung für die externe Seite (max. 40 / 300 Zeichen); ohne Angabe gelten `label` und `text`. Bitte immer angeben und ohne Ursachen formulieren |
| `phone` | nein | eigene Rückrufnummer für diesen Status, ersetzt `default_phone` |
| `exercise` | nein | `true` = als **ÜBUNG** kennzeichnen (Seite und Mail) |
| `alarm_mail_allowed` | nein | ALARM-Mail möglich (Standard: alles außer `ok`) |
| `alarm_mail_default` | nein | Hinweis in der Vorschau, wenn keine Mail gewählt wurde |
| `require_validity` / `allow_unlimited` | nein | Befristung Pflicht / unbefristet erlaubt |
| `require_totp` | nein | TOTP-Bestätigung Pflicht (Standard: `warn` und `critical`) |

### Standorte

`id` (`a-z0-9_-`), `name`, `phone`. Ohne `phone` wird `default_phone` angezeigt, bzw. die `phone` des Status, falls
gesetzt. Admins können `default_phone` unter **System → Standard-Rufnummer** im Browser überschreiben.

Die Liste in `config.json` ist nur der Startwert. Sobald ein Admin unter **System → Standorte** etwas speichert, gilt
die Liste aus dem Browser (verschlüsselt in der Datenbank, mit den E-Mail-Adressen der Standortverwaltungen).
Die Adressen gehören bewusst nicht in `config.json`, damit sie nicht im Klartext auf dem Webspace oder in Git liegen.

### Regeln für Meldungstexte

* Nur Auswirkung und Handlungsanweisung nennen, nie Ursache, Umfang, Namen oder Zahlen.
* Ruhig und sachlich formulieren, keine Versprechen ("in einer Stunde behoben"), keine Superlative.
* Übungen immer kennzeichnen (`"exercise": true`).
* `forbidden_terms` ergänzen, wenn Begriffe in Ihrer Organisation heikel sind. Ein Status mit einem solchen Begriff
  lässt sich nicht setzen.
* Jede Textänderung per Pull Request, nach dem Upload **System → Prüfung** ansehen.

### Warum die Meldungstexte in einer Datei liegen und nicht im Browser bearbeitet werden

Die Datenbank ist auf einem Webspace die angreifbarere Stelle: Ein geleaktes DB-Passwort oder eine SQL-Lücke reicht
dort schon. Um `config.json` zu ändern, braucht ein Angreifer Dateizugriff. In Git ist außerdem jede Textänderung
nachvollziehbar. Die Datei schreibgeschützt (`0444`) und möglichst außerhalb des Webroots ablegen.

Würden die Texte im Browser gepflegt, könnte ein einziges übernommenes Admin-Konto beliebigen Text an alle
Beschäftigten und per ALARM-Mail verschicken. Standorte, Kontakte, Alarmkreise und Präfixe sind dagegen im Browser
pflegbar: Sie enthalten keinen Meldungstext, werden auf kritische Begriffe geprüft, verlangen TOTP und stehen im
Protokoll.

### Mail-Vorlagen

Platzhalter in geschweiften Klammern. Für `alarm` und `alarm_end`: `{prefix}` (ÜBUNG), `{label}`, `{text}`,
`{locations}`, `{phone}`, `{contacts}`, `{validity}`, `{url}`. Fehlt `{contacts}` in `alarm`, werden die Kontakte
angehängt. Fehlt `alarm_end`, gilt ein eingebauter Text. Das Betreff-Präfix (`[ALARM]`, `[Aktualisierung]`, `[Ende]`)
stellt die Anwendung voran; es wird unter **System** festgelegt. Für `password`: `{name}`, `{what}`, `{phrase}`, `{url}`. Mail-Vorlagen werden ebenfalls auf
kritische Begriffe geprüft.
