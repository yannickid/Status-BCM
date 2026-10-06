# Installation und Ersteinrichtung

Diese Anleitung führt Schritt für Schritt von der leeren Webspace-Umgebung bis zum ersten gesetzten Status.
Für die meisten Schritte gibt es zwei Wege:

* **Mit SSH:** `setup.php` läuft direkt auf dem Server.
* **Ohne SSH (typischer Mini-Webspace):** `setup.php` läuft lokal auf dem eigenen Rechner. Die erzeugte
  `config.local.inc.php` wird per FTP/SFTP hochgeladen.

## 1. Voraussetzungen

| Was | Mindestens |
|---|---|
| PHP | 8.0, mit den Erweiterungen `openssl`, `pdo_mysql`, `mbstring`, `json` (bei fast allen Hostern Standard) |
| Datenbank | MySQL 5.7+ oder MariaDB 10.3+, eine eigene Datenbank und ein eigener Benutzer |
| Webserver | Apache mit `.htaccess` (auf nginx siehe [Betrieb](04-betrieb.md#nginx)) |
| HTTPS | Pflicht (z. B. Let's Encrypt über den Hoster) |
| Mail | ein SMTP-Postfach für den Absender, z. B. `status@ihre-domain.de` |
| Cron | Cronjob beim Hoster **oder** ein externer Cron-Dienst, der eine URL aufruft |
| Lokal (nur ohne SSH) | PHP ≥ 8.0 auf dem eigenen Rechner (`php -v`) |

Empfehlung: eine eigene, neutrale Subdomain wie `status.ihre-domain.de`, ohne Behörden- oder Konzernnamen im Titel.

## 2. Dateien holen

```bash
git clone https://github.com/yannickid/Status-BCM.git
cd Status-BCM
php tests/selftest.php     # muss mit "Alle Tests bestanden." enden
```

## 3. Datenbank anlegen (Hoster-Oberfläche)

1. Im Kundenmenü des Hosters eine neue MySQL-Datenbank anlegen, z. B. `statusbcm`.
2. Einen eigenen Benutzer nur für diese Datenbank anlegen, mit langem Zufallspasswort.
3. Rechte: `SELECT, INSERT, UPDATE, DELETE, CREATE, INDEX, TRIGGER`. Ohne `TRIGGER` funktioniert alles, die
   Append-only-Sperre entfällt dann aber (die Hash-Kette erkennt Manipulation weiterhin).
4. Host, Datenbankname, Benutzer und Passwort notieren.

Die Tabellen (Präfix `sbcm_`) legt die Anwendung beim ersten Aufruf selbst an.

## 4. Schlüssel und Zugangsdaten erzeugen

Ohne SSH führen Sie diese Befehle **lokal** im Projektordner aus, mit SSH auf dem Server.

```bash
php setup.php init
```

Das erzeugt `config.local.inc.php` mit Master-Key und Cron-Token. **Diese Datei sofort getrennt sichern**
(Passwortmanager oder Tresor der Notfallorganisation). Ohne sie sind gespeicherte Daten nicht mehr lesbar.

```bash
php setup.php set-stage1                         # gemeinsames Zugangspasswort für alle Beschäftigten (mind. 10 Zeichen)
php setup.php add-recipient person1@firma.de     # ALARM-Empfänger, je Adresse einmal (verschlüsselt gespeichert)
php setup.php set-cc1 isb@firma.de               # cc_default_mail1: Erinnerungen, Alarm-Kopie, täglicher Audit-Anker
```

**Erster Admin:**

* Ohne SSH (kein Datenbankzugriff vom eigenen Rechner):
  ```bash
  php setup.php add-user chef "Vorname Nachname" chef@firma.de admin --config
  ```
  Der Admin landet in `config.local.inc.php`. Weitere Benutzer legt er später im Browser an. Nach dem ersten
  Server-Login mit SSH kann er mit `php setup.php migrate-users` in die Datenbank umziehen (optional).
* Mit SSH:
  ```bash
  php setup.php add-user chef "Vorname Nachname" chef@firma.de admin
  ```

Der Befehl fragt das Passwort ab (mind. 12 Zeichen, gern ein Satz) und gibt ein **TOTP-Secret** aus:

1. Die Authenticator-App öffnen (Microsoft Authenticator, Google Authenticator, FreeOTP, Aegis, …).
2. "Konto hinzufügen" → "Schlüssel manuell eingeben" → Typ "zeitbasiert" wählen und das Secret eintragen.
3. Optional einen QR-Code lokal erzeugen: `qrencode -t ANSIUTF8 '<otpauth-URI>'`. Das Secret nie in Online-QR-Dienste
   eingeben.

## 5. Konfiguration eintragen

Öffnen Sie `config.local.inc.php` in einem Editor und ergänzen Sie dort die Werte. Die Datei `config.inc.php`
bleibt unverändert, sie enthält nur Platzhalter.

```php
'app'  => ['base_url' => 'https://status.ihre-domain.de', 'title' => 'Status'],
'db'   => ['dsn' => 'mysql:host=localhost;dbname=statusbcm;charset=utf8mb4', 'user' => 'statusbcm', 'pass' => '…'],
'mail' => ['host' => 'smtp.ihr-hoster.de', 'port' => 587, 'secure' => 'starttls',
           'user' => 'status@ihre-domain.de', 'pass' => '…', 'from_email' => 'status@ihre-domain.de'],
```

Tipp: Passwörter lassen sich verschlüsselt eintragen: `php setup.php encrypt-value 'geheim'` gibt `enc:v1:…` aus,
das Sie als Wert einsetzen können (z. B. für `mail.pass`).

Danach `config.json` anpassen: Standorte mit Durchwahl, `default_phone` und gegebenenfalls die Rufnummer im Status
"Eingeschränkte telefonische Erreichbarkeit". Siehe [Konfiguration](02-konfiguration.md).

## 6. Hochladen

Hochladen per SFTP/FTPS (nicht unverschlüsseltes FTP):

```
.htaccess  robots.txt  index.php  status.php  change.php  admin.php  cron.php  setup.php
lib.inc.php  config.inc.php  config.local.inc.php  config.json  assets/
```

**Nicht** hochladen: `tests/`, `docs/`, `.git/`, `README.md`.

Rechte setzen (im FTP-Programm "Dateiattribute"):

| Datei | Rechte |
|---|---|
| `config.local.inc.php` | `0600` (oder `0640`, falls der Hoster das verlangt) |
| `config.json` | `0444` (schreibgeschützt) |
| alle anderen | `0644`, Ordner `0755` |

Das Verzeichnis `storage/` legt die Anwendung selbst an. Besser ist es außerhalb des Webroots: dafür
`app.storage_dir` auf einen Pfad oberhalb von `public_html` setzen.

## 7. Cron einrichten

Der Cron verschickt Erinnerungen, den täglichen Audit-Anker und Passwort-Erinnerungen. Er räumt außerdem auf.
**Alle 5 Minuten**, eine Variante genügt:

```
*/5 * * * *  php /pfad/zu/cron.php
*/5 * * * *  curl -fsS -H "X-Cron-Token: <cron.token>" https://status.ihre-domain.de/cron.php
```

Ohne Cronjob beim Hoster nutzen Sie einen externen Cron-Dienst mit der URL
`https://status.ihre-domain.de/cron.php?t=<cron.token>`. Den Token finden Sie in `config.local.inc.php`.
Die Antwort `ok` bedeutet: Der Lauf war erfolgreich.

## 8. Prüfen

1. `https://status.ihre-domain.de/` aufrufen → Login mit dem Zugangspasswort → "Regelbetrieb".
2. "Einstellungen" → persönlicher Login → keine roten Systemhinweise.
3. Mit SSH: `php setup.php check`. Alle Punkte sollen `[ok]` zeigen.
4. Diese Adressen dürfen nichts liefern (403/404): `/config.json`, `/lib.inc.php`, `/config.local.inc.php`,
   `/setup.php`, `/tests/`.
5. Einen Test-Status "Übung" mit ALARM-Mail setzen (siehe [Bedienung](03-bedienung.md)), Empfang prüfen und den Status
   wieder beenden.

## 9. Weitere Benutzer

Im Browser unter **Benutzer** (nur Admins) anlegen. Die Person erhält ein Einmalpasswort und richtet beim ersten
Login ihr eigenes Passwort und die Authenticator-App selbst ein. Siehe [Bedienung → Benutzerverwaltung](03-bedienung.md#benutzerverwaltung-admins).
