# Status-BCM

**Die kleine Notfall-Statusseite für Unternehmen und Behörden.** Im Ernstfall sehen alle Beschäftigten auf einen
Blick, was gilt: "Regelbetrieb", "Standort vorübergehend nicht zugänglich", "Eingeschränkte telefonische
Erreichbarkeit" und dazu, wo sie anrufen können. Gesetzt wird der Status von wenigen Berechtigten, nachweisbar und
fälschungssicher.

Status-BCM läuft auf jedem einfachen PHP-Webspace, bewusst **außerhalb** der eigenen IT. So bleibt die Seite
erreichbar, wenn Netzwerk, Telefon oder Mail im Haus gestört sind.

<p>
  <img src="docs/img/status-mobil.png" alt="Statusseite auf dem Smartphone" width="250">
  <img src="docs/img/vorschau-mobil.png" alt="Vorschau vor dem verbindlichen Setzen" width="250">
  <img src="docs/img/benutzer-mobil.png" alt="Benutzerverwaltung" width="250">
</p>

## Was es kann

* **Zwei Stufen:** gemeinsames Zugangspasswort zum Lesen, persönlicher Login zum Ändern.
* **Keine Falschmeldungen:** nur freigegebene, pressetaugliche Textbausteine; immer Vorschau → verbindlich setzen;
  TOTP-Bestätigung bei ALARM-Mail und kritischen Status; kritische Begriffe ("Ausfall", "Angriff", …) werden
  blockiert.
* **Standorte mit Rückrufnummer,** Status mit **Dauer oder "Gültig bis"**; Erinnerungsmail bei Ablauf, bis verlängert
  oder beendet wird.
* **ALARM-Mail** per BCC an hinterlegte Empfänger. Die Adressen sind verschlüsselt und nirgends sichtbar.
* **Revisionssicheres Protokoll:** wer, was, wann, wie; Hash-Kette mit HMAC, append-only per DB-Trigger, täglicher
  Audit-Anker per Mail.
* **Verschlüsselte Ablage** (AES-256-GCM) von Meldungen, Standortdaten, Mail-Inhalten, Protokolldetails und
  Benutzerdaten.
* **Benutzerverwaltung** mit Rollen (Redaktion / Admin), Einmalpasswort, Selbst-Einrichtung der Authenticator-App,
  Passwort-Gültigkeit mit Erinnerungsmail.
* **Nutzung auswerten:** Anmeldungen je Stufe und Benutzer, anonymer Lesezähler je Status.
* **Mobile First** mit Bootstrap 5.3 (lokal, nur CSS), **ohne JavaScript**, etwa 3 KB je Seitenaufruf.
* **Keine Abhängigkeiten:** PHP ≥ 8.0, MySQL/MariaDB, kein Composer, kein CDN, eigener SMTP-Client mit
  Zertifikatsprüfung.

## Schnellstart

```bash
git clone https://github.com/yannickid/Status-BCM.git && cd Status-BCM
php tests/selftest.php                                   # Selbsttest
php setup.php init                                       # Master-Key + Cron-Token
php setup.php set-stage1                                 # Zugangspasswort für alle
php setup.php add-user chef "Vorname Nachname" chef@firma.de admin --config   # erster Admin (+ TOTP)
php setup.php add-recipient alarm1@firma.de              # ALARM-Empfänger
php setup.php set-cc1 isb@firma.de                       # Kopie/Erinnerungen/Audit-Anker
# config.local.inc.php: base_url, db.*, mail.* eintragen; config.json: Standorte und Rufnummern
# Dateien hochladen (ohne tests/, docs/), Cron alle 5 Min. auf cron.php
```

Die ausführliche Schritt-für-Schritt-Anleitung, auch für Webspaces ohne SSH, steht in
**[docs/01-installation.md](docs/01-installation.md)**.

## Dokumentation (Wiki)

| | |
|---|---|
| [Installation](docs/01-installation.md) | vom leeren Webspace bis zum ersten Status |
| [Konfiguration](docs/02-konfiguration.md) | alle Einstellungen, Status-Katalog, Regeln für Meldungstexte |
| [Bedienung](docs/03-bedienung.md) | für Beschäftigte, Redaktion und Admins, mit Notfall-Kurzkarte |
| [Betrieb](docs/04-betrieb.md) | Routine, Updates, Backup, Notfälle, nginx, DB-Härtung |
| [Sicherheit und Audit](docs/05-sicherheit-und-audit.md) | Schutzbedarf, Maßnahmen nach BSI IT-Grundschutz, Protokollierung, Restrisiken, Prüfanleitung |

## Aufbau

| Datei | Zweck |
|---|---|
| `index.php` | Login Stufe 1 (gemeinsames Zugangspasswort) |
| `status.php` | aktueller Status |
| `change.php` | Login Stufe 2, Status setzen (Formular → Vorschau → verbindlich), Verlauf, Protokoll, Nutzung, eigenes Passwort |
| `admin.php` | Benutzerverwaltung (nur Admins) |
| `cron.php` | Erinnerungen, Passwort-Erinnerungen, Audit-Anker, Aufräumen (CLI oder URL mit Token) |
| `setup.php` | Einrichtung und Notfallbefehle (nur CLI) |
| `lib.inc.php` | gesamte Logik |
| `config.inc.php` | Einstellungen mit Platzhaltern; echte Werte in `config.local.inc.php` (nicht im Git) |
| `config.json` | Status-Katalog, Standorte, Mail-Vorlagen, kritische Begriffe |
| `assets/` | Bootstrap 5.3.8 (MIT-Lizenz) und `app.css` |
| `tests/` | `selftest.php` (SQLite/MySQL) und `webtest.php` (kompletter Ablauf über `php -S`) |

## Tests

```bash
php tests/selftest.php
php tests/webtest.php
```

## Grenzen

Ein einzelner Webspace ist kein hochverfügbares Krisensystem. Halten Sie einen Rückfallweg ohne die Seite vor
(Telefonkette, Aushang) und üben Sie den Ablauf regelmäßig mit dem Status "Übung".

## Lizenz

Bootstrap: MIT, © The Bootstrap Authors (`assets/bootstrap.LICENSE`).
