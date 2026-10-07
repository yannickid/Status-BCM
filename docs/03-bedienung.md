# Bedienung

## Für alle Beschäftigten: Status abrufen

1. Die Adresse der Statusseite aufrufen, z. B. `https://status.ihre-domain.de`. Am besten als Lesezeichen oder auf
   dem Startbildschirm des Smartphones ablegen.
2. **Benutzername** und **Passwort** des gemeinsamen Zugangs eingeben (z. B. "Unternehmen"). Beides ist für alle
   gleich und wird intern bekannt gegeben. Groß- und Kleinschreibung beim Benutzernamen spielen keine Rolle.
3. Die Seite zeigt **alle gültigen Meldungen**, die wichtigste zuerst (z. B. "Netzwerk eingeschränkt" an Standort A
   und gleichzeitig "Sicherheitsmaßnahme" an Standort B). Je Meldung:
   * farbiges Etikett (Information, Hinweis, Wichtiger Hinweis) und der Meldungstext,
   * **"Für alle:"** über dem Titel, wenn die Meldung alle Standorte betrifft (ohne Standortliste, Zielgruppe "Alle" oder
     alle Standorte angekreuzt),
   * gegebenenfalls betroffene Standorte mit **Rückrufnummer**. Ein Tipp auf die Nummer startet den Anruf. Hat ein
     Standort keine eigene Durchwahl, steht dort die **Standard-Rufnummer** mit dem Zusatz "(zentrale Rufnummer)".
   * gegebenenfalls **Kontakt**: Notfallnummer, E-Mail oder Videokonferenz (Plattform, Link, Konferenz-ID),
   * "Stand" und "Gültig bis".
   Gilt keine Meldung, steht dort "Regelbetrieb".
4. Darunter stehen **ausgegraut** die Meldungen der letzten 48 Stunden, die nicht mehr gelten:
   * **"Nicht mehr gültig"**: Die Gültigkeit ist abgelaufen.
   * **"Zurückgenommen / gelöst"**: Die Redaktion hat die Meldung beendet.
5. Ganz oben steht, wann die Anmeldung bei Untätigkeit endet (30 Minuten, mit persönlicher Kennung 15 Minuten).
   **Zwei Minuten vorher** erscheint dort eine gelbe Warnung mit dem Knopf **Jetzt verlängern**; er verlängert die
   Sitzung, ohne die Seite neu zu laden, Eingaben in Formularen bleiben also erhalten. Nach Ablauf steht dort
   "Abgemeldet" mit einem Link zur Anmeldung.
6. Die Seite aktualisiert sich alle 2 Minuten von selbst. Wer das nicht möchte (z. B. mit Screenreader), schaltet es
   über den Link oben auf der Seite aus; die Einstellung gilt bis zum Abmelden.

## Für die Redaktion: Meldungen setzen

Auf der Startseite mit der **persönlichen Kennung** und dem eigenen Passwort anmelden. Danach fragt die Seite den
**6-stelligen Code aus der Authenticator-App** ab. Erst dann sehen Sie die Statusseite und zusätzlich das Menü
**Einstellungen**. Abmelden geht über **Abmelden** oben rechts; damit endet die gesamte Sitzung. Wer bereits mit dem gemeinsamen Zugang angemeldet ist, kann sich auch unter **Einstellungen**
persönlich anmelden (ebenfalls mit Code). Der gemeinsame Lesezugang braucht keinen Code.

Warum schon beim Login: Mit der persönlichen Kennung sieht man Protokoll, IP-Adressen und interne Notizen. Ein
abgefischtes Passwort allein reicht dafür nicht mehr.

Kritische Änderungen (ALARM-Mail, Setzen und Beenden von Meldungen der Stufen "Hinweis" und "Wichtiger Hinweis",
Benutzer, System) verlangen zusätzlich je Aktion einen Code. Ein Code gilt nur einmal: Direkt nach dem Login warten
Sie für die erste kritische Änderung auf den nächsten Code der App (höchstens 30 Sekunden).

### Erster Login

Sie haben ein Einmalpasswort erhalten. Beim ersten Login erscheint "Zugang einrichten":

1. Einmalpasswort eingeben, dann zweimal ein **eigenes Passwort** (mind. 12 Zeichen; ein Satz wie
   "Mein Kaffee ist um 7 Uhr kalt" ist ideal).
2. Die **Authenticator-App** auf dem Smartphone öffnen (z. B. Microsoft Authenticator, Google Authenticator,
   FreeOTP) → Konto hinzufügen → den angezeigten **QR-Code scannen**. Ohne Kamera: den Schlüssel darunter abtippen
   (Typ "zeitbasiert") oder den Link antippen.
3. Den aktuellen 6-stelligen Code aus der App eingeben → **Speichern**.

### Neue Meldung

Mehrere Meldungen können gleichzeitig gelten. Eine neue Meldung ersetzt keine bestehende.

1. **Status** wählen. Der Text ist fest vorgegeben; eigene Formulierungen gibt es bewusst nicht.
2. Bei Status "mit Standortliste": die **betroffenen Standorte** ankreuzen (oder "Alle Standorte der Liste").
3. Optional **Kontakt** ankreuzen (Notfallnummer, Funktionspostfach, Videokonferenz). Die Auswahl pflegen Admins unter
   **System**.
4. **Gültigkeit** festlegen: eine **Dauer** (1 Stunde … 2 Tage) **oder** "Gültig bis" (Datum und Uhrzeit).
5. Optional **ALARM-Mail senden** und die **Alarmkreise** wählen (z. B. IT, BOA/Krisenstab, Leitung). "Standortverwaltung
   der betroffenen Standorte" ist vorausgewählt; ohne Standortliste sind das alle Standortverwaltungen. Die Mail geht
   **an** die Absenderadresse (oder die unter System hinterlegte Adresse im An-Feld) und per **BCC** an diese Adressen,
   an Sie, an die Kopie-Adresse und an die **zusätzlichen Empfänger der Stufe** (siehe System). Die Empfänger sehen sich
   gegenseitig nicht. Sind für einen Kreis **Signal**-Empfänger oder ein
   **GroupAlarm**-Szenario hinterlegt, geht die Meldung zusätzlich dorthin (die Vorschau nennt das).
6. Optional eine **interne Notiz** (Anlass). Sie steht nur im Protokoll, nie auf der Statusseite.
7. **Vorschau**: Prüfen Sie die Meldung genau so, wie alle sie sehen werden. Bei ALARM-Mail stehen dort Betreff-Präfix,
   Zahl der Empfänger und die gewählten Kreise.
8. Bei ALARM-Mail oder kritischen Status den **TOTP-Code** aus der App eingeben.
9. **Verbindlich setzen**. Erst jetzt ändert sich die Statusseite. Mit **Abbrechen** verwerfen Sie die Änderung.

Die Rückmeldung zeigt, an wie viele Adressen die ALARM-Mail zugestellt wurde und wie Signal bzw. GroupAlarm
geantwortet haben. Bei Fehlern erscheint ein Hinweis.

### Verlängern, ändern oder beenden

Unter **Aktuelle Meldungen** steht jede offene Meldung mit ihren eigenen Schaltflächen:

* **Verlängern:** Dauer wählen → Vorschau → verbindlich setzen.
* **Ändern:** Standorte, Kontakt, Gültigkeit anpassen, optional mit ALARM-Mail (Betreff-Präfix "Aktualisierung").
* **Beenden (zurückgenommen / gelöst):** optional mit ALARM-Mail (Präfix "Ende") an die gewählten Kreise. Meldungen
  der Stufen "Hinweis" und "Wichtiger Hinweis" (und Übungen) verlangen beim Beenden den TOTP-Code, genau wie beim
  Setzen: Eine still beendete echte Warnung wirkt wie eine Entwarnung. "Information" lässt sich ohne Code beenden.
  Die Meldung bleibt 48 Stunden ausgegraut sichtbar.

Läuft die Gültigkeit ab, erhalten Sie (und `cc_default_mail1`) eine **Erinnerungsmail**. Sie wird stündlich
wiederholt, bis Sie verlängern oder beenden. Bis dahin steht die Meldung als "Nicht mehr gültig" ausgegraut auf der
Statusseite.

Jede Version bleibt im **Verlauf aller Meldungen** erhalten, mit Meldungsnummer, Autor, Gültigkeit, ALARM ja/nein und
"gelesen" (Anzahl der Sitzungen, die die Meldung gesehen haben).

### Passwort ändern

**Einstellungen → Mein Zugang (Passwort ändern)**. Dort stehen auch das Datum der letzten Änderung und die
Gültigkeit. Rechtzeitig vor dem Ablauf kommt eine Erinnerungsmail. Ein abgelaufenes Passwort sperrt Sie nicht aus;
Sie müssen es dann aber beim nächsten Login sofort ändern.

### Nutzung auswerten

**Einstellungen → Nutzung** zeigt die Anmeldungen heute, in 7 Tagen und in 30 Tagen:

* Stufe 1 zählt Anmeldungen mit dem gemeinsamen Passwort, keine Personen.
* Stufe 2 zählt je Benutzer, mit letzter Anmeldung und Fehlversuchen.

Tageswerte der letzten 30 Tage zeigt Admins die Seite **System**.

### Protokoll

**Einstellungen → Änderungsprotokoll** zeigt die letzten 30 Einträge (wer, wann, was, wie) und oben das Ergebnis
der Integritätsprüfung. "FEHLER" bedeutet: Das Protokoll wurde verändert. In diesem Fall sofort die ISB informieren.
Das vollständige Protokoll exportieren Admins unter **System → Protokoll-Export** (siehe unten).

### Fachverfahren

Status mit dem Zusatz "Fachverfahren" (Geplante Wartung, eingeschränkt nutzbar, nicht verfügbar) wählen und die betroffenen
Verfahren ankreuzen. Jede solche Meldung benachrichtigt automatisch alle hinterlegten Stellen (Rollen-Kreise, Nutzende,
Unternehmen und Behörden, Informationssicherheit, VSA, Datenschutz) und verlangt deshalb immer den TOTP-Code. Die Vorschau
zeigt jede Empfängergruppe, Hinweise aus der Einstufung (z. B. KRITIS-Meldepflichten, DSGVO-Referenz) und was öffentlich
erscheint. ALARM zusätzlich alarmiert auch über Signal und GroupAlarm. Auf der Statusseite steht unter den Meldungen die
Übersicht **Fachverfahren**. Pflege: Menü **Fachverfahren**; Adressbuch, Zieladressen und Infotexte unter **System** (Admins).
Details: [Fachverfahren](08-fachverfahren.md).

### Aushang drucken

**Einstellungen → Aushang mit QR-Code drucken** (bzw. **System**) erzeugt eine A4-Seite für Schwarze Bretter und den
Notfallordner: Titel, QR-Code und Adresse der Statusseite, eine kurze Anleitung. Optional kommen der Benutzername des
gemeinsamen Zugangs, ausgewählte Notfallrufnummern und ein eigener Hinweis dazu ("Passwort: siehe Notfallordner,
Register 1"). **Das Zugangspasswort wird nie gedruckt.** Drucken über das Browser-Menü (Strg+P bzw. Teilen → Drucken);
Menü und Formular erscheinen nicht im Ausdruck. Der QR-Code wird auf dem Server erzeugt, ohne fremden Dienst.

## Benutzerverwaltung (Admins)

Menü **Benutzer** (nur mit Rolle Admin sichtbar). Jede Aktion verlangt Ihren TOTP-Code. Ein Code gilt nur einmal;
für die nächste Aktion warten Sie bis zum nächsten Code (höchstens 30 Sekunden).

| Aufgabe | So geht's |
|---|---|
| Benutzer anlegen | Kennung (z. B. `mmuster`), Name, E-Mail, Rolle → TOTP → **Anlegen**. Das **Einmalpasswort** erscheint nur einmal oben auf der Seite. Übergeben Sie es persönlich oder telefonisch, **nicht per E-Mail**. |
| Passwort vergessen | Aktionen → **Passwort zurücksetzen** → neues Einmalpasswort übergeben |
| Smartphone verloren/gewechselt | Aktionen → **Authenticator-App neu koppeln**. Beim nächsten Login wird die App neu eingerichtet. |
| Rolle ändern | **Redaktion** (Meldungen setzen) oder **Admin** (zusätzlich Benutzerverwaltung) |
| Person verlässt die Organisation | **Deaktivieren**. Der Zugang endet sofort. Benutzer werden nicht gelöscht, damit das Protokoll nachvollziehbar bleibt. |

Die Liste zeigt je Benutzer: Rolle, ob die TOTP-App gekoppelt ist, wann das Passwort gesetzt wurde, wie lange es gilt
(grün "gültig", gelb "läuft bald ab", rot "abgelaufen") und die letzte Anmeldung.

Oben sehen Sie außerdem, wann das **gemeinsame Zugangspasswort** (Stufe 1) zuletzt gesetzt wurde. Gewechselt wird es
unter **System**.

**Empfehlung:** Mindestens **zwei Admins** und mindestens **zwei Personen je Schicht bzw. Bereitschaft** mit
Redaktionsrechten, damit im Ernstfall immer jemand eine Meldung setzen kann.

## System (Admins)

Menü **System** (nur Admins). Änderungen verlangen Ihren TOTP-Code und stehen im Protokoll.

| Bereich | Inhalt |
|---|---|
| Prüfung | alle Punkte von Konfiguration, Datenbank, Benutzern, Empfängern, Cron, Protokoll-Kette (mit Kopf-Hash) und Meldungstexten. "offen" heißt: bitte ansehen |
| Cron | die Adresse für den Cronjob beim Hoster, "Jetzt einmal ausführen", letzter Lauf und die Adresse für einen externen Uptime-Check (`health.php`) |
| Alarmkreise | Kreise wie IT, BOA/Krisenstab, Leitung anlegen oder löschen; Adressen hinzufügen (eine je Zeile) oder per Haken entfernen. Sichtbar nur maskiert. Je Kreis unter "Signal und GroupAlarm": Signal-Rufnummern (`+49…`) oder Signal-Gruppen (`group.…`) und eine GroupAlarm-Szenario-ID, dazu eine Signal-Testnachricht |
| Standorte | Name, Durchwahl und **E-Mail der Standortverwaltung** je Außenstelle. Name und Durchwahl erscheinen auf der Statusseite, die Adressen nie (nur maskiert unter System) |
| Kontakte für Meldungen | Notfallnummer, E-Mail, Videokonferenz (Plattform, https-Link, Konferenz-ID/PIN). Für alle Beschäftigten sichtbar, sobald einer Meldung zugeordnet |
| Betreff-Präfixe | Präfix der ALARM-Mail für "Neuer Alarm", "Aktualisierung" und "Ende", z. B. `[ALARM]` |
| Adresse im An-Feld der ALARM-Mail | Leer = Absenderadresse (`mail.from_email`). Alle anderen Empfänger stehen nur im BCC |
| Zusätzliche Empfänger je Stufe | Je Stufe (Information, Hinweis, Wichtiger Hinweis) Adressen, die jede ALARM-Mail dieser Stufe zusätzlich zu den gewählten Kreisen bekommen, z. B. Geschäftsführung nur bei "Wichtiger Hinweis". Per BCC, verschlüsselt, nur maskiert sichtbar |
| Standard-Rufnummer | Ersetzt `default_phone` aus `config.json`. Erscheint bei Meldungen ohne Standortliste und bei Standorten ohne eigene Durchwahl. Gilt für neue und geänderte Meldungen. Leer = Wert aus `config.json` |
| Kopie-Adresse | `cc_default_mail1` ändern (Erinnerungen, Kopie der ALARM-Mails, Audit-Anker) |
| Gemeinsamer Zugang für alle | Benutzername (z. B. "Unternehmen") und Zugangspasswort (Stufe 1) ändern; gilt sofort für neue Anmeldungen. Danach intern bekannt geben. Der Name darf keiner persönlichen Kennung gleichen |
| Protokoll-Export | Änderungsprotokoll als **CSV** (Excel, Revision) oder **PDF** (Ablage, ISB), wahlweise für einen Zeitraum und mit oder ohne IP-Adressen. Kopf mit Integritätsprüfung und Kopf-Hash; jeder Export steht selbst im Protokoll |
| Aushang | Link zur Druckvorlage mit QR-Code |
| Mailversand testen | Testmail an Ihre eigene Adresse |
| Anmeldungen je Tag | 30 Tage, Stufe 1 / Stufe 2 / Fehlversuche |

Hat der einzige Admin Passwort und Smartphone verloren, hilft der Notfallzugang, siehe
[Betrieb → Notfälle](04-betrieb.md#notfälle-im-betrieb).

## Notfall-Kurzkarte (zum Ausdrucken)

```
STATUS-BCM – KURZKARTE
1. Startseite: persönliche Kennung + Passwort + Code aus der App
2. Neue Meldung: Status + ggf. Standorte + Kontakt + Dauer
3. ALARM-Mail? nur die nötigen Alarmkreise wählen
4. Vorschau prüfen → TOTP-Code → Verbindlich setzen
5. Erinnerung kommt bei Ablauf → Verlängern oder Beenden
6. Erledigt? Beenden (zurückgenommen / gelöst)
Kein Zugriff? Rückfallweg: Telefonkette / Aushang
```
