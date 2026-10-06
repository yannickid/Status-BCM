# Bedienung

## Für alle Beschäftigten: Status abrufen

1. Die Adresse der Statusseite aufrufen, z. B. `https://status.ihre-domain.de`. Am besten als Lesezeichen oder auf
   dem Startbildschirm des Smartphones ablegen.
2. Das **Zugangspasswort** eingeben. Es ist für alle gleich und wird intern bekannt gegeben.
3. Die Seite zeigt den aktuellen Status:
   * farbiges Etikett (Normal, Information, Hinweis, Wichtiger Hinweis) und die Meldung,
   * gegebenenfalls betroffene Standorte mit **Rückrufnummer**. Ein Tipp auf die Nummer startet den Anruf.
   * "Stand" und "Gültig bis".
4. Die Seite aktualisiert sich alle 2 Minuten von selbst.

Erscheint "Die angegebene Gültigkeit ist überschritten", wird die Meldung gerade überprüft. Bitte die angegebene
Rufnummer nutzen.

## Für die Redaktion: Status setzen

Menü **Einstellungen** → persönlicher Login (Benutzer + Passwort).

### Erster Login

Sie haben ein Einmalpasswort erhalten. Beim ersten Login erscheint "Zugang einrichten":

1. Einmalpasswort eingeben, dann zweimal ein **eigenes Passwort** (mind. 12 Zeichen; ein Satz wie
   "Mein Kaffee ist um 7 Uhr kalt" ist ideal).
2. Die **Authenticator-App** auf dem Smartphone öffnen (z. B. Microsoft Authenticator, Google Authenticator,
   FreeOTP) → Konto hinzufügen → Schlüssel manuell eingeben → den angezeigten Schlüssel abtippen (Typ "zeitbasiert").
3. Den aktuellen 6-stelligen Code aus der App eingeben → **Speichern**.

### Neuen Status setzen

1. **Status** wählen. Der Text ist fest vorgegeben; eigene Formulierungen gibt es bewusst nicht.
2. Bei Status "mit Standortliste": die **betroffenen Standorte** ankreuzen (oder "Alle Standorte der Liste").
3. **Gültigkeit** festlegen: eine **Dauer** (1 Stunde … 2 Tage) **oder** "Gültig bis" (Datum und Uhrzeit).
   "Unbefristet" ist nur beim Regelbetrieb möglich.
4. Optional **ALARM-Mail senden**. Sie geht per BCC an alle hinterlegten Empfänger, an Sie und an die
   Standard-CC-Adresse.
5. Optional eine **interne Notiz** (Anlass). Sie steht nur im Protokoll, nie auf der Statusseite.
6. **Vorschau**: Prüfen Sie die Meldung genau so, wie alle sie sehen werden.
7. Bei ALARM-Mail oder kritischen Status den **TOTP-Code** aus der App eingeben.
8. **Verbindlich setzen**. Erst jetzt ändert sich die Statusseite. Mit **Abbrechen** verwerfen Sie die Änderung.

Die Rückmeldung zeigt, an wie viele Adressen die ALARM-Mail zugestellt wurde. Bei Fehlern erscheint ein Hinweis.

### Verlängern oder beenden

Läuft die Gültigkeit ab, erhalten Sie (und `cc_default_mail1`) eine **Erinnerungsmail**. Sie wird stündlich
wiederholt, bis Sie reagieren:

* **Weiterhin gültig:** Unter "Ist der Status noch gültig?" eine Dauer wählen → **Verlängern** → Vorschau →
  verbindlich setzen.
* **Nicht mehr gültig:** **Status beenden** → Vorschau → verbindlich setzen. Danach gilt wieder "Regelbetrieb".

Jeder Wechsel bleibt im **Statusverlauf** erhalten, mit Autor, Gültigkeit, ALARM ja/nein und "gelesen"
(Anzahl der Sitzungen, die den Status gesehen haben).

### Passwort ändern

**Einstellungen → Mein Zugang (Passwort ändern)**. Dort stehen auch das Datum der letzten Änderung und die
Gültigkeit. Rechtzeitig vor dem Ablauf kommt eine Erinnerungsmail. Ein abgelaufenes Passwort sperrt Sie nicht aus;
Sie müssen es dann aber beim nächsten Login sofort ändern.

### Nutzung auswerten

**Einstellungen → Nutzung** zeigt die Anmeldungen heute, in 7 Tagen und in 30 Tagen:

* Stufe 1 zählt Anmeldungen mit dem gemeinsamen Passwort, keine Personen.
* Stufe 2 zählt je Benutzer, mit letzter Anmeldung und Fehlversuchen.

Tageswerte gibt es per `php setup.php stats 90`.

### Protokoll

**Einstellungen → Änderungsprotokoll** zeigt die letzten 30 Einträge (wer, wann, was, wie) und oben das Ergebnis
der Integritätsprüfung. "FEHLER" bedeutet: Das Protokoll wurde verändert. In diesem Fall sofort die ISB informieren.

## Benutzerverwaltung (Admins)

Menü **Benutzer** (nur mit Rolle Admin sichtbar). Jede Aktion verlangt Ihren TOTP-Code. Ein Code gilt nur einmal;
für die nächste Aktion warten Sie bis zum nächsten Code (höchstens 30 Sekunden).

| Aufgabe | So geht's |
|---|---|
| Benutzer anlegen | Kennung (z. B. `mmuster`), Name, E-Mail, Rolle → TOTP → **Anlegen**. Das **Einmalpasswort** erscheint nur einmal oben auf der Seite. Übergeben Sie es persönlich oder telefonisch, **nicht per E-Mail**. |
| Passwort vergessen | Aktionen → **Passwort zurücksetzen** → neues Einmalpasswort übergeben |
| Smartphone verloren/gewechselt | Aktionen → **Authenticator-App neu koppeln**. Beim nächsten Login wird die App neu eingerichtet. |
| Rolle ändern | **Redaktion** (Status setzen) oder **Admin** (zusätzlich Benutzerverwaltung) |
| Person verlässt die Organisation | **Deaktivieren**. Der Zugang endet sofort. Benutzer werden nicht gelöscht, damit das Protokoll nachvollziehbar bleibt. |

Die Liste zeigt je Benutzer: Rolle, ob die TOTP-App gekoppelt ist, wann das Passwort gesetzt wurde, wie lange es gilt
(grün "gültig", gelb "läuft bald ab", rot "abgelaufen") und die letzte Anmeldung.

Oben sehen Sie außerdem, wann das **gemeinsame Zugangspasswort** (Stufe 1) zuletzt gesetzt wurde. Es wird per
`php setup.php set-stage1` gewechselt, danach erhalten alle Beschäftigten das neue Passwort.

**Empfehlung:** Mindestens **zwei Admins** und mindestens **zwei Personen je Schicht bzw. Bereitschaft** mit
Redaktionsrechten, damit im Ernstfall immer jemand den Status setzen kann.

## Notfall-Kurzkarte (zum Ausdrucken)

```
STATUS-BCM – KURZKARTE
1. Einstellungen → persönlich anmelden
2. Status + ggf. Standorte + Dauer wählen
3. ALARM-Mail? nur wenn alle sofort informiert werden müssen
4. Vorschau prüfen → TOTP-Code → Verbindlich setzen
5. Erinnerung kommt bei Ablauf → Verlängern oder Beenden
Kein Zugriff? Rückfallweg: Telefonkette / Aushang
```
