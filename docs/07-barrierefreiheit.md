# Barrierefreiheit

Status-BCM ist für **WCAG 2.1 Stufe AA** gebaut, die Grundlage der BITV 2.0 und der EN 301 549. Diese Seite nennt den
geprüften Stand, die bekannten Grenzen und enthält eine Vorlage für die Erklärung zur Barrierefreiheit.

> **Wichtig:** Eine automatische Prüfung findet nur einen Teil der Barrieren. Eine Prüfung mit Screenreader
> (z. B. NVDA, VoiceOver, TalkBack) durch Fachleute oder Betroffene steht noch aus. Für eine öffentliche Stelle ist
> sie vor der Veröffentlichung der Erklärung zu empfehlen (BITV-Test oder vergleichbar).

## Geprüfter Stand (Version 1.5.0)

Geprüft am 06.10.2026 mit axe-core 4 (Regelsätze WCAG 2.0/2.1 A und AA sowie Best Practices) auf allen Seiten:
Anmeldung, Fehlermeldung, TOTP-Schritt, Statusseite, Einstellungen, Vorschau, Benutzer, System, Aushang, Einrichtung,
Abmeldezeit-Rahmen. Der PDF-Export wurde mit veraPDF 1.28 gegen PDF/UA-1 geprüft (106 von 106 Regeln erfüllt).
Dazu Durchsicht des Codes.

| Anforderung (WCAG 2.1) | Stand |
|---|---|
| 1.1.1 Textalternativen | erfüllt: QR-Codes haben Alternativtext, die Adresse steht zusätzlich als Text daneben |
| 1.3.1 Info und Beziehungen | erfüllt: Überschriften je Seite (eine `h1`), Listen, Tabellen mit Kopfzeilen, jedes Eingabefeld mit Beschriftung, Fieldsets bei Auswahlgruppen |
| 1.3.5 Zweck von Eingabefeldern | erfüllt: `autocomplete` für Benutzername, Passwort, Einmalcode |
| 1.4.1 Farbe nicht als einziges Merkmal | erfüllt: Stufe steht immer als Text ("Hinweis", "Wichtiger Hinweis"), ebenso "Nicht mehr gültig", "Zurückgenommen / gelöst" und "Übung" |
| 1.4.3 Kontrast (Minimum) | erfüllt: Links, Navigation, Schaltflächen und Code auf mindestens 4,5:1 angehoben; ausgegraute Meldungen behalten vollen Textkontrast |
| 1.4.4 Text vergrößern / 1.4.10 Umbruch | erfüllt: bei 320 px Breite (entspricht 400 % Zoom) kein waagerechtes Scrollen auf allen Seiten |
| 1.4.11 Kontrast von Bedienelementen | erfüllt mit Bootstrap-Standard; Fokusrahmen verstärkt |
| 2.1.1 Tastatur | erfüllt: kein JavaScript, nur native Formulare, Links und Aufklappbereiche |
| 2.2.1 Zeitbegrenzungen anpassbar | erfüllt: Oben auf jeder angemeldeten Seite steht die Abmeldezeit. Zwei Minuten vor Ablauf erscheint eine Warnung (`role="alert"`) mit dem Knopf "Jetzt verlängern"; ein Klick genügt, Eingaben bleiben erhalten (siehe unten). Die Vorschau einer Meldung nennt ihre Ablaufzeit (5 Minuten). Die automatische Aktualisierung der Statusseite lässt sich ausschalten. Alle Zeiten sind in `config.local.inc.php` einstellbar. |
| 2.4.1 Blöcke überspringen | erfüllt: Link "Zum Inhalt springen" erscheint beim ersten Tabulator |
| 2.4.2 Seitentitel | erfüllt |
| 2.4.7 Fokus sichtbar | erfüllt: deutlicher Fokusrahmen (3 px) |
| 3.1.1 Sprache | erfüllt: `lang="de"` |
| 3.3.1 / 3.3.3 Fehler erkennen, Vorschläge | erfüllt: Fehlermeldungen als Klartext oben im Formular (`role="alert"`), mit Hinweis zur Korrektur |
| 3.3.4 Fehlervermeidung | erfüllt: jede Meldung erst als Vorschau, dann verbindlich |
| 4.1.2 Name, Rolle, Wert | erfüllt: nur native HTML-Elemente |

**Bekannte Grenzen**

* **Vorwarnung ohne JavaScript:** Die Warnung schaltet ein zeitgesteuertes Stylesheet in einem eingebetteten Rahmen
  (`sitzung.php`) ein; "Verlängern" lädt nur diesen Rahmen neu. Das funktioniert in allen aktuellen Browsern. Ob
  Screenreader die Warnung beim Erscheinen sofort ansagen, hängt von Screenreader und Browser ab (`role="alert"` in
  einem Rahmen) und ist noch nicht mit NVDA/VoiceOver geprüft. Die Abmeldezeit steht aber immer als Text oben auf der
  Seite. Die Vorschau einer Meldung (5 Minuten) lässt sich nicht verlängern, nur neu vorbereiten. Wer mehr Zeit braucht,
  kann `auth.stage2_idle_minutes` und `auth.pending_ttl_seconds` erhöhen; das senkt die Sicherheit etwas.
* **PDF-Export** ist getaggt nach PDF/UA-1: Strukturbaum mit Überschrift, Absätzen und Tabelle (Spaltenköpfe mit
  Scope), Lesereihenfolge, Sprache Deutsch, Dokumenttitel, eingebettete Schrift; Linien, Seitenzahlen und die auf
  Folgeseiten wiederholten Kopfzeilen sind als Artefakte markiert. Grenzen: Zeichen außerhalb von Windows-1252
  (z. B. Emojis, kyrillische Schrift) erscheinen als "?", der CSV-Export enthält sie vollständig. Die Datei wird durch
  die eingebettete Schrift größer (etwa 500 KB). Eine automatische Prüfung (veraPDF) ersetzt nicht den
  PDF/UA-Praxistest mit Screenreader (z. B. PAC 2024 und NVDA).
* **TOTP-Code** setzt eine Authenticator-App voraus. Die gängigen Apps sind mit Screenreadern bedienbar; der Code
  muss innerhalb von 30 Sekunden (±30 Sekunden Toleranz) eingegeben werden.
* **Meldungstexte** sind so verständlich wie die Texte in `config.json`. Empfehlung: kurze Sätze, Leichte Sprache
  prüfen, keine Abkürzungen ohne Erklärung.
* **Kein Dunkelmodus**; der Windows-Kontrastmodus funktioniert (die Farbleiste entfällt, der Stufen-Text bleibt).

## Vorlage: Erklärung zur Barrierefreiheit

Für öffentliche Stellen ist eine Erklärung Pflicht (§ 12b BGG bzw. Landesrecht, BITV 2.0); Status-BCM ist eine
interne Anwendung, für die die Erklärung im Intranet oder auf der Statusseite verlinkt werden kann. Für Unternehmen
ist sie freiwillig. Platzhalter in eckigen Klammern ausfüllen.

```
Erklärung zur Barrierefreiheit

[Organisation] ist bemüht, die Statusseite [Adresse] im Einklang mit [§ 12a BGG / Landesgesetz]
sowie der BITV 2.0 barrierefrei zugänglich zu machen.

Stand der Vereinbarkeit mit den Anforderungen
Diese Seite ist [vollständig / wegen der folgenden Unvereinbarkeiten teilweise] mit den Anforderungen vereinbar.

Nicht barrierefreie Inhalte
- Im PDF-Export des Protokolls erscheinen Zeichen außerhalb des westeuropäischen Zeichensatzes
  als "?"; der CSV-Export enthält sie vollständig.
- [ggf. Ergebnis der Screenreader-Prüfung der Abmelde-Warnung ergänzen]

Erstellung dieser Erklärung
Erstellt am [Datum] auf Grundlage einer Selbstbewertung (automatische Prüfung mit axe-core
und Durchsicht) [ergänzen: Prüfung mit Screenreader / BITV-Test am …].

Feedback und Kontakt
Barrieren melden Sie bitte an: [E-Mail, Telefon der zuständigen Stelle].

Schlichtungsverfahren
[Nur öffentliche Stellen: Schlichtungsstelle nach § 16 BGG bzw. Landesschlichtungsstelle mit
Kontaktdaten.]
```
