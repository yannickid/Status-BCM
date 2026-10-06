# Governance: Unterlagen für BSI-Grundschutz, ISB, ISMS, BCM und Datenschutz

Diese Seite liefert die Bausteine, die Informationssicherheitsbeauftragte (ISB), Datenschutzbeauftragte (DSB) und
Notfallbeauftragte für Status-BCM brauchen: Strukturanalyse, Schutzbedarfsfeststellung (SBF), Modellierung,
IT-Sicherheitskonzept (ISK), Risikoanalyse, BCM-Einbindung, Rollen und Datenschutzunterlagen. Die technischen
Maßnahmen stehen in [Sicherheit und Audit](05-sicherheit-und-audit.md), die Speicherorte in deren
[Abschnitt 11](05-sicherheit-und-audit.md#11-transparenz-wo-was-wie-gespeichert-ist).

> **So ist diese Seite zu lesen:** Sie ist eine **ausgefüllte Vorlage**. Was die Software festlegt, steht hier
> verbindlich. Was nur der Betreiber festlegen kann (Verantwortliche, Fristen, Verträge, Risikoakzeptanz), ist mit
> **[Betreiber]** markiert und muss ergänzt und von der Leitung freigegeben werden. Die Seite ersetzt keine
> Rechtsberatung und keine Prüfung durch DSB oder Revision.

Stand: Version 1.4 · Pflege: ISB · Freigabe: **[Betreiber: Leitung, Datum]**

---

## 1. Einordnung und Geltungsbereich

| Rahmenwerk | Bezug in Status-BCM |
|---|---|
| BSI-Standard 200-1 (ISMS) | Rollen und Prozesse, Abschnitt 8 |
| BSI-Standard 200-2 (IT-Grundschutz-Methodik) | Strukturanalyse, SBF, Modellierung, Check: Abschnitte 2 bis 4 |
| BSI-Standard 200-3 (Risikoanalyse) | Abschnitt 5 |
| BSI-Standard 200-4 (BCM) | Abschnitt 6 |
| IT-Grundschutz-Kompendium | Bausteine in Abschnitt 3; Umsetzung in [Sicherheit und Audit](05-sicherheit-und-audit.md) |
| ISO/IEC 27001:2022 | Die Maßnahmen lassen sich den Controls aus Anhang A zuordnen (z. B. 5.15 Zugangssteuerung, 8.5 sichere Authentisierung, 8.15 Protokollierung, 8.24 Kryptografie, 5.29/5.30 Informationssicherheit bei Störungen, IKT-Bereitschaft für Business Continuity) |
| DSGVO, BDSG | Abschnitt 7 |

**Informationsverbund (Geltungsbereich):** die Anwendung Status-BCM mit ihrer Datenbank, ihrem Webspace, den
angebundenen Diensten (Mailserver, optional Signal-Gateway und GroupAlarm, externer Uptime-Check) und den Prozessen
der Krisenkommunikation, die sie unterstützt. Nicht enthalten: die Endgeräte der Beschäftigten und die eigene
IT-Infrastruktur (diese ist bewusst getrennt, siehe Abschnitt 6).

Vorgehensweise nach 200-2: **Standard-Absicherung** für den Informationsverbund; wegen des hohen Schutzbedarfs bei
Integrität und Verfügbarkeit zusätzlich eine **Risikoanalyse nach 200-3** (Abschnitt 5).

## 2. Strukturanalyse und Schutzbedarfsfeststellung

### 2.1 Strukturanalyse

**Geschäftsprozess**

| ID | Prozess | Beschreibung | Verantwortlich |
|---|---|---|---|
| GP1 | Krisenkommunikation an Beschäftigte | Lage und Verhaltenshinweise im Notfall bereitstellen, Ansprechpartner nennen | **[Betreiber: Notfallbeauftragte/r]** |
| GP2 | Alarmierung von Funktionsgruppen | IT, BOA/Krisenstab, Leitung, Standortverwaltungen per Mail, Signal, GroupAlarm erreichen | **[Betreiber]** |

**Anwendungen**

| ID | Anwendung | Prozess | Plattform |
|---|---|---|---|
| A1 | Status-BCM (Statusseite, Einstellungen, Benutzer, System) | GP1, GP2 | S1, S2 |
| A2 | Mailversand (SMTP-Postfach) | GP2 | S3 |
| A3 | Signal-Versand (signal-cli-rest-api), optional | GP2 | S4 |
| A4 | GroupAlarm, optional | GP2 | S5 |
| A5 | Authenticator-App (TOTP) | GP1, GP2 | Smartphones der Redaktion |

**IT-Systeme und Dienste**

| ID | System | Betrieb | Standort |
|---|---|---|---|
| S1 | Webspace (PHP ≥ 8.0, Webserver) | Hoster | **[Betreiber: Hoster, RZ-Standort]** |
| S2 | Datenbank (MySQL/MariaDB) | Hoster | wie S1 |
| S3 | Mailserver des Absenderpostfachs | Hoster oder Mail-Anbieter | **[Betreiber]** |
| S4 | Server für das Signal-Gateway (vServer, Docker, Reverse-Proxy) | **[Betreiber]** | außerhalb der eigenen IT |
| S5 | GroupAlarm (Cloud-Dienst) | Anbieter | **[Betreiber: laut Vertrag]** |
| S6 | externer Uptime-Dienst | Anbieter | **[Betreiber]** |
| C1 | Endgeräte der Beschäftigten (Lesen) | Beschäftigte, teils privat | nicht im Verbund |

**Kommunikationsverbindungen**

| ID | Verbindung | Schutz |
|---|---|---|
| K1 | Browser ↔ S1 | HTTPS (TLS), HSTS |
| K2 | S1 ↔ S2 | lokal beim Hoster bzw. **[Betreiber: TLS, falls entfernt]** |
| K3 | S1 → S3 (SMTP) | STARTTLS/SSL mit Zertifikatsprüfung |
| K4 | S1 → S4 | HTTPS mit Token, ohne Umleitungen |
| K5 | S1 → S5 | HTTPS mit Personal-Access-Token |
| K6 | S6 → S1 (`health.php`) | HTTPS, optional Token |
| K7 | Cron-Dienst → S1 (`cron.php`) | HTTPS mit Token |

**Räume:** keine eigenen. Die Räume liegen beim Hoster bzw. Anbieter; ihre Absicherung regelt der Vertrag
(Abschnitt 7.6).

### 2.2 Schutzbedarfsfeststellung

**Schutzbedarfskategorien** (Vorschlag nach 200-2, an die Kategorien der eigenen Organisation anpassen):

| Kategorie | Bedeutung |
|---|---|
| normal | Schadensauswirkungen begrenzt und überschaubar |
| hoch | Schadensauswirkungen beträchtlich |
| sehr hoch | Schadensauswirkungen existenziell bedrohlich, katastrophal |

**Schadensszenarien (Begründung):**

* *Gefährdung von Leib und Leben:* Eine falsche Meldung ("Standort zugänglich", obwohl gesperrt) oder eine still
  beendete Warnung kann Personen an einen gefährlichen Ort schicken. → Integrität **hoch**.
* *Beeinträchtigung der Aufgabenerfüllung:* Ohne Seite fehlt im Notfall der zentrale Informationsweg. → Verfügbarkeit
  **hoch** (im Ereignisfall).
* *Ansehen:* Meldungen können öffentlich werden; deshalb nur pressetaugliche Texte. Eine gefälschte Meldung wäre
  peinlich und schädlich. → Integrität **hoch**.
* *Datenschutz:* Protokolle enthalten IP-Adressen und Kennungen der Redaktion, Verteiler enthalten dienstliche
  Kontaktdaten, optional Mobilnummern. Keine besonderen Kategorien (Art. 9 DSGVO). → Vertraulichkeit **normal**, für
  Verteiler und Protokolle **hoch** (Bündelung von Kontaktdaten der Krisenorganisation, nutzbar für Social
  Engineering).

| Objekt | Vertraulichkeit | Integrität | Verfügbarkeit | Begründung |
|---|---|---|---|---|
| GP1 Krisenkommunikation | normal | **hoch** | **hoch** | siehe oben |
| GP2 Alarmierung | hoch | **hoch** | **hoch** | Verteiler vertraulich; Fehlalarm oder ausbleibender Alarm schädlich |
| A1 Status-BCM | hoch | **hoch** | **hoch** | Maximumprinzip über GP1, GP2 |
| A2 Mailversand | hoch | hoch | normal | nur ein Kanal von mehreren (Verteilungseffekt) |
| A3 Signal | hoch | hoch | normal | Zusatzkanal; Gateway sieht Klartext |
| A4 GroupAlarm | hoch | hoch | normal | Zusatzkanal |
| S1/S2 Webspace, Datenbank | hoch | **hoch** | **hoch** | tragen A1 |
| S4 Signal-Server | hoch | hoch | normal | Zusatzkanal |
| `config.local.inc.php` (Master-Key) | **sehr hoch** | **sehr hoch** | hoch | Kompromittierung legt alles offen und erlaubt gültige Fälschungen |
| K1 bis K7 | wie die verbundenen Objekte | | | |

**[Betreiber]:** Kategorien und Einstufung bestätigen oder anpassen; bei "sehr hoch" für Verfügbarkeit (z. B.
Pflichtkanal einer KRITIS-Einrichtung) reicht ein einzelner Webspace nicht, siehe Abschnitt 5.

## 3. Modellierung

| Zielobjekt | Bausteine (IT-Grundschutz-Kompendium) | Umsetzung |
|---|---|---|
| Gesamter Verbund | ISMS.1 Sicherheitsmanagement; ORP.1 Organisation; ORP.2 Personal; ORP.3 Sensibilisierung und Schulung; ORP.4 Identitäts- und Berechtigungsmanagement; ORP.5 Compliance Management; CON.1 Kryptokonzept; CON.2 Datenschutz; CON.3 Datensicherungskonzept; CON.6 Löschen und Vernichten; OPS.1.1.3 Patch- und Änderungsmanagement; OPS.1.1.5 Protokollierung; OPS.2.3 Nutzung von Outsourcing; DER.1 Detektion von sicherheitsrelevanten Ereignissen; DER.2.1 Behandlung von Sicherheitsvorfällen; DER.4 Notfallmanagement | Software: 05 Abschnitt 5; Organisation: **[Betreiber]** |
| A1 Status-BCM | APP.3.1 Webanwendungen und Webservices; CON.8 Software-Entwicklung; CON.10 Entwicklung von Webanwendungen | 05 Abschnitt 5.2 |
| S1 Webspace | APP.3.2 Webserver; OPS.2.3 (Hoster) | `.htaccess`, Header; Hoster-Vertrag |
| S2 Datenbank | APP.4.3 Relationale Datenbanken | Prepared Statements, Trigger, eigener DB-Benutzer, [DB-Rechte härten](04-betrieb.md#datenbank-rechte-härten-optional) |
| A2/S3 Mail | APP.5.3 Allgemeiner E-Mail-Client und -Server (soweit eigener Server); sonst OPS.2.3 | TLS mit Zertifikatsprüfung, BCC |
| A3/S4 Signal-Gateway | SYS.1.1 Allgemeiner Server; SYS.1.3 Server unter Linux und Unix; SYS.1.6 Containerisierung; APP.3.2 (Reverse-Proxy) | **[Betreiber]**, siehe [Betrieb → Signal](04-betrieb.md#signal-einrichten) |
| A4/S5 GroupAlarm, S6 Uptime-Dienst | OPS.2.2 Cloud-Nutzung; OPS.2.3 | Vertrag, Token mit minimalen Rechten |
| Smartphones der Redaktion (TOTP) | SYS.3.2.1 Allgemeine Smartphones und Tablets | **[Betreiber]**: Displaysperre, Updates, Verlustmeldung |

Hinweis: Baustein-Bezeichnungen nach Kompendium Edition 2023; bei einer neueren Edition abgleichen.

## 4. IT-Sicherheitskonzept (ISK)

Das ISK für Status-BCM setzt sich aus diesen Teilen zusammen. Die Spalte "Quelle" zeigt, wo der Inhalt bereits steht.

| Kapitel des ISK | Inhalt | Quelle |
|---|---|---|
| 1. Geltungsbereich, Ziele | Informationsverbund, Sicherheitsziele (Integrität und Verfügbarkeit vor Vertraulichkeit) | Abschnitt 1; 05 Abschnitt 1 |
| 2. Strukturanalyse | Prozesse, Anwendungen, Systeme, Verbindungen | Abschnitt 2.1 |
| 3. Schutzbedarfsfeststellung | Kategorien, Einstufung, Begründung | Abschnitt 2.2 |
| 4. Modellierung | Bausteine je Zielobjekt | Abschnitt 3 |
| 5. IT-Grundschutz-Check | Umsetzungsstand je Anforderung | 05 Abschnitte 5 und 10 (Software); **[Betreiber]** für organisatorische Anforderungen |
| 6. Risikoanalyse | Gefährdungen, Bewertung, Behandlung | Abschnitt 5 |
| 7. Maßnahmen und Realisierungsplan | offene Maßnahmen mit Verantwortlichen und Terminen | Abschnitt 4.1 |
| 8. Restrisiken und Akzeptanz | von der Leitung unterschrieben | 05 Abschnitt 8; Abschnitt 5.4 |
| 9. Datensicherung, Notfallvorsorge | Backup, Wiederanlauf, Übungen | 05 Abschnitt 5.8; Abschnitt 6 |
| 10. Kryptokonzept | Verfahren, Schlüssel, Aufbewahrung | 05 Abschnitt 5.3 und 11 |
| 11. Protokollierung | Ereignisse, Integrität, Auswertung, Export | 05 Abschnitt 5.4 |
| 12. Datenschutz | VVT, TOM, DSFA-Schwellwert, AVV, Löschkonzept | Abschnitt 7 |

### 4.1 Realisierungsplan (organisatorische Maßnahmen beim Betreiber)

| Nr. | Maßnahme | Baustein | Verantwortlich | Termin | Erledigt |
|---|---|---|---|---|---|
| M1 | Master-Key (`config.local.inc.php`) getrennt und offline sichern, Zugriff dokumentieren | CON.1 | **[ ]** | **[ ]** | ☐ |
| M2 | Hoster-Vertrag mit AV-Vertrag, RZ-Standort, Backup, PHP-Updates, getrennten Sitzungsordnern | OPS.2.3, CON.2 | **[ ]** | **[ ]** | ☐ |
| M3 | Mindestens zwei Admins und zwei Redaktionspersonen je Bereitschaft; Freigabeprozess für neue Kennungen | ORP.4 | **[ ]** | **[ ]** | ☐ |
| M4 | Externer Uptime-Check auf `health.php`, Alarm außerhalb der eigenen Mail | DER.1, DER.4 | **[ ]** | **[ ]** | ☐ |
| M5 | Audit-Anker täglich archivieren, halbjährlich PDF-Export mit Anker abgleichen | OPS.1.1.5 | ISB | **[ ]** | ☐ |
| M6 | Signal-Gateway: Server härten, Reverse-Proxy mit Token, Updates; oder bewusst verzichten | SYS.1.1, SYS.1.6 | **[ ]** | **[ ]** | ☐ |
| M7 | GroupAlarm: Vertrag/AVV, Token mit minimalen Rechten, Szenarien je Kreis | OPS.2.2 | **[ ]** | **[ ]** | ☐ |
| M8 | Löschfristen festlegen (Abschnitt 7.8), Exporte verschlüsselt ablegen | CON.6, CON.2 | DSB, ISB | **[ ]** | ☐ |
| M9 | Schulung Redaktion (Kurzkarte, TOTP, Texte), jährliche Unterweisung | ORP.3 | **[ ]** | **[ ]** | ☐ |
| M10 | Übung halbjährlich mit Status "Übung", allen Kanälen und dem Aushang als Rückfallweg | DER.4 | Notfallbeauftragte/r | **[ ]** | ☐ |
| M11 | Smartphones der Redaktion: Sperre, Updates, Verlustmeldung an Admin (TOTP neu koppeln) | SYS.3.2.1 | **[ ]** | **[ ]** | ☐ |
| M12 | Informationspflichten (Art. 13 DSGVO) und Mitbestimmung (Abschnitt 7.9) erledigen | CON.2 | DSB, Personalabteilung | **[ ]** | ☐ |

## 5. Risikoanalyse nach BSI-Standard 200-3

### 5.1 Methode

Für Zielobjekte mit hohem oder sehr hohem Schutzbedarf (A1, S1, S2, Master-Key, GP1/GP2) wurden die relevanten
elementaren Gefährdungen aus dem Kompendium und zusätzliche, anwendungsspezifische Gefährdungen bewertet.

**Eintrittshäufigkeit:** selten (höchstens alle 5 Jahre) · mittel (einmal in 1 bis 5 Jahren) · häufig (mehrmals im
Jahr) · sehr häufig (monatlich oder öfter).

**Schadenshöhe:** vernachlässigbar · begrenzt · beträchtlich · existenzbedrohend.

**Risikomatrix** (Ergebnis: gering · mittel · hoch · sehr hoch):

| | vernachlässigbar | begrenzt | beträchtlich | existenzbedrohend |
|---|---|---|---|---|
| **sehr häufig** | gering | mittel | hoch | sehr hoch |
| **häufig** | gering | mittel | hoch | sehr hoch |
| **mittel** | gering | gering | mittel | hoch |
| **selten** | gering | gering | mittel | mittel |

**[Betreiber]:** Matrix an die Risikomethode der Organisation anpassen. Die Bewertung "nachher" setzt voraus, dass die
Maßnahmen aus 05 und der Realisierungsplan (4.1) umgesetzt sind.

### 5.2 Gefährdungen und Bewertung

| Nr. | Gefährdung (Kompendium) | Szenario | vorher | Maßnahmen | nachher | Behandlung |
|---|---|---|---|---|---|---|
| R1 | G 0.22 Manipulation von Informationen; G 0.46 Integritätsverlust | Gefälschte oder still beendete Meldung | hoch | Persönliche Kennung mit TOTP beim Login; TOTP je kritischer Aktion, auch beim Beenden; Vorschau; Zeilen-MAC; Protokoll-Abgleich; Hash-Kette; Audit-Anker | gering | reduzieren |
| R2 | G 0.36 Identitätsdiebstahl; G 0.42 Social Engineering | Phishing des persönlichen Passworts | hoch | TOTP beim Login; Brute-Force-Sperre; kein Passwort-Reset per Mail. Rest: Echtzeit-Phishing des TOTP-Codes | mittel | reduzieren, Rest akzeptieren (oder FIDO2 als Ausbau) |
| R3 | G 0.23 Unbefugtes Eindringen; G 0.28 Software-Schwachstellen | Angriff auf die Webanwendung | mittel | CSP ohne JavaScript, Prepared Statements, CSRF, Ausgabekodierung, keine Abhängigkeiten, automatische Tests | gering | reduzieren |
| R4 | G 0.30 Unberechtigte Nutzung; G 0.32 Missbrauch von Berechtigungen | Admin oder Redaktion missbraucht Rechte | mittel | Rollen, TOTP je Aktion, lückenloses Protokoll mit Export, Nutzer nie löschbar | gering | reduzieren |
| R5 | G 0.19 Offenlegung schützenswerter Informationen | Verteiler oder Protokoll gelangt nach außen | mittel | Verschlüsselung in der DB, Adressen nur maskiert, BCC, Export nur Admins und protokolliert | gering | reduzieren |
| R6 | G 0.21 Manipulation von Hard- oder Software; G 0.23 | Dateizugriff auf den Webspace (Master-Key) | mittel × existenzbedrohend = hoch | Hoster-Auswahl, FTP/SSH mit 2FA, Rechte 0600, Audit-Anker außerhalb | mittel | reduzieren, Rest akzeptieren |
| R7 | G 0.25 Ausfall von Geräten oder Systemen; G 0.9 Ausfall von Kommunikationsnetzen; G 0.40 Denial of Service | Webspace oder Netz nicht erreichbar | mittel | externer Uptime-Check, schlanke Seite, Aushang mit Adresse, Rückfallweg Telefonkette | mittel | akzeptieren; bei sehr hohem Verfügbarkeitsbedarf zweiten Standort vorsehen |
| R8 | G 0.9; zusätzliche Gefährdung "gemeinsamer Ausfall" | Mail fällt zusammen mit der eigenen IT aus | hoch | Signal und GroupAlarm als unabhängige Kanäle; Webspace extern | gering bis mittel | reduzieren |
| R9 | zusätzlich: Ausfall des Cron | Keine Erinnerungen, abgelaufene Meldungen bleiben unbemerkt | mittel | Hinweis, Prüfung, Warnmail, `health.php` | gering | reduzieren |
| R10 | G 0.31 Fehlerhafte Nutzung | Falsche Meldung, falscher Kreis alarmiert | häufig × begrenzt = mittel | feste Texte, Vorschau, Kreise mit Need-to-know, Übungen | gering | reduzieren |
| R11 | G 0.45 Datenverlust | Datenbank verloren | selten × beträchtlich = mittel | tägliches Backup beim Hoster, Wiederherstellungstest, Master-Key getrennt | gering | reduzieren |
| R12 | G 0.20 Informationen aus unzuverlässiger Quelle; G 0.18 Fehlplanung | Signal-Gateway ungepflegt oder offen | mittel | Reverse-Proxy mit Token, nur `/v2/send`, Updates (M6) | gering | reduzieren oder auf Signal verzichten |
| R13 | G 0.29 Verstoß gegen Gesetze; G 0.38 Missbrauch personenbezogener Daten | Datenschutzverstoß (Löschfristen, Drittland Signal, Mitbestimmung) | mittel | Abschnitt 7; IP-Adressen im Export nur auf Wahl | gering | reduzieren |
| R14 | G 0.37 Abstreiten von Handlungen | "Ich habe die Meldung nicht gesetzt" | mittel | persönliche Kennung mit TOTP, Protokoll mit IP und Browser, Hash-Kette | gering | reduzieren |
| R15 | zusätzlich: Weitergabe des gemeinsamen Zugangs | Unbefugte lesen die Statusseite | häufig × vernachlässigbar = gering | Inhalte pressetauglich, Wechsel des Passworts | gering | akzeptieren |

### 5.3 Ergebnis

Nach Umsetzung bleiben **mittlere** Risiken bei R2 (Echtzeit-Phishing), R6 (Dateizugriff beim Hoster) und R7
(Ausfall des einzelnen Webspaces). Alle anderen sind gering.

### 5.4 Risikoakzeptanz

**[Betreiber]:** Die Leitung nimmt die verbleibenden Risiken R2, R6, R7 und R15 zur Kenntnis und akzeptiert sie
bzw. beauftragt weitere Maßnahmen (z. B. FIDO2, zweiter Standort). Name, Funktion, Datum, Unterschrift:
\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_

## 6. Business Continuity Management (BSI-Standard 200-4)

| Thema | Festlegung |
|---|---|
| Rolle | Kommunikationsmittel der Notfall- und Krisenorganisation (BAO), kein Alarmierungs-Ersatz |
| Unabhängigkeit | Webspace außerhalb der eigenen IT; Signal/GroupAlarm unabhängig von der eigenen Mail; Aushang auf Papier |
| Wer darf melden | Redaktion und Admins mit persönlicher Kennung, Bereitschaften mit mindestens zwei Personen (M3) |
| Alarmierungskette | Statusseite + ALARM-Mail + Signal/GroupAlarm je Kreis; Telefonkette als Rückfallweg **[Betreiber: im Notfallhandbuch]** |
| Wiederanlauf der Seite selbst | Hoster-Backup und `config.local.inc.php` aus der Offline-Sicherung; Ziel-Wiederanlaufzeit **[Betreiber, z. B. 4 h]** |
| Überwachung | Uptime-Check auf `health.php`, Cron-Warnung |
| Übungen | halbjährlich, Status "Übung" mit ALARM über alle Kanäle; Auswertung: Zustellzahlen im Protokoll, Lesezähler, Rückmeldungen |
| Nachbereitung | Protokoll-Export (PDF) zur Ereignisakte; Lessons Learned |
| Pressetauglichkeit | nur freigegebene Texte; Ursache und Umfang nie auf der Seite |

## 7. Datenschutz

### 7.1 Verantwortlicher und Beteiligte

| Rolle | Wer |
|---|---|
| Verantwortlicher (Art. 4 Nr. 7 DSGVO) | **[Betreiber: Organisation, Anschrift]** |
| Datenschutzbeauftragte/r | **[Betreiber]** |
| Auftragsverarbeiter | Hoster (Webspace, DB), Mail-Anbieter (falls extern), GroupAlarm, Betreiber des Signal-Servers (falls extern), Uptime-Dienst (nur technische Daten) |
| Eigenständig Verantwortliche bzw. Dritte | Signal-Dienst (Zustellung der Nachrichten an die Empfängernummern) |

### 7.2 Eintrag für das Verzeichnis von Verarbeitungstätigkeiten (Art. 30 DSGVO)

| Feld | Inhalt |
|---|---|
| Bezeichnung | Krisenkommunikation und Alarmierung über Status-BCM |
| Zweck | Information der Beschäftigten im Notfall; Alarmierung von Funktionsgruppen; Nachweis von Änderungen (Revisionssicherheit); Schutz vor Missbrauch (Brute-Force-Schutz) |
| Rechtsgrundlagen | **[Betreiber mit DSB festlegen]**, typischerweise Art. 6 Abs. 1 lit. f DSGVO (berechtigtes Interesse an funktionsfähiger Krisenkommunikation und Nachweisbarkeit), bei öffentlichen Stellen lit. e i. V. m. der Aufgabennorm; für Beschäftigte zusätzlich Art. 88 DSGVO i. V. m. einer Betriebs- oder Dienstvereinbarung bzw. § 26 BDSG (nach EuGH C-34/21 die Tragfähigkeit von § 26 Abs. 1 BDSG mit dem DSB prüfen); private Mobilnummern für Signal nur freiwillig (Art. 6 Abs. 1 lit. a) oder dienstliche Geräte |
| Betroffene | Redaktion und Admins; Mitglieder der Alarmkreise und Standortverwaltungen; Beschäftigte (nur Lesezugang, anonym) |
| Datenkategorien | Redaktion/Admins: Kennung, Name, dienstliche E-Mail, Passwort-Hash, TOTP-Secret, Anmeldezeiten, IP-Adresse und Browserkennung bei Anmeldung und Änderungen, interne Notizen. Alarmkreise: dienstliche E-Mail-Adressen, optional Mobilnummern bzw. Signal-Gruppen. Kontakte: Funktionsnummern, Funktionspostfächer, Konferenzdaten. Beschäftigte: keine personenbezogenen Daten (Lesezähler ohne IP und Person; Fehlversuche nur pseudonymisiert) |
| Empfänger | Mailserver und Postfächer der Kreise; Signal-Gateway und Signal-Dienst; GroupAlarm; Hoster als Auftragsverarbeiter; bei Exporten Revision und ISB |
| Drittlandübermittlung | Signal: Empfängernummern und Metadaten beim Signal-Dienst (USA). **[Betreiber mit DSB bewerten]**, Alternativen: Verzicht auf Signal, nur dienstliche Nummern, GroupAlarm. Übrige Dienste: **[laut Vertrag, möglichst EU]** |
| Löschfristen | Abschnitt 7.8 |
| TOM | Abschnitt 7.3 und [Sicherheit und Audit](05-sicherheit-und-audit.md) |

### 7.3 Technische und organisatorische Maßnahmen (Art. 32 DSGVO)

| Schutzziel | Maßnahmen in Status-BCM |
|---|---|
| Vertraulichkeit | Zwei Anmeldestufen; persönliche Kennung nur mit TOTP; Verschlüsselung (AES-256-GCM) von Inhalten, Protokolldetails, Adressen, Nummern, E-Mail und TOTP-Secret; Adressen nur maskiert angezeigt; BCC; HTTPS; strenge CSP; Export nur Admins |
| Integrität | Vorschau, TOTP je kritischer Aktion, Zeilen-MAC, HMAC-Hash-Kette, append-only per Trigger, Audit-Anker |
| Verfügbarkeit und Belastbarkeit | externer Webspace, schlanke Seite ohne JavaScript, mehrere Alarmkanäle, Selbstüberwachung, `health.php`, Backups |
| Wiederherstellbarkeit | Backup-Konzept 05 Abschnitt 5.8, Master-Key offline |
| Pseudonymisierung | IP und Benutzer bei Fehlversuchen nur als HMAC; Lesezähler ohne Personenbezug |
| Datenminimierung | kein Freitext in Meldungen; IP-Adressen im Export nur auf Wahl; Stufe 1 anonym |
| Überprüfung, Bewertung, Evaluierung | Prüfung unter System, automatische Tests, Protokoll-Export, Übungen, jährliche Überprüfung dieser Seite |

### 7.4 Schwellwertanalyse zur Datenschutz-Folgenabschätzung (Art. 35 DSGVO)

| Kriterium (Leitlinien der Art.-29-Gruppe WP 248, vom EDSA bestätigt) | erfüllt? | Begründung |
|---|---|---|
| Bewertung oder Scoring | nein | keine |
| Automatisierte Entscheidung mit Rechtswirkung | nein | keine |
| Systematische Überwachung | nein | Protokoll nur von Änderungen der Redaktion, keine Überwachung der Beschäftigten |
| Sensible Daten (Art. 9, 10) | nein | keine |
| Umfangreiche Verarbeitung | nein | wenige Personen, wenige Datenfelder |
| Abgleich oder Zusammenführung von Datensätzen | nein | keine |
| Schutzbedürftige Betroffene | **ja** | Beschäftigte (Abhängigkeitsverhältnis) |
| Innovative Technologie | nein | etablierte Verfahren |
| Hindert Betroffene an Rechtsausübung oder Vertragsschluss | nein | keine |

Ergebnis: ein Kriterium erfüllt; die Verarbeitung steht nicht auf der DSFA-Muss-Liste der Datenschutzkonferenz.
**Vorschlag:** keine DSFA erforderlich; Ergebnis mit DSB dokumentieren. **[Betreiber: Bestätigung DSB, Datum]**

### 7.5 Informationspflichten (Art. 13 DSGVO)

Redaktion, Admins und Mitglieder der Alarmkreise sind zu informieren über Zweck, Rechtsgrundlage, Speicherdauer,
Empfänger (inkl. Signal/GroupAlarm), Betroffenenrechte und Kontakt des DSB. Beschäftigte mit Lesezugang: Hinweis,
dass ein anonymer Lesezähler geführt wird. **[Betreiber: Text im Intranet bzw. im Aushang-Ordner]**

### 7.6 Auftragsverarbeitung (Art. 28 DSGVO)

| Dienstleister | Gegenstand | Prüfpunkte |
|---|---|---|
| Hoster | Webspace, Datenbank, Backups, Sitzungsdateien, Logs | AVV, RZ-Standort, Zugriff des Personals, Backup-Aufbewahrung, getrennte Sitzungsordner, PHP-Updates |
| Mail-Anbieter (falls nicht der Hoster) | Versand und Postfach | AVV, TLS |
| GroupAlarm | Alarmtexte, Alarmierte | AVV, Serverstandort, Unterauftragnehmer, Löschung der Alarmhistorie |
| Betreiber des Signal-Servers (falls extern) | Klartext der Alarmtexte, Empfängernummern | AVV, Härtung, Zugriff |
| Uptime-Dienst | nur URL und Antwortcode | in der Regel keine personenbezogenen Daten; Nutzungsbedingungen prüfen |

### 7.7 Betroffenenrechte

Auskunft (Art. 15): Admins sehen Benutzerdaten unter **Benutzer**, Protokolleinträge einer Person lassen sich über den
Export (CSV, Spalte "Akteur") zusammenstellen. Berichtigung (Art. 16): unter **Benutzer** bzw. **System**.
Löschung (Art. 17): Konten werden deaktiviert, nicht gelöscht, weil das Protokoll zuordenbar bleiben muss
(Art. 17 Abs. 3 lit. b/e: Nachweis- und Rechtspflichten); Adressen und Nummern in Kreisen lassen sich sofort entfernen.
Widerspruch (Art. 21): **[Betreiber: Verfahren]**.

### 7.8 Löschkonzept (Vorschlag)

| Datenart | Vorschlag Regelfrist | Technisch |
|---|---|---|
| Fehlversuche (pseudonymisiert) | 2 Tage | automatisch |
| verbrauchte TOTP-Schritte | etwa 1 Stunde | automatisch |
| Kreise, Standortadressen, Kontakte | bis zum Entfernen (Personalwechsel) | unter **System** |
| Benutzerkonten | Deaktivierung beim Ausscheiden; Konto bleibt so lange wie das Protokoll | Deaktivierung |
| Statusverlauf und Änderungsprotokoll (inkl. IP) | **[Betreiber, z. B. 3 Jahre nach Jahresende]** | derzeit **keine Löschfunktion**: Die Hash-Kette ist absichtlich unveränderlich. Löschen alter Einträge ist nur durch die DB-Administration möglich, bricht die Kettenprüfung und muss dokumentiert werden (vorher PDF-Export als Nachweis). Eine Löschfunktion mit neuem Kettenanker ist als Ausbaustufe vorgemerkt. |
| Mail-Protokoll (Inhalte verschlüsselt, Adressen maskiert) | wie Statusverlauf | wie oben |
| Lesezähler | ohne Personenbezug, keine Frist nötig | – |
| Protokoll-Exporte (Dateien) | nach Zweck, spätestens **[Betreiber]** | beim Empfänger |
| Signal-Gateway, GroupAlarm | laut Vertrag bzw. Einstellung des Dienstes | beim Dienst |

### 7.9 Mitbestimmung

Das Änderungsprotokoll (wer hat wann von welcher IP welche Meldung gesetzt) ist objektiv geeignet, Verhalten oder
Leistung der Redaktion zu überwachen. Damit greift in der Regel die Mitbestimmung des Betriebsrats
(§ 87 Abs. 1 Nr. 6 BetrVG) bzw. des Personalrats nach dem einschlägigen Personalvertretungsrecht.
**[Betreiber]:** Betriebs- oder Dienstvereinbarung mit Zweckbindung (Nachweis und Sicherheit, keine
Leistungskontrolle) und Regelung der Auswertung (z. B. nur anlassbezogen, Vier-Augen-Prinzip mit ISB/DSB).

## 8. ISMS-Rollen und Prozesse

| Aufgabe | Leitung | ISB | DSB | Notfallbeauftragte/r | Admin | Redaktion | Hoster |
|---|---|---|---|---|---|---|---|
| Freigabe ISK und Risikoakzeptanz | **A** | R | C | C | I | – | – |
| Schutzbedarf, Risikoanalyse, Realisierungsplan pflegen | I | **A/R** | C | C | C | – | – |
| VVT, Informationspflichten, Löschkonzept | I | C | **A/R** | – | C | – | – |
| Meldungstexte freigeben (`config.json`) | A | C | – | **R** | I | I | – |
| Benutzer anlegen, Rechte prüfen (monatlich) | I | C | – | C | **A/R** | – | – |
| Meldungen setzen und beenden | – | – | – | A | – | **R** | – |
| Audit-Anker archivieren, Export prüfen | – | **A/R** | I | – | C | – | – |
| Backup, Patches Webspace | – | C | – | – | A | – | **R** |
| Übungen | I | C | – | **A/R** | R | R | – |
| Sicherheitsvorfall (z. B. Kettenfehler) | I | **A/R** | C | C | R | I | C |

R = durchführend, A = verantwortlich, C = beteiligt, I = informiert. **[Betreiber: Namen eintragen]**

**PDCA:** Jährliche Überprüfung dieser Seite und von 05 (Plan/Check); Kennzahlen aus der Anwendung:
Verfügbarkeit laut Uptime-Dienst, Cron-Warnungen, Zustellquote der ALARM-Mails und Kanäle (Protokoll), Ergebnis der
Kettenprüfung, Anzahl aktiver Kennungen ohne Anmeldung seit 90 Tagen (Seite **Benutzer**).

**Sicherheitsvorfall:** "Integrität der Protokollkette: FEHLER", eine unbekannte Änderung im Protokoll, ein
verlorenes Smartphone mit TOTP oder ein Verdacht auf Dateizugriff beim Hoster sind Vorfälle nach DER.2.1. Erste
Schritte: Export sichern, betroffene Kennung deaktivieren bzw. TOTP neu koppeln, Hoster einbinden, bei Dateizugriff
Master-Key als kompromittiert behandeln (Neuinstallation, alle Passwörter und Tokens wechseln).

## 9. Regulatorischer Kontext

* **NIS2 / KRITIS:** Fällt die Organisation darunter, gelten eigene Melde- und Nachweispflichten gegenüber dem BSI.
  Status-BCM ist **kein** Meldeweg an Behörden; es unterstützt die interne Krisenkommunikation und liefert mit
  Protokoll und Export Nachweise für das Notfallmanagement.
* **Barrierefreiheit:** Stand nach WCAG 2.1 AA, bekannte Grenzen und Vorlage für die Erklärung in
  [Barrierefreiheit](07-barrierefreiheit.md); eine Prüfung mit Screenreader bzw. ein BITV-Test ist **[Betreiber]**.

## 10. Audit-Mappe (Checkliste)

| Unterlage | Quelle |
|---|---|
| Strukturanalyse, SBF, Modellierung | Abschnitte 2 und 3 |
| ISK mit Realisierungsplan, unterschriebene Risikoakzeptanz | Abschnitte 4 und 5 |
| Technische Maßnahmen, Speicherorte | [05](05-sicherheit-und-audit.md), Abschnitte 5 und 11 |
| Prüfung unter System (Bildschirmfoto oder Ausdruck) | **System → Prüfung** |
| Protokoll-Export (PDF) und passende Audit-Anker-Mails | **System → Protokoll-Export**, Postfach `cc_default_mail1` |
| Benutzerliste mit Rollen und letzter Anmeldung | Seite **Benutzer** |
| VVT-Eintrag, DSFA-Schwellwert, AV-Verträge, Informationstext | Abschnitt 7 |
| Betriebs- oder Dienstvereinbarung | Abschnitt 7.9 |
| Übungsprotokolle, Lessons Learned | Abschnitt 6 |
| Testergebnisse der eingesetzten Version | `php tests/selftest.php`, `webtest.php`, `installtest.php` |
