# Service Roadmap – Gantt-Tool (Excel)

Eigenständiges Projekt, unabhängig von `zoraxy-guard`. Erstellt eine
Excel-Arbeitsmappe (`Service_Roadmap.xlsx`) mit zwei Reitern:

## Reiter „Service Roadmap"

- **Zeile 4**: Quartale, dunkelblauer Hintergrund, weisse Schrift. Die
  Quartalsblöcke werden durch einen weissen Trennstrich unterteilt.
- **Zeile 5**: Monate (eine Spalte pro Monat, 24 Monate ab Januar 2026).
- **Ab Zeile 6**: Tabelle mit Services/Massnahmen (Name, Kategorie, Start-,
  Enddatum) sowie automatisch eingefärbter Gantt-Balken im Zeitstrahl.

## Reiter „Anleitung"

- Kurzanleitung zur Bedienung der Tabelle.
- Farbzuordnungs-Tabelle: Pro Kategorie kann per Dropdown eine Farbe aus
  einer vordefinierten Palette gewählt werden. Ein Vorschau-Feld zeigt die
  gewählte Farbe direkt an.

### Live-Farbkopplung ohne Makro/VBA

Die Balken im Gantt-Diagramm sind **nicht** hart codiert einzufärben.
Stattdessen liest eine bedingte Formatierung (Conditional Formatting) im
Reiter „Service Roadmap" per `VLOOKUP` live aus, welche Farbe im Reiter
„Anleitung" aktuell für die jeweilige Kategorie einer Zeile ausgewählt ist.
Ändert man dort die Farbauswahl, passt sich der entsprechende Balken im
Gantt-Diagramm sofort an – ganz ohne Makro, beim Öffnen der Datei in
Excel, LibreOffice Calc etc.

## Datei erzeugen / neu generieren

```bash
pip install -r requirements.txt
python3 build_workbook.py
```

Erzeugt `Service_Roadmap.xlsx` im selben Ordner. Anpassbar direkt im
Skript `build_workbook.py`:

- `KATEGORIEN` – Liste der Kategorien/Phasen.
- `FARBEN` – Name → Hex-Farbcode der wählbaren Palette.
- `DEFAULT_ZUORDNUNG` – Start-Zuordnung Kategorie → Farbe.
- `BEISPIEL_TASKS` – Beispiel-Zeilen im Gantt (können in Excel beliebig
  ersetzt/ergänzt werden, bis Zeile 30).
- `TIMELINE_START`, `ANZAHL_MONATE` – Zeitraum des Zeitstrahls.

## Nutzung in Excel/LibreOffice

1. Reiter „Service Roadmap" öffnen, ab Zeile 6 eigene Services eintragen.
2. In Spalte B über das Dropdown die passende Kategorie wählen.
3. Start- und Enddatum in Spalte C/D eintragen – der Balken erscheint
   automatisch im Zeitstrahl.
4. Farben bei Bedarf im Reiter „Anleitung" anpassen.
