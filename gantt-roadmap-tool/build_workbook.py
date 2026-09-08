"""
Erstellt die Arbeitsdatei "Service_Roadmap.xlsx".

Reiter "Service Roadmap":
    - Zeile 4: Quartale (dunkelblauer Hintergrund, weisse Schrift, mit einem
      weissen Trennstrich zwischen den Quartalsbloecken).
    - Zeile 5: Monate (je eine Spalte pro Monat).
    - Ab Zeile 6: Liste der Services/Massnahmen mit Kategorie, Start-/Enddatum
      und automatisch eingefaerbtem Gantt-Balken.

Reiter "Anleitung":
    - Kurzanleitung zur Bedienung.
    - Farbzuordnungs-Tabelle: Pro Kategorie kann per Dropdown eine Farbe
      gewaehlt werden. Die Auswahl wird per Vorschau-Feld angezeigt und
      wirkt sich (per Conditional Formatting + VLOOKUP) live auf die
      Balkenfarben im Reiter "Service Roadmap" aus - ohne Makro/VBA.

Ausfuehren mit:  python3 build_workbook.py
"""

from datetime import date

from openpyxl import Workbook
from openpyxl.formatting.rule import FormulaRule
from openpyxl.styles import Alignment, Border, Font, PatternFill, Side
from openpyxl.utils import get_column_letter
from openpyxl.worksheet.datavalidation import DataValidation

# ---------------------------------------------------------------------------
# Grunddaten
# ---------------------------------------------------------------------------

KATEGORIEN = ["Konzept", "Entwicklung", "Test", "Rollout", "Betrieb"]

# Name -> Hex-Farbcode. Diese Liste erscheint als Dropdown im Reiter
# "Anleitung" und steuert die Balkenfarben im Gantt.
FARBEN = {
    "Blau": "2E75B6",
    "Gruen": "548235",
    "Orange": "C55A11",
    "Rot": "C00000",
    "Violett": "7030A0",
    "Grau": "7F7F7F",
}

# Default-Zuordnung Kategorie -> Farbe (kann im Reiter "Anleitung" jederzeit
# geaendert werden).
DEFAULT_ZUORDNUNG = {
    "Konzept": "Blau",
    "Entwicklung": "Gruen",
    "Test": "Orange",
    "Rollout": "Violett",
    "Betrieb": "Grau",
}

BEISPIEL_TASKS = [
    ("Anforderungsanalyse", "Konzept", date(2026, 1, 1), date(2026, 3, 31)),
    ("Architektur & Design", "Konzept", date(2026, 2, 1), date(2026, 4, 30)),
    ("Entwicklung Kernmodul", "Entwicklung", date(2026, 4, 1), date(2026, 9, 30)),
    ("Testphase", "Test", date(2026, 9, 1), date(2026, 11, 30)),
    ("Rollout Produktion", "Rollout", date(2026, 11, 15), date(2027, 1, 31)),
    ("Betrieb & Support", "Betrieb", date(2027, 2, 1), date(2027, 12, 31)),
]

TIMELINE_START = date(2026, 1, 1)
ANZAHL_MONATE = 24  # 2 Jahre
ERSTE_ZEITSTRAHL_SPALTE = 5  # Spalte E
ERSTE_TASK_ZEILE = 6
LETZTE_TASK_ZEILE = 30  # Platz fuer weitere Zeilen zum Selbst-Ausfuellen

DUNKELBLAU = "1F3864"
MONATSGRAU = "D9D9D9"
RAHMENGRAU = "BFBFBF"

WEISS_DICK = Side(style="medium", color="FFFFFF")
GRAU_DUENN = Side(style="thin", color=RAHMENGRAU)


def add_month_columns(ws):
    """Schreibt Quartale (Zeile 4) und Monate (Zeile 5) und liefert die
    Spalte der letzten Zeitstrahl-Spalte zurueck."""

    quartals_start_col = ERSTE_ZEITSTRAHL_SPALTE
    monat = TIMELINE_START
    quartal_cols = []  # Liste von (start_col, end_col, label)

    for i in range(ANZAHL_MONATE):
        col = ERSTE_ZEITSTRAHL_SPALTE + i
        cell = ws.cell(row=5, column=col, value=monat)
        cell.number_format = "MMM"
        cell.font = Font(bold=True, size=9)
        cell.fill = PatternFill("solid", fgColor=MONATSGRAU)
        cell.alignment = Alignment(horizontal="center", vertical="center")
        cell.border = Border(left=GRAU_DUENN, right=GRAU_DUENN, top=GRAU_DUENN, bottom=GRAU_DUENN)
        ws.column_dimensions[get_column_letter(col)].width = 4.2

        # Quartalsgrenze alle 3 Monate
        quartal_index = (monat.month - 1) // 3
        if i % 3 == 0:
            quartal_start_col = col
        if i % 3 == 2 or i == ANZAHL_MONATE - 1:
            jahr = monat.year
            label = f"Q{quartal_index + 1} {jahr}"
            quartal_cols.append((quartal_start_col, col, label))

        # naechster Monat
        if monat.month == 12:
            monat = date(monat.year + 1, 1, 1)
        else:
            monat = date(monat.year, monat.month + 1, 1)

    letzte_zeitstrahl_spalte = ERSTE_ZEITSTRAHL_SPALTE + ANZAHL_MONATE - 1

    # Quartalszeile (Zeile 4): dunkelblau, weisse Schrift, mit weissem
    # Trennstrich zwischen den Bloecken.
    for idx, (start_col, end_col, label) in enumerate(quartal_cols):
        for col in range(start_col, end_col + 1):
            cell = ws.cell(row=4, column=col)
            cell.fill = PatternFill("solid", fgColor=DUNKELBLAU)
            cell.font = Font(bold=True, color="FFFFFF", size=10)
            cell.alignment = Alignment(horizontal="center", vertical="center")

        ws.cell(row=4, column=start_col, value=label)
        ws.merge_cells(start_row=4, start_column=start_col, end_row=4, end_column=end_col)

        # Weisser Trennstrich rechts von jedem Quartalsblock (ausser dem
        # letzten), sowie linker Rand fuer den allerersten Block.
        rechte_zelle = ws.cell(row=4, column=end_col)
        rechte_zelle.border = Border(right=WEISS_DICK)
        if idx == 0:
            linke_zelle = ws.cell(row=4, column=start_col)
            linke_zelle.border = Border(left=WEISS_DICK, right=linke_zelle.border.right)

    ws.row_dimensions[4].height = 20
    ws.row_dimensions[5].height = 18

    return letzte_zeitstrahl_spalte


def build_service_roadmap(wb):
    ws = wb.create_sheet("Service Roadmap")

    # Titel
    ws["A1"] = "Service Roadmap"
    ws["A1"].font = Font(bold=True, size=16, color=DUNKELBLAU)
    ws["A2"] = "Farbzuordnung der Kategorien: siehe Reiter \u201eAnleitung\u201c"
    ws["A2"].font = Font(italic=True, size=9, color="7F7F7F")

    letzte_spalte = add_month_columns(ws)

    # Kopfzeilen fuer die Task-Tabelle (Spalten A-D), passend zur Monatszeile.
    kopf_labels = ["Service / Massnahme", "Kategorie", "Start", "Ende"]
    for i, label in enumerate(kopf_labels):
        col = 1 + i
        cell = ws.cell(row=5, column=col, value=label)
        cell.font = Font(bold=True, size=9)
        cell.fill = PatternFill("solid", fgColor=MONATSGRAU)
        cell.alignment = Alignment(horizontal="center", vertical="center")
        cell.border = Border(left=GRAU_DUENN, right=GRAU_DUENN, top=GRAU_DUENN, bottom=GRAU_DUENN)

    # Zeile 4 ueber den Spalten A-D optisch passend (dunkelblau, ohne Text).
    ws.merge_cells(start_row=4, start_column=1, end_row=4, end_column=4)
    top_left = ws.cell(row=4, column=1)
    top_left.fill = PatternFill("solid", fgColor=DUNKELBLAU)
    top_left.font = Font(bold=True, color="FFFFFF", size=10)
    top_left.value = "Zeitraum"
    top_left.alignment = Alignment(horizontal="center", vertical="center")

    ws.column_dimensions["A"].width = 30
    ws.column_dimensions["B"].width = 16
    ws.column_dimensions["C"].width = 11
    ws.column_dimensions["D"].width = 11

    # Beispiel-Tasks eintragen
    for offset, (name, kategorie, start, ende) in enumerate(BEISPIEL_TASKS):
        row = ERSTE_TASK_ZEILE + offset
        ws.cell(row=row, column=1, value=name)
        ws.cell(row=row, column=2, value=kategorie)
        c_start = ws.cell(row=row, column=3, value=start)
        c_start.number_format = "DD.MM.YYYY"
        c_ende = ws.cell(row=row, column=4, value=ende)
        c_ende.number_format = "DD.MM.YYYY"

    # Rahmen fuer die gesamte Tabelle (Spalten A-D, Zeilen 6-letzte Task-Zeile)
    duenn = Border(left=GRAU_DUENN, right=GRAU_DUENN, top=GRAU_DUENN, bottom=GRAU_DUENN)
    for row in range(ERSTE_TASK_ZEILE, LETZTE_TASK_ZEILE + 1):
        for col in range(1, 5):
            ws.cell(row=row, column=col).border = duenn

    # Dropdown "Kategorie" (Spalte B) -> Liste aus Reiter "Anleitung"
    kategorie_dv = DataValidation(
        type="list",
        formula1="Anleitung!$B$14:$B$18",
        allow_blank=True,
        showDropDown=False,
    )
    ws.add_data_validation(kategorie_dv)
    kategorie_dv.add(f"B{ERSTE_TASK_ZEILE}:B{LETZTE_TASK_ZEILE}")

    # ------------------------------------------------------------------
    # Conditional Formatting: Gantt-Balken automatisch einfaerben.
    #
    # Fuer jede der definierten Farben wird EINE Regel ueber den gesamten
    # Zeitstrahlbereich gelegt. Die Regel prueft fuer jede Zelle:
    #   1. Liegt der Monat der Spalte (Zeile 5) im Start-/End-Zeitraum der
    #      Zeile (Spalten C/D)?
    #   2. Ist die aktuell im Reiter "Anleitung" fuer die Kategorie dieser
    #      Zeile gewaehlte Farbe genau diese Farbe?
    # Da die Farbzuordnung per VLOOKUP live aus dem Reiter "Anleitung"
    # gelesen wird, wirkt sich eine Aenderung der Farbauswahl dort sofort
    # (ohne Makro) auf die Balkenfarbe hier aus.
    # ------------------------------------------------------------------
    gantt_range = (
        f"{get_column_letter(ERSTE_ZEITSTRAHL_SPALTE)}{ERSTE_TASK_ZEILE}:"
        f"{get_column_letter(letzte_spalte)}{LETZTE_TASK_ZEILE}"
    )
    erste_spalte_buchstabe = get_column_letter(ERSTE_ZEITSTRAHL_SPALTE)

    for farb_name, farb_hex in FARBEN.items():
        formel = (
            f'=AND($B{ERSTE_TASK_ZEILE}<>"",'
            f'{erste_spalte_buchstabe}${ERSTE_TASK_ZEILE - 1}<=$D{ERSTE_TASK_ZEILE},'
            f'EOMONTH({erste_spalte_buchstabe}${ERSTE_TASK_ZEILE - 1},0)>=$C{ERSTE_TASK_ZEILE},'
            f'IFERROR(VLOOKUP($B{ERSTE_TASK_ZEILE},Anleitung!$B$14:$C$18,2,FALSE),"")="{farb_name}")'
        )
        fill = PatternFill("solid", fgColor=farb_hex)
        ws.conditional_formatting.add(gantt_range, FormulaRule(formula=[formel], fill=fill))

    ws.freeze_panes = f"{get_column_letter(ERSTE_ZEITSTRAHL_SPALTE)}{ERSTE_TASK_ZEILE}"
    ws.sheet_view.showGridLines = False

    return ws


def build_anleitung(wb):
    ws = wb.create_sheet("Anleitung")

    ws["A1"] = "Anleitung \u2013 Service Roadmap"
    ws["A1"].font = Font(bold=True, size=16, color=DUNKELBLAU)

    anleitungstexte = [
        "1. Trage im Reiter \u201eService Roadmap\u201c ab Zeile 6 deine Services/Massnahmen ein (Spalte A).",
        "2. Waehle in Spalte B \u201eKategorie\u201c die passende Kategorie ueber das Dropdown aus.",
        "3. Trage Start- (Spalte C) und Enddatum (Spalte D) ein.",
        "4. Der Balken im Zeitstrahl (ab Spalte E) faerbt sich automatisch entsprechend der",
        "    aktuell gewaehlten Kategorie-Farbe (siehe Tabelle unten) ein.",
        "5. Aendere unten in der Tabelle \u201eFarbzuordnung\u201c die Farbe einer Kategorie \u2013 die",
        "    Anpassung wird automatisch und live im Gantt-Diagramm im Reiter",
        "    \u201eService Roadmap\u201c uebernommen (kein Makro/VBA notwendig).",
    ]
    for i, text in enumerate(anleitungstexte):
        cell = ws.cell(row=3 + i, column=1, value=text)
        cell.font = Font(size=10)
        cell.alignment = Alignment(wrap_text=False)

    ws["A12"] = "Farbzuordnung"
    ws["A12"].font = Font(bold=True, size=12, color=DUNKELBLAU)

    # Tabellenkopf
    kopf_row = 13
    for col, label in enumerate(["Kategorie", "Farbe (Auswahl)", "Vorschau"], start=2):
        cell = ws.cell(row=kopf_row, column=col, value=label)
        cell.font = Font(bold=True, size=10, color="FFFFFF")
        cell.fill = PatternFill("solid", fgColor=DUNKELBLAU)
        cell.alignment = Alignment(horizontal="center")

    # Kategorie-Zeilen mit Dropdown + Vorschau
    for i, kategorie in enumerate(KATEGORIEN):
        row = 14 + i
        ws.cell(row=row, column=2, value=kategorie).font = Font(size=10)
        farbe_cell = ws.cell(row=row, column=3, value=DEFAULT_ZUORDNUNG[kategorie])
        farbe_cell.alignment = Alignment(horizontal="center")
        vorschau_cell = ws.cell(row=row, column=4, value="")
        for c in (2, 3, 4):
            ws.cell(row=row, column=c).border = Border(
                left=GRAU_DUENN, right=GRAU_DUENN, top=GRAU_DUENN, bottom=GRAU_DUENN
            )

    letzte_kategorie_zeile = 13 + len(KATEGORIEN)

    # Farb-Dropdown (Data Validation) fuer Spalte C
    farb_dv = DataValidation(
        type="list",
        formula1="Anleitung!$H$14:$H$" + str(13 + len(FARBEN)),
        allow_blank=False,
        showDropDown=False,
    )
    ws.add_data_validation(farb_dv)
    farb_dv.add(f"C14:C{letzte_kategorie_zeile}")

    # Hilfsliste der Farbnamen (Quelle fuer das Dropdown), kompakt an der Seite.
    ws["G13"] = "Farbpalette"
    ws["G13"].font = Font(bold=True, size=9, italic=True)
    for i, (farb_name, farb_hex) in enumerate(FARBEN.items()):
        row = 14 + i
        ws.cell(row=row, column=8, value=farb_name)
        ws.cell(row=row, column=9, value=f"#{farb_hex}")

    # Vorschau-Feld (Spalte D) automatisch einfaerben, je nach Auswahl in Spalte C.
    vorschau_range = f"D14:D{letzte_kategorie_zeile}"
    for farb_name, farb_hex in FARBEN.items():
        formel = f'=$C14="{farb_name}"'
        fill = PatternFill("solid", fgColor=farb_hex)
        ws.conditional_formatting.add(vorschau_range, FormulaRule(formula=[formel], fill=fill))

    ws.column_dimensions["A"].width = 62
    ws.column_dimensions["B"].width = 16
    ws.column_dimensions["C"].width = 16
    ws.column_dimensions["D"].width = 12
    ws.column_dimensions["G"].width = 12
    ws.column_dimensions["H"].width = 10
    ws.column_dimensions["I"].width = 10

    return ws


def main():
    wb = Workbook()
    # Default-Sheet entfernen, eigene Reihenfolge definieren.
    default_sheet = wb.active
    wb.remove(default_sheet)

    build_service_roadmap(wb)
    build_anleitung(wb)

    wb.active = 0
    out_path = "Service_Roadmap.xlsx"
    wb.save(out_path)
    print(f"Gespeichert: {out_path}")


if __name__ == "__main__":
    main()
