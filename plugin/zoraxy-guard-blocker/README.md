# Zoraxy Guard Blocker

Ein [Zoraxy](https://github.com/tobychui/zoraxy) Router-Plugin, das einzelne
Pfade pro Domain direkt am Reverse Proxy mit **HTTP 403** sperrt — bevor die
Anfrage die eigentliche App erreicht. Das ist auch dann wirksam, wenn eine
App selbst mit `200`/Redirect auf unbekannte Pfade antwortet (z. B.
SPA-Fallback), also nie ein "richtiges" 404 liefert.

Pfade und Domains werden über frei wählbare **Tags** verknüpft: ein Tag wie
`dotfiles` kann mehrere Pfade (`/.env`, `/.envrc`, `/.git/config`, …)
gleichzeitig abdecken und auf beliebig viele Domains angewendet werden.

Einträge werden **manuell** im Plugin gepflegt, oder in Batches aus einem
[Zoraxy Guard](../../README.md) "Sperren"-Export importiert (History →
Handlungsbedarf-Zeilen markieren → Export → hier importieren). Es gibt keine
Netzwerkverbindung zwischen Zoraxy Guard und diesem Plugin — der Import ist
ein reiner Datei-Upload/Paste im Plugin-UI.

## Wie die Sperrung technisch funktioniert

1. Zoraxy leitet eingehenden Traffic nur dann an dieses Plugin weiter, wenn
   die betroffene HTTP-Proxy-Regel (Domain) einen Tag trägt, für den dieses
   Plugin in Zoraxy aktiviert ist ("Dynamic Capture"). Dieser eine, feste
   Zoraxy-Tag heisst **`zoraxy-guard-blocker`** (siehe Einrichtung unten) —
   er entscheidet nur, *ob* Traffic überhaupt beim Plugin ankommt.
2. Ob ein konkreter Pfad für eine konkrete Domain wirklich gesperrt wird,
   entscheidet **ausschliesslich die eigene Konfiguration dieses Plugins**
   (Reiter «Domains» + «Pfad-Regeln», jeweils mit den *eigenen* Tags des
   Plugins — unabhängig vom oben genannten festen Zoraxy-Tag). Das Plugin
   hat keinen Zugriff auf Zoraxy's eigene Tag-Zuordnung und ruft auch sonst
   keine Zoraxy-API auf.
3. Passt der angefragte Pfad zu einer aktiven Regel des Tags, den die Domain
   trägt, antwortet das Plugin sofort mit `403 Forbidden` — die Anfrage
   erreicht die dahinterliegende App nie.

## Einrichtung

Einmalig pro Domain, die geschützt werden soll:

1. **Zoraxy → HTTP Proxy Rules → <Domain> bearbeiten → Tags**: Tag
   `zoraxy-guard-blocker` hinzufügen.
2. **Zoraxy → Plugins → Zoraxy Guard Blocker**: für den Tag
   `zoraxy-guard-blocker` aktivieren (falls nicht ohnehin global aktiv).
3. **Im Plugin selbst** (Reiter «Domains»): dieselbe Domain eintragen und
   mit einem oder mehreren *eigenen* Tags versehen, z. B. `dotfiles`.
4. **Im Plugin** (Reiter «Pfad-Regeln»): Pfad-Regeln für diese Tags anlegen
   — manuell, oder gesammelt über «Import».

Danach führt jeder Treffer (Domain-Tag + Pfad-Regel) direkt zu `403`.

## Pfad-Matching

| Match-Typ  | Beispiel-Pfad | Verhalten |
| --- | --- | --- |
| `exact`    | `/.envrc` | nur exakt dieser Pfad |
| `prefix`   | `/.git`   | dieser Pfad **und** alle Unterpfade (`/.git/config`, `/.git/HEAD`, …) |
| `wildcard` | `/.git/*` | Go-`path.Match`-Glob (`*`, `?`, `[...]`) |

Der eingehende Pfad wird vor dem Vergleich URL-dekodiert und bereinigt
(`path.Clean`), inklusive `../`-Traversal, damit Umwege wie
`/public/../.env` nicht am Filter vorbeikommen. Query-Strings werden vor dem
Vergleich abgeschnitten. Domains werden case-insensitiv, ohne Port und ohne
abschliessenden Punkt verglichen.

## Import aus Zoraxy Guard

Erwartetes Export-Format (`format: "zoraxy-guard-blocker/import-v1"`):

```json
{
  "format": "zoraxy-guard-blocker/import-v1",
  "source": "zoraxy-guard",
  "entries": [
    {"domain": "files.gehring.li", "path": "/.envrc", "method": "GET", "status": 200, "note": "…", "ts": 1735000000}
  ]
}
```

Im Import-Assistenten wird pro Zeile (oder per Sammel-Auswahl für mehrere
Zeilen zugleich) ein Tag und ein Match-Typ zugewiesen; erst danach werden
Regel **und** Domain-Tag-Zuordnung gemeinsam angelegt. Bereits vorhandene
Tag-Zuweisungen einer Domain werden dabei ergänzt, nicht überschrieben.

## Fertige Binaries (kein Go/Docker nötig)

Jeder Push auf `main`, der diesen Plugin-Ordner verändert, baut automatisch
(GitHub Actions, [`.github/workflows/plugin-release.yml`](../../.github/workflows/plugin-release.yml))
Binaries für Linux (amd64/arm64), Windows (amd64) und macOS (arm64) und
veröffentlicht sie als rollende Release
[**`zoraxy-guard-blocker-latest`**](https://github.com/PaulG67/zoraxy-guard/releases/tag/zoraxy-guard-blocker-latest) —
bei jeder Änderung überschrieben, immer der aktuelle `main`-Stand. Direktlinks
(Unraid x86 i. d. R. `linux_amd64`):

```text
https://github.com/PaulG67/zoraxy-guard/releases/download/zoraxy-guard-blocker-latest/zoraxy-guard-blocker_linux_amd64
https://github.com/PaulG67/zoraxy-guard/releases/download/zoraxy-guard-blocker-latest/zoraxy-guard-blocker_linux_arm64
https://github.com/PaulG67/zoraxy-guard/releases/download/zoraxy-guard-blocker-latest/zoraxy-guard-blocker_windows_amd64.exe
https://github.com/PaulG67/zoraxy-guard/releases/download/zoraxy-guard-blocker-latest/zoraxy-guard-blocker_darwin_arm64
```

Jede Datei hat eine begleitende `.sha256`-Prüfsumme; `SHA256SUMS` enthält alle
zusammen. Nach dem Herunterladen (z. B. per `wget`/`curl` direkt auf dem
Unraid-Server) Datei in den Plugin-Unterordner legen und ausführbar machen:

```sh
chmod +x zoraxy-guard-blocker_linux_amd64
```

## Selbst bauen

```sh
go build -trimpath -ldflags="-s -w" -o zoraxy-guard-blocker .
```

Oder per Docker (Cross-Build, siehe [`Dockerfile`](Dockerfile)):

```sh
docker build --platform linux/amd64 -t zgb-build .
docker create --name zgb-extract zgb-build
docker cp zgb-extract:/out/zoraxy-guard-blocker ./zoraxy-guard-blocker
docker rm zgb-extract
```

## Installieren

Zoraxy startet Plugins als eigene Prozesse aus seinem Plugin-Verzeichnis
(Flag `-plugin`, Default `./plugins`). Eigenes Unterverzeichnis anlegen und
die gebaute Binary dort ablegen, z. B.:

```text
<zoraxy>/plugins/zoraxy-guard-blocker/zoraxy-guard-blocker
```

Danach in Zoraxy unter **Plugins** neu einlesen lassen und aktivieren.

## Datenspeicherung

Alle Tags, Domain-Zuweisungen und Pfad-Regeln liegen in einer einzigen
JSON-Datei (Default `./data/zoraxy-guard-blocker.json` relativ zum
Arbeitsverzeichnis der Plugin-Binary; Pfad über die Umgebungsvariable
`ZGB_DATA_FILE` überschreibbar). Schreibzugriffe erfolgen atomar
(`os.Rename` nach vollständigem Schreiben einer temporären Datei). Für
persistente Daten über Container-Neustarts hinweg diesen Pfad auf ein
gemountetes Volume legen.

## Sicherheitshinweise

- Der HTTP-Server bindet ausschliesslich an `127.0.0.1` (Vorgabe durch
  Zoraxy über `ConfigureSpec.Port`).
- Es werden keine Zoraxy-Management-API-Endpunkte aufgerufen und kein
  `api_key` benötigt (`permitted_api_endpoints` bleibt leer).
- Fällt eine Domain nicht in die eigene Domain-Tag-Zuordnung, wird **nichts**
  blockiert ("fail open") — eine vergessene Zuordnung sperrt also nichts
  Unbeabsichtigtes, sie schützt schlicht (noch) nichts.
- Der Import verarbeitet nur JSON aus Datei-Upload/Textfeld, es gibt keinen
  Netzwerkaufruf zu Zoraxy Guard oder einem anderen Dienst.
