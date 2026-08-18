"""Live and local checks that CrowdSec (LAPI + bouncer) actually works."""
from __future__ import annotations

from pathlib import Path
from typing import Any, Callable, Dict, List, Optional
from urllib.parse import urljoin, urlparse

import requests
import yaml

from . import csconfig

Check = Dict[str, Any]


def _ok(id_: str, title: str, detail: str) -> Check:
    return {"id": id_, "title": title, "status": "ok", "detail": detail}


def _warn(id_: str, title: str, detail: str) -> Check:
    return {"id": id_, "title": title, "status": "warn", "detail": detail}


def _fail(id_: str, title: str, detail: str) -> Check:
    return {"id": id_, "title": title, "status": "fail", "detail": detail}


def _load_bouncer(cfg: Optional[dict]) -> dict:
    path = Path(csconfig.bouncer_config(cfg))
    if not path.is_file():
        return {}
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        return data if isinstance(data, dict) else {}
    except (OSError, yaml.YAMLError):
        return {}


def normalize_lapi_url(raw: str) -> str:
    url = (raw or "").strip()
    if not url:
        return ""
    if "://" not in url:
        url = "http://" + url
    return url.rstrip("/")


def lapi_url_from_cfg(cfg: Optional[dict], override: str = "") -> str:
    over = normalize_lapi_url(override)
    if over:
        return over
    cs = csconfig.crowdsec_section(cfg)
    stored = normalize_lapi_url(str(cs.get("lapi_url") or ""))
    if stored:
        return stored
    bouncer = _load_bouncer(cfg)
    return normalize_lapi_url(str(bouncer.get("agent_url") or ""))


def _http_get(
    url: str,
    *,
    headers: Optional[dict] = None,
    timeout: float = 4.0,
) -> tuple[int, str]:
    try:
        resp = requests.get(
            url,
            headers=headers or {},
            timeout=timeout,
            allow_redirects=False,
        )
        body = (resp.text or "")[:240].replace("\n", " ").strip()
        return resp.status_code, body
    except requests.RequestException as exc:
        return 0, str(exc)


def _verdict(rows: List[Check]) -> str:
    by_id = {r["id"]: r["status"] for r in rows}
    bouncer = by_id.get("lapi_bouncer")
    health = by_id.get("lapi_health")
    if bouncer == "fail" or (health == "fail" and bouncer != "ok"):
        return "fail"
    if bouncer == "ok":
        return "ok"
    if any(r["status"] == "fail" for r in rows):
        return "warn"
    if any(r["status"] == "warn" for r in rows):
        return "warn"
    return "ok"


HttpGet = Callable[..., tuple[int, str]]


def run_check(
    cfg: Optional[dict],
    *,
    plugin_seen: bool = False,
    plugin_lines: int = 0,
    plugin_blocks: int = 0,
    history_blocks: int = 0,
    lapi_url: str = "",
    http_get: Optional[HttpGet] = None,
) -> dict:
    rows: List[Check] = []
    getter = http_get or _http_get
    cdir = Path(csconfig.config_dir(cfg))
    bpath = Path(csconfig.bouncer_config(cfg))
    bouncer = _load_bouncer(cfg)

    if cdir.is_dir():
        rows.append(_ok("mount_config", "CrowdSec-Config", f"Ordner erreichbar: {cdir}"))
    else:
        rows.append(
            _fail(
                "mount_config",
                "CrowdSec-Config",
                f"Nicht gemountet: {cdir}. Unraid-Pfad «CrowdSec Config» setzen, dann Edit → Apply.",
            )
        )

    engine = cdir / "config.yaml"
    if engine.is_file():
        rows.append(_ok("engine", "Engine config.yaml", str(engine)))
    else:
        rows.append(_warn("engine", "Engine config.yaml", f"Datei fehlt: {engine}"))

    cols = csconfig.list_collections(cfg)
    if cols:
        rows.append(_ok("collections", "Collections", f"{len(cols)} installiert"))
    else:
        rows.append(
            _warn(
                "collections",
                "Collections",
                "Keine collections/*.yaml — unter YAML / Listen einbinden oder cscli collections install.",
            )
        )

    if bpath.is_file():
        rows.append(_ok("mount_bouncer", "Bouncer-YAML", str(bpath)))
    else:
        rows.append(
            _fail(
                "mount_bouncer",
                "Bouncer-YAML",
                f"Nicht gefunden: {bpath}. Plugin-Ordner mounten.",
            )
        )

    key = str(bouncer.get("api_key") or "").strip()
    if key:
        rows.append(_ok("bouncer_key", "Bouncer API-Key", "gesetzt"))
    else:
        rows.append(
            _fail(
                "bouncer_key",
                "Bouncer API-Key",
                "Leer. In YAML / Listen setzen oder cscli bouncers add zoraxy-bouncer.",
            )
        )

    agent = str(bouncer.get("agent_url") or "").strip()
    if agent:
        rows.append(_ok("bouncer_url", "Bouncer agent_url", agent))
    else:
        rows.append(_fail("bouncer_url", "Bouncer agent_url", "Fehlt in der Plugin-config.yaml."))

    level = str(bouncer.get("log_level") or "").strip().lower()
    if level in ("info", "debug", "trace"):
        rows.append(_ok("log_level", "Bouncer Log-Level", level))
    elif level:
        rows.append(
            _warn(
                "log_level",
                "Bouncer Log-Level",
                f"{level} — «Request blocked» fehlt dann oft. Auf info stellen.",
            )
        )
    else:
        rows.append(_warn("log_level", "Bouncer Log-Level", "nicht gesetzt (Default oft warning)."))

    if plugin_seen:
        rows.append(
            _ok(
                "plugin_logs",
                "Zoraxy-Plugin in den Logs",
                f"{plugin_lines} Plugin-Zeilen, {plugin_blocks} Blöcke in dieser Session.",
            )
        )
    else:
        rows.append(
            _warn(
                "plugin_logs",
                "Zoraxy-Plugin in den Logs",
                "Noch keine CrowdSec-Plugin-Zeilen. History → Reset & laden, Log-Level info.",
            )
        )

    if history_blocks:
        rows.append(
            _ok(
                "history",
                "Blöcke in der Auswertung",
                f"{history_blocks} im aktuellen Memory-Ring.",
            )
        )
    else:
        rows.append(
            _warn(
                "history",
                "Blöcke in der Auswertung",
                "Keine 403-Blöcke im Ring — kann still sein, wenn gerade niemand scannt.",
            )
        )

    base = lapi_url_from_cfg(cfg, lapi_url)
    if not base:
        rows.append(
            _fail(
                "lapi_health",
                "LAPI erreichbar",
                "Keine URL. agent_url in der Bouncer-YAML oder unten eine LAPI-URL angeben.",
            )
        )
        rows.append(
            _fail(
                "lapi_bouncer",
                "Bouncer-API (Key)",
                "Ohne LAPI-URL nicht prüfbar.",
            )
        )
    else:
        host = urlparse(base).hostname or ""
        code, body = getter(urljoin(base + "/", "health"))
        if code == 200 and ("up" in body.lower() or body.startswith("{") or not body):
            rows.append(_ok("lapi_health", "LAPI /health", f"{base}/health → HTTP {code}"))
        elif code:
            rows.append(
                _warn(
                    "lapi_health",
                    "LAPI /health",
                    f"HTTP {code} von {base}/health ({body or 'kein Body'}). Ältere CrowdSec-Versionen haben /health nicht.",
                )
            )
        else:
            hint = (
                f"Guard erreicht {base} nicht ({body}). "
                "Im gleichen Docker-Netz wie CrowdSec, oder Host-IP:8080 (LAPI nach außen)."
            )
            if host in ("crowdsec", "localhost", "127.0.0.1"):
                hint += " «crowdsec» löst nur auf, wenn Guard in dem Netz ist — oft http://UNRAID-IP:8080 nutzen."
            rows.append(_fail("lapi_health", "LAPI /health", hint))

        if key:
            dec_url = urljoin(base + "/", "v1/decisions")
            code, body = getter(
                dec_url + "?ip=127.0.0.1",
                headers={"X-Api-Key": key, "Accept": "application/json"},
            )
            if code == 200:
                rows.append(
                    _ok(
                        "lapi_bouncer",
                        "Bouncer-API (Key)",
                        "GET /v1/decisions?ip=127.0.0.1 → HTTP 200. Key wird akzeptiert.",
                    )
                )
            elif code in (401, 403):
                rows.append(
                    _fail(
                        "lapi_bouncer",
                        "Bouncer-API (Key)",
                        f"HTTP {code} — Key ungültig oder Bouncer nicht registriert. cscli bouncers add …",
                    )
                )
            elif code:
                rows.append(
                    _fail(
                        "lapi_bouncer",
                        "Bouncer-API (Key)",
                        f"HTTP {code} ({body or 'kein Body'}).",
                    )
                )
            else:
                rows.append(_fail("lapi_bouncer", "Bouncer-API (Key)", f"Keine Verbindung: {body}"))
        else:
            rows.append(_fail("lapi_bouncer", "Bouncer-API (Key)", "Kein API-Key — Request übersprungen."))

    verdict = _verdict(rows)
    if verdict == "ok":
        summary = "CrowdSec antwortet: LAPI erreichbar, Bouncer-Key gültig."
        if plugin_seen:
            summary += " Das Zoraxy-Plugin schreibt Logs."
        else:
            summary += " Plugin-Logs fehlen noch — Zoraxy neu starten oder History nachladen."
    elif verdict == "warn":
        summary = "Teilweise ok. Gelbe Punkte prüfen — oft Log-Level, Mount oder noch keine Blöcke."
    else:
        summary = "CrowdSec aus Guard nicht bestätigt. Rote Punkte: URL, Netz oder API-Key."

    return {
        "lapi_url": base,
        "verdict": verdict,
        "summary": summary,
        "rows": rows,
    }
