"""Assess access risk: scanner noise vs action needed (no HTTP body fetch)."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Iterable, List, Optional

# Known mass-scan webshell / probe filenames (path contains)
PROBE_FRAGMENTS = (
    ".git/",
    ".git",
    ".env",
    ".aws",
    "wp-admin",
    "wp-login",
    "wp-content",
    "xmlrpc.php",
    "wps.php",
    "ioxi-o.php",
    "ioxi.php",
    "shell.php",
    "c99.php",
    "r57.php",
    "b374k",
    "webshell",
    "phpunit",
    "eval-stdin",
    "actuator",
    "cgi-bin",
    "vendor/phpunit",
    "phpmyadmin",
    "adminer",
    "filemanager",
    "alfa.php",
    "about.php",
    "radio.php",
    "classwithtostring",
    "setup.php",
    "install.php",
    "debug/default",
    "server-status",
    "server-info",
    "manager/html",
    "solr/",
    "console/",
    "owa/",
    "autodiscover",
    "HNAP1",
    "sdk",
    "passwd",
    "id_rsa",
    "../",
)

# Hard evidence targets (if 200 → really check)
HARD_LEAK_FRAGMENTS = (
    "/.git/config",
    "/.git/HEAD",
    "/.git/index",
    "/.env",
    "/.aws/credentials",
    "id_rsa",
    "wp-config.php",
)

# Typical SPA / app roots that return soft responses for any path
BENIGN_APP_PATH_RE = re.compile(
    r"^/(app|login|api|static|assets|assets/|favicon|sw\.js|manifest|robots\.txt|health|status)(/|$)",
    re.I,
)

REDIRECT_STATUSES = frozenset({301, 302, 303, 307, 308})
SUCCESS_CONTENT = frozenset(range(200, 300))
CLIENT_ERR = frozenset(range(400, 500))
SERVER_ERR = frozenset(range(500, 600))


@dataclass(frozen=True)
class RiskVerdict:
    level: str  # safe | noise | watch | action
    score: int  # 0–100
    title: str
    detail: str
    action_needed: bool
    tags: tuple[str, ...]

    def as_dict(self) -> dict[str, Any]:
        return {
            "level": self.level,
            "score": self.score,
            "title": self.title,
            "detail": self.detail,
            "action_needed": self.action_needed,
            "tags": list(self.tags),
        }


def _path_matches(path: str, fragments: Iterable[str]) -> Optional[str]:
    low = (path or "").lower()
    for f in fragments:
        if f.lower() in low:
            return f
    return None


def assess_access(
    *,
    path: str = "",
    status: int = 0,
    method: str = "GET",
    router: str = "",
    user_agent: str = "",
    origin: str = "",
    threat_list: Optional[str] = None,
    extra_exploit_paths: Optional[List[str]] = None,
) -> RiskVerdict:
    """
    Classify a single proxy access without inspecting response body.

    Heuristic (intentionally conservative on redirects):
    - Probe path + 403/404/blocked → noise (safe, no action)
    - Probe path + 3xx redirect → noise (SPA/login redirect, e.g. Navidrome)
    - Probe path + 200 → action unless looks like pure app route
    - Hard leak path + 200 → action urgently
    - Normal app traffic → safe
    """
    path = path or "/"
    status = int(status or 0)
    router_l = (router or "").lower()
    ua = (user_agent or "").strip()
    tags: List[str] = []

    if threat_list:
        tags.append("threat-list")
    if not ua:
        tags.append("empty-ua")

    blocked_router = any(
        x in router_l for x in ("blacklist", "block", "geoip", "access")
    )
    probe = _path_matches(path, PROBE_FRAGMENTS)
    hard = _path_matches(path, HARD_LEAK_FRAGMENTS)

    if extra_exploit_paths:
        low = path.lower()
        for p in extra_exploit_paths:
            p = str(p).lower()
            if p and p in low and not probe:
                probe = p
                tags.append("config-path")

    # Explicitly blocked by proxy
    if blocked_router or status in (401, 403, 429, 451):
        if probe or hard:
            return RiskVerdict(
                level="noise",
                score=5,
                title="Scanner abgewiesen",
                detail=(
                    f"Verdächtiger Pfad «{path}» mit HTTP {status}"
                    + (f" ({router})" if router else "")
                    + " — Proxy/Blacklist hat geblockt. Keine Aktion nötig."
                ),
                action_needed=False,
                tags=tuple(tags + ["blocked", "probe"] if probe or hard else tags + ["blocked"]),
            )
        return RiskVerdict(
            level="safe",
            score=5,
            title="Zugriff geblockt",
            detail=f"HTTP {status} / {router or 'filter'} — abgewiesen.",
            action_needed=False,
            tags=tuple(tags + ["blocked"]),
        )

    # Soft fail: not found
    if status == 404:
        if probe or hard:
            return RiskVerdict(
                level="noise",
                score=8,
                title="Scanner-Lärm (404)",
                detail=f"Pfad «{path}» existiert nicht (404). Typischer Massen-Scan, unbedenklich.",
                action_needed=False,
                tags=tuple(tags + ["probe", "404"]),
            )
        return RiskVerdict(
            level="safe",
            score=5,
            title="Nicht gefunden",
            detail="HTTP 404.",
            action_needed=False,
            tags=tuple(tags + ["404"]),
        )

    # Redirects (incl. Navidrome → login): not a content leak
    if status in REDIRECT_STATUSES:
        if probe or hard:
            return RiskVerdict(
                level="noise",
                score=10,
                title="Scan mit Redirect (unbedenklich)",
                detail=(
                    f"Scanner-Pfad «{path}» → HTTP {status}. "
                    "Viele Apps (z. B. Navidrome, SPAs) leiten unbekannte URLs auf die Login-/Startseite um. "
                    "Es wurde kein Dateiinhalt wie .env/.git ausgeliefert — kein Handlungsbedarf, "
                    "sofern der Redirect wirklich nur zur App-UI geht."
                ),
                action_needed=False,
                tags=tuple(tags + ["probe", "redirect", "spa-like"]),
            )
        return RiskVerdict(
            level="safe",
            score=10,
            title="HTTP-Redirect",
            detail=f"HTTP {status} für «{path}».",
            action_needed=False,
            tags=tuple(tags + ["redirect"]),
        )

    # Hard leak evidence with 200
    if hard and status in SUCCESS_CONTENT:
        return RiskVerdict(
            level="action",
            score=95,
            title="Mögliches Datenleck — prüfen!",
            detail=(
                f"Kritischer Pfad «{path}» mit HTTP {status}. "
                "Sofort im Browser prüfen: echter Dateiinhalt ([core], ref:, Passwörter) "
                "oder nur HTML einer SPA? Bei Dateiinhalt: Lücke schließen und Secrets rotieren."
            ),
            action_needed=True,
            tags=tuple(tags + ["hard-leak", "http-2xx"]),
        )

    # Probe path with real 200 body potential
    if probe and status in SUCCESS_CONTENT:
        # /app/ alone is not a webshell probe outcome for Navidrome-like apps
        if BENIGN_APP_PATH_RE.match(path.split("?")[0] or "/"):
            return RiskVerdict(
                level="safe",
                score=15,
                title="Normale App-Route",
                detail=f"«{path}» mit HTTP {status} — typische App-URL, kein Webshell-Muster.",
                action_needed=False,
                tags=tuple(tags + ["app-route"]),
            )
        return RiskVerdict(
            level="action",
            score=78,
            title="Verdächtiger Pfad mit HTTP 200",
            detail=(
                f"Scan-Pfad «{path}» antwortete mit {status}. "
                "Inhalt prüfen: PHP/Git/Env-Text = Handlungsbedarf; HTML-App-Shell = oft SPA-False-Positive. "
                "Im Zweifel View-Source: `<` = UI, `[core]`/`<?php` = Leck."
            ),
            action_needed=True,
            tags=tuple(tags + ["probe", "http-2xx", "verify-body"]),
        )

    # Probe with 5xx
    if (probe or hard) and status in SERVER_ERR:
        return RiskVerdict(
            level="watch",
            score=40,
            title="Probe verursachte Serverfehler",
            detail=f"«{path}» → HTTP {status}. Kein Leck, aber ggf. Origin-Log prüfen.",
            action_needed=False,
            tags=tuple(tags + ["probe", "5xx"]),
        )

    if (probe or hard) and status in CLIENT_ERR:
        return RiskVerdict(
            level="noise",
            score=12,
            title="Scanner abgewiesen (4xx)",
            detail=f"«{path}» → HTTP {status}. Unbedenklich.",
            action_needed=False,
            tags=tuple(tags + ["probe", "4xx"]),
        )

    # Empty UA + non-probe but odd
    if not ua and status in SUCCESS_CONTENT and method.upper() in ("GET", "POST", "HEAD"):
        if BENIGN_APP_PATH_RE.match(path.split("?")[0] or "/"):
            return RiskVerdict(
                level="safe",
                score=12,
                title="App-Zugriff ohne User-Agent",
                detail="Leerer UA, aber plausibler App-Pfad.",
                action_needed=False,
                tags=tuple(tags + ["app-route"]),
            )

    # Normal traffic
    if status in SUCCESS_CONTENT:
        return RiskVerdict(
            level="safe",
            score=8,
            title="Normaler Zugriff",
            detail=f"{method} {path} → {status}" + (f" @ {origin}" if origin else ""),
            action_needed=False,
            tags=tuple(tags + ["normal"]),
        )

    if status in CLIENT_ERR or status in SERVER_ERR:
        return RiskVerdict(
            level="safe",
            score=10,
            title="Fehler-Antwort",
            detail=f"HTTP {status} für «{path}» — kein Exploit-Erfolg.",
            action_needed=False,
            tags=tuple(tags + ["error-status"]),
        )

    return RiskVerdict(
        level="watch",
        score=25,
        title="Unklarer Zugriff",
        detail=f"{method} {path} → {status}. Bei Auffälligkeit History prüfen.",
        action_needed=False,
        tags=tuple(tags or ("unknown",)),
    )
