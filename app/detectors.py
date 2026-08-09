from __future__ import annotations

import re
import time
from collections import defaultdict, deque
from dataclasses import dataclass
from typing import Deque, Dict, List, Optional, Tuple

from .feeds import ThreatLists, find_list_match
from .iputil import IpAddress, IpNetwork, ip_in_networks, parse_ip
from .parser import LogEvent
from .risk import assess_access

SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


@dataclass
class Alert:
    severity: str
    title: str
    body: str
    fingerprint: str
    event: Optional[LogEvent] = None


class Detector:
    def __init__(self, cfg: dict, threats: Optional[ThreatLists] = None):
        self.cfg = cfg
        self.threats = threats
        self.allow = cfg.get("_allow_nets") or []
        self.block = list(cfg.get("_block_nets") or [])
        if threats:
            self.block.extend(threats.block_nets)
        self.sensitive = {h.lower().rstrip(".") for h in cfg.get("sensitive_hosts", [])}
        paths = list(cfg.get("exploit_paths", []))
        if threats:
            paths.extend(threats.extra_paths)
        self.exploit_rules = self._compile_paths(paths)
        self.exploit_ignore = [p.lower() for p in cfg.get("exploit_path_ignore", [])]
        self.bad_ua = [u.lower() for u in cfg.get("bad_user_agents", [])]
        if threats:
            self.bad_ua.extend(u.lower() for u in threats.extra_user_agents)
        th = cfg.get("thresholds", {})
        self.exploit_hits = int(th.get("exploit_hits_for_alert", 3))
        self.exploit_window = int(th.get("exploit_window_seconds", 120))
        self.block_hits = int(th.get("block_hits_for_alert", 30))
        self.block_window = int(th.get("block_window_seconds", 300))
        self.auth_fails = int(th.get("auth_fail_for_alert", 15))
        self.auth_window = int(th.get("auth_fail_window_seconds", 300))
        self.alert_sensitive_success = bool(cfg.get("alert_sensitive_success", True))

        self._exploit_times: Dict[str, Deque[float]] = defaultdict(deque)
        self._block_times: Dict[str, Deque[float]] = defaultdict(deque)
        self._auth_times: Dict[str, Deque[float]] = defaultdict(deque)

    @staticmethod
    def _compile_paths(paths: List[str]) -> List[Tuple[str, object]]:
        compiled = []
        for p in paths:
            p = str(p)
            if p.startswith("re:"):
                compiled.append(("re", re.compile(p[3:])))
            else:
                compiled.append(("sub", p.lower()))
        return compiled

    def _path_is_exploit(self, path: str) -> bool:
        low = path.lower()
        for ign in self.exploit_ignore:
            if ign and ign in low:
                return False
        for kind, rule in self.exploit_rules:
            if kind == "sub" and rule in low:
                return True
            if kind == "re" and rule.search(path):
                return True
        return False

    def _client_ip(self, event: LogEvent) -> Optional[IpAddress]:
        return parse_ip(event.client)

    def _is_allowed(self, ip: IpAddress) -> bool:
        return ip_in_networks(ip, self.allow)

    def _is_blocklisted(self, ip: IpAddress) -> bool:
        return ip_in_networks(ip, self.block)

    def _prune(self, q: Deque[float], window: int, now: float) -> int:
        while q and now - q[0] > window:
            q.popleft()
        return len(q)

    def process(self, event: LogEvent) -> List[Alert]:
        if event.kind != "request":
            return []
        ip = self._client_ip(event)
        if not ip:
            return []
        if self._is_allowed(ip):
            return []

        alerts: List[Alert] = []
        now = time.time()
        client = str(ip)
        origin = event.origin.lower().rstrip(".")
        path = event.path
        router = event.router.lower()
        status = event.status
        ua = event.user_agent.lower()

        # 1) Explicit blocklist / threat-list hit
        if self._is_blocklisted(ip):
            source = None
            if self.threats:
                source = find_list_match(client, self.threats)
            src_txt = f" (Liste: {source})" if source else ""
            alerts.append(
                Alert(
                    severity="high",
                    title="Bekannte schlechte IP",
                    body=(
                        f"Blocklist-IP {client}{src_txt} → {origin or '-'} "
                        f"{event.method} {path} ({status}) [{router}]"
                    ),
                    fingerprint=f"blocklist:{client}",
                    event=event,
                )
            )

        # 2) Bad user-agent
        for fragment in self.bad_ua:
            if fragment and fragment in ua:
                alerts.append(
                    Alert(
                        severity="medium",
                        title="Verdächtiger User-Agent",
                        body=f"{client} UA enthält «{fragment}»: {event.method} {path} on {origin or '-'} ({status})",
                        fingerprint=f"badua:{client}:{fragment}",
                        event=event,
                    )
                )
                break

        # 3) Exploit path probes — risk-aware (3xx SPA redirect ≠ leak)
        if self._path_is_exploit(path):
            q = self._exploit_times[client]
            q.append(now)
            n = self._prune(q, self.exploit_window, now)
            verdict = assess_access(
                path=path,
                status=status,
                method=event.method,
                router=router,
                user_agent=event.user_agent,
                origin=origin,
                extra_exploit_paths=[
                    r[1] if r[0] == "sub" else "" for r in self.exploit_rules
                ],
            )
            if verdict.level == "action" and 200 <= status < 300:
                alerts.append(
                    Alert(
                        severity="critical",
                        title="Exploit-Pfad mit Erfolg (HTTP 2xx) — prüfen",
                        body=(
                            f"{client} holte {path} von {origin or '-'} mit Status {status}. "
                            f"{verdict.detail}"
                        ),
                        fingerprint=f"exploit-ok:{client}:{path}",
                        event=event,
                    )
                )
            elif status in (301, 302, 303, 307, 308):
                # Soft: redirect to login/SPA — do not escalate as critical leak
                if n >= self.exploit_hits:
                    alerts.append(
                        Alert(
                            severity="low",
                            title="Exploit-Scan (Redirect, unbedenklich)",
                            body=(
                                f"{client}: {n} Probe-Pfade in {self.exploit_window}s, "
                                f"zuletzt {path} → {status} @ {origin or '-'} "
                                f"(typisch SPA/Login-Redirect, z. B. Navidrome). "
                                f"{verdict.title}"
                            ),
                            fingerprint=f"exploit-scan-redirect:{client}",
                            event=event,
                        )
                    )
            elif n >= self.exploit_hits:
                alerts.append(
                    Alert(
                        severity="high",
                        title="Exploit-Scan erkannt",
                        body=(
                            f"{client} hat {n} Exploit-Pfade in {self.exploit_window}s "
                            f"(zuletzt {event.method} {path} → {status} @ {origin or '-'})"
                        ),
                        fingerprint=f"exploit-scan:{client}",
                        event=event,
                    )
                )
            elif status >= 400 or router in ("blacklist", "whitelist"):
                alerts.append(
                    Alert(
                        severity="low",
                        title="Exploit-Probe (abgewiesen)",
                        body=f"{client} {event.method} {path} → {status} ({router}, {origin or '-'})",
                        fingerprint=f"exploit-probe:{client}:{path}",
                        event=event,
                    )
                )
            else:
                alerts.append(
                    Alert(
                        severity="low",
                        title="Exploit-Probe",
                        body=f"{client} {event.method} {path} → {status} ({router}, {origin or '-'}) — {verdict.title}",
                        fingerprint=f"exploit-probe:{client}:{path}",
                        event=event,
                    )
                )

        # 4) High volume blocks (geo/blacklist)
        if router in ("blacklist", "whitelist") or status == 403:
            q = self._block_times[client]
            q.append(now)
            n = self._prune(q, self.block_window, now)
            if n >= self.block_hits:
                alerts.append(
                    Alert(
                        severity="medium",
                        title="Hohe Block-Rate",
                        body=f"{client}: {n} Blocks/403 in {self.block_window}s (zuletzt {path} @ {origin or '-'})",
                        fingerprint=f"block-rate:{client}",
                        event=event,
                    )
                )

        # 5) Auth fail spikes on sensitive hosts
        if origin in self.sensitive and status in (401, 403):
            key = f"{client}:{origin}"
            q = self._auth_times[key]
            q.append(now)
            n = self._prune(q, self.auth_window, now)
            if n >= self.auth_fails:
                alerts.append(
                    Alert(
                        severity="high",
                        title="Mögliche Brute-Force",
                        body=f"{client} → {origin}: {n}× {status} in {self.auth_window}s (zuletzt {path})",
                        fingerprint=f"authfail:{key}",
                        event=event,
                    )
                )

        # 6) Successful hit on sensitive host from non-allowlisted IP
        if self.alert_sensitive_success and origin in self.sensitive and 200 <= status < 400:
            # Skip pure static/favicon noise lightly
            if not any(path.endswith(x) for x in (".css", ".js", ".png", ".ico", ".map", ".woff2")):
                alerts.append(
                    Alert(
                        severity="high",
                        title="Erfolgreicher Zugriff auf sensible Hosts",
                        body=(
                            f"{client} erreichte {origin}{path} mit {status}. "
                            f"Wenn unerwartet: Session/Credentials prüfen."
                        ),
                        fingerprint=f"sensitive-ok:{client}:{origin}",
                        event=event,
                    )
                )

        # Deduplicate same severity fingerprints in one event pass keeping highest severity
        by_fp: Dict[str, Alert] = {}
        for a in alerts:
            prev = by_fp.get(a.fingerprint)
            if not prev or SEVERITY_RANK.get(a.severity, 0) > SEVERITY_RANK.get(prev.severity, 0):
                by_fp[a.fingerprint] = a
        return list(by_fp.values())


def severity_at_least(level: str, minimum: str) -> bool:
    return SEVERITY_RANK.get(level, 0) >= SEVERITY_RANK.get(minimum, 0)