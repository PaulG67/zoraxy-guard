"""In-memory access history ring (max 24h, bounded size). No disk persistence."""

from __future__ import annotations

import time
from collections import defaultdict, deque
from dataclasses import dataclass
from threading import Lock
from typing import Any, Deque, DefaultDict, Optional, TYPE_CHECKING

from .feeds import find_list_match
from .iputil import parse_ip
from .risk import assess_access

if TYPE_CHECKING:
    from .feeds import ThreatLists
    from .geoip import GeoCache
    from .parser import LogEvent

MAX_WINDOW_SEC = 24 * 3600
DEFAULT_MAX_EVENTS = 15000
PATH_MAX = 100
UA_MAX = 72

WINDOWS = {
    "1h": 3600,
    "6h": 6 * 3600,
    "12h": 12 * 3600,
    "24h": MAX_WINDOW_SEC,
}

BLOCKED_ROUTERS = frozenset(
    {
        "blacklist",
        "ipblacklist",
        "geoip",
        "geoblacklist",
        "access",
        "block",
    }
)


@dataclass(slots=True, frozen=True)
class AccessEvent:
    ts: float
    client: str
    origin: str
    method: str
    path: str
    status: int
    router: str
    ua: str


def is_blocked(event: AccessEvent) -> bool:
    router = (event.router or "").lower().replace(" ", "")
    if event.status in (401, 403, 429, 451):
        return True
    if router in BLOCKED_ROUTERS:
        return True
    if "blacklist" in router or "block" in router:
        return True
    return False


def is_success(event: AccessEvent) -> bool:
    """HTTP 2xx/3xx — Antwort „erfolgreich“ (u. a. 200)."""
    return 200 <= int(event.status or 0) < 400


def is_failed(event: AccessEvent) -> bool:
    """Nicht erfolgreich: 1xx, 4xx, 5xx, 0."""
    return not is_success(event)


def block_reasons(event: AccessEvent, threat_list: Optional[str] = None) -> list[str]:
    reasons: list[str] = []
    router = (event.router or "").lower()
    if "blacklist" in router or router in ("ipblacklist", "geoip", "geoblacklist"):
        reasons.append(f"Router: {event.router or router}")
    if event.status == 403:
        reasons.append("HTTP 403")
    elif event.status == 401:
        reasons.append("HTTP 401 (Auth)")
    elif event.status == 429:
        reasons.append("HTTP 429 (Rate-Limit)")
    elif event.status == 451:
        reasons.append("HTTP 451")
    elif event.status >= 400 and not reasons:
        reasons.append(f"HTTP {event.status}")
    if threat_list:
        reasons.append(f"Threat-Liste: {threat_list}")
    return reasons or ["geblockt"]


class AccessHistory:
    """Bounded ring of access events for the Web UI (RAM only)."""

    def __init__(self, max_events: int = DEFAULT_MAX_EVENTS) -> None:
        self.max_events = max(1000, int(max_events))
        self._events: Deque[AccessEvent] = deque(maxlen=self.max_events)
        self._lock = Lock()
        self.dropped_old = 0
        self.recorded = 0
        # Memory session (shared by Status + History UI)
        now = time.time()
        self.session_generation = 1
        self.session_started_at = now
        self.session_recorded = 0
        self.fill_mode = "live"  # live | backfill | backfill+live

    def set_max_events(self, max_events: int) -> None:
        max_events = max(1000, int(max_events))
        if max_events == self.max_events:
            return
        with self._lock:
            items = list(self._events)[-max_events:]
            self.max_events = max_events
            self._events = deque(items, maxlen=max_events)

    def record(self, event: "LogEvent") -> None:
        if getattr(event, "kind", None) != "request":
            return
        path = (event.path or "")[:PATH_MAX] or "/"
        ua = (event.user_agent or "")[:UA_MAX]
        ts = time.time()
        if event.timestamp is not None:
            try:
                ts = event.timestamp.timestamp()
            except (OSError, OverflowError, ValueError):
                pass
        ev = AccessEvent(
            ts=ts,
            client=(event.client or "?").strip() or "?",
            origin=(event.origin or "-").strip() or "-",
            method=(event.method or "-")[:16],
            path=path,
            status=int(event.status or 0),
            router=(event.router or "")[:48],
            ua=ua,
        )
        with self._lock:
            self._events.append(ev)
            self.recorded += 1
            self.session_recorded += 1
            if self.fill_mode == "backfill":
                # Further records after backfill session mark mixed feed
                pass
            if self.recorded % 200 == 0:
                self._prune_locked(time.time() - MAX_WINDOW_SEC)

    def mark_live_ingress(self) -> None:
        """Call when live tail records (not disk backfill)."""
        with self._lock:
            if self.fill_mode == "backfill":
                self.fill_mode = "backfill+live"
            elif self.fill_mode not in ("backfill+live", "live"):
                self.fill_mode = "live"

    def buffer_info(self) -> dict[str, Any]:
        with self._lock:
            oldest = self._events[0].ts if self._events else 0.0
            newest = self._events[-1].ts if self._events else 0.0
            return {
                "size": len(self._events),
                "max": self.max_events,
                "recorded_total": self.recorded,
                "session_recorded": self.session_recorded,
                "pruned_old": self.dropped_old,
                "retention_hours": 24,
                "oldest_ts": oldest,
                "newest_ts": newest,
                "session_started_at": self.session_started_at,
                "session_generation": self.session_generation,
                "fill_mode": self.fill_mode,
            }

    def clear(self, fill_mode: str = "live") -> None:
        """Drop all in-memory access events; start a new memory session."""
        with self._lock:
            self._events.clear()
            self.session_generation += 1
            self.session_started_at = time.time()
            self.session_recorded = 0
            self.fill_mode = fill_mode if fill_mode in ("live", "backfill") else "live"

    def _prune_locked(self, cutoff: float) -> None:
        while self._events and self._events[0].ts < cutoff:
            self._events.popleft()
            self.dropped_old += 1

    def _threat_for(self, ip_str: str, threats: Optional["ThreatLists"]) -> Optional[str]:
        if not threats:
            return None
        ip = parse_ip(ip_str)
        if not ip:
            return None
        return find_list_match(str(ip), threats)

    def snapshot(
        self,
        window: str = "1h",
        view: str = "app",
        limit_groups: int = 80,
        samples_per_group: int = 25,
        q: str = "",
        geo: Optional["GeoCache"] = None,
        threats: Optional["ThreatLists"] = None,
        blocked_sample_limit: int = 40,
        only_success: bool = False,
        only_failed: bool = False,
        only_action: bool = False,
        only_noise: bool = False,
    ) -> dict[str, Any]:
        sec = WINDOWS.get(window, 3600)
        now = time.time()
        cutoff = now - sec
        qn = q.strip().lower()

        # Mutual exclusivity: if both, prefer success (UI usually sends one)
        if only_success and only_failed:
            only_failed = False
        if only_action and only_noise:
            only_noise = False

        with self._lock:
            self._prune_locked(now - MAX_WINDOW_SEC)
            events = [e for e in self._events if e.ts >= cutoff]
        buf = self.buffer_info()
        total_before_status = len(events)

        if qn:
            events = [
                e
                for e in events
                if qn in e.client.lower()
                or qn in e.origin.lower()
                or qn in e.path.lower()
                or qn in (e.router or "").lower()
            ]

        if only_success:
            events = [e for e in events if is_success(e)]
        elif only_failed:
            events = [e for e in events if is_failed(e)]

        def risk_for(e: AccessEvent, tl: Optional[str] = None) -> dict:
            return assess_access(
                path=e.path,
                status=e.status,
                method=e.method,
                router=e.router,
                user_agent=e.ua,
                origin=e.origin,
                threat_list=tl,
            ).as_dict()

        # Pre-filter by risk when requested (needs assessment per event)
        if only_action or only_noise:
            filtered = []
            for e in events:
                r = risk_for(e)
                if only_action and r.get("action_needed"):
                    filtered.append(e)
                elif only_noise and r.get("level") == "noise":
                    filtered.append(e)
            events = filtered

        # Geo for all client IPs in window (cached; few API misses)
        clients = {e.client for e in events}
        geo_map: dict[str, dict] = {}
        if geo and clients:
            geo_map = geo.resolve(clients)

        def ginfo(ip: str) -> dict:
            base = geo_map.get(ip) or {
                "country": "—",
                "country_code": "",
                "org": "—",
                "asn": "",
                "as_full": "",
                "label": "—",
            }
            return base

        groups: DefaultDict[str, list[AccessEvent]] = defaultdict(list)
        for e in events:
            key = e.origin if view == "app" else e.client
            groups[key].append(e)

        ranked = sorted(
            groups.items(),
            key=lambda kv: (kv[1][-1].ts if kv[1] else 0, len(kv[1])),
            reverse=True,
        )[:limit_groups]

        action_count = 0
        noise_count = 0
        out_groups = []
        for key, items in ranked:
            items_sorted = list(reversed(items[-samples_per_group:]))
            statuses: DefaultDict[str, int] = defaultdict(int)
            methods: DefaultDict[str, int] = defaultdict(int)
            partners: DefaultDict[str, int] = defaultdict(int)
            countries: DefaultDict[str, int] = defaultdict(int)
            blocked_n = 0
            for e in items:
                statuses[str(e.status)] += 1
                methods[e.method] += 1
                partner = e.client if view == "app" else e.origin
                partners[partner] += 1
                if is_blocked(e):
                    blocked_n += 1
                r = risk_for(e)
                if r.get("action_needed"):
                    action_count += 1
                if r.get("level") == "noise":
                    noise_count += 1
                if view == "app":
                    gi = ginfo(e.client)
                    cc = gi.get("country_code") or gi.get("country") or "?"
                    countries[str(cc)] += 1
                else:
                    gi = ginfo(key)
                    cc = gi.get("country_code") or gi.get("country") or "?"
                    countries[str(cc)] += 1

            top_partners = sorted(partners.items(), key=lambda x: -x[1])[:8]
            top_countries = sorted(countries.items(), key=lambda x: -x[1])[:6]
            key_geo = ginfo(key) if view == "ip" else None

            sample_rows = []
            for e in items_sorted:
                tl = self._threat_for(e.client, threats)
                sample_rows.append(
                    {
                        "ts": e.ts,
                        "client": e.client,
                        "origin": e.origin,
                        "method": e.method,
                        "path": e.path,
                        "status": e.status,
                        "router": e.router,
                        "ua": e.ua,
                        "blocked": is_blocked(e),
                        "geo": ginfo(e.client),
                        "threat_list": tl,
                        "risk": risk_for(e, tl),
                    }
                )

            out_groups.append(
                {
                    "key": key,
                    "count": len(items),
                    "blocked_count": blocked_n,
                    "first_ts": items[0].ts,
                    "last_ts": items[-1].ts,
                    "unique_partners": len(partners),
                    "status_top": sorted(statuses.items(), key=lambda x: -x[1])[:5],
                    "method_top": sorted(methods.items(), key=lambda x: -x[1])[:4],
                    "partners_top": top_partners,
                    "countries_top": top_countries,
                    "geo": key_geo,
                    "samples": sample_rows,
                }
            )

        # --- Blocked statistics (after status filter when applicable) ---
        blocked_events = [e for e in events if is_blocked(e)]
        block_by_country: DefaultDict[str, int] = defaultdict(int)
        block_by_org: DefaultDict[str, int] = defaultdict(int)
        block_by_ip: DefaultDict[str, int] = defaultdict(int)
        block_by_host: DefaultDict[str, int] = defaultdict(int)
        block_by_router: DefaultDict[str, int] = defaultdict(int)
        block_by_status: DefaultDict[str, int] = defaultdict(int)

        for e in blocked_events:
            gi = ginfo(e.client)
            cc = gi.get("country_code") or gi.get("country") or "?"
            org = gi.get("org") or "—"
            block_by_country[str(cc)] += 1
            block_by_org[str(org)[:60]] += 1
            block_by_ip[e.client] += 1
            block_by_host[e.origin] += 1
            block_by_router[e.router or "—"] += 1
            block_by_status[str(e.status or "—")] += 1

        blocked_samples = []
        for e in reversed(blocked_events[-blocked_sample_limit:]):
            tl = self._threat_for(e.client, threats)
            rv = risk_for(e, tl)
            blocked_samples.append(
                {
                    "ts": e.ts,
                    "client": e.client,
                    "origin": e.origin,
                    "method": e.method,
                    "path": e.path,
                    "status": e.status,
                    "router": e.router,
                    "ua": e.ua,
                    "geo": ginfo(e.client),
                    "threat_list": tl,
                    "reasons": block_reasons(e, tl),
                    "risk": rv,
                }
            )

        unique_ips = {e.client for e in events}
        unique_apps = {e.origin for e in events}
        return {
            "window": window,
            "window_sec": sec,
            "view": view,
            "query": q,
            "only_success": only_success,
            "only_failed": only_failed,
            "only_action": only_action,
            "only_noise": only_noise,
            "now": now,
            "total_in_window": len(events),
            "total_before_status_filter": total_before_status,
            "action_count": action_count,
            "noise_count": noise_count,
            "unique_ips": len(unique_ips),
            "unique_apps": len(unique_apps),
            "groups": out_groups,
            "blocked": {
                "total": len(blocked_events),
                "unique_ips": len(block_by_ip),
                "unique_apps": len(block_by_host),
                "by_country": sorted(block_by_country.items(), key=lambda x: -x[1])[:12],
                "by_org": sorted(block_by_org.items(), key=lambda x: -x[1])[:12],
                "by_ip": sorted(block_by_ip.items(), key=lambda x: -x[1])[:15],
                "by_host": sorted(block_by_host.items(), key=lambda x: -x[1])[:12],
                "by_router": sorted(block_by_router.items(), key=lambda x: -x[1])[:8],
                "by_status": sorted(block_by_status.items(), key=lambda x: -x[1])[:8],
                "samples": blocked_samples,
            },
            "geo_stats": geo.stats() if geo else {},
            "buffer": buf,
        }
