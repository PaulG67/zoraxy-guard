"""In-memory access history ring (max 24h, bounded size). No disk persistence."""

from __future__ import annotations

import time
from collections import defaultdict, deque
from dataclasses import dataclass
from threading import Lock
from typing import Any, Deque, DefaultDict, TYPE_CHECKING

if TYPE_CHECKING:
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


class AccessHistory:
    """Bounded ring of access events for the Web UI (RAM only)."""

    def __init__(self, max_events: int = DEFAULT_MAX_EVENTS) -> None:
        self.max_events = max(1000, int(max_events))
        self._events: Deque[AccessEvent] = deque(maxlen=self.max_events)
        self._lock = Lock()
        self.dropped_old = 0
        self.recorded = 0

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
            if self.recorded % 200 == 0:
                self._prune_locked(time.time() - MAX_WINDOW_SEC)

    def buffer_info(self) -> dict[str, Any]:
        with self._lock:
            return {
                "size": len(self._events),
                "max": self.max_events,
                "recorded_total": self.recorded,
                "pruned_old": self.dropped_old,
                "retention_hours": 24,
            }

    def _prune_locked(self, cutoff: float) -> None:
        while self._events and self._events[0].ts < cutoff:
            self._events.popleft()
            self.dropped_old += 1

    def snapshot(
        self,
        window: str = "1h",
        view: str = "app",
        limit_groups: int = 80,
        samples_per_group: int = 25,
        q: str = "",
    ) -> dict[str, Any]:
        sec = WINDOWS.get(window, 3600)
        now = time.time()
        cutoff = now - sec
        qn = q.strip().lower()

        with self._lock:
            self._prune_locked(now - MAX_WINDOW_SEC)
            # Copy only in-window events (slice from right is approx OK; scan is fine for 15k)
            events = [e for e in self._events if e.ts >= cutoff]
            buf_len = len(self._events)
            rec = self.recorded
            dropped = self.dropped_old
            max_ev = self.max_events

        if qn:
            events = [
                e
                for e in events
                if qn in e.client.lower()
                or qn in e.origin.lower()
                or qn in e.path.lower()
            ]

        groups: DefaultDict[str, list[AccessEvent]] = defaultdict(list)
        for e in events:
            key = e.origin if view == "app" else e.client
            groups[key].append(e)

        # Sort groups by latest activity then by count
        ranked = sorted(
            groups.items(),
            key=lambda kv: (kv[1][-1].ts if kv[1] else 0, len(kv[1])),
            reverse=True,
        )[:limit_groups]

        out_groups = []
        for key, items in ranked:
            items_sorted = items[-samples_per_group:]  # most recent N in group (append order)
            items_sorted = list(reversed(items_sorted))  # newest first for UI
            statuses: DefaultDict[str, int] = defaultdict(int)
            methods: DefaultDict[str, int] = defaultdict(int)
            partners: DefaultDict[str, int] = defaultdict(int)
            for e in items:
                statuses[str(e.status)] += 1
                methods[e.method] += 1
                partner = e.client if view == "app" else e.origin
                partners[partner] += 1

            top_partners = sorted(partners.items(), key=lambda x: -x[1])[:8]
            out_groups.append(
                {
                    "key": key,
                    "count": len(items),
                    "first_ts": items[0].ts,
                    "last_ts": items[-1].ts,
                    "unique_partners": len(partners),
                    "status_top": sorted(statuses.items(), key=lambda x: -x[1])[:5],
                    "method_top": sorted(methods.items(), key=lambda x: -x[1])[:4],
                    "partners_top": top_partners,
                    "samples": [
                        {
                            "ts": e.ts,
                            "client": e.client,
                            "origin": e.origin,
                            "method": e.method,
                            "path": e.path,
                            "status": e.status,
                            "router": e.router,
                            "ua": e.ua,
                        }
                        for e in items_sorted
                    ],
                }
            )

        unique_ips = {e.client for e in events}
        unique_apps = {e.origin for e in events}
        return {
            "window": window,
            "window_sec": sec,
            "view": view,
            "query": q,
            "now": now,
            "total_in_window": len(events),
            "unique_ips": len(unique_ips),
            "unique_apps": len(unique_apps),
            "groups": out_groups,
            "buffer": {
                "size": buf_len,
                "max": max_ev,
                "recorded_total": rec,
                "pruned_old": dropped,
                "retention_hours": 24,
            },
        }
