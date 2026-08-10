"""Persistent 'reviewed' fingerprints — shared by Status alerts / suppressions."""

from __future__ import annotations

import logging
import time
from pathlib import Path
from threading import Lock
from typing import Any, Dict, List, Optional

from .fileio import write_text

log = logging.getLogger("zoraxy-guard.acks")

DEFAULT_ACK_PATH = "/data/acks.json"


class AckStore:
    """Mark alert fingerprints as reviewed so they stop appearing as action items."""

    def __init__(self, path: str = DEFAULT_ACK_PATH) -> None:
        self.path = path
        self._lock = Lock()
        self._acks: Dict[str, dict] = {}
        self.load()

    def load(self) -> None:
        p = Path(self.path)
        if not p.is_file():
            self._acks = {}
            return
        try:
            import json

            data = json.loads(p.read_text(encoding="utf-8"))
            raw = data.get("acks") if isinstance(data, dict) else data
            if not isinstance(raw, dict):
                self._acks = {}
                return
            out: Dict[str, dict] = {}
            for k, v in raw.items():
                if isinstance(v, dict):
                    out[str(k)] = v
                else:
                    out[str(k)] = {"ts": time.time(), "title": str(v)}
            self._acks = out
        except Exception as exc:
            log.warning("Could not load acks from %s: %s", self.path, exc)
            self._acks = {}

    def save(self) -> None:
        import json

        with self._lock:
            text = json.dumps({"acks": self._acks}, indent=2, ensure_ascii=False) + "\n"
        try:
            write_text(self.path, text)
        except Exception as exc:
            log.error("Failed to save acks: %s", exc)

    def is_acked(self, fingerprint: str) -> bool:
        if not fingerprint:
            return False
        with self._lock:
            return fingerprint in self._acks

    def get(self, fingerprint: str) -> Optional[dict]:
        with self._lock:
            return dict(self._acks[fingerprint]) if fingerprint in self._acks else None

    def ack(
        self,
        fingerprint: str,
        *,
        title: str = "",
        origin: str = "",
        path: str = "",
        note: str = "",
    ) -> dict:
        if not fingerprint:
            raise ValueError("fingerprint required")
        entry = {
            "ts": time.time(),
            "title": (title or "")[:200],
            "origin": (origin or "")[:120],
            "path": (path or "")[:200],
            "note": (note or "")[:300],
        }
        with self._lock:
            self._acks[fingerprint] = entry
            # Bound size: keep newest 2000
            if len(self._acks) > 2000:
                ordered = sorted(self._acks.items(), key=lambda kv: kv[1].get("ts", 0))
                for k, _ in ordered[: len(self._acks) - 2000]:
                    self._acks.pop(k, None)
        self.save()
        return entry

    def unack(self, fingerprint: str) -> bool:
        with self._lock:
            if fingerprint not in self._acks:
                return False
            del self._acks[fingerprint]
        self.save()
        return True

    def list_acks(self, limit: int = 100) -> List[dict]:
        with self._lock:
            items = sorted(self._acks.items(), key=lambda kv: -float(kv[1].get("ts") or 0))
        out = []
        for fp, meta in items[:limit]:
            row = dict(meta)
            row["fingerprint"] = fp
            out.append(row)
        return out

    def count(self) -> int:
        with self._lock:
            return len(self._acks)

    def as_public_map(self) -> Dict[str, Any]:
        """Lightweight map fingerprint → ack meta for JSON UI."""
        with self._lock:
            return {k: dict(v) for k, v in self._acks.items()}
