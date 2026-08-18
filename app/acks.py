"""Persistent 'reviewed' fingerprints — shared by Status alerts / suppressions."""

from __future__ import annotations

import hashlib
import logging
import time
from pathlib import Path
from threading import Lock
from typing import Any, Dict, List, Optional, Tuple

from .fileio import write_text

log = logging.getLogger("zoraxy-guard.acks")

DEFAULT_ACK_PATH = "/data/acks.json"


def review_id(fingerprint: str) -> str:
    """Short stable ID for Pushover / Web (ZG-A1B2C3D4)."""
    fp = (fingerprint or "").strip()
    if not fp:
        return ""
    digest = hashlib.sha1(fp.encode("utf-8")).hexdigest()[:8].upper()
    return f"ZG-{digest}"


def normalize_review_id(value: str) -> str:
    raw = (value or "").strip().upper().replace(" ", "")
    if not raw:
        return ""
    raw = raw.replace("–", "-").replace("—", "-")
    if raw.startswith("ZG"):
        raw = raw[2:]
        if raw.startswith("-"):
            raw = raw[1:]
    raw = "".join(ch for ch in raw if ch.isalnum())
    if len(raw) < 6:
        return ""
    return f"ZG-{raw[:8]}"


class AckStore:
    """Mark alert fingerprints as reviewed so they stop appearing as action items."""

    def __init__(self, path: str = DEFAULT_ACK_PATH) -> None:
        self.path = path
        self._lock = Lock()
        self._acks: Dict[str, dict] = {}
        self._ids: Dict[str, dict] = {}
        self.load()

    def load(self) -> None:
        p = Path(self.path)
        if not p.is_file():
            self._acks = {}
            self._ids = {}
            return
        try:
            import json

            data = json.loads(p.read_text(encoding="utf-8"))
            raw = data.get("acks") if isinstance(data, dict) else data
            if not isinstance(raw, dict):
                self._acks = {}
            else:
                out: Dict[str, dict] = {}
                for k, v in raw.items():
                    if isinstance(v, dict):
                        out[str(k)] = v
                    else:
                        out[str(k)] = {"ts": time.time(), "title": str(v)}
                self._acks = out
            ids_raw = data.get("ids") if isinstance(data, dict) else {}
            ids_out: Dict[str, dict] = {}
            if isinstance(ids_raw, dict):
                for k, v in ids_raw.items():
                    rid = normalize_review_id(str(k))
                    if not rid:
                        continue
                    if isinstance(v, dict) and v.get("fingerprint"):
                        ids_out[rid] = v
                    elif isinstance(v, str) and v.strip():
                        ids_out[rid] = {"fingerprint": v.strip()}
            self._ids = ids_out
        except Exception as exc:
            log.warning("Could not load acks from %s: %s", self.path, exc)
            self._acks = {}
            self._ids = {}

    def save(self) -> None:
        import json

        with self._lock:
            text = (
                json.dumps(
                    {"acks": self._acks, "ids": self._ids},
                    indent=2,
                    ensure_ascii=False,
                )
                + "\n"
            )
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

    def register_id(
        self,
        fingerprint: str,
        *,
        title: str = "",
        origin: str = "",
        path: str = "",
    ) -> str:
        rid = review_id(fingerprint)
        if not rid:
            return ""
        entry = {
            "fingerprint": fingerprint,
            "title": (title or "")[:200],
            "origin": (origin or "")[:120],
            "path": (path or "")[:200],
            "ts": time.time(),
        }
        with self._lock:
            self._ids[rid] = entry
            if len(self._ids) > 2000:
                ordered = sorted(self._ids.items(), key=lambda kv: kv[1].get("ts", 0))
                for k, _ in ordered[: len(self._ids) - 2000]:
                    self._ids.pop(k, None)
        self.save()
        return rid

    def lookup_id(self, value: str) -> Optional[Tuple[str, dict]]:
        rid = normalize_review_id(value)
        if not rid:
            return None
        with self._lock:
            meta = self._ids.get(rid)
            if not meta:
                return None
            fp = str(meta.get("fingerprint") or "")
            if not fp:
                return None
            return fp, dict(meta)

    def ack(
        self,
        fingerprint: str,
        *,
        title: str = "",
        origin: str = "",
        path: str = "",
        note: str = "",
        client: str = "",
        method: str = "",
        status: Any = None,
        check_url: str = "",
    ) -> dict:
        if not fingerprint:
            raise ValueError("fingerprint required")
        entry = {
            "ts": time.time(),
            "title": (title or "")[:200],
            "origin": (origin or "")[:120],
            "path": (path or "")[:200],
            "note": (note or "")[:300],
            "review_id": review_id(fingerprint),
            "client": (client or "")[:80],
            "method": (method or "")[:16],
            "status": status,
            "check_url": (check_url or "")[:400],
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

    def query(
        self,
        *,
        q: str = "",
        origin: str = "",
        path: str = "",
        title: str = "",
        review_id_q: str = "",
        limit: int = 2000,
    ) -> dict[str, Any]:
        """Filter reviewed fingerprints for the Geprüft tab."""
        qn = (q or "").strip().lower()
        origin_f = (origin or "").strip().lower()
        path_f = (path or "").strip().lower()
        title_f = (title or "").strip().lower()
        rid_raw = (review_id_q or "").strip()
        rid_norm = normalize_review_id(rid_raw)
        rid_f = (rid_norm or rid_raw).lower()

        with self._lock:
            items = sorted(self._acks.items(), key=lambda kv: -float(kv[1].get("ts") or 0))
            id_map = {k: dict(v) for k, v in self._ids.items()}

        all_origins: set[str] = set()
        all_paths: set[str] = set()
        rows: List[dict] = []
        for fp, meta in items:
            row = dict(meta)
            row["fingerprint"] = fp
            rid = row.get("review_id") or review_id(fp)
            row["review_id"] = rid
            extra = id_map.get(rid) or {}
            row["origin"] = (row.get("origin") or extra.get("origin") or "").strip()
            row["path"] = (row.get("path") or extra.get("path") or "").strip() or ""
            row["title"] = (row.get("title") or extra.get("title") or "").strip()
            row["note"] = (row.get("note") or "").strip()
            row["client"] = (row.get("client") or extra.get("client") or "").strip()
            row["method"] = (row.get("method") or "").strip()
            if row["origin"]:
                all_origins.add(row["origin"])
            if row["path"]:
                all_paths.add(row["path"])
            hay = " ".join(
                [
                    rid,
                    fp,
                    row["origin"],
                    row["path"],
                    row["title"],
                    row["note"],
                    row["client"],
                    str(row.get("status") or ""),
                ]
            ).lower()
            if qn and qn not in hay:
                continue
            if origin_f and origin_f not in row["origin"].lower():
                continue
            if path_f and path_f not in (row["path"] or "").lower():
                continue
            if title_f and title_f not in row["title"].lower():
                continue
            if rid_f:
                blob = f"{rid} {fp}".lower()
                if rid_f not in blob and (rid_norm or "") != rid:
                    continue
            rows.append(row)

        return {
            "rows": rows[: max(1, int(limit))],
            "total": len(items),
            "filtered": len(rows),
            "origins": sorted(all_origins, key=str.lower),
            "paths": sorted(all_paths, key=str.lower)[:80],
        }

    def list_acks(self, limit: int = 100) -> List[dict]:
        with self._lock:
            items = sorted(self._acks.items(), key=lambda kv: -float(kv[1].get("ts") or 0))
        out = []
        for fp, meta in items[:limit]:
            row = dict(meta)
            row["fingerprint"] = fp
            row.setdefault("review_id", review_id(fp))
            out.append(row)
        return out

    def count(self) -> int:
        with self._lock:
            return len(self._acks)

    def as_public_map(self) -> Dict[str, Any]:
        """Lightweight map fingerprint → ack meta for JSON UI."""
        with self._lock:
            return {k: dict(v) for k, v in self._acks.items()}
