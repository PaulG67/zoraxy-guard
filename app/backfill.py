"""On-demand log backfill into History memory only (no alerts)."""

from __future__ import annotations

import glob
import logging
import os
import threading
import time
from typing import TYPE_CHECKING, List

from .parser import parse_line

if TYPE_CHECKING:
    from .runtime import Runtime

log = logging.getLogger("zoraxy-guard.backfill")

HOURS_OPTIONS = (1, 6, 12, 24)


def list_log_files(directory: str, pattern: str) -> List[str]:
    return sorted(glob.glob(os.path.join(directory, pattern)))


def start_history_backfill(runtime: "Runtime", hours: int) -> tuple[bool, str]:
    """
    Start background scan of disk logs into the history ring.
    Does not touch tailer offsets and never runs detectors / alerters.
    """
    hours = int(hours)
    if hours not in HOURS_OPTIONS:
        return False, "Ungültiges Zeitfenster (1 / 6 / 12 / 24 h)."

    with runtime.lock:
        st = runtime.backfill
        if st.get("running"):
            return False, "Nachladen läuft bereits."
        runtime.backfill = {
            "running": True,
            "hours": hours,
            "started_at": time.time(),
            "finished_at": 0.0,
            "files": 0,
            "lines_read": 0,
            "lines_loaded": 0,
            "lines_skipped_old": 0,
            "error": "",
            "message": f"Lade letzten {hours}h von Disk…",
        }

    t = threading.Thread(
        target=_run_backfill,
        args=(runtime, hours),
        name="history-backfill",
        daemon=True,
    )
    t.start()
    return True, f"Nachladen gestartet ({hours}h, nur Memory, keine Alerts)."


def _run_backfill(runtime: "Runtime", hours: int) -> None:
    cutoff = time.time() - hours * 3600
    try:
        with runtime.lock:
            cfg = runtime.cfg or {}
            history = runtime.history
        log_cfg = cfg.get("log") or {}
        directory = log_cfg.get("directory") or "/logs"
        pattern = log_cfg.get("pattern") or "zr_*.log"

        files = list_log_files(directory, pattern)
        # Clear ring so one explicit load = memory snapshot of this window (+ later live)
        history.clear()

        with runtime.lock:
            runtime.backfill["files"] = len(files)
            runtime.backfill["message"] = f"Scan von {len(files)} Datei(en)…"

        lines_read = 0
        loaded = 0
        skipped_old = 0

        for fpath in files:
            try:
                with open(fpath, "r", encoding="utf-8", errors="replace") as fh:
                    for line in fh:
                        if not line.strip():
                            continue
                        lines_read += 1
                        if lines_read % 5000 == 0:
                            with runtime.lock:
                                runtime.backfill["lines_read"] = lines_read
                                runtime.backfill["lines_loaded"] = loaded
                                runtime.backfill["lines_skipped_old"] = skipped_old
                                runtime.backfill["message"] = (
                                    f"Scan… {lines_read} Zeilen, {loaded} geladen"
                                )

                        event = parse_line(line)
                        if event.kind != "request":
                            continue
                        # Only in-window timestamps (no blind bulk of undated lines)
                        if event.timestamp is None:
                            skipped_old += 1
                            continue
                        try:
                            ts = event.timestamp.timestamp()
                        except (OSError, OverflowError, ValueError):
                            skipped_old += 1
                            continue
                        if ts < cutoff:
                            skipped_old += 1
                            continue
                        history.record(event)
                        loaded += 1
            except OSError as exc:
                log.warning("Backfill read %s: %s", fpath, exc)

        msg = (
            f"Fertig: {loaded} Requests aus {len(files)} Datei(en) "
            f"({hours}h, {lines_read} Zeilen gelesen, {skipped_old} übersprungen)."
        )
        log.info(msg)
        with runtime.lock:
            runtime.backfill.update(
                {
                    "running": False,
                    "finished_at": time.time(),
                    "lines_read": lines_read,
                    "lines_loaded": loaded,
                    "lines_skipped_old": skipped_old,
                    "message": msg,
                    "error": "",
                }
            )
    except Exception as exc:
        log.exception("History backfill failed")
        with runtime.lock:
            runtime.backfill.update(
                {
                    "running": False,
                    "finished_at": time.time(),
                    "error": str(exc)[:300],
                    "message": f"Fehler: {exc}",
                }
            )
