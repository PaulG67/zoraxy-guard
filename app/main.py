from __future__ import annotations

import glob
import json
import logging
import os
import sys
import time
from pathlib import Path
from typing import Dict, List

import yaml

from . import runtime as rt
from .alerter import Alerter
from .detectors import Detector
from .envconfig import apply_env_overrides
from .feeds import load_all_threat_lists
from .iputil import load_networks
from .parser import parse_line
from .runtime import Runtime
from .webui import start_web_server

log = logging.getLogger("zoraxy-guard")


def setup_logging() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        stream=sys.stdout,
    )


def load_config(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as fh:
        cfg = yaml.safe_load(fh) or {}
    return apply_env_overrides(cfg)


def refresh_lists(cfg: dict):
    cfg["_allow_nets"] = load_networks(cfg.get("allowlist_ips") or [])
    cache_dir = cfg.get("feed_cache_dir") or "/data/feed-cache"
    threats = load_all_threat_lists(cfg, cache_dir=cache_dir)
    cfg["_block_nets"] = []
    src_summary = ", ".join(f"{k}={v}" for k, v in sorted(threats.sources.items())[:12])
    log.info(
        "Threat lists loaded: %d networks from %d sources. Sample: %s",
        len(threats.block_nets),
        len(threats.sources),
        src_summary or "(none)",
    )
    return threats


def load_state(path: str) -> dict:
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except (FileNotFoundError, json.JSONDecodeError):
        return {"offsets": {}, "cooldowns": {}}


def save_state(path: str, state: dict) -> None:
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(state, fh)
    os.replace(tmp, path)


def list_log_files(directory: str, pattern: str) -> List[str]:
    return sorted(glob.glob(os.path.join(directory, pattern)))


class Tailer:
    def __init__(self, directory: str, pattern: str, offsets: Dict[str, int], from_end: bool):
        self.directory = directory
        self.pattern = pattern
        self.offsets = offsets
        self.from_end = from_end

    def configure(self, directory: str, pattern: str, from_end: bool) -> None:
        self.directory = directory
        self.pattern = pattern
        self.from_end = from_end

    def poll(self) -> List[str]:
        lines: List[str] = []
        files = list_log_files(self.directory, self.pattern)
        if not files:
            return lines

        for fpath in files:
            try:
                size = os.path.getsize(fpath)
            except OSError:
                continue

            if fpath not in self.offsets:
                self.offsets[fpath] = size if self.from_end else 0

            pos = self.offsets[fpath]
            if size < pos:
                pos = 0
            if size == pos:
                continue

            try:
                with open(fpath, "r", encoding="utf-8", errors="replace") as fh:
                    fh.seek(pos)
                    chunk = fh.read()
                    self.offsets[fpath] = fh.tell()
            except OSError as exc:
                log.error("Read failed %s: %s", fpath, exc)
                continue

            for line in chunk.splitlines():
                if line.strip():
                    lines.append(line)
        return lines


def _rebuild_from_config(config_path: str, cooldowns: dict):
    cfg = load_config(config_path)
    threats = refresh_lists(cfg)
    detector = Detector(cfg, threats)
    alerter = Alerter(cfg, cooldowns)
    return cfg, threats, detector, alerter


def run(config_path: str) -> None:
    setup_logging()
    state_path = None
    state = {"offsets": {}, "cooldowns": {}}
    cooldowns: Dict[str, float] = {}

    cfg, threats, detector, alerter = _rebuild_from_config(config_path, cooldowns)
    state_path = cfg.get("state_file", "/data/state.json")
    state = load_state(state_path)
    offsets = state.setdefault("offsets", {})
    cooldowns = state.setdefault("cooldowns", {})
    # rebuild alerter with persistent cooldowns
    alerter = Alerter(cfg, cooldowns)

    log_cfg = cfg.get("log", {})
    directory = log_cfg.get("directory", "/logs")
    pattern = log_cfg.get("pattern", "zr_*.log")
    from_end = bool(log_cfg.get("tail_from_end", True))
    poll = float(log_cfg.get("poll_interval", 2))

    tailer = Tailer(directory, pattern, offsets, from_end)

    runtime = Runtime(
        config_path=config_path,
        cfg=cfg,
        threats=threats,
        detector=detector,
        alerter=alerter,
        cooldowns=cooldowns,
        last_reload_at=time.time(),
        watching=f"{directory}/{pattern}",
        log_files=[os.path.basename(f) for f in list_log_files(directory, pattern)[-8:]],
    )
    rt.RUNTIME = runtime

    start_web_server(config_path)

    refresh_hours = float(cfg.get("lists_refresh_hours") or 24)
    last_feed = time.time()
    save_counter = 0

    log.info("Zoraxy Guard started. Watching %s/%s", directory, pattern)

    while True:
        # Config / lists reload from UI
        do_full = False
        do_lists = False
        with runtime.lock:
            if runtime.reload_requested:
                runtime.reload_requested = False
                do_full = True
            if runtime.lists_reload_requested:
                runtime.lists_reload_requested = False
                do_lists = True

        if do_full:
            try:
                cfg, threats, detector, alerter = _rebuild_from_config(config_path, cooldowns)
                alerter = Alerter(cfg, cooldowns)
                log_cfg = cfg.get("log", {})
                directory = log_cfg.get("directory", "/logs")
                pattern = log_cfg.get("pattern", "zr_*.log")
                from_end = bool(log_cfg.get("tail_from_end", True))
                poll = float(log_cfg.get("poll_interval", 2))
                tailer.configure(directory, pattern, from_end)
                with runtime.lock:
                    runtime.cfg = cfg
                    runtime.threats = threats
                    runtime.detector = detector
                    runtime.alerter = alerter
                    runtime.last_reload_at = time.time()
                    runtime.last_error = ""
                    runtime.watching = f"{directory}/{pattern}"
                    runtime.log_files = [
                        os.path.basename(f) for f in list_log_files(directory, pattern)[-8:]
                    ]
                refresh_hours = float(cfg.get("lists_refresh_hours") or 24)
                last_feed = time.time()
                log.info("Configuration reloaded from UI/file")
            except Exception as exc:
                log.error("Config reload failed: %s", exc)
                with runtime.lock:
                    runtime.last_error = str(exc)

        elif do_lists or (time.time() - last_feed > refresh_hours * 3600):
            try:
                threats = refresh_lists(cfg)
                detector = Detector(cfg, threats)
                with runtime.lock:
                    runtime.threats = threats
                    runtime.detector = detector
                    runtime.last_reload_at = time.time()
                    runtime.last_error = ""
                last_feed = time.time()
                log.info("Threat lists refreshed")
            except Exception as exc:
                log.error("List refresh failed: %s", exc)
                with runtime.lock:
                    runtime.last_error = str(exc)

        lines = tailer.poll()
        now = time.time()
        if lines:
            with runtime.lock:
                runtime.lines_processed += len(lines)
                runtime.last_line_at = now
                det = runtime.detector
                alt = runtime.alerter
            for line in lines:
                event = parse_line(line)
                if not det or not alt:
                    break
                for alert in det.process(event):
                    if alt.send(alert, now):
                        runtime.note_alert(alert)

        save_counter += 1
        if save_counter >= 10:
            with runtime.lock:
                alt = runtime.alerter or alerter
            cut = now - max(alt.cooldown * 3, 3600)
            state["cooldowns"] = {k: v for k, v in cooldowns.items() if v >= cut}
            state["offsets"] = offsets
            save_state(state_path, state)
            save_counter = 0

        time.sleep(poll)


def main() -> None:
    config_path = os.environ.get("ZORAXY_GUARD_CONFIG", "/config/config.yaml")
    if not os.path.isfile(config_path):
        print(f"Config not found: {config_path}", file=sys.stderr)
        print("Copy config.example.yaml to your config volume.", file=sys.stderr)
        sys.exit(1)
    run(config_path)


if __name__ == "__main__":
    main()
