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

from .alerter import Alerter
from .detectors import Detector
from .envconfig import apply_env_overrides
from .feeds import load_all_threat_lists
from .iputil import load_networks
from .parser import parse_line

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
    # Static blocklist still merged inside load_all_threat_lists
    cache_dir = cfg.get("feed_cache_dir") or "/data/feed-cache"
    threats = load_all_threat_lists(cfg, cache_dir=cache_dir)
    cfg["_block_nets"] = []  # all IP blocks live in threats now
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


def run(config_path: str) -> None:
    setup_logging()
    cfg = load_config(config_path)
    threats = refresh_lists(cfg)

    state_path = cfg.get("state_file", "/data/state.json")
    state = load_state(state_path)
    offsets = state.setdefault("offsets", {})
    cooldowns = state.setdefault("cooldowns", {})

    log_cfg = cfg.get("log", {})
    directory = log_cfg.get("directory", "/logs")
    pattern = log_cfg.get("pattern", "zr_*.log")
    from_end = bool(log_cfg.get("tail_from_end", True))
    poll = float(log_cfg.get("poll_interval", 2))

    detector = Detector(cfg, threats)
    alerter = Alerter(cfg, cooldowns)
    tailer = Tailer(directory, pattern, offsets, from_end)

    refresh_hours = float(cfg.get("lists_refresh_hours") or 24)
    last_feed = time.time()

    log.info("Zoraxy Guard started. Watching %s/%s", directory, pattern)
    save_counter = 0

    while True:
        if time.time() - last_feed > refresh_hours * 3600:
            try:
                threats = refresh_lists(cfg)
                detector = Detector(cfg, threats)
                last_feed = time.time()
            except Exception as exc:
                log.error("List refresh failed: %s", exc)

        lines = tailer.poll()
        now = time.time()
        for line in lines:
            event = parse_line(line)
            for alert in detector.process(event):
                alerter.send(alert, now)

        save_counter += 1
        if save_counter >= 10:
            cut = now - max(alerter.cooldown * 3, 3600)
            state["cooldowns"] = {k: v for k, v in cooldowns.items() if v >= cut}
            state["offsets"] = offsets
            save_state(state_path, state)
            save_counter = 0

        time.sleep(poll)


def main() -> None:
    config_path = os.environ.get("ZORAXY_GUARD_CONFIG", "/config/config.yaml")
    if not os.path.isfile(config_path):
        example = "/config.example.yaml"
        if os.path.isfile(example) and not os.path.isfile(config_path):
            print(f"Config not found: {config_path}", file=sys.stderr)
            print("Copy config.example.yaml to your config volume.", file=sys.stderr)
        else:
            print(f"Config not found: {config_path}", file=sys.stderr)
        sys.exit(1)
    run(config_path)


if __name__ == "__main__":
    main()
