"""Allow env overrides for secrets so Unraid templates stay clean."""
from __future__ import annotations

import os
from typing import Any, Dict


def apply_env_overrides(cfg: Dict[str, Any]) -> Dict[str, Any]:
    alerts = cfg.setdefault("alerts", {})
    if os.environ.get("DISCORD_WEBHOOK"):
        alerts["discord_webhook"] = os.environ["DISCORD_WEBHOOK"].strip()
    if os.environ.get("TELEGRAM_BOT_TOKEN"):
        alerts["telegram_bot_token"] = os.environ["TELEGRAM_BOT_TOKEN"].strip()
    if os.environ.get("TELEGRAM_CHAT_ID"):
        alerts["telegram_chat_id"] = os.environ["TELEGRAM_CHAT_ID"].strip()
    if os.environ.get("GENERIC_WEBHOOK"):
        alerts["generic_webhook"] = os.environ["GENERIC_WEBHOOK"].strip()
    if os.environ.get("MIN_SEVERITY"):
        alerts["min_severity"] = os.environ["MIN_SEVERITY"].strip()

    # Pushover (https://pushover.net)
    po = alerts.setdefault("pushover", {})
    if not isinstance(po, dict):
        po = {}
        alerts["pushover"] = po
    if os.environ.get("PUSHOVER_USER_KEY"):
        po["user_key"] = os.environ["PUSHOVER_USER_KEY"].strip()
    if os.environ.get("PUSHOVER_API_TOKEN"):
        po["api_token"] = os.environ["PUSHOVER_API_TOKEN"].strip()
    if os.environ.get("PUSHOVER_DEVICE"):
        po["device"] = os.environ["PUSHOVER_DEVICE"].strip()
    if os.environ.get("PUSHOVER_SOUND"):
        po["sound"] = os.environ["PUSHOVER_SOUND"].strip()

    if os.environ.get("LOG_DIR"):
        cfg.setdefault("log", {})["directory"] = os.environ["LOG_DIR"]
    if os.environ.get("LOG_PATTERN"):
        cfg.setdefault("log", {})["pattern"] = os.environ["LOG_PATTERN"]
    if os.environ.get("LISTS_DIR"):
        cfg["lists_dir"] = os.environ["LISTS_DIR"]
    if os.environ.get("KNOWN_LISTS"):
        # comma-separated catalog names
        names = [x.strip() for x in os.environ["KNOWN_LISTS"].split(",") if x.strip()]
        cfg["known_lists"] = {"use_cache": True, "enabled": names}
    if os.environ.get("ALLOWLIST_IPS"):
        cfg["allowlist_ips"] = [x.strip() for x in os.environ["ALLOWLIST_IPS"].split(",") if x.strip()]
    if os.environ.get("LISTS_REFRESH_HOURS"):
        cfg["lists_refresh_hours"] = float(os.environ["LISTS_REFRESH_HOURS"])
    if os.environ.get("TZ"):
        pass  # handled by container TZ

    if os.environ.get("CROWDSEC_CONFIG_DIR") or os.environ.get("CROWDSEC_BOUNCER_CONFIG"):
        cs = cfg.get("crowdsec")
        if not isinstance(cs, dict):
            cs = {}
            cfg["crowdsec"] = cs
        if os.environ.get("CROWDSEC_CONFIG_DIR"):
            cs["config_dir"] = os.environ["CROWDSEC_CONFIG_DIR"].strip()
        if os.environ.get("CROWDSEC_BOUNCER_CONFIG"):
            cs["bouncer_config"] = os.environ["CROWDSEC_BOUNCER_CONFIG"].strip()
    return cfg
