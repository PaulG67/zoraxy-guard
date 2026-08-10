from __future__ import annotations

import logging
import os
import secrets
import threading
import time
from functools import wraps
from pathlib import Path
from typing import Any, Callable, Optional

import yaml
from flask import (
    Flask,
    flash,
    jsonify,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from werkzeug.serving import make_server

from . import runtime as rt
from .detectors import Alert
from .envconfig import apply_env_overrides
from .fileio import write_text
from .parser import LogEvent
from .catalog import (
    catalog_as_feed_map,
    get_active_catalog,
    load_meta,
    prune_config_enabled,
    update_catalog_from_remote,
)
from . import catalog as catalog_mod
from .backfill import HOURS_OPTIONS, start_history_backfill

log = logging.getLogger("zoraxy-guard.web")


def _public_cfg(cfg: dict) -> dict:
    return {k: v for k, v in cfg.items() if not str(k).startswith("_")}


def _load_yaml_file(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as fh:
        return yaml.safe_load(fh) or {}


def _save_yaml_file(path: str, cfg: dict) -> None:
    data = _public_cfg(cfg)
    text = yaml.safe_dump(data, sort_keys=False, allow_unicode=True, default_flow_style=False)
    # Direct write: Unraid often bind-mounts config.yaml as a single file;
    # os.replace(tmp, path) then fails with EBUSY (Errno 16).
    write_text(path, text)


def _as_list(text: str) -> list:
    items = []
    for part in text.replace(",", "\n").splitlines():
        part = part.strip()
        if part:
            items.append(part)
    return items


def _as_text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, list):
        return "\n".join(str(x) for x in value)
    return str(value)


def create_app(config_path: str) -> Flask:
    app = Flask(
        __name__,
        template_folder=str(Path(__file__).parent / "templates"),
        static_folder=str(Path(__file__).parent / "static"),
    )
    app.secret_key = os.environ.get("WEB_SECRET") or secrets.token_hex(24)
    password = (os.environ.get("WEB_PASSWORD") or "").strip()

    def login_required(fn: Callable):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            if password and not session.get("auth"):
                return redirect(url_for("login", next=request.path))
            return fn(*args, **kwargs)

        return wrapper

    @app.context_processor
    def inject_globals():
        return {"app_name": "Zoraxy Guard", "has_password": bool(password)}

    @app.route("/login", methods=["GET", "POST"])
    def login():
        if not password:
            return redirect(url_for("dashboard"))
        if request.method == "POST":
            if request.form.get("password") == password:
                session["auth"] = True
                return redirect(request.args.get("next") or url_for("dashboard"))
            flash("Falsches Passwort.", "error")
        return render_template("login.html")

    @app.route("/logout")
    def logout():
        session.clear()
        return redirect(url_for("login" if password else "dashboard"))

    @app.route("/")
    @login_required
    def dashboard():
        snap = rt.RUNTIME.snapshot() if rt.RUNTIME else {}
        return render_template("dashboard.html", snap=snap, time=time)

    @app.route("/api/status")
    @login_required
    def api_status():
        """Read-only status/memory snapshot. Never mutates history ring."""
        if not rt.RUNTIME:
            return jsonify({"error": "runtime not ready"}), 503
        return jsonify(rt.RUNTIME.snapshot())

    @app.route("/api/alerts/ack", methods=["POST"])
    @login_required
    def api_alert_ack():
        """Mark alert fingerprint as reviewed (persisted under /data)."""
        if not rt.RUNTIME:
            return jsonify({"error": "runtime not ready"}), 503
        data = request.get_json(silent=True) or {}
        if request.form:
            data = {**data, **request.form.to_dict()}
        fp = (data.get("fingerprint") or "").strip()
        if not fp:
            return jsonify({"error": "fingerprint fehlt"}), 400
        note = (data.get("note") or "").strip()
        title = (data.get("title") or "").strip()
        origin = (data.get("origin") or "").strip()
        path = (data.get("path") or "").strip()
        entry = rt.RUNTIME.acks.ack(fp, title=title, origin=origin, path=path, note=note)
        rt.RUNTIME.mark_alert_acked(fp)
        return jsonify({"ok": True, "fingerprint": fp, "ack": entry, "acked_count": rt.RUNTIME.acks.count()})

    @app.route("/api/alerts/unack", methods=["POST"])
    @login_required
    def api_alert_unack():
        if not rt.RUNTIME:
            return jsonify({"error": "runtime not ready"}), 503
        data = request.get_json(silent=True) or {}
        if request.form:
            data = {**data, **request.form.to_dict()}
        fp = (data.get("fingerprint") or "").strip()
        if not fp:
            return jsonify({"error": "fingerprint fehlt"}), 400
        ok = rt.RUNTIME.acks.unack(fp)
        # Refresh open records if still in recent list
        with rt.RUNTIME.lock:
            for rec in rt.RUNTIME.recent_alerts:
                if rec.get("fingerprint") == fp:
                    rec["acked"] = False
                    if rec.get("risk"):
                        rec["risk"] = dict(rec["risk"])
        return jsonify({"ok": ok, "fingerprint": fp, "acked_count": rt.RUNTIME.acks.count()})

    @app.route("/history")
    @login_required
    def history_page():
        if not rt.RUNTIME:
            flash("Runtime nicht bereit.", "error")
            return redirect(url_for("dashboard"))
        window = (request.args.get("w") or "1h").strip().lower()
        if window not in ("1h", "6h", "12h", "24h"):
            window = "1h"
        view = (request.args.get("view") or "app").strip().lower()
        if view not in ("app", "ip"):
            view = "app"
        q = (request.args.get("q") or "").strip()
        only_success = request.args.get("ok") in ("1", "on", "true", "yes")
        only_failed = request.args.get("fail") in ("1", "on", "true", "yes")
        only_action = request.args.get("action") in ("1", "on", "true", "yes")
        only_noise = request.args.get("noise") in ("1", "on", "true", "yes")
        # Pure read path: snapshot/filter/view only — does not clear or reset memory.
        data = rt.RUNTIME.history.snapshot(
            window=window,
            view=view,
            q=q,
            geo=rt.RUNTIME.geo,
            threats=rt.RUNTIME.threats,
            only_success=only_success,
            only_failed=only_failed,
            only_action=only_action,
            only_noise=only_noise,
        )
        mem = rt.RUNTIME.memory_state()
        with rt.RUNTIME.lock:
            backfill = dict(rt.RUNTIME.backfill)
        return render_template(
            "history.html",
            data=data,
            mem=mem,
            time=time,
            backfill=backfill,
            backfill_hours=HOURS_OPTIONS,
            api_status_url=url_for("api_status"),
        )

    @app.route("/history/backfill", methods=["POST"])
    @login_required
    def history_backfill():
        if not rt.RUNTIME:
            flash("Runtime nicht bereit.", "error")
            return redirect(url_for("dashboard"))
        try:
            hours = int(request.form.get("hours") or 1)
        except (TypeError, ValueError):
            hours = 1
        ok, msg = start_history_backfill(rt.RUNTIME, hours)
        flash(msg, "ok" if ok else "error")
        # Show same filter window as requested hours when convenient
        w = {1: "1h", 6: "6h", 12: "12h", 24: "24h"}.get(hours, "1h")
        args = {"w": w}
        if request.form.get("ok") in ("1", "on"):
            args["ok"] = "1"
        if request.form.get("fail") in ("1", "on"):
            args["fail"] = "1"
        return redirect(url_for("history_page", **args))

    @app.route("/history/reset-load", methods=["POST"])
    @login_required
    def history_reset_load():
        """Clear memory ring and start a fresh disk backfill (no alerts)."""
        if not rt.RUNTIME:
            flash("Runtime nicht bereit.", "error")
            return redirect(url_for("dashboard"))
        try:
            hours = int(request.form.get("hours") or 1)
        except (TypeError, ValueError):
            hours = 1
        # start_history_backfill already clears the ring first
        ok, msg = start_history_backfill(rt.RUNTIME, hours)
        if ok:
            msg = f"Reset + Nachladen: {msg}"
        flash(msg, "ok" if ok else "error")
        w = {1: "1h", 6: "6h", 12: "12h", 24: "24h"}.get(hours, "1h")
        return redirect(url_for("history_page", w=w))

    @app.route("/config", methods=["GET", "POST"])
    @login_required
    def config_page():
        if not rt.RUNTIME:
            flash("Runtime nicht bereit.", "error")
            return redirect(url_for("dashboard"))

        if request.method == "POST":
            mode = request.form.get("mode", "form")
            try:
                if mode == "yaml":
                    raw = request.form.get("yaml_text") or ""
                    loaded = yaml.safe_load(raw) or {}
                    if not isinstance(loaded, dict):
                        raise ValueError("YAML root must be a mapping/object")
                    _save_yaml_file(config_path, loaded)
                else:
                    disk = _load_yaml_file(config_path)
                    disk.setdefault("log", {})
                    disk.setdefault("alerts", {})
                    if not isinstance(disk["alerts"].get("pushover"), dict):
                        disk["alerts"]["pushover"] = {}

                    disk["log"]["directory"] = request.form.get("log_directory", "/logs").strip()
                    disk["log"]["pattern"] = request.form.get("log_pattern", "zr_*.log").strip()
                    disk["log"]["tail_from_end"] = request.form.get("tail_from_end") == "on"
                    try:
                        disk["log"]["poll_interval"] = float(request.form.get("poll_interval") or 2)
                    except ValueError:
                        disk["log"]["poll_interval"] = 2

                    disk["allowlist_ips"] = _as_list(request.form.get("allowlist_ips", ""))
                    disk["blocklist_ips"] = _as_list(request.form.get("blocklist_ips", ""))
                    disk["sensitive_hosts"] = _as_list(request.form.get("sensitive_hosts", ""))
                    disk["exploit_paths"] = _as_list(request.form.get("exploit_paths", ""))
                    disk["bad_user_agents"] = _as_list(request.form.get("bad_user_agents", ""))

                    enabled = request.form.getlist("known_lists")
                    disk["known_lists"] = {"use_cache": True, "enabled": enabled}

                    try:
                        disk["lists_refresh_hours"] = float(request.form.get("lists_refresh_hours") or 24)
                    except ValueError:
                        disk["lists_refresh_hours"] = 24

                    disk["alert_sensitive_success"] = request.form.get("alert_sensitive_success") == "on"

                    a = disk["alerts"]
                    a["min_severity"] = request.form.get("min_severity", "medium").strip()
                    try:
                        a["cooldown_seconds"] = int(request.form.get("cooldown_seconds") or 300)
                    except ValueError:
                        a["cooldown_seconds"] = 300
                    a["stdout"] = request.form.get("stdout") == "on"
                    a["discord_webhook"] = request.form.get("discord_webhook", "").strip()
                    a["telegram_bot_token"] = request.form.get("telegram_bot_token", "").strip()
                    a["telegram_chat_id"] = request.form.get("telegram_chat_id", "").strip()
                    a["generic_webhook"] = request.form.get("generic_webhook", "").strip()

                    po = a.setdefault("pushover", {})
                    po["user_key"] = request.form.get("pushover_user_key", "").strip()
                    po["api_token"] = request.form.get("pushover_api_token", "").strip()
                    po["device"] = request.form.get("pushover_device", "").strip()
                    po["sound"] = request.form.get("pushover_sound", "").strip()

                    th = disk.setdefault("thresholds", {})
                    for key in (
                        "exploit_hits_for_alert",
                        "exploit_window_seconds",
                        "block_hits_for_alert",
                        "block_window_seconds",
                        "auth_fail_for_alert",
                        "auth_fail_window_seconds",
                    ):
                        try:
                            th[key] = int(request.form.get(key) or th.get(key) or 0)
                        except ValueError:
                            pass

                    _save_yaml_file(config_path, disk)

                rt.RUNTIME.request_reload()
                flash("Gespeichert. Konfiguration wird neu geladen…", "ok")
            except Exception as exc:
                log.exception("Config save failed")
                flash(f"Speichern fehlgeschlagen: {exc}", "error")
            return redirect(url_for("config_page"))

        try:
            disk = _load_yaml_file(config_path)
        except Exception as exc:
            flash(f"Config lesen fehlgeschlagen: {exc}", "error")
            disk = {}

        runtime_cfg = apply_env_overrides(_public_cfg(dict(disk)))
        enabled = []
        kl = disk.get("known_lists") or {}
        if isinstance(kl, list):
            enabled = kl
        elif isinstance(kl, dict):
            enabled = kl.get("enabled") or []

        yaml_text = yaml.safe_dump(_public_cfg(disk), sort_keys=False, allow_unicode=True)
        return render_template(
            "config.html",
            cfg=disk,
            runtime_cfg=runtime_cfg,
            yaml_text=yaml_text,
            catalog=catalog_as_feed_map(),
            enabled=set(enabled),
            as_text=_as_text,
        )

    @app.route("/actions/reload-lists", methods=["POST"])
    @login_required
    def action_reload_lists():
        if rt.RUNTIME:
            rt.RUNTIME.request_lists_reload()
            flash("Threat-Listen-Inhalte werden neu geladen…", "ok")
        return redirect(url_for("dashboard"))

    @app.route("/actions/update-catalog", methods=["POST"])
    @login_required
    def action_update_catalog():
        """Refresh which lists exist (new/deprecated), not IP content."""
        probe = request.form.get("probe") == "on"
        try:
            meta = update_catalog_from_remote(probe=probe)
            # Prune deprecated from config if user asked
            if request.form.get("prune_config") == "on" and rt.RUNTIME:
                path = rt.RUNTIME.config_path
                disk = _load_yaml_file(path)
                kl = disk.get("known_lists") or {}
                if isinstance(kl, list):
                    enabled = kl
                    kept, dropped = prune_config_enabled(enabled)
                    disk["known_lists"] = kept
                else:
                    enabled = list((kl or {}).get("enabled") or [])
                    kept, dropped = prune_config_enabled(enabled)
                    disk["known_lists"] = {"use_cache": True, "enabled": kept}
                if dropped:
                    _save_yaml_file(path, disk)
                    rt.RUNTIME.request_reload()
                    flash(
                        f"Katalog aktualisiert (v{meta.get('version')}). "
                        f"Neu: {len(meta.get('added') or [])}, entfernt: {len(meta.get('removed') or [])}. "
                        f"Aus Config entfernt (deprecated): {', '.join(dropped)}",
                        "ok",
                    )
                else:
                    flash(
                        f"Katalog aktualisiert (v{meta.get('version')}). "
                        f"+{len(meta.get('added') or [])} / -{len(meta.get('removed') or [])} Listen. "
                        f"Deprecated im Katalog: {len(meta.get('deprecated') or [])}.",
                        "ok",
                    )
            else:
                flash(
                    f"Katalog aktualisiert (v{meta.get('version')}). "
                    f"Neu: {meta.get('added') or '–'} · Entfernt: {meta.get('removed') or '–'} · "
                    f"Deprecated: {meta.get('deprecated') or '–'}",
                    "ok",
                )
            # Always refresh list contents on catalog change so new names can load later
            if rt.RUNTIME:
                rt.RUNTIME.request_lists_reload()
        except Exception as exc:
            log.exception("Catalog update failed")
            flash(f"Katalog-Update fehlgeschlagen: {exc}", "error")
        return redirect(url_for("lists_page"))

    @app.route("/actions/reload-config", methods=["POST"])
    @login_required
    def action_reload_config():
        if rt.RUNTIME:
            rt.RUNTIME.request_reload()
            flash("Konfiguration wird neu geladen…", "ok")
        return redirect(url_for("dashboard"))

    @app.route("/actions/test-alert", methods=["POST"])
    @login_required
    def action_test_alert():
        if not rt.RUNTIME or not rt.RUNTIME.alerter:
            flash("Alerter nicht bereit.", "error")
            return redirect(url_for("dashboard"))
        alert = Alert(
            severity="high",
            title="Test-Alarm aus der Web-UI",
            body="Wenn du das siehst, funktioniert die Alarmierung (Pushover/Discord/Telegram).",
            fingerprint=f"ui-test:{time.time()}",
            event=LogEvent(
                raw="[UI-TEST] simulated Zoraxy request line",
                timestamp=None,
                kind="request",
                router="host-http",
                origin="test.local",
                client="203.0.113.50",
                user_agent="ZoraxyGuard-WebUI/1.0",
                method="GET",
                path="/test-alert",
                status=200,
            ),
        )
        try:
            if rt.RUNTIME.alerter.send(alert, time.time()):
                rt.RUNTIME.note_alert(alert)
            flash("Test-Alarm gesendet (siehe Channels + Log).", "ok")
        except Exception as exc:
            flash(f"Test fehlgeschlagen: {exc}", "error")
        return redirect(url_for("dashboard"))

    @app.route("/lists")
    @login_required
    def lists_page():
        snap = rt.RUNTIME.snapshot() if rt.RUNTIME else {}
        lists_dir = "/data/lists"
        if rt.RUNTIME and rt.RUNTIME.cfg:
            lists_dir = rt.RUNTIME.cfg.get("lists_dir") or lists_dir
        files = []
        try:
            p = Path(lists_dir)
            if p.is_dir():
                for f in sorted(p.iterdir()):
                    if f.is_file():
                        files.append({"name": f.name, "size": f.stat().st_size})
        except OSError:
            pass
        cat = get_active_catalog()
        meta = load_meta()
        return render_template(
            "lists.html",
            snap=snap,
            files=files,
            lists_dir=lists_dir,
            catalog=catalog_as_feed_map(cat),
            catalog_doc=cat,
            catalog_meta=meta,
            catalog_url=catalog_mod.DEFAULT_REMOTE,
            time=time,
        )

    return app


def start_web_server(config_path: str) -> Optional[threading.Thread]:
    if os.environ.get("WEB_ENABLED", "true").lower() in ("0", "false", "no"):
        log.info("Web UI disabled (WEB_ENABLED=false)")
        return None

    host = os.environ.get("WEB_HOST", "0.0.0.0")
    port = int(os.environ.get("WEB_PORT", "8787"))
    app = create_app(config_path)
    server = make_server(host, port, app, threaded=True)

    def _run():
        log.info("Web UI listening on http://%s:%s", host, port)
        server.serve_forever()

    t = threading.Thread(target=_run, name="zoraxy-guard-web", daemon=True)
    t.start()
    return t
