from __future__ import annotations

import json
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
    Response,
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
from .notify import DEFAULT_NOTIFY_KINDS, NOTIFY_KINDS, normalize_mode
from .acks import review_id
from .checkurl import build_check_url
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
from . import cscheck
from . import csconfig
from . import cshub

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


def _crowdsec_setup_post(config_path: str):
    """Save CrowdSec YAML or Guard path settings from the CrowdSec tab."""
    action = (request.form.get("action") or "").strip()
    extra = (request.form.get("extra") or request.args.get("extra") or "").strip()
    cfg = rt.RUNTIME.cfg if rt.RUNTIME else {}

    try:
        if action == "paths":
            disk = _load_yaml_file(config_path)
            cs = disk.get("crowdsec")
            if not isinstance(cs, dict):
                cs = {}
                disk["crowdsec"] = cs
            cs["config_dir"] = (request.form.get("config_dir") or "").strip() or csconfig.DEFAULT_CONFIG_DIR
            cs["bouncer_config"] = (
                request.form.get("bouncer_config") or ""
            ).strip() or csconfig.DEFAULT_BOUNCER_CONFIG
            _save_yaml_file(config_path, disk)
            if rt.RUNTIME:
                with rt.RUNTIME.lock:
                    live = rt.RUNTIME.cfg.get("crowdsec")
                    if not isinstance(live, dict):
                        live = {}
                        rt.RUNTIME.cfg["crowdsec"] = live
                    live["config_dir"] = cs["config_dir"]
                    live["bouncer_config"] = cs["bouncer_config"]
                rt.RUNTIME.request_reload()
            flash("Pfade gespeichert. YAML-Dateien unten neu einlesen.", "ok")
        elif action == "form":
            ok, msg = csconfig.save_document_form(cfg, request.form.get("doc") or "", request.form)
            flash(msg, "ok" if ok else "error")
        elif action == "raw":
            ok, msg = csconfig.save_document_raw(
                cfg, request.form.get("doc") or "", request.form.get("yaml_text") or ""
            )
            flash(msg, "ok" if ok else "error")
        elif action == "extra":
            extra = (request.form.get("extra") or "").strip()
            ok, msg = csconfig.save_extra_raw(cfg, extra, request.form.get("yaml_text") or "")
            flash(msg, "ok" if ok else "error")
        elif action == "collections":
            wanted = request.form.getlist("collection")
            ok, msg = cshub.sync_collections(cfg, wanted)
            flash(msg, "ok" if ok else "error")
        elif action == "scenarios":
            ok, msg = cshub.save_simulation(
                cfg,
                global_simulation=request.form.get("global_simulation") == "on",
                ban_enabled=request.form.getlist("scenario_ban"),
            )
            flash(msg, "ok" if ok else "error")
        else:
            flash("Unbekannte Aktion.", "error")
    except Exception as exc:
        log.exception("CrowdSec YAML save failed")
        flash(f"Speichern fehlgeschlagen: {exc}", "error")

    args = {"view": "setup"}
    if extra:
        args["extra"] = extra
    return redirect(url_for("crowdsec_page", **args))


def _persist_crowdsec_lapi_url(config_path: str, url: str) -> None:
    url = cscheck.normalize_lapi_url(url)
    if not url:
        return
    disk = _load_yaml_file(config_path)
    cs = disk.get("crowdsec")
    if not isinstance(cs, dict):
        cs = {}
        disk["crowdsec"] = cs
    if cs.get("lapi_url") == url:
        return
    cs["lapi_url"] = url
    _save_yaml_file(config_path, disk)
    if rt.RUNTIME:
        with rt.RUNTIME.lock:
            live = rt.RUNTIME.cfg.get("crowdsec")
            if not isinstance(live, dict):
                live = {}
                rt.RUNTIME.cfg["crowdsec"] = live
            live["lapi_url"] = url


def _crowdsec_run_check(lapi_url: str = "") -> dict:
    cfg = rt.RUNTIME.cfg if rt.RUNTIME else {}
    plugin = rt.RUNTIME.crowdsec if rt.RUNTIME else None
    hist_total = 0
    if rt.RUNTIME:
        snap = rt.RUNTIME.history.snapshot_crowdsec(window="24h")
        hist_total = int(snap.get("total") or 0)
    return cscheck.run_check(
        cfg,
        plugin_seen=bool(plugin.seen_plugin) if plugin else False,
        plugin_lines=int(plugin.lines_seen) if plugin else 0,
        plugin_blocks=int(plugin.blocks_parsed) if plugin else 0,
        history_blocks=hist_total,
        lapi_url=lapi_url,
    )


def _crowdsec_check_page(_config_path: str, check: Optional[dict] = None):
    cfg = rt.RUNTIME.cfg if rt.RUNTIME else {}
    mem = rt.RUNTIME.memory_state() if rt.RUNTIME else {}
    lapi_default = ""
    if check and check.get("lapi_url"):
        lapi_default = check["lapi_url"]
    else:
        lapi_default = cscheck.lapi_url_from_cfg(cfg)
    return render_template(
        "crowdsec.html",
        view="check",
        data=None,
        setup=None,
        check=check,
        lapi_default=lapi_default,
        mem=mem,
        time=time,
    )


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
        muted = False
        if rt.RUNTIME and isinstance(rt.RUNTIME.cfg, dict):
            alerts = rt.RUNTIME.cfg.get("alerts") or {}
            if isinstance(alerts, dict):
                muted = bool(alerts.get("muted"))
        return {"app_name": "Zoraxy Guard", "has_password": bool(password), "alerts_muted": muted}

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
        rid_in = (data.get("review_id") or data.get("id") or "").strip()
        resolved = None
        if not fp and rid_in:
            resolved = rt.RUNTIME.resolve_review_id(rid_in)
            if not resolved or not resolved.get("fingerprint"):
                return jsonify({"error": "unbekannte Prüf-ID", "review_id": rid_in}), 404
            fp = resolved["fingerprint"]
        if not fp:
            return jsonify({"error": "fingerprint oder Prüf-ID fehlt"}), 400
        note = (data.get("note") or "").strip()
        extra: dict = {}
        with rt.RUNTIME.lock:
            for rec in rt.RUNTIME.recent_alerts:
                if rec.get("fingerprint") == fp:
                    extra = rec
                    break
        title = (
            data.get("title")
            or (resolved or {}).get("title")
            or extra.get("title")
            or ""
        ).strip()
        origin = (
            data.get("origin")
            or (resolved or {}).get("origin")
            or extra.get("origin")
            or ""
        ).strip()
        path = (
            data.get("path")
            or (resolved or {}).get("path")
            or extra.get("path")
            or ""
        ).strip()
        entry = rt.RUNTIME.acks.ack(
            fp,
            title=title,
            origin=origin,
            path=path,
            note=note,
            client=(extra.get("client") or ""),
            method=(extra.get("method") or ""),
            status=extra.get("status"),
            check_url=(extra.get("check_url") or ""),
        )
        rt.RUNTIME.mark_alert_acked(fp)
        return jsonify({
            "ok": True,
            "fingerprint": fp,
            "review_id": review_id(fp),
            "ack": entry,
            "acked_count": rt.RUNTIME.acks.count(),
        })

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

    @app.route("/reviewed")
    @login_required
    def reviewed_page():
        if not rt.RUNTIME:
            flash("Runtime nicht bereit.", "error")
            return redirect(url_for("dashboard"))
        filters = {
            "q": (request.args.get("q") or "").strip(),
            "origin": (request.args.get("origin") or "").strip(),
            "path": (request.args.get("path") or "").strip(),
            "title": (request.args.get("title") or "").strip(),
            "review_id_q": (request.args.get("id") or "").strip(),
        }
        data = rt.RUNTIME.reviewed_view(**filters)
        return render_template(
            "reviewed.html",
            data=data,
            filters=filters,
            time=time,
        )

    @app.route("/reviewed/unack", methods=["POST"])
    @login_required
    def reviewed_unack():
        if not rt.RUNTIME:
            flash("Runtime nicht bereit.", "error")
            return redirect(url_for("dashboard"))
        fp = (request.form.get("fingerprint") or "").strip()
        if not fp:
            flash("Fingerprint fehlt.", "error")
            return redirect(url_for("reviewed_page"))
        ok = rt.RUNTIME.acks.unack(fp)
        with rt.RUNTIME.lock:
            for rec in rt.RUNTIME.recent_alerts:
                if rec.get("fingerprint") == fp:
                    rec["acked"] = False
                    if rec.get("risk"):
                        rec["risk"] = dict(rec["risk"])
        flash(
            "Alarmierung wieder aktiv — dieser Link wird erneut gemeldet." if ok else "Eintrag nicht gefunden.",
            "ok" if ok else "error",
        )
        args = {}
        for key in ("q", "origin", "path", "title", "id"):
            val = (request.form.get(key) or "").strip()
            if val:
                args[key] = val
        return redirect(url_for("reviewed_page", **args))

    @app.route("/api/checks/expect", methods=["POST"])
    @login_required
    def api_check_expect():
        """Register origin+path so the next matching request is ignored (one shot)."""
        if not rt.RUNTIME:
            return jsonify({"error": "runtime not ready"}), 503
        data = request.get_json(silent=True) or {}
        if request.form:
            data = {**data, **request.form.to_dict()}
        origin = (data.get("origin") or "").strip()
        path = (data.get("path") or "").strip() or "/"
        url = build_check_url(origin, path)
        if not url:
            return jsonify({"error": "keine prüfbare URL"}), 400
        pending = rt.RUNTIME.selfchecks.expect(origin, path)
        return jsonify({"ok": True, "pending": pending, "check_url": url})

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
        block_export_enabled = bool(
            (rt.RUNTIME.cfg.get("block_export") or {}).get("enabled")
        )
        return render_template(
            "history.html",
            data=data,
            mem=mem,
            time=time,
            backfill=backfill,
            backfill_hours=HOURS_OPTIONS,
            api_status_url=url_for("api_status"),
            block_export_enabled=block_export_enabled,
        )

    @app.route("/history/export-block", methods=["POST"])
    @login_required
    def history_export_block():
        """Export selected 'Handlungsbedarf' entries as JSON for manual import into
        the zoraxy-guard-blocker plugin (Sperren per Tag). No network call — file only."""
        if not rt.RUNTIME:
            flash("Runtime nicht bereit.", "error")
            return redirect(url_for("dashboard"))
        enabled = bool((rt.RUNTIME.cfg.get("block_export") or {}).get("enabled"))
        if not enabled:
            flash("Sperren-Export ist deaktiviert (siehe Konfiguration).", "error")
            return redirect(url_for("history_page"))

        raw = request.form.get("payload") or "[]"
        try:
            rows = json.loads(raw)
        except (TypeError, ValueError):
            rows = []
        if not isinstance(rows, list) or not rows:
            flash("Keine Einträge ausgewählt.", "error")
            return redirect(url_for("history_page"))

        entries = []
        seen = set()
        for row in rows:
            if not isinstance(row, dict):
                continue
            domain = (row.get("domain") or "").strip().lower().rstrip(".")
            path = (row.get("path") or "").strip() or "/"
            if not domain or not path:
                continue
            key = (domain, path)
            if key in seen:
                continue
            seen.add(key)
            status = row.get("status")
            try:
                status = int(status) if status not in (None, "") else None
            except (TypeError, ValueError):
                status = None
            try:
                ts = float(row.get("ts") or 0) or time.time()
            except (TypeError, ValueError):
                ts = time.time()
            entries.append(
                {
                    "domain": domain,
                    "path": path,
                    "method": (row.get("method") or "GET").strip().upper()[:10],
                    "status": status,
                    "note": (row.get("note") or "")[:200],
                    "ts": ts,
                }
            )

        if not entries:
            flash("Keine gültigen Einträge in der Auswahl.", "error")
            return redirect(url_for("history_page"))

        payload = {
            "format": "zoraxy-guard-blocker/import-v1",
            "source": "zoraxy-guard",
            "exported_at": time.time(),
            "entries": entries,
        }
        body = json.dumps(payload, indent=2, ensure_ascii=False) + "\n"
        filename = f"zoraxy-guard-block-export-{int(time.time())}.json"
        return Response(
            body,
            mimetype="application/json",
            headers={"Content-Disposition": f"attachment; filename={filename}"},
        )

    @app.route("/crowdsec", methods=["GET", "POST"])
    @login_required
    def crowdsec_page():
        if not rt.RUNTIME:
            flash("Runtime nicht bereit.", "error")
            return redirect(url_for("dashboard"))

        if request.method == "POST":
            if (request.form.get("action") or "").strip() == "check":
                lapi_url = (request.form.get("lapi_url") or "").strip()
                try:
                    _persist_crowdsec_lapi_url(config_path, lapi_url)
                except Exception:
                    log.exception("CrowdSec LAPI-URL speichern fehlgeschlagen")
                return _crowdsec_check_page(config_path, _crowdsec_run_check(lapi_url))
            return _crowdsec_setup_post(config_path)

        view = (request.args.get("view") or "blocks").strip().lower()
        if view not in ("blocks", "setup", "check"):
            view = "blocks"
        mem = rt.RUNTIME.memory_state()
        if view == "check":
            return _crowdsec_check_page(config_path)
        if view == "setup":
            extra = (request.args.get("extra") or "").strip()
            setup = csconfig.setup_context(rt.RUNTIME.cfg, extra_rel=extra)
            return render_template(
                "crowdsec.html",
                view="setup",
                data=None,
                setup=setup,
                mem=mem,
                time=time,
            )

        window = (request.args.get("w") or "1h").strip().lower()
        if window not in ("1h", "6h", "12h", "24h"):
            window = "1h"
        q = (request.args.get("q") or "").strip()
        data = rt.RUNTIME.history.snapshot_crowdsec(
            window=window,
            q=q,
            geo=rt.RUNTIME.geo,
            threats=rt.RUNTIME.threats,
        )
        data["plugin_seen"] = bool(rt.RUNTIME.crowdsec.seen_plugin)
        data["plugin_lines"] = int(rt.RUNTIME.crowdsec.lines_seen)
        data["plugin_blocks"] = int(rt.RUNTIME.crowdsec.blocks_parsed)
        return render_template(
            "crowdsec.html",
            view="blocks",
            data=data,
            setup=None,
            mem=mem,
            time=time,
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

                    if not isinstance(disk.get("block_export"), dict):
                        disk["block_export"] = {}
                    disk["block_export"]["enabled"] = request.form.get("block_export_enabled") == "on"

                    a = disk["alerts"]
                    a["min_severity"] = request.form.get("min_severity", "medium").strip()
                    a["notify_mode"] = normalize_mode(request.form.get("notify_mode", "action"))
                    a["notify_skip_acked"] = request.form.get("notify_skip_acked") == "on"
                    a["notify_skip_blocked"] = request.form.get("notify_skip_blocked") == "on"
                    a["muted"] = request.form.get("alerts_muted") == "on"
                    kinds = [k for k in request.form.getlist("notify_kinds") if k in DEFAULT_NOTIFY_KINDS]
                    a["notify_kinds"] = kinds
                    try:
                        a["cooldown_seconds"] = int(request.form.get("cooldown_seconds") or 300)
                    except ValueError:
                        a["cooldown_seconds"] = 300
                    try:
                        a["digest_window_seconds"] = int(request.form.get("digest_window_seconds") or 180)
                    except ValueError:
                        a["digest_window_seconds"] = 180
                    try:
                        a["digest_idle_seconds"] = int(request.form.get("digest_idle_seconds") or 15)
                    except ValueError:
                        a["digest_idle_seconds"] = 15
                    a["digest_window_seconds"] = max(0, min(3600, a["digest_window_seconds"]))
                    a["digest_idle_seconds"] = max(0, min(600, a["digest_idle_seconds"]))
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
                    if rt.RUNTIME:
                        rt.RUNTIME.set_alerts_muted(bool(a.get("muted")))

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
            notify_kinds=NOTIFY_KINDS,
            notify_kind_ids=DEFAULT_NOTIFY_KINDS,
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

    @app.route("/actions/mute-alerts", methods=["POST"])
    @login_required
    def action_mute_alerts():
        muted = request.form.get("alerts_muted") == "on"
        try:
            disk = _load_yaml_file(config_path)
            disk.setdefault("alerts", {})
            if not isinstance(disk["alerts"], dict):
                disk["alerts"] = {}
            disk["alerts"]["muted"] = muted
            _save_yaml_file(config_path, disk)
            if rt.RUNTIME:
                rt.RUNTIME.set_alerts_muted(muted)
            flash(
                "Alarmierung pausiert — kein Pushover/Discord/Telegram."
                if muted
                else "Alarmierung wieder aktiv.",
                "ok",
            )
        except Exception as exc:
            flash(f"Pause konnte nicht gespeichert werden: {exc}", "error")
        return redirect(url_for("dashboard"))

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
            kind="test",
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
            if rt.RUNTIME.alerter.send(alert, time.time(), force=True):
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
