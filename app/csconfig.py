"""CrowdSec YAML documents editable from the Guard web UI.

Designed as a registry: add YamlDoc entries to expose more files/fields later.
Guard never talks to cscli; it only reads/writes mounted YAML.
"""
from __future__ import annotations

import copy
import os
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

import yaml

from .fileio import write_text

DEFAULT_CONFIG_DIR = "/crowdsec-config"
DEFAULT_BOUNCER_CONFIG = "/crowdsec-bouncer/config.yaml"

CREDENTIAL_NAMES = frozenset(
    {
        "local_api_credentials.yaml",
        "online_api_credentials.yaml",
        "local_api_credentials.yml",
        "online_api_credentials.yml",
    }
)

YAML_SUFFIXES = {".yaml", ".yml"}

LOG_LEVELS = ("trace", "debug", "info", "warning", "error")


@dataclass(frozen=True)
class Field:
    """One form control mapped onto a YAML path (dotted)."""

    name: str
    yaml_path: str
    kind: str  # text | password | bool | select | list | ip_cidr_list | ips_cidrs | profile_duration
    label: str
    hint: str = ""
    help: str = ""
    options: Tuple[str, ...] = ()
    keep_if_empty: bool = False
    default: Any = None


@dataclass(frozen=True)
class YamlDoc:
    """A CrowdSec (or bouncer) YAML file the UI can edit."""

    id: str
    title: str
    hint: str
    restart: str
    help: str = ""
    relpath: str = ""  # under config_dir; unused for bouncer
    bouncer: bool = False
    create_if_missing: bool = False
    raw_only: bool = False
    fields: Tuple[Field, ...] = ()
    defaults: Dict[str, Any] = field(default_factory=dict)
    # Extra copies written with the same mapping (e.g. parser + postoverflow whitelist)
    also_relpaths: Tuple[str, ...] = ()


# --- registry (append here to expose more YAML later) -----------------------

DOCUMENTS: Tuple[YamlDoc, ...] = (
    YamlDoc(
        id="bouncer",
        title="Zoraxy-Bouncer",
        hint=(
            "Plugin-config.yaml des Zoraxy CrowdSec-Bouncers. "
            "log_level info ist nötig, damit «Request blocked» in den Zoraxy-Logs steht. "
            "Unraid-Images, die die Datei beim Start aus Env bauen, brauchen CROWDSEC_LOG_LEVEL=info."
        ),
        restart="Danach Zoraxy- bzw. Plugin-Container neu starten.",
        bouncer=True,
        create_if_missing=True,
        defaults={
            "api_key": "",
            "agent_url": "http://crowdsec:8080",
            "log_level": "info",
            "is_proxied_behind_cloudflare": False,
        },
        fields=(
            Field(
                "api_key",
                "api_key",
                "password",
                "API-Key",
                keep_if_empty=True,
                default="",
                help="Von CrowdSec: cscli bouncers add zoraxy-bouncer. Leer lassen behält den gespeicherten Key.",
            ),
            Field(
                "agent_url",
                "agent_url",
                "text",
                "CrowdSec LAPI (agent_url)",
                default="http://crowdsec:8080",
                help="URL der Local API aus Sicht von Zoraxy, z. B. http://crowdsec:8080.",
            ),
            Field(
                "log_level",
                "log_level",
                "select",
                "Log-Level",
                options=LOG_LEVELS,
                default="info",
                help="warning unterdrückt Block-Zeilen. Für die Auswertung info oder debug.",
            ),
            Field(
                "cloudflare",
                "is_proxied_behind_cloudflare",
                "bool",
                "Hinter Cloudflare (echte Client-IP)",
                default=False,
                help="Echte Besucher-IP statt Cloudflare-Edge, wenn Zoraxy hinter Cloudflare sitzt.",
            ),
        ),
    ),
    YamlDoc(
        id="engine",
        title="CrowdSec Engine (config.yaml)",
        hint="Zentrale Engine: Logs, LAPI, Community-Listen, Prometheus, DB.",
        help="Nur bekannte Schlüssel werden gesetzt. Community-Blocklists kommen über die Central API.",
        restart="Danach CrowdSec-Container neu starten.",
        relpath="config.yaml",
        create_if_missing=False,
        fields=(
            Field(
                "log_level",
                "common.log_level",
                "select",
                "Log-Level",
                options=LOG_LEVELS,
                default="info",
                help="Wie ausführlich CrowdSec selbst loggt (nicht der Zoraxy-Bouncer).",
            ),
            Field(
                "log_media",
                "common.log_media",
                "select",
                "Log-Ziel",
                options=("stdout", "file", "syslog"),
                default="stdout",
                help="Im Docker meist stdout. file schreibt nach log_dir.",
            ),
            Field(
                "listen_uri",
                "api.server.listen_uri",
                "text",
                "LAPI listen_uri",
                default="0.0.0.0:8080",
                help="Im Docker 0.0.0.0:8080, damit der Bouncer von außen verbindet.",
            ),
            Field(
                "forwarded_for",
                "api.server.use_forwarded_for_headers",
                "bool",
                "X-Forwarded-For auswerten",
                default=False,
                help="Nur hinter einem vertrauenswürdigen Proxy und mit Trusted IPs.",
            ),
            Field(
                "trusted_ips",
                "api.server.trusted_ips",
                "list",
                "Trusted IPs / CIDRs",
                default=["127.0.0.1", "::1"],
                help="Diese Netze dürfen die Admin-API nutzen bzw. Forwarded-For setzen.",
            ),
            Field(
                "capi_sharing",
                "api.server.online_client.sharing",
                "bool",
                "Signale an die Community senden",
                default=True,
                help="Lokale Detections anonymisiert an die CrowdSec Central API.",
            ),
            Field(
                "capi_community",
                "api.server.online_client.pull.community",
                "bool",
                "Community-Blocklist beziehen",
                default=True,
                help="Gemeinschafts-Liste böser IPs. Der Zoraxy-Bouncer blockt sie mit 403.",
            ),
            Field(
                "capi_blocklists",
                "api.server.online_client.pull.blocklists",
                "bool",
                "Console-Blocklists beziehen",
                default=True,
                help="Zusätzliche Listen aus der CrowdSec Console, sobald die Instanz enrolled ist.",
            ),
            Field(
                "usage_metrics",
                "api.server.disable_usage_metrics_export",
                "bool",
                "Nutzungsmetriken nicht senden",
                default=False,
                help="Wenn gesetzt, keine anonymen Nutzungsstatistiken an CrowdSec.",
            ),
            Field(
                "prometheus",
                "prometheus.enabled",
                "bool",
                "Prometheus-Metriken",
                default=True,
                help="Metriken für Grafana. Standard-Port 6060.",
            ),
            Field(
                "prom_level",
                "prometheus.level",
                "select",
                "Prometheus-Detail",
                options=("full", "aggregated"),
                default="full",
                help="full = alle Series, aggregated = weniger Cardinality.",
            ),
            Field(
                "db_max_items",
                "db_config.flush.max_items",
                "text",
                "DB: max. Alerts",
                default="5000",
                help="Ältere Alerts werden gelöscht, sobald diese Zahl überschritten ist.",
            ),
            Field(
                "db_max_age",
                "db_config.flush.max_age",
                "text",
                "DB: max. Alter",
                default="7d",
                help="Alerts älter als dieser Zeitraum (7d, 48h, …) werden entfernt.",
            ),
        ),
    ),
    YamlDoc(
        id="acquis",
        title="Log-Erfassung (acquis.d)",
        hint=(
            "Eigene Overlay-Datei acquis.d/zoraxy-guard.yaml. "
            "Pfade gelten im CrowdSec-Container, nicht in Guard."
        ),
        restart="Danach CrowdSec-Container neu starten.",
        relpath="acquis.d/zoraxy-guard.yaml",
        create_if_missing=True,
        defaults={
            "source": "file",
            "filenames": ["/var/log/zoraxy/*.log"],
            "labels": {"type": "syslog"},
        },
        fields=(
            Field(
                "source",
                "source",
                "select",
                "Quelle",
                options=("file", "syslog", "journalctl", "docker"),
                default="file",
                help="file = Dateien/Globs. syslog = Netz-Empfang. journalctl = systemd. docker = Container-Logs.",
            ),
            Field(
                "filenames",
                "filenames",
                "list",
                "Log-Dateien / Globs",
                default=["/var/log/zoraxy/*.log"],
                help="Eine pro Zeile. Pfad im CrowdSec-Container, nicht Guard /logs.",
            ),
            Field(
                "log_type",
                "labels.type",
                "text",
                "Parser-Typ (labels.type)",
                "z. B. syslog, nginx — nur wenn die passende Collection installiert ist.",
                default="syslog",
            ),
        ),
    ),
    YamlDoc(
        id="whitelist",
        title="Whitelist (IPs / CIDRs)",
        hint=(
            "Lokale Overlay-Parser, die diese IPs nicht bannen. "
            "Wird nach parsers/s02-enrich und postoverflows/s01-whitelist geschrieben."
        ),
        restart="Danach CrowdSec-Container neu starten.",
        relpath="parsers/s02-enrich/zoraxy-guard-whitelist.yaml",
        also_relpaths=("postoverflows/s01-whitelist/zoraxy-guard-whitelist.yaml",),
        create_if_missing=True,
        defaults={
            "name": "zoraxy-guard/whitelist",
            "description": "IPs/CIDRs never banned (Zoraxy Guard)",
            "filter": "true",
            "whitelist": {
                "reason": "trusted (Zoraxy Guard)",
                "ip": [],
                "cidr": [],
            },
        },
        fields=(
            Field(
                "entries",
                "whitelist",
                "ip_cidr_list",
                "IPs und CIDRs",
                "Eine pro Zeile. Mit / wird als CIDR gespeichert, sonst als IP.",
                default=[],
            ),
        ),
    ),
    YamlDoc(
        id="capi_wl",
        title="CAPI-Whitelist",
        hint="IPs, die trotz Community-/Console-Blocklist nicht gebannt werden.",
        help="capi_whitelists.yaml wirkt gegen bezogene CAPI-Listen. Neuere CrowdSec-Versionen nutzen zusätzlich Console-Allowlists.",
        restart="Danach CrowdSec-Container neu starten.",
        relpath="capi_whitelists.yaml",
        create_if_missing=True,
        defaults={"ips": [], "cidrs": []},
        fields=(
            Field(
                "entries",
                "ips",
                "ips_cidrs",
                "IPs und CIDRs",
                default=[],
                help="Eine pro Zeile. Mit / als CIDR. z. B. VPN-Ausgang, der sonst auf der Community-Liste landet.",
            ),
        ),
    ),
    YamlDoc(
        id="simulation",
        title="Simulation",
        hint="Alerts erzeugen, aber keine Ban-Decisions — zum Testen.",
        help="Global an = nichts bannen. Einzelne Scenarios stellst du unter «Scenarios / Ban» stumm.",
        restart="Danach CrowdSec-Container neu starten.",
        relpath="simulation.yaml",
        create_if_missing=True,
        defaults={"simulation": False},
        fields=(
            Field(
                "simulation",
                "simulation",
                "bool",
                "Alles nur simulieren (kein Ban)",
                default=False,
                help="CrowdSec erkennt weiter, der Bouncer bekommt aber keine Ban-Decisions.",
            ),
        ),
    ),
    YamlDoc(
        id="console",
        title="CrowdSec Console",
        hint="Was mit app.crowdsec.net geteilt und von dort gesteuert wird.",
        help="Enrollment (cscli console enroll) bleibt im CrowdSec-Container.",
        restart="Danach CrowdSec-Container neu starten.",
        relpath="console.yaml",
        create_if_missing=True,
        defaults={
            "share_manual_decisions": False,
            "share_custom": True,
            "share_tainted": True,
            "share_context": False,
            "console_management": False,
        },
        fields=(
            Field(
                "console_management",
                "console_management",
                "bool",
                "Decisions von der Console erlauben",
                default=False,
                help="Die Web-Console darf Bans setzen oder löschen (nur enrolled).",
            ),
            Field(
                "share_manual",
                "share_manual_decisions",
                "bool",
                "Manuelle Entscheidungen teilen",
                default=False,
                help="Von Hand gesetzte Bans an Console/Community.",
            ),
            Field(
                "share_tainted",
                "share_tainted",
                "bool",
                "Tainted Scenarios teilen",
                default=True,
                help="Detections aus veränderten Hub-Scenarios teilen.",
            ),
            Field(
                "share_custom",
                "share_custom",
                "bool",
                "Eigene Scenarios teilen",
                default=True,
                help="Detections aus selbst geschriebenen Scenarios teilen.",
            ),
            Field(
                "share_context",
                "share_context",
                "bool",
                "Alert-Kontext teilen",
                default=False,
                help="Zusätzliche Alert-Felder an die Console — kann Details enthalten.",
            ),
        ),
    ),
    YamlDoc(
        id="profiles",
        title="Profile (Ban-Dauer)",
        hint="Wie lange eine gebannte IP gesperrt bleibt (erstes Profil).",
        help="Das Formular ändert die duration der ersten Ban-Decision. Weitere Profile im Raw-YAML.",
        restart="Danach CrowdSec-Container neu starten.",
        relpath="profiles.yaml",
        create_if_missing=False,
        fields=(
            Field(
                "duration",
                "duration",
                "profile_duration",
                "Standard-Ban-Dauer",
                default="4h",
                help="z. B. 4h, 24h, 168h. Gilt für das erste Profil mit Ban-Decision.",
            ),
        ),
    ),
)

DOCS_BY_ID: Dict[str, YamlDoc] = {d.id: d for d in DOCUMENTS}


def crowdsec_section(cfg: Optional[dict]) -> dict:
    raw = (cfg or {}).get("crowdsec")
    return raw if isinstance(raw, dict) else {}


def config_dir(cfg: Optional[dict]) -> str:
    cs = crowdsec_section(cfg)
    val = (
        str(cs.get("config_dir") or "").strip()
        or (os.environ.get("CROWDSEC_CONFIG_DIR") or "").strip()
        or DEFAULT_CONFIG_DIR
    )
    return val.rstrip("/\\")


def bouncer_config(cfg: Optional[dict]) -> str:
    cs = crowdsec_section(cfg)
    return (
        str(cs.get("bouncer_config") or "").strip()
        or (os.environ.get("CROWDSEC_BOUNCER_CONFIG") or "").strip()
        or DEFAULT_BOUNCER_CONFIG
    )


def get_doc(doc_id: str) -> Optional[YamlDoc]:
    return DOCS_BY_ID.get((doc_id or "").strip())


def document_path(cfg: Optional[dict], doc: YamlDoc) -> Path:
    if doc.bouncer:
        return Path(bouncer_config(cfg))
    return Path(config_dir(cfg)) / doc.relpath


def _resolve(path: Path) -> Path:
    try:
        return path.resolve()
    except OSError:
        return path


def _is_under(child: Path, root: Path) -> bool:
    try:
        child_r = _resolve(child)
        root_r = _resolve(root)
        return child_r == root_r or root_r in child_r.parents
    except (OSError, ValueError):
        return False


def allowed_write_path(cfg: Optional[dict], target: Path) -> bool:
    """Only bouncer file or anything under config_dir, never credential files."""
    name = target.name.lower()
    if name in CREDENTIAL_NAMES:
        return False
    if target.suffix.lower() not in YAML_SUFFIXES:
        return False
    resolved = _resolve(target)
    bpath = _resolve(Path(bouncer_config(cfg)))
    if resolved == bpath:
        return True
    root = Path(config_dir(cfg))
    if not str(root):
        return False
    return _is_under(resolved, root)


def _nested_get(data: Any, dotted: str) -> Any:
    cur = data
    if not dotted:
        return cur
    for part in dotted.split("."):
        if not isinstance(cur, dict):
            return None
        cur = cur.get(part)
    return cur


def _nested_set(data: dict, dotted: str, value: Any) -> None:
    parts = [p for p in dotted.split(".") if p]
    if not parts:
        return
    cur: dict = data
    for p in parts[:-1]:
        nxt = cur.get(p)
        if not isinstance(nxt, dict):
            nxt = {}
            cur[p] = nxt
        cur = nxt
    cur[parts[-1]] = value


def parse_list(text: str) -> List[str]:
    items: List[str] = []
    for part in (text or "").replace(",", "\n").splitlines():
        part = part.strip()
        if part:
            items.append(part)
    return items


def list_as_text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, list):
        return "\n".join(str(x) for x in value)
    return str(value)


def _as_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if value is None:
        return False
    return str(value).strip().lower() in ("1", "true", "yes", "on")


def _ip_cidr_from_whitelist(data: dict) -> List[str]:
    wl = data.get("whitelist") if isinstance(data.get("whitelist"), dict) else {}
    ips = list(wl.get("ip") or []) if isinstance(wl, dict) else []
    cidrs = list(wl.get("cidr") or []) if isinstance(wl, dict) else []
    return [str(x) for x in ips] + [str(x) for x in cidrs]


def _apply_ip_cidr(data: dict, entries: Sequence[str]) -> None:
    ips: List[str] = []
    cidrs: List[str] = []
    for item in entries:
        (cidrs if "/" in item else ips).append(item)
    wl = data.get("whitelist")
    if not isinstance(wl, dict):
        wl = {}
        data["whitelist"] = wl
    wl["ip"] = ips
    wl["cidr"] = cidrs
    wl.setdefault("reason", "trusted (Zoraxy Guard)")
    data.setdefault("name", "zoraxy-guard/whitelist")
    data.setdefault("description", "IPs/CIDRs never banned (Zoraxy Guard)")
    data.setdefault("filter", "true")


def _ips_cidrs_from_data(data: dict) -> List[str]:
    ips = list(data.get("ips") or data.get("ip") or [])
    cidrs = list(data.get("cidrs") or data.get("cidr") or [])
    return [str(x) for x in ips] + [str(x) for x in cidrs]


def _apply_ips_cidrs(data: dict, entries: Sequence[str]) -> None:
    ips: List[str] = []
    cidrs: List[str] = []
    for item in entries:
        (cidrs if "/" in item else ips).append(item)
    data["ips"] = ips
    data["cidrs"] = cidrs


def _load_yaml_docs(path: Path) -> List[Any]:
    text = path.read_text(encoding="utf-8")
    docs = [d for d in yaml.safe_load_all(text) if d is not None]
    return docs


def _profiles_duration(docs: Sequence[Any]) -> str:
    for d in docs:
        items = d if isinstance(d, list) else [d]
        for item in items:
            if not isinstance(item, dict):
                continue
            for dec in item.get("decisions") or []:
                if isinstance(dec, dict) and dec.get("duration"):
                    return str(dec["duration"])
    return "4h"


def _set_profiles_duration(docs: List[Any], duration: str) -> List[Any]:
    duration = (duration or "4h").strip() or "4h"
    patched = False
    out: List[Any] = []
    for d in docs:
        if patched:
            out.append(d)
            continue
        if isinstance(d, list):
            for item in d:
                if patched or not isinstance(item, dict):
                    continue
                for dec in item.get("decisions") or []:
                    if isinstance(dec, dict) and "duration" in dec:
                        dec["duration"] = duration
                        patched = True
                        break
            out.append(d)
            continue
        if isinstance(d, dict):
            for dec in d.get("decisions") or []:
                if isinstance(dec, dict) and ("duration" in dec or dec.get("type") == "ban"):
                    dec["duration"] = duration
                    patched = True
                    break
        out.append(d)
    return out


def _dump_yaml_docs(docs: Sequence[Any]) -> str:
    chunks = [dump_yaml(d).rstrip() for d in docs]
    return "\n---\n".join(chunks) + "\n"


def apply_fields(doc: YamlDoc, data: dict, form: dict) -> dict:
    """Patch known fields onto an existing mapping; unknown keys stay."""
    if not isinstance(data, dict):
        data = {}
    for fld in doc.fields:
        raw = form.get(fld.name)
        if fld.kind == "profile_duration":
            continue
        if fld.kind == "bool":
            # checkbox: missing means false
            _nested_set(data, fld.yaml_path, raw in ("on", "true", "1", "yes", True))
            continue
        if fld.kind == "password" and fld.keep_if_empty and not str(raw or "").strip():
            continue
        if fld.kind == "list":
            _nested_set(data, fld.yaml_path, parse_list(str(raw or "")))
            continue
        if fld.kind == "ip_cidr_list":
            _apply_ip_cidr(data, parse_list(str(raw or "")))
            continue
        if fld.kind == "ips_cidrs":
            _apply_ips_cidrs(data, parse_list(str(raw or "")))
            continue
        if fld.kind == "select":
            val = str(raw or "").strip() or str(fld.default or "")
            if fld.options and val not in fld.options:
                val = str(fld.default or (fld.options[0] if fld.options else val))
            _nested_set(data, fld.yaml_path, val)
            continue
        text = "" if raw is None else str(raw).strip()
        if fld.name in ("db_max_items",):
            try:
                _nested_set(data, fld.yaml_path, int(text or fld.default or 0))
                continue
            except ValueError:
                pass
        _nested_set(data, fld.yaml_path, text)
    return data


def dump_yaml(data: Any) -> str:
    return yaml.safe_dump(
        data, sort_keys=False, allow_unicode=True, default_flow_style=False
    )


def load_yaml(path: Path) -> Any:
    text = path.read_text(encoding="utf-8")
    loaded = yaml.safe_load(text)
    return {} if loaded is None else loaded


def _backup(path: Path) -> None:
    if not path.is_file():
        return
    bak = path.with_name(path.name + ".bak")
    try:
        bak.write_text(path.read_text(encoding="utf-8"), encoding="utf-8")
    except OSError:
        pass


def _parent_writable(path: Path) -> bool:
    parent = path.parent
    return parent.is_dir() and os.access(parent, os.W_OK)


def can_create(path: Path, root: Optional[Path] = None) -> bool:
    if path.exists():
        return path.is_file() and os.access(path, os.W_OK)
    if _parent_writable(path):
        return True
    if root and root.is_dir() and os.access(root, os.W_OK) and _is_under(path, root):
        return True
    return False


def path_status(path: Path, *, root: Optional[Path] = None, create: bool = False) -> dict:
    exists = path.exists()
    is_file = path.is_file()
    writable = False
    if is_file:
        writable = os.access(path, os.W_OK)
    elif create:
        writable = can_create(path, root)
    mtime = ""
    if is_file:
        try:
            mtime = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(path.stat().st_mtime))
        except OSError:
            mtime = ""
    return {
        "path": str(path),
        "exists": exists,
        "is_file": is_file,
        "writable": writable,
        "mtime": mtime,
        "missing": not exists,
    }


def _write_mapping(path: Path, data: dict, *, root: Optional[Path] = None) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    _backup(path)
    write_text(str(path), dump_yaml(data))


def save_document_form(cfg: Optional[dict], doc_id: str, form: dict) -> Tuple[bool, str]:
    doc = get_doc(doc_id)
    if not doc:
        return False, "Unbekanntes YAML-Dokument."
    if doc.raw_only:
        return False, "Diese Datei nur als Raw YAML speichern."
    path = document_path(cfg, doc)
    if not allowed_write_path(cfg, path):
        return False, f"Pfad nicht erlaubt: {path}"
    if doc.id == "profiles":
        return save_profiles_duration(cfg, str(form.get("duration") or "4h"))
    root = Path(config_dir(cfg)) if not doc.bouncer else None
    data: dict = {}
    if path.is_file():
        loaded = load_yaml(path)
        if not isinstance(loaded, dict):
            return False, "Datei ist keine YAML-Map — Raw YAML verwenden."
        data = loaded
    elif doc.create_if_missing and can_create(path, root):
        data = copy.deepcopy(doc.defaults) if doc.defaults else {}
    elif not path.exists():
        return False, (
            f"Datei nicht gefunden: {path}. "
            "CrowdSec- bzw. Bouncer-Pfad in Unraid mounten."
        )
    else:
        return False, f"Nicht schreibbar: {path}"

    apply_fields(doc, data, form)
    try:
        _write_mapping(path, data, root=root)
        for rel in doc.also_relpaths:
            extra = Path(config_dir(cfg)) / rel
            if not allowed_write_path(cfg, extra):
                continue
            _write_mapping(extra, data, root=root)
    except OSError as exc:
        return False, f"Speichern fehlgeschlagen: {exc}"
    return True, f"{doc.title} gespeichert. {doc.restart}"


def save_profiles_duration(cfg: Optional[dict], duration: str) -> Tuple[bool, str]:
    path = Path(config_dir(cfg)) / "profiles.yaml"
    if not path.is_file():
        return False, f"profiles.yaml nicht gefunden: {path}"
    if not allowed_write_path(cfg, path):
        return False, f"Pfad nicht erlaubt: {path}"
    try:
        docs = _load_yaml_docs(path)
        docs = _set_profiles_duration(docs, duration)
        _backup(path)
        write_text(str(path), _dump_yaml_docs(docs))
    except OSError as exc:
        return False, f"Speichern fehlgeschlagen: {exc}"
    return True, "Ban-Dauer gespeichert. CrowdSec-Container neu starten."


def save_document_raw(cfg: Optional[dict], doc_id: str, text: str) -> Tuple[bool, str]:
    doc = get_doc(doc_id)
    if not doc:
        return False, "Unbekanntes YAML-Dokument."
    path = document_path(cfg, doc)
    return save_raw_path(cfg, path, text, create=doc.create_if_missing, title=doc.title, restart=doc.restart)


def save_raw_path(
    cfg: Optional[dict],
    path: Path,
    text: str,
    *,
    create: bool = False,
    title: str = "YAML",
    restart: str = "",
) -> Tuple[bool, str]:
    if not allowed_write_path(cfg, path):
        return False, f"Pfad nicht erlaubt: {path}"
    try:
        loaded = yaml.safe_load(text or "")
    except yaml.YAMLError as exc:
        return False, f"Ungültiges YAML: {exc}"
    if loaded is None:
        loaded = {}
    if not isinstance(loaded, (dict, list)):
        return False, "YAML-Wurzel muss ein Mapping oder eine Liste sein."
    root = Path(config_dir(cfg))
    if not path.exists() and not (create and can_create(path, root)):
        return False, f"Datei nicht gefunden: {path}"
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        _backup(path)
        body = text if text.endswith("\n") else (text + "\n")
        write_text(str(path), body)
    except OSError as exc:
        return False, f"Speichern fehlgeschlagen: {exc}"
    extra = f" {restart}" if restart else ""
    return True, f"{title} gespeichert.{extra}"


def save_extra_raw(cfg: Optional[dict], rel: str, text: str) -> Tuple[bool, str]:
    rel_n = _normalize_rel(rel)
    if not rel_n:
        return False, "Ungültiger Dateipfad."
    path = Path(config_dir(cfg)) / rel_n
    return save_raw_path(cfg, path, text, create=False, title=rel_n)


def _normalize_rel(rel: str) -> str:
    rel = (rel or "").replace("\\", "/").strip().lstrip("/")
    if not rel or ".." in Path(rel).parts:
        return ""
    p = Path(rel)
    if p.suffix.lower() not in YAML_SUFFIXES:
        return ""
    if p.name.lower() in CREDENTIAL_NAMES:
        return ""
    return str(p).replace("\\", "/")


def field_value(doc: YamlDoc, fld: Field, data: Any) -> Any:
    if fld.kind == "profile_duration":
        return None
    if not isinstance(data, dict):
        data = {}
    if fld.kind == "ip_cidr_list":
        return _ip_cidr_from_whitelist(data)
    if fld.kind == "ips_cidrs":
        return _ips_cidrs_from_data(data)
    val = _nested_get(data, fld.yaml_path)
    if val is None:
        return fld.default
    return val


def document_view(cfg: Optional[dict], doc: YamlDoc) -> dict:
    path = document_path(cfg, doc)
    root = None if doc.bouncer else Path(config_dir(cfg))
    st = path_status(path, root=root, create=doc.create_if_missing)
    data: Any = None
    yaml_text = ""
    load_error = ""
    mapping = False
    if path.is_file():
        try:
            yaml_text = path.read_text(encoding="utf-8")
            if doc.id == "profiles":
                docs = _load_yaml_docs(path)
                data = docs[0] if docs else {}
                mapping = True
            else:
                data = load_yaml(path)
                mapping = isinstance(data, dict)
        except Exception as exc:
            load_error = str(exc)
            data = None
    elif doc.create_if_missing and doc.defaults:
        data = copy.deepcopy(doc.defaults)
        mapping = True
        yaml_text = dump_yaml(data)

    fields_out = []
    for fld in doc.fields:
        if fld.kind == "profile_duration":
            shown = _profiles_duration(_load_yaml_docs(path)) if path.is_file() else str(fld.default or "4h")
        else:
            val = field_value(doc, fld, data if isinstance(data, dict) else {})
            if fld.kind in ("list", "ip_cidr_list", "ips_cidrs"):
                shown = list_as_text(val)
            elif fld.kind == "bool":
                shown = _as_bool(val)
            elif fld.kind == "password":
                shown = "" if fld.keep_if_empty else ("" if val is None else str(val))
            else:
                shown = "" if val is None else str(val)
        options = list(fld.options)
        if fld.kind == "select" and shown and shown not in options:
            options = [shown] + options
        secret_set = False
        if fld.kind == "password":
            existing = _nested_get(data, fld.yaml_path) if isinstance(data, dict) else None
            secret_set = bool(str(existing or "").strip())
        fields_out.append(
            {
                "name": fld.name,
                "kind": fld.kind,
                "label": fld.label,
                "hint": fld.hint,
                "help": fld.help,
                "value": shown,
                "options": options,
                "secret_set": secret_set,
            }
        )

    return {
        "id": doc.id,
        "title": doc.title,
        "hint": doc.hint,
        "help": doc.help,
        "restart": doc.restart,
        "raw_only": doc.raw_only or (data is not None and not mapping and not load_error),
        "create_if_missing": doc.create_if_missing,
        "load_error": load_error,
        "yaml_text": yaml_text,
        "fields": fields_out,
        **st,
    }


def list_collections(cfg: Optional[dict]) -> List[dict]:
    root = Path(config_dir(cfg)) / "collections"
    if not root.is_dir():
        return []
    items: List[dict] = []
    files = sorted(root.glob("*.yaml")) + sorted(root.glob("*.yml"))
    for p in files:
        name = p.stem
        try:
            loaded = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
            if isinstance(loaded, dict) and loaded.get("name"):
                name = str(loaded["name"])
        except Exception:
            pass
        items.append(
            {
                "file": p.name,
                "name": name,
                "rel": f"collections/{p.name}",
            }
        )
    return items


def _iter_yaml_under(root: Path, *, max_files: int = 150) -> Iterable[Path]:
    if not root.is_dir():
        return
    skip_dirs = {".git", "hub", "data", "__pycache__"}
    n = 0
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in skip_dirs and not d.startswith(".")]
        # keep walk shallow-ish: parsers/s02-enrich is depth 2
        rel_dir = os.path.relpath(dirpath, root)
        depth = 0 if rel_dir == "." else rel_dir.count(os.sep) + 1
        if depth > 3:
            dirnames[:] = []
            continue
        for name in sorted(filenames):
            p = Path(dirpath) / name
            if p.suffix.lower() not in YAML_SUFFIXES:
                continue
            if name.lower() in CREDENTIAL_NAMES:
                continue
            yield p
            n += 1
            if n >= max_files:
                return


def list_extra_files(cfg: Optional[dict]) -> List[dict]:
    root = Path(config_dir(cfg))
    if not root.is_dir():
        return []
    managed = set()
    for doc in DOCUMENTS:
        if doc.bouncer:
            continue
        managed.add(_resolve(document_path(cfg, doc)))
        for rel in doc.also_relpaths:
            managed.add(_resolve(root / rel))
    out: List[dict] = []
    for p in _iter_yaml_under(root):
        if _resolve(p) in managed:
            continue
        rel = p.relative_to(root).as_posix()
        if rel.startswith("collections/"):
            continue
        out.append({"rel": rel, "name": p.name})
    out.sort(key=lambda x: x["rel"])
    return out


def extra_file_view(cfg: Optional[dict], rel: str) -> Optional[dict]:
    rel_n = _normalize_rel(rel)
    if not rel_n:
        return None
    path = Path(config_dir(cfg)) / rel_n
    if not _is_under(path, Path(config_dir(cfg))):
        return None
    st = path_status(path, root=Path(config_dir(cfg)), create=False)
    yaml_text = ""
    load_error = ""
    if path.is_file():
        try:
            yaml_text = path.read_text(encoding="utf-8")
        except OSError as exc:
            load_error = str(exc)
    return {"rel": rel_n, "yaml_text": yaml_text, "load_error": load_error, **st}


def setup_context(cfg: Optional[dict], extra_rel: str = "") -> dict:
    from . import cshub

    docs = [document_view(cfg, d) for d in DOCUMENTS]
    extra_files = list_extra_files(cfg)
    chosen = extra_rel or (extra_files[0]["rel"] if extra_files else "")
    extra = extra_file_view(cfg, chosen) if chosen else None
    cdir = Path(config_dir(cfg))
    bpath = Path(bouncer_config(cfg))
    hub = cshub.hub_view(cfg)
    return {
        "config_dir": str(cdir),
        "bouncer_config": str(bpath),
        "config_dir_status": path_status(cdir),
        "bouncer_status": path_status(bpath, create=True),
        "documents": docs,
        "collections": list_collections(cfg),
        "hub": hub,
        "extra_files": extra_files,
        "extra": extra,
    }
