"""Build browser URLs to verify an alert target (origin + path)."""

from __future__ import annotations

from urllib.parse import quote, urlsplit, urlunsplit

from .iputil import parse_ip


def build_check_url(origin: str, path: str = "", *, prefer_https: bool = True) -> str:
    """
    https://host/path for opening in browser.
    Returns empty string if origin is missing or not a usable host/IP.
    """
    origin = (origin or "").strip().rstrip(".")
    path = (path or "").strip()
    if not origin or origin == "-":
        return ""

    scheme = "https" if prefer_https else "http"
    host = origin
    port = ""

    if "://" in origin:
        parts = urlsplit(origin)
        scheme = parts.scheme or scheme
        host = parts.hostname or ""
        if parts.port:
            port = str(parts.port)
        if parts.path and parts.path != "/":
            # origin already includes path prefix — rare in zoraxy logs
            path = parts.path + (path if path.startswith("/") else ("/" + path if path else ""))
    else:
        # host:port in origin field
        if origin.count(":") == 1 and not origin.startswith("["):
            host_part, maybe_port = origin.rsplit(":", 1)
            if maybe_port.isdigit():
                host = host_part
                port = maybe_port

    host = host.strip("[]")
    if not host:
        return ""

    ip = parse_ip(host)
    if ip and ip.is_private:
        scheme = "http"

    if not path:
        path = "/"
    elif not path.startswith("/"):
        path = "/" + path

    netloc = f"[{host}]" if ":" in host and not host.startswith("[") else host
    if port:
        netloc = f"{netloc}:{port}"

    return urlunsplit((scheme, netloc, quote(path, safe="/?:&=%+#"), "", ""))
