"""File write helpers robust on Docker/Unraid single-file bind mounts."""

from __future__ import annotations

import errno
import os
from pathlib import Path


def write_text(path: str, text: str, encoding: str = "utf-8") -> None:
    """
    Write text to path.

    Prefer direct in-place write: Docker file bind mounts
    (e.g. host/.../config.yaml -> /config/config.yaml) cannot be replaced
    via rename (EBUSY / Errno 16). Temp+replace is still attempted when the
    target does not exist yet, then falls back to direct write.
    """
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)

    # Always write in place into the final path — works for directory volumes
    # and for single-file bind mounts.
    with open(path, "w", encoding=encoding) as fh:
        fh.write(text)
        fh.flush()
        try:
            os.fsync(fh.fileno())
        except OSError:
            pass


def write_text_atomic(path: str, text: str, encoding: str = "utf-8") -> None:
    """Best-effort atomic write; falls back to in-place on EBUSY/EXDEV."""
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = str(p) + ".tmp"
    with open(tmp, "w", encoding=encoding) as fh:
        fh.write(text)
        fh.flush()
        try:
            os.fsync(fh.fileno())
        except OSError:
            pass
    try:
        os.replace(tmp, path)
    except OSError as exc:
        # Docker single-file mounts, cross-device, busy renames
        if getattr(exc, "errno", None) in (errno.EBUSY, errno.EXDEV, 16):
            try:
                write_text(path, text, encoding=encoding)
            finally:
                try:
                    os.unlink(tmp)
                except OSError:
                    pass
            return
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
