"""Shared helpers: atomic writes, hashing, canonical JSON, timestamps, semgrep lookup."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path


def atomic_write_bytes(path, data: bytes) -> None:
    """Write data to path via a temp file in the same directory and os.replace.

    On any failure the temp file is removed and the target is left untouched.
    """
    path = Path(path)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.", suffix=".tmp")
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except FileNotFoundError:
            pass
        raise


def atomic_write_text(path, text: str) -> None:
    atomic_write_bytes(path, text.encode("utf-8"))


def atomic_write_json(path, obj) -> None:
    text = json.dumps(obj, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    atomic_write_text(path, text)


def canonical_json(obj) -> bytes:
    return json.dumps(
        obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def utc_stamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def semgrep_bin() -> str | None:
    """Prefer the semgrep next to sys.executable (the pinned venv copy), then PATH."""
    local = Path(sys.executable).parent / "semgrep"
    if local.is_file() and os.access(local, os.X_OK):
        return str(local)
    return shutil.which("semgrep")
