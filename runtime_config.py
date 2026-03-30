"""
Shared runtime configuration for filesystem-backed state.

This keeps Railway/dev paths consistent across the API, logger, and key store
while avoiding accidental writes into the repository root.
"""

from __future__ import annotations

import os
from pathlib import Path


def _default_data_dir() -> Path:
    explicit_tmp = os.environ.get("RAILWAY_VOLUME_MOUNT_PATH")
    if explicit_tmp:
        return Path(explicit_tmp) / "guni"
    return Path(os.environ.get("GUNI_DATA_DIR", ".guni"))


DATA_DIR = Path(os.environ.get("GUNI_DATA_DIR", _default_data_dir())).resolve()
DATA_DIR.mkdir(parents=True, exist_ok=True)

DB_PATH = os.environ.get("GUNI_DB_PATH", str(DATA_DIR / "guni.db"))
KEYS_PATH = os.environ.get("GUNI_KEYS_PATH", str(DATA_DIR / "guni_keys.json"))
AUDIT_LOG_PATH = os.environ.get("GUNI_LOG_PATH", str(DATA_DIR / "guni_audit.log"))
WAITLIST_PATH = os.environ.get("GUNI_WAITLIST_PATH", str(DATA_DIR / "guni_waitlist.json"))
EVENT_LOG_PATH = os.environ.get("GUNI_EVENT_LOG_PATH", str(DATA_DIR / "events.json"))
