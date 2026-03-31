"""
Shared runtime configuration for filesystem-backed state.

This keeps Railway/dev paths consistent across the API, logger, and key store
while avoiding accidental writes into the repository root.
"""

from __future__ import annotations

import os
from pathlib import Path


def _on_railway() -> bool:
    markers = (
        os.environ.get("RAILWAY_ENVIRONMENT"),
        os.environ.get("RAILWAY_PROJECT_ID"),
        os.environ.get("RAILWAY_SERVICE_ID"),
    )
    return any((marker or "").strip() for marker in markers)


def _default_data_dir() -> Path:
    explicit_data_dir = os.environ.get("GUNI_DATA_DIR")
    if explicit_data_dir:
        return Path(explicit_data_dir)

    railway_volume = os.environ.get("RAILWAY_VOLUME_MOUNT_PATH")
    if railway_volume:
        return Path(railway_volume) / "guni"

    if _on_railway():
        for candidate in ("/data/guni", "/mnt/data/guni", "/var/data/guni"):
            candidate_path = Path(candidate)
            parent = candidate_path.parent
            if parent.exists():
                return candidate_path

    return Path(".guni")


DATA_DIR = Path(os.environ.get("GUNI_DATA_DIR", _default_data_dir())).resolve()
DATA_DIR.mkdir(parents=True, exist_ok=True)

DB_PATH = os.environ.get("GUNI_DB_PATH", str(DATA_DIR / "guni.db"))
MONGO_URI = os.environ.get("GUNI_MONGO_URI", os.environ.get("MONGO_URI", ""))
MONGO_DB_NAME = os.environ.get("GUNI_MONGO_DB_NAME", "guni")
KEYS_PATH = os.environ.get("GUNI_KEYS_PATH", str(DATA_DIR / "guni_keys.json"))
AUDIT_LOG_PATH = os.environ.get("GUNI_LOG_PATH", str(DATA_DIR / "guni_audit.log"))
WAITLIST_PATH = os.environ.get("GUNI_WAITLIST_PATH", str(DATA_DIR / "guni_waitlist.json"))
EVENT_LOG_PATH = os.environ.get("GUNI_EVENT_LOG_PATH", str(DATA_DIR / "events.json"))
