"""
Guni Logger
Persists scan results to an audit log file.

In production (Railway/Docker): set GUNI_LOG_PATH=/tmp/guni_audit.log
In development: defaults to guni_audit.log in the working directory.
"""

import time
import json

from runtime_config import AUDIT_LOG_PATH


class GuniLogger:
    def __init__(self, log_path: str = None):
        self.log_path = log_path or AUDIT_LOG_PATH

    def log(self, result: dict):
        entry = {
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
            "url":       result.get("url", ""),
            "goal":      result.get("goal", ""),
            "risk":      result.get("risk"),
            "decision":  result.get("decision"),
            "latency":   result.get("total_latency", result.get("latency", 0)),
        }
        try:
            with open(self.log_path, "a", encoding="utf-8") as f:
                f.write(json.dumps(entry) + "\n")
        except OSError:
            # Non-fatal — in read-only filesystems just skip logging
            pass
