"""Shared logging helpers for backend modules."""

from __future__ import annotations

import logging


LOGGER_NAME = "guni"


def get_logger(name: str | None = None) -> logging.Logger:
    logger = logging.getLogger(LOGGER_NAME if not name else f"{LOGGER_NAME}.{name}")
    if not logging.getLogger(LOGGER_NAME).handlers:
        logging.basicConfig(
            level=logging.INFO,
            format="%(asctime)s %(levelname)s [%(name)s] %(message)s",
        )
    return logger
