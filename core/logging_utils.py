"""Logging helpers for PrivateTunnel."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Optional


def _build_formatter() -> logging.Formatter:
    return logging.Formatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s")


def setup_logging(log_dir: str | Path, log_name: str = "privatetunnel") -> logging.Logger:
    """Initialize console and file logging.

    Parameters
    ----------
    log_dir:
        Directory where log files will be stored.
    log_name:
        Base name of the log file without extension.

    Returns
    -------
    logging.Logger
        Configured root logger instance.
    """

    log_directory = Path(log_dir)
    log_directory.mkdir(parents=True, exist_ok=True)
    log_file = log_directory / f"{log_name}.log"

    logger = logging.getLogger("privatetunnel")
    logger.setLevel(logging.INFO)

    # Avoid attaching duplicate handlers in case of repeated initialization.
    existing_handlers = {type(handler) for handler in logger.handlers}

    formatter = _build_formatter()

    if logging.StreamHandler not in existing_handlers:
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(formatter)
        logger.addHandler(console_handler)

    if logging.FileHandler not in existing_handlers:
        file_handler = logging.FileHandler(log_file, encoding="utf-8")
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)

    logger.debug("Logging initialized", extra={"log_file": str(log_file)})
    return logger


def get_logger(name: Optional[str] = None) -> logging.Logger:
    """Return a namespaced logger under the ``privatetunnel`` hierarchy."""

    base = logging.getLogger("privatetunnel")
    return base.getChild(name) if name else base
