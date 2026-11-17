"""Utilities for centralized user action logging."""
from __future__ import annotations

import logging
import os
import json
from datetime import datetime, date
from logging.handlers import SysLogHandler
from pathlib import Path
from typing import Optional, TextIO

LOG_DIR = Path(__file__).resolve().parent / "logs"
LOG_DIR.mkdir(parents=True, exist_ok=True)
os.chmod(LOG_DIR, 0o700)

_LOGGER_NAME = "great_migration.user_actions"


class SafeFormatter(logging.Formatter):
    """Keep every event on one physical line, including untrusted identities."""
    def format(self, record):
        rendered = logging.makeLogRecord(record.__dict__.copy())
        summary = getattr(record, "audit_summary", None)
        if getattr(record, "event_type", None) == "audit_run" and isinstance(summary, dict):
            prefix = "event=audit_run audit_data=" + json.dumps(summary, ensure_ascii=True, separators=(",", ":")) + " "
        else:
            prefix = "event=application "
        rendered.msg = prefix + record.getMessage()
        rendered.args = ()
        return super().format(rendered).replace("\r", "\\r").replace("\n", "\\n").replace("\u2028", "\\u2028").replace("\u2029", "\\u2029")


class DailyFileHandler(logging.Handler):
    """A logging handler that writes to a daily log file (ddmmyyyy.log)."""

    def __init__(self, directory: Path):
        super().__init__()
        self._directory = directory
        self._directory.mkdir(parents=True, exist_ok=True)
        self._current_date: Optional[date] = None
        self._stream: Optional[TextIO] = None

    def emit(self, record: logging.LogRecord) -> None:  # pragma: no cover - thin wrapper
        try:
            record_date = datetime.fromtimestamp(record.created).date()
            if self._stream is None or self._current_date != record_date:
                if self._stream:
                    try:
                        self._stream.close()
                    except Exception:
                        pass
                filename = datetime.fromtimestamp(record.created).strftime("%d%m%Y.log")
                path = self._directory / filename
                self._stream = path.open("a", encoding="utf-8")
                self._current_date = record_date

            msg = self.format(record)
            assert self._stream is not None  # for type-checkers
            self._stream.write(msg + "\n")
            self._stream.flush()
        except Exception:
            self.handleError(record)

    def close(self) -> None:
        try:
            if self._stream:
                self._stream.close()
        finally:
            self._stream = None
            super().close()


def _create_syslog_handler(formatter: logging.Formatter) -> Optional[logging.Handler]:
    host = (os.getenv("SYSLOG_HOST") or os.getenv("SYSLOG_SERVER") or "").strip()
    if not host:
        return None

    port_raw = os.getenv("SYSLOG_PORT", "514").strip()
    try:
        port = int(port_raw)
    except ValueError:
        port = 514

    try:
        handler = SysLogHandler(address=(host, port))
    except OSError as exc:
        logging.getLogger(__name__).warning(
            "Failed to configure syslog handler for %s:%s: %s",
            host,
            port,
            exc,
        )
        return None

    handler.setFormatter(formatter)
    handler.setLevel(logging.INFO)
    return handler


def _configure_logger() -> logging.Logger:
    logger = logging.getLogger(_LOGGER_NAME)
    logger.setLevel(logging.INFO)
    logger.propagate = False
    if logger.handlers:
        return logger

    formatter = SafeFormatter("%(asctime)s | %(levelname)s | %(message)s")

    file_handler = DailyFileHandler(LOG_DIR)
    file_handler.setFormatter(formatter)
    file_handler.setLevel(logging.INFO)
    logger.addHandler(file_handler)

    syslog_handler = _create_syslog_handler(formatter)
    if syslog_handler:
        logger.addHandler(syslog_handler)

    return logger


_USER_LOGGER = _configure_logger()


def get_user_logger() -> logging.Logger:
    """Return the shared logger used for user action auditing."""
    return _USER_LOGGER


def log_user_action(message: str, *, level: int = logging.INFO) -> None:
    """Convenience helper to log a user action message."""
    _USER_LOGGER.log(level, message)


__all__ = ["get_user_logger", "log_user_action", "LOG_DIR", "DailyFileHandler"]
