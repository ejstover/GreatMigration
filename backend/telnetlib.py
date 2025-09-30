"""Compatibility shim for Python 3.13+ where :mod:`telnetlib` was removed.

Netmiko still imports :mod:`telnetlib` at module import time even when only
SSH transports are used. The original stdlib module was removed in Python
3.13, which would otherwise raise :class:`ModuleNotFoundError` and prevent
Netmiko from being imported at all. This lightweight stub satisfies the import
while making it clear that Telnet functionality is unavailable in this
environment.
"""
from __future__ import annotations

from typing import Any


class _UnsupportedTelnet:
    """Placeholder that raises a helpful error when instantiated."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:  # pragma: no cover - trivial
        raise ModuleNotFoundError(
            "telnetlib support is not available in this environment. Netmiko SSH "
            "features remain functional, but Telnet connections are unsupported."
        )


Telnet = _UnsupportedTelnet
__all__ = ["Telnet"]
