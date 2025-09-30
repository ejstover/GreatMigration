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


# Selected constants copied from the CPython 3.12 telnetlib module so that
# libraries performing ``from telnetlib import DO`` (and similar) continue to
# work even though Telnet support itself is disabled.
_CONSTANTS: dict[str, object] = {
    "DEBUGLEVEL": 0,
    "TELNET_PORT": 23,
    "IAC": bytes([255]),
    "DONT": bytes([254]),
    "DO": bytes([253]),
    "WONT": bytes([252]),
    "WILL": bytes([251]),
    "SE": bytes([240]),
    "NOP": bytes([241]),
    "DM": bytes([242]),
    "BRK": bytes([243]),
    "IP": bytes([244]),
    "AO": bytes([245]),
    "AYT": bytes([246]),
    "EC": bytes([247]),
    "EL": bytes([248]),
    "GA": bytes([249]),
    "SB": bytes([250]),
    "BINARY": bytes([0]),
    "ECHO": bytes([1]),
    "RCP": bytes([2]),
    "SGA": bytes([3]),
    "NAMS": bytes([4]),
    "STATUS": bytes([5]),
    "TM": bytes([6]),
    "RCTE": bytes([7]),
    "NAOL": bytes([8]),
    "NAOP": bytes([9]),
    "NAOCRD": bytes([10]),
    "NAOHTS": bytes([11]),
    "NAOHTD": bytes([12]),
    "NAOFFD": bytes([13]),
    "NAOVTS": bytes([14]),
    "NAOVTD": bytes([15]),
    "NAOLFD": bytes([16]),
    "XASCII": bytes([17]),
    "LOGOUT": bytes([18]),
    "BM": bytes([19]),
    "DET": bytes([20]),
    "SUPDUP": bytes([21]),
    "SUPDUPOUTPUT": bytes([22]),
    "SNDLOC": bytes([23]),
    "TTYPE": bytes([24]),
    "EOR": bytes([25]),
    "TUID": bytes([26]),
    "OUTMRK": bytes([27]),
    "TTYLOC": bytes([28]),
    "VT3270REGIME": bytes([29]),
    "X3PAD": bytes([30]),
    "NAWS": bytes([31]),
    "TSPEED": bytes([32]),
    "LFLOW": bytes([33]),
    "LINEMODE": bytes([34]),
    "XDISPLOC": bytes([35]),
    "OLD_ENVIRON": bytes([36]),
    "AUTHENTICATION": bytes([37]),
    "ENCRYPT": bytes([38]),
    "NEW_ENVIRON": bytes([39]),
    "TN3270E": bytes([40]),
    "XAUTH": bytes([41]),
    "CHARSET": bytes([42]),
    "RSP": bytes([43]),
    "COM_PORT_OPTION": bytes([44]),
    "SUPPRESS_LOCAL_ECHO": bytes([45]),
    "TLS": bytes([46]),
    "KERMIT": bytes([47]),
    "SEND_URL": bytes([48]),
    "FORWARD_X": bytes([49]),
    "PRAGMA_LOGON": bytes([138]),
    "SSPI_LOGON": bytes([139]),
    "PRAGMA_HEARTBEAT": bytes([140]),
    "EXOPL": bytes([255]),
    "NOOPT": bytes([0]),
}

globals().update(_CONSTANTS)

Telnet = _UnsupportedTelnet
__all__ = ["Telnet", *_CONSTANTS.keys()]

