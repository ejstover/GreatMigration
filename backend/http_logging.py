"""Log outbound HTTP metadata without recording payloads or credentials."""
from __future__ import annotations

from typing import Any

import requests
from urllib.parse import urlsplit
from security import validate_mist_request

from logging_utils import get_user_logger


_LOGGER = get_user_logger()
_INSTALLED = False
_ORIGINAL_SESSION_REQUEST = requests.sessions.Session.request


def install_http_logging() -> None:
    """Install a requests hook that logs method, hostname, and status only."""
    global _INSTALLED
    if _INSTALLED:
        return

    def _logged_request(self: requests.sessions.Session, method: str, url: str, **kwargs: Any):
        method_upper = (method or "").upper()
        headers = dict(self.headers)
        headers.update(kwargs.get("headers") or {})
        if any(key.lower() == "authorization" and str(value).startswith("Token ") for key, value in headers.items()):
            validate_mist_request(url)
            kwargs["allow_redirects"] = False
            if kwargs.get("verify") is False:
                raise ValueError("TLS verification is required for Mist")
        # Never derive credentials from the host's .netrc or proxy environment.
        self.trust_env = False
        parsed = urlsplit(url)
        _LOGGER.info("HTTP method=%s host=%s", method_upper, parsed.hostname)
        response = _ORIGINAL_SESSION_REQUEST(self, method, url, **kwargs)
        _LOGGER.info("HTTP method=%s host=%s status=%s", method_upper, parsed.hostname, response.status_code)
        return response

    requests.sessions.Session.request = _logged_request
    _INSTALLED = True


__all__ = ["install_http_logging"]
