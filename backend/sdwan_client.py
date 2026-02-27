"""Cisco SD-WAN (vManage) API client and configuration helpers."""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Sequence, Set

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

logger = logging.getLogger(__name__)

AUTH_MODE_AUTO = "auto"
AUTH_MODE_API_KEY = "api_key"
AUTH_MODE_JWT = "jwt"
SUPPORTED_AUTH_MODES = {AUTH_MODE_AUTO, AUTH_MODE_API_KEY, AUTH_MODE_JWT}


@dataclass(frozen=True)
class SDWANConfig:
    """Runtime config required for vManage API access."""

    api_url: str
    api_key: Optional[str] = None
    username: Optional[str] = None
    password: Optional[str] = None
    auth_mode: str = AUTH_MODE_AUTO
    verify_ssl: bool = True
    timeout_seconds: int = 30


class SDWANConfigError(RuntimeError):
    """Raised when SD-WAN configuration is missing or invalid."""


class SDWANAuthError(RuntimeError):
    """Raised when SD-WAN authentication fails."""


def load_sdwan_config_from_env() -> SDWANConfig:
    """Load and validate SD-WAN configuration from environment variables.

    Auth options:
    - API key: SDWAN_API_KEY
    - Username/password (JWT/session): SDWAN_USERNAME + SDWAN_PASSWORD
    """

    api_url = (os.getenv("SDWAN_API_URL") or "").strip().rstrip("/")
    api_key = (os.getenv("SDWAN_API_KEY") or "").strip() or None
    username = (os.getenv("SDWAN_USERNAME") or "").strip() or None
    password = (os.getenv("SDWAN_PASSWORD") or "").strip() or None
    auth_mode = (os.getenv("SDWAN_AUTH_MODE") or AUTH_MODE_AUTO).strip().lower()

    if not api_url:
        raise SDWANConfigError(
            "Missing Cisco SD-WAN configuration: SDWAN_API_URL. "
            "Configure the vManage base URL before running audits/site picker."
        )

    if auth_mode not in SUPPORTED_AUTH_MODES:
        valid = ", ".join(sorted(SUPPORTED_AUTH_MODES))
        raise SDWANConfigError(
            f"Unsupported SDWAN_AUTH_MODE '{auth_mode}'. Use one of: {valid}."
        )

    has_api_key = bool(api_key)
    has_userpass = bool(username and password)

    if auth_mode == AUTH_MODE_API_KEY and not has_api_key:
        raise SDWANConfigError(
            "SDWAN_AUTH_MODE is 'api_key' but SDWAN_API_KEY is missing."
        )

    if auth_mode == AUTH_MODE_JWT and not has_userpass:
        raise SDWANConfigError(
            "SDWAN_AUTH_MODE is 'jwt' but SDWAN_USERNAME/SDWAN_PASSWORD are missing."
        )

    if auth_mode == AUTH_MODE_AUTO and not (has_api_key or has_userpass):
        raise SDWANConfigError(
            "Missing Cisco SD-WAN credentials. Configure either SDWAN_API_KEY or "
            "SDWAN_USERNAME + SDWAN_PASSWORD before running audits/site picker."
        )

    verify_ssl = (os.getenv("SDWAN_VERIFY_SSL") or "true").strip().lower() not in {"0", "false", "no"}
    timeout_raw = (os.getenv("SDWAN_TIMEOUT_SECONDS") or "30").strip()
    timeout_seconds = 30
    if timeout_raw:
        try:
            timeout_seconds = max(5, int(timeout_raw))
        except ValueError:
            timeout_seconds = 30

    return SDWANConfig(
        api_url=api_url,
        api_key=api_key,
        username=username,
        password=password,
        auth_mode=auth_mode,
        verify_ssl=verify_ssl,
        timeout_seconds=timeout_seconds,
    )


class SDWANClient:
    """Cisco vManage REST client with retries, auth handling, and structured failures."""

    def __init__(self, config: SDWANConfig) -> None:
        self.config = config
        self._session = requests.Session()
        self._jwt_token: Optional[str] = None
        self._xsrf_token: Optional[str] = None

        retries = Retry(
            total=2,
            read=2,
            connect=2,
            backoff_factor=0.3,
            status_forcelist=(429, 500, 502, 503, 504),
            allowed_methods=frozenset({"GET", "POST"}),
            raise_on_status=False,
        )
        self._session.mount("https://", HTTPAdapter(max_retries=retries))
        self._session.mount("http://", HTTPAdapter(max_retries=retries))
        self._authenticate_if_required()

    def _authenticate_if_required(self) -> None:
        mode = self.config.auth_mode
        if mode == AUTH_MODE_API_KEY:
            return
        if mode == AUTH_MODE_JWT:
            self._authenticate_with_username_password()
            return

        # AUTO mode: prefer API key if configured, otherwise use username/password.
        if self.config.api_key:
            return
        self._authenticate_with_username_password()

    def _authenticate_with_username_password(self) -> None:
        username = self.config.username or ""
        password = self.config.password or ""
        if not username or not password:
            raise SDWANAuthError("Missing SD-WAN username/password for JWT authentication.")

        # First attempt: JWT login endpoint used by newer vManage versions.
        jwt_url = f"{self.config.api_url}/dataservice/j_security_check"
        jwt_resp = self._session.post(
            jwt_url,
            json={"j_username": username, "j_password": password},
            timeout=self.config.timeout_seconds,
            verify=self.config.verify_ssl,
        )

        if jwt_resp.status_code < 400:
            token = self._extract_token_from_response(jwt_resp)
            if token:
                self._jwt_token = token
                logger.debug("sdwan_auth mode=jwt_endpoint status=%s", jwt_resp.status_code)
                return

        # Fallback: classic session cookie flow.
        legacy_url = f"{self.config.api_url}/j_security_check"
        legacy_resp = self._session.post(
            legacy_url,
            data={"j_username": username, "j_password": password},
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            timeout=self.config.timeout_seconds,
            verify=self.config.verify_ssl,
        )

        if legacy_resp.status_code >= 400:
            raise SDWANAuthError(
                f"Cisco SD-WAN authentication failed with status {legacy_resp.status_code}. "
                "Verify SDWAN_USERNAME/SDWAN_PASSWORD and vManage auth mode."
            )

        token_url = f"{self.config.api_url}/dataservice/client/token"
        token_resp = self._session.get(
            token_url,
            timeout=self.config.timeout_seconds,
            verify=self.config.verify_ssl,
        )
        if token_resp.status_code < 400 and token_resp.text.strip():
            self._xsrf_token = token_resp.text.strip()
            logger.debug("sdwan_auth mode=legacy_session_xsrf status=%s", token_resp.status_code)
            return

        # If client/token is not available, cookie auth can still work on some versions.
        logger.debug(
            "sdwan_auth mode=legacy_session_cookie_only status=%s token_status=%s",
            legacy_resp.status_code,
            token_resp.status_code,
        )

    @staticmethod
    def _extract_token_from_response(response: requests.Response) -> Optional[str]:
        if not response.content:
            return None
        try:
            payload = response.json()
        except ValueError:
            return None

        if not isinstance(payload, dict):
            return None

        for key in ("token", "access_token", "jwt", "jwttoken"):
            value = payload.get(key)
            if isinstance(value, str) and value.strip():
                return value.strip()
        return None

    def _headers(self) -> Dict[str, str]:
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
        }
        bearer = self._jwt_token or self.config.api_key
        if bearer:
            headers["Authorization"] = f"Bearer {bearer}"
        if self._xsrf_token:
            headers["X-XSRF-TOKEN"] = self._xsrf_token
        return headers

    def _get(self, path: str) -> Any:
        url = f"{self.config.api_url}{path}"
        response = self._session.get(
            url,
            headers=self._headers(),
            timeout=self.config.timeout_seconds,
            verify=self.config.verify_ssl,
        )

        payload: Any = None
        if response.content:
            try:
                payload = response.json()
            except ValueError:
                payload = response.text

        logger.debug("sdwan_api_response path=%s status=%s payload=%s", path, response.status_code, payload)

        if response.status_code >= 400:
            raise RuntimeError(
                f"Cisco SD-WAN API request failed for '{path}' with status {response.status_code}: {payload}"
            )
        return payload

    def _get_data_items(self, paths: Sequence[str]) -> List[Dict[str, Any]]:
        last_error: Optional[RuntimeError] = None
        for path in paths:
            try:
                payload = self._get(path)
            except RuntimeError as exc:
                last_error = exc
                logger.debug("sdwan_api_fallback path=%s error=%s", path, exc)
                continue
            if isinstance(payload, dict):
                data = payload.get("data")
                if isinstance(data, list):
                    return [item for item in data if isinstance(item, dict)]
            if isinstance(payload, list):
                return [item for item in payload if isinstance(item, dict)]

        if last_error is not None:
            raise last_error
        return []

    def fetch_device_inventory(self) -> List[Dict[str, Any]]:
        """Fetch SD-WAN device inventory from common vManage endpoints."""

        return self._get_data_items((
            "/dataservice/device",
            "/dataservice/device/vedges",
        ))

    def fetch_device_operational_data(self) -> List[Dict[str, Any]]:
        """Fetch SD-WAN device operational/config data used for audit checks."""

        return self._get_data_items((
            "/dataservice/device/interface",
            "/dataservice/device/bgp/summary",
        ))

    def fetch_site_ids(self) -> Set[str]:
        """Return normalized set of site IDs observed in inventory."""

        site_ids: Set[str] = set()
        for item in self.fetch_device_inventory():
            for key in ("site-id", "site_id", "siteId"):
                raw = item.get(key)
                if raw is None:
                    continue
                text = str(raw).strip()
                if text and text.isdigit():
                    site_ids.add(text)
        return site_ids
