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


@dataclass(frozen=True)
class SDWANConfig:
    """Runtime config required for vManage API access."""

    api_url: str
    api_key: str
    verify_ssl: bool = True
    timeout_seconds: int = 30


class SDWANConfigError(RuntimeError):
    """Raised when SD-WAN configuration is missing or invalid."""


def load_sdwan_config_from_env() -> SDWANConfig:
    """Load and validate SD-WAN configuration from environment variables."""

    api_url = (os.getenv("SDWAN_API_URL") or "").strip().rstrip("/")
    api_key = (os.getenv("SDWAN_API_KEY") or "").strip()

    missing: List[str] = []
    if not api_url:
        missing.append("SDWAN_API_URL")
    if not api_key:
        missing.append("SDWAN_API_KEY")
    if missing:
        missing_joined = ", ".join(missing)
        raise SDWANConfigError(
            "Missing Cisco SD-WAN configuration: "
            f"{missing_joined}. Configure these environment variables before running audits/site picker."
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
        verify_ssl=verify_ssl,
        timeout_seconds=timeout_seconds,
    )


class SDWANClient:
    """Thin Cisco vManage REST client with retries and structured failures."""

    def __init__(self, config: SDWANConfig) -> None:
        self.config = config
        self._session = requests.Session()
        retries = Retry(
            total=2,
            read=2,
            connect=2,
            backoff_factor=0.3,
            status_forcelist=(429, 500, 502, 503, 504),
            allowed_methods=frozenset({"GET"}),
            raise_on_status=False,
        )
        self._session.mount("https://", HTTPAdapter(max_retries=retries))
        self._session.mount("http://", HTTPAdapter(max_retries=retries))

    def _headers(self) -> Dict[str, str]:
        return {
            "Authorization": f"Bearer {self.config.api_key}",
            "Accept": "application/json",
            "Content-Type": "application/json",
        }

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
        for path in paths:
            payload = self._get(path)
            if isinstance(payload, dict):
                data = payload.get("data")
                if isinstance(data, list):
                    return [item for item in data if isinstance(item, dict)]
            if isinstance(payload, list):
                return [item for item in payload if isinstance(item, dict)]
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
