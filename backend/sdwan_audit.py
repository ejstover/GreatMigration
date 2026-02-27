from __future__ import annotations

import json
import os
import re
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

import requests

from compliance import ENV_SWITCH_NAME_PATTERN

SDWAN_SITE_VAR_KEY = "SDWAN_SiteID"
SDWAN_SITE_VAR_LEGACY_KEY = "{{SDWAN_SiteID}}"
SITE_ID_RE = re.compile(r"^\d+$")


@dataclass
class DeviceSummary:
    system_ip: str
    host_name: str
    site_id: str
    device_group: Optional[str] = None
    latitude: Optional[float] = None
    longitude: Optional[float] = None


@dataclass
class SDWANConfig:
    api_url: str
    username: str
    password: str
    request_timeout: int = 15
    max_concurrency: int = 5
    verbose_logging: bool = True
    verify_ssl: bool = False


def normalize_sdwan_site_id(raw: Any) -> Optional[str]:
    if raw is None:
        return None
    text = str(raw).strip()
    if not text or not SITE_ID_RE.fullmatch(text):
        return None
    return text


def extract_sdwan_site_id(variables: Mapping[str, Any]) -> Optional[str]:
    return normalize_sdwan_site_id(
        variables.get(SDWAN_SITE_VAR_KEY, variables.get(SDWAN_SITE_VAR_LEGACY_KEY))
    )


def load_sdwan_config() -> SDWANConfig:
    timeout_raw = (os.getenv("SDWAN_REQUEST_TIMEOUT") or "15").strip()
    conc_raw = (os.getenv("SDWAN_MAX_CONCURRENCY") or "5").strip()
    verbose_raw = (os.getenv("SDWAN_VERBOSE_LOGGING") or "true").strip().lower()
    verify_raw = (os.getenv("SDWAN_VERIFY_SSL") or "false").strip().lower()
    try:
        timeout = max(int(timeout_raw), 1)
    except ValueError:
        timeout = 15
    try:
        concurrency = max(int(conc_raw), 1)
    except ValueError:
        concurrency = 5
    return SDWANConfig(
        api_url=(os.getenv("SDWAN_API_URL") or "").strip().rstrip("/"),
        username=(os.getenv("SDWAN_API_USERNAME") or "").strip(),
        password=(os.getenv("SDWAN_API_PASSWORD") or "").strip(),
        request_timeout=timeout,
        max_concurrency=concurrency,
        verbose_logging=verbose_raw not in {"0", "false", "no"},
        verify_ssl=verify_raw not in {"0", "false", "no"},
    )


def validate_sdwan_config(config: SDWANConfig) -> List[str]:
    errors: List[str] = []
    if not config.api_url:
        errors.append("Missing SDWAN_API_URL")
    if not config.username:
        errors.append("Missing SDWAN_API_USERNAME")
    if not config.password:
        errors.append("Missing SDWAN_API_PASSWORD")
    return errors


class SDWANClient:
    def __init__(self, config: SDWANConfig, logger: Any, correlation_id: str):
        self.config = config
        self.logger = logger
        self.correlation_id = correlation_id
        self.session = requests.Session()
        self._authenticated = False

    def _authenticate(self) -> None:
        if self._authenticated:
            return
        login_url = f"{self.config.api_url}/j_security_check"
        response = self.session.post(
            login_url,
            data={"j_username": self.config.username, "j_password": self.config.password},
            timeout=self.config.request_timeout,
            verify=self.config.verify_ssl,
        )
        response.raise_for_status()
        if b"<html>" in (response.content or b"").lower():
            raise RuntimeError("SD-WAN authentication failed")

        token_url = f"{self.config.api_url}/dataservice/client/token"
        token_response = self.session.get(
            token_url,
            timeout=self.config.request_timeout,
            verify=self.config.verify_ssl,
        )
        if token_response.ok and token_response.text:
            self.session.headers.update({"X-XSRF-TOKEN": token_response.text.strip()})
        self._authenticated = True
        self._log("authenticated", verify_ssl=self.config.verify_ssl)

    def _log(self, event: str, **payload: Any) -> None:
        base = {"component": "sdwan", "event": event, "correlation_id": self.correlation_id}
        base.update(payload)
        self.logger.info(json.dumps(base, sort_keys=True, default=str))

    def _request(self, method: str, path: str, *, params: Optional[Dict[str, Any]] = None) -> Any:
        url = f"{self.config.api_url}{path}"
        self._authenticate()
        headers = {"Accept": "application/json"}
        attempts = 0
        last_exc: Optional[Exception] = None
        while attempts < 2:
            attempts += 1
            started = time.perf_counter()
            try:
                response = self.session.request(
                    method,
                    url,
                    headers=headers,
                    params=params,
                    timeout=self.config.request_timeout,
                    verify=self.config.verify_ssl,
                )
                elapsed_ms = int((time.perf_counter() - started) * 1000)
                body_sample = ""
                if self.config.verbose_logging:
                    body_sample = (response.text or "")[:300]
                self._log(
                    "http",
                    method=method,
                    url=response.url,
                    status_code=response.status_code,
                    elapsed_ms=elapsed_ms,
                    verify_ssl=self.config.verify_ssl,
                    response_size=len(response.content or b""),
                    sample_body=body_sample,
                    retry_attempt=attempts - 1,
                )
                response.raise_for_status()
                if not response.content:
                    return None
                return response.json()
            except Exception as exc:
                last_exc = exc
                self._log("retry", method=method, path=path, attempt=attempts, error=str(exc))
                time.sleep(0.2 * attempts)
        assert last_exc is not None
        raise last_exc

    def get_vedges(self, site_id: Optional[str] = None) -> List[Dict[str, Any]]:
        params = {"site-id": site_id} if site_id else None
        payload = self._request("GET", "/dataservice/device/vedges", params=params)
        rows = _extract_items(payload)
        self._log("inventory_received", requested_site_id=site_id, device_count=len(rows))
        return rows

    def get_device_config(self, system_ip: str) -> Any:
        return self._request("GET", "/dataservice/device/config", params={"deviceId": system_ip})

    def get_cedges_for_sites(self, site_ids: List[str]) -> Tuple[Dict[str, List[DeviceSummary]], str]:
        strategy = "server_side_filter"
        filtered_rows: List[Dict[str, Any]] = []
        if site_ids:
            sample_site = site_ids[0]
            rows = self.get_vedges(sample_site)
            if rows and all(str(item.get("site-id", "")).strip() == sample_site for item in rows):
                for site_id in site_ids:
                    filtered_rows.extend(self.get_vedges(site_id))
            else:
                strategy = "fallback_full_inventory"
                filtered_rows = self.get_vedges()
        else:
            strategy = "fallback_full_inventory"
            filtered_rows = self.get_vedges()

        indexed = index_devices_by_site_id(filtered_rows, site_ids)
        self._log("inventory_strategy", strategy=strategy, requested_sites=len(site_ids), matched_sites=len(indexed))
        return indexed, strategy


def _extract_items(payload: Any) -> List[Dict[str, Any]]:
    if isinstance(payload, list):
        return [item for item in payload if isinstance(item, dict)]
    if isinstance(payload, dict):
        for key in ("data", "items", "results", "devices"):
            value = payload.get(key)
            if isinstance(value, list):
                return [item for item in value if isinstance(item, dict)]
    return []


def index_devices_by_site_id(rows: Sequence[Mapping[str, Any]], site_ids: Optional[Iterable[str]] = None) -> Dict[str, List[DeviceSummary]]:
    allow = set(site_ids or [])
    result: Dict[str, List[DeviceSummary]] = {}
    for row in rows:
        site_id = normalize_sdwan_site_id(row.get("site-id") or row.get("site_id"))
        if not site_id:
            continue
        if allow and site_id not in allow:
            continue
        system_ip = str(row.get("system-ip") or row.get("system_ip") or "").strip()
        if not system_ip:
            continue
        lat_raw = row.get("latitude")
        lon_raw = row.get("longitude")
        try:
            latitude = float(lat_raw) if lat_raw is not None else None
        except (TypeError, ValueError):
            latitude = None
        try:
            longitude = float(lon_raw) if lon_raw is not None else None
        except (TypeError, ValueError):
            longitude = None

        summary = DeviceSummary(
            system_ip=system_ip,
            host_name=str(row.get("host-name") or row.get("host_name") or "").strip() or system_ip,
            site_id=site_id,
            device_group=str(row.get("device-group") or row.get("device_group") or "").strip() or None,
            latitude=latitude,
            longitude=longitude,
        )
        result.setdefault(site_id, []).append(summary)
    return result


def parse_device_config(config_payload: Any) -> str:
    if isinstance(config_payload, str):
        return config_payload
    if isinstance(config_payload, dict):
        for key in ("config", "template", "data"):
            value = config_payload.get(key)
            if isinstance(value, str):
                return value
    return ""


def suffix_from_name(name: str) -> Optional[str]:
    text = (name or "").strip()
    if text.endswith("C EDGE 1"):
        return "C EDGE 1"
    if text.endswith("C EDGE 2"):
        return "C EDGE 2"
    return None


def validate_device_name(name: str) -> bool:
    if re.search(r"\b(one|two)\b", name or "", flags=re.IGNORECASE):
        return False
    suffix = suffix_from_name(name)
    if not suffix:
        return False
    base_name = (name or "")[: -len(suffix)].strip()
    if ENV_SWITCH_NAME_PATTERN and not ENV_SWITCH_NAME_PATTERN.search(base_name):
        return False
    return True


def is_cidr_29(value: str) -> bool:
    text = (value or "").strip()
    return bool(re.fullmatch(r"\d+\.\d+\.\d+\.\d+/29", text))


def expected_vrrp_priority(device_name: str) -> Optional[int]:
    suffix = suffix_from_name(device_name)
    if suffix == "C EDGE 1":
        return 110
    if suffix == "C EDGE 2":
        return 101
    return None


def check_router_id_equals_system_ip(router_id: str, system_ip: str) -> bool:
    return (router_id or "").strip() == (system_ip or "").strip()


def check_system_ip_equals_gig01(system_ip: str, gig01_ip: str) -> bool:
    ip = (gig01_ip or "").split("/")[0].strip()
    return (system_ip or "").strip() == ip


def _match_line(config: str, pattern: str) -> Optional[str]:
    m = re.search(pattern, config, flags=re.MULTILINE)
    return m.group(1).strip() if m else None


def evaluate_device_checks(device: DeviceSummary, config_text: str, row: Mapping[str, Any]) -> List[Dict[str, Any]]:
    site_id = normalize_sdwan_site_id(row.get("site-id") or row.get("site_id") or device.site_id)
    router_id = _match_line(config_text, r"router-id\s+(\S+)")
    bgp_as = _match_line(config_text, r"router\s+bgp\s+(\d+)")
    aggregate = _match_line(config_text, r"aggregate-address\s+(\S+)")
    lan_prefix = _match_line(config_text, r"address\s+(\d+\.\d+\.\d+\.\d+/\d+)")
    vrrp_group = _match_line(config_text, r"vrrp\s+(\d+)")
    vrrp_priority = _match_line(config_text, r"priority\s+(\d+)")
    neighbor_as = _match_line(config_text, r"neighbor\s+\S+\s+remote-as\s+(\d+)")
    device_group = str(row.get("device-group") or row.get("device_group") or device.device_group or "").strip()
    system_ip = device.system_ip
    gig01_ip = _match_line(config_text, r"interface\s+GigabitEthernet0/1[\s\S]*?ip\s+address\s+(\S+)")
    lat = row.get("latitude")
    lon = row.get("longitude")

    expected_priority = expected_vrrp_priority(device.host_name)

    checks = [
        ("sdwan_name", validate_device_name(device.host_name), device.host_name, "existing pattern + suffix C EDGE 1/2", "Rename to approved C EDGE suffix"),
        ("sdwan_lat_lon", isinstance(lat, (int, float)) and isinstance(lon, (int, float)) and -90 <= float(lat) <= 90 and -180 <= float(lon) <= 180, f"lat={lat}, lon={lon}", "valid lat/lon", "Populate valid latitude/longitude"),
        ("sdwan_bgp_as", bgp_as == "65494", bgp_as, "65494", "Set BGP AS to 65494"),
        ("sdwan_aggregate_prefix", bool(aggregate), aggregate, "non-empty", "Configure aggregate prefix"),
        ("sdwan_lan_prefix", is_cidr_29(lan_prefix or ""), lan_prefix, "x.x.x.x/29", "Use /29 LAN IPv4 prefix"),
        ("sdwan_vrrp_group", vrrp_group == "10", vrrp_group, "10", "Set VRRP group to 10"),
        ("sdwan_vrrp_priority", expected_priority is not None and vrrp_priority == str(expected_priority), vrrp_priority, str(expected_priority or ""), "Set VRRP priority based on C EDGE suffix"),
        ("sdwan_router_id", check_router_id_equals_system_ip(router_id or "", system_ip), router_id, system_ip, "Set router-id to system-ip"),
        ("sdwan_neighbor_as", neighbor_as == "65495", neighbor_as, "65495", "Set BGP neighbor remote-as to 65495"),
        ("sdwan_device_group", device_group == "branch_routers", device_group, "branch_routers", "Assign device group branch_routers"),
        ("sdwan_site_id", site_id is not None, site_id, "numeric site-id", "Ensure numeric site-id is configured"),
        ("sdwan_system_ip_gig01", check_system_ip_equals_gig01(system_ip, gig01_ip or ""), gig01_ip, system_ip, "Set gig0/1 IP equal to system-ip"),
    ]

    results: List[Dict[str, Any]] = []
    for check_id, passed, current_value, expected_value, remediation in checks:
        results.append(
            {
                "check_id": check_id,
                "description": check_id,
                "pass": bool(passed),
                "current_value": current_value,
                "expected_value": expected_value,
                "remediation_hint": remediation,
                "severity": "warning" if passed else "error",
            }
        )
    return results


def fetch_configs_for_devices(client: SDWANClient, devices: Sequence[DeviceSummary]) -> Tuple[Dict[str, Any], int, int]:
    successes = 0
    failures = 0
    configs: Dict[str, Any] = {}
    with ThreadPoolExecutor(max_workers=client.config.max_concurrency) as executor:
        future_map = {executor.submit(client.get_device_config, d.system_ip): d for d in devices}
        for future in as_completed(future_map):
            device = future_map[future]
            try:
                configs[device.system_ip] = future.result()
                successes += 1
            except Exception as exc:
                failures += 1
                client._log("device_config_failed", system_ip=device.system_ip, error=str(exc))
    return configs, successes, failures
