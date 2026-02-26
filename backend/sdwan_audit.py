"""Cisco SD-WAN canonical normalization and device audit checks."""

from __future__ import annotations

import ipaddress
import re
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

EXPECTED_BGP_AS = 65494
EXPECTED_NEIGHBOR_AS = 65495
EXPECTED_DEVICE_GROUP = "branch_routers"
EXPECTED_VRRP_GROUP = 10
EXPECTED_VRRP_PRIORITY_BY_ROLE: Dict[str, int] = {
    "cedge1": 110,
    "cedge2": 101,
}


def normalize_role_hint(device_name: str) -> Optional[str]:
    """Infer C-EDGE role from device name suffix; only numeric suffixes are valid."""

    text = (device_name or "").strip()
    if not text:
        return None
    normalized = re.sub(r"[\s_-]+", "", text).lower()
    if normalized.endswith("cedge1"):
        return "cedge1"
    if normalized.endswith("cedge2"):
        return "cedge2"
    return None


def is_valid_cidr_29(value: Any) -> bool:
    """Return True when value is a valid IPv4 /29 CIDR string."""

    if not isinstance(value, str) or not value.strip():
        return False
    try:
        network = ipaddress.ip_network(value.strip(), strict=False)
    except ValueError:
        return False
    return network.version == 4 and network.prefixlen == 29


def normalize_sdwan_device(raw: Mapping[str, Any]) -> Dict[str, Any]:
    """Map a raw vManage device payload into canonical audit fields."""

    device_name = str(raw.get("host-name") or raw.get("device_name") or raw.get("name") or "").strip()
    aggregate_prefix = raw.get("aggregate_prefix") or raw.get("aggregate-prefix") or raw.get("aggregatePrefix")
    if isinstance(aggregate_prefix, str):
        aggregate_value: Any = aggregate_prefix.strip()
    elif isinstance(aggregate_prefix, Sequence):
        aggregate_value = [str(item).strip() for item in aggregate_prefix if str(item).strip()]
    else:
        aggregate_value = aggregate_prefix

    return {
        "device_name": device_name,
        "device_group": raw.get("device_group") or raw.get("device-group") or raw.get("group"),
        "site_id": raw.get("site_id") or raw.get("site-id") or raw.get("siteId"),
        "latitude": raw.get("latitude"),
        "longitude": raw.get("longitude"),
        "bgp_as": raw.get("bgp_as") or raw.get("bgp-as") or raw.get("local_as"),
        "neighbor_as": raw.get("neighbor_as") or raw.get("neighbor-as"),
        "aggregate_prefix": aggregate_value,
        "lan_ipv4_prefix": raw.get("lan_ipv4_prefix") or raw.get("lan-ipv4-prefix") or raw.get("prefix"),
        "vrrp_group": raw.get("vrrp_group") or raw.get("vrrp-group"),
        "vrrp_priority": raw.get("vrrp_priority") or raw.get("vrrp-priority"),
        "router_id": raw.get("router_id") or raw.get("router-id"),
        "system_ip": raw.get("system_ip") or raw.get("system-ip"),
        "gi0_1_ip": raw.get("gi0_1_ip") or raw.get("gi0/1") or raw.get("gigabitethernet0/1"),
        "role_hint": normalize_role_hint(device_name),
    }


def normalize_sdwan_devices(items: Iterable[Mapping[str, Any]]) -> List[Dict[str, Any]]:
    return [normalize_sdwan_device(item) for item in items]


def _as_int(value: Any) -> Optional[int]:
    if value is None:
        return None
    text = str(value).strip()
    if not text or not re.fullmatch(r"\d+", text):
        return None
    return int(text)


def _result(check_id: str, description: str, passed: bool, current_value: Any, expected_value: Any, remediation_hint: str, severity: str = "error") -> Dict[str, Any]:
    return {
        "check_id": check_id,
        "description": description,
        "pass": passed,
        "current_value": current_value,
        "expected_value": expected_value,
        "remediation_hint": remediation_hint,
        "severity": severity,
    }


def check_name_suffix(device: Mapping[str, Any]) -> Dict[str, Any]:
    name = str(device.get("device_name") or "")
    role = normalize_role_hint(name)
    has_words = bool(re.search(r"\b(one|two)\b", name, flags=re.IGNORECASE))
    return _result(
        "sdwan_name_suffix",
        "Device name must end with C EDGE 1/C EDGE 2 (numeric suffix only).",
        bool(role) and not has_words,
        name,
        "Suffix must map to cedge1 or cedge2 and must not use words one/two",
        "Rename the device to end with numeric role suffix (1 or 2).",
    )


def check_lan_prefix_29(device: Mapping[str, Any]) -> Dict[str, Any]:
    prefix = device.get("lan_ipv4_prefix")
    return _result(
        "sdwan_lan_prefix_29",
        "LAN IPv4 prefix must be /29.",
        is_valid_cidr_29(prefix),
        prefix,
        "IPv4 CIDR /29",
        "Update LAN addressing to a /29 CIDR block.",
    )


def check_vrrp_priority(device: Mapping[str, Any]) -> Dict[str, Any]:
    role = device.get("role_hint") or normalize_role_hint(str(device.get("device_name") or ""))
    expected = EXPECTED_VRRP_PRIORITY_BY_ROLE.get(str(role))
    current = _as_int(device.get("vrrp_priority"))
    if expected is None:
        return _result(
            "sdwan_vrrp_priority",
            "VRRP priority must match C-EDGE role.",
            False,
            current,
            "cedge1=>110 or cedge2=>101",
            "Ensure device name ends with C EDGE 1/2 so role can be derived.",
        )
    return _result(
        "sdwan_vrrp_priority",
        "VRRP priority must match C-EDGE role.",
        current == expected,
        current,
        expected,
        "Set VRRP priority based on role: cedge1=110, cedge2=101.",
    )


def check_router_id_matches_system_ip(device: Mapping[str, Any]) -> Dict[str, Any]:
    router_id = str(device.get("router_id") or "").strip()
    system_ip = str(device.get("system_ip") or "").strip()
    return _result(
        "sdwan_router_id_matches_system_ip",
        "Router ID must equal System IP.",
        bool(router_id) and router_id == system_ip,
        {"router_id": router_id, "system_ip": system_ip},
        "router_id == system_ip",
        "Set router-id to the same value as system-ip.",
    )


def check_system_ip_matches_gi0_1(device: Mapping[str, Any]) -> Dict[str, Any]:
    system_ip = str(device.get("system_ip") or "").strip()
    gi_ip = str(device.get("gi0_1_ip") or "").strip()
    return _result(
        "sdwan_system_ip_matches_gi0_1",
        "System IP must equal physical interface gi0/1 IP.",
        bool(system_ip) and system_ip == gi_ip,
        {"system_ip": system_ip, "gi0_1_ip": gi_ip},
        "system_ip == gi0_1_ip",
        "Align system-ip with gi0/1 interface IP.",
    )


def check_mist_sdwan_site_id_value(value: Any) -> Dict[str, Any]:
    text = str(value).strip() if value is not None else ""
    return _result(
        "mist_sdwan_site_id",
        "Mist site variable SDWAN_site_id must exist and be numeric.",
        bool(text) and text.isdigit(),
        value,
        "numeric value",
        "Set Mist site variable SDWAN_site_id to a numeric site ID from vManage.",
    )


def filter_mist_sites_by_sdwan_intersection(
    mist_sites: Sequence[Mapping[str, Any]],
    mist_sdwan_ids: Mapping[str, Any],
    vmanage_site_ids: Sequence[str],
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """Return included/excluded Mist sites based on SDWAN_site_id ∩ vManage site IDs."""

    vmanage_ids = {str(item).strip() for item in vmanage_site_ids if str(item).strip()}
    included: List[Dict[str, Any]] = []
    excluded: List[Dict[str, Any]] = []
    for site in mist_sites:
        site_id = str(site.get("id") or "").strip()
        sdwan_id = str(mist_sdwan_ids.get(site_id) or "").strip()
        if sdwan_id and sdwan_id in vmanage_ids:
            included.append(dict(site))
        else:
            excluded.append(dict(site))
    return included, excluded


def run_all_sdwan_checks(device: Mapping[str, Any]) -> List[Dict[str, Any]]:
    """Execute Cisco SD-WAN audit checks for a canonical device."""

    checks = [
        check_name_suffix(device),
        _check_lat_long(device),
        _check_bgp_as(device),
        _check_aggregate_prefix(device),
        check_lan_prefix_29(device),
        _check_vrrp_group(device),
        check_vrrp_priority(device),
        check_router_id_matches_system_ip(device),
        _check_neighbor_as(device),
        _check_device_group(device),
        _check_site_id(device),
        check_system_ip_matches_gi0_1(device),
    ]
    return checks


def _check_lat_long(device: Mapping[str, Any]) -> Dict[str, Any]:
    lat, lon = device.get("latitude"), device.get("longitude")
    passed = False
    try:
        lat_f, lon_f = float(lat), float(lon)
        passed = -90.0 <= lat_f <= 90.0 and -180.0 <= lon_f <= 180.0
    except (TypeError, ValueError):
        passed = False
    return _result("sdwan_lat_long", "Latitude/longitude must be present and valid.", passed, {"latitude": lat, "longitude": lon}, "latitude[-90..90], longitude[-180..180]", "Populate valid site coordinates in vManage inventory.")


def _check_bgp_as(device: Mapping[str, Any]) -> Dict[str, Any]:
    value = _as_int(device.get("bgp_as"))
    return _result("sdwan_bgp_as", "BGP AS must equal 65494.", value == EXPECTED_BGP_AS, value, EXPECTED_BGP_AS, "Set local BGP AS to 65494.")


def _check_aggregate_prefix(device: Mapping[str, Any]) -> Dict[str, Any]:
    value = device.get("aggregate_prefix")
    if isinstance(value, list):
        completed = any(bool(str(item).strip()) for item in value)
    else:
        completed = bool(str(value).strip()) if value is not None else False
    return _result("sdwan_aggregate_prefix", "Aggregate prefix must be completed (non-empty).", completed, value, "non-empty aggregate prefix value", "Configure at least one aggregate prefix value.", severity="warn")


def _check_vrrp_group(device: Mapping[str, Any]) -> Dict[str, Any]:
    value = _as_int(device.get("vrrp_group"))
    return _result("sdwan_vrrp_group", "VRRP group number must equal 10.", value == EXPECTED_VRRP_GROUP, value, EXPECTED_VRRP_GROUP, "Set VRRP group to 10.")


def _check_neighbor_as(device: Mapping[str, Any]) -> Dict[str, Any]:
    value = _as_int(device.get("neighbor_as"))
    return _result("sdwan_neighbor_as", "Neighbor AS must equal 65495.", value == EXPECTED_NEIGHBOR_AS, value, EXPECTED_NEIGHBOR_AS, "Set neighbor AS to 65495.")


def _check_device_group(device: Mapping[str, Any]) -> Dict[str, Any]:
    value = str(device.get("device_group") or "").strip()
    return _result("sdwan_device_group", "Device group must equal branch_routers.", value == EXPECTED_DEVICE_GROUP, value, EXPECTED_DEVICE_GROUP, "Assign device to branch_routers group.")


def _check_site_id(device: Mapping[str, Any]) -> Dict[str, Any]:
    value = str(device.get("site_id") or "").strip()
    return _result("sdwan_site_id", "Site ID must be populated with a numeric value.", bool(value) and value.isdigit(), value, "numeric site ID", "Populate a numeric site-id value on the device.")
