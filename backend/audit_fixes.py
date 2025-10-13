"""Utilities to execute compliance auto-remediation actions."""

from __future__ import annotations

import re
import time
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Set, Tuple

import requests

from audit_actions import AP_RENAME_ACTION_ID
from compliance import DEFAULT_AP_NAME_PATTERN

AP_NAME_PATTERN = re.compile(DEFAULT_AP_NAME_PATTERN)
SWITCH_LLDPNAME_PATTERN = re.compile(
    r"^(?P<region>NA|LA|EU|AP)(?P<site>[A-Z]{3})(?P<location>MDF|IDF\d+)[A-Z]{2}\d+$"
)


def _mist_headers(token: str) -> Dict[str, str]:
    return {
        "Authorization": f"Token {token}",
        "Accept": "application/json",
        "Content-Type": "application/json",
    }


def _paginated_get(
    base_url: str,
    headers: Dict[str, str],
    path: str,
    *,
    params: Optional[Dict[str, Any]] = None,
) -> List[Dict[str, Any]]:
    url = f"{base_url}{path}"
    collected: List[Dict[str, Any]] = []
    query = dict(params or {})
    while url:
        response = requests.get(url, headers=headers, params=query or None, timeout=30)
        response.raise_for_status()
        data = response.json() or []
        if isinstance(data, dict):
            items = data.get("results") or data.get("data") or []
            if isinstance(items, list):
                collected.extend(item for item in items if isinstance(item, dict))
            else:
                items = []
            next_url = data.get("next")
            url = next_url if isinstance(next_url, str) and next_url else None
            query = {}
        elif isinstance(data, list):
            collected.extend(item for item in data if isinstance(item, dict))
            url = None
        else:
            url = None
    return collected


def _list_site_aps(
    base_url: str,
    headers: Dict[str, str],
    site_id: str,
) -> List[Dict[str, Any]]:
    return _paginated_get(
        base_url,
        headers,
        f"/sites/{site_id}/devices",
        params={"type": "ap"},
    )


def _get_site_ap_stats(
    base_url: str,
    headers: Dict[str, str],
    site_id: str,
) -> Dict[str, Dict[str, Any]]:
    stats = _paginated_get(
        base_url,
        headers,
        f"/sites/{site_id}/stats/devices",
        params={"type": "ap", "limit": 1000},
    )
    results: Dict[str, Dict[str, Any]] = {}
    for item in stats:
        mac = item.get("mac")
        if isinstance(mac, str) and mac:
            results[mac.lower()] = item
    return results


def _fetch_site_name(base_url: str, headers: Dict[str, str], site_id: str) -> str:
    try:
        response = requests.get(f"{base_url}/sites/{site_id}", headers=headers, timeout=30)
        response.raise_for_status()
        payload = response.json() or {}
        if isinstance(payload, dict):
            for key in ("name", "site_name", "display_name"):
                value = payload.get(key)
                if isinstance(value, str) and value.strip():
                    return value
    except Exception:
        pass
    return site_id


def _parse_switch_location(name: str) -> Optional[Tuple[str, str, str]]:
    match = SWITCH_LLDPNAME_PATTERN.match(name or "")
    if not match:
        return None
    return match.group("region"), match.group("site"), match.group("location")


def _initial_number_map(names: Iterable[str]) -> Dict[str, int]:
    numbers: Dict[str, int] = {}
    for name in names:
        if not isinstance(name, str):
            continue
        m = AP_NAME_PATTERN.fullmatch(name.strip())
        if not m:
            continue
        try:
            prefix, number = name.rsplit("AP", 1)
            base = f"{prefix}AP"
            current = int(number)
        except Exception:
            continue
        numbers[base] = max(numbers.get(base, 0), current)
    return numbers


def _next_available_name(base: str, existing: set[str], numbers: Dict[str, int]) -> str:
    start = numbers.get(base, 0) + 1
    candidate = f"{base}{start}"
    while candidate in existing:
        start += 1
        candidate = f"{base}{start}"
    numbers[base] = start
    existing.add(candidate)
    return candidate


def _needs_rename(name: Optional[str]) -> bool:
    if not name:
        return True
    return AP_NAME_PATTERN.fullmatch(name.strip()) is None


def _rename_device(
    base_url: str,
    headers: Dict[str, str],
    site_id: str,
    device_id: str,
    new_name: str,
) -> None:
    response = requests.put(
        f"{base_url}/sites/{site_id}/devices/{device_id}",
        headers=headers,
        json={"name": new_name},
        timeout=30,
    )
    response.raise_for_status()


def _neighbor_system_name(stats: Dict[str, Any]) -> Optional[str]:
    uplink = stats.get("uplink") if isinstance(stats, dict) else None
    if isinstance(uplink, dict):
        neighbor = uplink.get("neighbor")
        if isinstance(neighbor, dict):
            for key in ("system_name", "sys_name", "name"):
                value = neighbor.get(key)
                if isinstance(value, str) and value.strip():
                    return value.strip()
    return None


def _summarize_site(
    base_url: str,
    headers: Dict[str, str],
    site_id: str,
    *,
    dry_run: bool,
    pause: float,
    limit_device_ids: Optional[Set[str]] = None,
) -> Dict[str, Any]:
    site_name = _fetch_site_name(base_url, headers, site_id)
    devices = _list_site_aps(base_url, headers, site_id)
    stats = _get_site_ap_stats(base_url, headers, site_id)

    existing_names = {d.get("name", "") for d in devices if isinstance(d, dict)}
    name_numbers = _initial_number_map(existing_names)

    summary: Dict[str, Any] = {
        "site_id": site_id,
        "site_name": site_name,
        "renamed": 0,
        "skipped": 0,
        "failed": 0,
        "changes": [],
        "errors": [],
    }

    normalized_limit: Optional[Set[str]] = None
    if limit_device_ids is not None:
        normalized_limit = {str(device_id) for device_id in limit_device_ids if str(device_id).strip()}

    for device in devices:
        if not isinstance(device, dict):
            continue
        mac = device.get("mac")
        mac_key = mac.lower() if isinstance(mac, str) else None
        device_id = device.get("id")
        if not isinstance(device_id, str) or not device_id:
            summary["failed"] += 1
            summary["errors"].append(
                {
                    "mac": mac,
                    "reason": "Device record missing identifier.",
                }
            )
            continue
        if normalized_limit is not None and device_id not in normalized_limit:
            continue
        current_name = (device.get("name") or "").strip() or None
        if not _needs_rename(current_name):
            summary["skipped"] += 1
            continue

        stats_entry = stats.get(mac_key or "") if mac_key else None
        neighbor = _neighbor_system_name(stats_entry or {}) if stats_entry else None
        if not neighbor:
            summary["failed"] += 1
            summary["errors"].append(
                {
                    "device_id": device_id,
                    "mac": mac,
                    "reason": "Missing LLDP neighbor system_name.",
                }
            )
            continue

        parsed = _parse_switch_location(neighbor)
        if not parsed:
            summary["failed"] += 1
            summary["errors"].append(
                {
                    "device_id": device_id,
                    "mac": mac,
                    "neighbor": neighbor,
                    "reason": "Neighbor name does not match required pattern.",
                }
            )
            continue

        region, site, location = parsed
        base = f"{region}{site}{location}AP"
        candidate = _next_available_name(base, existing_names, name_numbers)

        if not dry_run:
            try:
                _rename_device(base_url, headers, site_id, device_id, candidate)
                time.sleep(max(pause, 0.0))
            except requests.HTTPError as exc:
                summary["failed"] += 1
                summary["errors"].append(
                    {
                        "device_id": device_id,
                        "mac": mac,
                        "neighbor": neighbor,
                        "reason": f"Rename failed: {exc}",
                    }
                )
                existing_names.discard(candidate)
                continue
        summary["renamed"] += 1
        summary["changes"].append(
            {
                "device_id": device_id,
                "mac": mac,
                "old_name": current_name,
                "new_name": candidate,
                "neighbor": neighbor,
            }
        )
    return summary


def execute_audit_action(
    action_id: str,
    base_url: str,
    token: str,
    site_ids: Sequence[str],
    *,
    dry_run: bool = False,
    pause: float = 0.2,
    device_map: Optional[Mapping[str, Sequence[str]]] = None,
) -> Dict[str, Any]:
    if action_id != AP_RENAME_ACTION_ID:
        raise ValueError(f"Unsupported action_id: {action_id}")

    headers = _mist_headers(token)
    normalized_site_ids = [sid for sid in site_ids if isinstance(sid, str) and sid]

    results: List[Dict[str, Any]] = []
    totals = {"renamed": 0, "skipped": 0, "failed": 0}
    for site_id in normalized_site_ids:
        try:
            limit_ids: Optional[Set[str]] = None
            if device_map is not None:
                device_ids = device_map.get(site_id)
                if device_ids:
                    limit_ids = {str(device_id) for device_id in device_ids if str(device_id).strip()}
            summary = _summarize_site(
                base_url,
                headers,
                site_id,
                dry_run=dry_run,
                pause=pause,
                limit_device_ids=limit_ids,
            )
        except requests.HTTPError as exc:
            results.append(
                {
                    "site_id": site_id,
                    "site_name": site_id,
                    "renamed": 0,
                    "skipped": 0,
                    "failed": 1,
                    "changes": [],
                    "errors": [
                        {
                            "reason": f"API error: {exc}",
                        }
                    ],
                }
            )
            totals["failed"] += 1
            continue
        results.append(summary)
        totals["renamed"] += summary.get("renamed", 0)
        totals["skipped"] += summary.get("skipped", 0)
        totals["failed"] += summary.get("failed", 0)

    return {
        "ok": True,
        "action_id": action_id,
        "dry_run": dry_run,
        "results": results,
        "totals": {**totals, "sites": len(results)},
    }


__all__ = ["execute_audit_action"]
