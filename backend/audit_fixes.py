"""Utilities to execute compliance auto-remediation actions."""

from __future__ import annotations

import re
import time
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Set, Tuple

import requests

from audit_actions import AP_RENAME_ACTION_ID, CLEAR_DNS_OVERRIDE_ACTION_ID
from compliance import (
    DEFAULT_AP_NAME_PATTERN,
    DNS_OVERRIDE_REQUIRED_VARS,
    DNS_OVERRIDE_TEMPLATE_NAME,
)

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


def _format_summary_message(verb: str, count: int) -> str:
    plural = "" if count == 1 else "s"
    return f"{verb} {count} device{plural}"


def _get_json(
    base_url: str,
    headers: Dict[str, str],
    path: str,
    *,
    optional: bool = False,
) -> Any:
    url = f"{base_url}{path}"
    response = requests.get(url, headers=headers, timeout=30)
    if optional and response.status_code == 404:
        return {}
    response.raise_for_status()
    try:
        data = response.json()
    except Exception:
        return {}
    return data


def _collect_template_names_from_docs(*docs: Any) -> Set[str]:
    names: Set[str] = set()

    def _maybe_add(value: Any) -> None:
        if isinstance(value, str):
            text = value.strip()
            if text:
                names.add(text)

    for doc in docs:
        if isinstance(doc, dict):
            for key in ("networktemplate_name", "template_name", "name"):
                _maybe_add(doc.get(key))
        elif isinstance(doc, list):
            for item in doc:
                if isinstance(item, dict):
                    for key in ("name", "template_name", "networktemplate_name"):
                        _maybe_add(item.get(key))
    return names


def _collect_site_variables_from_docs(*docs: Any) -> Dict[str, Any]:
    variables: Dict[str, Any] = {}
    keys = ("variables", "vars", "site_vars", "site_variables")
    for doc in docs:
        if not isinstance(doc, dict):
            continue
        for key in keys:
            value = doc.get(key)
            if isinstance(value, dict):
                for var_key, var_value in value.items():
                    if isinstance(var_key, str):
                        variables[var_key] = var_value
    return variables


def _site_display_name(doc: Any, default: str) -> str:
    if isinstance(doc, dict):
        for key in ("name", "site_name", "display_name"):
            value = doc.get(key)
            if isinstance(value, str):
                text = value.strip()
                if text:
                    return text
    return default


def _fetch_device_document(
    base_url: str, headers: Dict[str, str], site_id: str, device_id: str
) -> Dict[str, Any]:
    payload = _get_json(
        base_url,
        headers,
        f"/sites/{site_id}/devices/{device_id}",
    )
    return payload if isinstance(payload, dict) else {}


def _device_display_name(doc: Mapping[str, Any], default: str) -> str:
    for key in ("name", "device_name", "hostname", "display_name"):
        value = doc.get(key)
        if isinstance(value, str):
            text = value.strip()
            if text:
                return text
    return default


def _normalize_dns_values(values: Any) -> List[str]:
    normalized: List[str] = []
    if isinstance(values, list):
        for value in values:
            if isinstance(value, (str, bytes)):
                text = str(value).strip()
                if text:
                    normalized.append(text)
    return normalized


def _value_is_set(value: Any) -> bool:
    if value is None:
        return False
    if isinstance(value, (str, bytes)):
        return bool(str(value).strip())
    return True


DNS_KEYS = ("dns", "dns_servers", "dns_server")


def _sanitize_ip_config_dns(ip_config: Mapping[str, Any]) -> Tuple[Dict[str, Any], List[str]]:
    """Remove all DNS-related entries from an ip_config document."""

    cleaned_config: Dict[str, Any] = dict(ip_config)
    removed: List[str] = []

    def _pop_dns(target: Dict[str, Any]) -> None:
        nonlocal removed
        for key in DNS_KEYS:
            values = _normalize_dns_values(target.get(key))
            if values:
                removed.extend(values)
            if key in target:
                target.pop(key, None)

    _pop_dns(cleaned_config)

    static_cfg = cleaned_config.get("static_config")
    if isinstance(static_cfg, dict):
        new_static = dict(static_cfg)
        _pop_dns(new_static)
        if new_static:
            cleaned_config["static_config"] = new_static
        else:
            cleaned_config.pop("static_config", None)

    return cleaned_config, removed


def _build_dns_update_payload(
    device_doc: Mapping[str, Any],
    sanitized_direct_ip: Optional[Mapping[str, Any]],
    sanitized_switch_ip: Optional[Mapping[str, Any]],
) -> Dict[str, Any]:
    payload: Dict[str, Any] = {}
    if isinstance(device_doc.get("ip_config"), dict) and sanitized_direct_ip is not None:
        payload["ip_config"] = dict(sanitized_direct_ip)
    switch_config = device_doc.get("switch_config")
    if (
        isinstance(switch_config, dict)
        and isinstance(switch_config.get("ip_config"), dict)
        and sanitized_switch_ip is not None
    ):
        new_switch_config = dict(switch_config)
        new_switch_config["ip_config"] = dict(sanitized_switch_ip)
        payload["switch_config"] = new_switch_config
    return payload


def _update_device_payload(
    base_url: str,
    headers: Dict[str, str],
    site_id: str,
    device_id: str,
    payload: Mapping[str, Any],
) -> None:
    response = requests.put(
        f"{base_url}/sites/{site_id}/devices/{device_id}",
        headers=headers,
        json=dict(payload),
        timeout=30,
    )
    response.raise_for_status()


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
        "updated": 0,
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
        summary["updated"] += 1
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


def _clear_dns_overrides_for_site(
    base_url: str,
    headers: Dict[str, str],
    site_id: str,
    *,
    dry_run: bool,
    device_ids: Optional[Sequence[str]],
) -> Dict[str, Any]:
    site_doc = _get_json(base_url, headers, f"/sites/{site_id}")
    setting_doc = _get_json(base_url, headers, f"/sites/{site_id}/setting", optional=True)
    templates_doc = _get_json(
        base_url,
        headers,
        f"/sites/{site_id}/networktemplates",
        optional=True,
    )
    template_list = templates_doc if isinstance(templates_doc, list) else []

    site_name = _site_display_name(site_doc, site_id)

    normalized_devices: List[str] = []
    if device_ids:
        seen: Set[str] = set()
        for device_id in device_ids:
            if device_id is None:
                continue
            text = str(device_id).strip()
            if not text or text in seen:
                continue
            seen.add(text)
            normalized_devices.append(text)

    summary: Dict[str, Any] = {
        "site_id": site_id,
        "site_name": site_name,
        "updated": 0,
        "skipped": 0,
        "failed": 0,
        "changes": [],
        "errors": [],
    }

    if not normalized_devices:
        summary["failed"] = 1
        summary["errors"].append({"reason": "No target devices provided."})
        return summary

    template_names = _collect_template_names_from_docs(site_doc, setting_doc, template_list)
    if DNS_OVERRIDE_TEMPLATE_NAME not in template_names:
        summary["failed"] = len(normalized_devices)
        summary["errors"].append(
            {
                "reason": f"Required template '{DNS_OVERRIDE_TEMPLATE_NAME}' is not applied.",
                "templates": sorted(template_names),
            }
        )
        return summary

    site_variables = _collect_site_variables_from_docs(site_doc, setting_doc)
    missing_vars = [
        key for key in DNS_OVERRIDE_REQUIRED_VARS if not _value_is_set(site_variables.get(key))
    ]
    if missing_vars:
        summary["failed"] = len(normalized_devices)
        summary["errors"].append(
            {
                "reason": "Required site DNS variables are missing or empty.",
                "missing": sorted(missing_vars),
            }
        )
        return summary

    for device_id in normalized_devices:
        try:
            device_doc = _fetch_device_document(base_url, headers, site_id, device_id)
        except requests.HTTPError as exc:
            summary["failed"] += 1
            summary["errors"].append(
                {
                    "device_id": device_id,
                    "reason": f"Device lookup failed: {exc}",
                }
            )
            continue

        device_name = _device_display_name(device_doc, device_id)
        direct_ip = device_doc.get("ip_config")
        switch_config = device_doc.get("switch_config")
        has_direct_ip = isinstance(direct_ip, dict)
        has_switch_ip = isinstance(switch_config, dict) and isinstance(
            switch_config.get("ip_config"), dict
        )

        if not has_direct_ip and not has_switch_ip:
            summary["failed"] += 1
            summary["errors"].append(
                {
                    "device_id": device_id,
                    "reason": "Device does not expose ip_config overrides.",
                }
            )
            continue

        removed_dns: List[str] = []
        sanitized_direct: Optional[Dict[str, Any]] = None
        sanitized_switch: Optional[Dict[str, Any]] = None

        if has_direct_ip:
            sanitized_direct, direct_removed = _sanitize_ip_config_dns(direct_ip)
            removed_dns.extend(direct_removed)
        if has_switch_ip:
            sanitized_switch, switch_removed = _sanitize_ip_config_dns(switch_config["ip_config"])
            removed_dns.extend(switch_removed)

        deduped_removed: List[str] = []
        seen_dns: Set[str] = set()
        for value in removed_dns:
            if value not in seen_dns:
                deduped_removed.append(value)
                seen_dns.add(value)

        if not deduped_removed:
            summary["skipped"] += 1
            continue

        payload = _build_dns_update_payload(device_doc, sanitized_direct, sanitized_switch)
        if not payload:
            summary["failed"] += 1
            summary["errors"].append(
                {
                    "device_id": device_id,
                    "reason": "Unable to construct update payload for device.",
                }
            )
            continue

        if not dry_run:
            try:
                _update_device_payload(base_url, headers, site_id, device_id, payload)
            except requests.HTTPError as exc:
                summary["failed"] += 1
                summary["errors"].append(
                    {
                        "device_id": device_id,
                        "reason": f"Failed to clear DNS override: {exc}",
                    }
                )
                continue

        summary["updated"] += 1
        summary["changes"].append(
            {
                "device_id": device_id,
                "device_name": device_name,
                "removed_dns": deduped_removed,
            }
        )

    return summary


def _execute_ap_rename_action(
    base_url: str,
    token: str,
    site_ids: Sequence[str],
    *,
    dry_run: bool,
    pause: float,
    device_map: Optional[Mapping[str, Sequence[str]]],
) -> Dict[str, Any]:
    headers = _mist_headers(token)
    normalized_site_ids = [sid for sid in site_ids if isinstance(sid, str) and sid]

    results: List[Dict[str, Any]] = []
    totals = {"renamed": 0, "updated": 0, "skipped": 0, "failed": 0}
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
                    "updated": 0,
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
        renamed_count = summary.get("renamed", 0)
        totals["renamed"] += renamed_count
        totals["updated"] += summary.get("updated", renamed_count)
        totals["skipped"] += summary.get("skipped", 0)
        totals["failed"] += summary.get("failed", 0)

    totals_with_sites = {**totals, "sites": len(results)}
    totals_with_sites.setdefault("updated", totals_with_sites.get("renamed", 0))
    totals_with_sites.setdefault(
        "summary", _format_summary_message("Renamed", totals_with_sites.get("renamed", 0))
    )

    return {
        "ok": True,
        "action_id": AP_RENAME_ACTION_ID,
        "dry_run": dry_run,
        "results": results,
        "totals": totals_with_sites,
    }


def _execute_dns_override_action(
    base_url: str,
    token: str,
    site_ids: Sequence[str],
    *,
    dry_run: bool,
    device_map: Optional[Mapping[str, Sequence[str]]],
) -> Dict[str, Any]:
    headers = _mist_headers(token)
    normalized_site_ids = [sid for sid in site_ids if isinstance(sid, str) and sid]

    results: List[Dict[str, Any]] = []
    totals = {"updated": 0, "skipped": 0, "failed": 0}
    for site_id in normalized_site_ids:
        try:
            device_ids = device_map.get(site_id) if device_map else None
            summary = _clear_dns_overrides_for_site(
                base_url,
                headers,
                site_id,
                dry_run=dry_run,
                device_ids=device_ids,
            )
        except requests.HTTPError as exc:
            results.append(
                {
                    "site_id": site_id,
                    "site_name": site_id,
                    "updated": 0,
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
        totals["updated"] += summary.get("updated", 0)
        totals["skipped"] += summary.get("skipped", 0)
        totals["failed"] += summary.get("failed", 0)

    totals_with_sites = {**totals, "sites": len(results)}
    totals_with_sites.setdefault(
        "summary",
        _format_summary_message("Cleared DNS overrides for", totals_with_sites.get("updated", 0)),
    )

    return {
        "ok": True,
        "action_id": CLEAR_DNS_OVERRIDE_ACTION_ID,
        "dry_run": dry_run,
        "results": results,
        "totals": totals_with_sites,
    }


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
    if action_id == AP_RENAME_ACTION_ID:
        return _execute_ap_rename_action(
            base_url,
            token,
            site_ids,
            dry_run=dry_run,
            pause=pause,
            device_map=device_map,
        )
    if action_id == CLEAR_DNS_OVERRIDE_ACTION_ID:
        return _execute_dns_override_action(
            base_url,
            token,
            site_ids,
            dry_run=dry_run,
            device_map=device_map,
        )
    raise ValueError(f"Unsupported action_id: {action_id}")


__all__ = ["execute_audit_action"]
