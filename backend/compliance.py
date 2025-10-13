"""Compliance/audit checks for Mist site configuration."""

from __future__ import annotations

import ast
import copy
import os
import re
import warnings
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple


@dataclass
class SiteContext:
    """Bundle of site-related data used when evaluating compliance checks."""

    site_id: str
    site_name: str
    site: Dict[str, Any] = field(default_factory=dict)
    setting: Dict[str, Any] = field(default_factory=dict)
    templates: Sequence[Dict[str, Any]] = field(default_factory=list)
    devices: Sequence[Dict[str, Any]] = field(default_factory=list)


@dataclass
class Finding:
    """A single non-compliant item detected by a check."""

    site_id: str
    site_name: str
    message: str
    severity: Optional[str] = None
    device_id: Optional[str] = None
    device_name: Optional[str] = None
    details: Optional[Dict[str, Any]] = None

    def as_dict(self, default_severity: str) -> Dict[str, Any]:
        data: Dict[str, Any] = {
            "site_id": self.site_id,
            "site_name": self.site_name,
            "message": self.message,
            "severity": self.severity or default_severity,
        }
        if self.device_id:
            data["device_id"] = self.device_id
        if self.device_name:
            data["device_name"] = self.device_name
        if self.details is not None:
            data["details"] = self.details
        return data


class ComplianceCheck:
    """Base class for checks that can be executed against a site."""

    id: str = ""
    name: str = ""
    description: str = ""
    severity: str = "warning"

    def run(self, context: SiteContext) -> List[Finding]:  # pragma: no cover - interface
        raise NotImplementedError


def _normalize_site_name(site: Dict[str, Any]) -> str:
    for key in ("name", "site_name", "display_name"):
        value = site.get(key)
        if isinstance(value, str) and value.strip():
            return value
    return site.get("id") or ""


def _collect_site_variables(context: SiteContext) -> Dict[str, Any]:
    candidates: List[Dict[str, Any]] = []
    for container in (context.site, context.setting):
        if not isinstance(container, dict):
            continue
        for key in ("variables", "vars", "site_vars", "site_variables"):
            value = container.get(key)
            if isinstance(value, dict):
                candidates.append(value)
    merged: Dict[str, Any] = {}
    for candidate in candidates:
        merged.update({k: v for k, v in candidate.items() if isinstance(k, str)})
    return merged


DEFAULT_REQUIRED_SITE_VARIABLES: Tuple[str, ...] = (
    "hubradiusserver",
    "localradiusserver",
    "siteDNS",
    "hubDNSserver1",
    "hubDNSserver2",
)


def _load_site_variable_list(var_name: str, default: Sequence[str]) -> Tuple[str, ...]:
    raw = os.getenv(var_name)
    if raw is None:
        return tuple(default)
    # Split on commas and strip whitespace while filtering empty entries
    values = [item.strip() for item in raw.split(",")]
    filtered = [value for value in values if value]
    return tuple(filtered or default)


class RequiredSiteVariablesCheck(ComplianceCheck):
    id = "required_site_variables"
    name = "Required site variables"
    description = "Ensure required Mist site variables are defined."
    severity = "error"

    def __init__(self, required_keys: Optional[Sequence[str]] = None) -> None:
        default_keys = _load_site_variable_list("MIST_SITE_VARIABLES", DEFAULT_REQUIRED_SITE_VARIABLES)
        if required_keys is None:
            self.required_keys: Tuple[str, ...] = tuple(default_keys)
        else:
            self.required_keys = tuple(required_keys)

    def run(self, context: SiteContext) -> List[Finding]:
        findings: List[Finding] = []
        variables = _collect_site_variables(context)
        missing = [key for key in self.required_keys if key not in variables or variables.get(key) in (None, "")]
        for key in missing:
            findings.append(
                Finding(
                    site_id=context.site_id,
                    site_name=context.site_name,
                    message=f"Site variable '{key}' is not defined.",
                )
            )
        return findings


def _collect_template_names(context: SiteContext) -> Set[str]:
    names: Set[str] = set()
    for container in (context.site, context.setting):
        if not isinstance(container, dict):
            continue
        for key in ("networktemplate_name", "network_template_name", "template_name"):
            value = container.get(key)
            if isinstance(value, str) and value.strip():
                names.add(value)
    for tmpl in context.templates:
        if not isinstance(tmpl, dict):
            continue
        for key in ("name", "template_name"):
            value = tmpl.get(key)
            if isinstance(value, str) and value.strip():
                names.add(value)
    return names


class SwitchTemplateConfigurationCheck(ComplianceCheck):
    id = "switch_template_configuration"
    name = "Switch Template Configuration"
    description = (
        "Ensure lab sites use approved switch templates and non-lab sites remain on the production template."
    )
    severity = "warning"

    prod_template_name: str = "Prod - Standard Template"
    lab_template_name: str = "Test - Standard Template"

    def run(self, context: SiteContext) -> List[Finding]:
        template_names = _collect_template_names(context)
        if not template_names:
            return []

        site_name_upper = (context.site_name or "").upper()
        is_lab_site = "LAB" in site_name_upper
        findings: List[Finding] = []
        sorted_templates = ", ".join(sorted(template_names)) or "none"

        if is_lab_site:
            allowed = {self.prod_template_name, self.lab_template_name}
            if template_names.isdisjoint(allowed):
                findings.append(
                    Finding(
                        site_id=context.site_id,
                        site_name=context.site_name,
                        message=(
                            "Lab site should apply either "
                            f"'{self.prod_template_name}' or '{self.lab_template_name}' but current templates are: "
                            f"{sorted_templates}."
                        ),
                    )
                )
        else:
            if self.prod_template_name not in template_names:
                findings.append(
                    Finding(
                        site_id=context.site_id,
                        site_name=context.site_name,
                        message=(
                            f"Site should apply '{self.prod_template_name}' but current templates are: {sorted_templates}."
                        ),
                    )
                )
            extra_templates = template_names - {self.prod_template_name}
            if self.prod_template_name in template_names and extra_templates:
                findings.append(
                    Finding(
                        site_id=context.site_id,
                        site_name=context.site_name,
                        message=(
                            f"Site should not apply additional templates ({', '.join(sorted(extra_templates))}) when "
                            f"using '{self.prod_template_name}'."
                        ),
                    )
                )

        return findings


@dataclass
class OverrideEntry:
    path: str
    port_label: Optional[str] = None
    port_number: Optional[int] = None


def _collect_override_paths(data: Any, prefix: str = "") -> List[str]:
    paths: List[str] = []
    if isinstance(data, dict):
        for key, value in data.items():
            new_prefix = f"{prefix}.{key}" if prefix else key
            key_lower = key.lower()
            if "override" in key_lower and _has_value(value):
                paths.append(new_prefix)
                continue
            paths.extend(_collect_override_paths(value, new_prefix))
    elif isinstance(data, list):
        for idx, value in enumerate(data):
            new_prefix = f"{prefix}[{idx}]" if prefix else f"[{idx}]"
            paths.extend(_collect_override_paths(value, new_prefix))
    return paths


def _has_value(value: Any) -> bool:
    if value is None:
        return False
    if isinstance(value, (str, bytes)):
        return bool(str(value).strip())
    if isinstance(value, (list, tuple, set, dict)):
        return bool(value)
    return True


def _normalize_port_label(value: Any) -> Optional[str]:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _extract_port_number(label: Optional[str]) -> Optional[int]:
    if not label:
        return None
    digits = "".join(ch if ch.isdigit() else " " for ch in label)
    try:
        parts = [int(part) for part in digits.split() if part]
    except ValueError:
        return None
    if not parts:
        return None
    # Assume the last numeric segment represents the port number
    return parts[-1]


def _collect_port_overrides(device: Dict[str, Any]) -> List[OverrideEntry]:
    entries: List[OverrideEntry] = []
    port_overrides = device.get("port_overrides")
    if isinstance(port_overrides, list):
        for idx, item in enumerate(port_overrides):
            if not isinstance(item, dict):
                continue
            label = _normalize_port_label(
                item.get("port_id") or item.get("name") or item.get("port") or item.get("port_name")
            )
            entries.append(
                OverrideEntry(
                    path=f"port_overrides[{idx}]",
                    port_label=label,
                    port_number=_extract_port_number(label),
                )
            )
    elif isinstance(port_overrides, dict):
        for key, value in port_overrides.items():
            if not _has_value(value):
                continue
            label = _normalize_port_label(key)
            entries.append(
                OverrideEntry(
                    path=f"port_overrides.{key}",
                    port_label=label,
                    port_number=_extract_port_number(label),
                )
            )
    return entries


def _is_access_switch(device: Dict[str, Any]) -> bool:
    role_candidates: Sequence[Any] = (
        device.get("role"),
        device.get("device_profile"),
        device.get("device_profile_name"),
        device.get("profile"),
        device.get("template"),
    )
    for value in role_candidates:
        if isinstance(value, str) and "access" in value.lower():
            return True
    tags = device.get("tags")
    if isinstance(tags, (list, tuple, set)):
        for tag in tags:
            if isinstance(tag, str) and "access" in tag.lower():
                return True
    return False


def _is_switch(device: Dict[str, Any]) -> bool:
    """Best-effort heuristic to determine whether a device is a switch."""

    type_hints: Sequence[Any] = (
        device.get("type"),
        device.get("device_type"),
        device.get("category"),
        device.get("role"),
        device.get("device_profile"),
        device.get("device_profile_name"),
    )
    for value in type_hints:
        if isinstance(value, str):
            lowered = value.lower()
            if "switch" in lowered:
                return True
            if lowered in {"access", "distribution", "core", "wan"}:
                return True
    model = device.get("model")
    if isinstance(model, str) and "switch" in model.lower():
        return True
    return False


def _is_access_point(device: Dict[str, Any]) -> bool:
    """Return True when the device appears to be an access point/AP."""

    type_hints: Sequence[Any] = (
        device.get("type"),
        device.get("device_type"),
        device.get("category"),
        device.get("role"),
        device.get("device_profile"),
        device.get("device_profile_name"),
    )
    for value in type_hints:
        if isinstance(value, str) and "ap" in value.lower():
            return True
    model = device.get("model")
    if isinstance(model, str) and "ap" in model.lower():
        return True
    return False


def _is_device_online(device: Dict[str, Any]) -> bool:
    """Return True when the device appears to be online/connected."""

    online_tokens = ("connected", "online", "up", "ready")
    offline_tokens = ("disconnected", "offline", "down", "not connected", "not-connected")

    def interpret_status_value(value: Any) -> Optional[bool]:
        if isinstance(value, bool):
            return value
        if isinstance(value, (int, float)):
            if value == 1:
                return True
            if value == 0:
                return False
            return None
        if isinstance(value, str):
            lower = value.strip().lower()
            if not lower:
                return None
            for token in offline_tokens:
                if token in lower:
                    return False
            for token in online_tokens:
                if re.search(rf"\b{re.escape(token)}\b", lower):
                    return True
            return None
        return None

    def iter_status_values(value: Any):
        stack: List[Any] = [value]
        while stack:
            current = stack.pop()
            if isinstance(current, dict):
                stack.extend(current.values())
            elif isinstance(current, (list, tuple, set)):
                stack.extend(current)
            else:
                yield current

    candidates: List[Any] = []
    primary_status = device.get("status")
    if primary_status is not None:
        candidates.append(primary_status)
    for key in (
        "connection_state",
        "connection",
        "connectivity",
        "device_status",
        "mgmt_connection",
        "management_connection",
        "oper_status",
        "operational_status",
        "state",
        "link_state",
        "online",
        "connected",
        "ready",
        "up",
        "is_online",
    ):
        if key in device:
            candidates.append(device.get(key))

    for key, value in device.items():
        if isinstance(key, str):
            lowered = key.lower()
            if lowered.endswith("_status") or lowered.endswith("_state"):
                candidates.append(value)

    for candidate in candidates:
        for value in iter_status_values(candidate):
            result = interpret_status_value(value)
            if result is True:
                return True
    return False



def _extract_device_switch_config(device: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    keys = (
        "switch_config",
        "config",
        "configuration",
        "switch",
        "device_config",
    )
    for key in keys:
        value = device.get(key)
        if isinstance(value, dict):
            return value
    for key in ("data", "details", "template"):
        nested = device.get(key)
        if isinstance(nested, dict):
            value = _extract_device_switch_config(nested)
            if value is not None:
                return value
    return None


def _extract_switch_template_config(container: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    keys = (
        "switch_config",
        "config",
        "configuration",
        "switch",
        "device_config",
    )
    for key in keys:
        value = container.get(key)
        if isinstance(value, dict):
            return value
    for key in ("template", "data", "definition"):
        nested = container.get(key)
        if isinstance(nested, dict):
            value = _extract_switch_template_config(nested)
            if value is not None:
                return value
    return None


@dataclass
class SwitchTemplateInfo:
    template_id: Optional[str]
    name: Optional[str]
    config: Dict[str, Any]


def _gather_switch_templates(context: SiteContext) -> List[SwitchTemplateInfo]:
    templates: List[SwitchTemplateInfo] = []
    containers: List[Dict[str, Any]] = []

    if isinstance(context.setting, dict):
        containers.append(context.setting)
    containers.extend([tpl for tpl in context.templates if isinstance(tpl, dict)])

    seen: Set[Tuple[Optional[str], Optional[str]]] = set()
    for container in containers:
        config = _extract_switch_template_config(container)
        if not config:
            continue
        template_id = None
        for key in ("template_id", "id", "networktemplate_id", "switch_template_id"):
            value = container.get(key)
            if value is None:
                continue
            template_id = str(value)
            break
        name = None
        for key in ("name", "template_name", "networktemplate_name"):
            value = container.get(key)
            if isinstance(value, str) and value.strip():
                name = value
                break
        identity = (template_id, name)
        if identity in seen:
            continue
        seen.add(identity)
        templates.append(SwitchTemplateInfo(template_id=template_id, name=name, config=config))
    return templates


def _candidate_template_identifiers(device: Dict[str, Any]) -> Tuple[List[str], List[str]]:
    id_candidates: List[str] = []
    name_candidates: List[str] = []
    for key in (
        "switch_template_id",
        "template_id",
        "networktemplate_id",
        "network_template_id",
        "device_template_id",
    ):
        value = device.get(key)
        if value is None:
            continue
        text = str(value).strip()
        if text:
            id_candidates.append(text)
    for key in (
        "switch_template",
        "switch_template_name",
        "template",
        "template_name",
        "networktemplate_name",
    ):
        value = device.get(key)
        if isinstance(value, str):
            text = value.strip()
            if text:
                name_candidates.append(text)
    return id_candidates, name_candidates


def _resolve_switch_template(
    device: Dict[str, Any], templates: Sequence[SwitchTemplateInfo]
) -> Optional[SwitchTemplateInfo]:
    if not templates:
        return None
    id_candidates, name_candidates = _candidate_template_identifiers(device)
    for candidate in id_candidates:
        for template in templates:
            if template.template_id and template.template_id == candidate:
                return template
    for candidate in name_candidates:
        for template in templates:
            if template.name and template.name == candidate:
                return template
    if len(templates) == 1:
        return templates[0]
    return None


IGNORED_CONFIG_KEYS: Set[str] = {
    "id",
    "uuid",
    "mac",
    "serial",
    "last_modified",
    "modified",
    "updated",
    "updated_at",
    "updated_time",
    "created",
    "created_at",
    "created_time",
    "last_seen",
    "timestamp",
    "version",
}

ALLOWED_ADDITIONAL_CONFIG_KEYS: Set[str] = {"image1_url", "image2_url", "image3_url"}

WAN_ROLE_KEYWORDS: Tuple[str, ...] = ("wan",)
WAN_ALLOWED_CONFIG_PATH_PREFIXES: Tuple[str, ...] = (
    "mgmt_ip_config",
    "mgmt_port_config",
    "mgmt_interface_config",
    "oob_ip_config",
    "oob_port_config",
    "oob_interface_config",
)


def _diff_configs(
    expected: Any,
    actual: Any,
    path: str = "",
    *,
    ignore_keys: Optional[Set[str]] = None,
) -> List[Dict[str, Any]]:
    ignore_keys = ignore_keys or set()

    if isinstance(expected, dict) and isinstance(actual, dict):
        diffs: List[Dict[str, Any]] = []
        for key, exp_value in expected.items():
            if key in ignore_keys:
                continue
            new_path = f"{path}.{key}" if path else str(key)
            if key not in actual:
                diffs.append({"path": new_path, "expected": exp_value, "actual": None})
                continue
            diffs.extend(
                _diff_configs(
                    exp_value,
                    actual[key],
                    new_path,
                    ignore_keys=ignore_keys,
                )
            )
        for key, act_value in actual.items():
            if key in ignore_keys:
                continue
            if key in expected:
                continue
            new_path = f"{path}.{key}" if path else str(key)
            diffs.append({"path": new_path, "expected": None, "actual": act_value})
        return diffs
    if isinstance(expected, list) and isinstance(actual, list):
        diffs: List[Dict[str, Any]] = []
        length = max(len(expected), len(actual))
        for idx in range(length):
            new_path = f"{path}[{idx}]" if path else f"[{idx}]"
            if idx >= len(expected):
                diffs.append({"path": new_path, "expected": None, "actual": actual[idx]})
            elif idx >= len(actual):
                diffs.append({"path": new_path, "expected": expected[idx], "actual": None})
            else:
                diffs.extend(
                    _diff_configs(
                        expected[idx],
                        actual[idx],
                        new_path,
                        ignore_keys=ignore_keys,
                    )
                )
        return diffs
    if expected != actual:
        return [
            {
                "path": path or ".",
                "expected": expected,
                "actual": actual,
            }
        ]
    return []
def _role_scoped_switch_configs(
    role: Any,
    template_config: Dict[str, Any],
    device_config: Dict[str, Any],
) -> Tuple[Dict[str, Any], Dict[str, Any], Any, Any]:
    expected_trimmed: Dict[str, Any] = copy.deepcopy(template_config)
    actual_trimmed: Dict[str, Any] = copy.deepcopy(device_config)

    expected_ip = expected_trimmed.pop("ip_config", None)
    actual_ip = actual_trimmed.pop("ip_config", None)

    expected_trimmed.pop("port_config", None)
    actual_trimmed.pop("port_config", None)

    return expected_trimmed, actual_trimmed, expected_ip, actual_ip


def _diff_path_port_number(path: str) -> Optional[int]:
    match = re.search(r"(?:port|ports|ge-|xe-|et-).*?(\d+)$", path.lower())
    if match:
        try:
            return int(match.group(1))
        except ValueError:
            return None
    tokens = re.findall(r"(\d+)", path)
    for token in reversed(tokens):
        try:
            return int(token)
        except ValueError:
            continue
    return None


def _evaluate_ip_config(expected: Any, actual: Any) -> List[Dict[str, Any]]:
    diffs: List[Dict[str, Any]] = []

    if actual is None:
        diffs.append({
            "path": "ip_config",
            "expected": expected or "defined static IP configuration",
            "actual": actual,
        })
        return diffs

    if not isinstance(actual, dict):
        diffs.append({
            "path": "ip_config",
            "expected": "dictionary of IP configuration values",
            "actual": actual,
        })
        return diffs

    expected_type = None
    expected_network = None
    if isinstance(expected, dict):
        expected_type = expected.get("type")
        expected_network = expected.get("network")

    actual_type = actual.get("type")
    target_type = expected_type or "static"
    if actual_type != target_type:
        diffs.append({
            "path": "ip_config.type",
            "expected": target_type,
            "actual": actual_type,
        })

    actual_ip = actual.get("ip")
    if not (isinstance(actual_ip, str) and actual_ip.startswith("10.")):
        diffs.append({
            "path": "ip_config.ip",
            "expected": "address beginning with '10.'",
            "actual": actual_ip,
        })

    actual_gateway = actual.get("gateway")
    if not (isinstance(actual_gateway, str) and actual_gateway.startswith("10.")):
        diffs.append({
            "path": "ip_config.gateway",
            "expected": "gateway beginning with '10.'",
            "actual": actual_gateway,
        })

    actual_network = actual.get("network")
    target_network = expected_network or "IT_Mgmt"
    if target_network and actual_network != target_network:
        diffs.append({
            "path": "ip_config.network",
            "expected": target_network,
            "actual": actual_network,
        })

    if "netmask" not in actual:
        diffs.append({
            "path": "ip_config.netmask",
            "expected": "defined netmask",
            "actual": actual.get("netmask"),
        })

    allowed_ip_keys = {"type", "ip", "netmask", "network", "gateway"}
    for key in sorted(actual.keys()):
        if key in allowed_ip_keys:
            continue
        diffs.append({
            "path": f"ip_config.{key}",
            "expected": None,
            "actual": actual.get(key),
        })

    return diffs


def _collect_standard_device_issues(device: Dict[str, Any]) -> List[Dict[str, Any]]:
    diffs: List[Dict[str, Any]] = []

    role = device.get("role")
    if not (isinstance(role, str) and role.strip()):
        diffs.append({
            "path": "role",
            "expected": "non-empty role",
            "actual": role,
        })

    st_ip_base = device.get("st_ip_base")
    if st_ip_base not in (None, ""):
        diffs.append({
            "path": "st_ip_base",
            "expected": "empty string",
            "actual": st_ip_base,
        })

    for key in ("evpn_scope", "evpntopo_id", "deviceprofile_id", "bundled_mac"):
        value = device.get(key)
        if value not in (None, ""):
            diffs.append({
                "path": key,
                "expected": None,
                "actual": value,
            })

    return diffs


class ConfigurationOverridesCheck(ComplianceCheck):
    id = "configuration_overrides"
    name = "Configuration overrides"
    description = "Report site or device configuration overrides outside of approved exceptions."
    severity = "warning"

    allowed_access_port_max: int = 47

    def run(self, context: SiteContext) -> List[Finding]:
        findings: List[Finding] = []

        site_override_paths = _collect_override_paths(context.setting)
        if site_override_paths:
            findings.append(
                Finding(
                    site_id=context.site_id,
                    site_name=context.site_name,
                    message="Site configuration has overrides defined.",
                    details={"paths": sorted(site_override_paths)},
                )
            )

        templates = _gather_switch_templates(context)

        for device in context.devices:
            if not isinstance(device, dict):
                continue
            if not _is_switch(device):
                continue
            device_id = str(device.get("id")) if device.get("id") is not None else None
            device_name = _normalize_site_name(device) or device_id or "device"
            role_value = device.get("role")
            role_lower = role_value.lower() if isinstance(role_value, str) else ""
            is_wan_role = bool(role_lower and any(token in role_lower for token in WAN_ROLE_KEYWORDS))

            # Non-port overrides (e.g., config_override)
            direct_paths = [path for path in _collect_override_paths(device) if not path.startswith("port_overrides")]
            for path in direct_paths:
                findings.append(
                    Finding(
                        site_id=context.site_id,
                        site_name=context.site_name,
                        device_id=device_id,
                        device_name=device_name,
                        message="Device has configuration overrides defined.",
                        details={"paths": [path]},
                    )
                )

            # Port overrides with exception logic
            port_overrides = _collect_port_overrides(device)
            access_switch = _is_access_switch(device)
            port_override_allowed_paths: Set[str] = set()
            if port_overrides:
                for entry in port_overrides:
                    if access_switch and entry.port_number is not None and 0 <= entry.port_number <= self.allowed_access_port_max:
                        continue
                    findings.append(
                        Finding(
                            site_id=context.site_id,
                            site_name=context.site_name,
                            device_id=device_id,
                            device_name=device_name,
                            message="Device port override detected.",
                            details={
                                "path": entry.path,
                                "port": entry.port_label,
                                "port_number": entry.port_number,
                                "access_switch": access_switch,
                            },
                        )
                    )
                port_override_allowed_paths = {entry.path for entry in port_overrides}

            template = _resolve_switch_template(device, templates)
            expected_config_raw = template.config if template else None
            actual_config_raw = _extract_device_switch_config(device)
            if expected_config_raw and not isinstance(expected_config_raw, dict):
                expected_config_raw = None
            actual_config_source: Optional[Dict[str, Any]]
            if isinstance(actual_config_raw, dict):
                actual_config_source = actual_config_raw
            elif isinstance(device, dict):
                actual_config_source = {k: v for k, v in device.items() if isinstance(k, str)}
            else:
                actual_config_source = None

            expected_ip_config = None
            actual_ip_config = None

            if expected_config_raw and actual_config_source:
                (
                    filtered_expected,
                    filtered_actual,
                    expected_ip_config,
                    actual_ip_config,
                ) = _role_scoped_switch_configs(
                    role_value,
                    expected_config_raw,
                    actual_config_source,
                )
                if filtered_expected or filtered_actual:
                    diffs = _diff_configs(
                        filtered_expected,
                        filtered_actual,
                        ignore_keys=IGNORED_CONFIG_KEYS | ALLOWED_ADDITIONAL_CONFIG_KEYS,
                    )
                else:
                    diffs = []
            else:
                diffs = []

            if actual_ip_config is None and isinstance(actual_config_source, dict):
                actual_ip_config = actual_config_source.get("ip_config")
            if expected_ip_config is None and isinstance(expected_config_raw, dict):
                expected_ip_config = expected_config_raw.get("ip_config")

            ip_config_diffs: List[Dict[str, Any]] = []
            if expected_config_raw or actual_config_source:
                ip_config_diffs = _evaluate_ip_config(
                    expected_ip_config if expected_config_raw else None,
                    actual_ip_config if actual_config_source else None,
                )

            standard_device_diffs = _collect_standard_device_issues(device)

            combined_diffs = []
            if diffs:
                combined_diffs.extend(diffs)
            if ip_config_diffs:
                combined_diffs.extend(ip_config_diffs)
            if standard_device_diffs:
                combined_diffs.extend(standard_device_diffs)

            if combined_diffs:
                filtered_diffs: List[Dict[str, Any]] = []
                for diff in combined_diffs:
                    path = diff.get("path") or ""
                    normalized_path = path.lower()
                    if is_wan_role and any(
                        normalized_path.startswith(prefix) for prefix in WAN_ALLOWED_CONFIG_PATH_PREFIXES
                    ):
                        continue
                    if any(path.startswith(p) for p in port_override_allowed_paths):
                        continue
                    filtered_diffs.append(diff)
                if filtered_diffs:
                    template_label = None
                    if template:
                        template_label = template.name or template.template_id
                    findings.append(
                        Finding(
                            site_id=context.site_id,
                            site_name=context.site_name,
                            device_id=device_id,
                            device_name=device_name,
                            message="Device configuration differs from assigned template.",
                            details={
                                "diffs": filtered_diffs,
                                **({"template": template_label} if template_label else {}),
                            },
                        )
                    )

        return findings


DEFAULT_SWITCH_NAME_PATTERN = (
    r"^(NA|LA|EU|AP)[A-Z]{3}(?:MDFSPARE|MDF(AS|CS|WS)\d+|IDF\d+(AS|CS|WS)\d+)$"
)


def _strip_pattern_wrappers(value: str) -> str:
    """Remove optional r"..." or quoted wrappers from an env-sourced pattern."""

    if len(value) >= 3 and value[0] in {"r", "R"} and value[1] in {'"', "'"} and value[-1] == value[1]:
        return value[2:-1]
    if len(value) >= 2 and value[0] in {'"', "'"} and value[-1] == value[0]:
        return value[1:-1]
    return value


def _literal_eval_pattern(value: str) -> Optional[str]:
    """Attempt to evaluate quoted patterns such as r"^...$" into plain strings."""

    try:
        evaluated = ast.literal_eval(value)
    except (ValueError, SyntaxError):
        return None
    return evaluated if isinstance(evaluated, str) else None


def _load_pattern_from_env(var_name: str, default: Optional[str]) -> Optional[re.Pattern[str]]:
    raw = os.getenv(var_name)
    candidate = (raw or "").strip()
    if candidate:
        evaluated = _literal_eval_pattern(candidate)
        if evaluated is not None:
            candidate = evaluated
        else:
            candidate = _strip_pattern_wrappers(candidate)
        try:
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", DeprecationWarning)
                candidate = candidate.encode("utf-8").decode("unicode_escape")
        except Exception:
            pass
    if not candidate:
        candidate = default or ""
    if not candidate:
        return None
    try:
        return re.compile(candidate)
    except re.error:
        if default and candidate != default:
            try:
                return re.compile(default)
            except re.error:
                return None
        return None


def _ensure_pattern(
    pattern: Optional[re.Pattern[str] | str],
    fallback: Optional[re.Pattern[str]],
) -> Optional[re.Pattern[str]]:
    if isinstance(pattern, re.Pattern):
        return pattern
    if isinstance(pattern, str):
        stripped = pattern.strip()
        if not stripped:
            return None
        try:
            return re.compile(stripped)
        except re.error:
            return fallback
    return fallback


ENV_SWITCH_NAME_PATTERN = _load_pattern_from_env("SWITCH_NAME_REGEX_PATTERN", DEFAULT_SWITCH_NAME_PATTERN)
ENV_AP_NAME_PATTERN = _load_pattern_from_env("AP_NAME_REGEX_PATTERN", None)


def _load_positive_int_from_env(var_name: str, default: int) -> int:
    raw = os.getenv(var_name)
    if raw is None:
        return default
    candidate = raw.strip()
    if not candidate:
        return default
    try:
        value = int(candidate)
        if value < 0:
            return default
        return value
    except ValueError:
        return default


ENV_SWITCH_IMAGE_REQUIREMENT = _load_positive_int_from_env("SW_NUM_IMG", 2)
ENV_AP_IMAGE_REQUIREMENT = _load_positive_int_from_env("AP_NUM_IMG", 2)


class DeviceNamingConventionCheck(ComplianceCheck):
    id = "device_naming_convention"
    name = "Device naming convention"
    description = "Ensure device names follow the configured naming convention."
    severity = "warning"

    def __init__(
        self,
        switch_pattern: Optional[re.Pattern[str] | str] = None,
        ap_pattern: Optional[re.Pattern[str] | str] = None,
    ) -> None:
        self.switch_pattern = _ensure_pattern(switch_pattern, ENV_SWITCH_NAME_PATTERN)
        self.ap_pattern = _ensure_pattern(ap_pattern, ENV_AP_NAME_PATTERN)

    def run(self, context: SiteContext) -> List[Finding]:
        findings: List[Finding] = []
        for device in context.devices:
            if not isinstance(device, dict):
                continue

            pattern: Optional[re.Pattern[str]] = None
            label = "Device"
            if _is_switch(device):
                pattern = self.switch_pattern
                label = "Switch"
            elif _is_access_point(device):
                pattern = self.ap_pattern
                label = "Access point"

            if pattern is None:
                continue

            device_id = str(device.get("id")) if device.get("id") is not None else None
            device_name = (
                (device.get("name") or device.get("hostname") or device.get("device_name") or "")
                .strip()
            )
            if not device_name or not pattern.fullmatch(device_name):
                if label == "Switch" and pattern.pattern == DEFAULT_SWITCH_NAME_PATTERN:
                    message = (
                        "Switch name does not match required convention (e.g., NACHIMDFWS1, "
                        "NACHIIDF1AS3, or NACHIMDFSPARE)."
                    )
                else:
                    message = f"{label} name does not match required convention."

                findings.append(
                    Finding(
                        site_id=context.site_id,
                        site_name=context.site_name,
                        device_id=device_id,
                        device_name=device_name or device_id or "device",
                        message=message,
                        details={"expected_pattern": pattern.pattern},
                    )
                )
        return findings


def _collect_device_images(device: Dict[str, Any]) -> List[str]:
    image_keys = ("images", "pictures", "photos", "image_urls", "image")
    image_url_pattern = re.compile(r"^image\d+_url$", re.IGNORECASE)
    images: List[str] = []

    def append_images(value: Any) -> None:
        if isinstance(value, str):
            text = value.strip()
            if text:
                images.append(text)
        elif isinstance(value, list):
            for item in value:
                append_images(item)
        elif isinstance(value, dict):
            for item in value.values():
                append_images(item)

    for key in image_keys:
        value = device.get(key)
        if value is not None:
            append_images(value)

    for key, value in device.items():
        if isinstance(key, str) and image_url_pattern.match(key):
            append_images(value)

    # Deduplicate while preserving order
    seen: Set[str] = set()
    unique_images: List[str] = []
    for url in images:
        if url not in seen:
            seen.add(url)
            unique_images.append(url)
    return unique_images


class DeviceDocumentationCheck(ComplianceCheck):
    id = "device_documentation"
    name = "Device documentation"
    description = "Ensure devices are mapped to floorplans and have required reference images."
    severity = "warning"

    def __init__(
        self,
        *,
        switch_min_images: Optional[int] = None,
        ap_min_images: Optional[int] = None,
        default_min_images: int = 2,
    ) -> None:
        def _sanitize(value: Optional[int], fallback: int) -> int:
            if value is None:
                return max(fallback, 0)
            if value < 0:
                return max(fallback, 0)
            return value

        self.switch_min_images = _sanitize(switch_min_images, ENV_SWITCH_IMAGE_REQUIREMENT)
        self.ap_min_images = _sanitize(ap_min_images, ENV_AP_IMAGE_REQUIREMENT)
        self.default_min_images = _sanitize(default_min_images, 2)

    def run(self, context: SiteContext) -> List[Finding]:
        findings: List[Finding] = []
        for device in context.devices:
            if not isinstance(device, dict):
                continue
            device_id = str(device.get("id")) if device.get("id") is not None else None
            device_name = _normalize_site_name(device) or device_id or "device"
            map_id = device.get("map_id")
            if not map_id:
                findings.append(
                    Finding(
                        site_id=context.site_id,
                        site_name=context.site_name,
                        device_id=device_id,
                        device_name=device_name,
                        message="Device not assigned to any floorplan.",
                    )
                )
            images = _collect_device_images(device)
            required_images = self.default_min_images
            if _is_switch(device):
                required_images = self.switch_min_images
            elif _is_access_point(device):
                required_images = self.ap_min_images

            if required_images <= 0:
                continue

            if len(images) < required_images:
                findings.append(
                    Finding(
                        site_id=context.site_id,
                        site_name=context.site_name,
                        device_id=device_id,
                        device_name=device_name,
                        message=(
                            f"Required images not present (found {len(images)} of {required_images})."
                        ),
                    )
                )
        return findings


class SiteAuditRunner:
    """Runs a suite of compliance checks across one or more sites."""

    def __init__(self, checks: Sequence[ComplianceCheck]):
        self.checks: List[ComplianceCheck] = list(checks)

    def run(self, contexts: Sequence[SiteContext]) -> Dict[str, Any]:
        results: List[Dict[str, Any]] = []
        total_sites = len(contexts)
        total_devices = 0
        site_devices: Dict[str, int] = {}
        for context in contexts:
            devices = context.devices
            if isinstance(devices, Sequence) and not isinstance(devices, (str, bytes)):
                count = len(devices)
                total_devices += count
            else:
                count = 0
            site_devices[context.site_id] = count
        total_findings = 0
        site_findings: Dict[str, int] = {context.site_id: 0 for context in contexts}
        for check in self.checks:
            check_findings: List[Finding] = []
            for context in contexts:
                site_findings_for_check = check.run(context)
                check_findings.extend(site_findings_for_check)
                site_findings[context.site_id] = site_findings.get(context.site_id, 0) + len(
                    site_findings_for_check
                )
            total_findings += len(check_findings)
            failing_site_ids = sorted({finding.site_id for finding in check_findings})
            results.append(
                {
                    "id": check.id,
                    "name": check.name,
                    "description": check.description,
                    "severity": check.severity,
                    "findings": [finding.as_dict(check.severity) for finding in check_findings],
                    "failing_sites": failing_site_ids,
                    "passing_sites": max(total_sites - len(failing_site_ids), 0),
                }
            )
        return {
            "checks": results,
            "total_sites": total_sites,
            "total_devices": total_devices,
            "total_findings": total_findings,
            "site_findings": site_findings,
            "site_devices": site_devices,
        }


DEFAULT_CHECKS: Sequence[ComplianceCheck] = (
    RequiredSiteVariablesCheck(),
    SwitchTemplateConfigurationCheck(),
    ConfigurationOverridesCheck(),
    DeviceNamingConventionCheck(),
    DeviceDocumentationCheck(),
)


def build_default_runner() -> SiteAuditRunner:
    return SiteAuditRunner(DEFAULT_CHECKS)
