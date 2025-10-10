"""Compliance/audit checks for Mist site configuration."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence, Set


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


class RequiredSiteVariablesCheck(ComplianceCheck):
    id = "required_site_variables"
    name = "Required site variables"
    description = "Ensure required Mist site variables are defined."
    severity = "error"

    required_keys: Sequence[str] = ("hubradiusserver", "localradiusserver")

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


class LabTemplateRestrictionCheck(ComplianceCheck):
    id = "lab_template_scope"
    name = "Lab template scope"
    description = "Validate that the lab template is only applied to lab sites."
    severity = "warning"

    template_name: str = "Test - Standard Template"

    def run(self, context: SiteContext) -> List[Finding]:
        template_names = _collect_template_names(context)
        if not template_names:
            return []
        if self.template_name not in template_names:
            return []
        if "lab" in context.site_name.lower():
            return []
        return [
            Finding(
                site_id=context.site_id,
                site_name=context.site_name,
                message=(
                    f"Template '{self.template_name}' is applied but the site name does not appear to be a lab."
                ),
            )
        ]


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

        for device in context.devices:
            if not isinstance(device, dict):
                continue
            device_id = str(device.get("id")) if device.get("id") is not None else None
            device_name = _normalize_site_name(device) or device_id or "device"

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
            if not port_overrides:
                continue
            access_switch = _is_access_switch(device)
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

        return findings


class SiteAuditRunner:
    """Runs a suite of compliance checks across one or more sites."""

    def __init__(self, checks: Sequence[ComplianceCheck]):
        self.checks: List[ComplianceCheck] = list(checks)

    def run(self, contexts: Sequence[SiteContext]) -> Dict[str, Any]:
        results: List[Dict[str, Any]] = []
        total_sites = len(contexts)
        for check in self.checks:
            check_findings: List[Finding] = []
            for context in contexts:
                check_findings.extend(check.run(context))
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
        }


DEFAULT_CHECKS: Sequence[ComplianceCheck] = (
    RequiredSiteVariablesCheck(),
    LabTemplateRestrictionCheck(),
    ConfigurationOverridesCheck(),
)


def build_default_runner() -> SiteAuditRunner:
    return SiteAuditRunner(DEFAULT_CHECKS)
