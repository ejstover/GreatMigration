"""Typed policy forms around the existing, tested specialist checks."""
from __future__ import annotations

from standards_errors import StandardsValidationError

import copy
from contextvars import ContextVar

from standards_engine import compile_pattern

OPTIONS = ContextVar("standard_specialist_options", default={})


def option(name, default):
    return OPTIONS.get().get(name, default)


def pattern_option(name, default):
    value = OPTIONS.get().get(name)
    return TimedPattern(value) if value is not None else default


def definitions():
    import compliance as c
    # Types are deliberately narrow: these are configuration forms, not object mutation.
    spec = {
        "required_site_variables": (c.RequiredSiteVariablesCheck, {"required_keys": "strings", "variable_defaults": "mapping"}),
        "switch_template_configuration": (c.SwitchTemplateConfigurationCheck, {"prod_template_name": "string", "lab_template_name": "string"}),
        "site_sle_summary": (c.SiteSleSummaryCheck, {"duration": "string", "minimum_score": "fraction"}),
        "configuration_overrides": (c.ConfigurationOverridesCheck, {"allowed_access_port_max": "integer", "production_template_name": "string", "lab_template_name": "string", "production_template_ids": "strings", "lab_template_ids": "strings", "dns_variable_groups": "groups"}),
        "firmware_management": (c.FirmwareManagementCheck, {"allowed_switch_versions": "optional_strings", "allowed_ap_versions": "optional_strings"}),
        "cloud_management": (c.CloudManagementCheck, {}),
        "switch_cable_test": (c.SwitchCableTestCheck, {"timeout": "positive", "excluded_roles": "strings", "active_traffic_bytes": "positive"}),
        "switch_power_supply_health": (c.SwitchPowerSupplyHealthCheck, {"healthy_statuses": "strings"}),
        "spare_switch_presence": (c.SpareSwitchPresenceCheck, {"minimum_spares": "integer"}),
        "virtual_chassis_roles": (c.VirtualChassisRoleCheck, {}),
        "device_naming_convention": (c.DeviceNamingConventionCheck, {"switch_pattern": "optional_pattern", "ap_pattern": "optional_pattern"}),
        "device_documentation": (c.DeviceDocumentationCheck, {"switch_min_images": "integer", "ap_min_images": "integer", "default_min_images": "integer"}),
    }
    return spec


def defaults(check_id):
    import compliance as c
    cls, fields = definitions()[check_id]
    check = cls(refresh_standards=False) if check_id == "firmware_management" else cls()
    values = {}
    extras = {
        "minimum_score": 0.999999, "minimum_spares": 1, "healthy_statuses": ["ok"],
        "production_template_name": c.DNS_OVERRIDE_TEMPLATE_NAME, "lab_template_name": c.DNS_OVERRIDE_LAB_TEMPLATE_NAME,
        "production_template_ids": list(c.DNS_OVERRIDE_PROD_TEMPLATE_IDS), "lab_template_ids": list(c.DNS_OVERRIDE_LAB_TEMPLATE_IDS),
        "dns_variable_groups": [list(g) for g in c.DNS_OVERRIDE_REQUIRED_VAR_GROUPS],
        "excluded_roles": list(c.CABLE_TEST_EXCLUDED_ROLES), "active_traffic_bytes": c.CABLE_TEST_ACTIVE_TRAFFIC_BYTES_THRESHOLD,
    }
    for key in fields:
        value = getattr(check, key, extras.get(key))
        if key in ("allowed_switch_versions", "allowed_ap_versions"):
            value = None  # Preserve live per-model firmware matrix selection.
        if hasattr(value, "pattern"):
            value = value.pattern
        if isinstance(value, tuple):
            value = list(value)
        values[key] = value
    return check, values


def seed_policies():
    import compliance as c
    policies = []
    for prototype in c.DEFAULT_CHECKS:
        check, params = defaults(prototype.id)
        policies.append({"id": check.id, "revision": 1, "name": check.name, "description": check.description,
                         "severity": check.severity, "enabled": True, "target": {"kind": "site"},
                         "requirement": {"kind": "specialist", "check": check.id, "parameters": params}})
    return policies


def validate_specialist(node, policy):
    check_id = node.get("check")
    if check_id not in definitions():
        raise StandardsValidationError("Unknown specialist block")
    if node is not policy.get("requirement"):
        raise StandardsValidationError("A specialist must be the policy's root requirement; use its applicability conditions for filtering")
    # Existing action/exception identifiers must stay bound to their original meaning.
    if policy["id"] != check_id:
        raise StandardsValidationError("Edit the existing specialist policy; specialist identifiers cannot be duplicated or reassigned")
    if policy.get("target", {}).get("kind", "device") != "site" or any(policy.get("target", {}).get(k) for k in ("models", "device_types")):
        raise StandardsValidationError("Specialist blocks use site targets; use field rules for device/model selectors")
    params = node.get("parameters", {})
    fields = definitions()[check_id][1]
    if not isinstance(params, dict) or set(params) != set(fields):
        raise StandardsValidationError("Specialist parameters must match its published form")
    for key, kind in fields.items():
        value = params[key]
        valid = False
        if kind.startswith("optional_") and value is None:
            continue
        if kind in ("strings", "optional_strings"):
            valid = isinstance(value, list) and len(value) <= 500 and all(isinstance(x, str) and len(x) <= 500 for x in value)
        elif kind == "groups":
            valid = isinstance(value, list) and len(value) <= 100 and all(isinstance(g, list) and g and all(isinstance(x, str) for x in g) for g in value)
        elif kind == "mapping":
            valid = isinstance(value, dict) and len(value) <= 500 and all(isinstance(k, str) and isinstance(v, str) for k, v in value.items())
        elif kind == "integer":
            valid = type(value) is int and 0 <= value <= 10000
        elif kind in ("positive", "fraction"):
            valid = type(value) in (int, float) and 0 < value <= (1 if kind == "fraction" else 1000000)
        elif kind in ("string", "optional_pattern"):
            valid = isinstance(value, str) and len(value) <= 2000
            if valid and kind == "optional_pattern":
                compile_pattern(value)
        if not valid:
            raise StandardsValidationError(f"Invalid specialist parameter: {key}")


class TimedPattern:
    """re-compatible subset used by existing naming and location checks."""
    def __init__(self, pattern):
        import re
        self.pattern = pattern
        self.flags = re.compile(pattern).flags
        self.compiled = compile_pattern(pattern)

    def fullmatch(self, value):
        return self.compiled.fullmatch(value, timeout=0.025)

    def match(self, value):
        return self.compiled.match(value, timeout=0.025)


def instantiate(policy, refresh_standards=True):
    node = policy["requirement"]
    check_id, params = node["check"], copy.deepcopy(node["parameters"])
    cls = definitions()[check_id][0]
    kwargs = {}
    constructor = {
        "required_site_variables": ("required_keys",), "site_sle_summary": ("duration",),
        "firmware_management": ("allowed_switch_versions", "allowed_ap_versions"),
        "switch_cable_test": ("timeout",),
        "device_documentation": ("switch_min_images", "ap_min_images", "default_min_images"),
    }
    for key in constructor.get(check_id, ()):
        kwargs[key] = params[key]
    if check_id == "firmware_management":
        kwargs["refresh_standards"] = refresh_standards
    if check_id == "device_naming_convention":
        # None explicitly disables a pattern instead of falling back to the environment.
        check = cls(switch_pattern=".*", ap_pattern=".*")
        check.switch_pattern = TimedPattern(params["switch_pattern"]) if params["switch_pattern"] is not None else None
        check.ap_pattern = TimedPattern(params["ap_pattern"]) if params["ap_pattern"] is not None else None
    else:
        check = cls(**kwargs)
    for key in ("variable_defaults", "prod_template_name", "lab_template_name", "allowed_access_port_max", "minimum_score", "healthy_statuses", "minimum_spares"):
        if key in params:
            setattr(check, key, params[key])
    check.name, check.description, check.severity = policy["name"], policy.get("description", ""), policy.get("severity", "warning")
    check.policy = copy.deepcopy(policy)
    return check
