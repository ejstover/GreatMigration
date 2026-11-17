"""Translate supported checks into stable, independently approvable deviations."""

from __future__ import annotations

import copy
from dataclasses import replace
from typing import Any

from audit_exceptions import candidate_for


def state(value: Any, present: bool = True) -> dict[str, Any]:
    return {"present": present, **({"value": value} if present else {})}


def path_state(document: Any, path: str) -> dict[str, Any]:
    """Read audit paths, including Mist keys containing dots and list indexes."""
    if path in ("", "."):
        return state(document)
    if isinstance(document, dict):
        for key in sorted(document, key=lambda key: len(str(key)), reverse=True):
            if path == key:
                return state(document[key])
            if path.startswith(str(key) + "."):
                return path_state(document[key], path[len(key) + 1:])
            if path.startswith(str(key) + "["):
                return path_state(document[key], path[len(key):])
    if isinstance(document, list) and path.startswith("["):
        index, separator, rest = path[1:].partition("]")
        if separator and index.isdigit() and int(index) < len(document):
            return path_state(document[int(index)], rest.lstrip("."))
    return state(None, False)


def leaf_states(value: Any, prefix: str):
    if isinstance(value, dict) and value:
        for key, child in value.items():
            yield from leaf_states(child, prefix + "." + str(key))
    else:
        yield prefix, state(value)


def expand_finding(check: Any, context: Any, finding: Any, origin: str = "") -> list[Any]:
    # Imported at call time so the runner can use this module without a cycle.
    import compliance as c

    device = next((d for d in context.devices if isinstance(d, dict)
                   and str(d.get("id")) == finding.device_id), None)
    if finding.device_id in context.unavailable_device_ids or context.unavailable_sources:
        return [finding]
    if (finding.device_id or finding.device_name) and not finding.device_id:
        return [finding]
    details = finding.details or {}
    parts: list[tuple[str, Any, Any, dict, Any]] = []
    check_id = check.id
    if check_id == "configuration_overrides":
        source = device if device is not None else context.setting
        if details.get("diffs"):
            config = c._extract_device_switch_config(source) or source
            for diff in details["diffs"]:
                path = diff["path"]
                actions = finding.actions if path == "ip_config.dns" else None
                observed = path_state(config, path)
                if not observed["present"]:
                    observed = path_state(source, path)
                # Operational interface health is not a configuration exception.
                if path == "if_stat" or path.startswith("if_stat."):
                    parts.append((path, None, None, {"diffs": [diff]}, None))
                    continue
                observed = {"configured": observed, "evaluated": diff.get("actual")}
                parts.append((path, observed, state(diff.get("expected"), diff.get("expected_present", True)),
                              {"diffs": [diff]}, actions))
        else:
            paths = details.get("paths") or [details.get("path")]
            for path in paths:
                if not path:
                    continue
                stable_path = path
                # A port's identity must survive reordering the override list.
                if path.startswith("port_overrides["):
                    label = details.get("port")
                    if not label:
                        continue
                    stable_path = f"port_overrides.{label}"
                expected = {"rule": "no_configuration_override", "version": 1}
                if path.startswith("port_overrides"):
                    expected.update(allowed_access_port_max=check.allowed_access_port_max,
                                    access_switch=c._is_access_switch(source))
                observed = path_state(source, path)
                for leaf_path, leaf_value in leaf_states(observed.get("value"), stable_path):
                    parts.append((leaf_path, leaf_value if observed["present"] else observed, expected,
                                  {**details, "paths": [leaf_path]}, None))
    elif check_id == "required_site_variables":
        key = details.get("variable_key")
        if key:
            variables = c._collect_site_variables(context)
            parts.append((f"variables.{key}", state(variables.get(key), key in variables),
                          {"required": True, "default": state(check.variable_defaults.get(key), key in check.variable_defaults)},
                          details, finding.actions))
    elif check_id == "switch_template_configuration":
        expected = c._expected_template_details(context.site_name)
        parts.append(("templates", {"ids": sorted(c._collect_template_ids(context)), "names": sorted(c._collect_template_names(context))},
                      {"allowed_names": sorted(expected["allowed_template_names"]),
                       "allowed_ids": sorted(expected["allowed_template_ids"]),
                       "production_name": check.prod_template_name, "lab_name": check.lab_template_name,
                       "lab": "LAB" in context.site_name.upper()}, details, finding.actions))
    elif check_id == "firmware_management" and device is not None:
        version_paths = ("firmware_version", "version", "ap_fw_version", "sw_version", "details.version")
        version_path = next((path for path in version_paths if isinstance(path_state(device, path).get("value"), str)
                             and path_state(device, path)["value"].strip()),
                            next((path for path in version_paths if path_state(device, path)["present"]), "version"))
        parts.append(("version", {"version": path_state(device, version_path), "model": c._normalize_device_model(device.get("model"))},
                      {"allowed_versions": sorted(details["allowed_versions"])}, details, finding.actions))
    elif check_id == "cloud_management" and device is not None:
        parts.append(("disable_auto_config", path_state(device, "disable_auto_config"), state(False), details, finding.actions))
    elif check_id == "device_naming_convention" and device is not None:
        pattern = check.ap_pattern if c._is_access_point(device) else check.switch_pattern
        expected = {"pattern": pattern.pattern, "flags": pattern.flags}
        path = "name"
        if "mismatches" in details:
            path = "name.alignment"
            expected.update(switch_region=details["switch_region"], switch_site=details["switch_site"],
                            switch_location=details["switch_location"], switch_pattern=check.switch_pattern.pattern,
                            switch_flags=check.switch_pattern.flags)
        name_path = next((key for key in ("name", "hostname", "device_name") if device.get(key)), "name")
        parts.append((path, {"name": path_state(device, name_path)},
                      expected, details, finding.actions))
    elif check_id == "spare_switch_presence":
        switches = sorted(({"id": str(d.get("id")), "role": state(d.get("role"), "role" in d)}
                           for d in context.devices if isinstance(d, dict) and c._is_switch(d)), key=lambda d: d["id"])
        parts.append(("spare_switch_presence", switches, {"minimum_spares": 1, "role": "spare"}, details, finding.actions))
    elif check_id == "virtual_chassis_roles" and finding.device_id:
        members = details.get("members", [])
        layout = sorted(({"member_id": m["member_id"], "model": m.get("model"), "expected_role": m.get("expected_role")}
                         for m in members), key=lambda m: str(m["member_id"]))
        for member in members:
            if member.get("expected_role") == member.get("current_role"):
                continue
            if member.get("member_id") is None or not member.get("mac"):
                continue
            parts.append((f"members[{member['member_id']}].vc_role",
                          {"mac": member["mac"], "role": member.get("current_role")},
                          {"role": member.get("expected_role"), "layout": layout,
                           "num_routing_engines": details.get("num_routing_engines")},
                          {"member": member}, finding.actions))
    if not parts:
        return [finding]
    result = []
    for path, observed, expected, part_details, actions in parts:
        item = replace(finding, details=copy.deepcopy(part_details), actions=copy.deepcopy(actions))
        if observed is not None:
            item.exception_candidate = candidate_for(context, check_id, finding.device_id, path, observed, expected, origin)
        result.append(item)
    return result
