"""Keep audit remediation from changing currently approved deviations."""

from __future__ import annotations

import copy

from audit_actions import (
    AP_RENAME_ACTION_ID, CLEAR_DNS_OVERRIDE_ACTION_ID, ENABLE_CLOUD_MANAGEMENT_ACTION_ID,
    SET_SITE_VARIABLES_ACTION_ID, SET_SPARE_SWITCH_ROLE_ACTION_ID, SET_VIRTUAL_CHASSIS_ROLES_ACTION_ID,
)


def protects(record, device_id, field):
    if record["device_id"] != device_id:
        return False
    path = record["path"]
    for prefix in ("switch_config.", "config.", "configuration.", "device_config."):
        if path.startswith(prefix):
            path = path[len(prefix):]
    if "override" in path and not path.startswith("port_overrides"):
        # Override blobs cannot always be safely narrowed to individual writes.
        return True
    if field == "members":
        return path.startswith("members[") or path == "members"
    return path == field or path.startswith(field + ".") or path.startswith(field + "[") or field.startswith(path + ".")


def action_protected(action_id, record, device_id=None, variables=None):
    field = {
        AP_RENAME_ACTION_ID: "name", CLEAR_DNS_OVERRIDE_ACTION_ID: "ip_config.dns",
        ENABLE_CLOUD_MANAGEMENT_ACTION_ID: "disable_auto_config",
        SET_VIRTUAL_CHASSIS_ROLES_ACTION_ID: "members", SET_SPARE_SWITCH_ROLE_ACTION_ID: "role",
    }.get(action_id)
    if action_id == SET_SPARE_SWITCH_ROLE_ACTION_ID and record["path"] == "spare_switch_presence":
        return True
    if action_id == SET_SPARE_SWITCH_ROLE_ACTION_ID:
        return any(protects(record, device_id, field) for field in ("role", "name", "port_config", "port_overrides"))
    if action_id == SET_SITE_VARIABLES_ACTION_ID:
        return any(protects(record, None, "variables." + key) for key in (variables or []))
    return bool(field and protects(record, device_id, field))


def filter_suggested_actions(actions, approved, site_id=None):
    result = []
    for original in actions or []:
        action = copy.deepcopy(original)
        scoped = [r for r in approved if not site_id or r["site_id"] == site_id]
        metadata = action.get("metadata") or {}
        action_id = action.get("id")
        if action.get("devices"):
            action["devices"] = [d for d in action["devices"] if not any(
                r["site_id"] == d["site_id"] and action_protected(action_id, r, d["device_id"]) for r in scoped)]
            if not action["devices"]:
                continue
        elif action_id == SET_VIRTUAL_CHASSIS_ROLES_ACTION_ID:
            if any(action_protected(action_id, r, metadata.get("vc_device_id")) for r in scoped):
                continue
        elif action_id == SET_SPARE_SWITCH_ROLE_ACTION_ID:
            if any(r["path"] == "spare_switch_presence" for r in scoped):
                continue
            if metadata.get("switch_options"):
                metadata["switch_options"] = [d for d in metadata["switch_options"] if not any(
                    action_protected(action_id, r, d["device_id"]) for r in scoped)]
                if not metadata["switch_options"]:
                    continue
        elif action_id == SET_SITE_VARIABLES_ACTION_ID:
            metadata["variables"] = {key: value for key, value in metadata.get("variables", {}).items()
                                     if not any(action_protected(action_id, r, variables=[key]) for r in scoped)}
            if not metadata["variables"]:
                continue
        action["metadata"] = metadata
        result.append(action)
    return result


def guarded_execute(dispatch, action_id, base_url, token, site_ids, *, records, context_loader=None,
                    dry_run=False, pause=0.2, device_map=None, metadata=None):
    relevant = [r for r in records if not r.get("revoked_at") and r["origin"] == base_url.rstrip("/")
                and r["site_id"] in site_ids]
    kwargs = dict(dry_run=dry_run, pause=pause, device_map=device_map, metadata=metadata)
    if not relevant:
        return dispatch(action_id, base_url, token, site_ids, **kwargs)

    import compliance as c

    summaries = []
    contexts, _ = (context_loader(base_url, {"Authorization": f"Token {token}", "Accept": "application/json"}, site_ids)
                        if context_loader else ([], []))
    by_site = {ctx.site_id: ctx for ctx in contexts}
    for site_id in dict.fromkeys(site_ids):
        summary = {"site_id": site_id, "site_name": site_id, "updated": 0, "skipped": 0,
                   "failed": 0, "changes": [], "errors": []}

        def skip(reason, device_id=None, variable=None):
            summary["skipped"] += 1
            summary["changes"].append({"status": "skipped", "reason": reason,
                                       "device_id": device_id, "variable": variable})

        context = by_site.get(site_id)
        if context is None:
            skip("Cannot verify current audit exceptions; no changes made for this site.")
            summaries.append(summary)
            continue
        summary["site_name"] = context.site_name
        check_ids = {r["check_id"] for r in relevant if r["site_id"] == site_id}
        checks = c.build_default_runner(check_ids=check_ids, refresh_standards=False).checks
        result = c.SiteAuditRunner(checks).run([context], exception_records=relevant, origin=base_url)
        approved = [f["exception"] for check in result["checks"] for f in check["approved_exceptions"]]
        org_id = context.site.get("org_id") or context.setting.get("org_id")
        if not org_id:
            skip("Cannot verify the organization for current audit exceptions; no changes made.")
            summaries.append(summary)
            continue
        # Missing API data is uncertainty, not evidence that approval no longer applies.
        vc_ids = {str(doc.get("root_device_id") or doc.get("id")) for doc in context.vc_documents}
        approved.extend(r for r in relevant if r["site_id"] == site_id and r["org_id"] == str(org_id)
                        and (context.unavailable_sources or r["device_id"] in context.unavailable_device_ids
                             or r["check_id"] == "virtual_chassis_roles" and r["device_id"] not in vc_ids))
        scoped_metadata = copy.deepcopy(dict(metadata or {}))
        scoped_devices = None
        run = True
        if action_id in (AP_RENAME_ACTION_ID, CLEAR_DNS_OVERRIDE_ACTION_ID, ENABLE_CLOUD_MANAGEMENT_ACTION_ID):
            if device_map is not None:
                targets = list(device_map.get(site_id, []))
            else:
                targets = [str(d["id"]) for d in context.devices if isinstance(d, dict) and d.get("id")
                           and (c._is_access_point(d) if action_id == AP_RENAME_ACTION_ID else c._is_switch(d))]
            allowed = []
            for device_id in dict.fromkeys(targets):
                if any(action_protected(action_id, r, device_id) for r in approved):
                    skip("Approved audit exception protects this configuration.", device_id)
                else:
                    allowed.append(device_id)
            scoped_devices = {site_id: allowed}
            run = bool(allowed)
        elif action_id == SET_SITE_VARIABLES_ACTION_ID:
            _, defaults = c.load_site_variable_config()
            variables = scoped_metadata.get("variables") or defaults
            allowed = {}
            for key, value in variables.items():
                if any(action_protected(action_id, r, variables=[key]) for r in approved):
                    skip("Approved audit exception protects this site variable.", variable=key)
                else:
                    allowed[key] = value
            scoped_metadata["variables"] = allowed
            # Never dispatch an empty list: the existing handler falls back to all defaults.
            run = bool(allowed)
        else:
            target = scoped_metadata.get("vc_device_id") if action_id == SET_VIRTUAL_CHASSIS_ROLES_ACTION_ID else scoped_metadata.get("selected_switch_id")
            if any(action_protected(action_id, r, target) for r in approved):
                skip("Approved audit exception protects this operation's configuration.", target)
                run = False
        if run:
            response = dispatch(action_id, base_url, token, [site_id], dry_run=dry_run, pause=pause,
                                device_map=scoped_devices if scoped_devices is not None else device_map,
                                metadata=scoped_metadata)
            for item in response.get("results", []):
                for key in ("updated", "skipped", "failed"):
                    summary[key] += item.get(key, item.get("renamed", 0) if key == "updated" else 0)
                summary["changes"].extend(item.get("changes", []))
                summary["errors"].extend(item.get("errors", []))
        summaries.append(summary)
    totals = {key: sum(item[key] for item in summaries) for key in ("updated", "skipped", "failed")}
    reasons = sorted({change["reason"] for summary in summaries for change in summary["changes"]
                      if change.get("status") == "skipped" and change.get("reason")})
    totals.update(sites=len(summaries), summary=f"Updated {totals['updated']}; skipped {totals['skipped']}; failed {totals['failed']}. " + " ".join(reasons))
    return {"ok": True, "action_id": action_id, "dry_run": dry_run, "results": summaries, "totals": totals}
