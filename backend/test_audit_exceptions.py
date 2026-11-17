"""Value-specific approvals, persistence, API authorization, and remediation safety."""

import importlib
import json
import subprocess
import sys
from pathlib import Path

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient

BACKEND = Path(__file__).resolve().parent
if str(BACKEND) not in sys.path:
    sys.path.insert(0, str(BACKEND))

import audit_exceptions as store
import audit_fixes
import compliance as c
from audit_exception_evidence import path_state
from audit_actions import ENABLE_CLOUD_MANAGEMENT_ACTION_ID, SET_SITE_VARIABLES_ACTION_ID

ORIGIN = "https://mist.example/api/v1"


@pytest.fixture
def local_store(tmp_path, monkeypatch):
    path = tmp_path / "exceptions.json"
    monkeypatch.setattr(store, "EXCEPTIONS_PATH", path)
    return path


@pytest.fixture
def context():
    return c.SiteContext(site_id="s1", site_name="Local Site", site={"org_id": "org1"},
                         mist_base_url=ORIGIN, devices=[{"id": "d1", "type": "switch", "name": "Local Switch",
                                                       "disable_auto_config": True}])


def run(context, records=(), checks=None):
    return c.SiteAuditRunner(checks or [c.CloudManagementCheck()]).run(
        [context], exception_records=records, origin=ORIGIN)


def candidate(context):
    return run(context)["checks"][0]["findings"][0]["exception_candidate"]


def test_exact_match_is_separate_and_excluded_from_actionable_totals(local_store, context):
    record = store.approve(candidate(context), "Locally managed by design", "operator")
    result = run(context, store.load_records())
    assert result["total_findings"] == result["total_quick_fix_issues"] == 0
    assert result["total_exceptions"] == result["site_exceptions"]["s1"] == 1
    check = result["checks"][0]
    assert check["passing_sites"] == 1 and check["failing_sites"] == []
    assert check["approved_exceptions"][0]["exception"]["id"] == record["id"]
    assert "actions" not in check["approved_exceptions"][0]
    # Labels and telemetry are not configuration evidence.
    context.site_name = "Renamed Site"
    context.devices[0].update(name="Renamed Switch", last_seen=999, uptime=500)
    assert run(context, store.load_records())["total_exceptions"] == 1


@pytest.mark.parametrize("scope", ["org", "site", "device", "origin"])
def test_exception_never_transfers_scope(local_store, context, scope):
    store.approve(candidate(context), "reason", "operator")
    if scope == "org":
        context.site["org_id"] = "other"
    elif scope == "site":
        context.site_id = "other"
    elif scope == "device":
        context.devices[0]["id"] = "replacement"
    else:
        records = store.load_records()
        records[0]["origin"] = "https://other/api/v1"
        records[0]["fingerprint"] = store.fingerprint(records[0])
        assert run(context, records)["total_exceptions"] == 0
        return
    assert run(context, store.load_records())["total_findings"] == 1


def test_duplicate_revoke_restart_and_reapprove(local_store, context):
    evidence = candidate(context)
    first = store.approve(evidence, "reason", "alice")
    duplicate = store.approve(evidence, "different reason", "bob")
    assert first == duplicate
    assert len(json.loads(local_store.read_text())["exceptions"]) == 1
    # A fresh disk read is the source of truth; there is no process-local approval cache.
    assert store.load_records()[0]["approved_by"] == "alice"
    revoked = store.revoke(first["id"], "bob")
    assert store.revoke(first["id"], "charlie") == revoked
    assert run(context, store.load_records())["total_exceptions"] == 0
    assert store.approve(evidence, "reviewed again", "charlie")["id"] != first["id"]
    assert len(store.load_records()) == 2


def test_missing_null_and_literal_dotted_keys_are_distinct():
    assert path_state({}, "x") != path_state({"x": None}, "x")
    assert path_state({"ports": {"ge-0/0/0.0": {"usage": "local"}}}, "ports.ge-0/0/0.0.usage")["value"] == "local"
    assert path_state({"list": [{"x": None}]}, "list[0].x") == {"present": True, "value": None}


class DiffCheck(c.ConfigurationOverridesCheck):
    def __init__(self, expected_dns="standard"):
        self.expected_dns = expected_dns

    def run(self, context):
        device = context.devices[0]
        config = device["switch_config"]
        return [c.Finding(context.site_id, context.site_name, "Configuration differs", device_id=device["id"],
                          details={"diffs": [{"path": "ip_config.dns", "actual": config["ip_config"].get("dns"), "expected": self.expected_dns},
                                             {"path": "ip_config.gateway", "actual": config["ip_config"]["gateway"], "expected": "10.0.0.1"}]})]


def test_partial_approval_changed_value_and_changed_standard(local_store, context):
    context.devices[0]["switch_config"] = {"ip_config": {"dns": ["local"], "gateway": "10.1.1.1"}}
    check = DiffCheck()
    original = run(context, checks=[check])
    assert original["total_findings"] == 2
    dns = original["checks"][0]["findings"][0]["exception_candidate"]
    store.approve(dns, "Local DNS", "alice")
    result = run(context, store.load_records(), [check])
    assert result["total_exceptions"] == result["total_findings"] == 1
    assert result["checks"][0]["findings"][0]["exception_candidate"]["path"] == "ip_config.gateway"
    context.devices[0]["switch_config"]["ip_config"]["dns"] = ["new local DNS"]
    assert run(context, store.load_records(), [check])["total_exceptions"] == 0
    context.devices[0]["switch_config"]["ip_config"]["dns"] = ["local"]
    check.expected_dns = "new standard"
    assert run(context, store.load_records(), [check])["total_exceptions"] == 0


def test_nested_override_fields_and_port_order_have_stable_candidates(context):
    context.devices[0].update(config_override={"dns": "local", "ntp": "local"},
                              port_overrides=[{"port_id": "xe-0/0/48", "usage": "custom"},
                                              {"port_id": "xe-0/0/49", "usage": "other"}])
    result = run(context, checks=[c.ConfigurationOverridesCheck()])
    candidates = {f["exception_candidate"]["path"]: f["exception_candidate"]["fingerprint"]
                  for f in result["checks"][0]["findings"] if f.get("exception_candidate")}
    assert "config_override.dns" in candidates and "config_override.ntp" in candidates
    context.devices[0]["port_overrides"].reverse()
    after = run(context, checks=[c.ConfigurationOverridesCheck()])
    assert candidates == {f["exception_candidate"]["path"]: f["exception_candidate"]["fingerprint"]
                          for f in after["checks"][0]["findings"] if f.get("exception_candidate")}


def test_invalid_store_and_failed_atomic_replace_preserve_existing_data(local_store, context, monkeypatch):
    assert store.load_records() == []
    local_store.write_text("broken JSON")
    with pytest.raises(store.ExceptionStoreError):
        store.approve(candidate(context), "reason", "alice")
    assert local_store.read_text() == "broken JSON"
    local_store.unlink()
    store.approve(candidate(context), "reason", "alice")
    original = local_store.read_bytes()
    context.devices[0]["id"] = "d2"
    monkeypatch.setattr(store.os, "replace", lambda *args: (_ for _ in ()).throw(OSError("disk error")))
    with pytest.raises(store.ExceptionStoreError):
        store.approve(candidate(context), "reason", "alice")
    assert local_store.read_bytes() == original
    assert not list(local_store.parent.glob(".exceptions-*.tmp"))


def test_concurrent_process_saves_do_not_lose_updates(local_store, context):
    worker = """
import json, sys
from pathlib import Path
sys.path.insert(0, sys.argv[1])
import audit_exceptions as s
s.EXCEPTIONS_PATH = Path(sys.argv[2])
c = json.loads(sys.argv[3])
c['device_id'] = sys.argv[4]
c['fingerprint'] = s.fingerprint(c)
s.approve(c, 'concurrent approval', 'operator')
"""
    processes = [subprocess.Popen([sys.executable, "-c", worker, str(BACKEND), str(local_store),
                                   json.dumps(candidate(context)), f"device-{index}"],
                                  stdout=subprocess.PIPE, stderr=subprocess.PIPE) for index in range(5)]
    for process in processes:
        stdout, stderr = process.communicate(timeout=25)
        assert process.returncode == 0, stderr.decode()
    assert len(store.load_records()) == 5


@pytest.fixture
def api(monkeypatch, local_store, context):
    monkeypatch.setenv("MIST_ALLOWED_HOSTS", "mist.example")
    app = importlib.import_module("app")
    monkeypatch.setattr(app, "current_user", lambda request: {"name": "alice", "can_push": True})
    monkeypatch.setattr(app, "_load_mist_token", lambda: "test-token")
    monkeypatch.setattr(app, "_fetch_site_context", lambda *args: context)
    monkeypatch.setattr(app, "_gather_site_contexts", lambda *args: ([context], []))
    monkeypatch.setattr(app, "build_default_runner", lambda **kwargs: c.SiteAuditRunner([c.CloudManagementCheck()]))
    monkeypatch.setattr(app, "load_site_history", lambda *args: {})
    client = TestClient(app.app)
    import re
    html = client.get("/login").text
    client.headers["X-CSRF-Token"] = re.search(r'name="csrf_token" value="([^" ]+)"', html).group(1)
    return app, client


def test_api_fresh_evidence_conflict_permissions_and_revocation(api, context, local_store, monkeypatch):
    app, client = api
    evidence = candidate(context)
    payload = {**evidence, "reason": "Approved local management"}
    url = "/api/audit/exceptions?base_url=" + ORIGIN
    response = client.post(url, json=payload)
    assert response.status_code == 200, response.text
    record = response.json()["exception"]
    assert client.get(url).json()["exceptions"][0]["id"] == record["id"]
    assert client.get(url + "&org_id=another").json()["exceptions"] == []
    assert client.get(url + "&site_ids=another").json()["exceptions"] == []
    assert client.post(url, json=payload).json()["exception"]["id"] == record["id"]
    context.devices[0]["disable_auto_config"] = False
    assert client.post(url, json=payload).status_code == 409
    monkeypatch.setattr(app, "current_user", lambda request: {"name": "reader", "can_push": False})
    assert client.get(url).status_code == 200
    assert client.post(url, json=payload).status_code == 403
    assert client.post(f"/api/audit/exceptions/{record['id']}/revoke").status_code == 403
    monkeypatch.setattr(app, "current_user", lambda request: {"name": "alice", "can_push": True})
    assert client.post(f"/api/audit/exceptions/{record['id']}/revoke").json()["exception"]["revoked_by"] == "alice"
    assert client.post("/api/audit/exceptions/missing/revoke").status_code == 404
    def unauthenticated(request):
        raise HTTPException(401)
    monkeypatch.setattr(app, "current_user", unauthenticated)
    assert client.get(url).status_code == 401


def test_api_report_marks_unreadable_store_without_suppressing_findings(api, local_store):
    _, client = api
    local_store.write_text("broken JSON")
    response = client.post("/api/audit/run?base_url=" + ORIGIN, json={"site_ids": ["s1"]})
    assert response.status_code == 200, response.text
    result = response.json()
    assert result["total_findings"] == 1 and result["total_exceptions"] == 0
    assert result["exception_errors"]
    assert client.get("/api/audit/exceptions").status_code == 503


def test_api_reason_and_forged_evidence_rejected(api, context):
    _, client = api
    payload = {**candidate(context), "reason": "   "}
    url = "/api/audit/exceptions?base_url=" + ORIGIN
    assert client.post(url, json=payload).status_code == 400
    payload.update(reason="reason", fingerprint="forged")
    assert client.post(url, json=payload).status_code == 409
    payload["check_id"] = "switch_cable_test"
    assert client.post(url, json=payload).status_code == 400


def test_remediation_skips_approved_targets_and_narrows_site_wide_action(local_store, context, monkeypatch):
    store.approve(candidate(context), "local control", "alice")
    context.devices.append({"id": "d2", "type": "switch", "disable_auto_config": True})
    calls = []
    def dispatch(*args, **kwargs):
        calls.append(kwargs)
        return {"results": [{"updated": 1}]}
    monkeypatch.setattr(audit_fixes, "_execute_audit_action_unchecked", dispatch)
    loader = lambda *args: ([context], [])
    result = audit_fixes.execute_audit_action(ENABLE_CLOUD_MANAGEMENT_ACTION_ID, ORIGIN, "token", ["s1"], context_loader=loader)
    assert calls[0]["device_map"] == {"s1": ["d2"]}
    assert result["totals"]["skipped"] == result["totals"]["updated"] == 1
    calls.clear()
    result = audit_fixes.execute_audit_action(ENABLE_CLOUD_MANAGEMENT_ACTION_ID, ORIGIN, "token", ["s1"],
                                             device_map={"s1": ["d1"]}, context_loader=loader)
    assert not calls and result["totals"]["skipped"] == 1
    # Direct callers without fresh context cannot bypass the policy.
    audit_fixes.execute_audit_action(ENABLE_CLOUD_MANAGEMENT_ACTION_ID, ORIGIN, "token", ["s1"])
    assert not calls


def test_site_variable_batch_preserves_approved_key(local_store, context, monkeypatch):
    monkeypatch.setenv("MIST_SITE_VARIABLES", "dns=standard,ntp=standard")
    check = c.RequiredSiteVariablesCheck()
    result = run(context, checks=[check])
    store.approve(result["checks"][0]["findings"][0]["exception_candidate"], "No DNS variable required", "alice")
    calls = []
    def dispatch(*args, **kwargs):
        calls.append(kwargs["metadata"]["variables"])
        return {"results": [{"updated": 1}]}
    monkeypatch.setattr(audit_fixes, "_execute_audit_action_unchecked", dispatch)
    audit_fixes.execute_audit_action(SET_SITE_VARIABLES_ACTION_ID, ORIGIN, "token", ["s1"],
                                    context_loader=lambda *args: ([context], []))
    assert calls == [{"ntp": "standard"}]


def test_corrupt_store_blocks_fixes_even_with_stale_browser(local_store, monkeypatch):
    local_store.write_text("broken")
    monkeypatch.setattr(audit_fixes, "_execute_audit_action_unchecked", lambda *a, **k: pytest.fail("Must not dispatch"))
    with pytest.raises(store.ExceptionStoreError):
        audit_fixes.execute_audit_action(ENABLE_CLOUD_MANAGEMENT_ACTION_ID, ORIGIN, "token", ["s1"])


@pytest.mark.parametrize("kind", ["naming", "firmware", "templates", "spare", "variables", "vc"])
def test_supported_configuration_checks_produce_matching_evidence(kind, local_store, context, monkeypatch):
    if kind == "naming":
        check = c.DeviceNamingConventionCheck(switch_pattern="^STANDARD$")
    elif kind == "firmware":
        context.devices[0].update(version="local", model="EX2300")
        check = c.FirmwareManagementCheck(allowed_switch_versions=["standard"], allowed_ap_versions=[])
    elif kind == "templates":
        context.templates = [{"id": "local", "name": "Local Template"}]
        check = c.SwitchTemplateConfigurationCheck()
    elif kind == "spare":
        check = c.SpareSwitchPresenceCheck()
    elif kind == "variables":
        monkeypatch.setenv("MIST_SITE_VARIABLES", "dns=standard")
        check = c.RequiredSiteVariablesCheck()
    else:
        context.vc_documents = [{"id": "vc1", "root_device_id": "d1", "members": [
            {"member_id": 0, "mac": "aa0000000000", "vc_role": "master", "vc_state": "present", "model": "EX3400"},
            {"member_id": 1, "mac": "aa0000000001", "vc_role": "linecard", "vc_state": "present", "model": "EX3400"},
        ]}]
        check = c.VirtualChassisRoleCheck()
    original = run(context, checks=[check])
    evidence = original["checks"][0]["findings"][0]["exception_candidate"]
    store.approve(evidence, "Approved local standard", "alice")
    context.devices[0]["uptime"] = 999999
    if kind == "vc":
        context.vc_documents[0]["members"][1]["vc_state"] = "offline"
    matched = run(context, store.load_records(), [check])
    assert matched["total_exceptions"] == 1
    assert matched["total_findings"] == 0


def test_approval_validation_does_not_refresh_firmware_or_push_standards(monkeypatch):
    monkeypatch.setattr(c, "_refresh_firmware_standards_if_needed", lambda *a: pytest.fail("Must use existing standards without side effects"))
    runner = c.build_default_runner(check_ids=["firmware_management"], refresh_standards=False)
    assert len(runner.checks) == 1
    runner.checks[0].prepare_run()


def test_incomplete_device_data_cannot_remove_remediation_protection(local_store, context, monkeypatch):
    store.approve(candidate(context), "Locally managed", "alice")
    context.devices[0].pop("disable_auto_config")
    context.unavailable_device_ids.add("d1")
    monkeypatch.setattr(audit_fixes, "_execute_audit_action_unchecked", lambda *a, **k: pytest.fail("Missing configuration must not permit a fix"))
    result = audit_fixes.execute_audit_action(ENABLE_CLOUD_MANAGEMENT_ACTION_ID, ORIGIN, "token", ["s1"],
                                             device_map={"s1": ["d1"]}, context_loader=lambda *args: ([context], []))
    assert result["totals"]["skipped"] == 1


def test_api_rejects_incomplete_configuration(api, context):
    _, client = api
    evidence = candidate(context)
    context.unavailable_device_ids.add("d1")
    response = client.post("/api/audit/exceptions?base_url=" + ORIGIN, json={**evidence, "reason": "reason"})
    assert response.status_code == 502


def test_partial_vc_approval_removes_action_that_would_change_approved_member(local_store, context, monkeypatch):
    from audit_actions import SET_VIRTUAL_CHASSIS_ROLES_ACTION_ID
    context.vc_documents = [{"id": "vc1", "root_device_id": "d1", "members": [
        {"member_id": 0, "mac": "aa0000000000", "vc_role": "linecard", "vc_state": "present", "model": "EX3400"},
        {"member_id": 1, "mac": "aa0000000001", "vc_role": "linecard", "vc_state": "present", "model": "EX3400"},
    ]}]
    check = c.VirtualChassisRoleCheck()
    original = run(context, checks=[check])
    assert original["total_findings"] == 2
    store.approve(original["checks"][0]["findings"][0]["exception_candidate"], "Keep this VC member role", "alice")
    matched = run(context, store.load_records(), [check])
    assert matched["total_findings"] == matched["total_exceptions"] == 1
    assert not matched["checks"][0]["findings"][0]["actions"]
    assert matched["total_quick_fix_issues"] == 0
    monkeypatch.setattr(audit_fixes, "_execute_audit_action_unchecked", lambda *a, **k: pytest.fail("Must not rewrite approved member role"))
    result = audit_fixes.execute_audit_action(SET_VIRTUAL_CHASSIS_ROLES_ACTION_ID, ORIGIN, "token", ["s1"],
                                             metadata={"vc_device_id": "d1"}, context_loader=lambda *args: ([context], []))
    assert result["totals"]["skipped"] == 1


def test_ap_name_approval_blocks_site_wide_rename_but_not_other_aps(local_store, context, monkeypatch):
    from audit_actions import AP_RENAME_ACTION_ID
    context.devices = [{"id": "ap1", "type": "ap", "name": "local-ap"},
                       {"id": "ap2", "type": "ap", "name": "another-local-ap"}]
    check = c.DeviceNamingConventionCheck()
    result = run(context, checks=[check])
    store.approve(result["checks"][0]["findings"][0]["exception_candidate"], "Local AP name", "alice")
    calls = []
    def dispatch(*args, **kwargs):
        calls.append(kwargs["device_map"])
        return {"results": [{"renamed": 1}]}
    monkeypatch.setattr(audit_fixes, "_execute_audit_action_unchecked", dispatch)
    result = audit_fixes.execute_audit_action(AP_RENAME_ACTION_ID, ORIGIN, "token", ["s1"],
                                             context_loader=lambda *args: ([context], []))
    assert calls == [{"s1": ["ap2"]}]
    assert result["totals"]["skipped"] == result["totals"]["updated"] == 1


def test_spare_action_cannot_rename_a_switch_with_an_approved_name(local_store, context, monkeypatch):
    from audit_actions import SET_SPARE_SWITCH_ROLE_ACTION_ID
    check = c.DeviceNamingConventionCheck()
    result = run(context, checks=[check])
    store.approve(result["checks"][0]["findings"][0]["exception_candidate"], "Keep local name", "alice")
    monkeypatch.setattr(audit_fixes, "_execute_audit_action_unchecked", lambda *a, **k: pytest.fail("Spare action would rename approved device"))
    result = audit_fixes.execute_audit_action(SET_SPARE_SWITCH_ROLE_ACTION_ID, ORIGIN, "token", ["s1"],
                                             metadata={"selected_switch_id": "d1"}, context_loader=lambda *args: ([context], []))
    assert result["totals"]["skipped"] == 1
