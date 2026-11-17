"""Security regressions exercise real HTTP routing, cookies, and filesystem boundaries."""
import base64
import importlib
import json
import logging
import re
import ssl
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
from fastapi.testclient import TestClient
from itsdangerous import TimestampSigner

from security import hash_password, record_path, security_db, session_secret, verify_password


@pytest.fixture
def web(monkeypatch, tmp_path):
    password = hash_password("test-operator-password")
    users = tmp_path / "users.json"
    users.write_text(json.dumps({"operator": {"password_hash": password, "can_push": True},
                                 "reader": {"password_hash": password, "can_push": False}}))
    monkeypatch.setenv("LOCAL_USERS_FILE", str(users))
    monkeypatch.setenv("SESSION_HTTPS_ONLY", "false")
    monkeypatch.setenv("MIST_ALLOWED_HOSTS", "")
    monkeypatch.setenv("MIST_BASE_URL", "https://api.ac2.mist.com")
    auth = importlib.reload(importlib.import_module("auth_local"))
    app = importlib.reload(importlib.import_module("app"))
    client = TestClient(app.app, follow_redirects=False)
    return app, client, users


def sign_in(client, name="operator"):
    response = client.get("/login")
    assert response.status_code == 200
    token = re.search(r'name="csrf_token" value="([^"]+)"', response.text).group(1)
    response = client.post("/login", data={"username": name, "password": "test-operator-password", "csrf_token": token})
    assert response.status_code == 302, response.text
    page = client.get("/")
    token = re.search(r'name="csrf-token" content="([^"]+)"', page.text).group(1)
    client.headers["X-CSRF-Token"] = token
    return client


@pytest.mark.parametrize("method,path", [
    ("GET", "/api/sites"), ("GET", "/api/site_devices?site_id=s1"),
    ("GET", "/api/port_profiles"), ("GET", "/api/standards"),
    ("GET", "/api/rules"), ("GET", "/api/replacements"),
    ("GET", "/api/conversion-sets/demo"), ("GET", "/api/conversion-sets/demo/id"),
    ("GET", "/api/network-state/history/demo"), ("GET", "/api/network-state/runs/demo/id"),
    ("GET", "/api/ssh/jobs/id"), ("GET", "/api/network-state/baselines/jobs/id"),
    ("POST", "/api/ssh/jobs"), ("POST", "/api/convert"),
    ("POST", "/api/showtech"), ("POST", "/api/showtech/pdf"),
    ("POST", "/api/push"), ("POST", "/api/push_batch"),
    ("POST", "/api/audit/run"), ("GET", "/openapi.json"),
])
def test_anonymous_requests_are_rejected_before_parsing_or_io(web, method, path):
    _, client, _ = web
    assert client.request(method, path).status_code == 401


def test_every_registered_route_is_protected_by_default(web):
    app, client, _ = web
    for route in app.app.routes:
        if not hasattr(route, "methods") or route.path == "/login":
            continue
        url = re.sub(r"\{[^}]+\}", "synthetic", route.path)
        for method in route.methods:
            response = client.request(method, url)
            assert response.status_code in {401, 303}, (method, url, response.status_code)
            if response.status_code == 303:
                assert response.headers["location"] == "/login"


@pytest.mark.parametrize("kind", ["conversion", "snapshot"])
def test_record_traversal_is_rejected_by_http_route_before_file_read(web, monkeypatch, kind):
    _, client, _ = web
    import conversion_sets
    import network_state_snapshots
    sign_in(client)
    read = Mock()
    if kind == "conversion":
        monkeypatch.setattr(conversion_sets, "_read_json", read)
        url = "/api/conversion-sets/demo/..%5C..%5Coutside"
    else:
        monkeypatch.setattr(network_state_snapshots, "_read_json", read)
        url = "/api/network-state/runs/demo/..%5C..%5Coutside"
    assert client.get(url).status_code == 400
    read.assert_not_called()


@pytest.mark.parametrize("filename", ["../escaped.txt", "..\\escaped.txt", "C:/escaped.txt", "C:\\escaped.txt", "/tmp/escaped.txt"])
def test_upload_cannot_escape_temporary_directory(web, filename):
    _, client, _ = web
    sign_in(client)
    response = client.post("/api/convert", files={"files": (filename, b"hostname harmless\n")})
    # Multipart parsers may normalize legacy Windows browser paths before the app sees them.
    if filename == "C:\\escaped.txt" and response.status_code == 200:
        assert response.json()["items"][0]["source_file"] == "escaped.txt"
    else:
        assert response.status_code == 400, response.text


@pytest.mark.parametrize("url", ["http://api.ac2.mist.com/api/v1", "https://collector.invalid/api/v1", "https://api.ac2.mist.com.evil.invalid/api/v1", "https://api.ac2.mist.com@collector.invalid/api/v1", "https://127.0.0.1/api/v1"])
def test_mist_destination_rejected_before_network(web, url):
    _, client, _ = web
    sign_in(client)
    response = client.get("/api/sites", params={"base_url": url})
    assert response.status_code in {400, 422}, response.text


def test_outbound_hook_blocks_token_leak_redirects_and_payload_logs(monkeypatch):
    import http_logging
    import requests
    outbound = Mock(return_value=SimpleNamespace(status_code=200))
    log = Mock()
    monkeypatch.setattr(http_logging, "_ORIGINAL_SESSION_REQUEST", outbound)
    monkeypatch.setattr(http_logging._LOGGER, "info", log)
    with pytest.raises(ValueError):
        requests.get("https://collector.invalid/api/v1/self", headers={"Authorization": "Token synthetic"})
    outbound.assert_not_called()
    requests.get("https://api.ac2.mist.com/api/v1/self?secret=hidden", headers={"Authorization": "Token synthetic"}, json={"radius_secret": "hidden"})
    assert outbound.call_args.kwargs["allow_redirects"] is False
    assert outbound.call_args.args[0].trust_env is False
    assert "hidden" not in str(log.call_args_list)


def test_legacy_privileged_cookie_is_rejected(web):
    _, client, _ = web
    forged = TimestampSigner("change_me").sign(base64.b64encode(json.dumps({"user": {"name": "forged", "can_push": True}}).encode())).decode()
    client.cookies.set("session", forged)
    assert client.get("/me").status_code == 401


def test_weak_session_key_fails_closed(monkeypatch):
    monkeypatch.setenv("SESSION_SECRET", "change_me")
    with pytest.raises(RuntimeError):
        session_secret()


def test_password_hashes_are_salted_and_plaintext_is_rejected():
    first = hash_password("a strong password")
    assert first != hash_password("a strong password")
    assert verify_password("a strong password", first)
    assert not verify_password("wrong", first)
    assert not verify_password("plaintext", "plaintext")


def test_logout_invalidates_copied_cookie(web):
    app, client, _ = web
    sign_in(client)
    cookie = client.cookies.get("session")
    assert client.get("/me").status_code == 200
    assert client.post("/logout").status_code == 302
    replay = TestClient(app.app, follow_redirects=False)
    replay.cookies.set("session", cookie)
    assert replay.get("/me").status_code == 401


def test_reauthentication_rotates_existing_session_identifier(web):
    app, client, _ = web
    sign_in(client)
    previous = client.cookies.get("session")
    sign_in(client)
    assert client.cookies.get("session") != previous
    replay = TestClient(app.app, follow_redirects=False)
    replay.cookies.set("session", previous)
    assert replay.get("/me").status_code == 401


def test_inflight_response_cannot_resurrect_logged_out_session(web):
    import threading
    app, client, _ = web
    sign_in(client)
    cookie = client.cookies.get("session")
    entered = threading.Event()
    release = threading.Event()

    @app.app.get("/api/test-stalled-session")
    def stalled():
        entered.set()
        assert release.wait(5)
        return {"ok": True}

    delayed = TestClient(app.app, follow_redirects=False)
    delayed.cookies.set("session", cookie)
    responses = []
    worker = threading.Thread(target=lambda: responses.append(delayed.get("/api/test-stalled-session")))
    worker.start()
    try:
        assert entered.wait(5)
        assert client.post("/logout").status_code == 302
    finally:
        release.set()
        worker.join(timeout=5)
    assert responses and responses[0].status_code == 200
    replay = TestClient(app.app, follow_redirects=False)
    replay.cookies.set("session", cookie)
    assert replay.get("/me").status_code == 401


def test_account_and_role_changes_invalidate_sessions(web):
    _, client, users = web
    sign_in(client)
    doc = json.loads(users.read_text())
    doc["operator"]["can_push"] = False
    users.write_text(json.dumps(doc))
    assert client.get("/me").status_code == 401


def test_expired_server_session_is_rejected(web):
    _, client, _ = web
    sign_in(client)
    with security_db() as db:
        db.execute("UPDATE sessions SET expires=0")
    assert client.get("/me").status_code == 401


@pytest.mark.parametrize("path,payload", [("/api/rules", {"rules": []}), ("/api/replacements", {"rules": []}), ("/api/device_types", {"vendor": "Cisco", "model": "x"}), ("/api/standards/sync", {})])
def test_readonly_cannot_change_shared_policy(web, path, payload):
    _, client, _ = web
    sign_in(client, "reader")
    assert client.post(path, json=payload).status_code == 403


def test_single_push_checks_role_and_forwards_required_arguments(web, monkeypatch):
    app, client, _ = web
    sign_in(client, "reader")
    build = Mock(return_value={"ok": True})
    monkeypatch.setattr(app, "_build_payload_for_row", build)
    data = {"site_id": "s", "device_id": "d", "input_json": "{}", "dry_run": "false"}
    assert client.post("/api/push", data=data).status_code == 403
    build.assert_not_called()
    data["dry_run"] = "true"
    assert client.post("/api/push", data=data).status_code == 200
    assert build.call_args.kwargs["exclude_uplinks"] is False


@pytest.mark.parametrize("identifier", ["../other", "..\\other", "/outside", "C:/outside", "C:\\outside", "..", ""])
def test_record_ids_cannot_escape_storage(tmp_path, identifier):
    with pytest.raises(ValueError):
        record_path(tmp_path, identifier)


def test_csrf_and_cross_origin_requests_are_blocked(web):
    _, client, _ = web
    sign_in(client)
    assert client.post("/api/rules", json={"rules": []}, headers={"X-CSRF-Token": "wrong"}).status_code == 403
    response = client.post("/api/rules", json={"rules": []}, headers={"Origin": "https://untrusted.invalid"})
    assert response.status_code == 403
    assert "access-control-allow-origin" not in response.headers


def test_body_limit_applies_before_upload_parser(web, monkeypatch):
    _, client, _ = web
    sign_in(client)
    monkeypatch.setenv("MAX_REQUEST_BYTES", "100")
    assert client.post("/api/convert", content=b"x" * 101).status_code == 413


def test_remote_plain_http_and_untrusted_host_are_rejected(web):
    app, _, _ = web
    client = TestClient(app.app, base_url="http://testserver", client=("192.0.2.5", 1234))
    assert client.get("/login").status_code == 400
    client = TestClient(app.app, base_url="https://untrusted.invalid")
    assert client.get("/login").status_code == 400


def test_login_rate_limit(web):
    _, client, _ = web
    for _ in range(10):
        client.post("/login", data={"username": "invalid", "password": "bad"})
    assert client.post("/login", data={}).status_code == 429


def test_ldap_requires_certificate_validation_and_escapes_identity(monkeypatch):
    import auth_ldap
    monkeypatch.setattr(auth_ldap, "LDAP_SERVER_URL", "ldaps://directory.invalid:636")
    assert auth_ldap._server().tls.validate == ssl.CERT_REQUIRED
    monkeypatch.setattr(auth_ldap, "LDAP_SERVER_URL", "ldap://directory.invalid")
    with pytest.raises(ValueError):
        auth_ldap._server()
    conn = SimpleNamespace(search=Mock(return_value=False), entries=[])
    monkeypatch.setattr(auth_ldap, "_iter_search_bases", lambda: ["DC=test"])
    auth_ldap._search_user(conn, "name*)(other=value")
    assert r"name\2a\29\28other=value" in conn.search.call_args.kwargs["search_filter"]


def test_log_records_cannot_inject_physical_lines():
    from logging_utils import SafeFormatter
    record = logging.LogRecord("test", logging.WARNING, "", 1, "user=%s", ("attacker\nforged-event\r",), None)
    result = SafeFormatter("%(message)s").format(record)
    assert "\n" not in result and "\r" not in result


def test_inline_audit_markers_cannot_forge_history_and_legacy_logs_work(tmp_path):
    from datetime import datetime
    from audit_history import load_site_history
    from logging_utils import SafeFormatter
    formatter = SafeFormatter("%(asctime)s | %(levelname)s | %(message)s")
    timestamp = datetime(2026, 11, 17, 12).timestamp()
    lines = []
    for message in [
        "local_login_failed user=attacker action=audit_run site_issue_breakdown=HQ:999 site_device_breakdown=HQ:999",
        "user=anonymous client=test path=/action=audit_run site_issue_breakdown=HQ:999 site_device_breakdown=HQ:999",
    ]:
        record = logging.LogRecord("test", logging.INFO, "", 1, message, (), None)
        record.created = timestamp
        lines.append(formatter.format(record))
    record = logging.LogRecord("test", logging.INFO, "", 1, "user=attacker site_issue_breakdown=HQ:999 action=audit_run", (), None)
    record.created = timestamp
    record.event_type = "audit_run"
    record.audit_summary = {"issues": {"HQ": 2}, "devices": {"HQ": 3}}
    lines.append(formatter.format(record))
    lines.append("2026-11-17 12:00:00,000 | INFO | user=operator action=audit_run site_issue_breakdown=HQ:1 site_device_breakdown=HQ:4")
    (tmp_path / "17112026.log").write_text("\n".join(lines) + "\n")
    result = load_site_history(["HQ"], now=datetime(2026, 11, 17, 13), log_dir=tmp_path)["HQ"]
    assert result.run_count == 2
    assert result.issues_total == 3 and result.devices_total == 7


def test_credential_upgrade_is_idempotent_and_preserves_roles(tmp_path):
    from security_setup import upgrade_env
    target = tmp_path / ".env"
    target.write_text("SESSION_SECRET=change_me\nLOCAL_USERS=alice:private-test-password,bob:another-test-password\nLOCAL_PUSH_USERS=alice\nMIST_TOKEN=preserved-synthetic-token\n")
    assert upgrade_env(target)
    content = target.read_text()
    assert "private-test-password" not in content and "change_me" not in content
    assert "MIST_TOKEN=preserved-synthetic-token" in content
    users = json.loads((tmp_path / "data/local_users.json").read_text())
    assert verify_password("private-test-password", users["alice"]["password_hash"])
    assert users["alice"]["can_push"] and not users["bob"]["can_push"]
    assert not upgrade_env(target)


def test_credential_upgrade_removes_duplicate_weak_keys(tmp_path):
    from security_setup import upgrade_env
    target = tmp_path / ".env"
    target.write_text('SESSION_SECRET=change_me\nSESSION_SECRET="change_me" # old placeholder\n')
    assert upgrade_env(target)
    assert "change_me" not in target.read_text()
    assert target.read_text().count("SESSION_SECRET=") == 1


def test_retention_removes_only_expired_evidence_and_repairs_index(tmp_path, monkeypatch):
    import os
    from maintenance import purge_evidence
    monkeypatch.setenv("NETWORK_DATA_RETENTION_DAYS", "1")
    project = tmp_path / "network_state/project"
    project.mkdir(parents=True)
    old = project / "old.json"
    old.write_text("{}")
    os.utime(old, (1, 1))
    recent = project / "recent.json"
    recent.write_text("{}")
    (project / "index.json").write_text(json.dumps({"runs": [{"run_id": "old"}, {"run_id": "recent"}]}))
    credentials = tmp_path / "local_users.json"
    credentials.write_text("{}")
    os.utime(credentials, (1, 1))
    purge_evidence(tmp_path)
    assert not old.exists() and recent.exists() and credentials.exists()
    assert json.loads((project / "index.json").read_text())["runs"] == [{"run_id": "recent"}]


def test_ssh_cleanup_finds_orphans_without_touching_active_jobs(tmp_path, monkeypatch):
    import os
    import ssh_collect
    monkeypatch.chdir(tmp_path)
    root = tmp_path / "tmp_ssh_jobs"
    monkeypatch.setattr(ssh_collect, "JOB_ROOT", root)
    stale = root / ("a" * 32)
    active = root / ("b" * 32)
    for folder in (stale, active):
        (folder / "switch").mkdir(parents=True)
        (folder / "switch/raw.txt").write_text("synthetic evidence")
        os.utime(folder, (1, 1))
    monkeypatch.setattr(ssh_collect, "_JOBS", {active.name: ssh_collect.JobState(id=active.name, created=1, status="running", temp_dir=active)})
    ssh_collect.cleanup_old_jobs()
    assert not stale.exists() and active.exists()


def test_ssh_capacity_is_shared_and_released(monkeypatch):
    from security import acquire_job_slot, release_job_slot
    monkeypatch.setenv("MAX_SSH_JOBS", "1")
    acquire_job_slot("first")
    from fastapi import HTTPException
    with pytest.raises(HTTPException) as exc:
        acquire_job_slot("second")
    assert exc.value.status_code == 429
    release_job_slot("first")
    acquire_job_slot("second")


@pytest.mark.parametrize("failure", ["directory", "thread"])
def test_failed_ssh_start_releases_capacity_and_credentials(tmp_path, monkeypatch, failure):
    import ssh_collect
    if failure == "directory":
        root = tmp_path / "file"
        root.write_text("not a directory")
        monkeypatch.setattr(ssh_collect, "JOB_ROOT", root)
    else:
        monkeypatch.setattr(ssh_collect.threading.Thread, "start", Mock(side_effect=RuntimeError("synthetic start failure")))
    password = bytearray(b"synthetic password")
    with pytest.raises((OSError, RuntimeError)):
        ssh_collect.start_job(devices=[ssh_collect.DeviceInput("switch.test")], username="operator", password_bytes=password,
                              delay_factor=1, read_timeout=90, max_workers=1)
    assert not any(password)
    with security_db() as db:
        assert db.execute("SELECT count(*) FROM work_leases").fetchone()[0] == 0


def test_cleanup_preserves_jobs_leased_by_another_worker(tmp_path, monkeypatch):
    import os
    import ssh_collect
    from security import acquire_job_slot, release_job_slot
    root = tmp_path / "jobs"
    job_id = "c" * 32
    path = root / job_id
    path.mkdir(parents=True)
    (path / "capture.txt").write_text("synthetic")
    os.utime(path, (1, 1))
    monkeypatch.setattr(ssh_collect, "JOB_ROOT", root)
    monkeypatch.setattr(ssh_collect, "_JOBS", {})
    acquire_job_slot(job_id)
    ssh_collect.cleanup_old_jobs()
    assert path.exists()
    release_job_slot(job_id)
    ssh_collect.cleanup_old_jobs()
    assert not path.exists()


def test_ssh_collection_requires_trusted_host_keys(tmp_path, monkeypatch):
    import ssh_collect
    captured = {}
    class Connection:
        protocol = "ssh"
        def enable(self): pass
        def send_command(self, *args, **kwargs): return ""
        def disconnect(self): pass
    def connect(**params):
        captured.update(params)
        return Connection()
    monkeypatch.setattr(ssh_collect, "ConnectHandler", connect)
    monkeypatch.setenv("SSH_KNOWN_HOSTS_FILE", str(tmp_path / "known_hosts"))
    result = ssh_collect._collect_one_device(base_dir=tmp_path, device=ssh_collect.DeviceInput(host="switch.test", label=".."), username="operator", password_bytes=b"synthetic", delay_factor=1, read_timeout=90)
    assert captured["ssh_strict"] is True and captured["system_host_keys"] is True
    assert captured["alt_host_keys"] is True
    assert result.status == "ok"
    assert Path(result.temp_files["directory"]).resolve().is_relative_to(tmp_path.resolve())


def test_active_diagnostics_require_opt_in():
    import compliance
    passive = compliance.build_default_runner(refresh_standards=False)
    active = compliance.build_default_runner(refresh_standards=False, include_active_checks=True)
    assert not any(isinstance(check, compliance.SwitchCableTestCheck) for check in passive.checks)
    assert any(isinstance(check, compliance.SwitchCableTestCheck) for check in active.checks)


def test_readonly_active_diagnostics_are_rejected_before_io(web):
    _, client, _ = web
    sign_in(client, "reader")
    response = client.post("/api/audit/run", json={"site_ids": ["site1"], "include_active_checks": True})
    assert response.status_code == 403, response.text


def test_policy_sync_reports_success_and_failure(web, monkeypatch):
    app, client, _ = web
    import compliance
    sign_in(client)
    monkeypatch.setattr(app, "_refresh_firmware_standards_if_needed", lambda path: {})
    monkeypatch.setattr(compliance, "_load_firmware_standards_doc", lambda path: {})
    monkeypatch.setattr(compliance, "_sync_switch_auto_upgrade_custom_versions", lambda doc: True)
    assert client.post("/api/standards/sync").status_code == 200
    monkeypatch.setattr(compliance, "_sync_switch_auto_upgrade_custom_versions", lambda doc: False)
    assert client.post("/api/standards/sync").status_code == 502


def test_legacy_payload_scrubbing_preserves_audit_history(tmp_path):
    from security_setup import scrub_legacy_logs
    log = tmp_path / "17112026.log"
    log.write_text("HTTP GET host payload_received={secret:do-not-retain}\nuser=operator action=audit_run sites=1\n")
    assert scrub_legacy_logs(tmp_path) == 1
    assert "do-not-retain" not in log.read_text()
    assert "action=audit_run sites=1" in log.read_text()
    assert scrub_legacy_logs(tmp_path) == 0


def test_account_management_cli_uses_hidden_prompt_and_revokes_sessions(tmp_path, monkeypatch):
    import runpy
    import sys
    import getpass
    import time
    target = tmp_path / ".env"
    target.write_text("SESSION_SECRET=" + "x" * 48 + "\nAUTH_METHOD=local\n")
    monkeypatch.setattr(getpass, "getpass", lambda prompt: "new-strong-password")
    command = str(Path(__file__).with_name("security_setup.py"))
    monkeypatch.setattr(sys, "argv", [command, "--env", str(target), "--add-user", "operator", "--push"])
    runpy.run_path(command, run_name="__main__")
    users = json.loads((tmp_path / "data/local_users.json").read_text())
    assert verify_password("new-strong-password", users["operator"]["password_hash"])
    assert users["operator"]["can_push"]
    assert "LOCAL_USERS_FILE=data/local_users.json" in target.read_text()
    with security_db() as db:
        db.execute("INSERT INTO sessions VALUES (?,?,?)", ("synthetic", "{}", time.time() + 3600))
    monkeypatch.setattr(sys, "argv", [command, "--env", str(target), "--revoke-sessions"])
    runpy.run_path(command, run_name="__main__")
    with security_db() as db:
        assert db.execute("SELECT count(*) FROM sessions").fetchone()[0] == 0


def test_ldap_sessions_revalidate_directory_roles(monkeypatch):
    import auth_ldap
    from fastapi import HTTPException
    conn = SimpleNamespace(unbind=Mock())
    monkeypatch.setattr(auth_ldap, "_bind_service", lambda: conn)
    monkeypatch.setattr(auth_ldap, "_search_user", lambda *args: {"dn": "CN=Operator"})
    monkeypatch.setattr(auth_ldap, "PUSH_GROUP_DN", "CN=Push")
    monkeypatch.setattr(auth_ldap, "READONLY_GROUP_DNS", ["CN=Read"])
    monkeypatch.setattr(auth_ldap, "_is_member_of_group", lambda dn, group, conn: group == "CN=Read")
    request = SimpleNamespace(session={"user": {"dn": "CN=Operator", "login_name": "operator", "can_push": True}})
    assert auth_ldap.current_user(request)["can_push"] is False
    conn.unbind.assert_called_once()
    monkeypatch.setattr(auth_ldap, "_is_member_of_group", lambda *args: False)
    with pytest.raises(HTTPException) as error:
        auth_ldap.current_user(request)
    assert error.value.status_code == 401 and not request.session


def test_vlan_range_expansion_is_bounded():
    import app
    from convertciscotojson import parse_allowed_list
    with pytest.raises(ValueError):
        app._expand_vlan_id_set("1-999999999")
    assert parse_allowed_list("1-999999999,10-12") == [10, 11, 12]


@pytest.mark.parametrize("path", ["/", "/hardware", "/rules", "/replacements", "/standards", "/audit", "/network-snapshot"])
def test_pages_have_local_assets_csrf_and_security_headers(web, path):
    _, client, _ = web
    sign_in(client)
    response = client.get(path)
    assert response.status_code == 200
    assert "cdn.tailwindcss.com" not in response.text
    assert "{{CSRF_TOKEN}}" not in response.text and "{{CSP_NONCE}}" not in response.text
    assert "/static/security.js" in response.text
    assert "frame-ancestors 'none'" in response.headers["content-security-policy"]
    assert "'unsafe-inline'" not in response.headers["content-security-policy"].split("script-src", 1)[1].split(";", 1)[0]
