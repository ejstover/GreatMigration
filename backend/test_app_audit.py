import importlib
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict

import pytest


BACKEND_DIR = Path(__file__).resolve().parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))


@pytest.fixture
def app_module(monkeypatch):
    monkeypatch.setenv("SWITCH_TEMPLATE_ID", "template-1")
    app = importlib.reload(importlib.import_module("app"))
    monkeypatch.setattr(app, "_load_mist_token", lambda: "token")
    return app


def test_fetch_site_context_merges_device_details(monkeypatch, app_module):
    now_ts = 1_700_000_000.0
    monkeypatch.setattr(app_module, "_current_timestamp", lambda: now_ts)

    calls: list[str] = []

    responses: Dict[str, Any] = {
        "/sites/site-1": {"id": "site-1", "name": "HQ"},
        "/sites/site-1/setting": {"variables": {}},
        "/sites/site-1/networktemplates": [],
        "/sites/site-1/devices": [
            {
                "id": "dev-2",
                "name": "AP 2",
                "status": "connected",
                "last_seen": now_ts - 300,
            },
            {
                "id": "dev-3",
                "name": "Switch 3",
                "status": "offline",
                "last_seen": now_ts - (20 * 24 * 60 * 60),
            },
        ],
        "/sites/site-1/devices?type=switch": [
            {
                "id": "dev-1",
                "name": "Switch 1",
                "status": "connected",
                "last_seen": now_ts - 120,
            },
        ],
        "/sites/site-1/stats/devices?type=switch&limit=1000": {
            "results": [
                {
                    "id": "dev-1",
                    "name": "Switch 1",
                    "version": "23.4R2-S4.11",
                    "last_seen": now_ts - 60,
                },
            ]
        },
        "/sites/site-1/stats/devices?type=ap&limit=1000": {
            "results": [
                {
                    "id": "dev-2",
                    "name": "AP 2",
                    "version": "0.12.27452",
                    "last_seen": now_ts - 240,
                },
            ]
        },
        "/sites/site-1/devices/dev-1": {
            "id": "dev-1",
            "status": {"state": "online"},
            "switch_config": {"vlans": [10]},
            "extra": "detail",
        },
        "/sites/site-1/devices/dev-2": None,
        "/sites/site-1/devices/dev-3": None,
        "/sites/site-1/switch_templates/template-1": {
            "id": "template-1",
            "switch_config": {"port_config": {"ge-0/0/1": {"usage": "end_user"}}},
        },
    }

    def fake_get(base_url: str, headers: Dict[str, str], path: str, optional: bool = False):
        calls.append(path)
        return responses.get(path)

    monkeypatch.setattr(app_module, "_mist_get_json", fake_get)

    context = app_module._fetch_site_context("https://example.com/api/v1", {"Authorization": "token"}, "site-1")

    assert {d.get("id") for d in context.devices} == {"dev-1", "dev-2"}

    devices_by_id = {d.get("id"): d for d in context.devices if d.get("id")}

    dev1 = devices_by_id["dev-1"]
    # Base fields remain, detail fields are merged, and structured statuses are preserved.
    assert dev1["name"] == "Switch 1"
    assert dev1["status"] == {"state": "online"}
    assert dev1["switch_config"] == {"vlans": [10]}
    assert dev1["extra"] == "detail"
    assert dev1["version"] == "23.4R2-S4.11"

    dev2 = devices_by_id["dev-2"]
    # Device without detail fallback retains base information.
    assert dev2["name"] == "AP 2"
    assert dev2["status"] == "connected"
    assert dev2["version"] == "0.12.27452"

    assert all(device.get("id") != "dev-3" for device in context.devices)

    assert "/sites/site-1/devices" in calls
    assert "/sites/site-1/devices?type=switch" in calls
    assert "/sites/site-1/stats/devices?type=switch&limit=1000" in calls
    assert "/sites/site-1/stats/devices?type=ap&limit=1000" in calls
    assert "/sites/site-1/devices/dev-1" in calls
    assert "/sites/site-1/devices/dev-2" in calls
    assert "/sites/site-1/switch_templates/template-1" in calls

    template_ids = {t.get("id") for t in context.templates if isinstance(t, dict)}
    assert "template-1" in template_ids


def test_fetch_site_context_filters_recent_last_seen(monkeypatch, app_module):
    now_ts = 1_700_000_000.0
    monkeypatch.setattr(app_module, "_current_timestamp", lambda: now_ts)

    recent_iso_value = datetime.fromtimestamp(now_ts - 600, tz=timezone.utc).isoformat()

    responses: Dict[str, Any] = {
        "/sites/site-1": {"id": "site-1", "name": "HQ"},
        "/sites/site-1/setting": {"variables": {}},
        "/sites/site-1/networktemplates": [],
        "/sites/site-1/devices": [
            {"id": "recent", "name": "Recent", "last_seen": now_ts - 90},
            {"id": "stale", "name": "Stale", "last_seen": now_ts - (15 * 24 * 60 * 60)},
            {"id": "missing", "name": "Missing"},
            {"id": "recent-iso", "name": "Recent ISO", "last_seen": recent_iso_value},
        ],
        "/sites/site-1/devices?type=switch": [
            {
                "id": "recent-ms",
                "name": "Recent Millis",
                "last_seen": (now_ts - 180) * 1000,
            }
        ],
        "/sites/site-1/stats/devices?type=switch&limit=1000": {
            "results": [
                {"id": "recent", "last_seen": now_ts - 60},
                {"id": "stale", "last_seen": now_ts - (20 * 24 * 60 * 60)},
                {"id": "missing", "status": "connected"},
                {"id": "recent-ms", "last_seen": (now_ts - 120) * 1000},
            ]
        },
        "/sites/site-1/stats/devices?type=ap&limit=1000": [],
        "/sites/site-1/devices/recent": None,
        "/sites/site-1/devices/stale": None,
        "/sites/site-1/devices/missing": None,
        "/sites/site-1/devices/recent-iso": None,
        "/sites/site-1/devices/recent-ms": None,
        "/sites/site-1/switch_templates/template-1": {"id": "template-1"},
    }

    def fake_get(base_url: str, headers: Dict[str, str], path: str, optional: bool = False):
        return responses.get(path)

    monkeypatch.setattr(app_module, "_mist_get_json", fake_get)

    context = app_module._fetch_site_context("https://example.com/api/v1", {"Authorization": "token"}, "site-1")

    device_ids = [device.get("id") for device in context.devices if device.get("id")]

    assert device_ids == ["recent", "recent-iso", "recent-ms"]


def test_build_temp_config_payload_groups_port_profiles(app_module):
    row = {
        "_temp_config_source": {
            "vlans": [
                {"id": 17, "name": "17"},
                {"id": 100, "name": "Data"},
                {"id": 120, "name": "Voice"},
            ],
            "interfaces": [],
        }
    }

    for idx in range(1, 17):
        row["_temp_config_source"]["interfaces"].append(
            {
                "mode": "access",
                "data_vlan": 17,
                "juniper_if": f"ge-0/0/{idx}",
                "name": f"Gig{idx}",
            }
        )

    for idx in range(17, 27):
        row["_temp_config_source"]["interfaces"].append(
            {
                "mode": "access",
                "data_vlan": 100,
                "voice_vlan": 120,
                "juniper_if": f"ge-0/0/{idx}",
                "name": f"Gig{idx}",
            }
        )

    payload = app_module._build_temp_config_payload(row)
    assert payload is not None

    usages = payload.get("port_usages")
    assert isinstance(usages, dict)
    assert len(usages) == 2
    assert all(isinstance(name, str) and name for name in usages)
    networks = {net.get("name"): net for net in payload.get("networks", []) if isinstance(net, dict)}
    for usage_payload in usages.values():
        port_network = usage_payload.get("port_network")
        assert isinstance(port_network, str)
        assert port_network in networks
    assert "port_config" not in payload
    assert "port_overrides" not in payload


def test_prepare_payload_excludes_port_overrides(monkeypatch, app_module):
    monkeypatch.setattr(app_module, "_collect_candidate_org_ids", lambda *args, **kwargs: set())
    monkeypatch.setattr(app_module, "_load_site_template_networks", lambda *args, **kwargs: {})
    monkeypatch.setattr(app_module, "_collect_existing_vlan_details", lambda *args, **kwargs: (set(), []))
    monkeypatch.setattr(
        app_module,
        "_resolve_network_conflicts",
        lambda networks, profiles, usages, conflicts: (networks, profiles, usages, {}, []),
    )
    monkeypatch.setattr(
        app_module, "_merge_new_vlan_networks", lambda existing, new, vlan_ids: {}
    )

    class FakeResp:
        status_code = 200

        @staticmethod
        def json():
            return {}

    monkeypatch.setattr(app_module.requests, "get", lambda *args, **kwargs: FakeResp())

    payload = {
        "port_usages": [
            {"name": "temp1", "port_network": "data_vlan", "mode": "access"},
            {"name": "temp2", "port_network": "data_vlan", "mode": "access"},
        ],
        "port_overrides": [
            {"port_id": "ge-0/0/1", "usage": "temp1", "device_id": "dev-1"},
            {"port_id": "ge-0/0/1", "usage": "temp2", "device_id": "dev-2"},
        ]
    }

    request_body, warnings, rename_map = app_module._prepare_switch_port_profile_payload(
        "https://example.com/api/v1", "token", "site-1", payload
    )

    switch_body = request_body.get("switch", {})
    assert "port_overrides" not in switch_body
    assert "port_usages" in switch_body
    assert warnings == []
    assert rename_map == {}


def test_apply_temp_config_payload_strips_port_assignments(monkeypatch, app_module):
    captured_payloads: list[Dict[str, Any]] = []

    def fake_prepare(base_url: str, token: str, site_id: str, payload: Dict[str, Any], **kwargs):
        captured_payloads.append(payload)
        return payload, [], {}

    monkeypatch.setattr(app_module, "_prepare_switch_port_profile_payload", fake_prepare)

    row = {
        "ok": True,
        "site_id": "site-1",
        "device_id": "device-1",
        "_temp_config_source": {
            "vlans": [{"id": 10, "name": "Data"}],
            "interfaces": [
                {
                    "mode": "access",
                    "data_vlan": 10,
                    "juniper_if": "ge-0/0/1",
                    "name": "Gig1",
                }
            ],
        },
    }

    result = app_module._apply_temporary_config_for_rows(
        "https://example.com/api/v1",
        "token",
        [row],
        dry_run=True,
    )

    assert result["successes"] == 1
    preview_payload = result["payloads"][0]["payload"]

    assert captured_payloads
    assert "port_config" not in captured_payloads[0]
    assert "port_overrides" not in captured_payloads[0]
    assert "port_usages" in captured_payloads[0]
    assert "port_config" not in preview_payload
    assert "port_overrides" not in preview_payload


def test_remove_temp_config_returns_preview_when_dry_run(monkeypatch, app_module):
    row = {
        "ok": True,
        "site_id": "site-1",
        "device_id": "device-1",
        "_site_deployment_payload": {"port_config": {"ge-0/0/1": {"usage": "end_user"}}},
    }

    monkeypatch.setattr(
        app_module,
        "_derive_port_config_from_config_cmd",
        lambda *args, **kwargs: {"ge-0/0/1": {"usage": "derived_user"}},
    )

    result = app_module._remove_temporary_config_for_rows(
        "https://example.com/api/v1",
        "token",
        [row],
        dry_run=True,
    )

    assert result["skipped"] is True
    assert result["total"] == 1
    payloads = result.get("payloads") or []
    assert len(payloads) == 1
    preview = payloads[0]["payload"]
    assert preview["cleanup_request"] == {
        "networks": {},
        "switch": {
            "port_usages": {},
            "port_config": {},
            "port_overrides": [],
        },
    }
    assert preview["push_request"]["port_config"]["ge-0/0/1"]["usage"] == "derived_user"


def test_remove_temp_config_wipes_and_pushes(monkeypatch, app_module):
    calls: list[Dict[str, Any]] = []

    def fake_put(url: str, headers: Dict[str, str], json: Dict[str, Any], timeout: int = 60):
        calls.append({"url": url, "json": json})

        class Resp:
            status_code = 200

            def json(self):
                return {"ok": True}

            text = ""

        return Resp()

    monkeypatch.setattr(app_module.requests, "put", fake_put)
    monkeypatch.setattr(
        app_module,
        "_derive_port_config_from_config_cmd",
        lambda *args, **kwargs: {"ge-0/0/5": {"usage": "derived_user"}},
    )

    final_payload = {"port_config": {"ge-0/0/5": {"usage": "access"}}}
    row = {
        "ok": True,
        "site_id": "site-1",
        "device_id": "device-1",
        "_site_deployment_payload": final_payload,
    }

    result = app_module._remove_temporary_config_for_rows(
        "https://example.com/api/v1",
        "token",
        [row],
        dry_run=False,
    )

    assert result["ok"] is True
    assert result["successes"] == 1
    assert result["failures"] == []
    assert len(calls) == 2
    assert calls[0]["url"] == "https://example.com/api/v1/sites/site-1/setting"
    assert calls[0]["json"] == {
        "networks": {},
        "switch": {
            "port_usages": {},
            "port_config": {},
            "port_overrides": [],
        },
    }
    assert calls[1]["json"] == {"port_config": {"ge-0/0/5": {"usage": "derived_user"}}}


def test_parse_config_cmd_interfaces_extracts_profiles(app_module):
    cli = [
        "set vlans DATA vlan-id 3",
        "set vlans VOICE vlan-id 2",
        "set vlans MGMT vlan-id 1",
        "set interfaces interface-range MGMT member ge-0/0/1",
        "set interfaces interface-range USERS member ge-0/0/6",
        "set interfaces interface-range USERS member ge-0/0/7",
        "set interfaces interface-range MGMT apply-groups LEGACY_MGMT",
        "set interfaces interface-range USERS apply-groups LEGACY_ENDUSER",
        "set groups LEGACY_MGMT interfaces <*> unit 0 family ethernet-switching port-mode access",
        "set groups LEGACY_MGMT interfaces <*> unit 0 family ethernet-switching vlan members MGMT",
        "set groups LEGACY_ENDUSER interfaces <*> unit 0 family ethernet-switching port-mode access",
        "set groups LEGACY_ENDUSER interfaces <*> unit 0 family ethernet-switching vlan members DATA",
        "set groups LEGACY_ENDUSER interfaces <*> unit 0 family ethernet-switching vlan voice VOICE",
    ]

    interfaces = app_module._parse_config_cmd_interfaces(cli)
    by_name = {item["juniper_if"]: item for item in interfaces}

    assert by_name["ge-0/0/1"]["mode"] == "access"
    assert by_name["ge-0/0/1"]["data_vlan"] == 1
    assert by_name["ge-0/0/6"]["voice_vlan"] == 2
    assert by_name["ge-0/0/6"]["data_vlan"] == 3


def test_load_site_history_parses_breakdown(tmp_path):
    from audit_history import load_site_history

    log_dir = tmp_path / "logs"
    log_dir.mkdir()

    log_contents = (
        "2025-10-13 08:05:38,905 | INFO | user=Eric Stover action=audit_run sites=2 devices=52 "
        "issues=52 errors=0 started=2025-10-13T08:05:30.074244 duration_ms=8831 "
        "site_issue_breakdown=West Chicago:51, Wahpeton:1 site_device_breakdown=West Chicago:30, Wahpeton:22\n"
    )
    (log_dir / "13102025.log").write_text(log_contents, encoding="utf-8")

    history = load_site_history(
        ["West Chicago", "Wahpeton", "Unknown"],
        now=datetime(2025, 10, 13, 12, 0, 0),
        log_dir=log_dir,
    )

    assert history["West Chicago"].issues_total == 51
    assert history["West Chicago"].devices_total == 30
    assert history["West Chicago"].run_count == 1
    assert history["West Chicago"].last_audit_at == datetime(2025, 10, 13, 8, 5, 38, 905000)
    assert len(history["West Chicago"].runs) == 1
    assert history["West Chicago"].runs[0].issues == 51
    assert history["West Chicago"].runs[0].devices == 30
    west_dict = history["West Chicago"].as_dict()
    assert west_dict["runs"][0]["issues"] == 51
    assert west_dict["runs"][0]["devices"] == 30
    assert history["Wahpeton"].issues_total == 1
    assert history["Unknown"].run_count == 0
