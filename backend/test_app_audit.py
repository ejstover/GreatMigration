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


def test_api_audit_pdf_generates_report(app_module):
    audit_result = {
        "checks": [
            {
                "id": "required_site_variables",
                "name": "Required site variables",
                "description": "Ensure required Mist site variables are defined.",
                "severity": "error",
                "findings": [
                    {
                        "site_id": "site-1",
                        "site_name": "HQ",
                        "message": "Site variable 'hubDNSserver1' is not defined.",
                    }
                ],
                "failing_sites": ["site-1"],
                "passing_sites": 0,
                "actions": [],
            }
        ],
        "sites": [
            {"id": "site-1", "name": "HQ", "org_id": "org-1", "issues": 1, "devices": 2, "history": None}
        ],
        "total_sites": 1,
        "total_devices": 2,
        "total_findings": 1,
        "total_quick_fix_issues": 0,
        "errors": [],
        "started_at": "2024-05-01T12:00:00",
        "finished_at": "2024-05-01T12:00:02",
        "duration_ms": 2000,
    }

    response = app_module.api_audit_pdf(
        {
            "audit": audit_result,
            "generated_by": "Tester",
            "context": {"scope_label": "HQ sites", "site_names": ["HQ"]},
        }
    )

    assert response.media_type == "application/pdf"
    assert response.headers.get("content-disposition") == (
        "attachment; filename=compliance_audit_report_HQ_sites_20240501.pdf"
    )
    text = response.body.decode("latin-1", errors="ignore")
    assert "Compliance Audit Report" in text
    assert "Scope: HQ sites" in text
    assert "Sites audited: 1" in text
    assert "Site variable 'hubDNSserver1' is not defined." in text
    assert "HQ - 2 device" in text


def test_api_audit_pdf_falls_back_to_site_name(app_module):
    audit_result = {
        "checks": [
            {
                "id": "device_docs",
                "name": "Device documentation",
                "description": "Ensure devices are documented.",
                "severity": "warning",
                "findings": [],
                "failing_sites": [],
                "passing_sites": 1,
                "actions": [],
            }
        ],
        "sites": [{"id": "site-2", "name": "R&D / Lab", "issues": 0, "devices": 5}],
        "total_sites": 1,
        "total_devices": 5,
        "total_findings": 0,
        "total_quick_fix_issues": 0,
        "errors": [],
        "started_at": "2024-06-15T09:30:00",
        "finished_at": "2024-06-15T09:30:10",
        "duration_ms": 10000,
    }

    response = app_module.api_audit_pdf({"audit": audit_result})

    assert response.media_type == "application/pdf"
    assert response.headers.get("content-disposition") == (
        "attachment; filename=compliance_audit_report_R_D_Lab_20240615.pdf"
    )
    text = response.body.decode("latin-1", errors="ignore")
    assert "Device documentation" in text
    assert "R&D / Lab" in text
    assert "Passing sites: 1 | Failing sites: 0 | Findings: 0" in text
