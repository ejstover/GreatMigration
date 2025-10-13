import importlib
import sys
from datetime import datetime
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
    calls: list[str] = []

    responses: Dict[str, Any] = {
        "/sites/site-1": {"id": "site-1", "name": "HQ"},
        "/sites/site-1/setting": {"variables": {}},
        "/sites/site-1/networktemplates": [],
        "/sites/site-1/devices": [
            {"id": "dev-2", "name": "AP 2", "status": "connected"},
            {"id": "dev-3", "name": "Switch 3", "status": "offline"},
        ],
        "/sites/site-1/devices?type=switch": [
            {"id": "dev-1", "name": "Switch 1", "status": "connected"},
        ],
        "/sites/site-1/stats/devices?type=switch&limit=1000": {
            "results": [
                {"id": "dev-1", "name": "Switch 1", "version": "23.4R2-S4.11"},
            ]
        },
        "/sites/site-1/stats/devices?type=ap&limit=1000": {
            "results": [
                {"id": "dev-2", "name": "AP 2", "version": "0.12.27452"},
            ]
        },
        "/sites/site-1/devices/dev-1": {
            "id": "dev-1",
            "status": {"state": "online"},
            "switch_config": {"vlans": [10]},
            "extra": "detail",
        },
        "/sites/site-1/devices/dev-2": None,
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
