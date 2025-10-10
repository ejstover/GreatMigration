import importlib
import sys
from pathlib import Path
from typing import Any, Dict

import pytest


BACKEND_DIR = Path(__file__).resolve().parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))


@pytest.fixture
def app_module(monkeypatch):
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
            {"id": "dev-1", "name": "Switch 1", "status": "connected"},
            {"id": "dev-2", "name": "AP 2", "status": "connected"},
        ],
        "/sites/site-1/devices/dev-1": {
            "id": "dev-1",
            "status": {"state": "online"},
            "switch_config": {"vlans": [10]},
            "extra": "detail",
        },
        "/sites/site-1/devices/dev-2": None,
    }

    def fake_get(base_url: str, headers: Dict[str, str], path: str, optional: bool = False):
        calls.append(path)
        return responses.get(path)

    monkeypatch.setattr(app_module, "_mist_get_json", fake_get)

    context = app_module._fetch_site_context("https://example.com/api/v1", {"Authorization": "token"}, "site-1")

    assert [d.get("id") for d in context.devices] == ["dev-1", "dev-2"]

    dev1 = context.devices[0]
    # Base fields remain, detail fields are merged, and structured statuses are preserved.
    assert dev1["name"] == "Switch 1"
    assert dev1["status"] == {"state": "online"}
    assert dev1["switch_config"] == {"vlans": [10]}
    assert dev1["extra"] == "detail"

    dev2 = context.devices[1]
    # Device without detail fallback retains base information.
    assert dev2["name"] == "AP 2"
    assert dev2["status"] == "connected"

    assert "/sites/site-1/devices/dev-1" in calls
    assert "/sites/site-1/devices/dev-2" in calls
