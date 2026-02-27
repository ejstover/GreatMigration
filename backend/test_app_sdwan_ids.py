import importlib
import sys
import threading
import time
from pathlib import Path

import pytest

BACKEND_DIR = Path(__file__).resolve().parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))


@pytest.fixture
def app_module(monkeypatch):
    monkeypatch.setenv("SWITCH_TEMPLATE_ID", "template-1")
    app = importlib.reload(importlib.import_module("app"))
    monkeypatch.setattr(app, "_load_mist_token", lambda: "token")
    app._MIST_SITE_SDWAN_ID_CACHE["expires_at"] = 0
    app._MIST_SITE_SDWAN_ID_CACHE["values"] = {}
    return app


def test_mist_site_sdwan_ids_uses_concurrent_fetching(monkeypatch, app_module):
    active = 0
    max_active = 0
    lock = threading.Lock()

    def fake_get(base_url, headers, path, optional=False):
        nonlocal active, max_active
        with lock:
            active += 1
            max_active = max(max_active, active)
        try:
            time.sleep(0.05)
            site_id = path.split("/")[2]
            return {"variables": {"SDWAN_SiteID": site_id[-1]}}
        finally:
            with lock:
                active -= 1

    monkeypatch.setattr(app_module, "_mist_get_json", fake_get)
    monkeypatch.setattr(app_module, "MIST_SITE_SETTING_MAX_WORKERS", 4)

    sites = [{"id": f"site-{idx}"} for idx in range(8)]
    result = app_module._mist_site_sdwan_ids("https://example.com/api/v1", {"Authorization": "token"}, sites)

    assert result["site-0"] == "0"
    assert result["site-7"] == "7"
    assert max_active > 1


def test_mist_site_sdwan_ids_returns_partial_results_when_some_sites_fail(monkeypatch, app_module):
    monkeypatch.setattr(app_module, "MIST_SITE_SETTING_FETCH_TIMEOUT_SECONDS", 0.1)
    monkeypatch.setattr(app_module, "MIST_SITE_SETTING_POLL_INTERVAL_SECONDS", 0.01)

    def fake_get(base_url, headers, path, optional=False):
        site_id = path.split("/")[2]
        if site_id == "site-fast":
            return {"variables": {"SDWAN_SiteID": "100"}}
        if site_id == "site-error":
            raise RuntimeError("boom")
        if site_id == "site-slow":
            time.sleep(0.25)
            return {"variables": {"SDWAN_SiteID": "300"}}
        return None

    monkeypatch.setattr(app_module, "_mist_get_json", fake_get)

    started = time.perf_counter()
    result = app_module._mist_site_sdwan_ids(
        "https://example.com/api/v1",
        {"Authorization": "token"},
        [{"id": "site-fast"}, {"id": "site-error"}, {"id": "site-slow"}],
    )
    elapsed = time.perf_counter() - started

    assert result == {"site-fast": "100"}
    assert elapsed < 0.2
