import asyncio
import importlib
from types import SimpleNamespace

import pytest


@pytest.fixture
def app_module(monkeypatch):
    monkeypatch.setenv("AUTH_METHOD", "")
    app = importlib.reload(importlib.import_module("app"))
    monkeypatch.setattr(app, "_load_mist_token", lambda: "token")
    return app


def test_api_routes_require_auth(monkeypatch, app_module):
    def _raise(_request):
        raise app_module.HTTPException(status_code=401, detail="Auth required")

    monkeypatch.setattr(app_module, "current_user", _raise)

    request = SimpleNamespace(
        url=SimpleNamespace(path="/api/sites"),
        method="GET",
        headers={},
    )

    with pytest.raises(app_module.HTTPException) as exc:
        asyncio.run(app_module._enforce_api_auth(request, lambda req: None))

    assert exc.value.status_code == 401


def test_csrf_origin_enforced_for_writes(monkeypatch, app_module):
    monkeypatch.setattr(app_module, "current_user", lambda request: {"name": "alice", "can_push": True})
    request = SimpleNamespace(
        url=SimpleNamespace(path="/api/log_timing"),
        method="POST",
        headers={"host": "localhost", "origin": "https://evil.example"},
    )

    with pytest.raises(app_module.HTTPException) as exc:
        asyncio.run(app_module._enforce_api_auth(request, lambda req: None))

    assert exc.value.status_code == 403


def test_api_site_devices_handles_request_error(monkeypatch, app_module):
    class Boom(Exception):
        pass

    def explode(*args, **kwargs):
        raise Boom("network down")

    monkeypatch.setattr(app_module.requests, "get", explode)

    payload = app_module.api_site_devices("site-1")
    assert payload.status_code == 500
    assert payload.body
