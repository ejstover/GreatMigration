import importlib
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest


BACKEND_DIR = Path(__file__).resolve().parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))


@pytest.fixture
def app_module(monkeypatch):
    app = importlib.reload(importlib.import_module("app"))
    # Prevent network/token lookups during tests
    monkeypatch.setattr(app, "_load_mist_token", lambda: "token")
    return app


def _dummy_request():
    req = SimpleNamespace()
    req.client = SimpleNamespace(host="127.0.0.1")
    return req


def test_ensure_push_allowed_permits_dry_run(monkeypatch, app_module):
    req = _dummy_request()

    monkeypatch.setattr(
        app_module,
        "current_user",
        lambda request: {"name": "alice", "can_push": False, "read_only": True},
    )
    # Silence logging noise
    monkeypatch.setattr(app_module.action_logger, "warning", lambda *args, **kwargs: None)

    user = app_module._ensure_push_allowed(req, dry_run=True)
    assert user["read_only"] is True


def test_ensure_push_allowed_blocks_live_push(monkeypatch, app_module):
    req = _dummy_request()

    monkeypatch.setattr(
        app_module,
        "current_user",
        lambda request: {"name": "alice", "can_push": False, "read_only": True},
    )

    warnings = []

    def _record(*args, **kwargs):
        warnings.append((args, kwargs))

    monkeypatch.setattr(app_module.action_logger, "warning", _record)

    with pytest.raises(app_module.HTTPException) as exc:
        app_module._ensure_push_allowed(req, dry_run=False)

    assert exc.value.status_code == 403
    assert warnings
    assert "read_only_attempt" in warnings[0][0][0]


def test_sanitize_base_url_rejects_untrusted_host(app_module):
    with pytest.raises(ValueError):
        app_module._sanitize_base_url("https://evil.example.com/api/v1")


def test_api_sites_requires_auth(monkeypatch, app_module):
    req = _dummy_request()

    def _deny(_request):
        raise app_module.HTTPException(status_code=401, detail="Auth required")

    monkeypatch.setattr(app_module, "current_user", _deny)

    with pytest.raises(app_module.HTTPException) as exc:
        app_module.api_sites(req)

    assert exc.value.status_code == 401


def test_api_sites_uses_sanitized_base_url(monkeypatch, app_module):
    req = _dummy_request()
    monkeypatch.setattr(app_module, "current_user", lambda request: {"name": "alice", "can_push": False})
    monkeypatch.setattr(app_module, "_list_sites", lambda base_url, headers, org_id=None: [{"id": "s1", "name": "site"}])

    payload = app_module.api_sites(req, base_url="https://api.mist.com/api/v1/")

    assert payload["ok"] is True
    assert payload["items"][0]["id"] == "s1"
