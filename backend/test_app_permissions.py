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
