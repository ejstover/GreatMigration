"""Tests never use installation credentials, network access, or persistent state."""
import os
import sys
import json
from datetime import datetime, timezone
from pathlib import Path

import pytest
import requests
import dotenv

sys.path.insert(0, str(Path(__file__).resolve().parent))
os.environ.update(
    AUTH_METHOD="local", SESSION_SECRET="security-tests-only-" + "x" * 40,
    SESSION_HTTPS_ONLY="false", MIST_TOKEN="synthetic-test-token",
    LOCAL_USERS_FILE="", LOCAL_USERS="", SYSLOG_HOST="", SYSLOG_SERVER="",
    APP_ALLOWED_HOSTS="localhost,127.0.0.1,::1,testserver",
    MIST_ORG_ID="synthetic-test-org", MIST_BASE_URL="https://api.ac2.mist.com",
)

# Block external requests and installation-local dotenv loading during collection too.
def deny_network(*args, **kwargs):
    raise AssertionError("Unexpected network request in tests; mock the service explicitly")


requests.sessions.Session.send = deny_network
dotenv.load_dotenv = lambda *args, **kwargs: False


@pytest.fixture(autouse=True)
def isolated_runtime(monkeypatch, tmp_path):
    import requests
    import logging_utils
    import conversion_sets
    import network_state_snapshots
    import ssh_collect
    import compliance

    monkeypatch.setenv("SECURITY_DB_PATH", str(tmp_path / "security.sqlite3"))
    monkeypatch.setattr(conversion_sets, "DATA_DIR", tmp_path / "conversion_sets")
    monkeypatch.setattr(network_state_snapshots, "DATA_DIR", tmp_path / "network_state")
    monkeypatch.setattr(ssh_collect, "JOB_ROOT", tmp_path / "tmp_ssh_jobs")
    monkeypatch.setattr(logging_utils.get_user_logger(), "disabled", True)
    standards = tmp_path / "isolated_firmware_fixture.json"
    standards.write_text(json.dumps({"generated_at": datetime.now(timezone.utc).isoformat(),
        "models": {"switch": {"FIXTURE": [{"version": "fixture-version"}]}, "ap": {}}}), encoding="utf-8")
    monkeypatch.setattr(compliance, "_firmware_standards_path", lambda: standards)
    monkeypatch.setattr(compliance, "_MIST_ORG_ID_CACHE", None)

    monkeypatch.setattr(requests.sessions.Session, "send", deny_network)
