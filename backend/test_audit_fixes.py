import pytest
import requests

from audit_actions import AP_RENAME_ACTION_ID
from audit_fixes import execute_audit_action


class DummyResponse:
    def __init__(self, payload, status_code=200):
        self._payload = payload
        self.status_code = status_code
        self.text = ""

    def json(self):
        return self._payload

    def raise_for_status(self):
        if self.status_code >= 400:
            raise requests.HTTPError(response=self)


def test_execute_action_rejects_unknown_action():
    with pytest.raises(ValueError):
        execute_audit_action("unknown", "https://example", "token", [])


def test_execute_action_renames_aps_in_dry_run(monkeypatch):
    calls = {"get": [], "put": []}

    def fake_get(url, headers=None, params=None, timeout=None):
        calls["get"].append((url, params))
        if url.endswith("/sites/site-1"):
            return DummyResponse({"name": "Site One"})
        if url.endswith("/sites/site-1/devices"):
            assert params == {"type": "ap"}
            return DummyResponse([
                {"id": "dev1", "mac": "AA:BB:CC", "name": "BadAP"},
                {"id": "dev2", "mac": "DD:EE:FF", "name": "NAABCIDF1AP1"},
            ])
        if url.endswith("/sites/site-1/stats/devices"):
            assert params == {"type": "ap", "limit": 1000}
            return DummyResponse(
                {
                    "results": [
                        {"mac": "aa:bb:cc", "uplink": {"neighbor": {"system_name": "NACHIIDF1AS1"}}},
                        {"mac": "dd:ee:ff", "uplink": {"neighbor": {"system_name": "NACHIIDF1AS2"}}},
                    ]
                }
            )
        raise AssertionError(f"Unexpected GET {url}")

    def fake_put(url, headers=None, json=None, timeout=None):
        calls["put"].append((url, json))
        raise AssertionError("rename should not be executed during dry run")

    monkeypatch.setattr("audit_fixes.requests.get", fake_get)
    monkeypatch.setattr("audit_fixes.requests.put", fake_put)

    result = execute_audit_action(
        AP_RENAME_ACTION_ID,
        "https://api.mist.test/api/v1",
        "token",
        ["site-1"],
        dry_run=True,
    )

    assert result["ok"] is True
    totals = result["totals"]
    assert totals["renamed"] == 1
    assert totals["failed"] == 0
    assert totals["sites"] == 1
    summary = result["results"][0]
    assert summary["site_name"] == "Site One"
    assert summary["renamed"] == 1
    assert summary["changes"]
    # No live PUT requests should be attempted during dry run
    assert calls["put"] == []
