import importlib
import sys
from pathlib import Path


BACKEND_DIR = Path(__file__).resolve().parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))


def test_signature_validation_without_secret_allows_any_signature():
    app = importlib.reload(importlib.import_module("app"))
    assert app._signature_is_valid(b"{}", "", "") is True
    assert app._signature_is_valid(b"{}", "anything", "") is True


def test_signature_validation_with_secret_checks_hmac():
    app = importlib.reload(importlib.import_module("app"))
    secret = "super-secret"
    body = b'{"event":"device.updated"}'
    digest = app.hmac.new(secret.encode("utf-8"), body, app.hashlib.sha256).hexdigest()

    assert app._signature_is_valid(body, digest, secret) is True
    assert app._signature_is_valid(body, f"sha256={digest}", secret) is True
    assert app._signature_is_valid(body, "deadbeef", secret) is False


def test_extract_webhook_metadata_supports_common_key_variants():
    app = importlib.reload(importlib.import_module("app"))
    payload = {
        "topic": "org.site.push.completed",
        "orgId": "org-1",
        "siteId": "site-1",
        "deviceId": "device-1",
    }
    meta = app._extract_webhook_metadata(payload)

    assert meta == {
        "event": "org.site.push.completed",
        "org_id": "org-1",
        "site_id": "site-1",
        "device_id": "device-1",
    }


def test_register_recently_configured_device_sets_expiration():
    app = importlib.reload(importlib.import_module("app"))
    app.RECENTLY_CONFIGURED_DEVICES.clear()
    app._register_recently_configured_device(
        site_id="site-1",
        device_id="device-1",
        device_name="SW-1",
        now_ts=100.0,
    )
    row = app.RECENTLY_CONFIGURED_DEVICES["device-1"]
    assert row["device_name"] == "SW-1"
    assert row["expires_at"] == 100.0 + app.WEBHOOK_DEVICE_CACHE_TTL_SECONDS


def test_build_alerts_matches_recent_device_for_device_topic():
    app = importlib.reload(importlib.import_module("app"))
    app.RECENTLY_CONFIGURED_DEVICES.clear()
    app.WEBHOOK_ALERTS.clear()
    app.WEBHOOK_ALERT_SEQ = 0

    app._register_recently_configured_device(site_id="site-1", device_id="device-1", device_name="SW-1")
    matched = app._build_alerts_from_webhook(
        event_name="device-events.config.updated",
        payload={"device_id": "device-1", "site_id": "site-1"},
    )

    assert matched == [{"device_id": "device-1", "device_name": "SW-1"}]
    assert len(app.WEBHOOK_ALERTS) == 1
    assert app.WEBHOOK_ALERTS[0]["device_name"] == "SW-1"


def test_build_alerts_ignores_unrelated_topic():
    app = importlib.reload(importlib.import_module("app"))
    app.RECENTLY_CONFIGURED_DEVICES.clear()
    app.WEBHOOK_ALERTS.clear()
    app.WEBHOOK_ALERT_SEQ = 0

    app._register_recently_configured_device(site_id="site-1", device_id="device-1", device_name="SW-1")
    matched = app._build_alerts_from_webhook(
        event_name="org.inventory.changed",
        payload={"device_id": "device-1"},
    )

    assert matched == []
    assert len(app.WEBHOOK_ALERTS) == 0
