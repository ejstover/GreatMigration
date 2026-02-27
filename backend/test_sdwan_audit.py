from __future__ import annotations

from typing import Any

import pytest

from sdwan_audit import (
    SDWANClient,
    SDWANConfig,
    DeviceSummary,
    check_router_id_equals_system_ip,
    check_system_ip_equals_gig01,
    evaluate_device_checks,
    extract_sdwan_site_id,
    index_devices_by_site_id,
    is_cidr_29,
    normalize_sdwan_site_id,
    validate_device_name,
    expected_vrrp_priority,
)


class DummyLogger:
    def __init__(self) -> None:
        self.messages: list[str] = []

    def info(self, message: str) -> None:
        self.messages.append(message)


def test_sdwan_site_id_validation() -> None:
    assert normalize_sdwan_site_id(" 123 ") == "123"
    assert normalize_sdwan_site_id("abc") is None
    assert extract_sdwan_site_id({"{{SDWAN_SiteID}}": " 44 "}) == "44"


def test_name_suffix_validation() -> None:
    assert validate_device_name("NAABCIDF1AS1 C EDGE 1") is True
    assert validate_device_name("NAABCIDF1AS1 C EDGE one") is False


def test_cidr_29_validation() -> None:
    assert is_cidr_29("10.0.0.0/29") is True
    assert is_cidr_29("10.0.0.0/30") is False


def test_vrrp_priority_mapping() -> None:
    assert expected_vrrp_priority("SITE C EDGE 1") == 110
    assert expected_vrrp_priority("SITE C EDGE 2") == 101


def test_router_id_equals_system_ip() -> None:
    assert check_router_id_equals_system_ip("1.1.1.1", "1.1.1.1")
    assert not check_router_id_equals_system_ip("1.1.1.2", "1.1.1.1")


def test_system_ip_equals_gig01_ip() -> None:
    assert check_system_ip_equals_gig01("2.2.2.2", "2.2.2.2/24")
    assert not check_system_ip_equals_gig01("2.2.2.2", "2.2.2.3/24")


def test_inventory_indexing_logic() -> None:
    rows = [
        {"site-id": "100", "system-ip": "1.1.1.1", "host-name": "A", "latitude": 40.1, "longitude": -74.2},
        {"site-id": "200", "system-ip": "2.2.2.2", "host-name": "B"},
    ]
    indexed = index_devices_by_site_id(rows, ["100"])
    assert list(indexed.keys()) == ["100"]
    assert indexed["100"][0].system_ip == "1.1.1.1"
    assert indexed["100"][0].latitude == 40.1
    assert indexed["100"][0].longitude == -74.2


def test_fallback_filtering_logic(monkeypatch: pytest.MonkeyPatch) -> None:
    logger = DummyLogger()
    client = SDWANClient(SDWANConfig("https://example.com", "token"), logger, "cid")

    calls: list[Any] = []

    def fake_get(site_id=None):
        calls.append(site_id)
        if site_id == "100":
            return [{"site-id": "200", "system-ip": "3.3.3.3", "host-name": "wrong"}]
        return [{"site-id": "100", "system-ip": "1.1.1.1", "host-name": "ok"}]

    monkeypatch.setattr(client, "get_vedges", fake_get)
    indexed, strategy = client.get_cedges_for_sites(["100"])

    assert strategy == "fallback_full_inventory"
    assert indexed["100"][0].system_ip == "1.1.1.1"


def test_logging_strategy_records_events(monkeypatch: pytest.MonkeyPatch) -> None:
    logger = DummyLogger()
    client = SDWANClient(SDWANConfig("https://example.com", "token"), logger, "cid")
    monkeypatch.setattr(client, "get_vedges", lambda site_id=None: [{"site-id": "100", "system-ip": "1.1.1.1", "host-name": "ok"}])
    client.get_cedges_for_sites(["100"])
    assert any("inventory_strategy" in msg for msg in logger.messages)


def test_graceful_failure_when_sdwan_unavailable(monkeypatch: pytest.MonkeyPatch) -> None:
    logger = DummyLogger()
    client = SDWANClient(SDWANConfig("https://example.com", "token"), logger, "cid")

    def blow_up(*args, **kwargs):
        raise RuntimeError("down")

    monkeypatch.setattr(client, "get_vedges", blow_up)
    with pytest.raises(RuntimeError):
        client.get_cedges_for_sites(["100"])




def test_sdwan_config_ssl_verify_flag(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SDWAN_API_URL", "https://vmanage.local")
    monkeypatch.setenv("SDWAN_API_TOKEN", "token")
    monkeypatch.setenv("SDWAN_VERIFY_SSL", "false")

    from sdwan_audit import load_sdwan_config

    cfg = load_sdwan_config()
    assert cfg.verify_ssl is False


def test_sdwan_request_uses_verify_flag(monkeypatch: pytest.MonkeyPatch) -> None:
    logger = DummyLogger()
    client = SDWANClient(SDWANConfig("https://example.com", "token", verify_ssl=False), logger, "cid")

    captured = {}

    class Resp:
        status_code = 200
        url = "https://example.com/dataservice/device/vedges"
        text = "{}"
        content = b"{}"

        def raise_for_status(self):
            return None

        def json(self):
            return {"data": []}

    def fake_request(method, url, headers=None, params=None, timeout=None, verify=None):
        captured["verify"] = verify
        return Resp()

    monkeypatch.setattr("sdwan_audit.requests.request", fake_request)
    client.get_vedges()
    assert captured["verify"] is False

def test_device_checks_include_router_id_and_gi01() -> None:
    device = DeviceSummary(system_ip="10.10.10.10", host_name="NAABCIDF1AS1 C EDGE 1", site_id="100", device_group="branch_routers")
    config = """
router bgp 65494
 router-id 10.10.10.10
 neighbor 1.1.1.1 remote-as 65495
interface GigabitEthernet0/1
 ip address 10.10.10.10/24
 vrrp 10
  priority 110
aggregate-address 10.20.0.0/16
address 192.168.1.0/29
"""
    results = evaluate_device_checks(device, config, {"site-id": "100", "latitude": 1.0, "longitude": 2.0, "device-group": "branch_routers"})
    by_id = {r["check_id"]: r for r in results}
    assert by_id["sdwan_router_id"]["pass"] is True
    assert by_id["sdwan_system_ip_gig01"]["pass"] is True
