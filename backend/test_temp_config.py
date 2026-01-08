import importlib
import os
import sys
from pathlib import Path
from typing import Optional

BACKEND_DIR = Path(__file__).resolve().parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))


def _load_app():
    return importlib.reload(importlib.import_module("app"))


def _restore_env(var: str, original: Optional[str]) -> None:
    if original is None:
        os.environ.pop(var, None)
    else:
        os.environ[var] = original


def test_merge_new_vlan_networks_ignores_existing_name():
    app = _load_app()

    existing = {"Test250": {"vlan_id": 250}}
    networks_new = {"test250": {"vlan_id": 250, "note": "already present"}}

    result = app._merge_new_vlan_networks(existing, networks_new, set())

    assert result == {}


def test_merge_new_vlan_networks_keeps_unique_vlans():
    app = _load_app()

    existing = {"Test250": {"vlan_id": 250}}
    networks_new = {
        "NEW10": {"vlan_id": 10},
        "test250": {"vlan_id": 250},
    }

    result = app._merge_new_vlan_networks(existing, networks_new, set())

    assert "NEW10" in result
    assert result["NEW10"]["vlan_id"] == 10
    assert "test250" not in result
    assert result.get("Test250", {}).get("vlan_id") == 250


def test_generate_temp_network_name_respects_excluded_vlans():
    original = os.environ.get("EXCLUDE_VLANS")
    os.environ["EXCLUDE_VLANS"] = "10"
    try:
        app = _load_app()

        prefixed = app._generate_temp_network_name(20, "users")
        excluded = app._generate_temp_network_name(10, "users")

        assert prefixed.startswith("legacy_")
        assert not excluded.startswith("legacy_")
    finally:
        _restore_env("EXCLUDE_VLANS", original)
        _load_app()


def test_temp_port_profiles_prefixed_unless_vlan_excluded():
    original = os.environ.get("EXCLUDE_VLANS")
    os.environ["EXCLUDE_VLANS"] = "10"
    try:
        app = _load_app()
        row = {
            "_temp_config_source": {
                "interfaces": [
                    {"juniper_if": "ge-0/0/1", "mode": "access", "data_vlan": 10},
                    {"juniper_if": "ge-0/0/2", "mode": "access", "data_vlan": 30},
                ],
                "vlans": [
                    {"id": 10, "name": "Data10"},
                    {"id": 30, "name": "Data30"},
                ],
            }
        }

        payload = app._build_temp_config_payload(row) or {}
        port_usages = payload.get("port_usages", {})

        assert any(name.startswith("legacy_") for name in port_usages)
        assert any(not name.startswith("legacy_") for name in port_usages)
    finally:
        _restore_env("EXCLUDE_VLANS", original)
        _load_app()
