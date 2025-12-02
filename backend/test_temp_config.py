import importlib
import sys
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))


def _load_app():
    return importlib.reload(importlib.import_module("app"))


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
