from pathlib import Path
import sys


BACKEND_DIR = Path(__file__).resolve().parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

import network_state_snapshots as nss


def test_parse_legacy_mac_table_extracts_vlan_mac_and_interface():
    raw = """
          Mac Address Table
-------------------------------------------
Vlan    Mac Address       Type        Ports
----    -----------       --------    -----
  10    0011.2233.4455    DYNAMIC     Gi1/0/1
 200    aa:bb:cc:dd:ee:ff DYNAMIC     Port-channel5
"""

    results = nss.parse_legacy_mac_table(raw)

    assert results[0]["client_mac"] == "00:11:22:33:44:55"
    assert results[0]["vlan_id"] == 10
    assert results[0]["source_interface"] == "Gi1/0/1"
    assert results[1]["client_mac"] == "aa:bb:cc:dd:ee:ff"
    assert results[1]["source_interface"] == "Po5"


def test_compare_baseline_to_mist_reports_matches_missing_and_new():
    baseline = {
        "run_id": "baseline-1",
        "port_mappings": [
            {
                "source_device_aliases": ["core-1.running-config", "core-1"],
                "source_interface": "GigabitEthernet1/0/1",
                "site_id": "site-1",
                "site_name": "HQ",
                "device_id": "dev-1",
                "device_name": "Juniper-1",
                "target_port": "ge-0/0/0",
            }
        ],
        "legacy_mac_observations": [
            {
                "client_mac": "00:11:22:33:44:55",
                "source_device": "core-1",
                "source_device_aliases": ["core-1.running-config", "core-1"],
                "source_interface": "Gi1/0/1",
            },
            {
                "client_mac": "00:11:22:33:44:66",
                "source_device": "core-1",
                "source_device_aliases": ["core-1.running-config", "core-1"],
                "source_interface": "Gi1/0/1",
            },
        ],
    }
    mist = [
        {
            "client_mac": "00:11:22:33:44:55",
            "site_id": "site-1",
            "device_id": "dev-1",
            "device_name": "Renamed Juniper",
            "port_id": "ge-0/0/0",
        },
        {
            "client_mac": "00:11:22:33:44:77",
            "site_id": "site-1",
            "device_id": "dev-1",
            "device_name": "Renamed Juniper",
            "port_id": "ge-0/0/7",
        },
    ]

    result = nss.compare_baseline_to_mist(
        project_name="Campus Core",
        baseline_run=baseline,
        mist_observations=mist,
    )

    status_by_mac = {item["client_mac"]: item["status"] for item in result["results"]}
    assert status_by_mac["00:11:22:33:44:55"] == "matched_expected_port"
    assert status_by_mac["00:11:22:33:44:66"] == "missing_in_current_mist_state"
    assert status_by_mac["00:11:22:33:44:77"] == "new_post_only_mac"
