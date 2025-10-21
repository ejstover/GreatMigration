import json

import pytest

from mist_two_phase import (
    CiscoInterface,
    apply_vlan_mapping_to_port_config,
    build_temp_port_config,
    normalize_vlan_mapping_rules,
    parse_cisco_interfaces,
    parse_cisco_vlans,
)
from ciscoconfparse import CiscoConfParse


SAMPLE_CONFIG = """
vlan 10
 name Users
vlan 20
 name Voice
!
interface GigabitEthernet1/0/1
 description Finance
 switchport mode access
 switchport access vlan 10
 switchport voice vlan 20
!
interface GigabitEthernet1/0/24
 description Uplink IDF
 switchport mode trunk
 switchport trunk native vlan 10
 switchport trunk allowed vlan 10,20
!"""


def test_parse_cisco_vlans_and_interfaces():
    conf = CiscoConfParse(SAMPLE_CONFIG.splitlines(), syntax="ios")
    vlans = parse_cisco_vlans(conf)
    interfaces = parse_cisco_interfaces(conf)

    assert {v["vlan_id"] for v in vlans} == {10, 20}
    assert interfaces[0].name == "GigabitEthernet1/0/1"
    assert interfaces[0].access_vlan == 10
    assert interfaces[0].voice_vlan == 20
    assert interfaces[1].is_trunk()
    assert interfaces[1].trunk_native == 10
    assert set(interfaces[1].trunk_allowed) == {10, 20}


def test_build_temp_port_config_creates_expected_overrides():
    interfaces = [
        CiscoInterface(
            name="GigabitEthernet1/0/1",
            mode="access",
            access_vlan=10,
            voice_vlan=20,
            trunk_native=None,
            trunk_allowed=[],
            description="Finance",
        ),
        CiscoInterface(
            name="GigabitEthernet1/0/24",
            mode="trunk",
            access_vlan=None,
            voice_vlan=None,
            trunk_native=10,
            trunk_allowed=[10, 20],
            description="Uplink",
        ),
    ]

    port_config = build_temp_port_config(interfaces, model="EX4100-48MP")

    assert port_config["mge-0/0/0"]["usage"] == "temp_access"
    assert port_config["mge-0/0/0"]["vlan_id"] == 10
    assert port_config["mge-0/0/0"]["voice_vlan_id"] == 20
    assert port_config["ge-0/0/23"]["usage"] == "temp_trunk"
    assert port_config["ge-0/0/23"]["native_vlan_id"] == 10
    assert port_config["ge-0/0/23"]["allowed_vlan_ids"] == [10, 20]


def test_normalize_vlan_mapping_rules():
    raw_rules = {
        "10": 110,
        20: {"new_vlan_id": 220, "port_profile_id": "uuid", "usage": "end_user"},
    }
    normalized = normalize_vlan_mapping_rules(raw_rules)

    assert normalized[10] == {"new_vlan_id": 110}
    assert normalized[20]["new_vlan_id"] == 220
    assert normalized[20]["port_profile_id"] == "uuid"
    assert normalized[20]["usage"] == "end_user"


def test_apply_vlan_mapping_to_port_config():
    existing = {
        "ge-0/0/0": {"usage": "temp_access", "vlan_id": 10, "voice_vlan_id": 20},
        "ge-0/0/23": {
            "usage": "temp_trunk",
            "native_vlan_id": 10,
            "allowed_vlan_ids": [10, 20],
        },
    }
    mapping = normalize_vlan_mapping_rules({"10": 110, "20": {"new_vlan_id": 220, "usage": "voice"}})

    updated, touched = apply_vlan_mapping_to_port_config(existing, mapping)

    assert set(touched) == {"ge-0/0/0", "ge-0/0/23"}
    assert updated["ge-0/0/0"]["vlan_id"] == 110
    assert updated["ge-0/0/0"]["voice_vlan_id"] == 220
    assert updated["ge-0/0/0"]["usage"] == "access"
    assert updated["ge-0/0/23"]["native_vlan_id"] == 110
    assert updated["ge-0/0/23"]["allowed_vlan_ids"] == [110, 220]
    assert updated["ge-0/0/23"]["usage"] == "uplink"

