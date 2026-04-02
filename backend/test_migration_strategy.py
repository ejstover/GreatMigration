import pytest
import migration_strategy

def test_classify_interface_wan():
    intf = {"mode": "routed", "data_vlan": 10}
    assert migration_strategy.classify_interface(intf) == migration_strategy.ROLE_WAN
    
    intf = {"mode": "access", "data_vlan": 800}
    assert migration_strategy.classify_interface(intf) == migration_strategy.ROLE_WAN

def test_classify_interface_core():
    intf = {"mode": "trunk", "data_vlan": 10}
    assert migration_strategy.classify_interface(intf) == migration_strategy.ROLE_CORE
    
    intf = {"mode": "access", "data_vlan": 400}
    assert migration_strategy.classify_interface(intf) == migration_strategy.ROLE_CORE
    
    intf = {"mode": "access", "children": [" channel-group 1 mode active"]}
    assert migration_strategy.classify_interface(intf) == migration_strategy.ROLE_CORE

def test_classify_interface_access():
    intf = {"mode": "access", "data_vlan": 10}
    assert migration_strategy.classify_interface(intf) == migration_strategy.ROLE_ACCESS
    
    intf = {"mode": "access", "voice_vlan": 16}
    assert migration_strategy.classify_interface(intf) == migration_strategy.ROLE_ACCESS
    
    intf = {"mode": "access", "autoqos": True}
    assert migration_strategy.classify_interface(intf) == migration_strategy.ROLE_ACCESS

def test_parse_optics():
    text = """
NAME: "Te1/1/1", DESCR: "1000BaseSX SFP", PID: GLC-SX-MMD
NAME: "Te1/1/2", DESCR: "10GBase-SR", PID: SFP-10G-SR
NAME: "Gi1/0/1", DESCR: "1000BaseT", PID: GLC-T
"""
    optics = migration_strategy.parse_optics(text)
    assert optics["Te1/1/1"] == "GLC-SX-MMD"
    assert optics["Te1/1/2"] == "SFP-10G-SR"
    assert optics["Gi1/0/1"] == "GLC-T"

def test_get_optic_details():
    assert migration_strategy.get_optic_details("GLC-SX-MMD")["speed"] == "1g"
    assert migration_strategy.get_optic_details("SFP-10G-SR")["speed"] == "10g"
    assert migration_strategy.get_optic_details("GLC-T")["speed"] == "1g"
    assert migration_strategy.get_optic_details("NONE")["speed"] == "unknown"

def test_ex4650_port_mapping_constraints():
    # EX4650 should stay within 9-47
    available_ports = [f"et-0/0/{i}" for i in range(9, 48)]
    
    # Map 50 core ports (should overflow after 39 available)
    for i in range(50):
        port = migration_strategy.map_cisco_port_to_juniper("Gi1/0/1", migration_strategy.ROLE_CORE, i, available_ports)
        if i < 39:
            assert port == f"et-0/0/{9+i}"
        else:
            assert "OVERFLOW" in port

def test_calculate_migration_strategy_logic():
    cisco_json = {
        "interfaces": [
            {"name": "GigabitEthernet1/0/1", "mode": "access", "data_vlan": 10},
            {"name": "TenGigabitEthernet1/1/1", "mode": "trunk", "native_vlan": 1},
            {"name": "GigabitEthernet1/0/2", "mode": "routed"}
        ]
    }
    inventory = """
NAME: "TenGigabitEthernet1/1/1", PID: GLC-SX-MMD
"""
    available_ports = {
        migration_strategy.ROLE_CORE: ["et-0/0/9", "et-0/0/10"],
        migration_strategy.ROLE_WAN: [],
        migration_strategy.ROLE_ACCESS: []
    }
    
    result = migration_strategy.calculate_migration_strategy(cisco_json, inventory, available_ports)
    mappings = result["mappings"]
    
    # Verify classification and mapping
    access_m = next(m for m in mappings if m["source_port"] == "GigabitEthernet1/0/1")
    assert access_m["target_role"] == migration_strategy.ROLE_ACCESS
    assert access_m["target_port"] == "mge-0/0/0"
    
    core_m = next(m for m in mappings if m["source_port"] == "TenGigabitEthernet1/1/1")
    assert core_m["target_role"] == migration_strategy.ROLE_CORE
    assert core_m["target_port"] == "et-0/0/9"
    assert core_m["speed_conversion"] == "1g" # GLC-SX-MMD is 1g
    
    wan_m = next(m for m in mappings if m["source_port"] == "GigabitEthernet1/0/2")
    assert wan_m["target_role"] == migration_strategy.ROLE_WAN
    assert wan_m["target_port"] == "ge-0/0/0"
