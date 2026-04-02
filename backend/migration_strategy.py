#!/usr/bin/env python3
import re
import csv
import io
import requests
import json
from typing import List, Dict, Any, Optional, Set

# Constants for Roles
ROLE_WAN = "WAN"
ROLE_ACCESS = "ACCESS"
ROLE_CORE = "CORE"

# Model Mapping
MIGRATION_MODELS = {
    ROLE_WAN: "EX4000-24T",
    ROLE_ACCESS: "EX4100-48MP",
    ROLE_CORE: "EX4650-48Y",
}

# VLAN Rules
WAN_VLANS = {800, 810}
CORE_VLANS = {400, 401}

# EX4650 Constraints
EX4650_RESERVED_PORTS = set(range(9)) | set(range(48, 56))
EX4650_VALID_RANGE = range(9, 48)

# Optic Family Mapping
# (Pattern, Juniper Speed, Juniper Optic Name)
OPTIC_FAMILIES = [
    (r"SX", "1g", "1000BASE-SX"),
    (r"LX", "1g", "1000BASE-LX"),
    (r"LH", "1g", "1000BASE-LH"),
    (r"T",  "1g", "1000BASE-T"),
    (r"SR", "10g", "10GBASE-SR"),
    (r"LR", "10g", "10GBASE-LR"),
    (r"SR4", "40g", "40GBASE-SR4"),
    (r"LR4", "40g", "40GBASE-LR4"),
]

def classify_interface(intf: Dict[str, Any]) -> str:
    """
    Classifies a Cisco interface into WAN, ACCESS, or CORE/INFRA.
    Logic based on configuration state, ignoring descriptions.
    """
    mode = (intf.get("mode") or "").lower()
    data_vlan = intf.get("data_vlan")
    voice_vlan = intf.get("voice_vlan")
    native_vlan = intf.get("native_vlan")
    autoqos = intf.get("autoqos", False)
    children = intf.get("children", [])
    
    # Rule 1 (WAN): Routed ports (no switchport) or assigned to external/ISP VLANs (800/810)
    if mode == "routed" or data_vlan in WAN_VLANS:
        return ROLE_WAN
    
    # Rule 3 (Core/Infra): Trunk mode, OR in an EtherChannel, OR assigned to infra VLANs (400/401)
    is_etherchannel = any("channel-group" in line for line in children)
    if mode == "trunk" or is_etherchannel or data_vlan in CORE_VLANS or native_vlan in CORE_VLANS:
        return ROLE_CORE
    
    # Rule 2 (Access): Access mode, Voice VLANs, or auto-qos
    if mode == "access" or voice_vlan is not None or autoqos:
        return ROLE_ACCESS
    
    # Default to Access if not otherwise classified
    return ROLE_ACCESS

def parse_optics(show_inventory_text: str) -> Dict[str, str]:
    """
    Parses show inventory to map interface names to optic PIDs.
    Example: NAME: "Te1/1/1", DESCR: "1000BaseSX SFP", PID: GLC-SX-MMD
    """
    optics_map = {}
    current_name = None
    
    # Matches NAME: "Te1/1/1" or NAME: "Switch 1 - Te1/1/1"
    name_re = re.compile(r'NAME:\s*"(?:Switch\s*\d+\s*-\s*)?([^"]+)"', re.IGNORECASE)
    pid_re = re.compile(r"PID:\s*([^\s,]+)", re.IGNORECASE)
    
    for line in show_inventory_text.splitlines():
        name_match = name_re.search(line)
        if name_match:
            current_name = name_match.group(1).strip()
            # Don't continue, check for PID on same line
        
        pid_match = pid_re.search(line)
        if pid_match and current_name:
            pid = pid_match.group(1).strip()
            if pid and pid != "MISSING":
                optics_map[current_name] = pid
            current_name = None
                
    return optics_map

def get_optic_details(cisco_pid: Optional[str]) -> Dict[str, str]:
    """
    Returns speed and Juniper equivalent for a Cisco optic PID.
    """
    if not cisco_pid or cisco_pid == "none":
        return {"speed": "unknown", "juniper_optic": "none"}
    
    for pattern, speed, juniper_optic in OPTIC_FAMILIES:
        if re.search(pattern, cisco_pid, re.IGNORECASE):
            return {"speed": speed, "juniper_optic": juniper_optic}
            
    return {"speed": "unknown", "juniper_optic": "unknown"}

def get_available_core_ports(base_url: str, token: str, site_id: str, device_id: str) -> List[str]:
    """
    Fetches the current port_config for the Core switch and identifies available ports in range 9-47.
    """
    url = f"{base_url.rstrip('/')}/sites/{site_id}/devices/{device_id}"
    headers = {"Authorization": f"Token {token}", "Accept": "application/json"}
    
    try:
        resp = requests.get(url, headers=headers, timeout=20)
        resp.raise_for_status()
        data = resp.json()
        port_config = data.get("port_config", {})
        
        used_indices = set()
        for ifname in port_config.keys():
            m = re.match(r"^(?:et|ge|mge)-0/0/(\d+)$", ifname)
            if m:
                used_indices.add(int(m.group(1)))
        
        available = []
        for i in EX4650_VALID_RANGE:
            if i not in used_indices:
                available.append(f"et-0/0/{i}")
        
        return available
    except Exception as exc:
        print(f"Error fetching core port availability: {exc}")
        return [f"et-0/0/{i}" for i in EX4650_VALID_RANGE]

def map_cisco_port_to_juniper(cisco_name: str, role: str, index: int, available_ports: List[str]) -> str:
    """
    Maps a Cisco port to a Juniper port based on sequential assignment and role.
    """
    if role == ROLE_CORE:
        if index < len(available_ports):
            return available_ports[index]
        else:
            return f"OVERFLOW-CORE-{index}"
    elif role == ROLE_WAN:
        return f"ge-0/0/{index}"
    else:
        if index <= 15:
            return f"mge-0/0/{index}"
        else:
            return f"ge-0/0/{index}"

def calculate_migration_strategy(
    cisco_config_json: Dict[str, Any],
    show_inventory_text: str,
    available_ports_by_role: Dict[str, List[str]]
) -> Dict[str, Any]:
    """
    Main orchestration logic for migration strategy.
    """
    optics_map = parse_optics(show_inventory_text)
    
    interfaces = cisco_config_json.get("interfaces", [])
    roles = {ROLE_WAN: [], ROLE_ACCESS: [], ROLE_CORE: []}
    
    for intf in interfaces:
        role = classify_interface(intf)
        roles[role].append(intf)
    
    def cisco_sort_key(intf):
        name = intf.get("name", "")
        nums = [int(n) for n in re.findall(r"\d+", name)]
        return nums
    
    mappings = []
    hostname = "CiscoSwitch"
    for intf in interfaces:
        for line in intf.get("children", []):
            m = re.match(r"\s*hostname\s+([^\s]+)", line, re.IGNORECASE)
            if m:
                hostname = m.group(1).strip()
                break
    
    for role, role_intfs in roles.items():
        role_intfs.sort(key=cisco_sort_key)
        target_model = MIGRATION_MODELS[role]
        
        for i, intf in enumerate(role_intfs):
            cisco_name = intf.get("name")
            # Normalize name for optics map lookup
            short_name = re.sub(r"^(?:TenGigabitEthernet|GigabitEthernet|FastEthernet|Ten|Gi|Fa)", "", cisco_name, flags=re.IGNORECASE)
            
            # Find in optics map (keys might be short or long)
            cisco_optic = None
            for k, v in optics_map.items():
                if k == cisco_name or k == short_name or cisco_name.endswith(k):
                    cisco_optic = v
                    break
            
            optic_details = get_optic_details(cisco_optic)
            
            target_port = map_cisco_port_to_juniper(
                cisco_name, role, i, available_ports_by_role.get(role, [])
            )
            
            intent = f"{intf.get('mode', '').capitalize()}/{role}"
            
            mapping = {
                "source_device": hostname,
                "source_port": cisco_name,
                "source_optic": cisco_optic or "none",
                "target_role": role,
                "target_model": target_model,
                "target_port": target_port,
                "target_optic": optic_details["juniper_optic"],
                "speed_conversion": optic_details["speed"] if optic_details["speed"] == "1g" else None,
                "intent": intent
            }
            mappings.append(mapping)
            
    return {"mappings": mappings}

def generate_cut_sheet_csv(mappings: List[Dict[str, Any]]) -> str:
    """
    Generates a CSV string for the Cable Cut-Sheet.
    """
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow([
        "Source Device", "Source Port", "Source Optic", 
        "Target Role", "Target Model", "Target Port", 
        "Target Optic Required", "Deduced Intent"
    ])
    
    for m in mappings:
        writer.writerow([
            m.get("source_device", ""),
            m.get("source_port", ""),
            m.get("source_optic", ""),
            m.get("target_role", ""),
            m.get("target_model", ""),
            m.get("target_port", ""),
            m.get("target_optic", ""),
            m.get("intent", "")
        ])
        
    return output.getvalue()
