#!/usr/bin/env python3
"""
push_mist_port_config.py

Build/normalize a Mist switch port_config and (optionally) push it.
- Accepts a converter JSON with "interfaces" OR a ready-made "port_config"
- Classifies ports via RULES_DOC (first match wins)
- Maps Cisco Gi<sw>/<mod>/<port> -> Juniper names:
    * Ports 1..48  -> <type>-0/0/<port-1>
    * Ports 49..52 -> <uplink_type>-0/2/<port-49>   (uplinks)
  (<type> is mge/ge for access rows, xe for uplinks on EX4100)
- Shifts the **member** (first number) via --member-offset (or API handler)
- Excludes interfaces by exact name AFTER remap
- Dry-run prints exactly what would be PUT

CLI examples (PowerShell):
  $env:MIST_TOKEN="<token>"
  python push_mist_port_config.py --site-id <SITE> --device-id <DEV> --input input.json --dry-run
  python push_mist_port_config.py --site-id <SITE> --device-id <DEV> --input input.json --dry-run --member-offset 2 --normalize-modules

This module is also imported by FastAPI (app.py) using:
  ensure_port_config(), remap_members(), get_device_model(), timestamp_str()
"""

from __future__ import annotations

import argparse
import json
import os
import re
from datetime import datetime
from typing import Any, Dict, List, Optional

import requests

try:
    from zoneinfo import ZoneInfo  # py3.9+
except Exception:  # pragma: no cover
    ZoneInfo = None  # type: ignore

# -------------------------------
# Defaults (can be overridden by CLI or app layer)
# -------------------------------
API_TOKEN = ""  # prefer env var MIST_TOKEN
BASE_URL  = "https://api.mist.com/api/v1"
TZ        = "America/New_York"

# -------------------------------
# Rules (first match wins) — one per line for readability
# -------------------------------
RULES_DOC: Dict[str, Any] = {
    "defaults": {"no_local_overwrite": False, "critical": False},
    "rules": [
        # AP trunks by explicit VLANs / natives (highest priority)
        {"name": "ap-trunk-n150-allowed-110-120-130-210", "when": {"mode": "trunk", "native_vlan": 150, "allowed_vlans_equals": [110, 120, 130, 210]}, "set": {"usage": "ap"}},
        {"name": "ap-trunk-n120", "when": {"mode": "trunk", "native_vlan": 120}, "set": {"usage": "ap"}},

        # Time clocks (Kronos/UKG/etc.) -> it_peripherals
        {"name": "access-timeclocks-peripherals", "when": {"mode": "access", "description_regex": r"(?i)\b(time[-\s]?clock(s)?|time\s*keeping|timekeeper|kronos|ukg|workforce\s*(ready|central)|(in[\s-]*touch|intouch))\b"}, "set": {"usage": "it_peripherals"}},

        # Printers (brands + generic) -> it_peripherals
        {"name": "access-printers-peripherals", "when": {"mode": "access", "description_regex": r"(?i)\b((hp\s*(laserjet|officejet|deskjet|pagewide))|lexmark|brother|canon(?:\s*(imageclass|imagerunner))?|epson|ricoh|xerox(?:\s*(workcentre|versalink|altalink|phaser))?|konica\s*minolta|kyocera(?:\s*(ecosys|taskalfa))?|sharp\s*(mx|al)|oki|toshiba|dell\s*(laser|laserjet)?|samsung\s*(xpress|ml|sl-)?|mfp|multi[-\s]?function|multifunction|printer|copier|print(?:er|ing))\b"}, "set": {"usage": "it_peripherals"}},

        # Conference panels / Crestron -> it_peripherals
        {"name": "access-conf-panels-crestron", "when": {"mode": "access", "description_regex": r"(?i)\b(crestron|(conference\s*room.*(panel|sched))|(room\s*(sched(ul(e|ing))?|panel)))\b"}, "set": {"usage": "it_peripherals"}},

        # Specific access VLAN patterns
        {"name": "access-10-voice-15-end_user", "when": {"mode": "access", "data_vlan": 10, "voice_vlan": 15}, "set": {"usage": "end_user"}},
        {"name": "vlan-100-end_user", "when": {"mode": "access", "data_vlan": 100}, "set": {"usage": "end_user"}},
        {"name": "vlan-110-voice", "when": {"mode": "access", "data_vlan": 110}, "set": {"usage": "voice"}},
        {"name": "vlan-170-facility", "when": {"mode": "access", "data_vlan": 170}, "set": {"usage": "facility_mgmt"}},
        {"name": "vlan-160-it-periph", "when": {"mode": "access", "data_vlan": 160}, "set": {"usage": "it_peripherals"}},
        {"name": "vlan-3-end_user", "when": {"mode": "access", "data_vlan": 3}, "set": {"usage": "end_user"}},
        {"name": "doors-vlan-5-end_user", "when": {"mode": "access", "data_vlan": 5}, "set": {"usage": "end_user"}},

        # AP trunks by description (lower priority than explicit VLAN rules)
        {"name": "ap-trunk", "when": {"mode": "trunk", "description_regex": r"(?i)\b(ap|access\s*point)\b"}, "set": {"usage": "ap"}},

        # Generic trunk default: IDF uplink
        {"name": "uplink-idf", "when": {"mode": "trunk"}, "set": {"usage": "uplink_idf", "no_local_overwrite": True}},

        # Catch-all (last)
        {"name": "catch-all-blackhole", "when": {"any": True}, "set": {"usage": "blackhole"}},
    ]
}

# -------------------------------
# Description blacklist: drop bland/noisy descriptions
# -------------------------------
BLACKLIST_PATTERNS = [
    r"^\s*$",
    r"^\s*vla?n?\s*\d+\s*$",
    r"^\s*(data|voice)\s*(port)?\s*$",
    r"^\s*end\s*user\s*$",
    r"^\s*user\s*$",
    r".*\bdata\s*vla?n?\b.*",
    r".*\bvoice\s*vla?n?\b.*",
    r".*\b(auto\s*qos|portfast|service-?policy)\b.*",
]

def _norm_desc(s: str) -> str:
    s = re.sub(r"\s+", " ", s or "")
    return s.strip(" -_.,;")

def filter_description_blacklist(raw: str) -> str:
    d = _norm_desc(raw)
    low = d.lower()
    for p in BLACKLIST_PATTERNS:
        if re.search(p, low):
            return ""
    return d

# -------------------------------
# Utilities
# -------------------------------
def load_token() -> str:
    tok = (API_TOKEN or "").strip() or (os.getenv("MIST_TOKEN") or "").strip()
    if not tok:
        raise SystemExit("Missing API token: set env var MIST_TOKEN (preferred) or edit API_TOKEN in this file.")
    return tok

def timestamp_str(tz_name: str) -> str:
    if ZoneInfo is not None:
        try:
            now = datetime.now(ZoneInfo(tz_name))
        except Exception:
            now = datetime.now()
    else:
        now = datetime.now()
    return now.strftime("%Y-%m-%d %H:%M")

def tag_description(desc: str, ts: str) -> str:
    d = (desc or "").strip()
    return f"{d} - converted by API {ts}" if d else f"converted by API {ts}"

def _match_regex(val: Optional[str], pattern: str) -> bool:
    if val is None:
        return False
    return re.search(pattern, val) is not None

def _normalize_vlan_list(v) -> List[int]:
    """Accept list[int]|list[str]|'110,120,130' and return list[int]."""
    if v is None:
        return []
    if isinstance(v, list):
        out: List[int] = []
        for x in v:
            try: out.append(int(x))
            except Exception: pass
        return out
    if isinstance(v, str):
        parts = [p.strip() for p in v.split(",") if p.strip()]
        out = []
        for p in parts:
            try: out.append(int(p))
            except Exception: pass
        return out
    return []

def evaluate_rule(when: Dict[str, Any], intf: Dict[str, Any]) -> bool:
    if not when or when.get("any") is True:
        return True

    mode = (intf.get("mode") or "").lower()
    data_vlan   = int(intf["data_vlan"])   if intf.get("data_vlan")   is not None else None
    voice_vlan  = int(intf["voice_vlan"])  if intf.get("voice_vlan")  is not None else None
    native_vlan = int(intf["native_vlan"]) if intf.get("native_vlan") is not None else None
    allowed_vlans_list = _normalize_vlan_list(intf.get("allowed_vlans"))
    allowed_vlans_set  = set(allowed_vlans_list)
    name       = intf.get("name") or ""
    juniper_if = intf.get("juniper_if") or ""

    for k, v in when.items():
        if k == "mode":
            if mode != str(v).lower(): return False
        elif k == "data_vlan":
            if data_vlan != int(v): return False
        elif k == "data_vlan_in":
            if data_vlan not in set(int(x) for x in v): return False
        elif k == "voice_vlan":
            if voice_vlan != int(v): return False
        elif k == "native_vlan":
            if native_vlan != int(v): return False
        elif k == "allowed_vlans_contains":
            if int(v) not in allowed_vlans_set: return False
        elif k == "allowed_vlans_equals":
            target = set(int(x) for x in (v or []))
            if allowed_vlans_set != target: return False
        elif k == "has_voice":
            if bool(voice_vlan) != bool(v): return False
        elif k == "description_regex":
            if not _match_regex(intf.get("description") or "", v): return False
        elif k == "name_regex":
            if not _match_regex(name, v): return False
        elif k == "juniper_if_regex":
            if not _match_regex(juniper_if, v): return False
        elif k == "any":
            pass
        else:
            return False
    return True

# -------------------------------
# Cisco parsing / mapping
# -------------------------------
# Accept Gi/Te/Fa with 2- or 3-part paths: Gi1/0/49 OR Gi1/49
CISCO_2OR3_RE = re.compile(
    r'(?ix)^(?:ten|tengig|te|gi|gigabitethernet|fa|fastethernet)\s*'
    r'(?P<sw>\d+)\s*/\s*(?:(?P<mod>\d+)\s*/\s*)?(?P<port>\d+)$'
)

def cisco_split(name: str) -> Optional[Dict[str, int]]:
    n = (name or "").replace("Ethernet", "ethernet").strip()
    m = CISCO_2OR3_RE.match(n)
    if not m:
        return None
    sw = int(m.group("sw"))
    mod = int(m.group("mod")) if m.group("mod") is not None else 0
    port = int(m.group("port"))
    return {"sw": sw, "mod": mod, "port": port}

# Legacy helpers (index-based) kept as fallback
CISCO_IF_RE = re.compile(
    r"(?ix)^(?:ten|gig|fast)\s*gab?it(?:ethernet)?\s*(\d+)\s*/\s*(\d+)\s*/\s*(\d+)$|^(?:te|gi|fa)\s*(\d+)\s*/\s*(\d+)\s*/\s*(\d+)$"
)

def cisco_to_index(name: str) -> Optional[int]:
    """Return 1-based canonical index: Gi1/0/1->1, Gi2/0/1->49, etc."""
    n = (name or "").replace("Ethernet", "ethernet").strip()
    m = CISCO_IF_RE.match(n)
    if not m: return None
    g = [x for x in m.groups() if x]
    if len(g) != 3: return None
    sw, _, port = map(int, g)
    return (sw - 1) * 48 + port

def index_to_ex4100_if(model: Optional[str], index_1based: int) -> Optional[str]:
    """Map index to EX4100-like names (PIC 0 only). Member offset applied later."""
    if index_1based is None or index_1based <= 0:
        return None
    p = index_1based - 1  # 0..47
    if model and model.startswith("EX4100-48MP"):
        return f"mge-0/0/{p}" if 0 <= p <= 15 else f"ge-0/0/{p}"
    if model and model.startswith("EX4100-24MP"):
        return f"mge-0/0/{p}" if 0 <= p <= 7 else f"ge-0/0/{p}"
    return f"ge-0/0/{p}"

def cisco_to_ex_if_enhanced(model: Optional[str], name: str) -> Optional[str]:
    """
    Gi<sw>/<mod>/<port> -> Juniper:
      1..48  -> <type>-0/0/<port-1>
      49..52 -> <uplink_type>-0/2/<port-49>   (uplinks)
    Member offset is applied later by remap_members().
    """
    p = cisco_split(name)
    if not p: return None

    port = p["port"]
    member = 0  # base member; shifted later

    # Uplink group: 49..52 -> PIC 2, ports 0..3; xe for EX4100 family
    if 49 <= port <= 52:
        pic = 2
        jport = port - 49
        itype = "xe" if (model or "").startswith("EX4100") else "ge"
        return f"{itype}-{member}/{pic}/{jport}"

    # Front-panel: 1..48 -> PIC 0, ports 0..47; mge window per model
    pic = 0
    jport = port - 1
    if model and model.startswith("EX4100-48MP"):
        itype = "mge" if 0 <= jport <= 15 else "ge"
    elif model and model.startswith("EX4100-24MP"):
        itype = "mge" if 0 <= jport <= 7 else "ge"
    else:
        itype = "ge"
    return f"{itype}-{member}/{pic}/{jport}"

# -------------------------------
# Mist interface regex + MEMBER remap
# -------------------------------
# Accept ge/mge for access and xe/et for uplinks; shift <member> later
MIST_IF_RE = re.compile(r'^(?P<type>ge|mge|xe|et)-(?P<member>\d+)/(?P<pic>\d+)/(?P<port>\d+)$')

def _collect_members(port_config: Dict[str, Any]) -> List[int]:
    mems: List[int] = []
    for ifname in port_config.keys():
        m = MIST_IF_RE.match(ifname)
        if m:
            mems.append(int(m.group("member")))
    return mems

def remap_members(port_config: Dict[str, Any], member_offset: int = 0, normalize: bool = False) -> Dict[str, Any]:
    """
    Shift the **member** (first component) in <type>-<member>/<pic>/<port>.
    If normalize=True, rebase the minimum source member to 0, then add member_offset.
    """
    if member_offset == 0 and not normalize:
        return port_config

    base = 0
    if normalize:
        mems = _collect_members(port_config)
        base = min(mems) if mems else 0

    out: Dict[str, Any] = {}
    for ifname, cfg in port_config.items():
        m = MIST_IF_RE.match(ifname)
        if not m:
            out[ifname] = cfg
            continue

        itype  = m.group("type")
        member = int(m.group("member"))
        pic    = int(m.group("pic"))
        port   = int(m.group("port"))

        new_member = (member - base) + int(member_offset or 0)
        new_name = f"{itype}-{new_member}/{pic}/{port}"
        if new_name in out:
            raise SystemExit(f"Member remap collision on {new_name}")
        out[new_name] = cfg
    return out

# Back-compat alias if old callers used remap_modules()
def remap_modules(port_config: Dict[str, Any], member_offset: int = 0, normalize: bool = False) -> Dict[str, Any]:
    return remap_members(port_config, member_offset=member_offset, normalize=normalize)

# -------------------------------
# Mapping / normalization
# -------------------------------
def map_interfaces_to_port_config(intfs: List[Dict[str, Any]], model: Optional[str]) -> Dict[str, Dict[str, Any]]:
    rules = RULES_DOC.get("rules", []) or []
    defaults = RULES_DOC.get("defaults", {}) or {}

    port_config: Dict[str, Dict[str, Any]] = {}
    for intf in intfs:
        if (intf.get("mode") or "").lower() == "routed":
            continue

        # Prefer our enhanced mapper (handles 49..52 uplinks -> PIC 2)
        derived_if = cisco_to_ex_if_enhanced(model, intf.get("name", ""))

        # Fallback to index-based mapper if needed
        if not derived_if:
            idx = cisco_to_index(intf.get("name", ""))
            derived_if = index_to_ex4100_if(model, idx) if idx is not None else None

        # If converter already included a Juniper name, use it as last resort
        mist_if = derived_if or intf.get("juniper_if") or intf.get("name", "")

        # Evaluate rules (first match wins)
        chosen = None
        for r in rules:
            if evaluate_rule(r.get("when", {}) or {}, intf):
                chosen = r
                break

        usage = None
        no_overwrite = bool(defaults.get("no_local_overwrite", False))
        critical = bool(defaults.get("critical", False))
        if chosen:
            s = chosen.get("set", {}) or {}
            usage = s.get("usage", usage)
            no_overwrite = bool(s.get("no_local_overwrite", no_overwrite))
            critical = bool(s.get("critical", critical))

        raw_desc = intf.get("description", "") or ""
        filtered_desc = filter_description_blacklist(raw_desc)

        cfg: Dict[str, Any] = {"usage": usage or "blackhole", "description": filtered_desc, "no_local_overwrite": no_overwrite}
        if critical:
            cfg["critical"] = True

        if mist_if in port_config:
            raise SystemExit(f"Key collision for {mist_if} (from {intf.get('name')}); check uplink mapping (49–52).")
        port_config[mist_if] = cfg

    return port_config

def extract_port_config(input_json: Dict[str, Any], model: Optional[str] = None) -> Dict[str, Dict[str, Any]]:
    """
    Prefer to compute from 'interfaces' (lets us fix Cisco->Juniper mapping),
    but accept a ready 'port_config' if no interfaces are present.
    """
    if "interfaces" in input_json and isinstance(input_json["interfaces"], list):
        return map_interfaces_to_port_config(input_json["interfaces"], model)
    if "port_config" in input_json and isinstance(input_json["port_config"], dict):
        return input_json["port_config"]
    raise SystemExit("Input JSON must contain either 'interfaces' or 'port_config'.")

# Back-compat shim for imports in app.py
def ensure_port_config(*args) -> Dict[str, Dict[str, Any]]:
    """
    ensure_port_config(input_json [, model])
    """
    if len(args) == 1:
        return extract_port_config(args[0], model=None)
    elif len(args) >= 2:
        return extract_port_config(args[0], model=args[1])
    else:
        raise SystemExit("ensure_port_config requires 1 or 2 arguments.")

# -------------------------------
# Model lookup for CLI
# -------------------------------
def get_device_model(base_url: str, site_id: str, device_id: str, token: str) -> Optional[str]:
    url = f"{base_url.rstrip('/')}/sites/{site_id}/devices/{device_id}"
    try:
        resp = requests.get(url, headers={"Authorization": f"Token {token}"}, timeout=20)
        if 200 <= resp.status_code < 300:
            return resp.json().get("model")
    except Exception:
        pass
    return None

# -------------------------------
# CLI entry
# -------------------------------
def main():
    ap = argparse.ArgumentParser(description="Map and push Mist switch port_config with EX4100 uplink mapping and MEMBER offset.")
    ap.add_argument("--site-id", required=True, help="Mist site_id")
    ap.add_argument("--device-id", required=True, help="Mist device_id")
    ap.add_argument("--input", required=True, help="Path to JSON (converter output OR mapped payload)")
    ap.add_argument("--base-url", default=None, help="Override base URL (default: https://api.mist.com/api/v1)")
    ap.add_argument("--tz", default=None, help="Timezone for timestamp tag (default: America/New_York)")
    ap.add_argument("--dry-run", action="store_true", help="Print request payload instead of sending PUT")
    ap.add_argument("--save-output", default=None, help="Optional path to save the final PUT body JSON")
    ap.add_argument("--model", default=None, help="Device model override (skip API lookup)")
    ap.add_argument("--exclude-interface", action="append", default=None, help="Exact interface name to exclude AFTER remap (repeatable). e.g. --exclude-interface xe-1/2/0")
    ap.add_argument("--member-offset", type=int, default=0, help="Shift the Juniper MEMBER (first number) in <type>-<member>/<pic>/<port> by this offset.")
    ap.add_argument("--normalize-modules", action="store_true", help="Normalize the lowest source MEMBER to 0 before applying --member-offset.")

    args = ap.parse_args()

    token = load_token()
    base_url = (args.base_url or BASE_URL).rstrip("/")
    tz_name = (args.tz or TZ)
    model = args.model or get_device_model(base_url, args.site_id, args.device_id, token)

    with open(args.input, "r", encoding="utf-8") as f:
        inp = json.load(f)

    # Build/obtain port_config
    port_config = extract_port_config(inp, model=model)

    # Apply MEMBER remap BEFORE excludes
    try:
        port_config = remap_members(port_config, member_offset=int(args.member_offset or 0), normalize=bool(args.normalize_modules))
    except Exception as e:
        raise SystemExit(f"Failed to apply member offset: {e}")

    # Apply excludes by exact name (AFTER remap)
    excludes = set(args.exclude_interface or [])
    if excludes:
        port_config = {k: v for k, v in port_config.items() if k not in excludes}

    # Timestamp descriptions
    ts = timestamp_str(tz_name)
    final_port_config: Dict[str, Dict[str, Any]] = {}
    for ifname, cfg in port_config.items():
        c = dict(cfg)
        c["description"] = tag_description(c.get("description", ""), ts)
        final_port_config[ifname] = c

    body = {"port_config": final_port_config}
    url = f"{base_url}/sites/{args.site_id}/devices/{args.device_id}"
    headers = {"Authorization": f"Token {token}", "Content-Type": "application/json", "Accept": "application/json"}

    if args.dry_run:
        print(f"Device model: {model or 'unknown'}")
        print(f"Member offset: {args.member_offset} (normalize: {bool(args.normalize_modules)})")
        print(f"PUT {url}")
        print(json.dumps(body, indent=2))
        return

    # Live PUT
    resp = requests.put(url, headers=headers, json=body, timeout=60)
    try:
        content = resp.json()
    except Exception:
        content = {"text": resp.text}

    if 200 <= resp.status_code < 300:
        print("✅ Success")
        print(json.dumps(content, indent=2))
    else:
        print(f"❌ Error {resp.status_code} on PUT {url}")
        print(json.dumps(content, indent=2))
        if resp.status_code == 404:
            print("Hint: 404 usually means the device isn't in that site, the device_id/site_id is mistyped, or the base URL/region is wrong.")
        resp.raise_for_status()

if __name__ == "__main__":
    main()
