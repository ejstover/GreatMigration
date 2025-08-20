#!/usr/bin/env python3
# push_mist_port_config.py
#
# Build/normalize a Mist switch port_config and (optionally) push it.
# - Accepts a converter JSON (with "interfaces") or a ready-made "port_config"
# - Classifies ports using RULES_DOC (first match wins)
# - Cleans bland descriptions; appends "converted by API <timestamp>"
# - Maps Cisco -> EX4100 front-panel (index-based) when needed
# - **Offsets the JUNIPER MEMBER (first number)** in ge-<member>/<pic>/<port>
# - Per-run excludes
# - Dry-run prints the exact body that would be PUT to Mist
#
# PowerShell examples:
#   $env:MIST_TOKEN = "<token>"
#   python push_mist_port_config.py --site-id <SITE> --device-id <DEV> --input C:\configs\stack1.json --dry-run
#   python push_mist_port_config.py --site-id <SITE> --device-id <DEV> --input C:\configs\stack2.json --member-offset 3 --normalize-modules --dry-run
#
# Notes:
# - --member-offset shifts the **member** (first number) in interface names.
# - --normalize-modules re-bases the lowest member seen to 0 before applying the offset.
# - Excludes are applied AFTER remapping.

from __future__ import annotations

import argparse
import json
import os
import re
from datetime import datetime
from typing import Any, Dict, List, Optional

import requests

try:
    from zoneinfo import ZoneInfo  # Python 3.9+
except Exception:  # pragma: no cover
    ZoneInfo = None  # type: ignore

# ==============================
# CONFIG DEFAULTS (override via CLI/env)
# ==============================
API_TOKEN = ""  # leave blank; prefer env var MIST_TOKEN
BASE_URL  = "https://api.mist.com/api/v1"
TZ        = "America/New_York"

# ==============================
# RULES (first match wins) — one rule per line for readability
# ==============================
RULES_DOC: Dict[str, Any] = {
    "defaults": { "no_local_overwrite": False, "critical": False },
    "rules": [
        # AP trunks by explicit VLANs / natives (highest priority)
        {"name": "ap-trunk-n150-allowed-110-120-130-210", "when": {"mode": "trunk", "native_vlan": 150, "allowed_vlans_equals": [110, 120, 130, 210]}, "set": {"usage": "ap"}},
        {"name": "ap-trunk-n120", "when": {"mode": "trunk", "native_vlan": 120}, "set": {"usage": "ap"}},
        # Try to find time clocks
        {"name": "access-timeclocks-peripherals", "when": {"mode": "access", "description_regex": r"(?i)\b(time[-\s]?clock(s)?|time\s*keeping|timekeeper|kronos|ukg|workforce\s*(ready|central)|(in[\s-]*touch|intouch))\b"}, "set": {"usage": "it_peripherals"}},
        # Try to find printers
        {"name": "access-printers-peripherals", "when": {"mode": "access", "description_regex": r"(?i)\b((hp\s*(laserjet|officejet|deskjet|pagewide))|lexmark|brother|canon(?:\s*(imageclass|imagerunner))?|epson|ricoh|xerox(?:\s*(workcentre|versalink|altalink|phaser))?|konica\s*minolta|kyocera(?:\s*(ecosys|taskalfa))?|sharp\s*(mx|al)|oki|toshiba|dell\s*(laser|laserjet)?|samsung\s*(xpress|ml|sl-)?|mfp|multi[-\s]?function|multifunction|printer|copier|print(?:er|ing))\b"}, "set": {"usage": "it_peripherals"}},

        # Access ports for conference room panels
        {"name": "access-conf-panels-crestron", "when": {"mode": "access", "description_regex": r"(?i)\b(crestron|(conference\s*room.*(panel|sched))|(room\s*(sched(ul(e|ing))?|panel)))\b"}, "set": {"usage": "it_peripherals"}},

        # Existing specific access VLANs
        {"name": "vlan-100-end_user", "when": {"mode": "access", "data_vlan": 100}, "set": {"usage": "end_user"}},
        {"name": "vlan-110-voice", "when": {"mode": "access", "data_vlan": 110}, "set": {"usage": "voice"}},
        {"name": "vlan-170-facility", "when": {"mode": "access", "data_vlan": 170}, "set": {"usage": "facility_mgmt"}},
        {"name": "vlan-160-it-periph", "when": {"mode": "access", "data_vlan": 160}, "set": {"usage": "it_peripherals"}},
        {"name": "vlan-3-end_user", "when": {"mode": "access", "data_vlan": 3}, "set": {"usage": "end_user"}},
        {"name": "legacy-doors-vlan-5-end_user", "when": {"mode": "access", "data_vlan": 5}, "set": {"usage": "end_user"}},
        {"name": "legacy-doors-access-10-voice-15-end_user", "when": {"mode": "access", "data_vlan": 10, "voice_vlan": 15}, "set": {"usage": "end_user"}},
        {"name": "legacy-doors-access-10-voice-110-end_user", "when": {"mode": "access", "data_vlan": 10, "voice_vlan": 110}, "set": {"usage": "end_user"}},

        # AP trunks by description (lower priority than explicit VLAN rules)
        {"name": "ap-trunk", "when": {"mode": "trunk", "description_regex": r"(?i)\b(ap|access\s*point)\b"}, "set": {"usage": "ap"}},

        # Generic trunk default: IDF uplink
        {"name": "uplink-idf", "when": {"mode": "trunk"}, "set": {"usage": "uplink_idf", "no_local_overwrite": True}},

        # Catch-all
        {"name": "catch-all-blackhole", "when": {"any": True}, "set": {"usage": "blackhole"}},
    ]
}

# ==============================
# Description blacklist (drop if any match)
# ==============================
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

# ==============================
# Helpers
# ==============================
def load_token() -> str:
    tok = (API_TOKEN or "").strip() or (os.getenv("MIST_TOKEN") or "").strip()
    if not tok:
        raise SystemExit("Missing API token: set env var MIST_TOKEN (preferred) or edit API_TOKEN in the script.")
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
    """
    Accepts list[int] | list[str] | str("110,120,130") and returns a list[int].
    Basic parser; doesn't expand ranges like '120-125'.
    """
    if v is None:
        return []
    if isinstance(v, list):
        out = []
        for x in v:
            try:
                out.append(int(x))
            except Exception:
                pass
        return out
    if isinstance(v, str):
        parts = [p.strip() for p in v.split(",") if p.strip()]
        out = []
        for p in parts:
            try:
                out.append(int(p))
            except Exception:
                pass
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
    name = intf.get("name") or ""
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

# ==============================
# Cisco -> index mapping (Gi1/0/1 -> 1, Gi2/0/1 -> 49, ...)
# ==============================
CISCO_IF_RE = re.compile(
    r"(?ix)^(?:ten|gig|fast)\s*gab?it(?:ethernet)?\s*(\d+)\s*/\s*(\d+)\s*/\s*(\d+)$|^(?:te|gi|fa)\s*(\d+)\s*/\s*(\d+)\s*/\s*(\d+)$"
)

def cisco_to_index(name: str) -> Optional[int]:
    """
    Returns 1-based canonical index: Gi1/0/1->1, Gi1/0/5->5, Gi2/0/1->49, etc.
    """
    n = (name or "").replace("Ethernet", "ethernet").strip()
    m = CISCO_IF_RE.match(n)
    if not m:
        return None
    g = [x for x in m.groups() if x]
    if len(g) != 3:
        return None
    sw, _, port = map(int, g)
    return (sw - 1) * 48 + port

def index_to_ex4100_if(model: Optional[str], index_1based: int) -> Optional[str]:
    """
    Map canonical index to EX4100 front-panel names:
      EX4100-48MP: p=0..15 -> mge-0/0/p, p=16..47 -> ge-0/0/p
      EX4100-24MP: p=0..7  -> mge-0/0/p, p=8..23  -> ge-0/0/p
    We default to member=0, pic=0. Offset is applied later in remap step.
    """
    if index_1based is None or index_1based <= 0:
        return None
    p = index_1based - 1  # zero-based front-panel port

    if model and model.startswith("EX4100-48MP"):
        return f"mge-0/0/{p}" if 0 <= p <= 15 else f"ge-0/0/{p}"
    if model and model.startswith("EX4100-24MP"):
        return f"mge-0/0/{p}" if 0 <= p <= 7 else f"ge-0/0/{p}"

    # Fallback if model is unknown: default to ge (still index-based)
    return f"ge-0/0/{p}"

# ==============================
# Mist interface regex + **MEMBER** remap
# ==============================
# Juniper ELS style: <type>-<member>/<pic>/<port>, e.g., ge-0/0/5
MIST_IF_RE = re.compile(r'^(?P<type>ge|mge)-(?P<member>\d+)/(?P<pic>\d+)/(?P<port>\d+)$')

def _collect_members(port_config: Dict[str, Any]) -> List[int]:
    members: List[int] = []
    for ifname in port_config.keys():
        m = MIST_IF_RE.match(ifname)
        if m:
            members.append(int(m.group("member")))
    return members

def remap_members(port_config: Dict[str, Any], member_offset: int = 0, normalize: bool = False) -> Dict[str, Any]:
    """
    Shift the **member** (first component) in ge-<member>/<pic>/<port>.
    If normalize=True, rebase the minimum source member to 0, then add member_offset.
    """
    if member_offset == 0 and not normalize:
        return port_config

    base = 0
    if normalize:
        mems = _collect_members(port_config)
        base = min(mems) if mems else 0

    new_pc: Dict[str, Any] = {}
    for ifname, cfg in port_config.items():
        m = MIST_IF_RE.match(ifname)
        if not m:
            new_pc[ifname] = cfg
            continue

        itype  = m.group("type")
        member = int(m.group("member"))
        pic    = int(m.group("pic"))
        port   = int(m.group("port"))

        new_member = (member - base) + int(member_offset or 0)
        new_name = f"{itype}-{new_member}/{pic}/{port}"

        if new_name in new_pc:
            raise SystemExit(f"Member remap collision on {new_name}")
        new_pc[new_name] = cfg
    return new_pc

# Back-compat: if older code calls "remap_modules", route it to member remap
def remap_modules(port_config: Dict[str, Any], member_offset: int = 0, normalize: bool = False) -> Dict[str, Any]:
    return remap_members(port_config, member_offset=member_offset, normalize=normalize)

# ==============================
# Mapping / normalization
# ==============================
def map_interfaces_to_port_config(intfs: List[Dict[str, Any]], model: Optional[str]) -> Dict[str, Dict[str, Any]]:
    rules = RULES_DOC.get("rules", []) or []
    defaults = RULES_DOC.get("defaults", {}) or {}

    port_config: Dict[str, Dict[str, Any]] = {}
    for intf in intfs:
        if intf.get("mode") == "routed":
            continue

        # Compute front-panel name by index (prefer), default member/pic is 0/0 here
        idx = cisco_to_index(intf.get("name", ""))
        derived_if = index_to_ex4100_if(model, idx) if idx is not None else None

        # If converter already added a juniper name, we can use it as a fallback
        mist_if = derived_if or intf.get("juniper_if") or intf.get("name", "")

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

        cfg: Dict[str, Any] = {
            "usage": usage or "blackhole",
            "description": filtered_desc,
            "no_local_overwrite": no_overwrite
        }
        if critical:
            cfg["critical"] = True

        port_config[mist_if] = cfg

    return port_config

# Flexible extractor used by app/backends
def extract_port_config(input_json: Dict[str, Any], model: Optional[str] = None) -> Dict[str, Dict[str, Any]]:
    if "port_config" in input_json and isinstance(input_json["port_config"], dict):
        return input_json["port_config"]
    if "interfaces" in input_json and isinstance(input_json["interfaces"], list):
        return map_interfaces_to_port_config(input_json["interfaces"], model)
    raise SystemExit("Input JSON must contain either 'interfaces' or 'port_config'.")

# Back-compat shim for different import signatures in app.py
def ensure_port_config(*args) -> Dict[str, Dict[str, Any]]:
    """
    Accepts either:
      ensure_port_config(input_json)
      ensure_port_config(input_json, model)
    """
    if len(args) == 1:
        return extract_port_config(args[0], model=None)
    elif len(args) >= 2:
        return extract_port_config(args[0], model=args[1])
    else:
        raise SystemExit("ensure_port_config requires 1 or 2 arguments.")

# ==============================
# Model lookup
# ==============================
def get_device_model(base_url: str, site_id: str, device_id: str, token: str) -> Optional[str]:
    url = f"{base_url.rstrip('/')}/sites/{site_id}/devices/{device_id}"
    try:
        resp = requests.get(url, headers={"Authorization": f"Token {token}"}, timeout=20)
        if 200 <= resp.status_code < 300:
            return resp.json().get("model")
    except Exception:
        pass
    return None

# ==============================
# Main
# ==============================
def main():
    ap = argparse.ArgumentParser(description="Map and push Mist switch port_config with EX4100 GE/MGE normalization and MEMBER offset.")
    ap.add_argument("--site-id", required=True, help="Mist site_id")
    ap.add_argument("--device-id", required=True, help="Mist device_id")
    ap.add_argument("--input", required=True, help="Path to JSON (converter output OR mapped payload)")
    ap.add_argument("--base-url", default=None, help="Override base URL (default: https://api.mist.com/api/v1)")
    ap.add_argument("--tz", default=None, help="Timezone for timestamp tag (default: America/New_York)")
    ap.add_argument("--dry-run", action="store_true", help="Print request payload instead of sending PUT")
    ap.add_argument("--save-output", default=None, help="Optional path to save the final PUT body JSON")
    ap.add_argument("--model", default=None, help="Device model override (skip API lookup)")
    ap.add_argument("--exclude-interface", action="append", default=None, help="Interface name to exclude after remap (repeatable). Example: --exclude-interface ge-1/0/47")
    # Offset flags (apply to JUNIPER MEMBER)
    ap.add_argument("--member-offset", type=int, default=0, help="Shift the Juniper MEMBER (first number) in ge-<member>/<pic>/<port> by this offset.")
    ap.add_argument("--normalize-modules", action="store_true", help="Normalize the lowest source MEMBER to 0 before applying --member-offset.")

    args = ap.parse_args()

    token = load_token()
    base_url = (args.base_url or BASE_URL).rstrip("/")
    tz_name = (args.tz or TZ)

    # Lookup/override model (used when mapping 'interfaces' -> 'port_config')
    model = args.model or get_device_model(base_url, args.site_id, args.device_id, token)

    with open(args.input, "r", encoding="utf-8") as f:
        inp = json.load(f)

    # Build/obtain port_config
    port_config = extract_port_config(inp, model=model)

    # Apply MEMBER remap BEFORE excludes
    try:
        port_config = remap_members(port_config, member_offset=int(args.member_offset or 0), normalize=bool(args.normalize_modules))
    except SystemExit:
        raise
    except Exception as e:
        raise SystemExit(f"Failed to apply member offset: {e}")

    # Apply exclude(s) (EXACT names after remap)
    excludes = set(args.exclude_interface or [])
    if excludes:
        port_config = {k: v for k, v in port_config.items() if k not in excludes}

    # Add timestamped description tags
    ts = timestamp_str(tz_name)
    final_port_config: Dict[str, Dict[str, Any]] = {}
    for ifname, cfg in port_config.items():
        cfg = dict(cfg)
        cfg["description"] = tag_description(cfg.get("description", ""), ts)
        final_port_config[ifname] = cfg

    body = {"port_config": final_port_config}

    # Persist body if requested
    if args.save_output:
        try:
            with open(args.save_output, "w", encoding="utf-8") as o:
                json.dump(body, o, indent=2)
        except Exception as e:
            print(f"Warning: failed to save output to {args.save_output}: {e}")

    url = f"{base_url}/sites/{args.site_id}/devices/{args.device_id}"
    headers = {"Authorization": f"Token {token}", "Content-Type": "application/json", "Accept": "application/json"}

    if args.dry_run:
        print(f"Device model: {model or 'unknown'}")
        print(f"Member offset: {args.member_offset} (normalize: {bool(args.normalize_modules)})")
        print(f"PUT {url}")
        print(json.dumps(body, indent=2))
        return

    # Live PUT
    resp = requests.put(url, headers=headers, data=json.dumps(body), timeout=60)
    if 200 <= resp.status_code < 300:
        print("✅ Success")
        try:
            print(json.dumps(resp.json(), indent=2))
        except Exception:
            print(resp.text)
    else:
        print(f"❌ Error {resp.status_code} on PUT {url}")
        try:
            print(json.dumps(resp.json(), indent=2))
        except Exception:
            print(resp.text)
        if resp.status_code == 404:
            print("Hint: 404 usually means the device isn't in that site, the device_id/site_id is mistyped, or the base URL/region is wrong. Verify the device appears under that exact site in Mist.")
        resp.raise_for_status()

if __name__ == "__main__":
    main()
