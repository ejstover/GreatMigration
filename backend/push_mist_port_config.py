#!/usr/bin/env python3
"""
push_mist_port_config.py

Build/normalize a Mist switch port_config and (optionally) push it.

Key features:
- Cisco -> Juniper interface mapping:
    * 3-part names (Gi<SW>/<MOD>/<PORT>): trust module
        - MOD 0 => PIC 0 (front panel), PORT 1..48 -> /0/<PORT-1>
        - MOD 1 => PIC 2 (uplinks),     PORT 1..4  -> /2/<PORT-1>   (uplink type xe on EX4100)
        - member = SW - 1
    * 2-part names (Gi<SW>/<PORT>): fallback
        - 1..48 => PIC 0; 49..52 => PIC 2 (uplinks)
        - member = SW - 1
- Per-row member offset remap (shifts <member>), optional normalization
- Rules engine (first match wins) with your one-liner rules
- Capacity validator by model (blocks live push, warns in dry-run)
"""

from __future__ import annotations

import argparse
import json
import os
import re
import time
from pathlib import Path
from datetime import datetime
from typing import Any, Dict, Iterable, List, Optional, Tuple

import requests

try:
    from zoneinfo import ZoneInfo  # py3.9+
except Exception:  # pragma: no cover
    ZoneInfo = None  # type: ignore

# -------------------------------
# Defaults
# -------------------------------
API_TOKEN = ""  # prefer env var MIST_TOKEN
BASE_URL  = "https://api.mist.com/api/v1"
TZ        = "America/New_York"

# -------------------------------
# Rules (first match wins) — kept compact & readable
# -------------------------------
RULES_PATH = Path(__file__).with_name("port_rules.json")


def load_rules(path: Path = RULES_PATH) -> Dict[str, Any]:
    """Load rule document from JSON file."""
    try:
        with path.open("r", encoding="utf-8") as fh:
            return json.load(fh)
    except Exception:
        return {"rules": []}


RULES_DOC: Dict[str, Any] = load_rules()

def validate_rules_doc(doc: Dict[str, Any]) -> None:
    """Validate structure and field types for a rules document.

    Raises ValueError with a descriptive message on problems.
    """
    if not isinstance(doc, dict):
        raise ValueError("Rules document must be a JSON object")
    rules = doc.get("rules")
    if not isinstance(rules, list):
        raise ValueError("Rules document missing 'rules' list")

    allowed_when = {"mode", "data_vlan", "voice_vlan", "native_vlan", "description_regex"}
    allowed_set = {"usage"}

    for idx, rule in enumerate(rules, 1):
        if not isinstance(rule, dict):
            raise ValueError(f"Rule {idx} is not an object")
        when = rule.get("when", {})
        if not isinstance(when, dict):
            raise ValueError(f"Rule {idx} 'when' must be an object")
        for k, v in when.items():
            if k not in allowed_when:
                raise ValueError(f"Rule {idx} uses unknown condition '{k}'")
            if k.endswith("_vlan"):
                try:
                    int(v)
                except Exception:
                    raise ValueError(f"Rule {idx} condition '{k}' must be an integer")
            if k == "description_regex":
                try:
                    re.compile(str(v))
                except re.error as e:
                    raise ValueError(f"Rule {idx} has invalid regex: {e}")
        setp = rule.get("set", {})
        if not isinstance(setp, dict):
            raise ValueError(f"Rule {idx} 'set' must be an object")
        for k in setp:
            if k not in allowed_set:
                raise ValueError(f"Rule {idx} has unknown action '{k}'")

BLACKLIST_PATTERNS = [
    r"^\s*$", r"^\s*vla?n?\s*\d+\s*$", r"^\s*(data|voice)\s*(port)?\s*$",
    r"^\s*end\s*user\s*$", r"^\s*user\s*$", r".*\bdata\s*vla?n?\b.*",
    r".*\bvoice\s*vla?n?\b.*", r".*\b(auto\s*qos|portfast|service-?policy)\b.*",
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

def load_token() -> str:
    tok = (API_TOKEN or "").strip() or (os.getenv("MIST_TOKEN") or "").strip()
    if not tok:
        raise SystemExit("Missing API token: set env var MIST_TOKEN (preferred) or edit API_TOKEN.")
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
    allowed_vlans_set  = set(_normalize_vlan_list(intf.get("allowed_vlans")))
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
            if allowed_vlans_set != set(int(x) for x in (v or [])): return False
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

def cisco_to_index(name: str) -> Optional[int]:
    # legacy fallback; unused in normal paths now
    return None

def index_to_ex4100_if(model: Optional[str], index_1based: int) -> Optional[str]:
    if index_1based is None or index_1based <= 0:
        return None
    p = index_1based - 1
    if model and model.startswith("EX4100-48MP"):
        return f"mge-0/0/{p}" if 0 <= p <= 15 else f"ge-0/0/{p}"
    if model and model.startswith("EX4100-24MP"):
        return f"mge-0/0/{p}" if 0 <= p <= 7 else f"ge-0/0/{p}"
    return f"ge-0/0/{p}"

def cisco_to_ex_if_enhanced(model: Optional[str], name: str) -> Optional[str]:
    """
    Cisco Gi<SW>/<MOD>/<PORT> -> <type>-<member>/<pic>/<port>
      * member = SW - 1
      * MOD 0 => PIC 0 (front), PORT 1..48 -> jport=PORT-1
      * MOD 1 => PIC 2 (uplinks), PORT 1..4 -> jport=PORT-1
    Fallback for 2-part names (Gi<SW>/<PORT>): 49..52 -> PIC 2; else PIC 0.
    """
    p = cisco_split(name)
    if not p:
        return None
    sw, mod, port = p["sw"], p["mod"], p["port"]
    member = max(sw - 1, 0)

    if mod == 1:
        pic, jport = 2, port - 1
        itype = "xe" if (model or "").startswith("EX4100") else "ge"
        return f"{itype}-{member}/{pic}/{jport}"

    if mod == 0:
        pic, jport = 0, port - 1
        if model and model.startswith("EX4100-48MP"):
            itype = "mge" if 0 <= jport <= 15 else "ge"
        elif model and model.startswith("EX4100-24MP"):
            itype = "mge" if 0 <= jport <= 7 else "ge"
        else:
            itype = "ge"
        return f"{itype}-{member}/{pic}/{jport}"

    # Fallback when MOD missing (2-part names)
    if 49 <= port <= 52:
        pic, jport = 2, port - 49
        itype = "xe" if (model or "").startswith("EX4100") else "ge"
        return f"{itype}-{member}/{pic}/{jport}"

    pic, jport = 0, port - 1
    if model and model.startswith("EX4100-48MP"):
        itype = "mge" if 0 <= jport <= 15 else "ge"
    elif model and model.startswith("EX4100-24MP"):
        itype = "mge" if 0 <= jport <= 7 else "ge"
    else:
        itype = "ge"
    return f"{itype}-{member}/{pic}/{jport}"

# Accept ge/mge/xe/et; used by remap & capacity checks
MIST_IF_RE = re.compile(r'^(?P<type>ge|mge|xe|et)-(?P<member>\d+)/(?P<pic>\d+)/(?P<port>\d+)$')

def _collect_members(port_config: Dict[str, Any]) -> List[int]:
    mems: List[int] = []
    for ifname in port_config.keys():
        m = MIST_IF_RE.match(ifname)
        if m:
            mems.append(int(m.group("member")))
    return mems

def remap_members(port_config: Dict[str, Any], member_offset: int = 0, normalize: bool = False) -> Dict[str, Any]:
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

def remap_ports(
    port_config: Dict[str, Any],
    port_offset: int = 0,
    model: Optional[str] = None,
) -> Dict[str, Any]:
    """Shift the ``<port>`` component in interface names by ``port_offset`` and
    adjust ``ge``/``mge`` prefixes when the shifted port crosses the model's
    speed boundary.

    Example: ``mge-0/0/0`` with ``port_offset=24`` on an EX4100-48MP becomes
    ``ge-0/0/24``.  Collisions raise ``SystemExit`` to match
    :func:`remap_members` behaviour.
    """
    if int(port_offset or 0) == 0:
        return port_config

    # Determine mge/ge cutoff based on model (default 16 like EX4100-48MP)
    cutoff = 16
    if model:
        m = model.strip().lower()
        if m.startswith("ex4100-24"):
            cutoff = 8
        elif m.startswith("ex4100-48"):
            cutoff = 16

    out: Dict[str, Any] = {}
    for ifname, cfg in port_config.items():
        m = MIST_IF_RE.match(ifname)
        if not m:
            out[ifname] = cfg
            continue
        itype = m.group("type")
        member = int(m.group("member"))
        pic = int(m.group("pic"))
        port = int(m.group("port"))
        new_port = port + int(port_offset or 0)

        new_type = itype
        if itype in {"ge", "mge"}:
            new_type = "mge" if new_port < cutoff else "ge"

        new_name = f"{new_type}-{member}/{pic}/{new_port}"
        if new_name in out:
            raise SystemExit(f"Port remap collision on {new_name}")
        out[new_name] = cfg
    return out

def remap_modules(port_config: Dict[str, Any], member_offset: int = 0, normalize: bool = False) -> Dict[str, Any]:
    return remap_members(port_config, member_offset=member_offset, normalize=normalize)

def map_interfaces_to_port_config(intfs: List[Dict[str, Any]], model: Optional[str]) -> Dict[str, Dict[str, Any]]:
    rules = RULES_DOC.get("rules", []) or []

    port_config: Dict[str, Dict[str, Any]] = {}
    for intf in intfs:
        if (intf.get("mode") or "").lower() == "routed":
            continue

        derived_if = cisco_to_ex_if_enhanced(model, intf.get("name", ""))
        if not derived_if:
            idx = None
            derived_if = index_to_ex4100_if(model, idx) if idx is not None else None

        mist_if = derived_if or intf.get("juniper_if") or intf.get("name", "")

        chosen = None
        for r in rules:
            if evaluate_rule(r.get("when", {}) or {}, intf):
                chosen = r
                break

        usage = None
        if chosen:
            s = chosen.get("set", {}) or {}
            usage = s.get("usage", usage)

        raw_desc = intf.get("description", "") or ""
        filtered_desc = filter_description_blacklist(raw_desc)

        cfg: Dict[str, Any] = {"usage": usage or "blackhole", "description": filtered_desc}

        if mist_if in port_config:
            raise SystemExit(f"Key collision for {mist_if} (from {intf.get('name')}); check Cisco mapping.")
        port_config[mist_if] = cfg

    return port_config

def extract_port_config(input_json: Dict[str, Any], model: Optional[str] = None) -> Dict[str, Dict[str, Any]]:
    if "interfaces" in input_json and isinstance(input_json["interfaces"], list):
        return map_interfaces_to_port_config(input_json["interfaces"], model)
    if "port_config" in input_json and isinstance(input_json["port_config"], dict):
        return input_json["port_config"]
    raise SystemExit("Input JSON must contain either 'interfaces' or 'port_config'.")

def ensure_port_config(*args) -> Dict[str, Dict[str, Any]]:
    if len(args) == 1:
        return extract_port_config(args[0], model=None)
    elif len(args) >= 2:
        return extract_port_config(args[0], model=args[1])
    else:
        raise SystemExit("ensure_port_config requires 1 or 2 arguments.")

# -------------------------------
# Model capacity map & validator
# -------------------------------
MODEL_CAPS = {
    "EX4100-24":   {"access_pic0": 24, "uplink_pic2": 4},
    "EX4100-24MP": {"access_pic0": 24, "uplink_pic2": 4},
    "EX4100-48":   {"access_pic0": 48, "uplink_pic2": 4},
    "EX4100-48MP": {"access_pic0": 48, "uplink_pic2": 4},
    # extend here as needed
}

def _model_key(model: Optional[str]) -> Optional[str]:
    if not model:
        return None
    m = model.strip().upper()
    for k in MODEL_CAPS.keys():
        if m.startswith(k.upper()):
            return k
    return m

def validate_port_config_against_model(port_config: Dict[str, Any], model: Optional[str]) -> Dict[str, Any]:
    errors: List[str] = []
    warnings: List[str] = []

    mk = _model_key(model)
    caps = MODEL_CAPS.get(mk) if mk else None
    if not caps:
        warnings.append(f"Unknown/unsupported model '{model}'. Capacity checks skipped.")
        return {"ok": True, "errors": [], "warnings": warnings, "counts": {}, "limits": {}}

    access_cap = caps["access_pic0"]
    uplink_cap = caps.get("uplink_pic2", 0)

    bad_access: List[str] = []
    bad_uplink: List[str] = []
    seen_pic0: set[int] = set()
    seen_pic2: set[int] = set()

    for ifname in port_config.keys():
        m = MIST_IF_RE.match(ifname)
        if not m:
            continue
        pic = int(m.group("pic"))
        port = int(m.group("port"))
        if pic == 0:
            seen_pic0.add(port)
            if port >= access_cap:
                bad_access.append(ifname)
        elif pic == 2:
            seen_pic2.add(port)
            if port >= uplink_cap:
                bad_uplink.append(ifname)

    counts = {"pic0_ports": len(seen_pic0), "pic2_ports": len(seen_pic2)}
    limits = {"pic0_max": access_cap, "pic2_max": uplink_cap}

    if bad_access:
        errors.append(f"{len(bad_access)} interface(s) exceed access capacity for {model} (PIC 0 supports 0..{access_cap-1}): {', '.join(sorted(bad_access)[:6])}{' …' if len(bad_access)>6 else ''}")
    if bad_uplink:
        errors.append(f"{len(bad_uplink)} interface(s) exceed uplink capacity for {model} (PIC 2 supports 0..{uplink_cap-1}): {', '.join(sorted(bad_uplink)[:6])}{' …' if len(bad_uplink)>6 else ''}")

    ok = not errors
    return {"ok": ok, "errors": errors, "warnings": warnings, "counts": counts, "limits": limits}

# -------------------------------
# Device model lookup
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
# Mist site helpers for staged pushes
# -------------------------------

class MistSiteClient:
    """Small helper around the Mist site APIs used for staged pushes."""

    def __init__(self, base_url: str, site_id: str, token: str, timeout: int = 30):
        self.base_url = base_url.rstrip("/")
        self.site_id = site_id
        self.session = requests.Session()
        self.session.headers.update(
            {
                "Authorization": f"Token {token}",
                "Accept": "application/json",
                "Content-Type": "application/json",
            }
        )
        self.timeout = timeout

    # ---- generic helpers ----

    def _url(self, path: str) -> str:
        return f"{self.base_url}{path}"

    def request(self, method: str, path: str, **kwargs) -> requests.Response:
        timeout = kwargs.pop("timeout", self.timeout)
        resp = self.session.request(method, self._url(path), timeout=timeout, **kwargs)
        if resp.status_code >= 400:
            try:
                payload: Any = resp.json()
            except Exception:
                payload = resp.text
            msg = f"{method.upper()} {path} failed with status {resp.status_code}: {payload}"
            raise requests.HTTPError(msg, response=resp)
        return resp

    # ---- VLAN helpers ----

    def list_vlans(self) -> List[Dict[str, Any]]:
        resp = self.request("GET", f"/sites/{self.site_id}/vlans")
        data = resp.json() or []
        return data if isinstance(data, list) else []

    def ensure_vlan(
        self,
        vlan_payload: Dict[str, Any],
        dry_run: bool = False,
        existing_vlans: Optional[List[Dict[str, Any]]] = None,
    ) -> Optional[str]:
        vlan_id = vlan_payload.get("vlan_id") or vlan_payload.get("id")
        name = vlan_payload.get("name")
        existing_id: Optional[str] = None
        for vlan in (existing_vlans if existing_vlans is not None else self.list_vlans()):
            if vlan_id and vlan.get("vlan_id") == vlan_id:
                existing_id = vlan.get("id")
                break
            if name and (vlan.get("name") or "").strip().lower() == str(name).strip().lower():
                existing_id = vlan.get("id")
                break

        if existing_id:
            payload = dict(vlan_payload)
            payload.pop("id", None)
            if dry_run:
                print(f"DRY-RUN: would update VLAN {existing_id} with {payload}")
            else:
                self.request("PUT", f"/sites/{self.site_id}/vlans/{existing_id}", json=payload)
            return existing_id

        if dry_run:
            print(f"DRY-RUN: would create VLAN {vlan_payload}")
            return None

        resp = self.request("POST", f"/sites/{self.site_id}/vlans", json=vlan_payload)
        created = resp.json() or {}
        return created.get("id")

    def delete_vlan(self, vlan_id: str, dry_run: bool = False) -> None:
        if dry_run:
            print(f"DRY-RUN: would delete VLAN {vlan_id}")
            return
        self.request("DELETE", f"/sites/{self.site_id}/vlans/{vlan_id}")

    # ---- Port profile helpers ----

    def list_port_profiles(self) -> List[Dict[str, Any]]:
        resp = self.request("GET", f"/sites/{self.site_id}/portprofiles")
        data = resp.json() or []
        return data if isinstance(data, list) else []

    def ensure_port_profile(
        self,
        profile_payload: Dict[str, Any],
        dry_run: bool = False,
        existing_profiles: Optional[List[Dict[str, Any]]] = None,
    ) -> Optional[str]:
        name = (profile_payload.get("name") or "").strip()
        existing_id: Optional[str] = None
        profiles = existing_profiles if existing_profiles is not None else self.list_port_profiles()
        for profile in profiles:
            if profile.get("name", "").strip().lower() == name.lower() and name:
                existing_id = profile.get("id")
                break

        payload = dict(profile_payload)
        payload.pop("id", None)

        if existing_id:
            if dry_run:
                print(f"DRY-RUN: would update port profile {existing_id} with {payload}")
            else:
                self.request("PUT", f"/sites/{self.site_id}/portprofiles/{existing_id}", json=payload)
            return existing_id

        if dry_run:
            print(f"DRY-RUN: would create port profile {payload}")
            return None

        resp = self.request("POST", f"/sites/{self.site_id}/portprofiles", json=payload)
        created = resp.json() or {}
        return created.get("id")

    def delete_port_profile(self, profile_id: str, dry_run: bool = False) -> None:
        if dry_run:
            print(f"DRY-RUN: would delete port profile {profile_id}")
            return
        self.request("DELETE", f"/sites/{self.site_id}/portprofiles/{profile_id}")

    # ---- Device helpers ----

    def get_device(self, device_id: str) -> Dict[str, Any]:
        resp = self.request("GET", f"/sites/{self.site_id}/devices/{device_id}")
        data = resp.json() or {}
        return data if isinstance(data, dict) else {}

    def update_device(self, device_id: str, payload: Dict[str, Any], dry_run: bool = False) -> None:
        if dry_run:
            print(f"DRY-RUN: would update device {device_id} with {payload}")
            return
        self.request("PATCH", f"/sites/{self.site_id}/devices/{device_id}", json=payload)

    def push_port_config(self, device_id: str, port_config: Dict[str, Any], dry_run: bool = False) -> Dict[str, Any]:
        payload = {"port_config": port_config}
        if dry_run:
            print(f"DRY-RUN: would push port_config to {device_id}: {json.dumps(payload, indent=2)}")
            return {}
        resp = self.request("PUT", f"/sites/{self.site_id}/devices/{device_id}", json=payload, timeout=60)
        try:
            return resp.json() or {}
        except Exception:
            return {"status_code": resp.status_code}


def _load_json_file(path: Optional[str]) -> Dict[str, Any]:
    if not path:
        raise ValueError("Path to JSON document was not provided.")
    document_path = Path(path)
    with document_path.open("r", encoding="utf-8") as handle:
        data = json.load(handle)
    if not isinstance(data, dict):
        raise ValueError(f"JSON document at {path} must be an object at the top level.")
    return data


def _iter_switch_entries(doc: Dict[str, Any]) -> Iterable[Dict[str, Any]]:
    switches = doc.get("switches")
    if isinstance(switches, list):
        for entry in switches:
            if isinstance(entry, dict):
                yield entry


def _extract_port_config(entry: Dict[str, Any], keys: Iterable[str]) -> Optional[Dict[str, Any]]:
    for key in keys:
        cfg = entry.get(key)
        if isinstance(cfg, dict):
            return cfg
    return None


def _extract_vlan_id(entry: Dict[str, Any], keys: Iterable[str]) -> Optional[int]:
    for key in keys:
        if key in entry and entry[key] is not None:
            try:
                return int(entry[key])
            except Exception:
                continue
    return None


def _port_config_uses_profile(port_config: Dict[str, Any], profile_name: str, profile_id: Optional[str] = None) -> bool:
    prof_name = profile_name.strip().lower()
    for cfg in port_config.values():
        if not isinstance(cfg, dict):
            continue
        usage = cfg.get("usage")
        if isinstance(usage, str) and usage.strip().lower() == prof_name:
            return True
        if profile_id and cfg.get("port_profile_id") == profile_id:
            return True
    return False


def _port_config_uses_vlan(port_config: Dict[str, Any], vlan_id: int) -> bool:
    for cfg in port_config.values():
        if not isinstance(cfg, dict):
            continue
        for key in ("vlan_id", "data_vlan", "voice_vlan", "native_vlan"):
            if cfg.get(key) == vlan_id:
                return True
        allowed = cfg.get("allowed_vlans")
        if isinstance(allowed, list) and vlan_id in allowed:
            return True
    return False


def ensure_temp_resources(client: MistSiteClient, plan_doc: Dict[str, Any], dry_run: bool = False) -> Tuple[Dict[str, str], Dict[str, str]]:
    """Ensure temporary VLANs and port profiles exist.

    Returns tuples mapping (vlan_name -> id, profile_name -> id).
    """

    vlan_map: Dict[str, str] = {}
    existing_vlans = client.list_vlans()
    for vlan in plan_doc.get("vlans", []) or []:
        if not isinstance(vlan, dict):
            continue
        name = str(vlan.get("name") or vlan.get("id") or vlan.get("vlan_id") or "temp-vlan")
        created_id = client.ensure_vlan(vlan, dry_run=dry_run, existing_vlans=existing_vlans)
        if created_id:
            vlan_map[name] = created_id

    profile_map: Dict[str, str] = {}
    existing_profiles = client.list_port_profiles()
    for profile in plan_doc.get("port_profiles", []) or []:
        if not isinstance(profile, dict):
            continue
        name = str(profile.get("name") or "").strip()
        created_id = client.ensure_port_profile(profile, dry_run=dry_run, existing_profiles=existing_profiles)
        if name and created_id:
            profile_map[name] = created_id

    return vlan_map, profile_map


def apply_temp_assignments(client: MistSiteClient, plan_doc: Dict[str, Any], dry_run: bool = False) -> None:
    ensure_temp_resources(client, plan_doc, dry_run=dry_run)

    for entry in _iter_switch_entries(plan_doc):
        device_id = entry.get("device_id") or entry.get("id")
        if not device_id:
            continue
        port_config = _extract_port_config(entry, ("temp_port_config", "port_config"))
        if not port_config:
            continue
        client.push_port_config(device_id, port_config, dry_run=dry_run)


def _wait_for_heartbeat(
    client: MistSiteClient,
    device_id: str,
    previous_last_seen: Optional[int],
    target_vlan: int,
    timeout: int = 300,
    interval: int = 15,
) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        time.sleep(interval)
        device = client.get_device(device_id)
        last_seen = device.get("last_seen")
        mgmt_vlan = device.get("mgmt_vlan_id")
        if mgmt_vlan != target_vlan:
            continue
        if last_seen is None:
            continue
        if previous_last_seen is None or last_seen > previous_last_seen:
            return True
    return False


def flip_management_vlan(
    client: MistSiteClient,
    device_id: str,
    new_vlan_id: int,
    dry_run: bool = False,
    heartbeat_timeout: int = 300,
    heartbeat_interval: int = 15,
) -> None:
    device = client.get_device(device_id)
    current_vlan = device.get("mgmt_vlan_id")
    if current_vlan == new_vlan_id:
        return

    last_seen = device.get("last_seen")
    payload = {"mgmt_vlan_id": new_vlan_id}
    client.update_device(device_id, payload, dry_run=dry_run)

    if dry_run:
        return

    success = _wait_for_heartbeat(
        client,
        device_id,
        previous_last_seen=last_seen,
        target_vlan=new_vlan_id,
        timeout=heartbeat_timeout,
        interval=heartbeat_interval,
    )

    if success:
        return

    # Roll back on failure
    rollback_payload = {"mgmt_vlan_id": current_vlan}
    client.update_device(device_id, rollback_payload, dry_run=False)
    raise RuntimeError(
        f"Device {device_id} did not report a heartbeat after moving to management VLAN {new_vlan_id}; rolled back to {current_vlan}."
    )


def apply_final_assignments(
    client: MistSiteClient,
    final_doc: Dict[str, Any],
    dry_run: bool = False,
    heartbeat_timeout: int = 300,
    heartbeat_interval: int = 15,
) -> None:
    for entry in _iter_switch_entries(final_doc):
        device_id = entry.get("device_id") or entry.get("id")
        if not device_id:
            continue
        target_vlan = _extract_vlan_id(
            entry,
            (
                "final_mgmt_vlan_id",
                "management_vlan_id",
                "mgmt_vlan_id",
                "final_management_vlan",
            ),
        )
        if target_vlan is not None:
            flip_management_vlan(
                client,
                device_id,
                target_vlan,
                dry_run=dry_run,
                heartbeat_timeout=heartbeat_timeout,
                heartbeat_interval=heartbeat_interval,
            )

        port_config = _extract_port_config(entry, ("final_port_config", "port_config"))
        if port_config:
            client.push_port_config(device_id, port_config, dry_run=dry_run)


def cleanup_temp_resources(
    client: MistSiteClient,
    plan_doc: Dict[str, Any],
    final_doc: Optional[Dict[str, Any]] = None,
    dry_run: bool = False,
) -> None:
    final_port_configs: List[Dict[str, Any]] = []
    if final_doc:
        for entry in _iter_switch_entries(final_doc):
            cfg = _extract_port_config(entry, ("final_port_config", "port_config"))
            if cfg:
                final_port_configs.append(cfg)

    # Port profiles
    existing_profiles = {p.get("name"): p for p in client.list_port_profiles()}
    for profile in plan_doc.get("port_profiles", []) or []:
        if not isinstance(profile, dict):
            continue
        if not profile.get("temporary", True) and not profile.get("temp", False):
            continue
        name = (profile.get("name") or "").strip()
        if not name:
            continue
        current = existing_profiles.get(name)
        if not current:
            continue
        profile_id = current.get("id")
        still_referenced = False
        for cfg in final_port_configs:
            if _port_config_uses_profile(cfg, name, profile_id):
                still_referenced = True
                break
        if still_referenced:
            continue
        if profile_id:
            client.delete_port_profile(profile_id, dry_run=dry_run)

    # VLANs
    existing_vlans = {v.get("vlan_id"): v for v in client.list_vlans()}
    for vlan in plan_doc.get("vlans", []) or []:
        if not isinstance(vlan, dict):
            continue
        if not vlan.get("temporary", True) and not vlan.get("temp", False):
            continue
        vlan_id = vlan.get("vlan_id") or vlan.get("id")
        try:
            vlan_id_int = int(vlan_id)
        except Exception:
            vlan_id_int = None
        existing = None
        if vlan_id_int is not None and vlan_id_int in existing_vlans:
            existing = existing_vlans[vlan_id_int]
        if not existing:
            continue
        still_referenced_vlan = False
        for cfg in final_port_configs:
            if vlan_id_int is not None and _port_config_uses_vlan(cfg, vlan_id_int):
                still_referenced_vlan = True
                break
        if still_referenced_vlan:
            continue
        vlan_uuid = existing.get("id")
        if vlan_uuid:
            client.delete_vlan(vlan_uuid, dry_run=dry_run)

# -------------------------------
# CLI
# -------------------------------
def main():
    ap = argparse.ArgumentParser(description="Map and push Mist port_config with EX4100 uplink mapping and member/port offsets.")
    ap.add_argument("--site-id", required=True)
    ap.add_argument("--device-id", required=True)
    ap.add_argument("--input", help="Path to converter JSON ('interfaces') or Mist 'port_config'")
    ap.add_argument("--base-url", default=None)
    ap.add_argument("--tz", default=None)
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--save-output", default=None)
    ap.add_argument("--model", default=None, help="Override device model (skip API lookup)")
    ap.add_argument("--exclude-interface", action="append", default=None)
    ap.add_argument("--member-offset", type=int, default=0)
    ap.add_argument("--port-offset", type=int, default=0)
    ap.add_argument("--normalize-modules", action="store_true")
    ap.add_argument("--plan", default="plan.json", help="Path to staging plan JSON (default: plan.json)")
    ap.add_argument("--final", dest="final_plan", default="final.json", help="Path to final assignment JSON (default: final.json)")
    ap.add_argument("--heartbeat-timeout", type=int, default=300, help="Seconds to wait for heartbeat after mgmt VLAN change")
    ap.add_argument("--heartbeat-interval", type=int, default=15, help="Seconds between heartbeat checks")

    group = ap.add_mutually_exclusive_group()
    group.add_argument("--apply-temp", action="store_true", help="Ensure temporary resources exist and push temp assignments")
    group.add_argument("--finalize", action="store_true", help="Flip mgmt VLAN, push final assignments, and clean temp resources")
    group.add_argument("--cleanup-temp", action="store_true", help="Remove temporary VLANs and port profiles when safe")

    args = ap.parse_args()

    token = load_token()
    base_url = (args.base_url or BASE_URL).rstrip("/")
    tz_name = (args.tz or TZ)
    client = MistSiteClient(base_url, args.site_id, token)

    if args.apply_temp:
        plan_doc = _load_json_file(args.plan)
        apply_temp_assignments(client, plan_doc, dry_run=args.dry_run)
        return

    if args.finalize:
        plan_doc: Optional[Dict[str, Any]]
        try:
            plan_doc = _load_json_file(args.plan)
        except Exception:
            plan_doc = None
        final_doc = _load_json_file(args.final_plan)
        apply_final_assignments(
            client,
            final_doc,
            dry_run=args.dry_run,
            heartbeat_timeout=args.heartbeat_timeout,
            heartbeat_interval=args.heartbeat_interval,
        )
        if plan_doc:
            cleanup_temp_resources(client, plan_doc, final_doc=final_doc, dry_run=args.dry_run)
        return

    if args.cleanup_temp:
        plan_doc = _load_json_file(args.plan)
        try:
            final_doc = _load_json_file(args.final_plan)
        except Exception:
            final_doc = None
        cleanup_temp_resources(client, plan_doc, final_doc=final_doc, dry_run=args.dry_run)
        return

    if not args.input:
        ap.error("--input is required unless --apply-temp/--finalize/--cleanup-temp is provided")

    model = args.model or get_device_model(base_url, args.site_id, args.device_id, token)

    with open(args.input, "r", encoding="utf-8") as f:
        inp = json.load(f)

    # Build/obtain port_config
    port_config = extract_port_config(inp, model=model)

    # Apply member/port remap BEFORE excludes
    port_config = remap_members(port_config, member_offset=int(args.member_offset or 0), normalize=bool(args.normalize_modules))
    port_config = remap_ports(port_config, port_offset=int(args.port_offset or 0), model=model)

    # Apply excludes AFTER remap
    excludes = set(args.exclude_interface or [])
    if excludes:
        port_config = {k: v for k, v in port_config.items() if k not in excludes}

    # Capacity validation
    validation = validate_port_config_against_model(port_config, model)
    if not args.dry_run and not validation.get("ok"):
        print("❌ Capacity error:")
        print(json.dumps(validation, indent=2))
        raise SystemExit(2)

    # Timestamp descriptions
    ts = timestamp_str(tz_name)
    final_port_config: Dict[str, Dict[str, Any]] = {}
    for ifname, cfg in port_config.items():
        c = dict(cfg)
        c["description"] = tag_description(c.get("description", ""), ts)
        final_port_config[ifname] = c

    if args.dry_run:
        print(f"Device model: {model or 'unknown'}")
        print(f"Member offset: {args.member_offset} (normalize: {bool(args.normalize_modules)})")
        print(f"Port offset: {args.port_offset}")
        print("Validation:")
        print(json.dumps(validation, indent=2))
        print(json.dumps({"port_config": final_port_config}, indent=2))
        return

    result = client.push_port_config(args.device_id, final_port_config, dry_run=False)
    print("✅ Success")
    print(json.dumps(result, indent=2))

if __name__ == "__main__":
    main()
