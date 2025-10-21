"""Two-phase workflow for staging and finalizing Mist switch port configs.

This module automates the process of migrating an access switch from an
existing Cisco IOS configuration to a Juniper Mist switch.  The workflow is
split into two phases:

* **Stage** – Parse the Cisco configuration, create temporary VLANs on the
  target Mist site, and push `temp_` prefixed port overrides that mirror the
  legacy state.
* **Finalize** – Apply a VLAN mapping table to convert those temporary port
  overrides to the new standardized scheme and remove all temporary VLANs and
  overrides.

The implementation intentionally keeps all network side-effects behind small
helper methods so that they can be stubbed/mocked in tests or future
extensions.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

import requests
from ciscoconfparse import CiscoConfParse

from convertciscotojson import is_port_interface, parse_allowed_list, to_int
from push_mist_port_config import cisco_to_ex_if_enhanced, get_device_model

DEFAULT_BASE_URL = os.getenv("MIST_BASE_URL", "https://api.ac2.mist.com/api/v1")
TEMP_PREFIX = "temp_"


class MistApiError(RuntimeError):
    """Raised when the Mist API returns an unexpected response."""


@dataclass
class CiscoInterface:
    """Normalized representation of a Cisco access interface."""

    name: str
    mode: str
    access_vlan: Optional[int]
    voice_vlan: Optional[int]
    trunk_native: Optional[int]
    trunk_allowed: List[int]
    description: str

    def is_trunk(self) -> bool:
        return self.mode.lower() == "trunk"

    def is_access(self) -> bool:
        return self.mode.lower() != "trunk"


def _load_token(token: Optional[str]) -> str:
    tok = (token or os.getenv("MIST_TOKEN") or "").strip()
    if not tok:
        raise SystemExit("Mist API token missing. Provide --token or set MIST_TOKEN.")
    return tok


def _read_text_file(path: str) -> str:
    if path == "-":
        return sys.stdin.read()
    return Path(path).read_text(encoding="utf-8")


def _extract_name_from_interface_line(line: str) -> str:
    parts = line.split(None, 1)
    return parts[1].strip() if len(parts) > 1 else ""


def parse_cisco_vlans(conf: CiscoConfParse) -> List[Dict[str, Any]]:
    """Return a list of VLAN definitions from a Cisco configuration."""

    vlans: List[Dict[str, Any]] = []
    for vlan_obj in conf.find_objects(r"^vlan\s+\d+"):
        header = vlan_obj.text.strip()
        try:
            vlan_id = int(header.split()[1])
        except (IndexError, ValueError):
            continue
        name = ""
        for child in vlan_obj.children:
            text = getattr(child, "text", child)
            m = re.match(r"^\s*name\s+(.+)$", str(text))
            if m:
                name = m.group(1).strip()
                break
        vlans.append({"vlan_id": vlan_id, "name": name})
    return vlans


def parse_cisco_interfaces(conf: CiscoConfParse) -> List[CiscoInterface]:
    """Extract relevant interface attributes from a Cisco configuration."""

    interfaces: List[CiscoInterface] = []
    for intf in conf.find_objects(r"^interface\s+\S+"):
        ifname = _extract_name_from_interface_line(intf.text)
        if not ifname or not is_port_interface(ifname):
            continue

        mode = "access"
        access_vlan: Optional[int] = None
        voice_vlan: Optional[int] = None
        trunk_native: Optional[int] = None
        allowed: List[int] = []
        description = ""

        for child in intf.children:
            text = str(getattr(child, "text", child)).strip()
            if text.startswith("switchport mode"):
                if "trunk" in text:
                    mode = "trunk"
                elif "access" in text:
                    mode = "access"
            elif text.startswith("switchport access vlan"):
                parts = text.split()
                access_vlan = to_int(parts[-1])
            elif text.startswith("switchport voice vlan"):
                parts = text.split()
                voice_vlan = to_int(parts[-1])
            elif text.startswith("switchport trunk native vlan"):
                parts = text.split()
                trunk_native = to_int(parts[-1])
            elif re.match(r"switchport\s+trunk\s+allowed\s+vlan", text):
                tokens = text.split("vlan", 1)
                vlan_str = tokens[1] if len(tokens) > 1 else ""
                allowed = parse_allowed_list(vlan_str.strip())
            elif text.startswith("description"):
                description = text.split(" ", 1)[1].strip() if " " in text else ""

        interfaces.append(
            CiscoInterface(
                name=ifname,
                mode=mode,
                access_vlan=access_vlan,
                voice_vlan=voice_vlan,
                trunk_native=trunk_native,
                trunk_allowed=allowed,
                description=description,
            )
        )
    return interfaces


def _temp_vlan_name(vlan_id: int, name: str) -> str:
    suffix = name.strip().replace(" ", "_")
    suffix = re.sub(r"[^0-9A-Za-z_-]", "", suffix)[:40]
    return f"{TEMP_PREFIX}{vlan_id}{('_' + suffix) if suffix else ''}"


def build_temp_port_config(
    interfaces: Sequence[CiscoInterface],
    *,
    model: Optional[str],
) -> Dict[str, Dict[str, Any]]:
    """Create Mist port_config overrides that mirror the Cisco state."""

    port_config: Dict[str, Dict[str, Any]] = {}
    for intf in interfaces:
        mist_if = cisco_to_ex_if_enhanced(model, intf.name)
        if not mist_if:
            continue

        cfg: Dict[str, Any] = {
            "usage": f"{TEMP_PREFIX}{'trunk' if intf.is_trunk() else 'access'}",
            "description": intf.description,
        }

        if intf.is_trunk():
            if intf.trunk_native is not None:
                cfg["native_vlan_id"] = int(intf.trunk_native)
            if intf.trunk_allowed:
                cfg["allowed_vlan_ids"] = sorted({int(v) for v in intf.trunk_allowed})
        else:
            if intf.access_vlan is not None:
                cfg["vlan_id"] = int(intf.access_vlan)
            if intf.voice_vlan is not None:
                cfg["voice_vlan_id"] = int(intf.voice_vlan)

        port_config[mist_if] = cfg

    return port_config


def normalize_vlan_mapping_rules(rules: Dict[Any, Any]) -> Dict[int, Dict[str, Any]]:
    """Normalize a VLAN mapping table into a predictable structure."""

    normalized: Dict[int, Dict[str, Any]] = {}
    for key, value in rules.items():
        try:
            vlan_id = int(key)
        except Exception as exc:  # pragma: no cover - defensive
            raise ValueError(f"Invalid VLAN mapping key {key!r}") from exc

        if isinstance(value, int):
            normalized[vlan_id] = {"new_vlan_id": int(value)}
            continue

        if not isinstance(value, dict):
            raise ValueError(f"VLAN mapping for {vlan_id} must be int or dict")

        new_vlan = value.get("new_vlan_id") or value.get("new_id") or value.get("target")
        if new_vlan is None:
            raise ValueError(f"VLAN mapping for {vlan_id} missing 'new_vlan_id'")

        normalized[vlan_id] = {
            "new_vlan_id": int(new_vlan),
        }

        if "port_profile_id" in value and value["port_profile_id"]:
            normalized[vlan_id]["port_profile_id"] = str(value["port_profile_id"])
        if "usage" in value and value["usage"]:
            normalized[vlan_id]["usage"] = str(value["usage"])

    return normalized


def apply_vlan_mapping_to_port_config(
    existing: Dict[str, Dict[str, Any]],
    mapping: Dict[int, Dict[str, Any]],
) -> Tuple[Dict[str, Dict[str, Any]], List[str]]:
    """Return updated port_config entries and the list of touched interfaces."""

    updated: Dict[str, Dict[str, Any]] = {}
    touched: List[str] = []

    for ifname, cfg in existing.items():
        usage = str(cfg.get("usage") or "")
        if not usage.startswith(TEMP_PREFIX):
            continue

        new_cfg = dict(cfg)

        if "vlan_id" in new_cfg and new_cfg["vlan_id"] is not None:
            old_vlan = int(new_cfg["vlan_id"])
            if old_vlan in mapping:
                rule = mapping[old_vlan]
                new_cfg["vlan_id"] = rule["new_vlan_id"]
                if "usage" in rule:
                    new_cfg["usage"] = rule["usage"]
            else:
                raise ValueError(f"No mapping provided for VLAN {old_vlan} (port {ifname})")

        if "voice_vlan_id" in new_cfg and new_cfg["voice_vlan_id"] is not None:
            voice_old = int(new_cfg["voice_vlan_id"])
            if voice_old in mapping:
                new_cfg["voice_vlan_id"] = mapping[voice_old]["new_vlan_id"]
            else:
                new_cfg.pop("voice_vlan_id", None)

        if "native_vlan_id" in new_cfg and new_cfg["native_vlan_id"] is not None:
            native_old = int(new_cfg["native_vlan_id"])
            if native_old in mapping:
                new_cfg["native_vlan_id"] = mapping[native_old]["new_vlan_id"]
            else:
                raise ValueError(
                    f"No mapping provided for native VLAN {native_old} (port {ifname})"
                )

        if "allowed_vlan_ids" in new_cfg:
            allowed_vals = []
            for vlan in new_cfg.get("allowed_vlan_ids") or []:
                vlan_int = int(vlan)
                if vlan_int not in mapping:
                    raise ValueError(
                        f"No mapping provided for allowed VLAN {vlan_int} (port {ifname})"
                    )
                allowed_vals.append(mapping[vlan_int]["new_vlan_id"])
            new_cfg["allowed_vlan_ids"] = sorted({int(v) for v in allowed_vals})
            if allowed_vals:
                if usage.startswith(f"{TEMP_PREFIX}trunk"):
                    # default to a neutral trunk usage when not provided
                    new_cfg.setdefault("usage", "uplink")

        # Remove temp prefix from usage if still present
        if str(new_cfg.get("usage") or "").startswith(TEMP_PREFIX):
            base_usage = "access" if "vlan_id" in new_cfg else "uplink"
            new_cfg["usage"] = base_usage

        if "port_profile_id" in mapping.get(int(new_cfg.get("vlan_id", -1)), {}):
            rule = mapping[int(new_cfg["vlan_id"])]
            new_cfg["portconf_id"] = rule["port_profile_id"]
        else:
            new_cfg.pop("portconf_id", None)

        touched.append(ifname)
        updated[ifname] = new_cfg

    return updated, touched


def _extract_switch_config(doc: Dict[str, Any]) -> Dict[str, Any]:
    keys = ("switch_config", "config", "configuration", "switch", "device_config")
    for key in keys:
        value = doc.get(key)
        if isinstance(value, dict):
            return value
    for key in ("data", "details", "template"):
        nested = doc.get(key)
        if isinstance(nested, dict):
            extracted = _extract_switch_config(nested)
            if extracted:
                return extracted
    return {}


class MistTwoPhaseManager:
    """Encapsulates Mist API interactions for the two-phase workflow."""

    def __init__(self, *, base_url: Optional[str] = None, token: Optional[str] = None):
        self.base_url = (base_url or DEFAULT_BASE_URL).rstrip("/")
        self.token = _load_token(token)
        self.session = requests.Session()

    # ------------------------
    # Mist API helpers
    # ------------------------
    def _headers(self) -> Dict[str, str]:
        return {
            "Authorization": f"Token {self.token}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        }

    def _request(self, method: str, url: str, **kwargs: Any) -> requests.Response:
        resp = self.session.request(method, url, headers=self._headers(), timeout=60, **kwargs)
        if not (200 <= resp.status_code < 300):
            raise MistApiError(f"Mist API {method} {url} failed: {resp.status_code} {resp.text}")
        return resp

    def get_device(self, site_id: str, device_id: str) -> Dict[str, Any]:
        url = f"{self.base_url}/sites/{site_id}/devices/{device_id}"
        return self._request("GET", url).json()

    def get_site_vlans(self, site_id: str) -> List[Dict[str, Any]]:
        url = f"{self.base_url}/sites/{site_id}/vlans"
        resp = self._request("GET", url)
        data = resp.json()
        if isinstance(data, list):
            return data
        return data.get("results", []) if isinstance(data, dict) else []

    def ensure_temp_vlans(self, site_id: str, vlans: Iterable[Dict[str, Any]]) -> List[int]:
        existing = {int(v.get("vlan_id")): v for v in self.get_site_vlans(site_id)}
        created: List[int] = []
        url = f"{self.base_url}/sites/{site_id}/vlans"

        for vlan in vlans:
            vlan_id = int(vlan["vlan_id"])
            name = _temp_vlan_name(vlan_id, vlan.get("name", "") or "")
            existing_vlan = existing.get(vlan_id)
            if existing_vlan and str(existing_vlan.get("name", "")).startswith(TEMP_PREFIX):
                continue
            body = {
                "name": name,
                "vlan_id": vlan_id,
            }
            self._request("POST", url, json=body)
            created.append(vlan_id)
        return created

    def update_port_config(self, site_id: str, device_id: str, port_config: Dict[str, Any]) -> Dict[str, Any]:
        url = f"{self.base_url}/sites/{site_id}/devices/{device_id}"
        body = {"port_config": port_config}
        return self._request("PUT", url, json=body).json()

    def delete_site_vlan(self, site_id: str, vlan_uuid: str) -> None:
        url = f"{self.base_url}/sites/{site_id}/vlans/{vlan_uuid}"
        self._request("DELETE", url)

    # ------------------------
    # Workflow actions
    # ------------------------
    def stage_from_cisco_config(
        self,
        *,
        site_id: str,
        device_id: str,
        cisco_config_text: str,
    ) -> Dict[str, Any]:
        conf = CiscoConfParse(cisco_config_text.splitlines(), syntax="ios")
        vlans = parse_cisco_vlans(conf)
        interfaces = parse_cisco_interfaces(conf)

        created_vlans = self.ensure_temp_vlans(site_id, vlans)

        device = self.get_device(site_id, device_id)
        model = get_device_model(self.base_url, site_id, device_id, self.token) or device.get("model")
        switch_config = _extract_switch_config(device)
        existing_port_config = dict(switch_config.get("port_config") or {})

        staged_config = build_temp_port_config(interfaces, model=model)
        merged = dict(existing_port_config)
        merged.update(staged_config)

        self.update_port_config(site_id, device_id, merged)

        return {
            "created_temp_vlans": created_vlans,
            "updated_ports": sorted(staged_config.keys()),
        }

    def finalize_from_mapping(
        self,
        *,
        site_id: str,
        device_id: str,
        vlan_mapping_rules: Dict[Any, Any],
    ) -> Dict[str, Any]:
        mapping = normalize_vlan_mapping_rules(vlan_mapping_rules)

        device = self.get_device(site_id, device_id)
        switch_config = _extract_switch_config(device)
        existing_port_config = dict(switch_config.get("port_config") or {})

        updated_entries, touched = apply_vlan_mapping_to_port_config(existing_port_config, mapping)
        if updated_entries:
            merged = dict(existing_port_config)
            merged.update(updated_entries)
            self.update_port_config(site_id, device_id, merged)

        removed_vlans: List[int] = []
        for vlan in self.get_site_vlans(site_id):
            name = str(vlan.get("name") or "")
            if not name.startswith(TEMP_PREFIX):
                continue
            vlan_id_val = vlan.get("vlan_id")
            vlan_uuid = vlan.get("id")
            if vlan_uuid:
                self.delete_site_vlan(site_id, str(vlan_uuid))
            if vlan_id_val is not None:
                removed_vlans.append(int(vlan_id_val))

        return {
            "updated_ports": sorted(touched),
            "removed_temp_vlans": sorted(set(removed_vlans)),
        }


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Automate temporary Mist switch staging and finalization")
    sub = parser.add_subparsers(dest="command", required=True)

    stage_p = sub.add_parser("stage", help="Stage temporary Mist configuration from a Cisco config")
    stage_p.add_argument("--site-id", required=True)
    stage_p.add_argument("--device-id", required=True)
    stage_p.add_argument("--config-file", required=True, help="Cisco running-config file path or '-' for stdin")
    stage_p.add_argument("--base-url", default=None)
    stage_p.add_argument("--token", default=None)

    final_p = sub.add_parser("finalize", help="Finalize staged config using VLAN mapping rules")
    final_p.add_argument("--site-id", required=True)
    final_p.add_argument("--device-id", required=True)
    final_p.add_argument("--mapping-file", required=True, help="JSON file containing VLAN mapping rules")
    final_p.add_argument("--base-url", default=None)
    final_p.add_argument("--token", default=None)

    args = parser.parse_args(argv)

    manager = MistTwoPhaseManager(base_url=args.base_url, token=args.token)

    if args.command == "stage":
        config_text = _read_text_file(args.config_file)
        result = manager.stage_from_cisco_config(
            site_id=args.site_id,
            device_id=args.device_id,
            cisco_config_text=config_text,
        )
    else:
        mapping_text = _read_text_file(args.mapping_file)
        try:
            rules = json.loads(mapping_text)
        except json.JSONDecodeError as exc:
            raise SystemExit(f"Invalid mapping JSON: {exc}")
        result = manager.finalize_from_mapping(
            site_id=args.site_id,
            device_id=args.device_id,
            vlan_mapping_rules=rules,
        )

    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())

