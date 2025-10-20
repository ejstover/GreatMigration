#!/usr/bin/env python3
# convertciscotojson.py
#
# pip install ciscoconfparse
#
# Single file:
#   python convertciscotojson.py "C:\path\to\Config.txt"
#
# Bulk convert a directory (outputs *_converted.json in same dir):
#   python convertciscotojson.py --bulk-convert "C:\path\to\configs"
#
# Optional overrides:
#   --uplink-module 1          # Cisco module number used for uplinks (default 1)
#   --force-model ex4100-48mp  # Force ALL members to this model (skip inference)
#   --strict-overflow          # Error if an access port exceeds the inferred model capacity
#
# Behavior (simple first):
# - Ignore interface speed/type prefixes. Use ONLY numbers: member/module/port.
# - Infer model PER MEMBER by the largest access port found for that member:
#     max_port<=24 -> ex4100-24mp (0-7 mge, 8-23 ge), else ex4100-48mp (0-15 mge, 16-47 ge)
# - VC size = max member number seen (Cisco 1-based) => Juniper FPC is member-1 (0-based).
# - Uplinks: module == uplink_module -> xe-<fpc>/2/<port-1 clamped 0..3>
# - Access: fpc=member-1, local_idx=port-1, prefix by inferred model for that member.
# - Skip Cisco mgmt Gi0/0 entirely.

import argparse
import json
import os
import re
from pathlib import Path
from typing import Any, Dict, List, Optional

from ciscoconfparse import CiscoConfParse

from plan_builder import PlannerError, generate_plan

TARGET_MODELS = {"ex4100-48mp", "ex4100-24mp"}

# ----------------------------
# Parsing & classification (number-driven)
# ----------------------------
def _extract_numbers(name: str) -> List[int]:
    """Extract numeric segments, preserving the leading member digit."""
    tail = re.sub(r"^\D+", "", name)
    nums = [int(p) for p in tail.split("/") if p.strip().isdigit()] if tail else []
    if not nums:
        m = re.search(r"(\d+(?:/\d+){0,3})$", name)
        if m:
            nums = [int(p) for p in m.group(1).split("/") if p.strip().isdigit()]
    return nums

def is_port_interface(name: str) -> bool:
    """Physical-ish if there's at least one slash and >=2 numeric segments (speed-agnostic)."""
    if "/" not in name:
        return False
    nums = _extract_numbers(name)
    return len(nums) >= 2

def _is_mgmt_gi0_0(name: str, nums: List[int]) -> bool:
    """Exclude Cisco mgmt GigabitEthernet0/0 (and gi0/0/0)."""
    n = re.sub(r"\s+", "", name).lower()
    if re.match(r"^(gi|gigabitethernet)0/0(?:/0)?$", n):
        return True
    return (("gigabitethernet" in n or n.startswith("gi"))
            and len(nums) >= 2 and nums[0] == 0 and nums[1] == 0)

def first(children: List[str], pattern: str, group: int = 1) -> Optional[str]:
    rgx = re.compile(pattern)
    for line in children:
        m = rgx.search(line)
        if m:
            return m.group(group).strip()
    return None

def flag(children: List[str], pattern: str) -> bool:
    rgx = re.compile(pattern)
    return any(rgx.search(l) for l in children)

def parse_allowed_list(val: Optional[str]) -> List[int]:
    """Parse '10-12,20,30-31' -> [10,11,12,20,30,31]"""
    if not val:
        return []
    out = set()
    for tok in [t.strip() for t in val.split(",") if t.strip()]:
        if "-" in tok:
            a, b = tok.split("-", 1)
            try:
                a, b = int(a), int(b)
                for v in range(min(a, b), max(a, b) + 1):
                    out.add(v)
            except ValueError:
                pass
        else:
            try:
                out.add(int(tok))
            except ValueError:
                pass
    return sorted(out)

def to_int(x) -> Optional[int]:
    try:
        return int(x)
    except Exception:
        return None

# ----------------------------
# Model layout helpers
# ----------------------------
def _dest_ports_per_member(model: str) -> int:
    return 48 if model.lower() == "ex4100-48mp" else 24

def _dest_prefix_for_model(model: str, local_port_idx: int) -> str:
    m = model.lower()
    if m == "ex4100-48mp":
        return "mge" if 0 <= local_port_idx <= 15 else "ge"
    elif m == "ex4100-24mp":
        return "mge" if 0 <= local_port_idx <= 7 else "ge"
    return "ge"

# ----------------------------
# Mapping (module-driven logic)
# ----------------------------
def _looks_like_uplink_by_module(nums: List[int], uplink_module: int) -> bool:
    """Uplink if we have member/module/port AND module == uplink_module."""
    return len(nums) >= 3 and nums[1] == uplink_module

def _map_uplink(nums: List[int], derived_vc_members: int) -> str:
    """
    EX4100 uplinks are xe-<fpc>/2/<0-3>.
    fpc  = (member-1); clamp to 0 if single switch
    port = clamp(port-1, 0..3)
    """
    src_member_1b = max(nums[0], 1)
    fpc = src_member_1b - 1
    if derived_vc_members == 1:
        fpc = 0
    port = max(0, min((nums[-1] - 1), 3))
    return f"xe-{fpc}/2/{port}"

def cisco_to_juniper_if_direct(
    name: str,
    member_models: Dict[int, str],  # key: Cisco member (1-based), val: ex4100-24mp|ex4100-48mp
    derived_vc_members: int,
    uplink_module: int = 1,
    strict_overflow: bool = False,
    port_offset: int = 0,
) -> str:
    """
    Direct mapping (no flatten): fpc = member-1; local_idx = port-1; prefix by the
    inferred model for THAT member.
    """
    nums = _extract_numbers(name)
    if not nums:
        return name

    # Uplinks (always xe on EX4100)
    if _looks_like_uplink_by_module(nums, uplink_module):
        upl = _map_uplink(nums, derived_vc_members)
        try:
            fpc = int(upl.split("-")[1].split("/")[0])
            if strict_overflow and fpc >= derived_vc_members:
                raise ValueError(f"[OVERFLOW-UPLINK] {name} -> FPC {fpc} but VC has {derived_vc_members}")
        except Exception:
            pass
        return upl

    # Access/user
    src_member_1b = max(nums[0], 1)
    fpc = src_member_1b - 1
    local_idx = max(nums[-1] - 1, 0) + int(port_offset or 0)

    model = member_models.get(src_member_1b, "ex4100-48mp")  # safe default
    dest_ppm = _dest_ports_per_member(model)

    if strict_overflow and local_idx >= dest_ppm:
        raise ValueError(
            f"[OVERFLOW] {name} -> local_idx {local_idx}, but {model} has only {dest_ppm} access ports"
        )
    # Keep readable even if strict is off
    local_idx = local_idx % dest_ppm

    prefix = _dest_prefix_for_model(model, local_idx)
    return f"{prefix}-{fpc}/0/{local_idx}"

# ----------------------------
# Inference: per-member model + VC size
# ----------------------------
def infer_member_models(conf: CiscoConfParse, uplink_module: int) -> Dict[int, str]:
    """
    Inspect the config and decide per-member model by max access port number observed.
    Returns: { member_1b: "ex4100-24mp"|"ex4100-48mp" }
    """
    per_member_max: Dict[int, int] = {}
    for intf in conf.find_objects(r"^interface\s+\S+"):
        ifname = intf.text.split(None, 1)[1]
        if not is_port_interface(ifname):
            continue
        nums = _extract_numbers(ifname)
        if _is_mgmt_gi0_0(ifname, nums):
            continue
        # if we have member/module/port and this is the uplink module, skip for access sizing
        if len(nums) >= 3 and nums[1] == uplink_module:
            continue
        # use the LAST number (port)
        if nums:
            member = max(nums[0], 1)
            port = max(nums[-1], 1)
            per_member_max[member] = max(per_member_max.get(member, 0), port)

    member_models: Dict[int, str] = {}
    for member, max_port in per_member_max.items():
        member_models[member] = "ex4100-24mp" if max_port <= 24 else "ex4100-48mp"

    # If a member had no access ports (only uplinks), assume 48MP for safety.
    # This keeps mapping valid even for uplink-only configs.
    if not member_models:
        # No data at all? default member 1 → 48MP
        member_models[1] = "ex4100-48mp"

    return member_models

# ----------------------------
# Convert ONE file
# ----------------------------
def convert_one_file(
    input_path: Path,
    uplink_module: int,
    strict_overflow: bool,
    force_model: Optional[str] = None,
    output_dir: Optional[Path] = None,
    start_port: int = 0,
) -> Path:
    """
    Convert a single Cisco config text file to JSON using the rules above.
    Returns the output JSON Path.
    """
    if output_dir is None:
        out_dir = input_path.parent
    else:
        out_dir = output_dir
    base_name = os.path.splitext(os.path.basename(str(input_path)))[0]
    output_file = out_dir / f"{base_name}_converted.json"

    # Parse config
    conf = CiscoConfParse(str(input_path), factory=True)

    # Infer VC size from source (max member number) and per-member models
    member_numbers = []
    for intf in conf.find_objects(r"^interface\s+\S+"):
        ifname = intf.text.split(None, 1)[1]
        if not is_port_interface(ifname):
            continue
        nums = _extract_numbers(ifname)
        if _is_mgmt_gi0_0(ifname, nums):
            continue
        if nums:
            member_numbers.append(nums[0])
    derived_vc_members = max(member_numbers) if member_numbers else 1
    if derived_vc_members < 1:
        derived_vc_members = 1

    if force_model and force_model.lower() not in TARGET_MODELS:
        raise ValueError(f"--force-model must be one of {sorted(TARGET_MODELS)}")
    if force_model:
        member_models = {m: force_model.lower() for m in range(1, derived_vc_members + 1)}
    else:
        member_models = infer_member_models(conf, uplink_module=uplink_module)

    # VLANs (optional)
    vlans: List[Dict[str, Any]] = []
    for vlan_obj in conf.find_objects(r"^vlan\s+\d+"):
        m = re.search(r"^vlan\s+(\d+)", vlan_obj.text)
        if not m:
            continue
        vid = int(m.group(1))
        vname = ""
        for ch in vlan_obj.children:
            n = re.search(r"^\s*name\s+(.+)$", ch.text)
            if n:
                vname = n.group(1).strip()
                break
        vlans.append({"id": vid, "name": vname})

    # Interfaces
    interfaces: List[Dict[str, Any]] = []
    overflow_count = 0
    for intf in conf.find_objects(r"^interface\s+\S+"):
        ifname = intf.text.split(None, 1)[1]
        if not is_port_interface(ifname):
            continue

        nums = _extract_numbers(ifname)
        if _is_mgmt_gi0_0(ifname, nums):
            continue  # skip Cisco mgmt Gi0/0 entirely

        children = [c.text.strip() for c in intf.all_children]

        is_trunk  = flag(children, r"^switchport\s+mode\s+trunk\b")
        is_access = flag(children, r"^switchport\s+mode\s+access\b")
        mode = "trunk" if is_trunk else ("access" if is_access else "routed")

        access_vlan  = first(children, r"^switchport\s+access\s+vlan\s+(\d+)$")
        voice_vlan   = first(children, r"^switchport\s+voice\s+vlan\s+(\d+)$")
        native_vlan  = first(children, r"^switchport\s+trunk\s+native\s+vlan\s+(\d+)$")
        allowed_raw  = first(children, r"^switchport\s+trunk\s+allowed\s+vlan\s+(.+)$")
        allowed_list = parse_allowed_list(allowed_raw)

        # Build Juniper target interface
        try:
            j_if = cisco_to_juniper_if_direct(
                ifname,
                member_models=member_models,
                derived_vc_members=derived_vc_members,
                uplink_module=uplink_module,
                strict_overflow=strict_overflow,
                port_offset=start_port,
            )
            mapping_overflow = False
        except ValueError:
            j_if = cisco_to_juniper_if_direct(
                ifname,
                member_models=member_models,
                derived_vc_members=derived_vc_members,
                uplink_module=uplink_module,
                strict_overflow=False,
                port_offset=start_port,
            )
            mapping_overflow = True
            overflow_count += 1

        src_member = nums[0] if nums else None
        src_module = nums[1] if len(nums) >= 2 else None
        src_port   = nums[-1] if nums else None
        is_uplink  = (len(nums) >= 3 and nums[1] == uplink_module)

        iface: Dict[str, Any] = {
            "name": ifname,
            "juniper_if": j_if,
            "mode": mode,
            "description": first(children, r"^description\s+(.+)$") or "",
            "data_vlan": to_int(access_vlan),
            "voice_vlan": to_int(voice_vlan),
            "native_vlan": to_int(native_vlan),
            "allowed_vlans": allowed_list if mode == "trunk" else [],
            "shutdown": flag(children, r"^shutdown$"),
            "portfast": flag(children, r"^spanning-tree\s+portfast\b"),
            "autoqos": flag(children, r"^auto\s+qos\b"),
            "trust_device": first(children, r"^trust\s+device\s+(.+)$") or "",
            "service_policy_in": first(children, r"^service-policy\s+input\s+(.+)$") or "",
            "service_policy_out": first(children, r"^service-policy\s+output\s+(.+)$") or "",
            "uplink": is_uplink,
            "src_member": src_member,
            "src_module": src_module,
            "src_port": src_port,
            "children": children,
        }
        if mapping_overflow:
            iface["mapping_overflow"] = True
        interfaces.append(iface)

    out = {
        "meta": {
            "derived_vc_members": derived_vc_members,
            "uplink_module": uplink_module,
            "strict_overflow": strict_overflow,
            "member_models": member_models,  # {1: "ex4100-24mp", 2: "ex4100-48mp", ...}
            "force_model": force_model.lower() if force_model else None,
        },
        "vlans": vlans,
        "interfaces": interfaces,
    }

    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(out, f, indent=2)

    print(f"✅ VC members: {derived_vc_members} | Models: {member_models} | Interfaces: {len(interfaces)} | ↳ {output_file}")
    if overflow_count:
        print(f"  ⚠️  Access-port overflows vs inferred model: {overflow_count} (see 'mapping_overflow': true)")
    return output_file

# ----------------------------
# Main (single-file or bulk directory)
# ----------------------------
def main():
    ap = argparse.ArgumentParser(description="CiscoConfParse → JSON (number-driven; per-member model inference).")
    ap.add_argument("input_file", nargs="?", help="Path to a Cisco config text file")
    ap.add_argument(
        "--bulk-convert",
        help="Directory containing Cisco config files (.txt/.cfg/.conf). Outputs JSONs into the same directory.",
    )
    ap.add_argument(
        "--uplink-module",
        type=int,
        default=1,
        help="Cisco module number that represents uplinks (default 1)."
    )
    ap.add_argument(
        "--force-model",
        choices=sorted(TARGET_MODELS),
        help="Force ALL members to this model, bypassing inference (ex4100-24mp or ex4100-48mp)."
    )
    ap.add_argument(
        "--strict-overflow",
        action="store_true",
        help="If set, raise an error when a port exceeds the inferred/forced model capacity."
    )
    ap.add_argument("--start-port", type=int, default=0, help="Offset final Juniper port numbers by this amount.")
    ap.add_argument("--skip-plan", action="store_true", help="Skip planner artifact generation after conversion.")
    ap.add_argument("--data-mapping", help="Override planner data VLAN mapping JSON file.")
    ap.add_argument("--voice-mapping", help="Override planner voice VLAN mapping JSON file.")
    ap.add_argument(
        "--plan-output-dir",
        help="Directory for plan/final JSON artifacts (defaults to converter output directory).",
    )
    ap.add_argument(
        "--plan-persist-dir",
        help="Directory to persist planner artifacts per switch (defaults to backend/logs/planner).",
    )
    ap.add_argument("--mist-base-url", dest="plan_base_url", help="Override Mist API base URL for planner validation.")
    ap.add_argument("--mist-org-id", dest="plan_org_id", help="Override Mist org ID for planner validation.")
    ap.add_argument(
        "--mist-template-id",
        dest="plan_template_id",
        help="Override Mist switch template ID for planner validation.",
    )
    ap.add_argument("--mist-token", dest="plan_token", help="Override Mist token for planner validation.")
    args = ap.parse_args()

    if not args.input_file and not args.bulk_convert:
        ap.error("Provide either a single input_file or --bulk-convert <directory>")

    planner_persist_default = Path(__file__).resolve().parent / "logs" / "planner"

    def _run_planner(output_file: Path, source_label: str) -> None:
        if args.skip_plan:
            return
        plan_output_dir = Path(args.plan_output_dir) if args.plan_output_dir else None
        persist_dir = Path(args.plan_persist_dir) if args.plan_persist_dir else planner_persist_default
        try:
            result = generate_plan(
                output_file,
                data_mapping_path=Path(args.data_mapping) if args.data_mapping else None,
                voice_mapping_path=Path(args.voice_mapping) if args.voice_mapping else None,
                output_dir=plan_output_dir,
                base_url=args.plan_base_url,
                org_id=args.plan_org_id,
                template_id=args.plan_template_id,
                token=args.plan_token,
                persist_dir=persist_dir,
            )
        except PlannerError as exc:
            print(f"  ⚠️ Planner failed for {source_label}: {exc}")
            return

        print(f"  📄 Plan: {result.plan_path.name} | Final: {result.final_path.name}")
        if result.persisted_plan_path:
            print(f"    ↳ persisted to {result.persisted_plan_path.parent}")
        if result.errors:
            print("    ⚠️ Planner issues detected:")
            for issue in result.errors:
                print(f"      - {issue}")

    # Single-file mode
    if args.input_file:
        in_path = Path(args.input_file)
        if not in_path.exists():
            ap.error(f"Input file not found: {in_path}")
        output_file = convert_one_file(
            input_path=in_path,
            uplink_module=args.uplink_module,
            strict_overflow=args.strict_overflow,
            force_model=args.force_model,
            start_port=args.start_port,
        )
        _run_planner(output_file, in_path.name)
        return

    # Bulk mode
    bulk_dir = Path(args.bulk_convert)
    if not bulk_dir.exists() or not bulk_dir.is_dir():
        ap.error(f"--bulk-convert path must be an existing directory: {bulk_dir}")

    exts = {".txt", ".cfg", ".conf"}
    files = sorted([p for p in bulk_dir.iterdir() if p.is_file() and p.suffix.lower() in exts])

    if not files:
        print(f"ℹ️  No .txt/.cfg/.conf files found in {bulk_dir}")
        return

    print(f"📦 Bulk converting {len(files)} files in: {bulk_dir}")
    ok = 0
    failed = 0
    for p in files:
        try:
            output_file = convert_one_file(
                input_path=p,
                uplink_module=args.uplink_module,
                strict_overflow=args.strict_overflow,
                force_model=args.force_model,
                output_dir=bulk_dir,  # keep outputs alongside sources
                start_port=args.start_port,
            )
            ok += 1
            _run_planner(output_file, p.name)
        except Exception as e:
            failed += 1
            print(f"❌ {p.name}: {e}")

    print(f"✅ Done. Converted: {ok} | Failed: {failed}")

if __name__ == "__main__":
    main()
