"""Utilities to generate migration planning artifacts from converter output."""
from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set, Tuple

import requests

DEFAULT_DATA_MAPPING_PATH = Path(__file__).with_name("data_vlan_mappings.json")
DEFAULT_VOICE_MAPPING_PATH = Path(__file__).with_name("voice_vlan_mappings.json")
DEFAULT_BASE_URL = "https://api.mist.com/api/v1"


class PlannerError(RuntimeError):
    """Raised when the planner cannot build artifacts."""


@dataclass
class PlanBuildResult:
    plan_path: Path
    final_path: Path
    plan_doc: Dict[str, Any]
    final_doc: Dict[str, Any]
    errors: Sequence[str]
    persisted_plan_path: Optional[Path] = None
    persisted_final_path: Optional[Path] = None


def _load_json_document(path: Path) -> Dict[str, Any]:
    if not path.exists():
        raise PlannerError(f"Required JSON file not found: {path}")
    try:
        with path.open("r", encoding="utf-8") as fh:
            data = json.load(fh)
    except json.JSONDecodeError as exc:  # pragma: no cover - defensive
        raise PlannerError(f"Invalid JSON in {path}: {exc}") from exc
    if not isinstance(data, dict):
        raise PlannerError(f"Expected an object at top level of {path}")
    return data


def _as_int(value: Any) -> Optional[int]:
    if value is None:
        return None
    try:
        return int(value)
    except Exception:  # pragma: no cover - defensive
        return None


def _merge_dict(base: Dict[str, Any], overlay: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    merged = dict(base)
    if overlay:
        merged.update(overlay)
    return merged


def _collect_vlan_ids(values: Iterable[Any]) -> Set[int]:
    out: Set[int] = set()
    for value in values:
        val = _as_int(value)
        if val is not None:
            out.add(val)
    return out


def _safe_prefix(value: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9_.-]", "_", value)
    cleaned = cleaned.strip("_.")
    return cleaned or "plan"


def fetch_port_profiles(
    *,
    base_url: Optional[str] = None,
    org_id: Optional[str] = None,
    template_id: Optional[str] = None,
    token: Optional[str] = None,
) -> Set[str]:
    """Fetch port profile names from a Mist switch template."""

    token = (token or os.getenv("MIST_TOKEN") or "").strip()
    if not token:
        raise PlannerError("Missing Mist token for planner validation. Set MIST_TOKEN or pass token explicitly.")

    template_id = (template_id or os.getenv("SWITCH_TEMPLATE_ID") or "").strip()
    if not template_id:
        raise PlannerError("Missing switch template identifier (SWITCH_TEMPLATE_ID).")

    org_id = (org_id or os.getenv("MIST_ORG_ID") or "").strip()
    if not org_id:
        raise PlannerError("Missing Mist organization identifier (MIST_ORG_ID).")

    base = (base_url or os.getenv("MIST_BASE_URL") or DEFAULT_BASE_URL).rstrip("/")

    url = f"{base}/orgs/{org_id}/networktemplates/{template_id}"
    try:
        response = requests.get(url, headers={"Authorization": f"Token {token}"}, timeout=30)
        response.raise_for_status()
        payload = response.json() or {}
    except requests.HTTPError as exc:
        raise PlannerError(f"Unable to fetch Mist template {template_id}: {exc}") from exc
    except Exception as exc:  # pragma: no cover - defensive
        raise PlannerError(f"Unexpected error fetching Mist template {template_id}: {exc}") from exc

    port_usages = payload.get("port_usages")
    if isinstance(port_usages, dict):
        return {str(name) for name in port_usages.keys()}
    raise PlannerError("Mist template response missing 'port_usages' block.")


def build_plan_documents(
    converter_doc: Dict[str, Any],
    data_mapping: Dict[str, Any],
    voice_mapping: Dict[str, Any],
    *,
    available_profiles: Sequence[str],
) -> Tuple[Dict[str, Any], Dict[str, Any], List[str]]:
    interfaces = converter_doc.get("interfaces") or []
    meta = converter_doc.get("meta") or {}

    data_defaults = data_mapping.get("defaults", {}) if isinstance(data_mapping, dict) else {}
    data_entries = data_mapping.get("vlans", {}) if isinstance(data_mapping, dict) else {}
    management_entry = data_mapping.get("management", {}) if isinstance(data_mapping, dict) else {}

    voice_defaults = voice_mapping.get("defaults", {}) if isinstance(voice_mapping, dict) else {}
    voice_entries = voice_mapping.get("vlans", {}) if isinstance(voice_mapping, dict) else {}

    available_set = {str(name) for name in available_profiles}

    temp_vlans: Set[int] = set()
    temp_profiles: Set[str] = set()
    final_profiles: Set[str] = set()
    errors: List[str] = []

    plan_ports: List[Dict[str, Any]] = []
    final_ports: List[Dict[str, Any]] = []

    timestamp = datetime.now(timezone.utc).isoformat()

    for iface in interfaces:
        if not isinstance(iface, dict):
            continue
        name = iface.get("name") or ""
        mode = (iface.get("mode") or "").lower()
        uplink = bool(iface.get("uplink"))
        data_vlan = _as_int(iface.get("data_vlan"))
        voice_vlan = _as_int(iface.get("voice_vlan"))
        native_vlan = _as_int(iface.get("native_vlan"))
        allowed_vlans = iface.get("allowed_vlans") if isinstance(iface.get("allowed_vlans"), list) else []

        iface_temp_vlans = _collect_vlan_ids([data_vlan, voice_vlan, native_vlan])
        iface_temp_vlans.update(_collect_vlan_ids(allowed_vlans))
        temp_vlans.update(iface_temp_vlans)

        port_issues: List[str] = []

        plan_entry: Dict[str, Any] = {
            "name": name,
            "juniper_if": iface.get("juniper_if"),
            "mode": mode,
            "description": iface.get("description"),
            "legacy": {
                "data_vlan": data_vlan,
                "voice_vlan": voice_vlan,
                "native_vlan": native_vlan,
                "allowed_vlans": allowed_vlans,
                "uplink": uplink,
            },
        }

        final_entry: Dict[str, Any] = {
            "name": name,
            "juniper_if": iface.get("juniper_if"),
            "mode": mode,
            "uplink": uplink,
        }

        if mode == "trunk" or uplink:
            mgmt = _merge_dict(data_defaults, management_entry)
            temp_profile = mgmt.get("temp_profile")
            final_profile = mgmt.get("final_profile")
            final_vlan = _as_int(mgmt.get("final_vlan"))
            if temp_profile:
                plan_entry["temporary_profile"] = temp_profile
                temp_profiles.add(temp_profile)
            if final_profile:
                final_entry["final_profile"] = final_profile
                final_profiles.add(final_profile)
                if final_profile not in available_set:
                    msg = f"Port {name} final profile '{final_profile}' not found in Mist template"
                    errors.append(msg)
                    port_issues.append(msg)
            else:
                msg = f"Port {name} missing management final profile mapping"
                errors.append(msg)
                port_issues.append(msg)
            if final_vlan is not None:
                final_entry["final_vlan"] = final_vlan
        else:
            entry = data_entries.get(str(data_vlan)) if data_vlan is not None else None
            mapping = _merge_dict(data_defaults, entry) if data_vlan is not None else {}
            temp_profile = mapping.get("temp_profile")
            final_profile = mapping.get("final_profile")
            final_vlan = _as_int(mapping.get("final_vlan")) if mapping else None

            if data_vlan is not None and entry is None:
                msg = f"No data VLAN mapping defined for VLAN {data_vlan} (port {name})"
                errors.append(msg)
                port_issues.append(msg)

            if temp_profile:
                plan_entry["temporary_profile"] = temp_profile
                temp_profiles.add(temp_profile)

            if final_profile:
                final_entry["final_profile"] = final_profile
                final_profiles.add(final_profile)
                if final_profile not in available_set:
                    msg = f"Port {name} final profile '{final_profile}' not found in Mist template"
                    errors.append(msg)
                    port_issues.append(msg)
            else:
                msg = f"Port {name} missing final profile mapping"
                errors.append(msg)
                port_issues.append(msg)

            if final_vlan is not None:
                final_entry["final_vlan"] = final_vlan

            if voice_vlan is not None:
                voice_entry = voice_entries.get(str(voice_vlan))
                voice_map = _merge_dict(voice_defaults, voice_entry) if voice_entry else dict(voice_defaults)
                final_voice_vlan = _as_int(voice_map.get("final_vlan")) if voice_map else None
                if voice_entry is None:
                    msg = f"No voice VLAN mapping defined for VLAN {voice_vlan} (port {name})"
                    errors.append(msg)
                    port_issues.append(msg)
                if final_voice_vlan is not None:
                    final_entry["final_voice_vlan"] = final_voice_vlan

        if port_issues:
            plan_entry["issues"] = list(port_issues)
            final_entry["issues"] = list(port_issues)

        plan_ports.append(plan_entry)
        final_ports.append(final_entry)

    plan_doc: Dict[str, Any] = {
        "source": converter_doc.get("source") or "converter",
        "meta": meta,
        "generated_at": timestamp,
        "management": management_entry,
        "temp_vlans": sorted(temp_vlans),
        "temp_profiles": sorted(temp_profiles),
        "ports": plan_ports,
        "errors": errors,
    }

    final_doc: Dict[str, Any] = {
        "source": converter_doc.get("source") or "converter",
        "meta": meta,
        "generated_at": timestamp,
        "management": management_entry,
        "final_profiles": sorted(final_profiles),
        "ports": final_ports,
        "errors": errors,
    }

    return plan_doc, final_doc, errors


def generate_plan(
    converter_json: Path,
    *,
    data_mapping_path: Optional[Path] = None,
    voice_mapping_path: Optional[Path] = None,
    output_dir: Optional[Path] = None,
    available_profiles: Optional[Sequence[str]] = None,
    base_url: Optional[str] = None,
    org_id: Optional[str] = None,
    template_id: Optional[str] = None,
    token: Optional[str] = None,
    persist_dir: Optional[Path] = None,
) -> PlanBuildResult:
    """Load all inputs and write plan/final JSON artifacts."""

    converter_path = Path(converter_json)
    if not converter_path.exists():
        raise PlannerError(f"Converter JSON not found: {converter_path}")

    data_path = Path(data_mapping_path) if data_mapping_path else DEFAULT_DATA_MAPPING_PATH
    voice_path = Path(voice_mapping_path) if voice_mapping_path else DEFAULT_VOICE_MAPPING_PATH

    converter_doc = _load_json_document(converter_path)
    converter_doc.setdefault("source", converter_path.name)
    data_mapping = _load_json_document(data_path)
    voice_mapping = _load_json_document(voice_path)

    profiles = (
        set(available_profiles)
        if available_profiles is not None
        else fetch_port_profiles(base_url=base_url, org_id=org_id, template_id=template_id, token=token)
    )

    plan_doc, final_doc, errors = build_plan_documents(
        converter_doc,
        data_mapping,
        voice_mapping,
        available_profiles=profiles,
    )

    base_name = converter_path.stem
    prefix = base_name[:-10] if base_name.endswith("_converted") else base_name

    destination_dir = Path(output_dir) if output_dir else converter_path.parent
    destination_dir.mkdir(parents=True, exist_ok=True)

    plan_filename = f"{prefix}_plan.json"
    final_filename = f"{prefix}_final.json"

    plan_path = destination_dir / plan_filename
    final_path = destination_dir / final_filename

    plan_path.write_text(json.dumps(plan_doc, indent=2), encoding="utf-8")
    final_path.write_text(json.dumps(final_doc, indent=2), encoding="utf-8")

    persisted_plan_path: Optional[Path] = None
    persisted_final_path: Optional[Path] = None
    if persist_dir:
        safe_prefix = _safe_prefix(prefix)
        target_dir = Path(persist_dir) / safe_prefix
        target_dir.mkdir(parents=True, exist_ok=True)
        persisted_plan_path = target_dir / plan_filename
        persisted_plan_path.write_text(plan_path.read_text(encoding="utf-8"), encoding="utf-8")
        persisted_final_path = target_dir / final_filename
        persisted_final_path.write_text(final_path.read_text(encoding="utf-8"), encoding="utf-8")

    return PlanBuildResult(
        plan_path=plan_path,
        final_path=final_path,
        plan_doc=plan_doc,
        final_doc=final_doc,
        errors=errors,
        persisted_plan_path=persisted_plan_path,
        persisted_final_path=persisted_final_path,
    )


def main() -> None:  # pragma: no cover - CLI helper
    import argparse

    ap = argparse.ArgumentParser(description="Build migration plan artifacts from converter JSON outputs.")
    ap.add_argument("input", help="Path to <name>_converted.json")
    ap.add_argument("--output-dir", help="Directory for generated plan/final JSON")
    ap.add_argument("--data-mapping", help="Path to data VLAN mapping JSON")
    ap.add_argument("--voice-mapping", help="Path to voice VLAN mapping JSON")
    ap.add_argument("--persist-dir", help="Optional directory to persist artifacts per switch")
    ap.add_argument("--mist-base-url", dest="base_url", help="Override Mist API base URL")
    ap.add_argument("--mist-org-id", dest="org_id", help="Override Mist organization ID")
    ap.add_argument("--mist-template-id", dest="template_id", help="Override Mist switch template ID")
    ap.add_argument("--mist-token", dest="token", help="Mist API token (falls back to env var)")

    args = ap.parse_args()

    try:
        result = generate_plan(
            Path(args.input),
            data_mapping_path=Path(args.data_mapping) if args.data_mapping else None,
            voice_mapping_path=Path(args.voice_mapping) if args.voice_mapping else None,
            output_dir=Path(args.output_dir) if args.output_dir else None,
            base_url=args.base_url,
            org_id=args.org_id,
            template_id=args.template_id,
            token=args.token,
            persist_dir=Path(args.persist_dir) if args.persist_dir else None,
        )
    except PlannerError as exc:
        ap.error(str(exc))
        return

    print(f"Plan written to {result.plan_path}")
    print(f"Final written to {result.final_path}")
    if result.errors:
        print("Encountered planner issues:")
        for err in result.errors:
            print(f" - {err}")


if __name__ == "__main__":  # pragma: no cover - CLI entry
    main()
