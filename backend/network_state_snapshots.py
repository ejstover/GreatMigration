from __future__ import annotations

import json
from security import record_path
import re
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Set, Tuple


DATA_DIR = Path(__file__).resolve().parent / "data" / "network_state"
MAC_RE = re.compile(r"([0-9A-Fa-f]{4}[.:-]){2}[0-9A-Fa-f]{4}|([0-9A-Fa-f]{2}[.:-]){5}[0-9A-Fa-f]{2}")
VLAN_ID_RE = re.compile(r"^\d+$")


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def run_id_now() -> str:
    return utc_now().strftime("%Y%m%dT%H%M%SZ")


def sanitize_project_key(value: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9._-]+", "_", str(value or "").strip()).strip("._-")
    return cleaned[:80] or "project"


def normalize_mac(value: Any) -> str:
    text = str(value or "").strip().lower()
    if not text:
        return ""
    hexchars = re.sub(r"[^0-9a-f]", "", text)
    if len(hexchars) != 12:
        return ""
    return ":".join(hexchars[i:i + 2] for i in range(0, 12, 2))


def normalize_interface_name(value: Any) -> str:
    text = str(value or "").strip()
    if not text:
        return ""
    lowered = text.lower().replace(" ", "")
    replacements = {
        "tengigabitethernet": "Te",
        "gigabitethernet": "Gi",
        "fastethernet": "Fa",
        "twogigabitethernet": "Tw",
        "fortygigabitethernet": "Fo",
        "hundredgige": "Hu",
        "hundredgigabitethernet": "Hu",
        "port-channel": "Po",
        "portchannel": "Po",
        "ethernet": "Eth",
    }
    for prefix, short in replacements.items():
        if lowered.startswith(prefix):
            suffix = text[len(prefix):].strip()
            return f"{short}{suffix}"
    return text


def extract_hostname_from_running_config(text: str) -> str:
    for line in (text or "").splitlines():
        match = re.match(r"\s*hostname\s+([^\s]+)", line, flags=re.IGNORECASE)
        if match:
            return match.group(1).strip()
    return ""


def extract_legacy_device_aliases(device: Mapping[str, Any]) -> Set[str]:
    aliases: Set[str] = set()
    for key in ("label", "host"):
        value = str(device.get(key) or "").strip()
        if value:
            aliases.add(value.lower())
    running_config = device.get("running_config")
    if isinstance(running_config, Mapping):
        filename = str(running_config.get("filename") or "").strip()
        if filename:
            aliases.add(filename.lower())
            aliases.add(Path(filename).stem.lower())
        hostname = extract_hostname_from_running_config(str(running_config.get("text") or ""))
        if hostname:
            aliases.add(hostname.lower())
    return {alias for alias in aliases if alias}


def _extract_mac_tokens(text: str) -> List[str]:
    return [normalize_mac(match.group(0)) for match in MAC_RE.finditer(text or "")]


def parse_legacy_mac_table(raw_text: str) -> List[Dict[str, Any]]:
    observations: List[Dict[str, Any]] = []
    if not raw_text:
        return observations

    for line in raw_text.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        lowered = stripped.lower()
        if lowered.startswith(("vlan", "----", "total", "legend")):
            continue

        macs = [mac for mac in _extract_mac_tokens(stripped) if mac]
        if not macs:
            continue
        mac = macs[0]

        tokens = stripped.split()
        vlan_id: Optional[int] = None
        interface_name = ""

        for idx, token in enumerate(tokens):
            candidate = token.strip(",")
            if vlan_id is None and VLAN_ID_RE.match(candidate):
                try:
                    vlan_id = int(candidate)
                except ValueError:
                    vlan_id = None
            if normalize_mac(candidate) == mac:
                for trailing in tokens[idx + 1:]:
                    maybe_if = normalize_interface_name(trailing.strip(","))
                    if maybe_if and re.search(r"[A-Za-z]+[0-9/]+", maybe_if):
                        interface_name = maybe_if
                        break
                break

        if not interface_name:
            match = re.search(r"((?:[A-Za-z][A-Za-z-]*)(?:\d+/)*\d+)$", stripped)
            if match:
                interface_name = normalize_interface_name(match.group(1))

        observations.append(
            {
                "client_mac": mac,
                "vlan_id": vlan_id,
                "source_interface": interface_name,
                "raw_line": stripped,
            }
        )

    return observations


def project_dir(project_key: str) -> Path:
    return DATA_DIR / sanitize_project_key(project_key)


def index_path(project_key: str) -> Path:
    return project_dir(project_key) / "index.json"


def ensure_project_dir(project_key: str) -> Path:
    path = project_dir(project_key)
    path.mkdir(parents=True, exist_ok=True)
    return path


def _read_json(path: Path, default: Any) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return default
    except Exception:
        return default


def save_run(project_key: str, run: Mapping[str, Any]) -> Path:
    target_dir = ensure_project_dir(project_key)
    run_id = str(run.get("run_id") or "").strip() or run_id_now()
    path = record_path(target_dir, run_id)
    path.write_text(json.dumps(run, indent=2, sort_keys=True), encoding="utf-8")
    return path


def load_run(project_key: str, run_id: str) -> Optional[Dict[str, Any]]:
    path = record_path(project_dir(project_key), run_id)
    data = _read_json(path, None)
    return data if isinstance(data, dict) else None


def update_project_index(project_key: str, summary: Mapping[str, Any]) -> Dict[str, Any]:
    ensure_project_dir(project_key)
    path = index_path(project_key)
    current = _read_json(path, {"project_key": project_key, "runs": []})
    runs = current.get("runs")
    if not isinstance(runs, list):
        runs = []
    filtered = [
        item for item in runs
        if not (isinstance(item, Mapping) and str(item.get("run_id") or "") == str(summary.get("run_id") or ""))
    ]
    filtered.append(dict(summary))
    filtered.sort(key=lambda item: str(item.get("run_id") or ""), reverse=True)
    current["project_key"] = project_key
    current["runs"] = filtered
    path.write_text(json.dumps(current, indent=2, sort_keys=True), encoding="utf-8")
    return current


def load_project_history(project_key: str) -> Dict[str, Any]:
    data = _read_json(index_path(project_key), {"project_key": sanitize_project_key(project_key), "runs": []})
    if not isinstance(data, dict):
        return {"project_key": sanitize_project_key(project_key), "runs": []}
    runs = data.get("runs")
    if not isinstance(runs, list):
        data["runs"] = []
    return data


def build_baseline_summary(run: Mapping[str, Any]) -> Dict[str, Any]:
    observations = run.get("legacy_mac_observations")
    mappings = run.get("port_mappings")
    devices = run.get("devices")
    return {
        "run_id": run.get("run_id"),
        "run_type": "baseline",
        "project_name": run.get("project_name"),
        "created_at": run.get("created_at"),
        "device_count": len(devices) if isinstance(devices, list) else 0,
        "legacy_mac_count": len(observations) if isinstance(observations, list) else 0,
        "mapping_count": len(mappings) if isinstance(mappings, list) else 0,
        "label": f"Baseline {run.get('run_id')}",
    }


def build_compare_summary(run: Mapping[str, Any]) -> Dict[str, Any]:
    counts = run.get("summary") if isinstance(run.get("summary"), Mapping) else {}
    return {
        "run_id": run.get("run_id"),
        "run_type": "compare",
        "project_name": run.get("project_name"),
        "created_at": run.get("created_at"),
        "baseline_run_id": run.get("baseline_run_id"),
        "label": f"Compare {run.get('run_id')}",
        "counts": dict(counts),
    }


def _make_lookup_keys(*values: Any) -> Set[str]:
    keys: Set[str] = set()
    for value in values:
        text = str(value or "").strip().lower()
        if not text:
            continue
        keys.add(text)
        keys.add(Path(text).stem.lower())
    return keys


def assign_row_mapping_to_legacy_device(
    legacy_devices: Sequence[Mapping[str, Any]],
    row_source_file: str,
) -> Optional[Mapping[str, Any]]:
    target_keys = _make_lookup_keys(row_source_file)
    for device in legacy_devices:
        aliases = extract_legacy_device_aliases(device)
        if aliases & target_keys:
            return device
    return None


def build_baseline_run(
    *,
    project_name: str,
    operator: str,
    job_id: str,
    devices: Sequence[Mapping[str, Any]],
    port_mappings: Sequence[Mapping[str, Any]],
) -> Dict[str, Any]:
    created_at = utc_now().isoformat()
    project_key = sanitize_project_key(project_name)
    observations: List[Dict[str, Any]] = []

    for device in devices:
        command_outputs = device.get("command_outputs")
        if not isinstance(command_outputs, Mapping):
            continue
        mac_table = str(
            command_outputs.get("show mac address-table")
            or command_outputs.get("show mac-address-table")
            or command_outputs.get("show mac address-table dynamic")
            or ""
        )
        aliases = sorted(extract_legacy_device_aliases(device))
        device_label = str(device.get("label") or device.get("host") or "").strip()
        for item in parse_legacy_mac_table(mac_table):
            entry = dict(item)
            entry["source_device"] = device_label
            entry["source_device_aliases"] = aliases
            observations.append(entry)

    run = {
        "run_id": run_id_now(),
        "run_type": "baseline",
        "project_name": str(project_name or "").strip(),
        "project_key": project_key,
        "created_at": created_at,
        "operator": operator,
        "job_id": job_id,
        "devices": list(devices),
        "port_mappings": list(port_mappings),
        "legacy_mac_observations": observations,
    }
    return run


def extract_mist_mac_observations(
    *,
    sites: Sequence[Mapping[str, Any]],
    site_devices: Mapping[str, Sequence[Mapping[str, Any]]],
    wired_clients: Mapping[str, Sequence[Mapping[str, Any]]],
) -> List[Dict[str, Any]]:
    device_identity: Dict[Tuple[str, str], Dict[str, Any]] = {}
    for site in sites:
        site_id = str(site.get("id") or "").strip()
        for device in site_devices.get(site_id, []) or []:
            mac = normalize_mac(device.get("mac"))
            if mac:
                device_identity[(site_id, mac)] = dict(device)

    observations: List[Dict[str, Any]] = []
    for site in sites:
        site_id = str(site.get("id") or "").strip()
        site_name = str(site.get("name") or "").strip()
        for client in wired_clients.get(site_id, []) or []:
            client_mac = normalize_mac(client.get("mac"))
            switch_mac = normalize_mac(client.get("device_mac"))
            port_id = str(client.get("port_id") or client.get("port") or client.get("interface") or "").strip()
            if not client_mac or not site_id or not port_id:
                continue
            matched_device = device_identity.get((site_id, switch_mac), {})
            observations.append(
                {
                    "client_mac": client_mac,
                    "site_id": site_id,
                    "site_name": site_name,
                    "device_mac": switch_mac,
                    "device_id": matched_device.get("id"),
                    "device_name": matched_device.get("name") or matched_device.get("hostname"),
                    "port_id": port_id,
                    "raw": dict(client),
                }
            )
    return observations


def _build_expected_mapping_index(
    mappings: Sequence[Mapping[str, Any]],
) -> Dict[Tuple[str, str], List[Dict[str, Any]]]:
    index: Dict[Tuple[str, str], List[Dict[str, Any]]] = defaultdict(list)
    for mapping in mappings:
        aliases = mapping.get("source_device_aliases")
        if not isinstance(aliases, list):
            aliases = []
        interface_name = normalize_interface_name(mapping.get("source_interface"))
        if not interface_name:
            continue
        for alias in aliases:
            key = (str(alias or "").strip().lower(), interface_name)
            if key[0]:
                index[key].append(dict(mapping))
    return index


def compare_baseline_to_mist(
    *,
    project_name: str,
    baseline_run: Mapping[str, Any],
    mist_observations: Sequence[Mapping[str, Any]],
) -> Dict[str, Any]:
    by_mac: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for item in mist_observations:
        mac = normalize_mac(item.get("client_mac"))
        if mac:
            by_mac[mac].append(dict(item))

    mapping_index = _build_expected_mapping_index(
        baseline_run.get("port_mappings") if isinstance(baseline_run.get("port_mappings"), list) else []
    )

    results: List[Dict[str, Any]] = []
    seen_pre_macs: Set[str] = set()

    for observation in baseline_run.get("legacy_mac_observations", []) if isinstance(baseline_run.get("legacy_mac_observations"), list) else []:
        mac = normalize_mac(observation.get("client_mac"))
        if not mac:
            continue
        seen_pre_macs.add(mac)
        aliases = observation.get("source_device_aliases")
        if not isinstance(aliases, list):
            aliases = []
        source_if = normalize_interface_name(observation.get("source_interface"))
        expected_mappings: List[Dict[str, Any]] = []
        for alias in aliases:
            expected_mappings.extend(mapping_index.get((str(alias or "").strip().lower(), source_if), []))

        current = by_mac.get(mac, [])
        if len(current) > 1:
            results.append(
                {
                    "client_mac": mac,
                    "status": "ambiguous_multiple_locations",
                    "source_device": observation.get("source_device"),
                    "source_interface": source_if,
                    "expected": expected_mappings,
                    "actual": current,
                }
            )
            continue
        if not current:
            results.append(
                {
                    "client_mac": mac,
                    "status": "missing_in_current_mist_state",
                    "source_device": observation.get("source_device"),
                    "source_interface": source_if,
                    "expected": expected_mappings,
                    "actual": [],
                }
            )
            continue

        actual = current[0]
        matched_expected_port = any(
            str(item.get("site_id") or "") == str(actual.get("site_id") or "")
            and str(item.get("device_id") or "") == str(actual.get("device_id") or "")
            and str(item.get("target_port") or "") == str(actual.get("port_id") or "")
            for item in expected_mappings
        )
        if matched_expected_port:
            status = "matched_expected_port"
        elif any(
            str(item.get("site_id") or "") == str(actual.get("site_id") or "")
            and str(item.get("device_id") or "") == str(actual.get("device_id") or "")
            for item in expected_mappings
        ):
            status = "matched_expected_switch_wrong_port"
        elif any(str(item.get("site_id") or "") == str(actual.get("site_id") or "") for item in expected_mappings):
            status = "matched_same_site_wrong_switch"
        else:
            status = "matched_elsewhere"

        results.append(
            {
                "client_mac": mac,
                "status": status,
                "source_device": observation.get("source_device"),
                "source_interface": source_if,
                "expected": expected_mappings,
                "actual": [actual],
            }
        )

    for mac, items in by_mac.items():
        if mac in seen_pre_macs:
            continue
        results.append(
            {
                "client_mac": mac,
                "status": "new_post_only_mac",
                "expected": [],
                "actual": items,
            }
        )

    counts = Counter(str(item.get("status") or "unknown") for item in results)
    return {
        "run_id": run_id_now(),
        "run_type": "compare",
        "project_name": str(project_name or "").strip(),
        "project_key": sanitize_project_key(project_name),
        "created_at": utc_now().isoformat(),
        "baseline_run_id": baseline_run.get("run_id"),
        "summary": dict(counts),
        "results": results,
    }
