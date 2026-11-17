from __future__ import annotations

import json
from security import record_path
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional


DATA_DIR = Path(__file__).resolve().parent / "data" / "conversion_sets"


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def run_id_now() -> str:
    return utc_now().strftime("%Y%m%dT%H%M%SZ")


def sanitize_project_key(value: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9._-]+", "_", str(value or "").strip()).strip("._-")
    return cleaned[:80] or "project"


def _read_json(path: Path, default: Any) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return default
    except Exception:
        return default


def _project_dir(project_key: str) -> Path:
    return DATA_DIR / sanitize_project_key(project_key)


def _index_path(project_key: str) -> Path:
    return _project_dir(project_key) / "index.json"


def ensure_project_dir(project_key: str) -> Path:
    path = _project_dir(project_key)
    path.mkdir(parents=True, exist_ok=True)
    return path


def save_conversion_set(project_name: str, payload: Mapping[str, Any]) -> Dict[str, Any]:
    project_key = sanitize_project_key(project_name)
    ensure_project_dir(project_key)
    conversion_set_id = str(payload.get("conversion_set_id") or "").strip() or run_id_now()
    record = dict(payload)
    record["conversion_set_id"] = conversion_set_id
    record["project_name"] = str(project_name or "").strip()
    record["project_key"] = project_key
    record.setdefault("created_at", utc_now().isoformat())
    path = record_path(_project_dir(project_key), conversion_set_id)
    path.write_text(json.dumps(record, indent=2, sort_keys=True), encoding="utf-8")

    summary = {
        "conversion_set_id": conversion_set_id,
        "project_name": record.get("project_name"),
        "project_key": project_key,
        "created_at": record.get("created_at"),
        "label": record.get("label") or f"Conversion set {conversion_set_id}",
        "row_count": len(record.get("rows")) if isinstance(record.get("rows"), list) else 0,
    }
    index = _read_json(_index_path(project_key), {"project_key": project_key, "items": []})
    items = index.get("items")
    if not isinstance(items, list):
        items = []
    items = [
        item for item in items
        if not (isinstance(item, Mapping) and str(item.get("conversion_set_id") or "") == conversion_set_id)
    ]
    items.append(summary)
    items.sort(key=lambda item: str(item.get("conversion_set_id") or ""), reverse=True)
    index["project_key"] = project_key
    index["items"] = items
    _index_path(project_key).write_text(json.dumps(index, indent=2, sort_keys=True), encoding="utf-8")
    return summary


def load_conversion_set(project_key: str, conversion_set_id: str) -> Optional[Dict[str, Any]]:
    data = _read_json(record_path(_project_dir(project_key), conversion_set_id), None)
    return data if isinstance(data, dict) else None


def list_conversion_sets(project_key: str) -> Dict[str, Any]:
    data = _read_json(_index_path(project_key), {"project_key": sanitize_project_key(project_key), "items": []})
    if not isinstance(data, dict):
        return {"project_key": sanitize_project_key(project_key), "items": []}
    items = data.get("items")
    if not isinstance(items, list):
        data["items"] = []
    return data
