"""Installation-local policy catalog with atomic migration, revisions and recovery."""
from __future__ import annotations

import copy
import json
import os
from pathlib import Path
import tempfile
from datetime import datetime, timezone

from audit_exceptions import _locked
from standards_catalog import default_sources
from standards_collector import validate_source
from standards_engine import validate_policy, semantic_hash
from standards_specialists import seed_policies, validate_specialist

STORE_PATH = Path(__file__).resolve().parent / "data" / "standards.json"


class StoreError(ValueError):
    pass


class RevisionConflict(StoreError):
    pass


def path():
    return Path(os.environ.get("STANDARDS_STORE_PATH", str(STORE_PATH)))


def validate_document(document):
    if not isinstance(document, dict) or document.get("version") != 1 or type(document.get("revision")) is not int:
        raise StoreError("Unsupported standards document")
    if not isinstance(document.get("policies"), list) or not isinstance(document.get("sources"), list):
        raise StoreError("Standards policies and sources must be lists")
    if len(document["policies"]) > 1000 or len(document["sources"]) > 200:
        raise StoreError("Catalog exceeds 1,000 policies or 200 sources")
    for collection in (document["sources"], document["policies"]):
        ids = [entry.get("id") for entry in collection if isinstance(entry, dict)]
        if len(ids) != len(collection) or len(set(ids)) != len(ids):
            raise StoreError("Catalog contains invalid or duplicate entries")
        if any(type(entry.get("revision")) is not int or entry["revision"] < 1 for entry in collection):
            raise StoreError("Catalog entries require positive revisions")
    for source in document["sources"]:
        validate_source(source)
    for policy in document["policies"]:
        validate_policy(policy, document["sources"], validate_specialist)
    if not any(s["id"] == "device_config" and s["operation"] == "listSiteDevices" and s["scope"] == "device"
               for s in document["sources"]):
        raise StoreError("The device configuration target source must remain registered")
    population = next(s for s in document["sources"] if s["id"] == "device_config")
    baseline = next(s for s in default_sources() if s["id"] == "device_config")
    if any(population.get(key) != baseline.get(key) for key in ("operation", "scope", "record_path", "identity_path", "mac_path", "pagination", "parameters", "bindings", "device_types")):
        raise StoreError("The target population mapping is fixed. Add a separate source for filtered data.")
    return document


def atomic_write(target, data):
    target.parent.mkdir(parents=True, exist_ok=True)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=target.parent,
                                         prefix=".standards-", suffix=".tmp", delete=False) as handle:
            temporary = Path(handle.name)
            json.dump(data, handle, indent=2, allow_nan=False)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, target)
    finally:
        if temporary and temporary.exists():
            temporary.unlink()


def _read(target):
    try:
        return validate_document(json.loads(target.read_text(encoding="utf-8")))
    except (ValueError, OSError, TypeError, KeyError) as exc:
        raise StoreError("Standards could not be loaded. Restore a validated backup from Standards; no policies were activated.") from exc


def _load_locked(target):
    if target.exists():
        return _read(target)
    document = {"version": 1, "revision": 1, "migrated_at": datetime.now(timezone.utc).isoformat(),
                "policies": seed_policies(), "sources": default_sources()}
    for policy in document["policies"]:
        policy["imported_semantics"] = semantic_hash(policy)
    try:
        validate_document(document)
    except (ValueError, TypeError, KeyError) as exc:
        raise StoreError(f"Standards migration failed validation: {exc}. Existing configuration was retained.") from exc
    # The initial import remains available even after later policy changes.
    atomic_write(target.with_suffix(".import.json"), document)
    atomic_write(target, document)
    return document


def load():
    target = path()
    with _locked(target):
        return copy.deepcopy(_load_locked(target))


def save_entry(collection, entry, expected_revision):
    if collection not in ("policies", "sources") or not isinstance(entry, dict):
        raise StoreError("Invalid catalog entry")
    target = path()
    with _locked(target):
        current = _load_locked(target)
        document = copy.deepcopy(current)
        existing = next((x for x in document[collection] if x["id"] == entry.get("id")), None)
        actual_revision = existing["revision"] if existing else 0
        if type(expected_revision) is not int or expected_revision != actual_revision:
            raise RevisionConflict("This entry changed. Reload it before saving your edits.")
        replacement = {**copy.deepcopy(entry), "revision": actual_revision + 1}
        replacement.pop("_source_semantics", None)
        replacement.pop("imported_semantics", None)
        if existing and existing.get("imported_semantics"):
            replacement["imported_semantics"] = existing["imported_semantics"]
        if existing:
            document[collection][document[collection].index(existing)] = replacement
        else:
            document[collection].append(replacement)
        document["revision"] += 1
        validate_document(document)
        atomic_write(target.with_suffix(".backup.json"), current)
        atomic_write(target, document)
        return replacement


def restore(which, expected_revision):
    if which not in ("backup", "import"):
        raise StoreError("Choose the previous revision or initial import")
    target = path()
    with _locked(target):
        if target.exists():
            try:
                current = _read(target)
            except StoreError:
                current = None
        else:
            current = None
        if current and expected_revision != current["revision"]:
            raise RevisionConflict("The catalog changed. Reload before restoring.")
        recovered = _read(target.with_suffix(f".{which}.json"))
        if current:
            recovered["revision"] = current["revision"] + 1
            for collection in ("sources", "policies"):
                revisions = {e["id"]: e["revision"] for e in current[collection]}
                for entry in recovered[collection]:
                    entry["revision"] = max(entry["revision"], revisions.get(entry["id"], 0)) + 1
            atomic_write(target.with_suffix(".backup.json"), current)
        else:
            # Preserve malformed data for inspection, without overwriting a valid backup.
            if target.exists():
                atomic_write(target.with_suffix(".invalid.json"), {"raw": target.read_text(encoding="utf-8", errors="replace")})
            recovered["revision"] += 1
        validate_document(recovered)
        atomic_write(target, recovered)
        return recovered
