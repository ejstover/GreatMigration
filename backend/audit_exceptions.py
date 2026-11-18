"""Local, value-specific audit approvals. No device configuration is written here."""

from __future__ import annotations

import copy
import hashlib
import json
import os
import tempfile
import threading
import time
import uuid
import re
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping, Sequence

EXCEPTIONS_PATH = Path(__file__).resolve().parent / "exceptions.json"
_THREAD_LOCK = threading.RLock()
IDENTITY_FIELDS = ("origin", "org_id", "site_id", "device_id", "check_id", "path")
SUPPORTED_CHECK_IDS = frozenset({
    "configuration_overrides", "switch_template_configuration", "device_naming_convention",
    "required_site_variables", "firmware_management", "cloud_management", "spare_switch_presence",
    "virtual_chassis_roles",
})


def supported_check_id(check_id):
    # Validate stored identities without consulting mutable or unavailable policy storage.
    return check_id in SUPPORTED_CHECK_IDS or bool(isinstance(check_id, str) and re.fullmatch(r"custom_[A-Za-z0-9_-]{1,73}", check_id))


class ExceptionStoreError(ValueError):
    """The approval store could not be read or safely updated."""


def canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)


def fingerprint(candidate: Mapping[str, Any]) -> str:
    evidence = {key: candidate[key] for key in (*IDENTITY_FIELDS, "observed", "expected")}
    return hashlib.sha256(canonical(evidence).encode("utf-8")).hexdigest()


def candidate_for(context: Any, check_id: str, device_id: str | None, path: str,
                  observed: Any, expected: Any, origin: str = "") -> dict[str, Any] | None:
    org_id = context.site.get("org_id") or context.setting.get("org_id")
    origin = (origin or context.mist_base_url).rstrip("/")
    # Never approve a device using its display name, or an unknown organization.
    if not org_id or not origin or not context.site_id:
        return None
    result = {
        "origin": origin, "org_id": str(org_id), "site_id": context.site_id,
        "device_id": device_id, "check_id": check_id, "path": path,
        "observed": copy.deepcopy(observed), "expected": copy.deepcopy(expected),
    }
    result["fingerprint"] = fingerprint(result)
    return result


def matching_record(candidate: Mapping[str, Any], records: Sequence[Mapping[str, Any]]) -> Mapping[str, Any] | None:
    return next((record for record in records
                 if not record.get("revoked_at") and record["fingerprint"] == candidate["fingerprint"]), None)


def load_records(path: Path | None = None) -> list[dict[str, Any]]:
    path = path or EXCEPTIONS_PATH
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(document, dict) or document.get("version") != 1 or not isinstance(document.get("exceptions"), list):
            raise ValueError("Expected a version 1 exception document")
        records = document["exceptions"]
        ids: set[str] = set()
        for record in records:
            if not isinstance(record, dict):
                raise ValueError("Invalid exception record")
            for key in (*IDENTITY_FIELDS, "id", "reason", "approved_by", "approved_at", "fingerprint"):
                if key == "device_id" and record.get(key) is None:
                    continue
                if not isinstance(record.get(key), str) or not record[key].strip():
                    raise ValueError(f"Invalid exception field: {key}")
            if not supported_check_id(record["check_id"]):
                raise ValueError("Unsupported exception check")
            if record["id"] in ids or record["fingerprint"] != fingerprint(record):
                raise ValueError("Duplicate ID or invalid exception evidence")
            ids.add(record["id"])
            datetime.fromisoformat(record["approved_at"])
            if record.get("revoked_at"):
                datetime.fromisoformat(record["revoked_at"])
                if not isinstance(record.get("revoked_by"), str) or not record["revoked_by"].strip():
                    raise ValueError("Missing revocation actor")
        return records
    except FileNotFoundError:
        return []
    except (OSError, ValueError, TypeError, KeyError) as exc:
        raise ExceptionStoreError("Cannot read audit exceptions; check server configuration") from exc


@contextmanager
def _locked(path: Path):
    """Serialize read-modify-write across threads and Windows/POSIX workers."""
    with _THREAD_LOCK:
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.with_suffix(path.suffix + ".lock").open("a+b") as handle:
            handle.seek(0, os.SEEK_END)
            if handle.tell() == 0:
                handle.write(b"\0")
                handle.flush()
            deadline = time.monotonic() + 10
            while True:
                try:
                    if os.name == "nt":
                        import msvcrt
                        handle.seek(0)
                        msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
                    else:
                        import fcntl
                        fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                    break
                except OSError:
                    if time.monotonic() >= deadline:
                        raise ExceptionStoreError("Audit exceptions are busy; retry the operation")
                    time.sleep(0.05)
            try:
                yield
            finally:
                if os.name == "nt":
                    handle.seek(0)
                    msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
                else:
                    fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


def _write(path: Path, records: list[dict[str, Any]]) -> None:
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=path.parent,
                                         prefix=".exceptions-", suffix=".tmp", delete=False) as handle:
            temporary = Path(handle.name)
            json.dump({"version": 1, "exceptions": records}, handle, indent=2, ensure_ascii=False, allow_nan=False)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


@contextmanager
def locked_records():
    """Hold the approval policy stable while a remediation is evaluated/executed."""
    try:
        with _locked(EXCEPTIONS_PATH):
            yield load_records()
    except OSError as exc:
        raise ExceptionStoreError("Cannot lock audit exceptions; check server configuration") from exc


def approve(candidate: Mapping[str, Any], reason: str, actor: str, *, site_name: str = "",
            device_name: str = "", path: Path | None = None) -> dict[str, Any]:
    if not isinstance(reason, str) or not reason.strip() or len(reason.strip()) > 2000:
        raise ValueError("A reason of 1–2000 characters is required")
    try:
        if (not supported_check_id(candidate["check_id"]) or candidate["fingerprint"] != fingerprint(candidate)
                or not actor.strip() or any(not isinstance(candidate.get(key), str) or not candidate[key].strip()
                                            for key in IDENTITY_FIELDS if key != "device_id")):
            raise ValueError("Invalid exception evidence or approver")
    except (KeyError, TypeError, AttributeError) as exc:
        raise ValueError("Invalid exception evidence or approver") from exc
    path = path or EXCEPTIONS_PATH
    try:
        with _locked(path):
            records = load_records(path)
            existing = matching_record(candidate, records)
            if existing:
                return dict(existing)
            record = copy.deepcopy(dict(candidate))
            record.update(id=str(uuid.uuid4()), reason=reason.strip(), approved_by=actor,
                          approved_at=datetime.now(timezone.utc).isoformat(), site_name=site_name,
                          device_name=device_name, revoked_at=None, revoked_by=None)
            records.append(record)
            _write(path, records)
            return record
    except OSError as exc:
        raise ExceptionStoreError("Cannot save audit exception; check server configuration") from exc


def revoke(exception_id: str, actor: str, *, path: Path | None = None) -> dict[str, Any]:
    path = path or EXCEPTIONS_PATH
    try:
        with _locked(path):
            records = load_records(path)
            record = next((item for item in records if item["id"] == exception_id), None)
            if record is None:
                raise KeyError(exception_id)
            if not record.get("revoked_at"):
                record.update(revoked_at=datetime.now(timezone.utc).isoformat(), revoked_by=actor)
                _write(path, records)
            return record
    except OSError as exc:
        raise ExceptionStoreError("Cannot revoke audit exception; check server configuration") from exc
