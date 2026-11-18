"""Pinned Mist read-operation catalog and schema/live field discovery."""
from __future__ import annotations

from standards_errors import StandardsValidationError

import copy
import json
import re
from functools import lru_cache
from pathlib import Path
from typing import Any

SENSITIVE = re.compile(r"password|secret|token|private.?key|auth.?key|shared.?key|api.?key|passphrase|community|psk", re.I)


@lru_cache(maxsize=1)
def catalog():
    return json.loads(Path(__file__).with_name("mist_standards_catalog.json").read_text(encoding="utf-8"))


def operation(operation_id):
    result = next((op for op in catalog()["operations"] if op["id"] == operation_id), None)
    if result is None or not result["supported"]:
        raise StandardsValidationError("Choose a supported passive JSON operation from the Mist catalog")
    return result


def sanitized(value: Any, depth=0):
    if depth > 8:
        return "…"
    if isinstance(value, dict):
        return {str(k): "[redacted]" if SENSITIVE.search(str(k)) else sanitized(v, depth + 1)
                for k, v in list(value.items())[:40]}
    if isinstance(value, list):
        return [sanitized(v, depth + 1) for v in value[:10]]
    return value[:300] if isinstance(value, str) else value


def schema_fields(operation_id, record_path=None, collection=False):
    return copy.deepcopy(_schema_fields(operation_id, tuple(record_path or []), collection))


@lru_cache(maxsize=256)
def _schema_fields(operation_id, record_path=(), collection=False):
    op = operation(operation_id)
    result = {}

    def walk(node, path, seen, description=""):
        if len(path) > 14 or len(result) >= 12000:
            return
        if "$ref" in node:
            ref = node["$ref"]
            if ref in seen:
                return
            walk(catalog()["refs"].get(ref, {}), path, seen | {ref}, description)
            return
        for branch in ("allOf", "oneOf", "anyOf"):
            for child in node.get(branch, []):
                walk(child, path, seen, node.get("description", description))
        kind = node.get("type") or ("object" if "properties" in node else "unknown")
        if path:
            key = json.dumps(path)
            item = result.setdefault(key, {"path": path, "types": [], "description": "", "origin": "schema"})
            if kind not in item["types"]:
                item["types"].append(kind)
            item["description"] = str(node.get("description") or description)[:500]
            if "enum" in node:
                item["enum"] = node["enum"]
        for name, child in node.get("properties", {}).items():
            walk(child, path + [name], seen)
        if isinstance(node.get("additionalProperties"), dict):
            walk(node["additionalProperties"], path + ["*"], seen)
        if "items" in node:
            # List responses describe records, whereas nested arrays retain a wildcard.
            walk(node["items"], path + (["*"] if path or collection else []), seen)

    walk(op["schema"], [], set())
    fields = list(result.values())
    prefix = list(record_path)
    if prefix:
        if not collection and any(f["path"] == prefix and "array" in f["types"] for f in fields):
            prefix.append("*")
        fields = [{**f, "path": f["path"][len(prefix):]} for f in fields
                  if f["path"][:len(prefix)] == prefix and len(f["path"]) > len(prefix)]
    return fields


def discover(operation_id, records=(), record_path=None, collection=False):
    fields = {json.dumps(f["path"]): copy.deepcopy(f) for f in schema_fields(operation_id, record_path, collection)}

    def walk(value, path, depth=0):
        if depth > 14 or len(fields) >= 15000:
            return
        if path:
            key = json.dumps(path)
            kind = ("null" if value is None else "boolean" if isinstance(value, bool) else
                    "number" if isinstance(value, (int, float)) else "object" if isinstance(value, dict) else
                    "array" if isinstance(value, list) else "string")
            field = fields.setdefault(key, {"path": path, "types": [], "description": "Observed in Mist", "origin": "observed"})
            if kind not in field["types"]:
                field["types"].append(kind)
            # Do not return entire objects, identifiers, or secret values as samples.
            if kind not in ("object", "array"):
                field["example"] = "[redacted]" if any(SENSITIVE.search(str(x)) for x in path) else sanitized(value)
        if isinstance(value, dict):
            for key, child in list(value.items())[:500]:
                walk(child, path + [key], depth + 1)
        elif isinstance(value, list):
            for child in value[:20]:
                walk(child, path + ["*"], depth + 1)

    for record in list(records)[:100]:
        walk(record, [])
    return sorted(fields.values(), key=lambda f: json.dumps(f["path"]))


def default_sources():
    specs = [
        ("device_config", "Device configuration", "listSiteDevices", "device", "page", []),
        ("device_stats", "Device statistics", "listSiteDevicesStats", "device", "page", []),
        ("site", "Site details", "getSiteInfo", "site", "none", []),
        ("site_settings", "Site settings", "getSiteSetting", "site", "none", []),
        ("derived_settings", "Derived site settings", "getSiteSettingDerived", "site", "none", []),
        ("templates", "Site network templates", "listSiteNetworkTemplatesDerived", "site", "none", []),
        ("inventory", "Organization inventory", "getOrgInventory", "device", "page", []),
    ]
    result = []
    for sid, name, oid, scope, pagination, record_path in specs:
        op = operation(oid)
        query_names = {p["name"] for p in op["parameters"] if p["in"] == "query"}
        result.append({"id": sid, "name": name, "operation": oid, "scope": scope,
                       "record_path": record_path, "identity_path": ["id"], "mac_path": ["mac"],
                       "pagination": pagination if "page" in query_names else "none",
                       "parameters": {}, "device_types": ["ap", "switch", "gateway"] if "type" in query_names else [],
                       "bindings": {}, "revision": 1})
    return result
