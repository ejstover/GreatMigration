"""Passive source collection, explicit identity mapping, and completeness tracking."""
from __future__ import annotations

from standards_errors import StandardsValidationError

import copy
import re
import time
from datetime import datetime, timezone
from urllib.parse import quote, urlencode

import requests

from security import mist_base_url
from standards_catalog import operation
from standards_engine import MISSING, Snapshot, path_value, validate_path

CONTEXT_PARAMETERS = {"org_id", "site_id", "device_id", "device_mac"}


def validate_source(source):
    if not isinstance(source, dict) or not isinstance(source.get("id"), str) or not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9_-]{0,79}", source["id"]):
        raise StandardsValidationError("Source ID must contain 1–80 letters, numbers, underscores, or hyphens")
    if not isinstance(source.get("name"), str) or not 1 <= len(source["name"].strip()) <= 200:
        raise StandardsValidationError("Enter a source name of 1–200 characters")
    op = operation(source.get("operation"))
    if source.get("scope") not in ("device", "site", "organization"):
        raise StandardsValidationError("Source scope must be device, site, or organization")
    for name in ("record_path", "identity_path", "mac_path"):
        validate_path(source.get(name, []))
        if "*" in source.get(name, []):
            raise StandardsValidationError("Source mappings must use concrete paths; use wildcard paths in policies")
    if source["scope"] == "device" and not source.get("identity_path") and not source.get("mac_path"):
        raise StandardsValidationError("Device sources require an identity or MAC path")
    if source.get("pagination", "none") not in ("none", "page", "start", "cursor"):
        raise StandardsValidationError("Choose no pagination, page, start, or cursor pagination")
    for name in ("parameters", "bindings"):
        if not isinstance(source.get(name, {}), dict):
            raise StandardsValidationError(f"{name} must be an object")
    known_query = {p["name"] for p in op["parameters"] if p["in"] == "query"}
    if set(source.get("parameters", {})) - known_query:
        raise StandardsValidationError("Source contains query parameters not documented by the operation")
    for name, value in source.get("parameters", {}).items():
        if type(value) not in (str, int, float, bool) or len(str(value)) > 500:
            raise StandardsValidationError("Source query parameters must be short scalar values")
    placeholders = set(re.findall(r"\{([^}]+)\}", op["path"]))
    if set(source.get("bindings", {})) - placeholders:
        raise StandardsValidationError("Bindings must name documented path parameters")
    for name in placeholders - CONTEXT_PARAMETERS:
        value = source.get("bindings", {}).get(name)
        if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9_.:-]{1,200}", value) or value in (".", ".."):
            raise StandardsValidationError(f"Supply a resource identifier for {name}")
    if source["scope"] == "organization" and placeholders & {"site_id", "device_id", "device_mac"}:
        raise StandardsValidationError("An organization source cannot bind site/device-specific endpoints")
    if source["scope"] == "site" and placeholders & {"device_id", "device_mac"}:
        raise StandardsValidationError("A site source cannot bind device-specific endpoints")
    if any(t not in ("ap", "switch", "gateway") for t in source.get("device_types", [])):
        raise StandardsValidationError("Unknown device type")
    mode = source.get("pagination", "none")
    if mode in ("page", "start") and mode not in known_query:
        raise StandardsValidationError("This operation does not document the selected pagination parameter")
    if mode == "start":
        parameter = next(p for p in op["parameters"] if p["name"] == "start" and p["in"] == "query")
        if not re.search(r"offset|index", parameter.get("description", ""), re.I):
            raise StandardsValidationError("This endpoint's start parameter is a time boundary, not an offset. Choose its documented cursor pagination.")
    if mode == "cursor":
        parameter = source.get("cursor_parameter", "cursor")
        if parameter not in known_query:
            raise StandardsValidationError("Choose the documented cursor query parameter")
        validate_path(source.get("next_cursor_path", []))
        if not source.get("next_cursor_path"):
            raise StandardsValidationError("Cursor pagination requires a response path for the next cursor")
    return source


class Collector:
    def __init__(self, base_url, headers, get=None):
        self.base_url = mist_base_url(base_url)
        self.headers = headers
        self.get = get or self.http_get
        self.cache = {}
        self.deadline = time.monotonic() + 120
        self.request_count = 0

    def http_get(self, path):
        for attempt in range(3):
            response = requests.get(self.base_url + path, headers=self.headers, timeout=30, allow_redirects=False)
            if response.status_code != 429:
                break
            if attempt < 2:
                try:
                    delay = min(max(float(response.headers.get("Retry-After", "1")), 0), 2)
                except ValueError:
                    delay = 1
                time.sleep(delay)
        if not 200 <= response.status_code < 300:
            raise StandardsValidationError(f"Mist returned HTTP {response.status_code}")
        return response.json()

    def cached_get(self, path):
        if path not in self.cache:
            if self.request_count >= 5000 or time.monotonic() > self.deadline:
                raise StandardsValidationError("Collection budget exceeded; narrow the audit scope and retry")
            self.request_count += 1
            self.cache[path] = self.get(path)
        return self.cache[path]

    def fetch(self, source, context):
        op = operation(source["operation"])
        bindings = {**source.get("bindings", {}), **context}
        path = op["path"]
        for name in re.findall(r"\{([^}]+)\}", path):
            value = bindings.get(name)
            if not value or str(value) in (".", ".."):
                raise StandardsValidationError(f"No value is available for {name}")
            path = path.replace("{" + name + "}", quote(str(value), safe=""))
        params = dict(source.get("parameters", {}))
        known_query = {p["name"] for p in op["parameters"] if p["in"] == "query"}
        for p in op["parameters"]:
            if p["in"] == "query" and p.get("required") and p["name"] not in params and p["name"] not in context:
                raise StandardsValidationError(f"Required query parameter {p['name']} has no value")
        for name in known_query & context.keys():
            params[name] = context[name]
        mode = source.get("pagination", "none")
        if mode != "none" and "limit" in known_query:
            params["limit"] = 1000
        output, seen, cursor = [], set(), None
        for page in range(1, 1001):
            query = dict(params)
            if mode == "page":
                query["page"] = page
            elif mode == "start":
                query["start"] = len(output)
            elif mode == "cursor" and cursor is not None:
                query[source.get("cursor_parameter", "cursor")] = cursor
            document = self.cached_get(path + ("?" + urlencode(sorted(query.items())) if query else ""))
            value = path_value(document, source.get("record_path", []))
            if value is MISSING:
                raise StandardsValidationError("The configured record path is absent from the response")
            if mode == "none":
                if isinstance(document, dict) and isinstance(document.get("total"), int) and isinstance(value, list) and document["total"] > len(value):
                    raise StandardsValidationError("Response is truncated; configure pagination before using this source")
                return value
            if not isinstance(value, list):
                raise StandardsValidationError("Paginated record mapping must resolve to an array")
            if not value:
                return output
            # A server ignoring page/start must never look like a complete inventory.
            marker = __import__("hashlib").sha256(__import__("json").dumps(value, sort_keys=True).encode()).hexdigest()
            if marker in seen:
                raise StandardsValidationError("Mist repeated a page; source collection is incomplete")
            seen.add(marker)
            output.extend(value)
            if len(output) > 100000:
                raise StandardsValidationError("Source exceeds the 100,000-record collection limit")
            if mode == "cursor":
                cursor = path_value(document, source["next_cursor_path"])
                if cursor is MISSING or cursor in (None, ""):
                    return output
                if not isinstance(cursor, (str, int)):
                    raise StandardsValidationError("Next cursor must be a scalar token")
            else:
                total = document.get("total") if isinstance(document, dict) else None
                if isinstance(total, int) and len(output) >= total:
                    return output
                if len(value) < query.get("limit", 1000):
                    return output
        raise StandardsValidationError("Source exceeded the pagination limit")

    def collect(self, sources, selected_contexts, org_sites=None, full_organization=False):
        source_map = {s["id"]: s for s in sources}
        snapshot = Snapshot(sources=source_map, collected_at=datetime.now(timezone.utc).isoformat())
        sites = [{"id": ctx.site_id, "name": ctx.site_name, "org_id": ctx.site.get("org_id") or ctx.setting.get("org_id")}
                 for ctx in selected_contexts]
        org_ids = {s["org_id"] for s in sites if s.get("org_id")}
        if any(not s.get("org_id") for s in sites):
            snapshot.errors.append({"source": "device_config", "org_id": None, "site_id": None, "error": "Site organization is unknown"})
        if full_organization:
            expanded = []
            for org_id in org_ids:
                try:
                    if org_sites:
                        org_data = org_sites(org_id)
                    else:
                        org_data = self.fetch({"operation": "listOrgSites", "record_path": [], "pagination": "page"}, {"org_id": org_id})
                    if not isinstance(org_data, list):
                        raise StandardsValidationError("Organization site list is unavailable")
                    expanded.extend({**s, "org_id": org_id} for s in org_data if isinstance(s, dict) and s.get("id"))
                    snapshot.complete_orgs.add(org_id)
                except (ValueError, requests.RequestException):
                    snapshot.errors.append({"source": "device_config", "org_id": org_id, "site_id": None, "error": "Organization site discovery failed"})
            # Keep selected sites even if discovery was incomplete.
            sites = list({s["id"]: s for s in sites + expanded}.values())
        for org_id in org_ids:
            snapshot.targets.append({"kind": "organization", "id": org_id, "org_id": org_id, "name": org_id})
        for site in sites:
            snapshot.targets.append({"kind": "site", "id": site["id"], "site_id": site["id"], "org_id": site.get("org_id"), "name": site.get("name", site["id"])})
        # Configuration establishes the target population and is never age-filtered.
        ordered = sorted(sources, key=lambda s: s["id"] != "device_config")
        for source in ordered:
            snapshot.records[source["id"]] = []
            op = operation(source["operation"])
            per_device = "{device_id}" in op["path"] or "{device_mac}" in op["path"]
            per_site = "{site_id}" in op["path"]
            contexts = [{"org_id": oid} for oid in org_ids]
            if per_site:
                contexts = [{"org_id": s.get("org_id"), "site_id": s["id"]} for s in sites]
            if per_device:
                contexts = [{"org_id": t["org_id"], "site_id": t["site_id"], "device_id": t["id"], "device_mac": t.get("mac"), "type": t.get("type")}
                            for t in snapshot.targets if t["kind"] == "device"]
            for context in contexts:
                types = source.get("device_types", []) or [None]
                for device_type in types:
                    try:
                        value = self.fetch(source, {**context, **({"type": device_type} if device_type else {})})
                        values = value if source["scope"] == "device" and isinstance(value, list) else [value]
                        for record in values:
                            wrapper = {"org_id": context.get("org_id"), "site_id": context.get("site_id") if per_site else None, "value": copy.deepcopy(record)}
                            if source["scope"] == "device":
                                if not isinstance(record, dict):
                                    raise StandardsValidationError("Device source records must be objects")
                                identity = path_value(record, source.get("identity_path", [])) if source.get("identity_path") else MISSING
                                mac = path_value(record, source.get("mac_path", [])) if source.get("mac_path") else MISSING
                                if identity in (MISSING, None, "") and mac in (MISSING, None, ""):
                                    raise StandardsValidationError("Record has no mapped identity or MAC")
                                wrapper.update(device_id=str(identity) if identity is not MISSING and identity else None, mac=mac if mac is not MISSING else None)
                                if source["id"] == "device_config":
                                    dtype = record.get("type") or device_type
                                    if dtype not in ("ap", "switch", "gateway"):
                                        raise StandardsValidationError("Device configuration record has no supported device type")
                                    target = {"kind": "device", "id": str(identity if identity is not MISSING and identity else mac),
                                              "org_id": context.get("org_id"), "site_id": context.get("site_id"), "type": dtype,
                                              "model": record.get("model"), "name": record.get("name", ""), "mac": record.get("mac")}
                                    if not any(t["kind"] == "device" and t["id"] == target["id"] and t.get("site_id") == target["site_id"] for t in snapshot.targets):
                                        snapshot.targets.append(target)
                            snapshot.records[source["id"]].append(wrapper)
                    except (ValueError, TypeError, KeyError, requests.RequestException) as exc:
                        snapshot.errors.append({"source": source["id"], **context, **({"type": device_type} if device_type else {}), "error": exc.public_message if isinstance(exc, StandardsValidationError) else "Mist source could not be collected; check connectivity and retry"})
                        if source["id"] == "device_config":
                            snapshot.complete_orgs.discard(context.get("org_id"))
        return snapshot
