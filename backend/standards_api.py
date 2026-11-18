"""Authenticated standards authoring, source discovery, and passive previews."""
from __future__ import annotations

import copy

from fastapi import APIRouter, Body, Request
from fastapi.responses import JSONResponse

import standards_store as store
from standards_catalog import catalog, discover, sanitized
from standards_collector import Collector, validate_source
from standards_engine import validate_policy
from standards_integration import build_runner
from standards_specialists import definitions, validate_specialist


def router(runtime):
    routes = APIRouter(prefix="/api/standards")

    def failure(exc):
        status = 409 if isinstance(exc, store.RevisionConflict) else 503 if isinstance(exc, store.StoreError) else 400
        return JSONResponse({"ok": False, "error": str(exc)}, status_code=status)

    def contexts(payload, base_url, specialist=False):
        base_url = runtime.mist_base_url(base_url)
        headers = runtime._mist_headers(runtime._load_mist_token())
        collector = Collector(base_url, headers)
        ids = payload.get("site_ids", [])
        if not isinstance(ids, list) or len(ids) > 2000 or any(not isinstance(s, str) or not s.strip() for s in ids):
            raise ValueError("Choose up to 2,000 site identifiers")
        if payload.get("entire_org"):
            org_id = payload.get("org_id")
            if not isinstance(org_id, str) or not org_id:
                raise ValueError("Choose an organization")
            sites = collector.fetch({"operation": "listOrgSites", "record_path": [], "pagination": "page"}, {"org_id": org_id})
            ids = [s["id"] for s in sites if isinstance(s, dict) and s.get("id")]
        if not ids:
            raise ValueError("Choose at least one site for a live preview")
        if specialist:
            result, errors = runtime._gather_site_contexts(base_url, headers, list(dict.fromkeys(ids)))
            if errors:
                raise ValueError("Some selected sites could not be collected; retry before previewing")
        else:
            result = []
            from urllib.parse import quote
            for sid in dict.fromkeys(ids):
                site = collector.cached_get("/sites/" + quote(sid, safe=""))
                if not isinstance(site, dict) or not site.get("org_id"):
                    raise ValueError("Site details or organization are unavailable")
                result.append(runtime.SiteContext(site_id=sid, site_name=site.get("name", sid), site=site,
                                                 mist_base_url=base_url, mist_headers=headers))
        return result, collector

    @routes.get("/catalog")
    def get_catalog(request: Request):
        runtime.current_user(request)
        try:
            document = store.load()
            return {"ok": True, **document, "schema_version": catalog()["version"],
                    "schema_source": catalog()["source"],
                    "operations": [{k: v for k, v in op.items() if k != "schema"} for op in catalog()["operations"]],
                    "specialists": {key: {"fields": fields, "active": key == "switch_cable_test"} for key, (_, fields) in definitions().items()}}
        except (ValueError, OSError) as exc:
            return failure(exc)

    @routes.put("/policies/{policy_id}")
    def save_policy(policy_id: str, request: Request, payload: dict = Body(...)):
        runtime._ensure_push_allowed(request, dry_run=False)
        try:
            policy = payload.get("policy", {})
            if not isinstance(policy, dict):
                raise ValueError("Policy must be an object")
            if policy.get("id") != policy_id:
                raise ValueError("Policy identifier does not match the URL")
            entry = store.save_entry("policies", policy, payload.get("expected_revision"))
            return {"ok": True, "policy": entry}
        except (ValueError, OSError) as exc:
            return failure(exc)

    @routes.put("/sources/{source_id}")
    def save_source(source_id: str, request: Request, payload: dict = Body(...)):
        runtime._ensure_push_allowed(request, dry_run=False)
        try:
            source = payload.get("source", {})
            if not isinstance(source, dict):
                raise ValueError("Source must be an object")
            if source.get("id") != source_id:
                raise ValueError("Source identifier does not match the URL")
            entry = store.save_entry("sources", source, payload.get("expected_revision"))
            return {"ok": True, "source": entry}
        except (ValueError, OSError) as exc:
            return failure(exc)

    @routes.post("/validate")
    def validate(request: Request, payload: dict = Body(...)):
        runtime.current_user(request)
        try:
            document = store.load()
            validate_policy(payload.get("policy"), document["sources"], validate_specialist)
            return {"ok": True}
        except (ValueError, OSError) as exc:
            return failure(exc)

    @routes.get("/fields")
    def fields(request: Request, source_id: str):
        runtime.current_user(request)
        try:
            source = next((s for s in store.load()["sources"] if s["id"] == source_id), None)
            if not source:
                raise ValueError("Unknown data source")
            return {"ok": True, "fields": discover(source["operation"], record_path=source.get("record_path"), collection=source["scope"] != "device")}
        except (ValueError, OSError) as exc:
            return failure(exc)

    @routes.post("/fields/discover")
    def discover_fields(request: Request, payload: dict = Body(...), base_url: str = runtime.DEFAULT_BASE_URL):
        runtime.current_user(request)
        try:
            source = next((s for s in store.load()["sources"] if s["id"] == payload.get("source_id")), None)
            if not source:
                raise ValueError("Choose a registered source")
            ctxs, collector = contexts(payload, base_url)
            snapshot = collector.collect([source], ctxs)
            records = [r["value"] for r in snapshot.records[source["id"]]]
            return {"ok": True, "fields": discover(source["operation"], records, source.get("record_path"), collection=source["scope"] != "device"),
                    "errors": snapshot.errors, "collected_at": snapshot.collected_at}
        except (ValueError, OSError, runtime.requests.RequestException) as exc:
            return failure(exc)

    @routes.post("/sources/test")
    def test_source(request: Request, payload: dict = Body(...), base_url: str = runtime.DEFAULT_BASE_URL):
        runtime._ensure_push_allowed(request, dry_run=False)
        try:
            source = validate_source(payload.get("source", {}))
            ctxs, collector = contexts(payload, base_url)
            # Per-device endpoint tests need a target population too.
            device_source = next(s for s in store.load()["sources"] if s["id"] == "device_config")
            sources = [source] if source["id"] == "device_config" else [device_source, source]
            snapshot = collector.collect(sources, ctxs)
            records = [r["value"] for r in snapshot.records[source["id"]]]
            return {"ok": not snapshot.errors, "record_count": len(records), "errors": snapshot.errors,
                    "fields": discover(source["operation"], records, source.get("record_path"), collection=source["scope"] != "device"),
                    "sample": sanitized(records[:2])}
        except (ValueError, OSError, runtime.requests.RequestException) as exc:
            return failure(exc)

    @routes.post("/preview")
    def preview(request: Request, payload: dict = Body(...), base_url: str = runtime.DEFAULT_BASE_URL):
        runtime.current_user(request)
        try:
            document = store.load()
            policy = copy.deepcopy(payload.get("policy", {}))
            if not isinstance(policy, dict):
                raise ValueError("Policy must be an object")
            policy.setdefault("revision", 0)
            validate_policy(policy, document["sources"], validate_specialist)
            policy["enabled"] = True
            document["policies"] = [policy]
            specialist = policy["requirement"]["kind"] == "specialist"
            ctxs, _ = contexts(payload, base_url, specialist=specialist)
            runner = build_runner(document=document, refresh_standards=False, include_active_checks=True)
            runner.include_active_checks = False  # Preview is passive, including for diagnostic blocks.
            result = runner.run(ctxs, exception_records=[], origin=runtime.mist_base_url(base_url))
            return {"ok": True, **result}
        except (ValueError, OSError, runtime.requests.RequestException) as exc:
            return failure(exc)

    @routes.post("/restore")
    def restore(request: Request, payload: dict = Body(...)):
        runtime._ensure_push_allowed(request, dry_run=False)
        try:
            restored = store.restore(payload.get("backup"), payload.get("expected_revision"))
            return {"ok": True, "revision": restored["revision"]}
        except (ValueError, OSError) as exc:
            return failure(exc)

    return routes
