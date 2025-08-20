import os
import json
import tempfile
from pathlib import Path
from typing import List, Optional, Dict, Any

import requests
from fastapi import FastAPI, UploadFile, File, Form
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware

# User modules (must be next to this file)
from convertciscotojson import convert_one_file  # type: ignore
from push_mist_port_config import (  # type: ignore
    ensure_port_config,
    get_device_model,
    timestamp_str,
    remap_members,      # <-- added
)

APP_TITLE = "Switch Port Config Frontend"
DEFAULT_BASE_URL = "https://api.ac2.mist.com/api/v1"
DEFAULT_TZ = "America/New_York"

app = FastAPI(title=APP_TITLE)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount /static only if folder exists (prevents startup errors on clean zips)
static_path = Path(__file__).resolve().parent.parent / "static"
if static_path.exists():
    app.mount("/static", StaticFiles(directory=str(static_path)), name="static")


@app.get("/", response_class=HTMLResponse)
def index():
    tpl = (Path(__file__).resolve().parent.parent / "templates" / "index.html").read_text(encoding="utf-8")
    return HTMLResponse(tpl)


# ----- Helpers -----
def _load_mist_token() -> str:
    tok = (os.getenv("MIST_TOKEN") or "").strip()
    if not tok:
        raise RuntimeError("Missing MIST_TOKEN environment variable on the server.")
    return tok


# ----- Sites / Devices -----
@app.get("/api/sites")
def api_sites(base_url: str = DEFAULT_BASE_URL, org_id: Optional[str] = None):
    """
    Return all sites accessible to the token.
    If org_id is provided, query that org directly.
    Otherwise, discover orgs via /self then enumerate.
    """
    token = _load_mist_token()
    base_url = base_url.rstrip("/")
    headers = {"Authorization": f"Token {token}", "Accept": "application/json"}

    items: List[Dict[str, Any]] = []
    try:
        if org_id:
            r = requests.get(f"{base_url}/orgs/{org_id}/sites", headers=headers, timeout=30)
            r.raise_for_status()
            for s in r.json() or []:
                items.append({
                    "id": s.get("id"),
                    "name": s.get("name") or s.get("site_name") or s.get("id"),
                    "org_id": org_id,
                })
        else:
            # Discover orgs from /self
            r = requests.get(f"{base_url}/self", headers=headers, timeout=30)
            r.raise_for_status()
            who = r.json() or {}

            org_ids = set()

            # orgs can be a list of dicts or strings
            orgs = who.get("orgs")
            if isinstance(orgs, list):
                for o in orgs:
                    if isinstance(o, dict) and o.get("org_id"):
                        org_ids.add(o["org_id"])
                    elif isinstance(o, dict) and o.get("id"):
                        org_ids.add(o["id"])
                    elif isinstance(o, str):
                        org_ids.add(o)

            # privileges may be a list of dicts with org_id
            priv = who.get("privileges")
            if isinstance(priv, list):
                for p in priv:
                    if isinstance(p, dict) and p.get("org_id"):
                        org_ids.add(p["org_id"])
            elif isinstance(priv, dict):
                org_ids.update([k for k in priv.keys() if isinstance(k, str)])

            if isinstance(who.get("org_id"), str):
                org_ids.add(who["org_id"])

            # enumerate sites per org
            for oid in org_ids:
                try:
                    r2 = requests.get(f"{base_url}/orgs/{oid}/sites", headers=headers, timeout=30)
                    r2.raise_for_status()
                    for s in r2.json() or []:
                        items.append({
                            "id": s.get("id"),
                            "name": s.get("name") or s.get("site_name") or s.get("id"),
                            "org_id": oid,
                        })
                except Exception:
                    continue

        items.sort(key=lambda x: (x["name"] or "").lower())
        return {"ok": True, "items": items}
    except Exception as e:
        # Try to surface the API error payload if available
        try:
            err_payload = r.json()  # type: ignore[name-defined]
        except Exception:
            err_payload = {"error": str(e)}
        return JSONResponse({"ok": False, "error": err_payload}, status_code=getattr(r, "status_code", 500))  # type: ignore[name-defined]


@app.get("/api/site_devices")
def api_site_devices(site_id: str, base_url: str = DEFAULT_BASE_URL):
    """
    Return devices for a given site (switches first).
    """
    token = _load_mist_token()
    base_url = base_url.rstrip("/")
    headers = {"Authorization": f"Token {token}", "Accept": "application/json"}
    try:
        r = requests.get(f"{base_url}/sites/{site_id}/devices?type=switch", headers=headers, timeout=30)
        r.raise_for_status()
        data = r.json() or []
        items: List[Dict[str, Any]] = []
        for d in data:
            dev_type = d.get("type")
            is_switch = (dev_type or "").lower() == "switch"
            name = d.get("name") or d.get("hostname") or f"{d.get('model','device')} {d.get('mac','')}"
            items.append({
                "id": d.get("id"),
                "name": name,
                "type": dev_type,
                "model": d.get("model"),
                "mac": d.get("mac"),
                "is_switch": is_switch,
            })
        items.sort(key=lambda x: (not x["is_switch"], (x["name"] or "").lower()))
        return {"ok": True, "items": items}
    except Exception as e:
        try:
            err_payload = r.json()  # type: ignore[name-defined]
        except Exception:
            err_payload = {"error": str(e)}
        return JSONResponse({"ok": False, "error": err_payload}, status_code=getattr(r, "status_code", 500))  # type: ignore[name-defined]


# ----- Convert -----
@app.post("/api/convert")
async def api_convert(
    files: List[UploadFile] = File(...),
    uplink_module: int = Form(1),
    force_model: Optional[str] = Form(None),
    strict_overflow: bool = Form(False),
) -> JSONResponse:
    results = []
    with tempfile.TemporaryDirectory() as tmpdir:
        tmpdir_path = Path(tmpdir)
        for uf in files:
            contents = await uf.read()
            in_path = tmpdir_path / uf.filename
            in_path.write_bytes(contents)

            out_path = convert_one_file(
                input_path=in_path,
                uplink_module=uplink_module,
                strict_overflow=strict_overflow,
                force_model=force_model,
                output_dir=tmpdir_path,
            )
            try:
                data = json.loads(out_path.read_text(encoding="utf-8"))
            except Exception as e:
                return JSONResponse({"ok": False, "error": f"Failed to load JSON for {uf.filename}: {e}"}, status_code=400)

            results.append({
                "source_file": uf.filename,
                "output_file": out_path.name,
                "json": data,
            })

    return JSONResponse({"ok": True, "items": results})


# ----- Push -----
@app.post("/api/push")
async def api_push(
    site_id: str = Form(...),
    device_id: str = Form(...),
    input_json: str = Form(...),
    dry_run: bool = Form(True),
    base_url: str = Form(DEFAULT_BASE_URL),
    tz: str = Form(DEFAULT_TZ),
    model_override: Optional[str] = Form(None),
    excludes: Optional[str] = Form(None),
    save_output: Optional[bool] = Form(False),

    # NEW: per-row member offset & normalization toggle
    member_offset: int = Form(0),
    normalize_modules: bool = Form(True),  # UI says "Normalization is always on"
) -> JSONResponse:
    # Parse payload
    try:
        payload_in = json.loads(input_json)
    except Exception as e:
        return JSONResponse({"ok": False, "error": f"Invalid input_json: {e}"}, status_code=400)

    token = _load_mist_token()
    base_url = base_url.rstrip("/")

    # Resolve device model (or use override)
    model = model_override or get_device_model(base_url, site_id, device_id, token)

    # Ensure we have Mist-style port_config (mapping from 'interfaces' if present)
    try:
        port_config = ensure_port_config(payload_in, model)
    except Exception as e:
        return JSONResponse({"ok": False, "error": f"Failed to build port_config: {e}"}, status_code=400)

    # Apply MEMBER remap (first number in ge|mge-<member>/<pic>/<port>)
    try:
        port_config = remap_members(
            port_config,
            member_offset=int(member_offset or 0),
            normalize=bool(normalize_modules),
        )
    except Exception as e:
        return JSONResponse({"ok": False, "error": f"Failed to apply member offset: {e}"}, status_code=400)

    # Apply exact-name excludes AFTER remap
    exclude_set = set([e.strip() for e in (excludes or "").split(",") if e.strip()])
    if exclude_set:
        port_config = {k: v for k, v in port_config.items() if k not in exclude_set}

    # Timestamped description
    ts = timestamp_str(tz)
    final_port_config: Dict[str, Dict[str, Any]] = {}
    for ifname, cfg in port_config.items():
        c = dict(cfg)
        desc = (c.get("description") or "").strip()
        c["description"] = f"{desc + ' - ' if desc else ''}converted by API {ts}"
        final_port_config[ifname] = c

    put_body = {"port_config": final_port_config}

    url = f"{base_url}/sites/{site_id}/devices/{device_id}"
    headers = {
        "Authorization": f"Token {token}",
        "Content-Type": "application/json",
        "Accept": "application/json",
    }

    # Dry run: echo debug fields so you can verify offset usage in UI
    if dry_run:
        return JSONResponse({
            "ok": True,
            "dry_run": True,
            "device_model": model,
            "url": url,
            "member_offset": int(member_offset or 0),
            "normalize_modules": bool(normalize_modules),
            "body": put_body
        })

    # Live PUT
    try:
        resp = requests.put(url, headers=headers, json=put_body, timeout=60)
    except Exception as e:
        return JSONResponse({"ok": False, "error": f"Request error: {e}"}, status_code=502)

    try:
        content = resp.json()
    except Exception:
        content = {"text": resp.text}

    if 200 <= resp.status_code < 300:
        return JSONResponse({"ok": True, "dry_run": False, "status": resp.status_code, "response": content})
    else:
        return JSONResponse({"ok": False, "dry_run": False, "status": resp.status_code, "response": content}, status_code=resp.status_code)
