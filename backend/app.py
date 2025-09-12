import os
import json
import tempfile
from pathlib import Path
from typing import List, Optional, Dict, Any

import requests
from fastapi import FastAPI, UploadFile, File, Form, Request, Body
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware

# Optional .env support
try:
    from dotenv import load_dotenv  # type: ignore
    load_dotenv(dotenv_path=Path(__file__).resolve().parent / ".env")
    load_dotenv()  # fallback search
except Exception:
    pass

# User modules
from convertciscotojson import convert_one_file  # type: ignore
import push_mist_port_config as pm  # type: ignore
from push_mist_port_config import (  # type: ignore
    ensure_port_config,
    get_device_model,
    timestamp_str,
    remap_members,
    remap_ports,
    validate_port_config_against_model,
)

APP_TITLE = "Switch Port Config Frontend"
DEFAULT_BASE_URL = "https://api.ac2.mist.com/api/v1"  # adjust region if needed
DEFAULT_TZ = "America/New_York"

app = FastAPI(title=APP_TITLE)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount /static only if folder exists
static_path = Path(__file__).resolve().parent.parent / "static"
if static_path.exists():
    app.mount("/static", StaticFiles(directory=str(static_path)), name="static")

# Optional authentication
# Optional authentication
README_URL = "https://github.com/jacob-hopkins/GreatMigration#readme"
# Where to send users when they click the help icon
HELP_URL = os.getenv("HELP_URL", README_URL)
RULES_PATH = Path(__file__).resolve().parent / "port_rules.json"
REPLACEMENTS_PATH = Path(__file__).resolve().parent / "replacement_rules.json"
NETBOX_DT_URL = "https://api.github.com/repos/netbox-community/devicetype-library/contents/device-types"
SWITCH_TEMPLATE_ID = (os.getenv("SWITCH_TEMPLATE_ID") or "").strip()
DEFAULT_ORG_ID = (os.getenv("MIST_ORG_ID") or "").strip()
AUTH_METHOD = (os.getenv("AUTH_METHOD") or "").lower()
if AUTH_METHOD == "ldap":
    try:
        import auth_ldap as _auth
        _auth.install_auth(app)
        current_user = _auth.current_user  # type: ignore[attr-defined]
        require_push_rights = _auth.require_push_rights  # type: ignore[attr-defined]
    except Exception as e:  # pragma: no cover - surface import errors
        raise RuntimeError(f"Failed to load LDAP auth: {e}")
elif AUTH_METHOD == "local":
    import auth_local as _auth
    _auth.install_auth(app)
    current_user = _auth.current_user  # type: ignore[attr-defined]
    require_push_rights = _auth.require_push_rights  # type: ignore[attr-defined]
else:
    current_user = lambda: {"name": "anon", "can_push": True}  # type: ignore
    require_push_rights = lambda user=current_user(): user  # type: ignore

    @app.middleware("http")
    async def _auth_missing(request: Request, call_next):
        return HTMLResponse(
            f"<h1>Authentication not configured</h1>"
            f"<p>Set the AUTH_METHOD environment variable to 'local' or 'ldap'. "
            f"See the <a href='{README_URL}'>README</a> for setup instructions.</p>",
            status_code=500,
        )

@app.get("/", response_class=HTMLResponse)
def index():
    tpl_path = Path(__file__).resolve().parent.parent / "templates" / "index.html"
    tpl = tpl_path.read_text(encoding="utf-8")
    return HTMLResponse(tpl.replace("{{HELP_URL}}", HELP_URL))


@app.get("/rules", response_class=HTMLResponse)
def rules_page():
    tpl_path = Path(__file__).resolve().parent.parent / "templates" / "rules.html"
    tpl = tpl_path.read_text(encoding="utf-8")
    return HTMLResponse(tpl.replace("{{HELP_URL}}", HELP_URL))


@app.get("/replacements", response_class=HTMLResponse)
def replacements_page():
    tpl_path = Path(__file__).resolve().parent.parent / "templates" / "replacements.html"
    tpl = tpl_path.read_text(encoding="utf-8")
    return HTMLResponse(tpl.replace("{{HELP_URL}}", HELP_URL))


def _load_mist_token() -> str:
    tok = (os.getenv("MIST_TOKEN") or "").strip()
    if not tok:
        raise RuntimeError("Missing MIST_TOKEN environment variable on the server.")
    return tok


@app.get("/api/rules")
def api_get_rules():
    """Return current rule document."""
    try:
        data = json.loads(RULES_PATH.read_text(encoding="utf-8"))
        return {"ok": True, "doc": data}
    except Exception as e:
        return JSONResponse({"ok": False, "error": str(e)}, status_code=500)


@app.post("/api/rules")
def api_save_rules(request: Request, doc: Dict[str, Any] = Body(...)):
    """Persist rule document and refresh in memory."""
    try:
        # Ensure the request is from an authenticated user
        current_user(request)
        pm.validate_rules_doc(doc)
        RULES_PATH.write_text(json.dumps(doc, indent=2), encoding="utf-8")
        pm.RULES_DOC = pm.load_rules()
        return {"ok": True}
    except ValueError as e:
        return JSONResponse({"ok": False, "error": str(e)}, status_code=400)
    except Exception as e:
        return JSONResponse({"ok": False, "error": str(e)}, status_code=500)


@app.get("/api/replacements")
def api_get_replacements():
    try:
        data = json.loads(REPLACEMENTS_PATH.read_text(encoding="utf-8"))
    except Exception:
        data = {"rules": []}
    return {"ok": True, "doc": data}


@app.post("/api/replacements")
def api_save_replacements(request: Request, doc: Dict[str, Any] = Body(...)):
    try:
        current_user(request)
        REPLACEMENTS_PATH.write_text(json.dumps(doc, indent=2), encoding="utf-8")
        return {"ok": True}
    except Exception as e:
        return JSONResponse({"ok": False, "error": str(e)}, status_code=500)


@app.get("/api/device_types")
def api_device_types(vendor: str):
    try:
        r = requests.get(f"{NETBOX_DT_URL}/{vendor}", timeout=30)
        r.raise_for_status()
        items = [i.get("name", "").rsplit(".", 1)[0] for i in r.json() if i.get("type") == "file"]
        items.sort(key=lambda x: x.lower())
        return {"ok": True, "items": items}
    except Exception as e:
        return JSONResponse({"ok": False, "error": str(e)}, status_code=500)


@app.get("/api/sites")
def api_sites(base_url: str = DEFAULT_BASE_URL, org_id: Optional[str] = None):
    """
    Returns the list of sites visible to the token. If org_id is provided, scopes to that org.
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
                items.append({"id": s.get("id"), "name": s.get("name") or s.get("site_name") or s.get("id"), "org_id": org_id})
        else:
            # Discover orgs from /self and enumerate sites per org
            r = requests.get(f"{base_url}/self", headers=headers, timeout=30)
            r.raise_for_status()
            who = r.json() or {}

            org_ids = set()
            if isinstance(who.get("orgs"), list):
                for o in who["orgs"]:
                    if isinstance(o, dict) and o.get("org_id"):
                        org_ids.add(o["org_id"])
                    elif isinstance(o, dict) and o.get("id"):
                        org_ids.add(o["id"])
                    elif isinstance(o, str):
                        org_ids.add(o)
            if isinstance(who.get("privileges"), list):
                for p in who["privileges"]:
                    if isinstance(p, dict) and p.get("org_id"):
                        org_ids.add(p["org_id"])
            if isinstance(who.get("org_id"), str):
                org_ids.add(who["org_id"])

            for oid in org_ids:
                try:
                    r2 = requests.get(f"{base_url}/orgs/{oid}/sites", headers=headers, timeout=30)
                    r2.raise_for_status()
                    for s in r2.json() or []:
                        items.append({"id": s.get("id"), "name": s.get("name") or s.get("site_name") or s.get("id"), "org_id": oid})
                except Exception:
                    continue

        items.sort(key=lambda x: (x["name"] or "").lower())
        return {"ok": True, "items": items}
    except Exception as e:
        try:
            err_payload = r.json()  # type: ignore[name-defined]
        except Exception:
            err_payload = {"error": str(e)}
        return JSONResponse({"ok": False, "error": err_payload}, status_code=getattr(r, "status_code", 500))  # type: ignore[name-defined]


@app.get("/api/site_devices")
def api_site_devices(site_id: str, base_url: str = DEFAULT_BASE_URL):
    """
    Returns the list of switch devices in the given site.
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
                "is_switch": is_switch
            })
        items.sort(key=lambda x: (not x["is_switch"], (x["name"] or "").lower()))
        return {"ok": True, "items": items}
    except Exception as e:
        try:
            err_payload = r.json()  # type: ignore[name-defined]
        except Exception:
            err_payload = {"error": str(e)}
        return JSONResponse({"ok": False, "error": err_payload}, status_code=getattr(r, "status_code", 500))  # type: ignore[name-defined]

def _discover_org_ids(base_url: str, headers: Dict[str, str]) -> List[str]:
    """Return list of org IDs visible to the token using /self."""
    r = requests.get(f"{base_url}/self", headers=headers, timeout=30)
    r.raise_for_status()
    who = r.json() or {}
    org_ids: set[str] = set()
    if isinstance(who.get("orgs"), list):
        for o in who["orgs"]:
            if isinstance(o, dict) and o.get("org_id"):
                org_ids.add(o["org_id"])
            elif isinstance(o, dict) and o.get("id"):
                org_ids.add(o["id"])
            elif isinstance(o, str):
                org_ids.add(o)
    if isinstance(who.get("privileges"), list):
        for p in who["privileges"]:
            if isinstance(p, dict) and p.get("org_id"):
                org_ids.add(p["org_id"])
    if isinstance(who.get("org_id"), str):
        org_ids.add(who["org_id"])
    return list(org_ids)


@app.get("/api/port_profiles")
def api_port_profiles(base_url: str = DEFAULT_BASE_URL, org_id: Optional[str] = None):
    """Return port profiles visible to the token."""
    items: List[Dict[str, Any]] = []
    try:
        token = _load_mist_token()
        base_url = base_url.rstrip("/")
        headers = {"Authorization": f"Token {token}", "Accept": "application/json"}

        template_id = SWITCH_TEMPLATE_ID
        org_id = org_id or DEFAULT_ORG_ID or None

        def _fetch_from_template(oid: str, tid: str) -> List[Dict[str, Any]]:
            r = requests.get(
                f"{base_url}/orgs/{oid}/networktemplates/{tid}",
                headers=headers,
                timeout=30,
            )
            r.raise_for_status()
            data = r.json() or {}
            port_usages = data.get("port_usages") or {}
            return [{"id": name, "name": name, "org_id": oid} for name in port_usages.keys()]

        if template_id:
            org_ids = [org_id] if org_id else _discover_org_ids(base_url, headers)
            for oid in org_ids:
                try:
                    items = _fetch_from_template(oid, template_id)
                    if items:
                        break
                except Exception:
                    continue
            if not items:
                return JSONResponse(
                    {
                        "ok": False,
                        "error": "Unable to locate switch template in accessible organizations",
                    },
                    status_code=404,
                )
        else:
            org_ids = [org_id] if org_id else _discover_org_ids(base_url, headers)
            seen: set[str] = set()
            for oid in org_ids:
                try:
                    r = requests.get(
                        f"{base_url}/orgs/{oid}/networktemplates",
                        headers=headers,
                        timeout=30,
                    )
                    r.raise_for_status()
                    templates = r.json() or []
                    for t in templates:
                        tid = t.get("id")
                        if not tid:
                            continue
                        try:
                            for item in _fetch_from_template(oid, tid):
                                if item["name"] not in seen:
                                    seen.add(item["name"])
                                    items.append(item)
                        except Exception:
                            continue
                except Exception:
                    continue
        items.sort(key=lambda x: (x.get("name") or "").lower())
        return {"ok": True, "items": items}
    except Exception as e:
        err_payload: Any
        try:
            err_payload = r.json()  # type: ignore[name-defined]
        except Exception:
            err_payload = {}
        msg = ""
        if isinstance(err_payload, dict):
            msg = (
                err_payload.get("error")
                or err_payload.get("detail")
                or err_payload.get("message")
                or json.dumps(err_payload)
            )
        else:
            msg = str(err_payload)
        if not msg:
            msg = str(e)
        return JSONResponse(
            {"ok": False, "error": msg},
            status_code=getattr(r, "status_code", 500),
        )  # type: ignore[name-defined]


@app.post("/api/convert")
async def api_convert(
    files: List[UploadFile] = File(...),
    uplink_module: int = Form(1),
    force_model: Optional[str] = Form(None),
    strict_overflow: bool = Form(False),
) -> JSONResponse:
    """
    Converts one or more Cisco configs into the normalized JSON that the push script consumes.
    """
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

            results.append({"source_file": uf.filename, "output_file": out_path.name, "json": data})

    return JSONResponse({"ok": True, "items": results})


def _build_payload_for_row(
    *,
    base_url: str,
    tz: str,
    token: str,
    site_id: str,
    device_id: str,
    payload_in: Dict[str, Any],
    model_override: Optional[str],
    excludes: Optional[str],
    member_offset: int,
    port_offset: int,
    normalize_modules: bool,
    dry_run: bool,
) -> Dict[str, Any]:
    """
    Shared logic used by both /api/push and /api/push_batch for a single row.
    Returns a dict with keys: ok, payload, validation, device_model, (and for live push: status/response)
    """
    # Resolve model
    model = model_override or get_device_model(base_url, site_id, device_id, token)

    # Build port_config
    port_config = ensure_port_config(payload_in, model)

    # Apply member/port remap BEFORE excludes
    port_config = remap_members(port_config, member_offset=int(member_offset or 0), normalize=bool(normalize_modules))
    port_config = remap_ports(port_config, port_offset=int(port_offset or 0), model=model)

    # Apply excludes AFTER remap
    exclude_set = set([e.strip() for e in (excludes or "").split(",") if e.strip()])
    if exclude_set:
        port_config = {k: v for k, v in port_config.items() if k not in exclude_set}

    # Capacity validation (block live push; warn on dry-run)
    validation = validate_port_config_against_model(port_config, model)

    # Timestamp descriptions
    ts = timestamp_str(tz)
    final_port_config: Dict[str, Dict[str, Any]] = {}
    for ifname, cfg in port_config.items():
        c = dict(cfg)
        desc = (c.get("description") or "").strip()
        c["description"] = f"{desc + ' - ' if desc else ''}converted by API {ts}"
        final_port_config[ifname] = c

    put_body = {"port_config": final_port_config}
    url = f"{base_url}/sites/{site_id}/devices/{device_id}"
    headers = {"Authorization": f"Token {token}", "Content-Type": "application/json", "Accept": "application/json"}

    if dry_run:
        return {
            "ok": True,
            "dry_run": True,
            "device_model": model,
            "url": url,
            "member_offset": int(member_offset or 0),
            "port_offset": int(port_offset or 0),
            "normalize_modules": bool(normalize_modules),
            "validation": validation,
            "payload": put_body
        }

    # live push
    if not validation.get("ok"):
        return {
            "ok": False,
            "dry_run": False,
            "error": "Model capacity mismatch",
            "validation": validation,
            "payload": put_body
        }

    resp = requests.put(url, headers=headers, json=put_body, timeout=60)
    try:
        content = resp.json()
    except Exception:
        content = {"text": resp.text}

    return {
        "ok": 200 <= resp.status_code < 300,
        "dry_run": False,
        "status": resp.status_code,
        "response": content,
        "payload": put_body
    }


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
    member_offset: int = Form(0),
    port_offset: int = Form(0),
    normalize_modules: bool = Form(True),
) -> JSONResponse:
    """
    Single push. Response includes `payload` (the exact body to Mist) and `validation`.
    """
    try:
        payload_in = json.loads(input_json)
    except Exception as e:
        return JSONResponse({"ok": False, "error": f"Invalid input_json: {e}"}, status_code=400)

    token = _load_mist_token()
    base_url = base_url.rstrip("/")

    try:
        row_result = _build_payload_for_row(
            base_url=base_url, tz=tz, token=token,
            site_id=site_id, device_id=device_id,
            payload_in=payload_in, model_override=model_override,
            excludes=excludes, member_offset=member_offset, port_offset=port_offset, normalize_modules=normalize_modules,
            dry_run=dry_run,
        )
        status = 200 if row_result.get("ok") else 400
        return JSONResponse(row_result, status_code=status)
    except Exception as e:
        return JSONResponse({"ok": False, "error": f"Server error: {e}"}, status_code=500)


@app.post("/api/push_batch")
async def api_push_batch(
    rows: str = Form(...),  # JSON array of rows
    dry_run: bool = Form(True),
    base_url: str = Form(DEFAULT_BASE_URL),
    tz: str = Form(DEFAULT_TZ),
    model_override: Optional[str] = Form(None),  # optional global override (row can still override)
    normalize_modules: bool = Form(True),
) -> JSONResponse:
    """
    Batch push. Each row can specify: site_id, device_id, input_json (object),
    excludes (str), member_offset (int), port_offset (int), model_override (str, optional).
    Returns per-row results with payload + validation, and never aborts the whole batch.

    NOTE: Duplicate devices ARE allowed as long as (device_id, member_offset, port_offset) triples are unique.
    If the same triple appears more than once, those rows are rejected with a clear error.
    """
    token = _load_mist_token()
    base_url = base_url.rstrip("/")

    try:
        row_list = json.loads(rows)
        assert isinstance(row_list, list)
    except Exception as e:
        return JSONResponse({"ok": False, "error": f"Invalid 'rows' payload: {e}"}, status_code=400)

    # Pre-scan for duplicate (device_id, member_offset, port_offset) triples
    pair_counts: Dict[str, int] = {}
    for r in row_list:
        device_id = (r.get("device_id") or "").strip()
        member_offset = int(r.get("member_offset") or 0)
        port_offset = int(r.get("port_offset") or 0)
        key = f"{device_id}@@{member_offset}@@{port_offset}"
        if device_id:
            pair_counts[key] = pair_counts.get(key, 0) + 1

    results: List[Dict[str, Any]] = []
    used_ifnames: Dict[str, set[str]] = {}
    for i, r in enumerate(row_list):
        try:
            site_id = (r.get("site_id") or "").strip()
            device_id = (r.get("device_id") or "").strip()
            payload_in = r.get("input_json")
            excludes = r.get("excludes") or ""
            member_offset = int(r.get("member_offset") or 0)
            port_offset = int(r.get("port_offset") or 0)
            row_model_override = r.get("model_override") or model_override

            if not site_id or not device_id or not isinstance(payload_in, (dict, list)):
                results.append({"ok": False, "row_index": i, "error": "Missing site_id/device_id or malformed input_json"})
                continue

            # Reject duplicate (device_id, member_offset, port_offset) triples
            key = f"{device_id}@@{member_offset}@@{port_offset}"
            if pair_counts.get(key, 0) > 1:
                results.append({
                    "ok": False,
                    "row_index": i,
                    "site_id": site_id,
                    "device_id": device_id,
                    "error": "Duplicate device with the same Start member and Start port detected. Use distinct offsets for repeated device selections.",
                })
                continue

            if isinstance(payload_in, list):
                payload_in = {"interfaces": payload_in}

            row_result = _build_payload_for_row(
                base_url=base_url, tz=tz, token=token,
                site_id=site_id, device_id=device_id,
                payload_in=payload_in, model_override=row_model_override,
                excludes=excludes, member_offset=member_offset, port_offset=port_offset, normalize_modules=normalize_modules,
                dry_run=dry_run,
            )
            row_result["row_index"] = i
            row_result["site_id"] = site_id
            row_result["device_id"] = device_id
            if row_result.get("ok"):
                names = set((row_result.get("payload") or {}).get("port_config", {}).keys())
                used = used_ifnames.setdefault(device_id, set())
                overlap = used.intersection(names)
                if overlap:
                    row_result["ok"] = False
                    row_result["error"] = "Port overlap detected with another row for this device."
                else:
                    used.update(names)
            results.append(row_result)

        except Exception as e:
            results.append({"ok": False, "row_index": i, "error": f"Server error: {e}"})

    top_ok = all(r.get("ok") for r in results) if results else False
    return JSONResponse({"ok": top_ok, "dry_run": bool(dry_run), "results": results})
