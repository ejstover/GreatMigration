import os
import json
import tempfile
import re
from pathlib import Path
from typing import List, Optional, Dict, Any

import requests
from fastapi import FastAPI, UploadFile, File, Form, Request, Body, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware

from logging_utils import get_user_logger

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
from translate_showtech import (
    parse_showtech,
    load_mapping,
    find_copper_10g_ports,
)  # type: ignore
from fpdf import FPDF

APP_TITLE = "Switch Port Config Frontend"
DEFAULT_BASE_URL = "https://api.ac2.mist.com/api/v1"  # adjust region if needed
DEFAULT_TZ = "America/New_York"

TEMPLATES_DIR = Path(__file__).resolve().parent.parent / "templates"

PAGE_COPY: dict[str, dict[str, str]] = {
    "config": {
        "title": "Config Conversion",
        "tagline": "Upload Cisco configs → map rows → batch test/push to Mist",
    },
    "hardware": {
        "title": "Hardware Conversion",
        "tagline": "Upload Cisco show tech files and map to Juniper replacements",
    },
    "replacements": {
        "title": "Hardware Replacement Rules",
        "tagline": "Map Cisco models to Juniper replacements",
    },
    "rules": {
        "title": "Port Profile Rules",
        "tagline": "Create and reorder port mapping rules",
    },
}

NAV_LINK_KEYS = ("hardware", "replacements", "config", "rules")


def _page_label(key: str) -> str:
    data = PAGE_COPY.get(key, {})
    return data.get("menu_label") or data.get("title") or ""


def _render_page(template_name: str, page_key: str) -> HTMLResponse:
    tpl_path = TEMPLATES_DIR / template_name
    html = tpl_path.read_text(encoding="utf-8")
    page_data = PAGE_COPY.get(page_key, {})
    doc_title = page_data.get("doc_title")
    if not doc_title:
        base_title = page_data.get("title")
        if base_title and base_title != APP_TITLE:
            doc_title = f"{base_title} • {APP_TITLE}"
        else:
            doc_title = APP_TITLE
    banner_title = page_data.get("banner_title") or page_data.get("title") or APP_TITLE
    tagline = page_data.get("tagline", "")

    replacements = {
        "{{HELP_URL}}": HELP_URL,
        "{{DOC_TITLE}}": doc_title,
        "{{BANNER_TITLE}}": banner_title,
        "{{BANNER_TAGLINE}}": tagline,
    }

    for key in NAV_LINK_KEYS:
        replacements[f"{{{{NAV_{key.upper()}}}}}"] = _page_label(key)

    for placeholder, value in replacements.items():
        html = html.replace(placeholder, value)

    return HTMLResponse(html)


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
NETBOX_DT_URL = os.getenv(
    "NETBOX_DT_URL",
    "https://api.github.com/repos/netbox-community/devicetype-library/contents/device-types",
).strip()
NETBOX_LOCAL_DT = (os.getenv("NETBOX_LOCAL_DT") or "").strip()
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
    def current_user(request: Request | None = None):  # type: ignore[override]
        """Fallback auth stub when AUTH_METHOD is unset."""
        return {"name": "anon", "can_push": True, "read_only": False}

    def require_push_rights(user=current_user()):  # type: ignore[override]
        return user

    @app.middleware("http")
    async def _auth_missing(request: Request, call_next):
        client_host = request.client.host if request.client else "-"
        path = request.url.path
        query = request.url.query
        query_suffix = f"?{query}" if query else ""
        # Log using the shared action logger (defined later in the module)
        try:
            action_logger.warning(
                "user=anonymous client=%s method=%s path=%s%s status=500 detail=auth_not_configured",
                client_host,
                request.method,
                path,
                query_suffix,
            )
        except Exception:
            pass
        return HTMLResponse(
            f"<h1>Authentication not configured</h1>"
            f"<p>Set the AUTH_METHOD environment variable to 'local' or 'ldap'. "
            f"See the <a href='{README_URL}'>README</a> for setup instructions.</p>",
            status_code=500,
        )


action_logger = get_user_logger()


def _request_user_label(request: Request) -> str:
    try:
        info = current_user(request)
    except Exception:
        return "anonymous"

    if isinstance(info, dict):
        for key in ("name", "email", "upn"):
            val = info.get(key)
            if val:
                return str(val)
    return str(info) if info is not None else "anonymous"


def _ensure_push_allowed(request: Request, *, dry_run: bool) -> Dict[str, Any]:
    """Ensure the current user is allowed to execute a live push."""
    user = current_user(request)
    if not dry_run and not user.get("can_push"):
        label = user.get("name") or user.get("email") or user.get("upn") or "anonymous"
        client_host = request.client.host if request.client else "-"
        action_logger.warning(
            "mist_push_denied user=%s client=%s reason=read_only_attempt",
            label,
            client_host,
        )
        raise HTTPException(
            status_code=403,
            detail="Push permission required for live changes.",
        )
    return user


@app.middleware("http")
async def _log_user_actions(request: Request, call_next):
    user_label = _request_user_label(request)
    client_host = request.client.host if request.client else "-"
    path = request.url.path
    query = request.url.query
    query_suffix = f"?{query}" if query else ""

    try:
        response = await call_next(request)
    except Exception as exc:
        action_logger.exception(
            "user=%s client=%s method=%s path=%s%s error=%s",
            user_label,
            client_host,
            request.method,
            path,
            query_suffix,
            exc,
        )
        raise

    if user_label == "anonymous":
        post_label = _request_user_label(request)
        if post_label != "anonymous":
            user_label = post_label

    action_logger.info(
        "user=%s client=%s method=%s path=%s%s status=%s",
        user_label,
        client_host,
        request.method,
        path,
        query_suffix,
        response.status_code,
    )
    return response

@app.get("/", response_class=HTMLResponse)
def index():
    return _render_page("index.html", "config")


@app.get("/rules", response_class=HTMLResponse)
def rules_page():
    return _render_page("rules.html", "rules")


@app.get("/replacements", response_class=HTMLResponse)
def replacements_page():
    return _render_page("hardwarereplacementrules.html", "replacements")


@app.get("/hardware", response_class=HTMLResponse)
def hardware_page():
    return _render_page("hardware.html", "hardware")


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


@app.post("/api/showtech")
async def api_showtech(files: List[UploadFile] = File(...)):
    try:
        mapping = load_mapping()
        results = []
        for f in files:
            text = (await f.read()).decode("utf-8", errors="ignore")
            inventory = parse_showtech(text)
            copper_ports = find_copper_10g_ports(text)
            switches = []
            for sw, items in inventory.items():
                if sw.lower() == "global":
                    continue
                sw_items = []
                for pid, count in items.items():
                    replacement = mapping.get(pid, "no replacement model defined")
                    sw_items.append(
                        {"pid": pid, "count": count, "replacement": replacement}
                    )
                switches.append({"switch": sw, "items": sw_items})
            copper_total = sum(len(v) for v in copper_ports.values())
            results.append(
                {
                    "filename": f.filename,
                    "switches": switches,
                    "copper_10g_ports": {**copper_ports, "total": copper_total},
                }
            )
        return {"ok": True, "results": results}
    except Exception as e:
        return JSONResponse({"ok": False, "error": str(e)}, status_code=500)


@app.post("/api/showtech/pdf")
def api_showtech_pdf(data: Dict[str, Any] = Body(...)):
    pdf = FPDF()
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.add_page()
    pdf.set_font("Helvetica", size=12)
    for file in data.get("results", []):
        pdf.set_font("Helvetica", "B", 14)
        pdf.cell(0, 10, file.get("filename", ""), ln=True)
        pdf.set_font("Helvetica", size=12)
        for sw in file.get("switches", []):
            pdf.cell(0, 10, sw.get("switch", ""), ln=True)
            for item in sw.get("items", []):
                line = f"  {item.get('pid')} x{item.get('count')} -> {item.get('replacement')}"
                pdf.cell(0, 10, line, ln=True)
        copper_total = file.get("copper_10g_ports", {}).get("total")
        if copper_total:
            line = f"10Gb copper ports requiring SFPs (SFPP-10G-T): {copper_total}"
            pdf.cell(0, 10, line, ln=True)
        pdf.ln(5)
    # fpdf2 returns a bytearray; convert it to bytes for the response
    pdf_bytes = bytes(pdf.output())
    headers = {"Content-Disposition": "attachment; filename=hardware_conversion_report.pdf"}
    return Response(content=pdf_bytes, media_type="application/pdf", headers=headers)


@app.get("/api/device_types")
def api_device_types(vendor: str):
    try:
        r = requests.get(f"{NETBOX_DT_URL}/{vendor}", timeout=30)
        r.raise_for_status()
        items = [i.get("name", "").rsplit(".", 1)[0] for i in r.json() if i.get("type") == "file"]

        if NETBOX_LOCAL_DT:
            try:
                local_data = json.loads(Path(NETBOX_LOCAL_DT).read_text(encoding="utf-8"))
                for name in local_data.get(vendor, []):
                    if isinstance(name, str) and name not in items:
                        items.append(name)
            except FileNotFoundError:
                pass

        items.sort(key=lambda x: x.lower())
        return {"ok": True, "items": items}
    except Exception as e:
        return JSONResponse({"ok": False, "error": str(e)}, status_code=500)


@app.post("/api/device_types")
def api_add_device_type(request: Request, data: Dict[str, str] = Body(...)):
    """Persist a custom device type to the local overrides file."""
    try:
        current_user(request)

        vendor = (data.get("vendor") or "").strip()
        model = (data.get("model") or "").strip()
        if not vendor or not model:
            raise ValueError("vendor and model are required")

        if not NETBOX_LOCAL_DT:
            raise RuntimeError("NETBOX_LOCAL_DT is not configured on the server")

        path = Path(NETBOX_LOCAL_DT)
        try:
            doc = json.loads(path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            doc = {}

        models = doc.setdefault(vendor, [])
        if model not in models:
            models.append(model)
            models.sort(key=lambda x: x.lower())
            path.write_text(json.dumps(doc, indent=2), encoding="utf-8")

        return {"ok": True, "items": models}
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
    exclude_uplinks: bool,
    member_offset: int,
    port_offset: int,
    normalize_modules: bool,
    dry_run: bool,
) -> Dict[str, Any]:
    """
    Shared logic used by both /api/push and /api/push_batch for a single row.
    Returns a dict with keys: ok, payload, validation, device_model,
    (and for live push: status/response)
    """
    # Resolve model
    model = model_override or get_device_model(base_url, site_id, device_id, token)

    # Build port_config
    port_config = ensure_port_config(payload_in, model)

    # Apply member/port remap BEFORE excludes
    port_config = remap_members(port_config, member_offset=int(member_offset or 0), normalize=bool(normalize_modules))
    port_config = remap_ports(port_config, port_offset=int(port_offset or 0), model=model)

    # Apply excludes AFTER remap

    def _expand_if_range(val: str) -> List[str]:
        m = re.search(r"\[(\d+)-(\d+)\]", val)
        if not m:
            return [val]
        start, end = int(m.group(1)), int(m.group(2))
        prefix = val[: m.start()]
        suffix = val[m.end():]
        rng = range(start, end + 1) if start <= end else range(end, start + 1)
        return [f"{prefix}{i}{suffix}" for i in rng]

    exclude_set: set[str] = set()
    for tok in [e.strip() for e in (excludes or "").split(",") if e.strip()]:
        exclude_set.update(_expand_if_range(tok))

    if exclude_uplinks:
        for mbr in range(10):
            for p in range(4):
                exclude_set.add(f"xe-{mbr}/2/{p}")

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
    request: Request,
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
    _ensure_push_allowed(request, dry_run=dry_run)

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
    request: Request,
    rows: str = Form(...),  # JSON array of rows
    dry_run: bool = Form(True),
    base_url: str = Form(DEFAULT_BASE_URL),
    tz: str = Form(DEFAULT_TZ),
    model_override: Optional[str] = Form(None),  # optional global override (row can still override)
    normalize_modules: bool = Form(True),
) -> JSONResponse:
    """
    Batch push. Each row can specify: site_id, device_id, input_json (object),
    excludes (str), exclude_uplinks (bool), member_offset (int), port_offset (int), model_override (str, optional).
    Returns per-row results with payload + validation, and never aborts the whole batch.

    NOTE: Duplicate devices ARE allowed as long as (device_id, member_offset, port_offset) triples are unique.
    If the same triple appears more than once, those rows are rejected with a clear error.
    """
    _ensure_push_allowed(request, dry_run=dry_run)

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
            exclude_uplinks = bool(r.get("exclude_uplinks"))
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
                excludes=excludes, exclude_uplinks=exclude_uplinks,
                member_offset=member_offset, port_offset=port_offset, normalize_modules=normalize_modules,
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
