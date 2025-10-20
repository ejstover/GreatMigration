import os
import json
import tempfile
import re
import math
from collections import defaultdict
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import List, Optional, Dict, Any, Sequence, Iterable, Mapping, Set
from zoneinfo import ZoneInfo
from time import perf_counter

import requests
from fastapi import FastAPI, UploadFile, File, Form, Request, Body, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field, SecretStr, field_validator, model_validator

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
from plan_builder import PlannerError, generate_plan  # type: ignore
from translate_showtech import (
    parse_showtech,
    load_mapping,
    find_copper_10g_ports,
)  # type: ignore
import ssh_collect
from fpdf import FPDF
from compliance import SiteAuditRunner, SiteContext, build_default_runner
from audit_fixes import execute_audit_action
from audit_actions import AP_RENAME_ACTION_ID
from audit_history import load_site_history

APP_TITLE = "Switch Port Config Frontend"
DEFAULT_BASE_URL = "https://api.ac2.mist.com/api/v1"  # adjust region if needed
DEFAULT_TZ = "America/New_York"

TEMPLATES_DIR = Path(__file__).resolve().parent.parent / "templates"

PAGE_COPY: dict[str, dict[str, str]] = {
    "config": {
        "title": "Config Conversion",
        "tagline": "Collect Cisco configs via SSH or upload files → map rows → batch test/push to Mist",
    },
    "audit": {
        "title": "Compliance Audit",
        "tagline": "Audit Mist sites for common configuration issues",
        "menu_label": "Compliance Audit",
    },
    "audit": {
        "title": "Compliance Audit",
        "tagline": "Audit Mist sites for common configuration issues",
        "menu_label": "Compliance Audit",
    },
    "hardware": {
        "title": "Hardware Conversion",
        "tagline": "Collect Cisco hardware via SSH or upload show tech files",
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

NAV_LINK_KEYS = ("hardware", "replacements", "config", "audit", "rules")


class SSHDeviceModel(BaseModel):
    host: str
    label: Optional[str] = None

    @field_validator("host")
    @classmethod
    def _clean_host(cls, value: str) -> str:
        cleaned = (value or "").strip()
        if not cleaned:
            raise ValueError("host is required")
        return cleaned

    @field_validator("label")
    @classmethod
    def _strip_label(cls, value: Optional[str]) -> Optional[str]:
        if value is None:
            return None
        cleaned = value.strip()
        return cleaned or None

    @model_validator(mode="after")
    def _default_label(self):
        if not self.label:
            self.label = self.host
        return self


class SSHJobRequest(BaseModel):
    username: str
    password: SecretStr
    devices: List[SSHDeviceModel]
    delay_factor: float = Field(default=1.0, ge=0.1, le=10.0)
    read_timeout: int = Field(default=90, ge=15, le=600)
    max_workers: int = Field(default=4, ge=1, le=16)

    @field_validator("username")
    @classmethod
    def _validate_username(cls, value: str) -> str:
        cleaned = (value or "").strip()
        if not cleaned:
            raise ValueError("username is required")
        return cleaned

    @field_validator("devices")
    @classmethod
    def _validate_devices(cls, value: List[SSHDeviceModel]) -> List[SSHDeviceModel]:
        if not value:
            raise ValueError("devices must not be empty")
        if len(value) > 64:
            raise ValueError("a maximum of 64 devices can be processed at once")
        return value


class TimingEvent(BaseModel):
    event: str = Field(..., min_length=1, max_length=64)
    duration_ms: float = Field(..., ge=0)
    metadata: Optional[Dict[str, Any]] = None

    @field_validator("event")
    @classmethod
    def _normalize_event(cls, value: str) -> str:
        cleaned = (value or "").strip()
        if not cleaned:
            raise ValueError("event must not be empty")
        normalized = re.sub(r"[^A-Za-z0-9_.-]", "_", cleaned.lower())
        return normalized[:64]


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

AUDIT_RUNNER: SiteAuditRunner = build_default_runner()


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


@app.post("/api/log_timing")
async def api_log_timing(request: Request, payload: TimingEvent):
    user_label = _request_user_label(request)
    client_host = request.client.host if request.client else "-"
    metadata = payload.metadata or {}
    try:
        metadata_json = json.dumps(metadata, sort_keys=True)
    except TypeError:
        metadata_json = json.dumps(str(metadata))
    action_logger.info(
        "timing event=%s user=%s client=%s duration_ms=%.2f metadata=%s",
        payload.event,
        user_label,
        client_host,
        payload.duration_ms,
        metadata_json,
    )
    return {"ok": True}

@app.get("/", response_class=HTMLResponse)
def index():
    return _render_page("index.html", "config")


@app.get("/audit", response_class=HTMLResponse)
def audit_page():
    return _render_page("audit.html", "audit")


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


def _site_display_name(data: Dict[str, Any], fallback: str = "") -> str:
    for key in ("name", "site_name", "display_name"):
        value = data.get(key)
        if isinstance(value, str) and value.strip():
            return value
    if fallback:
        return fallback
    value = data.get("id")
    return str(value) if value is not None else ""


def _mist_get_json(
    base_url: str,
    headers: Dict[str, str],
    path: str,
    *,
    optional: bool = False,
) -> Any:
    url = f"{base_url}{path}"
    response = requests.get(url, headers=headers, timeout=30)
    try:
        response.raise_for_status()
    except requests.HTTPError as exc:
        if optional and exc.response is not None and exc.response.status_code == 404:
            return None
        raise
    if not response.content:
        return None
    try:
        return response.json()
    except ValueError:
        return None


def _list_sites(base_url: str, headers: Dict[str, str], org_id: Optional[str] = None) -> List[Dict[str, Any]]:
    items: List[Dict[str, Any]] = []
    if org_id:
        r = requests.get(f"{base_url}/orgs/{org_id}/sites", headers=headers, timeout=30)
        r.raise_for_status()
        for s in r.json() or []:
            if not isinstance(s, dict):
                continue
            items.append(
                {
                    "id": s.get("id"),
                    "name": _site_display_name(s),
                    "org_id": org_id,
                }
            )
        return sorted(items, key=lambda x: (x["name"] or "").lower())

    org_ids = _discover_org_ids(base_url, headers)
    for oid in org_ids:
        try:
            r = requests.get(f"{base_url}/orgs/{oid}/sites", headers=headers, timeout=30)
            r.raise_for_status()
        except Exception:
            continue
        for s in r.json() or []:
            if not isinstance(s, dict):
                continue
            items.append(
                {
                    "id": s.get("id"),
                    "name": _site_display_name(s),
                    "org_id": oid,
                }
            )
    items.sort(key=lambda x: (x["name"] or "").lower())
    return items


def _collect_candidate_org_ids(*sources: Iterable[Any]) -> List[str]:
    """Return a list of potential org IDs discovered in the given sources."""

    ids: List[str] = []
    seen: set[str] = set()

    def _add(value: Any) -> None:
        if value is None:
            return
        text = str(value).strip()
        if not text or text in seen:
            return
        seen.add(text)
        ids.append(text)

    for source in sources:
        if isinstance(source, dict):
            _add(source.get("org_id"))
        elif isinstance(source, (list, tuple, set)):
            for item in source:
                if isinstance(item, dict):
                    _add(item.get("org_id"))

    if DEFAULT_ORG_ID:
        _add(DEFAULT_ORG_ID)

    return ids


def _fetch_switch_template_document(
    base_url: str,
    headers: Dict[str, str],
    site_id: str,
    template_id: str,
    org_ids: Sequence[str],
) -> Optional[Dict[str, Any]]:
    """Fetch a switch template using site and org scoped endpoints."""

    site_doc = _mist_get_json(
        base_url,
        headers,
        f"/sites/{site_id}/switch_templates/{template_id}",
        optional=True,
    )
    if isinstance(site_doc, dict) and site_doc:
        return site_doc

    for org_id in org_ids:
        org_doc = _mist_get_json(
            base_url,
            headers,
            f"/orgs/{org_id}/switch_templates/{template_id}",
            optional=True,
        )
        if isinstance(org_doc, dict) and org_doc:
            return org_doc

    return None


RECENT_LAST_SEEN_WINDOW_SECONDS = 14 * 24 * 60 * 60


def _current_timestamp() -> float:
    return datetime.now(tz=timezone.utc).timestamp()


def _coerce_epoch_seconds(value: Any) -> Optional[float]:
    if isinstance(value, (int, float)):
        candidate = float(value)
    elif isinstance(value, str):
        text = value.strip()
        if not text:
            return None
        try:
            candidate = float(text)
        except ValueError:
            try:
                normalized = text.replace("Z", "+00:00") if text.endswith("Z") else text
                parsed = datetime.fromisoformat(normalized)
            except ValueError:
                return None
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=timezone.utc)
            candidate = parsed.timestamp()
    else:
        return None
    if candidate <= 0:
        return None
    if candidate > 1e12:
        candidate /= 1000.0
    return candidate


def _extract_last_seen_timestamp(device: Mapping[str, Any]) -> Optional[float]:
    keys = ("last_seen", "lastSeen")
    candidates: List[Any] = []
    for key in keys:
        if key in device:
            candidates.append(device.get(key))
    for nested_key in ("details", "status"):
        nested = device.get(nested_key)
        if isinstance(nested, Mapping):
            for key in keys:
                if key in nested:
                    candidates.append(nested.get(key))
    timestamps = [ts for ts in (_coerce_epoch_seconds(value) for value in candidates) if ts is not None]
    if not timestamps:
        return None
    return max(timestamps)


def _is_recent_device(device: Mapping[str, Any], reference_ts: float) -> bool:
    last_seen_ts = _extract_last_seen_timestamp(device)
    if last_seen_ts is None:
        return False
    return last_seen_ts >= reference_ts - RECENT_LAST_SEEN_WINDOW_SECONDS


def _fetch_site_context(base_url: str, headers: Dict[str, str], site_id: str) -> SiteContext:
    raw_site = _mist_get_json(base_url, headers, f"/sites/{site_id}")
    site_doc = raw_site if isinstance(raw_site, dict) else {}
    site_name = _site_display_name(site_doc, fallback=site_id)
    setting_doc = _mist_get_json(base_url, headers, f"/sites/{site_id}/setting", optional=True)
    if not isinstance(setting_doc, dict):
        setting_doc = {}
    templates_doc = _mist_get_json(base_url, headers, f"/sites/{site_id}/networktemplates", optional=True)
    template_list = [t for t in templates_doc or [] if isinstance(t, dict)] if isinstance(templates_doc, list) else []

    base_devices_doc = _mist_get_json(base_url, headers, f"/sites/{site_id}/devices", optional=True)
    switch_devices_doc = _mist_get_json(
        base_url,
        headers,
        f"/sites/{site_id}/devices?type=switch",
        optional=True,
    )

    switch_stats_doc = _mist_get_json(
        base_url,
        headers,
        f"/sites/{site_id}/stats/devices?type=switch&limit=1000",
        optional=True,
    )
    ap_stats_doc = _mist_get_json(
        base_url,
        headers,
        f"/sites/{site_id}/stats/devices?type=ap&limit=1000",
        optional=True,
    )

    ordered_ids: List[str] = []
    devices_by_id: Dict[str, Dict[str, Any]] = {}
    anonymous_devices: List[Dict[str, Any]] = []

    def _ingest_devices(doc: Any) -> None:
        if not isinstance(doc, list):
            return
        for item in doc:
            if not isinstance(item, dict):
                continue
            device_id = item.get("id")
            if isinstance(device_id, str) and device_id:
                if device_id not in devices_by_id:
                    ordered_ids.append(device_id)
                    devices_by_id[device_id] = dict(item)
                else:
                    devices_by_id[device_id].update(item)
            else:
                anonymous_devices.append(dict(item))

    _ingest_devices(base_devices_doc)
    _ingest_devices(switch_devices_doc)

    def _normalize_mac(value: Any) -> str:
        if value is None:
            return ""
        return str(value).strip().lower()

    def _iter_stats(doc: Any):
        if isinstance(doc, list):
            for item in doc:
                if isinstance(item, dict):
                    yield item
            return
        if isinstance(doc, dict):
            containers = [doc.get(key) for key in ("results", "items", "data", "devices")]
            emitted = False
            for container in containers:
                if isinstance(container, list):
                    for item in container:
                        if isinstance(item, dict):
                            emitted = True
                            yield item
            if not emitted and doc:
                yield doc

    stats_payloads: List[Dict[str, Any]] = []
    stats_by_id: Dict[str, Dict[str, Any]] = {}
    stats_by_mac: Dict[str, Dict[str, Any]] = {}

    def _register_stats_item(item: Dict[str, Any]) -> None:
        item_copy = dict(item)
        stats_payloads.append(item_copy)
        for key in ("id", "device_id"):
            identifier = item.get(key)
            if isinstance(identifier, str) and identifier.strip():
                stats_by_id.setdefault(identifier.strip(), item_copy)
        mac = _normalize_mac(item.get("mac"))
        if mac:
            stats_by_mac.setdefault(mac, item_copy)

    for stats_doc in (switch_stats_doc, ap_stats_doc):
        if stats_doc is None:
            continue
        for stats_item in _iter_stats(stats_doc):
            _register_stats_item(stats_item)

    consumed_stats: Set[int] = set()

    def _claim_stats(device: Mapping[str, Any]) -> Optional[Dict[str, Any]]:
        stats: Optional[Dict[str, Any]] = None
        device_id = device.get("id")
        if isinstance(device_id, str) and device_id.strip():
            stats = stats_by_id.get(device_id.strip())
        if stats is None:
            mac = _normalize_mac(device.get("mac"))
            if mac:
                stats = stats_by_mac.get(mac)
        if stats is not None and id(stats) not in consumed_stats:
            consumed_stats.add(id(stats))
            return stats
        return None

    device_list: List[Dict[str, Any]] = []
    for device_id in ordered_ids:
        device = devices_by_id[device_id]
        detailed_doc: Optional[Dict[str, Any]] = None
        try:
            detailed = _mist_get_json(
                base_url,
                headers,
                f"/sites/{site_id}/devices/{device_id}",
                optional=True,
            )
        except Exception:
            detailed = None
        if isinstance(detailed, dict):
            detailed_doc = detailed
        merged: Dict[str, Any] = dict(device)
        if detailed_doc:
            merged.update({k: v for k, v in detailed_doc.items() if k not in {"id", "site_id"} or v is not None})
        stats_doc = _claim_stats(merged)
        if stats_doc:
            merged.update({k: v for k, v in stats_doc.items() if v is not None})
        device_list.append(merged)

    device_list.extend(anonymous_devices)
    for stats_doc in stats_payloads:
        if id(stats_doc) in consumed_stats:
            continue
        extra_device = dict(stats_doc)
        if not extra_device.get("id") and isinstance(extra_device.get("device_id"), str):
            extra_device.setdefault("id", extra_device["device_id"])
        device_list.append(extra_device)
    candidate_org_ids = _collect_candidate_org_ids(site_doc, setting_doc, template_list, device_list)

    reference_ts = _current_timestamp()
    filtered_devices: List[Dict[str, Any]] = []
    for device in device_list:
        if not isinstance(device, dict):
            continue
        if _is_recent_device(device, reference_ts):
            filtered_devices.append(device)

    device_list = filtered_devices

    if SWITCH_TEMPLATE_ID:
        template_doc = _fetch_switch_template_document(
            base_url,
            headers,
            site_id,
            SWITCH_TEMPLATE_ID,
            candidate_org_ids,
        )
        if isinstance(template_doc, dict):
            enriched_template = dict(template_doc)
            enriched_template.setdefault("id", SWITCH_TEMPLATE_ID)
            existing_ids = {
                str(t.get("id") or t.get("template_id")).strip()
                for t in template_list
                if isinstance(t, dict) and (t.get("id") or t.get("template_id"))
            }
            if SWITCH_TEMPLATE_ID not in existing_ids:
                template_list.append(enriched_template)
            else:
                for template in template_list:
                    identifier = str(template.get("id") or template.get("template_id") or "").strip()
                    if identifier == SWITCH_TEMPLATE_ID:
                        template.update(enriched_template)
                        break

    return SiteContext(
        site_id=site_id,
        site_name=site_name or site_id,
        site=site_doc,
        setting=setting_doc,
        templates=template_list,
        devices=device_list,
    )


def _gather_site_contexts(
    base_url: str,
    headers: Dict[str, str],
    site_ids: Sequence[str],
) -> tuple[List[SiteContext], List[Dict[str, Any]]]:
    contexts: List[SiteContext] = []
    errors: List[Dict[str, Any]] = []
    for site_id in site_ids:
        try:
            contexts.append(_fetch_site_context(base_url, headers, site_id))
        except requests.HTTPError as exc:
            status = exc.response.status_code if exc.response is not None else None
            detail: Any = None
            if exc.response is not None:
                try:
                    detail = exc.response.json()
                except Exception:
                    detail = exc.response.text
            errors.append(
                {
                    "site_id": site_id,
                    "error": str(exc),
                    "status": status,
                    "detail": detail,
                }
            )
        except Exception as exc:
            errors.append(
                {
                    "site_id": site_id,
                    "error": str(exc),
                }
            )
    return contexts, errors


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
        data = {}

    if not isinstance(data, dict):
        data = {}

    rules = data.get("rules")
    if not isinstance(rules, list):
        rules = []

    accessories_raw = data.get("accessories")
    accessories: List[str]
    if isinstance(accessories_raw, list):
        accessories = []
        for item in accessories_raw:
            if isinstance(item, str):
                name = item.strip()
                if name:
                    accessories.append(name)
    else:
        accessories = []

    data["rules"] = rules
    data["accessories"] = accessories
    return {"ok": True, "doc": data}


@app.post("/api/replacements")
def api_save_replacements(request: Request, doc: Dict[str, Any] = Body(...)):
    try:
        current_user(request)
        payload = doc if isinstance(doc, dict) else {}

        cleaned_rules: List[Dict[str, str]] = []
        for item in payload.get("rules", []) if isinstance(payload.get("rules"), list) else []:
            if not isinstance(item, dict):
                continue
            cisco = str(item.get("cisco", "")).strip()
            juniper = str(item.get("juniper", "")).strip()
            if cisco and juniper:
                cleaned_rules.append({"cisco": cisco, "juniper": juniper})

        accessories_input = payload.get("accessories", [])
        cleaned_accessories: List[str] = []
        seen = set()
        if isinstance(accessories_input, list):
            for accessory in accessories_input:
                if not isinstance(accessory, str):
                    continue
                name = accessory.strip()
                if not name:
                    continue
                key = name.casefold()
                if key in seen:
                    continue
                seen.add(key)
                cleaned_accessories.append(name)

        cleaned_doc = {"rules": cleaned_rules, "accessories": cleaned_accessories}

        REPLACEMENTS_PATH.write_text(json.dumps(cleaned_doc, indent=2), encoding="utf-8")
        return {"ok": True}
    except Exception as e:
        return JSONResponse({"ok": False, "error": str(e)}, status_code=500)


@app.post("/api/ssh/jobs")
def api_start_ssh_job(payload: SSHJobRequest):
    try:
        ssh_collect.cleanup_old_jobs()
        password_bytes = bytearray(payload.password.get_secret_value(), "utf-8")
        devices = [
            ssh_collect.DeviceInput(host=item.host, label=item.label)
            for item in payload.devices
        ]
        max_workers = max(1, min(payload.max_workers, len(devices)))
        job = ssh_collect.start_job(
            devices=devices,
            username=payload.username,
            password_bytes=password_bytes,
            delay_factor=payload.delay_factor,
            read_timeout=payload.read_timeout,
            max_workers=max_workers,
        )
        return {"ok": True, "job_id": job.id}
    except Exception as e:
        return JSONResponse({"ok": False, "error": str(e)}, status_code=500)


@app.get("/api/ssh/jobs/{job_id}")
def api_get_ssh_job(job_id: str):
    ssh_collect.cleanup_old_jobs()
    job = ssh_collect.get_job(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="job not found")
    return {"ok": True, "job": job.to_dict()}


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


def _safe_project_filename_fragment(value: str, max_length: int = 64) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9._-]+", "_", value or "").strip("._-")
    if not cleaned:
        return ""
    if len(cleaned) > max_length:
        cleaned = cleaned[:max_length].rstrip("._-")
    return cleaned


def _coerce_positive_decimal(value: Any) -> Optional[Decimal]:
    if isinstance(value, Decimal):
        num = value
    elif isinstance(value, (int, float)):
        if isinstance(value, float) and not math.isfinite(value):
            return None
        try:
            num = Decimal(str(value))
        except (InvalidOperation, ValueError):
            return None
    elif isinstance(value, str):
        cleaned = value.strip()
        if not cleaned:
            return None
        try:
            num = Decimal(cleaned)
        except (InvalidOperation, ValueError):
            return None
    else:
        return None
    if num <= 0:
        return None
    return num


def _format_decimal_quantity(value: Decimal) -> str:
    if value == value.to_integral():
        return str(int(value))
    normalized = value.normalize()
    text = format(normalized, "f").rstrip("0").rstrip(".")
    return text or format(normalized, "f")


def _build_bom_summary(
    results: Optional[Sequence[Mapping[str, Any]]],
    accessories: Optional[Sequence[Mapping[str, Any]]],
) -> list[tuple[str, Decimal]]:
    totals: defaultdict[str, Decimal] = defaultdict(lambda: Decimal(0))

    if results:
        for file_item in results:
            if not isinstance(file_item, Mapping):
                continue
            switches = file_item.get("switches")
            if isinstance(switches, Sequence):
                for switch in switches:
                    if not isinstance(switch, Mapping):
                        continue
                    items = switch.get("items")
                    if not isinstance(items, Sequence):
                        continue
                    for item in items:
                        if not isinstance(item, Mapping):
                            continue
                        replacement = str(item.get("replacement") or "").strip()
                        if not replacement:
                            continue
                        qty = _coerce_positive_decimal(item.get("count"))
                        if qty is None:
                            continue
                        totals[replacement] += qty
            copper_ports = file_item.get("copper_10g_ports")
            if isinstance(copper_ports, Mapping):
                copper_qty = _coerce_positive_decimal(copper_ports.get("total"))
                if copper_qty is not None:
                    totals["SFPP-10G-T"] += copper_qty

    if accessories:
        for accessory in accessories:
            if not isinstance(accessory, Mapping):
                continue
            name = str(accessory.get("name") or "").strip()
            if not name:
                continue
            qty = _coerce_positive_decimal(accessory.get("quantity"))
            if qty is None:
                qty = Decimal(1)
            totals[name] += qty

    summary = sorted(totals.items(), key=lambda kv: kv[0].lower())
    return summary


@app.post("/api/showtech/pdf")
def api_showtech_pdf(data: Dict[str, Any] = Body(...)):
    pdf = FPDF()
    try:
        pdf.set_compression(False)
    except AttributeError:
        pass
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.add_page()
    logo_path = static_path / "reportlogo.png"
    if logo_path.exists():
        logo_width = 50
        try:
            pdf.image(str(logo_path), x=pdf.w - pdf.r_margin - logo_width, y=pdf.t_margin, w=logo_width)
        except RuntimeError:
            # Ignore image errors and continue rendering the report
            pass

    pdf.set_font("Helvetica", "B", 16)
    pdf.cell(0, 10, "Hardware Conversion Report", ln=True)

    project_name = str(data.get("project_name") or "").strip()
    generated_by = data.get("generated_by") or "Unknown user"
    try:
        tz = ZoneInfo(os.environ.get("TZ", DEFAULT_TZ))
    except Exception:
        tz = None
    now = datetime.now(tz) if tz else datetime.now()
    generated_on = now.strftime("%Y-%m-%d %H:%M %Z") if tz else now.strftime("%Y-%m-%d %H:%M")

    pdf.set_font("Helvetica", size=12)
    if project_name:
        pdf.cell(0, 8, f"Project: {project_name}", ln=True)
    pdf.cell(0, 8, f"Generated by: {generated_by}", ln=True)
    pdf.cell(0, 8, f"Generated on: {generated_on}", ln=True)
    pdf.ln(5)

    bom_summary = _build_bom_summary(data.get("results"), data.get("accessories"))
    if bom_summary:
        pdf.set_font("Helvetica", "B", 14)
        pdf.cell(0, 10, "Bill of Materials Summary", ln=True)
        pdf.set_font("Helvetica", size=12)
        for name, qty in bom_summary:
            pdf.cell(0, 10, f"{_format_decimal_quantity(qty)} - {name}", ln=True)
        pdf.ln(5)

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

    accessories_output = []
    for item in data.get("accessories", []) or []:
        if not isinstance(item, dict):
            continue
        name = str(item.get("name", "")).strip()
        if not name:
            continue
        quantity = item.get("quantity")
        quantity_text = ""
        if isinstance(quantity, (int, float)):
            if isinstance(quantity, float) and not quantity.is_integer():
                quantity_text = str(quantity)
            else:
                quantity_text = str(int(quantity))
        elif isinstance(quantity, str):
            quantity_text = quantity.strip()
        accessories_output.append((name, quantity_text))

    if accessories_output:
        pdf.ln(3)
        pdf.set_font("Helvetica", "B", 14)
        pdf.cell(0, 10, "Accessories", ln=True)
        pdf.set_font("Helvetica", size=12)
        for name, qty_text in accessories_output:
            line = f"{name} (Qty: {qty_text})" if qty_text else name
            pdf.cell(0, 10, line, ln=True)
        pdf.ln(5)
    # fpdf2 returns a bytearray; convert it to bytes for the response
    pdf_bytes = bytes(pdf.output())
    filename_fragment = _safe_project_filename_fragment(project_name)
    if filename_fragment:
        download_name = f"hardware_conversion_report_{filename_fragment}.pdf"
    else:
        download_name = "hardware_conversion_report.pdf"
    headers = {"Content-Disposition": f"attachment; filename={download_name}"}
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

    try:
        items = _list_sites(base_url, headers, org_id=org_id)
        return {"ok": True, "items": items}
    except requests.HTTPError as exc:
        response = exc.response
        status = response.status_code if response is not None else 500
        if response is not None:
            try:
                err_payload: Any = response.json()
            except Exception:
                err_payload = response.text
        else:
            err_payload = str(exc)
        return JSONResponse({"ok": False, "error": err_payload}, status_code=status)
    except Exception as e:
        return JSONResponse({"ok": False, "error": str(e)}, status_code=500)


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


@app.post("/api/audit/run")
def api_audit_run(
    request: Request,
    payload: Dict[str, Any] = Body(...),
    base_url: str = DEFAULT_BASE_URL,
):
    try:
        current_user(request)

        site_ids_raw = payload.get("site_ids") or []
        if site_ids_raw and not isinstance(site_ids_raw, list):
            raise ValueError("site_ids must be a list of site identifiers")

        entire_org = bool(payload.get("entire_org"))
        requested_org_id = (payload.get("org_id") or "").strip() or None

        base_url = base_url.rstrip("/")
        token = _load_mist_token()
        headers = {"Authorization": f"Token {token}", "Accept": "application/json"}

        site_ids: List[str] = []
        if entire_org:
            sites = _list_sites(base_url, headers, org_id=requested_org_id)
            for item in sites:
                site_id = item.get("id")
                if isinstance(site_id, str) and site_id:
                    site_ids.append(site_id)
        else:
            for value in site_ids_raw:
                if value is None:
                    continue
                text = str(value).strip()
                if text:
                    site_ids.append(text)

        # Deduplicate while preserving order
        unique_site_ids: List[str] = []
        seen_ids: set[str] = set()
        for sid in site_ids:
            if sid not in seen_ids:
                seen_ids.add(sid)
                unique_site_ids.append(sid)

        if not unique_site_ids:
            raise ValueError("Select at least one site or choose Entire Org.")

        tz_name = os.environ.get("TZ", DEFAULT_TZ)
        try:
            tz = ZoneInfo(tz_name)
        except Exception:
            tz = None
        started_at = datetime.now(tz) if tz else datetime.now()
        timer = perf_counter()

        contexts, errors = _gather_site_contexts(base_url, headers, unique_site_ids)
        audit_result = AUDIT_RUNNER.run(contexts)
        duration_ms = int((perf_counter() - timer) * 1000)
        finished_at = datetime.now(tz) if tz else datetime.now()

        site_findings = audit_result.get("site_findings", {}) or {}
        site_devices = audit_result.get("site_devices", {}) or {}
        history_records = load_site_history([ctx.site_name for ctx in contexts])
        history_by_name = {
            name: history.as_dict()
            for name, history in history_records.items()
        }
        site_history: Dict[str, Optional[Dict[str, Any]]] = {}
        summary_sites = []
        for ctx in contexts:
            history = history_by_name.get(ctx.site_name)
            summary_sites.append(
                {
                    "id": ctx.site_id,
                    "name": ctx.site_name,
                    "org_id": ctx.site.get("org_id") or ctx.setting.get("org_id"),
                    "issues": site_findings.get(ctx.site_id, 0),
                    "devices": site_devices.get(ctx.site_id, 0),
                    "history": history,
                }
            )
            site_history[ctx.site_id] = history

        summary = {
            "ok": True,
            "checks": audit_result.get("checks", []),
            "total_sites": audit_result.get("total_sites", 0),
            "total_devices": audit_result.get("total_devices", 0),
            "total_findings": audit_result.get("total_findings", 0),
            "total_quick_fix_issues": audit_result.get("total_quick_fix_issues", 0),
            "errors": errors,
            "sites": summary_sites,
            "site_findings": site_findings,
            "site_history": site_history,
            "started_at": started_at.isoformat(),
            "finished_at": finished_at.isoformat(),
            "duration_ms": duration_ms,
        }

        breakdown = ", ".join(f"{site['name']}:{site['issues']}" for site in summary_sites) or "none"
        device_breakdown = ", ".join(
            f"{site['name']}:{site['devices']}" for site in summary_sites
        ) or "none"

        action_logger.info(
            "user=%s action=audit_run sites=%s devices=%s issues=%s errors=%s started=%s duration_ms=%s site_issue_breakdown=%s site_device_breakdown=%s",
            _request_user_label(request),
            len(unique_site_ids),
            summary["total_devices"],
            summary["total_findings"],
            len(errors),
            summary["started_at"],
            duration_ms,
            breakdown,
            device_breakdown,
        )

        return summary
    except ValueError as exc:
        return JSONResponse({"ok": False, "error": str(exc)}, status_code=400)
    except requests.HTTPError as exc:
        response = exc.response
        status = response.status_code if response is not None else 500
        if response is not None:
            try:
                err_payload: Any = response.json()
            except Exception:
                err_payload = response.text
        else:
            err_payload = str(exc)
        action_logger.error(
            "user=%s action=audit_run status=%s error=%s",
            _request_user_label(request),
            status,
            err_payload,
        )
        return JSONResponse({"ok": False, "error": err_payload}, status_code=status)
    except Exception as exc:
        action_logger.error(
            "user=%s action=audit_run error=%s",
            _request_user_label(request),
            exc,
        )
        return JSONResponse({"ok": False, "error": str(exc)}, status_code=500)


@app.post("/api/audit/fix")
def api_audit_fix(
    request: Request,
    payload: Dict[str, Any] = Body(...),
    base_url: str = DEFAULT_BASE_URL,
):
    try:
        _ensure_push_allowed(request, dry_run=False)

        action_id = str(payload.get("action_id") or "").strip()
        if not action_id:
            raise ValueError("action_id is required")

        site_ids_raw = payload.get("site_ids") or []
        if site_ids_raw and not isinstance(site_ids_raw, list):
            raise ValueError("site_ids must be provided as a list")

        site_ids: List[str] = []
        for sid in site_ids_raw:
            if sid is None:
                continue
            text = str(sid).strip()
            if text:
                site_ids.append(text)

        devices_raw = payload.get("devices") or []
        device_map: Dict[str, List[str]] = {}
        if devices_raw:
            if not isinstance(devices_raw, list):
                raise ValueError("devices must be provided as a list")
            for entry in devices_raw:
                if not isinstance(entry, dict):
                    continue
                site_id_raw = entry.get("site_id")
                device_id_raw = entry.get("device_id")
                site_id = str(site_id_raw).strip() if site_id_raw is not None else ""
                device_id = str(device_id_raw).strip() if device_id_raw is not None else ""
                if not site_id or not device_id:
                    continue
                device_map.setdefault(site_id, []).append(device_id)
                if site_id not in site_ids:
                    site_ids.append(site_id)

        if not site_ids:
            raise ValueError("Provide at least one site identifier.")

        # Deduplicate device identifiers per site while preserving order
        if device_map:
            for site_id, devices in list(device_map.items()):
                seen: set[str] = set()
                deduped: List[str] = []
                for device_id in devices:
                    if device_id not in seen:
                        seen.add(device_id)
                        deduped.append(device_id)
                device_map[site_id] = deduped

        dry_run = bool(payload.get("dry_run", False))
        pause_default = 0.2 if action_id == AP_RENAME_ACTION_ID else 0.1
        pause_value = payload.get("pause")
        try:
            pause = float(pause_value)
            if pause < 0:
                pause = 0.0
        except (TypeError, ValueError):
            pause = pause_default

        token = _load_mist_token()
        base_url = base_url.rstrip("/")
        result = execute_audit_action(
            action_id,
            base_url,
            token,
            site_ids,
            dry_run=dry_run,
            pause=pause,
            device_map=device_map if device_map else None,
        )

        totals = result.get("totals", {}) if isinstance(result, dict) else {}
        updated_total = totals.get("updated")
        if not isinstance(updated_total, (int, float)):
            updated_total = totals.get("renamed", 0)
        action_logger.info(
            "user=%s action=audit_fix fix_id=%s dry_run=%s sites=%s updated=%s failed=%s",
            _request_user_label(request),
            action_id,
            dry_run,
            totals.get("sites", 0),
            updated_total,
            totals.get("failed", 0),
        )
        return result
    except ValueError as exc:
        return JSONResponse({"ok": False, "error": str(exc)}, status_code=400)
    except requests.HTTPError as exc:
        response = exc.response
        status = response.status_code if response is not None else 500
        try:
            detail = response.json() if response is not None else None
        except Exception:
            detail = response.text if response is not None else None
        action_logger.error(
            "user=%s action=audit_fix status=%s error=%s",
            _request_user_label(request),
            status,
            detail or str(exc),
        )
        return JSONResponse({"ok": False, "error": str(exc)}, status_code=status)
    except Exception as exc:
        action_logger.exception(
            "user=%s action=audit_fix error=%s",
            _request_user_label(request),
            exc,
        )
        return JSONResponse({"ok": False, "error": "Unexpected remediation failure."}, status_code=500)


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
    planner_persist_dir = Path(__file__).resolve().parent / "logs" / "planner"
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

            plan_doc: Optional[Dict[str, Any]] = None
            final_doc: Optional[Dict[str, Any]] = None
            planner_errors: List[str] = []
            planner_error: Optional[str] = None
            persisted_dir: Optional[Path] = None
            try:
                plan_result = generate_plan(
                    out_path,
                    output_dir=tmpdir_path,
                    persist_dir=planner_persist_dir,
                )
                plan_doc = plan_result.plan_doc
                final_doc = plan_result.final_doc
                planner_errors = list(plan_result.errors)
                if plan_result.persisted_plan_path:
                    persisted_dir = plan_result.persisted_plan_path.parent
            except PlannerError as exc:
                planner_error = str(exc)
            except Exception as exc:  # pragma: no cover - defensive
                planner_error = f"Unexpected planner failure: {exc}"

            item = {"source_file": uf.filename, "output_file": out_path.name, "json": data}
            if plan_doc is not None and final_doc is not None:
                item.update(
                    {
                        "plan_file": plan_result.plan_path.name,
                        "final_file": plan_result.final_path.name,
                        "plan": plan_doc,
                        "final": final_doc,
                        "planner_errors": planner_errors,
                    }
                )
                if persisted_dir:
                    item["planner_persist_dir"] = str(persisted_dir)
            else:
                item["planner_error"] = planner_error or "Planner was skipped"

            results.append(item)

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
