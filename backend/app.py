import os
import json
import tempfile
import re
import math
import hashlib
from collections import defaultdict
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import List, Optional, Dict, Any, Sequence, Iterable, Mapping, Set, Tuple
from zoneinfo import ZoneInfo
from time import perf_counter
import copy

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


def _mist_headers(token: str) -> Dict[str, str]:
    return {
        "Authorization": f"Token {token}",
        "Accept": "application/json",
        "Content-Type": "application/json",
    }


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

    if isinstance(payload_in, list):
        payload_in = {"interfaces": payload_in}

    temp_source = copy.deepcopy(payload_in)

    # Build port_config
    port_config = ensure_port_config(payload_in, model)

    member_offset_val = int(member_offset or 0)
    port_offset_val = int(port_offset or 0)
    normalize_flag = bool(normalize_modules)

    # Apply member/port remap BEFORE excludes
    port_config = remap_members(port_config, member_offset=member_offset_val, normalize=normalize_flag)
    port_config = remap_ports(port_config, port_offset=port_offset_val, model=model)

    temp_interfaces = temp_source.get("interfaces") if isinstance(temp_source, dict) else None
    if isinstance(temp_interfaces, list):
        temp_map: Dict[str, Dict[str, Any]] = {}
        for intf in temp_interfaces:
            if not isinstance(intf, Mapping):
                continue
            key = str(intf.get("juniper_if") or intf.get("name") or "").strip()
            if not key:
                continue
            temp_map[key] = dict(intf)
        if temp_map:
            temp_map = remap_members(temp_map, member_offset=member_offset_val, normalize=normalize_flag)
            temp_map = remap_ports(temp_map, port_offset=port_offset_val, model=model)
            temp_interfaces_out: List[Dict[str, Any]] = []
            for ifname, data in temp_map.items():
                updated = dict(data)
                updated["juniper_if"] = ifname
                temp_interfaces_out.append(updated)
            temp_source["interfaces"] = temp_interfaces_out

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
        if isinstance(temp_source, dict) and isinstance(temp_source.get("interfaces"), list):
            filtered_interfaces = [
                intf
                for intf in temp_source.get("interfaces", [])
                if isinstance(intf, Mapping) and str(intf.get("juniper_if") or "").strip() not in exclude_set
            ]
            temp_source["interfaces"] = filtered_interfaces

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
            "payload": put_body,
            "_temp_config_source": temp_source,
        }

    # live push
    if not validation.get("ok"):
        return {
            "ok": False,
            "dry_run": False,
            "error": "Model capacity mismatch",
            "validation": validation,
            "payload": put_body,
            "_temp_config_source": temp_source,
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
        "payload": put_body,
        "_temp_config_source": temp_source,
    }


def _extract_mist_error(resp: requests.Response) -> str:
    try:
        data = resp.json()
    except Exception:
        data = None

    if isinstance(data, dict):
        for key in ("error", "message", "detail", "details"):
            value = data.get(key)
            if isinstance(value, str):
                text = value.strip()
                if text:
                    return text
            if isinstance(value, list):
                joined = "; ".join(str(item).strip() for item in value if str(item).strip())
                if joined:
                    return joined
    text = resp.text.strip()
    return text or f"HTTP {resp.status_code}"


def _safe_json_response(resp: requests.Response) -> Any:
    try:
        return resp.json()
    except Exception:
        text = resp.text.strip()
        return {"text": text} if text else None


class MistAPIError(RuntimeError):
    def __init__(self, status_code: int, message: str, *, response: Any = None):
        super().__init__(message)
        self.status_code = status_code
        self.response = response


def _invoke_batch_phase(
    results: Sequence[Dict[str, Any]],
    *,
    base_url: str,
    token: str,
    dry_run: bool,
    method: str,
    path_template: str,
    success_template: str,
    partial_template: str,
    skip_message: str,
    empty_message: str,
    body_getter: Optional[Any] = None,
    timeout: int = 60,
    include_payloads: bool = False,
) -> Dict[str, Any]:
    ok_rows = [
        r for r in results if r.get("ok") and r.get("site_id") and r.get("device_id")
    ]
    total = len(ok_rows)
    if total == 0:
        return {
            "ok": True,
            "skipped": True,
            "message": empty_message,
            "successes": 0,
            "failures": [],
            "total": 0,
        }

    payload_records: List[Dict[str, Any]] = []

    def _capture_payload(row: Mapping[str, Any]) -> Optional[Dict[str, Any]]:
        if not callable(body_getter):
            return None
        try:
            payload_obj = body_getter(row)
        except Exception:
            return None
        return payload_obj

    if dry_run:
        if include_payloads and callable(body_getter):
            for row in ok_rows:
                site_id = str(row.get("site_id") or "").strip()
                device_id = str(row.get("device_id") or "").strip()
                if not site_id or not device_id:
                    continue
                payload_obj = _capture_payload(row)
                if payload_obj is not None:
                    payload_records.append(
                        {
                            "site_id": site_id,
                            "device_id": device_id,
                            "payload": copy.deepcopy(payload_obj),
                        }
                    )

        response: Dict[str, Any] = {
            "ok": True,
            "skipped": True,
            "message": skip_message.format(total=total),
            "successes": 0,
            "failures": [],
            "total": total,
        }
        if include_payloads:
            response["payloads"] = payload_records
        return response

    headers = {
        "Authorization": f"Token {token}",
        "Accept": "application/json",
        "Content-Type": "application/json",
    }

    successes = 0
    failures: List[Dict[str, Any]] = []
    method_upper = method.upper()

    for row in ok_rows:
        site_id = str(row.get("site_id") or "").strip()
        device_id = str(row.get("device_id") or "").strip()
        if not site_id or not device_id:
            continue

        url = f"{base_url}{path_template.format(site_id=site_id, device_id=device_id)}"
        payload = _capture_payload(row)

        if include_payloads and payload is not None:
            payload_records.append(
                {
                    "site_id": site_id,
                    "device_id": device_id,
                    "payload": copy.deepcopy(payload),
                }
            )

        try:
            request_kwargs: Dict[str, Any] = {"headers": headers, "timeout": timeout}
            if payload is not None and method_upper != "DELETE":
                request_kwargs["json"] = payload
            resp = requests.request(method_upper, url, **request_kwargs)
            if 200 <= resp.status_code < 300:
                successes += 1
            else:
                failures.append(
                    {
                        "site_id": site_id,
                        "device_id": device_id,
                        "status": resp.status_code,
                        "message": _extract_mist_error(resp),
                    }
                )
        except Exception as exc:  # pragma: no cover - network failures are reported to the UI
            failures.append(
                {
                    "site_id": site_id,
                    "device_id": device_id,
                    "status": None,
                    "message": str(exc),
                }
            )

    if failures:
        response = {
            "ok": False,
            "skipped": False,
            "message": partial_template.format(successes=successes, total=total),
            "successes": successes,
            "failures": failures,
            "total": total,
        }
        if include_payloads:
            response["payloads"] = payload_records
        return response

    response = {
        "ok": True,
        "skipped": False,
        "message": success_template.format(count=successes, total=total),
        "successes": successes,
        "failures": [],
        "total": total,
    }
    if include_payloads:
        response["payloads"] = payload_records
    return response


def _int_or_none(value: Any) -> Optional[int]:
    if value is None:
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _normalize_vlan_values(values: Any) -> List[int]:
    out: List[int] = []
    if isinstance(values, (list, tuple, set)):
        for item in values:
            v = _int_or_none(item)
            if v is not None:
                out.append(v)
    elif isinstance(values, str):
        for part in [p.strip() for p in values.split(",") if p.strip()]:
            v = _int_or_none(part)
            if v is not None:
                out.append(v)
    out_sorted = sorted(dict.fromkeys(out))
    return out_sorted


def _compact_dict(data: Mapping[str, Any]) -> Dict[str, Any]:
    return {k: v for k, v in data.items() if v not in (None, "", [], {}, set())}


def _generate_temp_network_name(vlan_id: int, raw_name: Optional[str]) -> str:
    base = str(raw_name or "").strip()
    if base:
        # Replace whitespace with underscores and strip non-alphanumerics to keep Mist happy
        base = re.sub(r"\s+", "_", base)
        base = re.sub(r"[^A-Za-z0-9_-]", "", base)
        base = base.strip("-_")
    if not base:
        base = f"vlan{vlan_id}"
    lowered = base.lower()
    if not lowered.startswith("old_"):
        base = f"old_{base}"

    name = base.lower()

    if len(name) > 32:
        digest = hashlib.sha1(name.encode("utf-8")).hexdigest()[:6]
        # Leave space for underscore + digest (7 characters)
        prefix = name[: max(32 - 7, 4)].rstrip("-_")
        name = f"{prefix}_{digest}" if prefix else f"old_{digest}"

    # Mist network names must start with a letter; ensure the prefix guarantees it
    if not name or not name[0].isalpha():
        name = f"old_{name}"
        if len(name) > 32:
            name = name[:32]

    return name


def _rename_network_fields(record: Mapping[str, Any], rename_map: Mapping[str, str]) -> None:
    if not isinstance(record, Mapping) or not rename_map:
        return
    network_keys = (
        "port_network",
        "voip_network",
        "guest_network",
        "server_reject_network",
        "server_fail_network",
        "native_network",
    )
    mutable = getattr(record, "__setitem__", None)
    for key in network_keys:
        value = record.get(key)
        replacement = rename_map.get(value) if isinstance(value, str) else None
        if replacement is not None and mutable is not None:
            record[key] = replacement  # type: ignore[index]

    list_keys = ("networks", "dynamic_vlan_networks")
    for key in list_keys:
        value = record.get(key)
        if isinstance(value, list):
            record[key] = [rename_map.get(item, item) for item in value]  # type: ignore[index]
        elif isinstance(value, tuple):
            record[key] = tuple(rename_map.get(item, item) for item in value)  # type: ignore[index]


def _apply_network_rename_to_payload(payload: Mapping[str, Any], rename_map: Mapping[str, str]) -> None:
    if not isinstance(payload, Mapping) or not rename_map:
        return

    def _rename_network_entries(entries: Any) -> Any:
        if isinstance(entries, list):
            for entry in entries:
                if isinstance(entry, Mapping):
                    name = entry.get("name")
                    new_name = rename_map.get(name) if isinstance(name, str) else None
                    if new_name is not None:
                        entry["name"] = new_name  # type: ignore[index]
                    _rename_network_fields(entry, rename_map)
        elif isinstance(entries, Mapping):
            updated: Dict[Any, Any] = {}
            for key, entry in entries.items():
                new_key = rename_map.get(key, key) if isinstance(key, str) else key
                new_entry = entry
                if isinstance(entry, Mapping):
                    new_entry = dict(entry)
                    name = new_entry.get("name")
                    new_name = rename_map.get(name) if isinstance(name, str) else None
                    if new_name is not None:
                        new_entry["name"] = new_name
                    _rename_network_fields(new_entry, rename_map)
                updated[new_key] = new_entry
            return updated
        return entries

    networks_value = payload.get("networks")
    if networks_value is not None:
        updated_networks = _rename_network_entries(networks_value)
        if isinstance(networks_value, Mapping) and isinstance(payload, dict):
            payload["networks"] = updated_networks

    vlans_value = payload.get("vlans")
    if vlans_value is not None:
        updated_vlans = _rename_network_entries(vlans_value)
        if isinstance(vlans_value, Mapping) and isinstance(payload, dict):
            payload["vlans"] = updated_vlans

    port_usages = payload.get("port_usages")
    if isinstance(port_usages, Mapping):
        for usage in port_usages.values():
            if isinstance(usage, Mapping):
                _rename_network_fields(usage, rename_map)

    port_profiles = payload.get("port_profiles")
    if isinstance(port_profiles, list):
        for profile in port_profiles:
            if isinstance(profile, Mapping):
                _rename_network_fields(profile, rename_map)

    port_overrides = payload.get("port_overrides")
    if isinstance(port_overrides, list):
        for override in port_overrides:
            if isinstance(override, Mapping):
                _rename_network_fields(override, rename_map)

    port_config = payload.get("port_config")
    if isinstance(port_config, Mapping):
        for cfg in port_config.values():
            if isinstance(cfg, Mapping):
                _rename_network_fields(cfg, rename_map)


def _collect_network_entries(networks: Mapping[str, Any]) -> List[Dict[str, Any]]:
    entries: List[Dict[str, Any]] = []
    if not isinstance(networks, Mapping):
        return entries
    for key, data in networks.items():
        if not isinstance(data, Mapping):
            continue
        vid = _int_or_none(data.get("vlan_id") or data.get("id"))
        if vid is None:
            continue
        raw_name = None
        if isinstance(data.get("name"), str) and data.get("name").strip():
            raw_name = data.get("name").strip()
        elif isinstance(key, str) and key.strip():
            raw_name = key.strip()
        entries.append({"id": vid, "name": raw_name or str(vid)})
    return entries


def _dedupe_with_template_priority(
    template_vlans: Sequence[Mapping[str, Any]],
    device_vlans: Sequence[Mapping[str, Any]],
) -> Dict[int, Dict[str, Any]]:
    by_id: Dict[int, Dict[str, Any]] = {}
    for entry in device_vlans:
        vid = _int_or_none(entry.get("id") or entry.get("vlan_id"))
        if vid is None:
            continue
        name = str(entry.get("name") or "").strip() or str(vid)
        by_id[vid] = {"id": vid, "name": name}
    for entry in template_vlans:
        vid = _int_or_none(entry.get("id") or entry.get("vlan_id"))
        if vid is None:
            continue
        name = str(entry.get("name") or "").strip() or str(vid)
        by_id[vid] = {"id": vid, "name": name}
    return by_id


def _collect_existing_vlan_names(
    *network_maps: Mapping[str, Any]
) -> Dict[int, Set[str]]:
    conflicts: Dict[int, Set[str]] = {}
    for networks in network_maps:
        if not isinstance(networks, Mapping):
            continue
        for key, data in networks.items():
            if not isinstance(data, Mapping):
                continue
            vid = _int_or_none(data.get("vlan_id") or data.get("id"))
            if vid is None:
                continue
            name = None
            if isinstance(data.get("name"), str) and data.get("name").strip():
                name = data.get("name").strip()
            elif isinstance(key, str) and key.strip():
                name = key.strip()
            else:
                name = str(vid)
            conflicts.setdefault(vid, set()).add(name)
    return conflicts


def _collect_existing_vlan_details(
    template_networks: Dict[str, Dict[str, Any]],
    device_networks: Dict[str, Dict[str, Any]],
) -> Tuple[Set[int], Dict[int, Set[str]]]:
    template_entries = _collect_network_entries(template_networks)
    device_entries = _collect_network_entries(device_networks)
    deduped = _dedupe_with_template_priority(template_entries, device_entries)
    conflicts = _collect_existing_vlan_names(device_networks, template_networks)
    return set(deduped.keys()), conflicts


def _resolve_network_conflicts(
    networks_new: Dict[str, Dict[str, Any]],
    port_profiles_seq: List[Dict[str, Any]],
    port_usages_seq: List[Dict[str, Any]],
    existing_conflicts: Mapping[int, Set[str]],
) -> Tuple[
    Dict[str, Dict[str, Any]],
    List[Dict[str, Any]],
    List[Dict[str, Any]],
    Dict[str, str],
    List[str],
]:
    rename_map: Dict[str, str] = {}
    warnings: List[str] = []

    if not networks_new:
        return networks_new, port_profiles_seq, port_usages_seq, rename_map, warnings

    for original_name, data in list(networks_new.items()):
        if not isinstance(data, Mapping):
            continue
        vid = _int_or_none(data.get("vlan_id") or data.get("id"))
        if vid is None:
            continue
        conflict_names = existing_conflicts.get(vid) if isinstance(existing_conflicts, Mapping) else None
        if not conflict_names:
            continue
        networks_new.pop(original_name, None)
        preferred_name = sorted(conflict_names)[0]
        rename_map[original_name] = preferred_name
        warnings.append(
            "Detected VLAN ID {vid} already configured on Mist as {conflicts}; "
            "no temporary network changes were staged for this VLAN.".format(
                vid=vid,
                conflicts=", ".join(sorted(conflict_names)),
            )
        )

    if rename_map:
        for seq in (port_profiles_seq, port_usages_seq):
            for profile in seq:
                if isinstance(profile, Mapping):
                    _rename_network_fields(profile, rename_map)

    return networks_new, port_profiles_seq, port_usages_seq, rename_map, warnings


def _generate_temp_usage_name(
    *,
    mode: str,
    data_vlan: Optional[int],
    voice_vlan: Optional[int],
    native_vlan: Optional[int],
    allowed_vlans: Sequence[int],
) -> str:
    parts: List[str] = ["old", "access" if mode == "access" else "trunk"]

    if mode == "access":
        if data_vlan is not None:
            parts.append(f"vlan{data_vlan}")
        else:
            parts.append("vlan_unassigned")
        if voice_vlan is not None:
            parts.append(f"voice{voice_vlan}")
    else:
        if native_vlan is not None:
            parts.append(f"native{native_vlan}")
        if allowed_vlans:
            allowed_tokens = [f"v{vid}" for vid in allowed_vlans]
            parts.append("allow_" + "_".join(allowed_tokens))
        else:
            parts.append("all")

    name = "_".join(parts)
    name = re.sub(r"[^A-Za-z0-9_-]", "_", name)
    name = name.lower()
    if not name.startswith("old_"):
        name = f"old_{name}"

    if len(name) > 32:
        digest = hashlib.sha1(name.encode("utf-8")).hexdigest()[:6]
        prefix = name[: max(32 - 7, 4)].rstrip("-_")
        name = f"{prefix}_{digest}" if prefix else f"old_{digest}"

    return name


def _normalize_port_profile_list(value: Any) -> List[Dict[str, Any]]:
    profiles: Dict[str, Dict[str, Any]] = {}
    if isinstance(value, Mapping):
        for name, data in value.items():
            if not isinstance(data, Mapping):
                continue
            entry = dict(data)
            entry.setdefault("name", str(name))
            key = entry.get("name")
            if isinstance(key, str) and key.strip():
                profiles[key] = entry
    elif isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        for item in value:
            if not isinstance(item, Mapping):
                continue
            name = str(item.get("name") or "").strip()
            if not name:
                continue
            profiles[name] = dict(item)
    return list(profiles.values())


def _normalize_port_override_list(value: Any) -> List[Dict[str, Any]]:
    overrides: Dict[str, Dict[str, Any]] = {}
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        for item in value:
            if not isinstance(item, Mapping):
                continue
            port_id = str(item.get("port_id") or "").strip()
            if not port_id:
                continue
            overrides[port_id] = dict(item)
    elif isinstance(value, Mapping):
        # Some APIs return overrides keyed by port ID
        for port_id, item in value.items():
            if not isinstance(item, Mapping):
                continue
            port_key = str(port_id or "").strip()
            if not port_key:
                continue
            overrides[port_key] = dict(item)
    return list(overrides.values())


def _normalize_network_map(value: Any, *, sanitize: bool) -> Dict[str, Dict[str, Any]]:
    networks: Dict[str, Dict[str, Any]] = {}
    if isinstance(value, Mapping):
        items: Iterable[Tuple[Optional[str], Any]] = value.items()
    elif isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        items = ((None, entry) for entry in value)
    else:
        return networks

    for key, entry in items:
        if not isinstance(entry, Mapping):
            continue
        data = dict(entry)
        vid = _int_or_none(data.get("vlan_id") or data.get("id"))
        raw_name = None
        if isinstance(key, str) and key.strip():
            raw_name = key.strip()
        elif isinstance(data.get("name"), str) and data.get("name").strip():
            raw_name = data.get("name").strip()

        if sanitize:
            if vid is None:
                continue
            name = _generate_temp_network_name(vid, raw_name)
            sanitized = {
                k: v
                for k, v in data.items()
                if k not in {"name", "id", "source_name", "temporary"}
                and v not in (None, "")
            }
            sanitized["vlan_id"] = vid
            networks[name] = sanitized
        else:
            if raw_name:
                name = raw_name
            elif vid is not None:
                name = _generate_temp_network_name(vid, raw_name)
            else:
                continue
            if vid is not None:
                data["vlan_id"] = vid
            networks[name] = data

    return networks


def _load_site_template_networks(
    base_url: str,
    headers: Dict[str, str],
    site_id: str,
    candidate_org_ids: Sequence[str],
) -> Dict[str, Dict[str, Any]]:
    """Fetch VLAN definitions from switch templates attached to the site."""

    _ = candidate_org_ids  # retained for compatibility; no longer required for the derived endpoint

    resp = requests.get(
        f"{base_url}/sites/{site_id}/setting/derived",
        headers=headers,
        timeout=60,
    )
    if resp.status_code == 404:
        return {}
    if not (200 <= resp.status_code < 300):
        raise MistAPIError(resp.status_code, _extract_mist_error(resp), response=_safe_json_response(resp))

    doc = resp.json() or {}
    discovered: Dict[str, Dict[str, Any]] = {}

    def _merge_containers(container: Any) -> None:
        fetched = _normalize_network_map(container, sanitize=False)
        for name, data in fetched.items():
            if name not in discovered:
                discovered[name] = data

    possible_containers: List[Any] = []
    if isinstance(doc, Mapping):
        possible_containers.extend([
            doc.get("networks"),
            doc.get("vlans"),
        ])

        switch_section = doc.get("switch") if isinstance(doc.get("switch"), Mapping) else None
        if switch_section:
            possible_containers.extend([
                switch_section.get("networks"),
                switch_section.get("vlans"),
            ])

    for container in possible_containers:
        if container is not None:
            _merge_containers(container)

    return discovered


def _prepare_switch_port_profile_payload(
    base_url: str,
    token: str,
    site_id: str,
    device_id: str,
    payload: Mapping[str, Any],
) -> Tuple[Dict[str, Any], List[str], Dict[str, str]]:
    networks_new = _normalize_network_map(payload.get("networks"), sanitize=True)
    if not networks_new:
        networks_new = _normalize_network_map(payload.get("vlans"), sanitize=True)
    port_profiles_new = payload.get("port_profiles")
    port_usages_new = payload.get("port_usages")
    port_overrides_new = payload.get("port_overrides")
    port_config_new = payload.get("port_config")

    port_profiles_seq = _normalize_port_profile_list(port_profiles_new)
    port_usages_seq = _normalize_port_profile_list(port_usages_new)

    if (
        not networks_new
        and not port_profiles_seq
        and not port_usages_seq
        and not port_overrides_new
        and not port_config_new
    ):
        return {}, [], {}

    url = f"{base_url}/sites/{site_id}/devices/{device_id}"
    headers = _mist_headers(token)

    resp_get = requests.get(url, headers=headers, timeout=60)
    if not (200 <= resp_get.status_code < 300):
        raise MistAPIError(resp_get.status_code, _extract_mist_error(resp_get), response=_safe_json_response(resp_get))

    current = resp_get.json() or {}
    existing_profile_field = "port_profiles"
    if "port_usages" in current:
        existing_profile_field = "port_usages"
    existing_profiles = _normalize_port_profile_list(current.get(existing_profile_field))
    existing_overrides = _normalize_port_override_list(current.get("port_overrides"))
    existing_networks = _normalize_network_map(current.get("networks"), sanitize=False)
    if not existing_networks:
        existing_networks = _normalize_network_map(current.get("vlans"), sanitize=False)

    candidate_org_ids = _collect_candidate_org_ids(
        [current],
        [payload],
        port_profiles_seq,
        port_usages_seq,
        existing_profiles,
        existing_overrides,
    )

    derived_networks = _load_site_template_networks(base_url, headers, site_id, candidate_org_ids)

    existing_vlan_ids, existing_conflicts = _collect_existing_vlan_details(
        derived_networks,
        existing_networks,
    )

    original_network_keys = set(networks_new.keys())

    (
        networks_new,
        port_profiles_seq,
        port_usages_seq,
        rename_map,
        conflict_warnings,
    ) = _resolve_network_conflicts(
        networks_new,
        port_profiles_seq,
        port_usages_seq,
        existing_conflicts,
    )

    if rename_map:
        if isinstance(port_config_new, Mapping):
            port_config_new = {key: dict(value) for key, value in port_config_new.items() if isinstance(value, Mapping)}
            for cfg in port_config_new.values():
                _rename_network_fields(cfg, rename_map)
        if isinstance(port_overrides_new, Sequence) and not isinstance(
            port_overrides_new, (str, bytes, bytearray)
        ):
            updated_overrides: List[Dict[str, Any]] = []
            for override in port_overrides_new:
                if not isinstance(override, Mapping):
                    continue
                new_override = dict(override)
                _rename_network_fields(new_override, rename_map)
                updated_overrides.append(new_override)
            port_overrides_new = updated_overrides

    removed_network_names = original_network_keys - set(networks_new.keys())
    if rename_map:
        removed_network_names -= set(rename_map.keys())

    def _record_targets_removed_network(record: Mapping[str, Any]) -> bool:
        if not removed_network_names or not isinstance(record, Mapping):
            return False

        direct_keys = (
            "port_network",
            "voip_network",
            "guest_network",
            "server_reject_network",
            "server_fail_network",
            "native_network",
        )

        for key in direct_keys:
            value = record.get(key)
            if isinstance(value, str) and value in removed_network_names:
                return True

        for key in ("networks", "dynamic_vlan_networks"):
            value = record.get(key)
            if isinstance(value, (list, tuple, set)):
                for item in value:
                    if isinstance(item, str) and item in removed_network_names:
                        return True

        return False

    skipped_usage_names: List[str] = []

    if removed_network_names and port_usages_seq:
        filtered_usages: List[Dict[str, Any]] = []
        for profile in port_usages_seq:
            if _record_targets_removed_network(profile):
                name = str(profile.get("name") or "").strip()
                if name:
                    skipped_usage_names.append(name)
                continue
            filtered_usages.append(profile)
        if skipped_usage_names:
            port_usages_seq = filtered_usages
            conflict_warnings.append(
                "Skipped {count} port usage profile(s) because their VLAN assignments already exist on Mist: {names}.".format(
                    count=len(skipped_usage_names),
                    names=", ".join(sorted(skipped_usage_names)),
                )
            )

    if removed_network_names and port_profiles_seq:
        filtered_profiles: List[Dict[str, Any]] = []
        skipped_profile_names: List[str] = []
        for profile in port_profiles_seq:
            if _record_targets_removed_network(profile):
                name = str(profile.get("name") or "").strip()
                if name:
                    skipped_profile_names.append(name)
                continue
            filtered_profiles.append(profile)
        if skipped_profile_names:
            port_profiles_seq = filtered_profiles
            conflict_warnings.append(
                "Skipped {count} port profile(s) because their VLAN assignments already exist on Mist: {names}.".format(
                    count=len(skipped_profile_names),
                    names=", ".join(sorted(skipped_profile_names)),
                )
            )

    blocked_usage_names = set(skipped_usage_names)

    def _should_skip_config(record: Mapping[str, Any]) -> bool:
        if not isinstance(record, Mapping):
            return False
        usage = record.get("usage")
        if isinstance(usage, str) and usage in blocked_usage_names:
            return True
        return _record_targets_removed_network(record)

    skipped_port_ids: List[str] = []
    if removed_network_names and isinstance(port_config_new, Mapping):
        filtered_config: Dict[str, Dict[str, Any]] = {}
        for port_id, cfg in port_config_new.items():
            port_key = str(port_id)
            if not isinstance(cfg, Mapping):
                continue
            if _should_skip_config(cfg):
                skipped_port_ids.append(port_key)
                continue
            filtered_config[port_key] = dict(cfg)
        if skipped_port_ids:
            port_config_new = filtered_config
            conflict_warnings.append(
                "Skipped {count} switchport assignment(s) because their VLAN assignments already exist on Mist: {names}.".format(
                    count=len(skipped_port_ids),
                    names=", ".join(sorted(skipped_port_ids)),
                )
            )

    if removed_network_names and isinstance(port_overrides_new, Sequence) and not isinstance(
        port_overrides_new, (str, bytes, bytearray)
    ):
        filtered_overrides: List[Dict[str, Any]] = []
        skipped_override_ports: List[str] = []
        for override in port_overrides_new:
            if not isinstance(override, Mapping):
                continue
            if _should_skip_config(override):
                port_id = str(override.get("port_id") or "").strip()
                if port_id:
                    skipped_override_ports.append(port_id)
                continue
            filtered_overrides.append(dict(override))
        if skipped_override_ports:
            port_overrides_new = filtered_overrides
            conflict_warnings.append(
                "Skipped {count} port override(s) because their VLAN assignments already exist on Mist: {names}.".format(
                    count=len(skipped_override_ports),
                    names=", ".join(sorted(skipped_override_ports)),
                )
            )
    request_body: Dict[str, Any] = {}
    networks_payload: Dict[str, Dict[str, Any]] = {}
    if networks_new:
        for name in sorted(networks_new):
            values = networks_new[name]
            if not isinstance(values, Mapping) or not name:
                continue
            vid = _int_or_none(values.get("vlan_id") or values.get("id"))
            if vid is None:
                continue
            if vid in existing_vlan_ids:
                continue
            networks_payload[name] = {"vlan_id": str(vid)}
    if networks_payload:
        request_body["networks"] = networks_payload

    if port_usages_seq:
        request_body["port_usages"] = {
            str(profile.get("name") or "").strip(): _compact_dict(
                {k: v for k, v in profile.items() if k != "name"}
            )
            for profile in port_usages_seq
            if isinstance(profile, Mapping) and str(profile.get("name") or "").strip()
        }
    elif port_profiles_seq:
        request_body[existing_profile_field] = [
            _compact_dict(dict(value))
            for value in port_profiles_seq
            if isinstance(value, Mapping)
        ]

    if isinstance(port_overrides_new, Sequence) and not isinstance(
        port_overrides_new, (str, bytes, bytearray)
    ):
        overrides_payload: List[Dict[str, Any]] = []
        for override in port_overrides_new:
            if not isinstance(override, Mapping):
                continue
            overrides_payload.append(dict(override))
        if overrides_payload:
            request_body["port_overrides"] = overrides_payload

    if isinstance(port_config_new, Mapping):
        config_payload: Dict[str, Dict[str, Any]] = {}
        for port_id, cfg in port_config_new.items():
            if not isinstance(cfg, Mapping):
                continue
            config_payload[str(port_id)] = dict(cfg)
        if config_payload:
            request_body["port_config"] = config_payload

    return request_body, conflict_warnings, rename_map


def _configure_switch_port_profile_override(
    base_url: str,
    token: str,
    site_id: str,
    device_id: str,
    payload: Mapping[str, Any],
) -> Dict[str, Any]:
    request_body, warnings, rename_map = _prepare_switch_port_profile_payload(
        base_url,
        token,
        site_id,
        device_id,
        payload,
    )

    if not request_body:
        result: Dict[str, Any] = {"ok": True, "skipped": True, "message": "No temporary config updates."}
        if warnings:
            result["warnings"] = warnings
        if rename_map:
            result["renamed_networks"] = rename_map
        return result

    url = f"{base_url}/sites/{site_id}/devices/{device_id}"
    headers = _mist_headers(token)

    resp_post = requests.put(url, headers=headers, json=request_body, timeout=60)
    data = _safe_json_response(resp_post)
    if not (200 <= resp_post.status_code < 300):
        raise MistAPIError(resp_post.status_code, _extract_mist_error(resp_post), response=data)

    result: Dict[str, Any] = {
        "ok": True,
        "status": resp_post.status_code,
        "request": request_body,
        "response": data,
    }
    if warnings:
        result["warnings"] = warnings
    if rename_map:
        result["renamed_networks"] = rename_map
    return result


def _build_temp_config_payload(row: Mapping[str, Any]) -> Optional[Dict[str, Any]]:
    source = row.get("_temp_config_source")
    if not isinstance(source, Mapping):
        return None

    interfaces = source.get("interfaces")
    if not isinstance(interfaces, list):
        return None

    port_usages: Dict[tuple, Dict[str, Any]] = {}
    port_config: Dict[str, Dict[str, Any]] = {}
    port_overrides: List[Dict[str, Any]] = []

    networks: List[Dict[str, Any]] = []
    seen_vlan_ids: set[int] = set()
    vlan_name_map: Dict[int, str] = {}

    def _register_vlan(vlan_id: Optional[int], raw_name: Optional[str] = None) -> Optional[str]:
        if vlan_id is None:
            return None
        if vlan_id in vlan_name_map:
            return vlan_name_map[vlan_id]
        network_name = _generate_temp_network_name(vlan_id, raw_name)
        vlan_name_map[vlan_id] = network_name
        if vlan_id not in seen_vlan_ids:
            seen_vlan_ids.add(vlan_id)
            networks.append(
                {
                    "id": vlan_id,
                    "vlan_id": vlan_id,
                    "name": network_name,
                    "source_name": (raw_name.strip() if isinstance(raw_name, str) else raw_name) or None,
                }
            )
        return network_name

    vlans = source.get("vlans")
    if isinstance(vlans, list):
        for item in vlans:
            if not isinstance(item, Mapping):
                continue
            vid = _int_or_none(item.get("id"))
            display_name = str(item.get("name") or "").strip() or None
            _register_vlan(vid, display_name)

    for intf in interfaces:
        if not isinstance(intf, Mapping):
            continue
        mode = str(intf.get("mode") or "").lower()
        if mode not in {"access", "trunk"}:
            continue
        juniper_if = str(intf.get("juniper_if") or "").strip()
        if not juniper_if:
            continue

        data_vlan = _int_or_none(intf.get("data_vlan"))
        voice_vlan = _int_or_none(intf.get("voice_vlan"))
        native_vlan = _int_or_none(intf.get("native_vlan"))
        allowed_vlan_ids = tuple(_normalize_vlan_values(intf.get("allowed_vlans")))

        data_network = _register_vlan(data_vlan)
        voice_network = _register_vlan(voice_vlan)
        native_network = _register_vlan(native_vlan)
        allowed_network_list: List[str] = []
        for vlan_id in allowed_vlan_ids:
            network_name = _register_vlan(vlan_id)
            if network_name:
                allowed_network_list.append(network_name)
        allowed_networks = tuple(allowed_network_list)

        usage_fingerprint = (mode, data_vlan, voice_vlan, native_vlan, allowed_vlan_ids)

        profile = port_usages.get(usage_fingerprint)
        if profile is None:
            usage_name = _generate_temp_usage_name(
                mode=mode,
                data_vlan=data_vlan,
                voice_vlan=voice_vlan,
                native_vlan=native_vlan,
                allowed_vlans=allowed_vlan_ids,
            )
            profile = {
                "name": usage_name,
                "mode": mode or None,
                "disabled": False,
                "port_network": data_network if mode == "access" else native_network,
                "voip_network": voice_network,
                "stp_edge": mode == "access",
                "use_vstp": mode == "trunk",
                "stp_p2p": False,
                "stp_no_root_port": False,
                "stp_disable": False,
                "stp_required": False,
                "all_networks": bool(mode == "trunk" and not allowed_networks),
                "networks": list(allowed_networks) if allowed_networks else None,
                "speed": "auto",
                "duplex": "auto",
                "mac_limit": 0,
                "persist_mac": False,
                "poe_disabled": False,
                "enable_qos": False,
                "storm_control": {},
                "mtu": None,
                "allow_dhcpd": False,
                "disable_autoneg": False,
            }
            port_usages[usage_fingerprint] = _compact_dict(profile)

        profile_name = profile["name"]
        description = str(intf.get("description") or "").strip()
        shutdown = bool(intf.get("shutdown"))

        port_config[juniper_if] = _compact_dict(
            {
                "usage": profile_name,
                "mode": mode,
                "port_network": data_network if mode == "access" else native_network,
                "voip_network": voice_network,
                "networks": list(allowed_networks) if allowed_networks else None,
                "description": description,
                "disabled": shutdown,
                "source_interface": str(intf.get("name") or "").strip() or None,
            }
        )

        port_overrides.append(
            _compact_dict(
                {
                    "port_id": juniper_if,
                    "usage": profile_name,
                    "mode": mode,
                    "port_network": data_network if mode == "access" else native_network,
                    "voip_network": voice_network,
                    "networks": list(allowed_networks) if allowed_networks else None,
                    "description": description,
                    "disabled": shutdown,
                    "source_interface": str(intf.get("name") or "").strip() or None,
                }
            )
        )

    if not port_config:
        return None

    usage_payload: Dict[str, Dict[str, Any]] = {}
    for profile in port_usages.values():
        name = str(profile.get("name") or "").strip()
        if not name:
            continue
        cleaned = _compact_dict(dict(profile))
        cleaned.pop("name", None)
        usage_payload[name] = cleaned

    payload: Dict[str, Any] = {
        "port_usages": usage_payload,
        "port_config": port_config,
        "port_overrides": port_overrides,
    }
    if networks:
        payload["networks"] = networks
        # Keep legacy key for compatibility with earlier previews/status handling
        payload["vlans"] = networks

    return payload


def _apply_temporary_config_for_rows(
    base_url: str,
    token: str,
    results: Sequence[Dict[str, Any]],
    *,
    dry_run: bool,
) -> Dict[str, Any]:
    ok_rows = [r for r in results if r.get("ok") and r.get("site_id") and r.get("device_id")]
    total = len(ok_rows)
    payload_records: List[Dict[str, Any]] = []

    if total == 0:
        return {
            "ok": True,
            "skipped": True,
            "message": "No successful rows available to stage temporary config previews.",
            "successes": 0,
            "failures": [],
            "total": 0,
        }

    successes = 0
    failures: List[Dict[str, Any]] = []

    for row in ok_rows:
        site_id = str(row.get("site_id") or "").strip()
        device_id = str(row.get("device_id") or "").strip()
        payload = _build_temp_config_payload(row)
        base_payload: Dict[str, Any] = payload if isinstance(payload, Mapping) else {}

        record: Dict[str, Any] = {
            "site_id": site_id,
            "device_id": device_id,
            "payload": dict(base_payload),
        }

        warnings: List[str] = []

        if not base_payload:
            failures.append(
                {
                    "site_id": site_id,
                    "device_id": device_id,
                    "message": "No temporary config payload available.",
                    "status": None,
                }
            )
            payload_records.append(record)
            continue

        if site_id and device_id:
            try:
                prepared_body, conflict_warnings, rename_map = _prepare_switch_port_profile_payload(
                    base_url,
                    token,
                    site_id,
                    device_id,
                    base_payload,
                )
                if rename_map:
                    _apply_network_rename_to_payload(base_payload, rename_map)
                    record["renamed_networks"] = rename_map
                preview_body = prepared_body
                record["payload"] = preview_body if preview_body else {}
                if conflict_warnings:
                    warnings.extend(conflict_warnings)
            except MistAPIError as exc:
                warnings.append(f"Unable to inspect Mist configuration: {exc}")
                failures.append(
                    {
                        "site_id": site_id,
                        "device_id": device_id,
                        "message": str(exc),
                        "status": exc.status_code,
                    }
                )
                record["payload"] = base_payload
                if warnings:
                    record["warnings"] = warnings
                payload_records.append(record)
                continue
        else:
            record["payload"] = base_payload

        if warnings:
            record["warnings"] = warnings

        successes += 1

        payload_records.append(record)

    ok = successes == total and not failures
    skipped = not failures

    message = (
        "Prepared temporary config payloads for {count} device(s). Review before finalizing."
        if ok
        else "Prepared temporary config payloads for {successes}/{total} device(s). Manual follow-up recommended."
    ).format(count=successes, successes=successes, total=total)

    return {
        "ok": ok,
        "skipped": skipped,
        "message": message,
        "successes": successes,
        "failures": failures,
        "total": total,
        "payloads": payload_records,
    }


def _finalize_assignments_for_rows(
    base_url: str,
    token: str,
    results: Sequence[Dict[str, Any]],
    *,
    dry_run: bool,
) -> Dict[str, Any]:
    ok_rows = [
        r for r in results if r.get("ok") and r.get("site_id") and r.get("device_id")
    ]
    total = len(ok_rows)

    if total == 0:
        return {
            "ok": True,
            "skipped": True,
            "message": "No completed rows available to finalize assignments.",
            "successes": 0,
            "failures": [],
            "total": 0,
        }

    payload_records: List[Dict[str, Any]] = []

    def _prepare_finalize_payload(row: Mapping[str, Any]) -> Optional[Dict[str, Any]]:
        payload = _build_temp_config_payload(row)
        if not isinstance(payload, Mapping):
            return None

        sanitized: Dict[str, Any] = {}
        for key in (
            "port_profiles",
            "port_usages",
            "port_overrides",
            "port_config",
            "networks",
            "vlans",
        ):
            value = payload.get(key)
            if value:
                sanitized[key] = copy.deepcopy(value)

        return sanitized or None

    if dry_run:
        for row in ok_rows:
            site_id = str(row.get("site_id") or "").strip()
            device_id = str(row.get("device_id") or "").strip()
            if not site_id or not device_id:
                continue
            payload_obj = _prepare_finalize_payload(row)
            record: Dict[str, Any] = {
                "site_id": site_id,
                "device_id": device_id,
                "payload": payload_obj or {},
            }
            warnings: List[str] = []
            if payload_obj:
                try:
                    _, conflict_warnings, rename_map = _prepare_switch_port_profile_payload(
                        base_url,
                        token,
                        site_id,
                        device_id,
                        payload_obj,
                    )
                    if rename_map:
                        _apply_network_rename_to_payload(payload_obj, rename_map)
                        record["payload"] = payload_obj
                    if conflict_warnings:
                        warnings.extend(conflict_warnings)
                except MistAPIError as exc:
                    warnings.append(
                        f"Unable to inspect existing Mist configuration for VLAN conflicts: {exc}"
                    )
            if warnings:
                record["warnings"] = warnings
            payload_records.append(record)

        return {
            "ok": True,
            "skipped": True,
            "message": "Skipped finalizing assignments for {total} device(s) during a preview-only run.".format(
                total=total
            ),
            "successes": 0,
            "failures": [],
            "total": total,
            "payloads": payload_records,
        }

    successes = 0
    failures: List[Dict[str, Any]] = []
    records: List[Dict[str, Any]] = []

    for row in ok_rows:
        site_id = str(row.get("site_id") or "").strip()
        device_id = str(row.get("device_id") or "").strip()
        payload_obj = _prepare_finalize_payload(row)

        record: Dict[str, Any] = {
            "site_id": site_id,
            "device_id": device_id,
            "payload": payload_obj or {},
        }
        payload_records.append(record)
        records.append(record)

        errors: List[Tuple[str, Optional[int]]] = []
        record["_errors"] = errors  # type: ignore[assignment]

        if not site_id or not device_id:
            errors.append(("Missing site or device identifier while finalizing.", None))

        if not payload_obj:
            errors.append(("No staged temporary configuration is available to finalize.", None))

    for record in records:
        payload = record.get("payload")
        errors: List[Tuple[str, Optional[int]]] = record.get("_errors", [])

        if not payload or errors:
            continue

        site_id = str(record.get("site_id") or "")
        device_id = str(record.get("device_id") or "")

        try:
            device_result = _configure_switch_port_profile_override(
                base_url,
                token,
                site_id,
                device_id,
                payload,
            )
            record["device_result"] = device_result
            rename_map = device_result.get("renamed_networks") if isinstance(device_result, Mapping) else None
            if rename_map and isinstance(payload, Mapping):
                _apply_network_rename_to_payload(payload, rename_map)
                record["payload"] = payload
            warning_list = device_result.get("warnings") if isinstance(device_result, Mapping) else None
            if warning_list:
                record.setdefault("warnings", []).extend(
                    [w for w in warning_list if isinstance(w, str) and w.strip()]
                )
            if not device_result.get("ok"):
                errors.append(
                    (
                        str(device_result.get("message") or "Device update failed."),
                        _int_or_none(device_result.get("status")),
                    )
                )
        except MistAPIError as exc:
            record["device_result"] = {
                "ok": False,
                "status": exc.status_code,
                "message": str(exc),
                "response": exc.response,
            }
            errors.append((str(exc), exc.status_code))

    for record in records:
        errors: List[Tuple[str, Optional[int]]] = record.get("_errors", [])
        site_id = record.get("site_id")
        device_id = record.get("device_id")

        if errors:
            message, status = errors[0]
            failures.append(
                {
                    "site_id": site_id,
                    "device_id": device_id,
                    "message": message,
                    "status": status,
                }
            )
        else:
            successes += 1

        record.pop("_errors", None)

    ok = successes == total
    return {
        "ok": ok,
        "skipped": False,
        "message": (
            "Finalized temporary assignments for {count} device(s)."
            if ok
            else "Finalized temporary assignments for {successes}/{total} device(s). Manual follow-up required."
        ).format(count=successes, successes=successes, total=total),
        "successes": successes,
        "failures": failures,
        "total": total,
        "payloads": payload_records,
    }


def _remove_temporary_config_for_rows(
    base_url: str,
    token: str,
    results: Sequence[Dict[str, Any]],
    *,
    dry_run: bool,
) -> Dict[str, Any]:
    return _invoke_batch_phase(
        results,
        base_url=base_url,
        token=token,
        dry_run=dry_run,
        method="delete",
        path_template="/sites/{site_id}/devices/{device_id}/temp_port_config",
        success_template="Removed temporary config from {count} device(s).",
        partial_template="Removed temporary config from {successes}/{total} device(s). Manual follow-up required.",
        skip_message="Skipped removing temporary config for {total} device(s) during a preview-only run.",
        empty_message="No temporary config records to remove for the submitted batch.",
    )


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
    base_url: str = Form(DEFAULT_BASE_URL),
    tz: str = Form(DEFAULT_TZ),
    model_override: Optional[str] = Form(None),  # optional global override (row can still override)
    normalize_modules: bool = Form(True),
    apply_temp_config: bool = Form(False),
    finalize_assignments: bool = Form(False),
    remove_temp_config: bool = Form(False),
    stage_site_deployment: bool = Form(False),
    push_site_deployment: bool = Form(False),
) -> JSONResponse:
    """
    Batch push. Each row can specify: site_id, device_id, input_json (object),
    excludes (str), exclude_uplinks (bool), member_offset (int), port_offset (int), model_override (str, optional).
    Returns per-row results with payload + validation, and never aborts the whole batch.

    NOTE: Duplicate devices ARE allowed as long as (device_id, member_offset, port_offset) triples are unique.
    If the same triple appears more than once, those rows are rejected with a clear error.
    """
    token = _load_mist_token()
    base_url = base_url.rstrip("/")

    stage_site_deployment = bool(stage_site_deployment)
    push_site_deployment = bool(push_site_deployment)
    apply_temp_config = bool(apply_temp_config)
    finalize_assignments = bool(finalize_assignments)
    remove_temp_config = bool(remove_temp_config)
    site_selection_count = int(stage_site_deployment) + int(push_site_deployment)
    lcm_selection_count = int(apply_temp_config) + int(finalize_assignments) + int(remove_temp_config)
    site_actions_selected = stage_site_deployment or push_site_deployment
    lcm_actions_selected = bool(apply_temp_config or finalize_assignments or remove_temp_config)

    preview_only = not (
        push_site_deployment or apply_temp_config or finalize_assignments or remove_temp_config
    )

    _ensure_push_allowed(request, dry_run=preview_only)

    if site_actions_selected and lcm_actions_selected:
        return JSONResponse(
            {
                "ok": False,
                "error": "Select either Site Deployment Automation or Lifecycle Automation actions, not both."
            },
            status_code=400,
        )

    if site_selection_count > 1:
        return JSONResponse(
            {
                "ok": False,
                "error": "Select only one Site Deployment Automation phase per run.",
            },
            status_code=400,
        )

    if lcm_selection_count > 1:
        return JSONResponse(
            {
                "ok": False,
                "error": "Select only one Lifecycle Automation phase per run.",
            },
            status_code=400,
        )

    should_push_live = push_site_deployment
    effective_dry_run = not should_push_live

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
                dry_run=effective_dry_run,
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

    phase_status: Dict[str, Dict[str, Any]] = {}

    if site_actions_selected:
        total_rows = len(results)
        successes = sum(1 for r in results if r.get("ok"))
        failures: List[Dict[str, Any]] = []
        for r in results:
            if r.get("ok"):
                continue
            message = ""
            error_text = r.get("error")
            if isinstance(error_text, str) and error_text.strip():
                message = error_text.strip()
            else:
                validation_data = r.get("validation")
                if isinstance(validation_data, Mapping):
                    errors_list = validation_data.get("errors")
                    if isinstance(errors_list, Sequence) and not isinstance(errors_list, (str, bytes, bytearray)):
                        joined = "; ".join(
                            str(item).strip() for item in errors_list if str(item).strip()
                        )
                        if joined:
                            message = joined
            status_val = r.get("status") if isinstance(r.get("status"), int) else None
            if not message:
                if status_val is not None:
                    message = f"Mist API returned HTTP {status_val}"
                else:
                    message = "Conversion failed."
            failures.append(
                {
                    "site_id": r.get("site_id"),
                    "device_id": r.get("device_id"),
                    "status": status_val,
                    "message": message,
                }
            )

        if stage_site_deployment:
            if total_rows == 0:
                phase_status["site_stage"] = {
                    "ok": True,
                    "skipped": True,
                    "message": "No rows submitted for Site Deployment staging.",
                    "successes": 0,
                    "failures": [],
                    "total": 0,
                }
            else:
                phase_status["site_stage"] = {
                    "ok": successes == total_rows,
                    "skipped": False,
                    "message": (
                        "Prepared converted Mist payloads for {count} device(s)."
                        if successes == total_rows
                        else "Prepared converted Mist payloads for {successes}/{total} device(s). Check batch results for details."
                    ).format(count=successes, successes=successes, total=total_rows),
                    "successes": successes,
                    "failures": failures,
                    "total": total_rows,
                }

        if push_site_deployment:
            if not should_push_live:
                phase_status["site_push"] = {
                    "ok": True,
                    "skipped": True,
                    "message": "Skipped pushing converted config during a preview-only run.",
                    "successes": 0,
                    "failures": [],
                    "total": len(results),
                }
            elif len(results) == 0:
                phase_status["site_push"] = {
                    "ok": True,
                    "skipped": True,
                    "message": "No rows available to push converted config.",
                    "successes": 0,
                    "failures": [],
                    "total": 0,
                }
            else:
                phase_status["site_push"] = {
                    "ok": successes == len(results),
                    "skipped": False,
                    "message": (
                        "Pushed converted config to {count} device(s)."
                        if successes == len(results)
                        else "Pushed converted config to {successes}/{total} device(s). Check batch results for details."
                    ).format(count=successes, successes=successes, total=len(results)),
                    "successes": successes,
                    "failures": failures,
                    "total": len(results),
                }

    if not site_actions_selected:
        for row in results:
            if isinstance(row, dict):
                row.pop("payload", None)
                row.pop("response", None)
                row.pop("status", None)

    if apply_temp_config:
        phase_status["apply_temporary_config"] = _apply_temporary_config_for_rows(
            base_url=base_url,
            token=token,
            results=results,
            dry_run=preview_only,
        )

    if finalize_assignments:
        phase_status["finalize_assignments"] = _finalize_assignments_for_rows(
            base_url=base_url,
            token=token,
            results=results,
            dry_run=preview_only,
        )

    if remove_temp_config:
        phase_status["remove_temporary_config"] = _remove_temporary_config_for_rows(
            base_url=base_url,
            token=token,
            results=results,
            dry_run=preview_only,
        )

    for row in results:
        if isinstance(row, dict):
            row.pop("_temp_config_source", None)

    top_ok = all(r.get("ok") for r in results) if results else False
    phase_ok = all(status.get("ok") or status.get("skipped") for status in phase_status.values())
    overall_ok = top_ok and phase_ok

    return JSONResponse(
        {
            "ok": overall_ok,
            "dry_run": preview_only,
            "results": results,
            "phase_status": phase_status,
        }
    )
