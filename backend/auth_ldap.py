# auth_ldap.py
import os
from typing import Optional, Dict, Any, List

from fastapi import APIRouter, Depends, HTTPException, Request, status, Form
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from starlette.middleware.sessions import SessionMiddleware
from ldap3 import Server, Connection, ALL, Tls, NTLM, SUBTREE

SESSION_SECRET = os.getenv("SESSION_SECRET", "change-me")
LDAP_SERVER_URL = os.getenv("LDAP_SERVER_URL", "ldaps://dc01.corp.local:636")
LDAP_SEARCH_BASE = os.getenv("LDAP_SEARCH_BASE", "")
LDAP_BIND_TEMPLATE = os.getenv("LDAP_BIND_TEMPLATE", "{username}@corp.local")
PUSH_GROUP_DN = os.getenv("PUSH_GROUP_DN")  # CN=NetAuto-Push,OU=Groups,...

# Optional service account for searches
LDAP_SERVICE_DN = os.getenv("LDAP_SERVICE_DN")
LDAP_SERVICE_PASSWORD = os.getenv("LDAP_SERVICE_PASSWORD")

router = APIRouter()

def _server() -> Server:
    use_ssl = LDAP_SERVER_URL.lower().startswith("ldaps://")
    return Server(LDAP_SERVER_URL, use_ssl=use_ssl, get_info=ALL, connect_timeout=8)

def _bind_as(username: str, password: str) -> Connection:
    """Bind as the user. username is raw (e.g., 'alice'), we render per template."""
    user_bind = LDAP_BIND_TEMPLATE.format(username=username)
    conn = Connection(_server(), user=user_bind, password=password, auto_bind=True)
    return conn

def _bind_service() -> Optional[Connection]:
    """Bind as service account for searches, if configured."""
    if not LDAP_SERVICE_DN or not LDAP_SERVICE_PASSWORD:
        return None
    return Connection(_server(), user=LDAP_SERVICE_DN, password=LDAP_SERVICE_PASSWORD, auto_bind=True)

def _search_user(conn: Connection, username: str) -> Optional[Dict[str, Any]]:
    """Find user entry by UPN or sAMAccountName."""
    # Two filters to be robust
    upn = LDAP_BIND_TEMPLATE.format(username=username)
    search_filter = f"(|(userPrincipalName={upn})(sAMAccountName={username}))"
    attrs = ["distinguishedName", "displayName", "mail", "userPrincipalName", "memberOf"]
    ok = conn.search(search_base=LDAP_SEARCH_BASE, search_filter=search_filter,
                     search_scope=SUBTREE, attributes=attrs, size_limit=1)
    if not ok or not conn.entries:
        return None
    e = conn.entries[0]
    def _list(attr):
        try:
            return [str(x) for x in getattr(e, attr).values]
        except Exception:
            return []
    return {
        "dn": str(e.entry_dn),
        "displayName": str(getattr(e, "displayName", "")),
        "mail": str(getattr(e, "mail", "")),
        "upn": str(getattr(e, "userPrincipalName", "")),
        "memberOf": _list("memberOf"),
    }

def _is_member_of_group(user_dn: str, group_dn: str, search_conn: Connection) -> bool:
    """
    Recursive group check via LDAP_MATCHING_RULE_IN_CHAIN
    """
    # (memberOf:1.2.840.113556.1.4.1941:=<groupDN>) true if user is directly or indirectly a member
    filt = f"(&(distinguishedName={user_dn})(memberOf:1.2.840.113556.1.4.1941:={group_dn}))"
    ok = search_conn.search(search_base=LDAP_SEARCH_BASE, search_filter=filt,
                            search_scope=SUBTREE, attributes=["distinguishedName"], size_limit=1)
    return bool(ok and search_conn.entries)

def _html_login(error: Optional[str] = None) -> str:
    msg = f'<p class="text-sm text-rose-600 mt-2">{error}</p>' if error else ''
    return f"""
<!doctype html>
<html>
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width,initial-scale=1" />
    <title>Sign in</title>
    <script src="https://cdn.tailwindcss.com"></script>
  </head>
  <body class="bg-slate-50 text-slate-900">
    <div class="min-h-screen flex items-center justify-center p-6">
      <div class="w-full max-w-md bg-white rounded-2xl shadow p-6">
        <h1 class="text-xl font-semibold">Sign in</h1>
        <p class="text-sm text-slate-600">Use your corporate AD credentials</p>
        {msg}
        <form method="post" action="/login" class="mt-4 space-y-3">
          <div>
            <label class="block text-sm font-medium mb-1">Username</label>
            <input name="username" autocomplete="username" class="w-full border rounded p-2" required />
            <p class="text-xs text-slate-500 mt-1">Format: {'user@corp.local' if '{username}@' in LDAP_BIND_TEMPLATE else 'CORP\\\\user'}</p>
          </div>
          <div>
            <label class="block text-sm font-medium mb-1">Password</label>
            <input name="password" type="password" autocomplete="current-password" class="w-full border rounded p-2" required />
          </div>
          <button class="w-full mt-2 px-3 py-2 rounded text-white bg-emerald-600 hover:bg-emerald-700">Sign in</button>
        </form>
      </div>
    </div>
  </body>
</html>
"""

@router.get("/login", response_class=HTMLResponse)
def get_login():
    return HTMLResponse(_html_login())

@router.post("/login")
def post_login(request: Request, username: str = Form(...), password: str = Form(...)):
    # 1) Bind as user to verify credentials
    try:
        user_conn = _bind_as(username, password)
    except Exception:
        return HTMLResponse(_html_login("Invalid username or password."), status_code=401)

    # 2) Find user entry (with groups)
    entry = _search_user(user_conn, username)
    if not entry:
        return HTMLResponse(_html_login("User not found in directory."), status_code=401)

    # 3) If we need recursive group check, bind service (or reuse user bind if permitted)
    can_push = False
    if PUSH_GROUP_DN:
        try:
            svc = _bind_service() or user_conn
            can_push = _is_member_of_group(entry["dn"], PUSH_GROUP_DN, svc)
        except Exception:
            # if check fails, default to False
            can_push = False

    # 4) Store session
    request.session["user"] = {
        "name": entry.get("displayName") or username,
        "email": entry.get("mail") or entry.get("upn") or "",
        "dn": entry["dn"],
        "upn": entry.get("upn") or "",
        "can_push": bool(can_push),
    }
    return RedirectResponse("/", status_code=302)

@router.get("/logout")
def logout(request: Request):
    request.session.clear()
    resp = RedirectResponse("/", status_code=302)
    return resp

# ----- Dependencies you can use to protect routes -----
def current_user(request: Request) -> Dict[str, Any]:
    u = request.session.get("user")
    if not u:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Auth required")
    return u

def require_push_rights(user = Depends(current_user)):
    if not user.get("can_push"):
        raise HTTPException(status_code=403, detail="Push permission required")
    return user

@router.get("/me")
def me(user = Depends(current_user)):
    # Minimal info for the frontend
    return {"ok": True, "user": {"name": user.get("name"), "email": user.get("email"), "can_push": user.get("can_push", False)}}

def install_auth(app):
    """Call this from app.py to enable sessions + routes."""
    # Add SessionMiddleware if not already present
    app.add_middleware(SessionMiddleware, secret_key=SESSION_SECRET, same_site="lax", https_only=False)
    app.include_router(router)
