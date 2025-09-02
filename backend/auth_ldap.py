# auth_ldap.py
import os
from typing import Optional, Dict, Any

from fastapi import APIRouter, Depends, HTTPException, Request, status, Form
from fastapi.responses import HTMLResponse, RedirectResponse
from starlette.middleware.sessions import SessionMiddleware
from ldap3 import Server, Connection, ALL, Tls, NTLM, SUBTREE

SESSION_SECRET = os.getenv("SESSION_SECRET", "change-me")
LDAP_SERVER_URL = os.getenv("LDAP_SERVER_URL", "ldaps://dc01.testdomain.local:636")
LDAP_SEARCH_BASE = os.getenv("LDAP_SEARCH_BASE", "DC=testdomain,DC=local")
LDAP_BIND_TEMPLATE = os.getenv("LDAP_BIND_TEMPLATE", "{username}@testdomain.local")

router = APIRouter()

def _server() -> Server:
    use_ssl = LDAP_SERVER_URL.lower().startswith("ldaps://")
    return Server(LDAP_SERVER_URL, use_ssl=use_ssl, get_info=ALL, connect_timeout=8)

def _bind_as(username: str, password: str) -> Connection:
    """Bind as the user. username is raw (e.g., 'alice'), we render per template."""
    user_bind = LDAP_BIND_TEMPLATE.format(username=username)
    conn = Connection(_server(), user=user_bind, password=password, auto_bind=True)
    return conn

def _search_user(conn: Connection, username: str) -> Optional[Dict[str, Any]]:
    """Find user entry by UPN or sAMAccountName."""
    # Two filters to be robust
    upn = LDAP_BIND_TEMPLATE.format(username=username)
    search_filter = f"(|(userPrincipalName={upn})(sAMAccountName={username}))"
    attrs = [
        "distinguishedName",
        "displayName",
        "mail",
        "userPrincipalName",
        "memberOf",
    ]
    ok = conn.search(
        search_base=LDAP_SEARCH_BASE,
        search_filter=search_filter,
        search_scope=SUBTREE,
        attributes=attrs,
        size_limit=1,
    )
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

def _html_login(error: Optional[str] = None) -> str:
    msg = f'<p class="text-sm text-rose-600 mt-2">{error}</p>' if error else ''
    hint = 'user@testdomain.local' if '{username}@' in LDAP_BIND_TEMPLATE else 'TESTDOMAIN\\user'
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
        <p class="text-sm text-slate-600">Use your OC AD credentials</p>
        {msg}
        <form method="post" action="/login" class="mt-4 space-y-3">
          <div>
            <label class="block text-sm font-medium mb-1">Username</label>
            <input name="username" autocomplete="username" class="w-full border rounded p-2" required />
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

    # 3) Store session (all authenticated users may push)
    request.session["user"] = {
        "name": entry.get("displayName") or username,
        "email": entry.get("mail") or entry.get("upn") or "",
        "dn": entry["dn"],
        "upn": entry.get("upn") or "",
        "can_push": True,
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
    """All authenticated users may push."""
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

__all__ = ["install_auth", "current_user", "require_push_rights"]
