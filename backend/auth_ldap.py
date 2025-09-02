import os
from typing import Optional, Dict, Any, List

from fastapi import APIRouter, Depends, HTTPException, Request, status, Form
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from starlette.middleware.sessions import SessionMiddleware
from ldap3 import Server, Connection, ALL, Tls, NTLM, SUBTREE

SESSION_SECRET = os.getenv("SESSION_SECRET", "change-me")
LDAP_SERVER_URL = os.getenv("LDAP_SERVER_URL", "ldaps://dc01.testdomain.local:636")
LDAP_SEARCH_BASE = os.getenv("LDAP_SEARCH_BASE", "DC=testdomain,DC=local")
LDAP_BIND_TEMPLATE = os.getenv("LDAP_BIND_TEMPLATE", "{username}@testdomain.local")
PUSH_GROUP_DN = os.getenv("PUSH_GROUP_DN")  # CN=NetAuto-Push,OU=Groups,...

# Optional service account for searches
LDAP_SERVICE_DN = os.getenv("LDAP_SERVICE_DN", "CN=GreatMigration,CN=Users,DC=testdomain,DC=local")
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
@@ -49,70 +49,71 @@ def _search_user(conn: Connection, username: str) -> Optional[Dict[str, Any]]:
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
        <p class="text-sm text-slate-600">Use your corporate AD credentials</p>
        {msg}
        <form method="post" action="/login" class="mt-4 space-y-3">
          <div>
            <label class="block text-sm font-medium mb-1">Username</label>
            <input name="username" autocomplete="username" class="w-full border rounded p-2" required />
            <p class="text-xs text-slate-500 mt-1">Format: {hint}</p>
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