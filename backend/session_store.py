"""Revocable, opaque sessions shared by all workers on this installation."""
import json
import secrets
import time
import hashlib
from http.cookies import SimpleCookie

from itsdangerous import BadSignature, TimestampSigner
from starlette.datastructures import MutableHeaders
from starlette.requests import HTTPConnection

from security import security_db


class SessionMiddleware:
    def __init__(self, app, secret_key, same_site="lax", https_only=True, max_age=3600):
        self.app = app
        self.signer = TimestampSigner(str(secret_key), digest_method=hashlib.sha256)
        self.same_site = same_site
        self.https_only = https_only
        self.max_age = max_age

    async def __call__(self, scope, receive, send):
        if scope["type"] not in {"http", "websocket"}:
            return await self.app(scope, receive, send)
        cookie = HTTPConnection(scope).cookies.get("session")
        sid = None
        expires = time.time() + self.max_age
        scope["session"] = {}
        if cookie:
            try:
                sid = self.signer.unsign(cookie, max_age=self.max_age).decode()
                with security_db() as db:
                    row = db.execute("SELECT data, expires FROM sessions WHERE id=? AND expires>?", (sid, time.time())).fetchone()
                if row:
                    scope["session"] = json.loads(row[0])
                    expires = row[1]
                else:
                    sid = None
            except (BadSignature, ValueError):
                sid = None
        old_user = scope["session"].get("user")
        old_login = scope["session"].get("login_nonce")

        async def persist(message):
            nonlocal sid
            if message["type"] == "http.response.start":
                if not scope["session"] and not cookie:
                    return await send(message)
                # Rotate the identifier on authentication; invalidate the old session.
                new_login = scope["session"].get("login_nonce") != old_login
                rotate = new_login or scope["session"].get("user") != old_user
                with security_db() as db:
                    if sid and (not scope["session"] or rotate):
                        db.execute("DELETE FROM sessions WHERE id=?", (sid,))
                        sid = None
                    if scope["session"]:
                        if new_login:
                            expires_at = time.time() + self.max_age
                        else:
                            expires_at = expires
                        if sid:
                            updated = db.execute("UPDATE sessions SET data=? WHERE id=? AND expires>?", (json.dumps(scope["session"]), sid, time.time()))
                            if not updated.rowcount:
                                # A concurrent logout/revocation must never be undone.
                                scope["session"].clear()
                                sid = None
                        else:
                            sid = secrets.token_urlsafe(48)
                            db.execute("INSERT INTO sessions VALUES (?,?,?)", (sid, json.dumps(scope["session"]), expires_at))
                result = SimpleCookie()
                result["session"] = self.signer.sign(sid.encode()).decode() if scope["session"] else ""
                result["session"]["path"] = "/"
                result["session"]["httponly"] = True
                result["session"]["samesite"] = self.same_site
                result["session"]["max-age"] = max(0, int(expires_at - time.time())) if scope["session"] else 0
                if self.https_only or scope.get("scheme") == "https":
                    result["session"]["secure"] = True
                MutableHeaders(scope=message).append("set-cookie", result.output(header="").strip())
            await send(message)

        await self.app(scope, receive, persist)
