"""Shared security boundaries for the web application and command-line clients."""
from __future__ import annotations

import base64
import hashlib
import hmac
import ipaddress
import json
import os
import re
import secrets
import sqlite3
import time
import threading
import anyio
from contextlib import contextmanager
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

from fastapi import HTTPException
from starlette.requests import Request
from starlette.responses import JSONResponse, RedirectResponse


BACKEND_DIR = Path(__file__).resolve().parent


def session_secret() -> str:
    value = os.getenv("SESSION_SECRET", "").strip()
    if not value:
        raise RuntimeError("SESSION_SECRET is required. Run backend/security_setup.py.")
    if len(value) < 32 or value.lower() in {"change_me", "changeme", "replace_me"}:
        raise RuntimeError("SESSION_SECRET must be a random secret of at least 32 characters. Run backend/security_setup.py.")
    return value


def hash_password(password: str) -> str:
    if not password or len(password) > 1024:
        raise ValueError("Password must contain 1–1024 characters")
    salt = secrets.token_bytes(16)
    digest = hashlib.scrypt(password.encode(), salt=salt, n=16384, r=8, p=1)
    return "scrypt$" + base64.urlsafe_b64encode(salt).decode() + "$" + base64.urlsafe_b64encode(digest).decode()


def verify_password(password: str, encoded: str) -> bool:
    try:
        if not password or len(password) > 1024:
            return False
        kind, salt, digest = encoded.split("$")
        if kind != "scrypt":
            return False
        actual = hashlib.scrypt(password.encode(), salt=base64.urlsafe_b64decode(salt), n=16384, r=8, p=1)
        return hmac.compare_digest(actual, base64.urlsafe_b64decode(digest))
    except (ValueError, TypeError):
        return False


def record_path(root: Path, record_id: str) -> Path:
    if not isinstance(record_id, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", record_id):
        raise ValueError("Invalid record identifier")
    target = (root / (record_id + ".json")).resolve()
    if not target.is_relative_to(root.resolve()):
        raise ValueError("Record path escapes storage")
    return target


def mist_base_url(value: str) -> str:
    parts = urlsplit(value)
    configured = urlsplit(os.getenv("MIST_BASE_URL", "https://api.ac2.mist.com"))
    allowed = {configured.hostname, "api.ac2.mist.com"}
    allowed.update(x.strip().lower() for x in os.getenv("MIST_ALLOWED_HOSTS", "").split(",") if x.strip())
    if (parts.scheme != "https" or not parts.hostname or parts.hostname.lower() not in allowed
            or parts.username or parts.password or parts.port not in (None, 443)
            or parts.query or parts.fragment or parts.path.rstrip("/") not in ("", "/api/v1")):
        raise ValueError("Mist destination must be an approved HTTPS API origin")
    return f"https://{parts.hostname.lower()}/api/v1"


def validate_mist_request(url: str) -> None:
    parts = urlsplit(url)
    mist_base_url(f"{parts.scheme}://{parts.netloc}/api/v1")
    if not parts.path.startswith("/api/v1/") or "\\" in url or any(ord(c) < 32 for c in url):
        raise ValueError("Invalid Mist API URL")


@contextmanager
def security_db():
    path = Path(os.getenv("SECURITY_DB_PATH", str(BACKEND_DIR / "data" / "security.sqlite3")))
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    with sqlite3.connect(path, timeout=10) as db:
        os.chmod(path, 0o600)
        db.execute("CREATE TABLE IF NOT EXISTS sessions (id TEXT PRIMARY KEY, data TEXT NOT NULL, expires REAL NOT NULL)")
        db.execute("CREATE TABLE IF NOT EXISTS rate_limits (key TEXT PRIMARY KEY, count INTEGER NOT NULL, expires REAL NOT NULL)")
        db.execute("CREATE TABLE IF NOT EXISTS work_leases (id TEXT PRIMARY KEY, expires REAL NOT NULL)")
        db.execute("DELETE FROM sessions WHERE expires < ?", (time.time(),))
        db.execute("DELETE FROM rate_limits WHERE expires < ?", (time.time(),))
        db.execute("DELETE FROM work_leases WHERE expires < ?", (time.time(),))
        yield db


def rate_limit(key: str, *, maximum: int, window: int) -> bool:
    # The immediate transaction makes limits effective across processes/workers.
    with security_db() as db:
        db.execute("INSERT INTO rate_limits VALUES (?, 1, ?) ON CONFLICT(key) DO UPDATE SET count=count+1", (key, time.time() + window))
        return db.execute("SELECT count FROM rate_limits WHERE key=?", (key,)).fetchone()[0] <= maximum


def csrf_token(request: Request) -> str:
    return request.session.setdefault("csrf", secrets.token_urlsafe(32))


def acquire_job_slot(job_id: str) -> None:
    with security_db() as db:
        db.execute("UPDATE work_leases SET expires=expires")
        count = db.execute("SELECT count(*) FROM work_leases").fetchone()[0]
        if count >= int(os.getenv("MAX_SSH_JOBS", "2")):
            raise HTTPException(status_code=429, detail="SSH collection capacity reached; wait for an active job to finish")
        db.execute("INSERT INTO work_leases VALUES (?,?)", (job_id, time.time() + 4 * 3600))


def release_job_slot(job_id: str) -> None:
    with security_db() as db:
        db.execute("DELETE FROM work_leases WHERE id=?", (job_id,))


def renew_job_slot(job_id: str) -> None:
    with security_db() as db:
        db.execute("UPDATE work_leases SET expires=? WHERE id=?", (time.time() + 4 * 3600, job_id))


class SecurityMiddleware:
    """Authenticate and bound requests before parsing any attacker-controlled body."""
    def __init__(self, app, authenticate):
        self.app = app
        self.authenticate = authenticate
        self.slots = threading.BoundedSemaphore(int(os.getenv("MAX_INFLIGHT_REQUESTS", "8")))

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http" or scope.get("path", "").startswith("/static/"):
            return await self.dispatch(scope, receive, send)
        if not self.slots.acquire(blocking=False):
            return await JSONResponse({"detail": "Server capacity reached; retry shortly"}, status_code=429)(scope, receive, send)
        try:
            return await self.dispatch(scope, receive, send)
        finally:
            self.slots.release()

    async def dispatch(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        request = Request(scope)
        nonce = secrets.token_urlsafe(24)
        scope.setdefault("state", {})["csp_nonce"] = nonce

        async def secure_send(message):
            if message["type"] == "http.response.start":
                message.setdefault("headers", []).extend([
                    (b"content-security-policy", ("default-src 'self'; script-src 'self' 'nonce-" + nonce + "'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'").encode()),
                    (b"x-content-type-options", b"nosniff"),
                    (b"x-frame-options", b"DENY"),
                    (b"referrer-policy", b"same-origin"),
                    (b"cache-control", b"no-store"),
                ])
                if scope.get("scheme") == "https":
                    message["headers"].append((b"strict-transport-security", b"max-age=31536000"))
            await send(message)

        async def reject(status, detail):
            return await JSONResponse({"detail": detail}, status_code=status)(scope, receive, secure_send)

        host = request.url.hostname or ""
        allowed_hosts = {x.strip().lower().strip("[]") for x in os.getenv("APP_ALLOWED_HOSTS", "localhost,127.0.0.1,::1").split(",")}
        if host.lower() not in allowed_hosts:
            return await reject(400, "Unapproved host")
        peer = (scope.get("client") or ("", 0))[0]
        loopback = host in {"localhost", "127.0.0.1", "::1", "testserver"} and (peer in {"testclient", "127.0.0.1", "::1"})
        if scope.get("scheme") != "https" and not (loopback and os.getenv("SESSION_HTTPS_ONLY", "true").lower() == "false"):
            return await reject(400, "HTTPS is required")

        path = scope["path"]
        public = path == "/login" or path.startswith("/static/")
        if path == "/login" and request.method == "GET":
            if not rate_limit("login-page:" + peer, maximum=60, window=60):
                return await reject(429, "Request limit exceeded")
        if path == "/login" and request.method == "POST":
            if not rate_limit("login:" + peer, maximum=10, window=300):
                return await reject(429, "Too many login attempts; try again later")
        if not public:
            try:
                # LDAP verification performs blocking I/O; keep it off the event loop.
                from starlette.concurrency import run_in_threadpool
                scope["state"]["authenticated_user"] = await run_in_threadpool(self.authenticate, request)
            except HTTPException as exc:
                if path.startswith("/api/") or path in {"/me", "/docs", "/openapi.json", "/redoc"}:
                    return await reject(exc.status_code, exc.detail)
                return await RedirectResponse("/login", status_code=303)(scope, receive, secure_send)
            if not rate_limit("api:" + peer, maximum=300, window=60):
                return await reject(429, "Request limit exceeded")

        unsafe = request.method not in {"GET", "HEAD", "OPTIONS"}
        if unsafe:
            origin = request.headers.get("origin")
            expected = str(request.base_url).rstrip("/")
            if (origin and origin != expected) or request.headers.get("sec-fetch-site") == "cross-site":
                return await reject(403, "Cross-origin changes are forbidden")
            if not rate_limit("request:" + peer, maximum=120, window=60):
                return await reject(429, "Request limit exceeded")
            limit = 8192 if path == "/login" else int(os.getenv("MAX_REQUEST_BYTES", str(16 * 1024 * 1024)))
            try:
                if int(request.headers.get("content-length", "0")) > limit:
                    return await reject(413, "Request too large")
            except ValueError:
                return await reject(400, "Invalid Content-Length")
            body = bytearray()
            try:
                with anyio.fail_after(30):
                    while True:
                        message = await receive()
                        if message["type"] == "http.disconnect":
                            return
                        body.extend(message.get("body", b""))
                        if len(body) > limit:
                            return await reject(413, "Request too large")
                        if not message.get("more_body"):
                            break
            except TimeoutError:
                return await reject(408, "Request body timed out")
            token = request.headers.get("x-csrf-token", "")
            if path == "/login" and "application/x-www-form-urlencoded" in request.headers.get("content-type", ""):
                token = parse_qs(body.decode(errors="replace")).get("csrf_token", [""])[0]
            expected_token = request.session.get("csrf", "")
            if not expected_token or not re.fullmatch(r"[A-Za-z0-9_-]{32,128}", token) or not hmac.compare_digest(token, expected_token):
                return await reject(403, "Invalid CSRF token; reload the page")
            delivered = False

            async def replay():
                nonlocal delivered
                if not delivered:
                    delivered = True
                    return {"type": "http.request", "body": bytes(body), "more_body": False}
                return await receive()

            return await self.app(scope, replay, secure_send)
        return await self.app(scope, receive, secure_send)
