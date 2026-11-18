"""Isolated application server for browser tests; all infrastructure is synthetic."""
import argparse
import json
import os
import sys
from pathlib import Path

parser = argparse.ArgumentParser()
parser.add_argument("--port", type=int, required=True)
parser.add_argument("--data", type=Path, required=True)
args = parser.parse_args()
root = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(root / "backend"))
args.data.mkdir(parents=True, exist_ok=True)
os.environ.update(AUTH_METHOD="local", SESSION_SECRET="browser-tests-" + "x" * 48,
                  SESSION_HTTPS_ONLY="false", MIST_TOKEN="browser-synthetic-token",
                  LOCAL_USERS_FILE=str(args.data / "users.json"), SYSLOG_HOST="", SYSLOG_SERVER="",
                  SECURITY_DB_PATH=str(args.data / "sessions.sqlite3"),
                  STANDARDS_STORE_PATH=str(args.data / "policy-catalog.json"),
                  MIST_BASE_URL="https://api.ac2.mist.com", MIST_ORG_ID="org1")
from security import hash_password
password_hash = hash_password("browser-test-password")
(args.data / "users.json").write_text(json.dumps({
    "operator": {"password_hash": password_hash, "can_push": True},
    "reader": {"password_hash": password_hash, "can_push": False},
}))
import requests
import dotenv
dotenv.load_dotenv = lambda *args, **kwargs: False
from urllib.parse import urlsplit

def synthetic_send(self, request, **kwargs):
    path = urlsplit(request.url).path
    payload = []
    if path.endswith("/self"):
        payload = {"privileges": [{"scope": "org", "org_id": "org1"}]}
    elif path.endswith("/sites"):
        payload = [{"id": "site1", "name": '<img src=x onerror="window.securityMarker=1">', "org_id": "org1"}]
    elif path.endswith("/inventory/count"):
        payload = {"results": [{"model": "EX4100-48P", "count": 1}]}
    elif path.endswith("/setting") or path.endswith("/derived"):
        payload = {"switch": {}, "variables": {}, "port_usages": {"end_user": {"mode": "access"}}, "networks": {}}
    elif "/devices" in path:
        payload = []
    response = requests.Response()
    response.status_code = 200
    response._content = json.dumps(payload).encode()
    response.headers["Content-Type"] = "application/json"
    response.request = request
    response.url = request.url
    return response

requests.sessions.Session.send = synthetic_send
import app
import compliance
import conversion_sets
import network_state_snapshots
import audit_exceptions
import ssh_collect
app.action_logger.disabled = True
app.app.state.evidence_root = args.data
ssh_collect.JOB_ROOT = args.data / "tmp_ssh_jobs"
conversion_sets.DATA_DIR = args.data / "conversion_sets"
network_state_snapshots.DATA_DIR = args.data / "network_state"
audit_exceptions.EXCEPTIONS_PATH = args.data / "exceptions.json"
for name, filename in [("RULES_LOCAL_PATH", "rules.json"), ("REPLACEMENTS_PATH", "replacements.json")]:
    setattr(app, name, args.data / filename)
malicious_name = '\"><img src=x onerror="window.securityMarker=1">'
rules = {"rules": [{"name": malicious_name, "when": {"any": True}, "set": {"usage": "end_user"}}]}
app.RULES_LOCAL_PATH.write_text(json.dumps(rules))
app.RULES_REPO_PATH = app.RULES_LOCAL_PATH
app.pm.RULES_DOC = rules
app.REPLACEMENTS_PATH.write_text('{"rules":[],"accessories":[]}')
standards = args.data / "standards.json"
standards.write_text(json.dumps({"generated_at": "2026-11-17T00:00:00Z", "models": {"switch": {"EX4100-48P": [{"version": "24.4R2"}]}, "ap": {}}}))
app._firmware_standards_path = lambda: standards
compliance._firmware_standards_path = lambda: standards
app._refresh_firmware_standards_if_needed = lambda path: {}
compliance._refresh_firmware_standards_if_needed = lambda path=None: json.loads(standards.read_text())
app._discover_org_ids = lambda *args: ["org1"]
import uvicorn
uvicorn.run(app.app, host="127.0.0.1", port=args.port, log_level="warning")
