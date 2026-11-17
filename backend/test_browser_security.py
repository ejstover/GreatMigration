"""Real Chromium tests against an isolated server with synthetic infrastructure."""
import os
import socket
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

import pytest


@pytest.fixture(scope="module")
def browser_server(tmp_path_factory):
    root = Path(__file__).resolve().parents[1]
    data = tmp_path_factory.mktemp("browser_server")
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    output = (data / "server.log").open("w", encoding="utf-8")
    protected_roots = [root / "tmp_ssh_jobs", root / "backend/data/conversion_sets", root / "backend/data/network_state"]
    before = {str(p): (p.stat().st_size, p.stat().st_mtime_ns) for directory in protected_roots
              for p in directory.rglob("*") if p.is_file()}
    server = subprocess.Popen([sys.executable, str(root / "tests/browser_server.py"), "--port", str(port), "--data", str(data)],
                              cwd=root, stdout=output, stderr=subprocess.STDOUT,
                              creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0)
    origin = f"http://127.0.0.1:{port}"
    try:
        deadline = time.monotonic() + 25
        while time.monotonic() < deadline:
            if server.poll() is not None:
                raise AssertionError((data / "server.log").read_text())
            try:
                urllib.request.urlopen(origin + "/login", timeout=1).close()
                break
            except OSError:
                time.sleep(0.1)
        else:
            raise AssertionError("Browser test server did not become ready")
        yield origin, data
    finally:
        server.terminate()
        server.wait(timeout=10)
        output.close()
        after = {str(p): (p.stat().st_size, p.stat().st_mtime_ns) for directory in protected_roots
                 for p in directory.rglob("*") if p.is_file()}
        assert after == before, "Browser tests must never alter workspace evidence"


def login(page, origin, username="operator"):
    page.goto(origin + "/login", wait_until="networkidle")
    page.locator('[name="username"]').fill(username)
    page.locator('[name="password"]').fill("browser-test-password")
    page.get_by_role("button", name="Sign in").click()
    page.wait_for_url(origin + "/")
    page.wait_for_load_state("networkidle")


def test_browser_pages_uploads_and_stored_xss(browser_server):
    from playwright.sync_api import sync_playwright, expect
    origin, data = browser_server
    with sync_playwright() as pw:
        browser = pw.chromium.launch(headless=True)
        page = browser.new_page()
        errors = []
        violations = []
        page.on("pageerror", lambda error: errors.append(str(error)))
        page.on("console", lambda message: violations.append(message.text) if "Content Security Policy" in message.text or "violates the following" in message.text else None)
        login(page, origin)
        for path in ["/", "/hardware", "/rules", "/replacements", "/standards", "/audit", "/network-snapshot"]:
            response = page.goto(origin + path, wait_until="networkidle")
            assert response.status == 200
            assert page.evaluate("typeof window.securityMarker") == "undefined"
            assert page.locator("img[onerror]").count() == 0
            assert page.evaluate("getComputedStyle(document.body).fontFamily")
        page.goto(origin + "/rules", wait_until="networkidle")
        expect(page.locator("input.name")).to_have_count(1)
        assert "<img" in page.locator("input.name").input_value()
        page.locator("input.name").fill("Safe browser-tested rule")
        # Exercise the actual CSRF-protected policy endpoint through the browser wrapper.
        status = page.evaluate("async () => (await fetch('/api/rules', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({rules:[{name:'Safe browser-tested rule',when:{any:true},set:{usage:'end_user'}}]})})).status")
        assert status == 200
        page.reload(wait_until="networkidle")
        expect(page.locator("input.name")).to_have_value("Safe browser-tested rule")
        page.goto(origin + "/", wait_until="networkidle")
        conversion = page.evaluate("""async () => {
          const form = new FormData();
          form.append('files', new File(['hostname legacy\\ninterface GigabitEthernet1/0/1\\n switchport mode access\\n switchport access vlan 10\\n!\\n'], 'switch.txt'));
          const response = await fetch('/api/convert', {method:'POST',body:form});
          return {status:response.status, data:await response.json()};
        }""")
        assert conversion["status"] == 200 and conversion["data"]["ok"], conversion
        assert conversion["data"]["items"][0]["json"]["interfaces"]
        hardware = page.evaluate("""async () => {
          const form = new FormData();
          form.append('files', new File(['hostname legacy\\nNAME: "1", DESCR: "C9300"\\nPID: C9300-48P , VID: V01 , SN: TEST\\n'], 'hardware.txt'));
          const response = await fetch('/api/showtech', {method:'POST',body:form});
          return {status:response.status, data:await response.json()};
        }""")
        assert hardware["status"] == 200 and hardware["data"]["ok"]
        pdf = page.evaluate("""async () => {
          const response = await fetch('/api/showtech/pdf', {method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({project_name:'Browser test',results:[],accessories:[]})});
          return {status:response.status, type:response.headers.get('Content-Type'), bytes:(await response.arrayBuffer()).byteLength};
        }""")
        assert pdf["status"] == 200 and "application/pdf" in pdf["type"] and pdf["bytes"] > 100
        page.screenshot(path=str(data / "secured-conversion.png"), full_page=True)
        assert not errors, errors
        assert not violations, violations
        browser.close()


def test_browser_readonly_controls_and_logout(browser_server):
    from playwright.sync_api import sync_playwright, expect
    origin, _ = browser_server
    with sync_playwright() as pw:
        browser = pw.chromium.launch(headless=True)
        page = browser.new_page()
        login(page, origin, "reader")
        page.goto(origin + "/standards", wait_until="networkidle")
        expect(page.locator("#sync_standards")).to_be_hidden()
        page.goto(origin + "/audit", wait_until="networkidle")
        expect(page.locator("#active_checks_control")).to_be_hidden()
        status = page.evaluate("async () => (await fetch('/api/rules',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({rules:[]})})).status")
        assert status == 403
        page.evaluate("window.secureLogout()")
        page.wait_for_url(origin + "/login")
        assert page.request.get(origin + "/me").status == 401
        browser.close()
