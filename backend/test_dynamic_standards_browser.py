"""Exercise the guided standard builder against isolated synthetic Mist data."""
from playwright.sync_api import sync_playwright, expect

from test_browser_security import browser_server, login  # noqa: F401


def test_create_preview_save_reload_and_discover(browser_server):
    origin, data = browser_server
    with sync_playwright() as pw:
        browser = pw.chromium.launch(headless=True)
        page = browser.new_page(ignore_https_errors=True, viewport={"width": 1440, "height": 1100})
        errors = []
        page.on('pageerror', lambda error: errors.append(str(error)))
        login(page, origin)
        page.goto(origin + '/standards', wait_until='networkidle')
        expect(page.get_by_role('tab', name='Policies', exact=True)).to_have_attribute('aria-selected', 'true')
        expect(page.locator('#policy_list button')).to_have_count(12)
        page.get_by_role('button', name='New standard', exact=True).click()
        page.get_by_label('Name', exact=True).fill('Browser switch naming')
        expect(page.get_by_label('Value', exact=True)).to_have_value('^NYC-SW-[0-9]{3}$')
        expect(page.get_by_label('Choose a field')).to_be_visible()
        page.get_by_label('Search fields', exact=True).fill('name')
        page.get_by_label('Choose a field').select_option('["name"]')
        page.get_by_role('button', name='Validate', exact=True).click()
        expect(page.locator('#standards_notice')).to_contain_text('valid')
        # A browser-route fixture exercises the actual form and CSRF wrapper without
        # giving the isolated server access to real infrastructure.
        preview_payloads = []
        def preview(route):
            preview_payloads.append(route.request.post_data_json)
            route.fulfill(json={"ok":True,"evaluation_coverage":{"pass":1,"fail":1,"excluded":0,"unevaluated":0},
                "checks":[{"evaluations":[
                    {"target":{"id":"sw1","name":"NYC-SW-001"},"status":"pass","message":"Requirement satisfied","evidence":[]},
                    {"target":{"id":"sw2","name":"legacy"},"status":"fail","message":"Requirement not satisfied","evidence":[{"source":"device_config","path":["name"],"value":"legacy"}]}]}]})
        page.route('**/api/standards/preview', preview)
        page.get_by_label('Sites for live preview', exact=True).fill('site1')
        page.get_by_role('button', name='Preview on live data', exact=True).click()
        expect(page.locator('.standards-status')).to_contain_text('Passing: 1')
        expect(page.locator('.standards-status')).to_contain_text('Failing: 1')
        assert preview_payloads[0]['policy']['requirement']['left']['path'] == ['name']
        page.get_by_role('button', name='Save standard', exact=True).click()
        expect(page.locator('#standards_notice')).to_contain_text('Standard saved')
        expect(page.locator('#policy_list button')).to_have_count(13)
        page.reload(wait_until='networkidle')
        page.get_by_role('button', name='Browser switch naming', exact=False).click()
        expect(page.get_by_label('Name', exact=True)).to_have_value('Browser switch naming')
        page.screenshot(path=str(data / 'dynamic-standards.png'), full_page=True)
        page.get_by_role('tab', name='Data Sources', exact=True).click()
        expect(page.locator('#source_list button')).to_have_count(7)
        page.locator('#source_list button').first.click()
        expect(page.get_by_role('button', name='Test mapping', exact=True)).to_be_enabled()
        page.get_by_role('tab', name='Firmware Matrix', exact=True).click()
        expect(page.get_by_role('heading', name='Firmware Standards Matrix')).to_be_visible()
        assert not errors, errors
        browser.close()


def test_readonly_authoring_and_mobile_layout(browser_server):
    origin, _ = browser_server
    with sync_playwright() as pw:
        browser = pw.chromium.launch(headless=True)
        page = browser.new_page(ignore_https_errors=True, viewport={"width":390,"height":844})
        login(page,origin,'reader')
        page.goto(origin+'/standards',wait_until='networkidle')
        page.get_by_role('button',name='New standard',exact=True).click()
        expect(page.get_by_role('button',name='Save standard',exact=True)).to_be_disabled()
        expect(page.get_by_role('button',name='Preview on live data',exact=True)).to_be_enabled()
        assert page.evaluate('document.documentElement.scrollWidth <= window.innerWidth')
        browser.close()
