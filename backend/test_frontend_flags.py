from pathlib import Path


def test_preserve_legacy_vlan_checkbox_serialized():
    index_html = (Path(__file__).resolve().parent.parent / "templates" / "index.html").read_text(encoding="utf-8")

    assert 'id="preserve_legacy_vlans"' in index_html
    assert "form.append('preserve_legacy_vlans'" in index_html


def test_webhook_toast_stack_is_available_on_app_pages():
    templates_dir = Path(__file__).resolve().parent.parent / "templates"
    for name in ["index.html", "audit.html", "hardware.html", "rules.html", "hardwarereplacementrules.html"]:
        html = (templates_dir / name).read_text(encoding="utf-8")
        assert 'id="mist_toast_stack"' in html
        assert '/api/webhooks/mist/alerts' in html
        assert 'startWebhookAlerts()' in html or 'refreshMistActivityPanel' in html


def test_webhook_toasts_auto_dismiss_after_ten_seconds():
    templates_dir = Path(__file__).resolve().parent.parent / "templates"
    for name in ["index.html", "audit.html", "hardware.html", "rules.html", "hardwarereplacementrules.html"]:
        html = (templates_dir / name).read_text(encoding="utf-8")
        assert 'setTimeout(remove, 10000)' in html
        assert "closeBtn.textContent = '×'" in html
