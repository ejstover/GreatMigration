from pathlib import Path


def test_preserve_legacy_vlan_checkbox_serialized():
    index_html = (Path(__file__).resolve().parent.parent / "templates" / "index.html").read_text(encoding="utf-8")

    assert 'id="preserve_legacy_vlans"' in index_html
    assert "form.append('preserve_legacy_vlans'" in index_html


def test_lcm_step3_preview_button_states_serialized():
    index_html = (Path(__file__).resolve().parent.parent / "templates" / "index.html").read_text(encoding="utf-8")

    assert "Preview Selected Automation" in index_html
    assert "Apply Configuration" in index_html
    assert "form.append('force_preview'" in index_html


def test_audit_check_level_map_includes_device_checks():
    audit_html = (Path(__file__).resolve().parent.parent / "templates" / "audit.html").read_text(encoding="utf-8")

    assert "switch_power_supply_health: 'device'" in audit_html
    assert "virtual_chassis_roles: 'device'" in audit_html


def test_one_click_fix_completion_status_is_applied_to_clicked_button():
    audit_html = (Path(__file__).resolve().parent.parent / "templates" / "audit.html").read_text(encoding="utf-8")

    assert "const completionSummary = `1 Click Fix completed: ${summaryDetails.join(' ')}.`;" in audit_html
    assert "applyActionStatus(button, completionSummary, summaryVariant);" in audit_html
