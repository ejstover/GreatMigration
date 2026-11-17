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


def test_network_snapshot_ui_moves_to_dedicated_template():
    index_html = (Path(__file__).resolve().parent.parent / "templates" / "index.html").read_text(encoding="utf-8")
    snapshot_html = (Path(__file__).resolve().parent.parent / "templates" / "network_snapshot.html").read_text(encoding="utf-8")

    assert 'id="snapshot_project_name"' not in index_html
    assert 'id="snapshot_capture_btn"' not in index_html
    assert 'Network Snapshot and MAC validation' not in index_html
    assert 'id="snapshot_project_name"' in snapshot_html
    assert 'id="snapshot_capture_btn"' in snapshot_html
    assert 'id="snapshot_compare_btn"' in snapshot_html
    assert '/api/network-state/baselines/jobs' in snapshot_html
    assert '/api/network-state/compare' in snapshot_html
    assert "bg-linear-to-r from-emerald-500 to-sky-500" in snapshot_html
    assert "The page auto-selects the latest saved set for a project’s first baseline" in snapshot_html
    assert "rounded-2xl border border-slate-200/70 bg-white p-6 shadow-xs" in snapshot_html
    assert "bg-[linear-gradient(120deg,#92400e,#f59e0b,#0f766e)]" not in snapshot_html


def test_config_page_serializes_conversion_set_save_controls():
    index_html = (Path(__file__).resolve().parent.parent / "templates" / "index.html").read_text(encoding="utf-8")

    assert 'id="conversion_set_project_name"' in index_html
    assert 'id="save_conversion_set_btn"' in index_html
    assert '/api/conversion-sets' in index_html


def test_audit_check_level_map_includes_device_checks():
    audit_html = (Path(__file__).resolve().parent.parent / "templates" / "audit.html").read_text(encoding="utf-8")

    assert "switch_cable_test: 'device'" in audit_html
    assert "switch_power_supply_health: 'device'" in audit_html
    assert "virtual_chassis_roles: 'device'" in audit_html


def test_one_click_fix_completion_status_is_applied_to_clicked_button():
    audit_html = (Path(__file__).resolve().parent.parent / "templates" / "audit.html").read_text(encoding="utf-8")

    assert "const completionSummary = `1 Click Fix completed: ${summaryDetails.join(' ')}.`;" in audit_html
    assert "applyActionStatus(button, completionSummary, summaryVariant);" in audit_html
