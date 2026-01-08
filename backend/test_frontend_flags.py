from pathlib import Path


def test_preserve_legacy_vlan_checkbox_serialized():
    index_html = (Path(__file__).resolve().parent.parent / "templates" / "index.html").read_text(encoding="utf-8")

    assert 'id="preserve_legacy_vlans"' in index_html
    assert "form.append('preserve_legacy_vlans'" in index_html
