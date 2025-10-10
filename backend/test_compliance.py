import pytest

from compliance import (
    SiteContext,
    RequiredSiteVariablesCheck,
    LabTemplateRestrictionCheck,
    ConfigurationOverridesCheck,
    DeviceNamingConventionCheck,
    DeviceImageInventoryCheck,
    SiteAuditRunner,
)


def test_required_site_variables_check_flags_missing():
    ctx = SiteContext(
        site_id="site-1",
        site_name="HQ",
        site={"variables": {"hubradiusserver": "1.1.1.1"}},
        setting={},
        templates=[],
        devices=[],
    )
    check = RequiredSiteVariablesCheck()
    findings = check.run(ctx)
    assert len(findings) == 1
    assert "localradiusserver" in findings[0].message


def test_required_site_variables_check_passes_when_present():
    ctx = SiteContext(
        site_id="site-1",
        site_name="HQ",
        site={"variables": {"hubradiusserver": "1.1.1.1", "localradiusserver": "2.2.2.2"}},
        setting={},
        templates=[],
        devices=[],
    )
    check = RequiredSiteVariablesCheck()
    findings = check.run(ctx)
    assert findings == []


def test_lab_template_restriction_check_identifies_non_lab_site():
    ctx = SiteContext(
        site_id="site-2",
        site_name="Corporate Campus",
        site={},
        setting={},
        templates=[{"name": "Test - Standard Template"}],
        devices=[],
    )
    check = LabTemplateRestrictionCheck()
    findings = check.run(ctx)
    assert len(findings) == 1
    assert "does not appear" in findings[0].message


def test_lab_template_restriction_allows_lab_site():
    ctx = SiteContext(
        site_id="site-3",
        site_name="Innovation Lab",
        site={},
        setting={},
        templates=[{"name": "Test - Standard Template"}],
        devices=[],
    )
    check = LabTemplateRestrictionCheck()
    assert check.run(ctx) == []


def test_configuration_overrides_check_respects_access_exceptions():
    ctx = SiteContext(
        site_id="site-4",
        site_name="Branch",
        site={},
        setting={"switch_override": {"foo": "bar"}},
        templates=[],
        devices=[
            {
                "id": "access1",
                "name": "Access Switch",
                "role": "ACCESS",
                "status": "connected",
                "port_overrides": [{"port_id": "ge-0/0/10", "profile": "Voice"}],
            },
            {
                "id": "dist1",
                "name": "Distribution Switch",
                "role": "DISTRIBUTION",
                "status": "connected",
                "port_overrides": [{"port_id": "ge-0/0/48", "profile": "Uplink"}],
            },
            {
                "id": "cfg1",
                "name": "Custom Switch",
                "status": "connected",
                "config_override": {"foo": "bar"},
            },
        ],
    )
    check = ConfigurationOverridesCheck()
    findings = check.run(ctx)

    # Site override should be reported
    site_findings = [f for f in findings if f.device_id is None]
    assert site_findings

    # Access switch override on port 10 should be allowed
    assert all(f.device_id != "access1" for f in findings)

    # Distribution switch override should be reported
    assert any(f.device_id == "dist1" for f in findings)

    # Direct config override should be reported
    assert any(f.device_id == "cfg1" for f in findings)


def test_configuration_overrides_check_detects_template_differences():
    ctx = SiteContext(
        site_id="site-7",
        site_name="Template Site",
        site={},
        setting={},
        templates=[
            {
                "id": "tmpl-1",
                "name": "Standard",
                "switch_config": {
                    "ports": {
                        "0": {"profile": "ACCESS"},
                        "48": {"profile": "UPLINK"},
                    }
                },
            }
        ],
        devices=[
            {
                "id": "dist1",
                "name": "Distribution",
                "role": "DISTRIBUTION",
                "status": "connected",
                "switch_template_id": "tmpl-1",
                "switch_config": {
                    "ports": {
                        "0": {"profile": "ACCESS"},
                        "48": {"profile": "VOICE"},
                    }
                },
            },
            {
                "id": "access1",
                "name": "Access",
                "role": "ACCESS",
                "status": "connected",
                "switch_template_id": "tmpl-1",
                "switch_config": {
                    "ports": {
                        "0": {"profile": "VOICE"},
                        "48": {"profile": "UPLINK"},
                    }
                },
            },
        ],
    )
    check = ConfigurationOverridesCheck()
    findings = check.run(ctx)

    dist_findings = [f for f in findings if f.device_id == "dist1" and "differs" in f.message]
    assert dist_findings, "Distribution switch diff should be reported"

    access_findings = [f for f in findings if f.device_id == "access1" and "differs" in f.message]
    assert not access_findings, "Access switch port overrides within exception should be ignored"


def test_configuration_overrides_check_skips_offline_devices():
    ctx = SiteContext(
        site_id="site-8",
        site_name="Offline Site",
        site={},
        setting={},
        templates=[
            {
                "id": "tmpl-1",
                "switch_config": {"foo": "bar"},
            }
        ],
        devices=[
            {
                "id": "offline1",
                "name": "Offline Switch",
                "role": "DISTRIBUTION",
                "status": "offline",
                "switch_template_id": "tmpl-1",
                "switch_config": {"foo": "baz"},
                "config_override": {"foo": "baz"},
            }
        ],
    )
    check = ConfigurationOverridesCheck()
    findings = check.run(ctx)
    assert findings == []


def test_device_naming_convention_enforces_pattern():
    ctx = SiteContext(
        site_id="site-9",
        site_name="Naming Site",
        site={},
        setting={},
        templates=[],
        devices=[
            {"id": "good1", "name": "NAABCAS1", "type": "switch", "status": "connected"},
            {"id": "bad1", "name": "NaABCAS2", "type": "switch", "status": "connected"},
            {"id": "bad2", "name": "", "type": "switch", "status": "connected"},
            {"id": "ignore1", "name": "ap-1", "type": "ap", "status": "connected"},
            {"id": "offline", "name": "NAABCCS1", "type": "switch", "status": "offline"},
        ],
    )
    check = DeviceNamingConventionCheck()
    findings = check.run(ctx)
    ids = {f.device_id for f in findings}
    assert ids == {"bad1", "bad2"}
    for finding in findings:
        assert finding.details and "expected_pattern" in finding.details


def test_device_image_inventory_requires_two_images():
    ctx = SiteContext(
        site_id="site-10",
        site_name="Image Site",
        site={},
        setting={},
        templates=[],
        devices=[
            {
                "id": "enough",
                "name": "NAABCAS1",
                "type": "switch",
                "status": "connected",
                "images": ["img1", "img2"],
            },
            {
                "id": "insufficient",
                "name": "NAABCAS2",
                "type": "switch",
                "status": "connected",
                "pictures": ["img1"],
            },
            {
                "id": "offline",
                "name": "NAABCAS3",
                "type": "switch",
                "status": "offline",
                "images": [],
            },
        ],
    )
    check = DeviceImageInventoryCheck()
    findings = check.run(ctx)
    assert [f.device_id for f in findings] == ["insufficient", "offline"]


def test_device_image_inventory_handles_numbered_urls():
    ctx = SiteContext(
        site_id="site-11",
        site_name="Camera Site",
        site={},
        setting={},
        templates=[],
        devices=[
            {
                "id": "numbered",
                "name": "NAABCAS5",
                "type": "switch",
                "status": "connected",
                "image1_url": "https://example.com/image1.jpg",
                "image2_url": " https://example.com/image2.jpg ",
            },
            {
                "id": "single-numbered",
                "name": "NAABCAS6",
                "type": "switch",
                "status": "connected",
                "image1_url": "https://example.com/only.jpg",
            },
        ],
    )
    check = DeviceImageInventoryCheck()
    findings = check.run(ctx)
    assert [f.device_id for f in findings] == ["single-numbered"]


def test_device_image_inventory_handles_nested_status_dicts():
    ctx = SiteContext(
        site_id="site-12",
        site_name="Nested Status",
        site={},
        setting={},
        templates=[],
        devices=[
            {
                "id": "nested",
                "name": "NAABCAS7",
                "type": "switch",
                "status": {"status": "connected", "uptime": 12345},
            },
            {
                "id": "offline-nested",
                "name": "NAABCAS8",
                "type": "switch",
                "status": {"status": "offline"},
            },
        ],
    )
    check = DeviceImageInventoryCheck()
    findings = check.run(ctx)
    assert [f.device_id for f in findings] == ["nested", "offline-nested"]




def test_device_image_inventory_handles_status_strings_with_suffix():
    ctx = SiteContext(
        site_id="site-13",
        site_name="Status Strings",
        site={},
        setting={},
        templates=[],
        devices=[
            {
                "id": "suffix",
                "name": "NAABCAS9",
                "type": "switch",
                "status": "Connected (wired)",
            },
            {
                "id": "offline-suffix",
                "name": "NAABCAS10",
                "type": "switch",
                "status": "Disconnected",
            },
        ],
    )
    check = DeviceImageInventoryCheck()
    findings = check.run(ctx)
    assert [f.device_id for f in findings] == ["suffix", "offline-suffix"]


def test_device_image_inventory_handles_deeply_nested_status_structures():
    ctx = SiteContext(
        site_id="site-14",
        site_name="Nested Structures",
        site={},
        setting={},
        templates=[],
        devices=[
            {
                "id": "deep-nested",
                "name": "NAABCAS11",
                "type": "switch",
                "status": {
                    "wired": {
                        "details": {"state": "Connected"},
                        "history": [
                            {"state": "offline"},
                            {"state": "connected"},
                        ],
                    }
                },
            },
        ],
    )
    check = DeviceImageInventoryCheck()
    findings = check.run(ctx)
    assert [f.device_id for f in findings] == ["deep-nested"]


def test_site_audit_runner_summarizes_results():
    contexts = [
        SiteContext(
            site_id="site-5",
            site_name="Site 5",
            site={"variables": {"hubradiusserver": "1.1.1.1", "localradiusserver": "2.2.2.2"}},
            setting={},
            templates=[],
            devices=[],
        ),
        SiteContext(
            site_id="site-6",
            site_name="Site 6",
            site={"variables": {"hubradiusserver": "1.1.1.1"}},
            setting={},
            templates=[],
            devices=[],
        ),
    ]
    runner = SiteAuditRunner([RequiredSiteVariablesCheck()])
    result = runner.run(contexts)
    assert result["total_sites"] == 2
    checks = result["checks"]
    assert len(checks) == 1
    check = checks[0]
    assert check["failing_sites"] == ["site-6"]
    assert check["passing_sites"] == 1
