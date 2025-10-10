import pytest

from compliance import (
    SiteContext,
    RequiredSiteVariablesCheck,
    LabTemplateRestrictionCheck,
    ConfigurationOverridesCheck,
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
                "port_overrides": [{"port_id": "ge-0/0/10", "profile": "Voice"}],
            },
            {
                "id": "dist1",
                "name": "Distribution Switch",
                "role": "DISTRIBUTION",
                "port_overrides": [{"port_id": "ge-0/0/48", "profile": "Uplink"}],
            },
            {
                "id": "cfg1",
                "name": "Custom Switch",
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
