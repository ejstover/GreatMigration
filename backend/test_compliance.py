import pytest

from compliance import (
    SiteContext,
    RequiredSiteVariablesCheck,
    LabTemplateRestrictionCheck,
    ConfigurationOverridesCheck,
    DeviceNamingConventionCheck,
    DeviceDocumentationCheck,
    SiteAuditRunner,
)


def test_required_site_variables_check_flags_missing():
    ctx = SiteContext(
        site_id="site-1",
        site_name="HQ",
        site={"variables": {}},
        setting={},
        templates=[],
        devices=[],
    )
    check = RequiredSiteVariablesCheck()
    findings = check.run(ctx)
    assert {f.message for f in findings} == {
        "Site variable 'hubradiusserver' is not defined.",
        "Site variable 'localradiusserver' is not defined.",
        "Site variable 'siteDNS' is not defined.",
        "Site variable 'hubDNSserver1' is not defined.",
        "Site variable 'hubDNSserver2' is not defined.",
    }


def test_required_site_variables_check_passes_when_present():
    ctx = SiteContext(
        site_id="site-1",
        site_name="HQ",
        site={
            "variables": {
                "hubradiusserver": "1.1.1.1",
                "localradiusserver": "2.2.2.2",
                "siteDNS": "dns.example.com",
                "hubDNSserver1": "10.0.0.53",
                "hubDNSserver2": "10.0.0.54",
            }
        },
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
                "map_id": "map-access1",
                "port_overrides": [{"port_id": "ge-0/0/10", "profile": "Voice"}],
                "switch_config": {
                    "ip_config": {
                        "type": "static",
                        "ip": "10.0.0.10",
                        "gateway": "10.0.0.1",
                        "network": "IT_Mgmt",
                        "netmask": "255.255.255.0",
                    }
                },
            },
            {
                "id": "dist1",
                "name": "Distribution Switch",
                "role": "DISTRIBUTION",
                "status": "connected",
                "map_id": "map-dist1",
                "port_overrides": [{"port_id": "ge-0/0/48", "profile": "Uplink"}],
                "switch_config": {
                    "ip_config": {
                        "type": "static",
                        "ip": "10.0.1.10",
                        "gateway": "10.0.1.1",
                        "network": "IT_Mgmt",
                        "netmask": "255.255.255.0",
                    }
                },
            },
            {
                "id": "cfg1",
                "name": "Custom Switch",
                "status": "connected",
                "type": "switch",
                "map_id": "map-cfg1",
                "config_override": {"foo": "bar"},
                "switch_config": {
                    "ip_config": {
                        "type": "static",
                        "ip": "10.0.2.10",
                        "gateway": "10.0.2.1",
                        "network": "IT_Mgmt",
                        "netmask": "255.255.255.0",
                    }
                },
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
                    "ip_config": {
                        "type": "static",
                        "ip": "10.0.0.2",
                        "gateway": "10.0.0.1",
                        "network": "IT_Mgmt",
                        "netmask": "255.255.255.0",
                    },
                },
            }
        ],
        devices=[
            {
                "id": "dist1",
                "name": "Distribution",
                "role": "DISTRIBUTION",
                "status": "connected",
                "map_id": "map-dist1",
                "switch_template_id": "tmpl-1",
                "switch_config": {
                    "ip_config": {
                        "type": "static",
                        "ip": "10.0.0.3",
                        "gateway": "10.0.0.1",
                        "network": "IT_Mgmt",
                        "netmask": "255.255.255.0",
                    },
                    "dhcp_snooping": {"enabled": True},
                },
            },
            {
                "id": "access1",
                "name": "Access",
                "role": "ACCESS",
                "status": "connected",
                "map_id": "map-access1",
                "switch_template_id": "tmpl-1",
                "switch_config": {
                    "ip_config": {
                        "type": "static",
                        "ip": "10.0.0.2",
                        "gateway": "10.0.0.1",
                        "network": "IT_Mgmt",
                        "netmask": "255.255.255.0",
                    },
                    "port_config": {
                        "ge-0/0/0": {"usage": "voice"},
                        "ge-0/0/48": {"usage": "uplink_idf"},
                        "xe-0/2/1": {"usage": "uplink_idf"},
                    },
                },
            },
            {
                "id": "access2",
                "name": "Access Edge",
                "role": "ACCESS",
                "status": "connected",
                "map_id": "map-access2",
                "switch_template_id": "tmpl-1",
                "switch_config": {
                    "ip_config": {
                        "type": "static",
                        "ip": "192.168.0.2",
                        "gateway": "192.168.0.1",
                        "network": "IT_Mgmt",
                        "netmask": "255.255.255.0",
                    },
                    "port_config": {
                        "ge-0/0/0": {"usage": "end_user"},
                        "ge-0/0/48": {"usage": "uplink_idf"},
                        "xe-0/2/1": {"usage": "internet_only"},
                    },
                },
            },
        ],
    )
    check = ConfigurationOverridesCheck()
    findings = check.run(ctx)

    dist_findings = [
        f
        for f in findings
        if f.device_id == "dist1"
        and any("dhcp" in (diff.get("path") or "") for diff in (f.details or {}).get("diffs", []))
    ]
    assert dist_findings, "Distribution switch dhcp_snooping override should be reported"

    access1_findings = [f for f in findings if f.device_id == "access1" and "differs" in f.message]
    assert not access1_findings, "Access switch non-uplink differences should be ignored"

    access2_findings = [f for f in findings if f.device_id == "access2" and "differs" in f.message]
    assert access2_findings, "Access switch IP violations should be reported"


def test_configuration_overrides_check_includes_offline_devices():
    ctx = SiteContext(
        site_id="site-8",
        site_name="Offline Site",
        site={},
        setting={},
        templates=[
            {
                "id": "tmpl-1",
                "switch_config": {
                    "ip_config": {"type": "static", "ip": "10.0.0.1"},
                    "port_config": {"ge-0/0/48": {"usage": "uplink_idf"}},
                },
            }
        ],
        devices=[
            {
                "id": "offline1",
                "name": "Offline Switch",
                "role": "DISTRIBUTION",
                "status": "offline",
                "switch_template_id": "tmpl-1",
                "switch_config": {
                    "ip_config": {"type": "static", "ip": "10.0.0.2"},
                    "port_config": {"ge-0/0/48": {"usage": "internet_only"}},
                },
                "config_override": {"foo": "baz"},
            }
        ],
    )
    check = ConfigurationOverridesCheck()
    findings = check.run(ctx)

    assert any(f.device_id == "offline1" and "differs" in f.message for f in findings)
    assert any(f.device_id == "offline1" and "override" in f.message.lower() for f in findings)


def test_configuration_overrides_check_flags_map_and_ip_exceptions():
    ctx = SiteContext(
        site_id="site-standard",
        site_name="Standard Site",
        site={},
        setting={},
        templates=[
            {
                "id": "tmpl-1",
                "switch_config": {
                    "ip_config": {
                        "type": "static",
                        "ip": "10.1.0.2",
                        "gateway": "10.1.0.1",
                        "network": "IT_Mgmt",
                        "netmask": "255.255.255.0",
                    }
                },
            }
        ],
        devices=[
            {
                "id": "sw1",
                "name": "Switch One",
                "status": "connected",
                "type": "switch",
                "map_id": None,
                "st_ip_base": "10.1.0.0/24",
                "evpn_scope": "fabric",
                "switch_template_id": "tmpl-1",
                "switch_config": {
                    "ip_config": {
                        "type": "static",
                        "ip": "10.1.0.5",
                        "gateway": "10.1.0.1",
                        "network": "IT_Mgmt",
                        "netmask": "255.255.255.0",
                        "dns": ["10.1.0.10"],
                    }
                },
            }
        ],
    )

    check = ConfigurationOverridesCheck()
    findings = check.run(ctx)

    assert findings, "Expected configuration override findings to be reported"

    paths = {
        diff.get("path")
        for finding in findings
        for diff in (finding.details or {}).get("diffs", [])
    }

    assert "map_id" not in paths
    assert "st_ip_base" in paths
    assert "evpn_scope" in paths
    assert "ip_config.dns" in paths


def test_configuration_overrides_check_skips_vc_port_differences():
    ctx = SiteContext(
        site_id="site-10",
        site_name="VC Site",
        site={},
        setting={},
        templates=[
            {
                "id": "tmpl-1",
                "switch_config": {
                    "ip_config": {"type": "static", "ip": "10.1.0.1"},
                    "port_config": {"ge-0/0/48": {"usage": "uplink_idf"}},
                },
            }
        ],
        devices=[
            {
                "id": "vc1",
                "name": "VC Stack",
                "role": "Access-VC-Star",
                "status": "connected",
                "switch_template_id": "tmpl-1",
                "switch_config": {
                    "ip_config": {"type": "static", "ip": "10.1.0.1"},
                    "port_config": {"ge-0/0/48": {"usage": "internet_only"}},
                },
            }
        ],
    )
    check = ConfigurationOverridesCheck()
    findings = check.run(ctx)

    assert not any(f.device_id == "vc1" and "differs" in f.message for f in findings)


def test_configuration_overrides_check_allows_wan_mgmt_and_oob_blocks():
    ctx = SiteContext(
        site_id="site-11",
        site_name="WAN Site",
        site={},
        setting={},
        templates=[
            {
                "id": "tmpl-1",
                "name": "Standard",
                "switch_config": {
                    "ip_config": {
                        "type": "static",
                        "ip": "10.0.0.2",
                        "gateway": "10.0.0.1",
                        "network": "IT_Mgmt",
                        "netmask": "255.255.255.0",
                    }
                },
            }
        ],
        devices=[
            {
                "id": "wan1",
                "name": "WAN Switch",
                "role": "WAN",
                "status": "connected",
                "map_id": "map-wan1",
                "switch_template_id": "tmpl-1",
                "switch_config": {
                    "ip_config": {
                        "type": "static",
                        "ip": "10.0.0.2",
                        "gateway": "10.0.0.1",
                        "network": "IT_Mgmt",
                        "netmask": "255.255.255.0",
                    },
                    "mgmt_ip_config": {
                        "type": "static",
                        "ip": "10.10.10.10",
                        "gateway": "10.10.10.1",
                        "netmask": "255.255.255.0",
                    },
                    "oob_ip_config": {
                        "type": "static",
                        "ip": "10.20.20.20",
                        "gateway": "10.20.20.1",
                        "netmask": "255.255.255.0",
                    },
                },
            }
        ],
    )
    check = ConfigurationOverridesCheck()
    findings = check.run(ctx)
    assert all(f.device_id != "wan1" for f in findings)


def test_configuration_overrides_check_flags_unexpected_wan_fields():
    ctx = SiteContext(
        site_id="site-12",
        site_name="WAN Site With Overrides",
        site={},
        setting={},
        templates=[
            {
                "id": "tmpl-1",
                "name": "Standard",
                "switch_config": {
                    "ip_config": {
                        "type": "static",
                        "ip": "10.0.0.2",
                        "gateway": "10.0.0.1",
                        "network": "IT_Mgmt",
                        "netmask": "255.255.255.0",
                    }
                },
            }
        ],
        devices=[
            {
                "id": "wan2",
                "name": "WAN Switch Overrides",
                "role": "wan",
                "status": "connected",
                "map_id": "map-wan2",
                "switch_template_id": "tmpl-1",
                "switch_config": {
                    "ip_config": {
                        "type": "static",
                        "ip": "10.0.0.2",
                        "gateway": "10.0.0.1",
                        "network": "IT_Mgmt",
                        "netmask": "255.255.255.0",
                    },
                    "mgmt_ip_config": {
                        "type": "static",
                        "ip": "10.10.10.10",
                        "gateway": "10.10.10.1",
                        "netmask": "255.255.255.0",
                    },
                    "dhcp_snooping": {"enabled": True},
                },
            }
        ],
    )
    check = ConfigurationOverridesCheck()
    findings = check.run(ctx)
    wan_findings = [f for f in findings if f.device_id == "wan2"]
    assert wan_findings, "WAN device with unexpected fields should be flagged"
    assert any(
        any("dhcp" in (diff.get("path") or "") for diff in (finding.details or {}).get("diffs", []))
        for finding in wan_findings
    )


def test_device_naming_convention_enforces_pattern():
    ctx = SiteContext(
        site_id="site-9",
        site_name="Naming Site",
        site={},
        setting={},
        templates=[],
        devices=[
            {"id": "good1", "name": "NAABCMDFAS1", "type": "switch", "status": "connected"},
            {"id": "spare", "name": "NAABCMDFSPARE", "type": "switch", "status": "connected"},
            {"id": "bad1", "name": "NaABCMDFAS2", "type": "switch", "status": "connected"},
            {"id": "bad2", "name": "NAABCIDFAS3", "type": "switch", "status": "connected"},
            {"id": "ignore1", "name": "ap-1", "type": "ap", "status": "connected"},
            {"id": "offline", "name": "NAABCIDF1CS4", "type": "switch", "status": "offline"},
        ],
    )
    check = DeviceNamingConventionCheck()
    findings = check.run(ctx)
    ids = {f.device_id for f in findings}
    assert ids == {"bad1", "bad2"}
    for finding in findings:
        assert finding.details and "expected_pattern" in finding.details


def test_device_naming_convention_respects_custom_patterns():
    ctx = SiteContext(
        site_id="site-9b",
        site_name="Naming Site Custom",
        site={},
        setting={},
        templates=[],
        devices=[
            {"id": "switch-ok", "name": "SW-1", "type": "switch", "status": "connected"},
            {"id": "switch-bad", "name": "NAABCMDFAS1", "type": "switch", "status": "connected"},
            {"id": "ap-ok", "name": "AP-1", "type": "ap", "status": "connected"},
            {"id": "ap-bad", "name": "bad-ap", "type": "ap", "status": "connected"},
        ],
    )
    check = DeviceNamingConventionCheck(switch_pattern=r"^SW-\d+$", ap_pattern=r"^AP-\d+$")
    findings = check.run(ctx)
    assert {(f.device_id, f.details.get("expected_pattern")) for f in findings} == {
        ("switch-bad", r"^SW-\d+$"),
        ("ap-bad", r"^AP-\d+$"),
    }


def test_device_documentation_reports_missing_items():
    ctx = SiteContext(
        site_id="site-10",
        site_name="Image Site",
        site={},
        setting={},
        templates=[],
        devices=[
            {
                "id": "complete",
                "name": "NAABCMDFAS1",
                "type": "switch",
                "status": "connected",
                "map_id": "map-1",
                "images": ["img1", "img2"],
            },
            {
                "id": "no-images",
                "name": "NAABCMDFAS2",
                "type": "switch",
                "status": "connected",
                "map_id": "map-2",
                "pictures": ["img1"],
            },
            {
                "id": "no-map",
                "name": "NAABCIDF1AS3",
                "type": "switch",
                "status": "offline",
                "images": ["img1", "img2"],
            },
        ],
    )
    check = DeviceDocumentationCheck()
    findings = check.run(ctx)
    assert {(f.device_id, f.message) for f in findings} == {
        ("no-images", "Required images not present (found 1 of 2)."),
        ("no-map", "Device not assigned to any floorplan."),
    }


def test_device_documentation_handles_numbered_urls():
    ctx = SiteContext(
        site_id="site-11",
        site_name="Camera Site",
        site={},
        setting={},
        templates=[],
        devices=[
            {
                "id": "numbered",
                "name": "NAABCMDFAS5",
                "type": "switch",
                "status": "connected",
                "map_id": "map-5",
                "image1_url": "https://example.com/image1.jpg",
                "image2_url": " https://example.com/image2.jpg ",
            },
            {
                "id": "single-numbered",
                "name": "NAABCMDFAS6",
                "type": "switch",
                "status": "connected",
                "map_id": "map-6",
                "image1_url": "https://example.com/only.jpg",
            },
        ],
    )
    check = DeviceDocumentationCheck()
    findings = check.run(ctx)
    assert [f.device_id for f in findings] == ["single-numbered"]


def test_device_documentation_handles_nested_status_dicts():
    ctx = SiteContext(
        site_id="site-12",
        site_name="Nested Status",
        site={},
        setting={},
        templates=[],
        devices=[
            {
                "id": "nested",
                "name": "NAABCMDFAS7",
                "type": "switch",
                "status": {"status": "connected", "uptime": 12345},
                "map_id": "map-7",
            },
            {
                "id": "offline-nested",
                "name": "NAABCMDFAS8",
                "type": "switch",
                "status": {"status": "offline"},
                "map_id": "map-8",
            },
        ],
    )
    check = DeviceDocumentationCheck()
    findings = check.run(ctx)
    assert {(f.device_id, f.message) for f in findings} == {
        ("nested", "Required images not present (found 0 of 2)."),
        ("offline-nested", "Required images not present (found 0 of 2)."),
    }




def test_device_documentation_handles_status_strings_with_suffix():
    ctx = SiteContext(
        site_id="site-13",
        site_name="Status Strings",
        site={},
        setting={},
        templates=[],
        devices=[
            {
                "id": "suffix",
                "name": "NAABCMDFAS9",
                "type": "switch",
                "status": "Connected (wired)",
                "map_id": "map-9",
            },
            {
                "id": "offline-suffix",
                "name": "NAABCMDFAS10",
                "type": "switch",
                "status": "Disconnected",
                "map_id": "map-10",
            },
        ],
    )
    check = DeviceDocumentationCheck()
    findings = check.run(ctx)
    assert {(f.device_id, f.message) for f in findings} == {
        ("suffix", "Required images not present (found 0 of 2)."),
        ("offline-suffix", "Required images not present (found 0 of 2)."),
    }


def test_device_documentation_handles_deeply_nested_status_structures():
    ctx = SiteContext(
        site_id="site-14",
        site_name="Nested Structures",
        site={},
        setting={},
        templates=[],
        devices=[
            {
                "id": "deep-nested",
                "name": "NAABCMDFAS11",
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
                "map_id": "map-11",
            },
        ],
    )
    check = DeviceDocumentationCheck()
    findings = check.run(ctx)
    assert {(f.device_id, f.message) for f in findings} == {
        ("deep-nested", "Required images not present (found 0 of 2)."),
    }


def test_site_audit_runner_summarizes_results():
    contexts = [
        SiteContext(
            site_id="site-5",
            site_name="Site 5",
            site={
                "variables": {
                    "hubradiusserver": "1.1.1.1",
                    "localradiusserver": "2.2.2.2",
                    "siteDNS": "dns.example.com",
                    "hubDNSserver1": "10.0.0.53",
                    "hubDNSserver2": "10.0.0.54",
                }
            },
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
