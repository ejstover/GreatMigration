from sdwan_audit import (
    check_lan_prefix_29,
    check_mist_sdwan_site_id_value,
    check_name_suffix,
    check_router_id_matches_system_ip,
    check_system_ip_matches_gi0_1,
    check_vrrp_priority,
    filter_mist_sites_by_sdwan_intersection,
)


def test_name_suffix_validation_rejects_words_accepts_numeric():
    assert check_name_suffix({"device_name": "BR01 C EDGE one"})["pass"] is False
    assert check_name_suffix({"device_name": "BR01 C EDGE 2"})["pass"] is True


def test_cidr_29_validation():
    assert check_lan_prefix_29({"lan_ipv4_prefix": "10.10.10.0/29"})["pass"] is True
    assert check_lan_prefix_29({"lan_ipv4_prefix": "10.10.10.0/28"})["pass"] is False


def test_vrrp_priority_mapping_logic():
    assert check_vrrp_priority({"device_name": "X C EDGE 1", "vrrp_priority": 110})["pass"] is True
    assert check_vrrp_priority({"device_name": "X C EDGE 2", "vrrp_priority": 110})["pass"] is False


def test_router_id_equals_system_ip_logic():
    assert check_router_id_matches_system_ip({"router_id": "1.1.1.1", "system_ip": "1.1.1.1"})["pass"] is True
    assert check_router_id_matches_system_ip({"router_id": "1.1.1.1", "system_ip": "1.1.1.2"})["pass"] is False


def test_system_ip_equals_gi0_1_ip_logic():
    assert check_system_ip_matches_gi0_1({"system_ip": "2.2.2.2", "gi0_1_ip": "2.2.2.2"})["pass"] is True
    assert check_system_ip_matches_gi0_1({"system_ip": "2.2.2.2", "gi0_1_ip": "2.2.2.3"})["pass"] is False


def test_mist_variable_existence_and_numeric_check():
    assert check_mist_sdwan_site_id_value("100")["pass"] is True
    assert check_mist_sdwan_site_id_value("site-100")["pass"] is False
    assert check_mist_sdwan_site_id_value("")["pass"] is False


def test_site_picker_intersection_logic():
    mist_sites = [
        {"id": "a", "name": "A"},
        {"id": "b", "name": "B"},
        {"id": "c", "name": "C"},
    ]
    mist_sdwan_ids = {"a": "100", "b": "200"}
    included, excluded = filter_mist_sites_by_sdwan_intersection(mist_sites, mist_sdwan_ids, ["100"])

    assert [site["id"] for site in included] == ["a"]
    assert sorted(site["id"] for site in excluded) == ["b", "c"]
