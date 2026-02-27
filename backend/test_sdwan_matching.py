from app import _extract_sdwan_site_id, _find_sdwan_site_id_in_variables
from sdwan_client import SDWANClient, SDWANConfig


def test_extract_sdwan_site_id_accepts_integer_like_decimal():
    assert _extract_sdwan_site_id("101") == "101"
    assert _extract_sdwan_site_id("101.0") == "101"
    assert _extract_sdwan_site_id("101.5") == ""


def test_find_sdwan_site_id_is_case_insensitive_on_key_name():
    assert _find_sdwan_site_id_in_variables({"SDWAN_site_id": "900"}) == "900"
    assert _find_sdwan_site_id_in_variables({"sdwan-site-id": "901.0"}) == "901"
    assert _find_sdwan_site_id_in_variables({"SdWaN_SiTe_Id": "abc"}) == ""


def test_sdwan_client_site_id_normalization():
    cfg = SDWANConfig(api_url="https://vmanage.example", api_key="token")
    client = SDWANClient(cfg)
    assert client._normalize_site_id("100") == "100"
    assert client._normalize_site_id("100.0") == "100"
    assert client._normalize_site_id("site-100") == ""
