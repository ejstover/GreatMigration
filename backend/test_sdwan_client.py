import pytest

from sdwan_client import (
    AUTH_MODE_API_KEY,
    AUTH_MODE_AUTO,
    AUTH_MODE_JWT,
    SDWANClient,
    SDWANConfig,
    SDWANConfigError,
    load_sdwan_config_from_env,
)


def test_load_sdwan_config_allows_api_key(monkeypatch):
    monkeypatch.setenv("SDWAN_API_URL", "https://vmanage.example.com")
    monkeypatch.setenv("SDWAN_API_KEY", "abc123")
    monkeypatch.setenv("SDWAN_AUTH_MODE", AUTH_MODE_API_KEY)

    config = load_sdwan_config_from_env()

    assert config.api_url == "https://vmanage.example.com"
    assert config.api_key == "abc123"
    assert config.auth_mode == AUTH_MODE_API_KEY


def test_load_sdwan_config_allows_username_password(monkeypatch):
    monkeypatch.setenv("SDWAN_API_URL", "https://vmanage.example.com/")
    monkeypatch.setenv("SDWAN_USERNAME", "ops-user")
    monkeypatch.setenv("SDWAN_PASSWORD", "super-secret")
    monkeypatch.setenv("SDWAN_AUTH_MODE", AUTH_MODE_JWT)

    config = load_sdwan_config_from_env()

    assert config.api_url == "https://vmanage.example.com"
    assert config.username == "ops-user"
    assert config.password == "super-secret"
    assert config.auth_mode == AUTH_MODE_JWT


def test_load_sdwan_config_auto_mode_requires_credentials(monkeypatch):
    monkeypatch.setenv("SDWAN_API_URL", "https://vmanage.example.com")
    monkeypatch.delenv("SDWAN_API_KEY", raising=False)
    monkeypatch.delenv("SDWAN_USERNAME", raising=False)
    monkeypatch.delenv("SDWAN_PASSWORD", raising=False)
    monkeypatch.setenv("SDWAN_AUTH_MODE", AUTH_MODE_AUTO)

    with pytest.raises(SDWANConfigError):
        load_sdwan_config_from_env()


def test_load_sdwan_config_rejects_invalid_auth_mode(monkeypatch):
    monkeypatch.setenv("SDWAN_API_URL", "https://vmanage.example.com")
    monkeypatch.setenv("SDWAN_API_KEY", "abc123")
    monkeypatch.setenv("SDWAN_AUTH_MODE", "invalid")

    with pytest.raises(SDWANConfigError):
        load_sdwan_config_from_env()


def test_get_data_items_falls_back_after_request_error(monkeypatch):
    client = SDWANClient(
        SDWANConfig(
            api_url="https://vmanage.example.com",
            api_key="abc123",
        )
    )

    attempts = []

    def fake_get(path):
        attempts.append(path)
        if path == "/dataservice/device":
            raise RuntimeError("404")
        return {"data": [{"deviceId": "edge-1"}]}

    monkeypatch.setattr(client, "_get", fake_get)

    payload = client._get_data_items(("/dataservice/device", "/dataservice/device/vedges"))

    assert attempts == ["/dataservice/device", "/dataservice/device/vedges"]
    assert payload == [{"deviceId": "edge-1"}]


def test_get_data_items_raises_when_all_paths_fail(monkeypatch):
    client = SDWANClient(
        SDWANConfig(
            api_url="https://vmanage.example.com",
            api_key="abc123",
        )
    )

    def fake_get(_path):
        raise RuntimeError("boom")

    monkeypatch.setattr(client, "_get", fake_get)

    with pytest.raises(RuntimeError, match="boom"):
        client._get_data_items(("/dataservice/device", "/dataservice/device/vedges"))
