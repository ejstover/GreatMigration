import pytest

from sdwan_client import (
    AUTH_MODE_API_KEY,
    AUTH_MODE_AUTO,
    AUTH_MODE_JWT,
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
