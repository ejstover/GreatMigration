import pytest

from ssh_collect import _describe_exception


@pytest.mark.parametrize(
    "exc,message,expected_code",
    [
        (Exception("Authentication failed for device"), "Authentication", "auth_failure"),
        (Exception("Device timed out during SSH connect"), "timeout", "timeout"),
        (Exception("switch1: Name or service not known"), "hostname", "dns_lookup_failed"),
    ],
)
def test_describe_exception_classification(exc, message, expected_code):
    info = _describe_exception(exc)
    assert info["code"] == expected_code
    assert info["detail"].startswith(str(exc))
    assert message.lower() in info["reason"].lower() or message.lower() in info["suggestion"].lower()


def test_describe_exception_fallback_message():
    exc = Exception("")
    info = _describe_exception(exc)
    assert info["code"] == "unknown"
    # Should fall back to class name when message is empty
    assert info["detail"] == exc.__class__.__name__
    assert "SSH" in info["reason"]
