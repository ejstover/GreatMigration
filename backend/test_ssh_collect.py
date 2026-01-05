import pytest

from ssh_collect import _describe_exception
from ssh_collect import DeviceResult, JobState


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


def test_job_to_dict_prefers_available_show_vlan_text():
    job = JobState(id="job1", created=0.0)
    # include only brief output to ensure fallback works
    result = DeviceResult(
        host="switch1",
        label="switch1",
        status="ok",
        command_outputs={"show vlan brief": "VLAN Name\n1 default"},
    )
    job.results.append(result)

    data = job.to_dict()
    assert data["results"][0]["show_vlan_text"] == "VLAN Name\n1 default"
