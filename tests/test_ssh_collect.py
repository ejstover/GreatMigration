import pytest

from ssh_collect import _build_running_config_filename, _describe_exception
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


def test_job_to_dict_prefers_brief_when_full_command_is_cli_error():
    job = JobState(id="job2", created=0.0)
    result = DeviceResult(
        host="switch2",
        label="switch2",
        status="ok",
        command_outputs={
            "show vlan": "% Invalid input detected at '^' marker.",
            "show vlan brief": "VLAN Name\n1 default\n10 users",
        },
    )
    job.results.append(result)

    data = job.to_dict()
    assert data["results"][0]["show_vlan_text"] == "VLAN Name\n1 default\n10 users"


@pytest.mark.parametrize(
    "host,label,outputs,expected",
    [
        (
            "10.0.0.1",
            "Switch A",
            {"show running-config": "hostname core-switch\ninterface Gi1/0"},
            "core-switch-10.0.0.1-Switch_A.running-config.txt",
        ),
        (
            "192.168.1.2",
            "",
            {"show running-config": " hostname   Edge01 "},
            "Edge01-192.168.1.2.running-config.txt",
        ),
        (
            "10.0.0.3",
            "datacenter-1",
            {"show running-config": "! no hostname present"},
            "10.0.0.3-datacenter-1.running-config.txt",
        ),
    ],
)
def test_build_running_config_filename(host, label, outputs, expected):
    assert _build_running_config_filename(host, label, outputs) == expected
