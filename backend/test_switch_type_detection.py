import app


def test_determine_switch_type_returns_core_when_name_and_pid_match(monkeypatch):
    monkeypatch.setenv("CORE_SWITCH_MODELS", "C9300-48UXM,C9500-24Y4C")
    running_config = "!\nhostname NASPRMDFCS1\n!"
    inventory = (
        'NAME: "Switch 1", DESCR: "C9300-48UXM"\n'
        "PID: C9300-48UXM       , VID: V03  , SN: FOC2528L96L\n"
    )

    assert app.determine_switch_type(running_config, inventory) == "core"


def test_determine_switch_type_returns_access_when_hostname_does_not_match(monkeypatch):
    monkeypatch.setenv("CORE_SWITCH_MODELS", "C9300-48UXM")
    running_config = "hostname NASPRIDFAS1"
    inventory = (
        'NAME: "Switch 1", DESCR: "C9300-48UXM"\n'
        "PID: C9300-48UXM       , VID: V03  , SN: FOC2528L96L\n"
    )

    assert app.determine_switch_type(running_config, inventory) == "access"


def test_determine_switch_type_returns_access_when_switch_one_pid_not_in_env(monkeypatch):
    monkeypatch.setenv("CORE_SWITCH_MODELS", "C9500-24Y4C")
    running_config = "hostname NASPRMDFCS1"
    inventory = (
        'NAME: "Switch 1", DESCR: "C9300-48UXM"\n'
        "PID: C9300-48UXM       , VID: V03  , SN: FOC2528L96L\n"
    )

    assert app.determine_switch_type(running_config, inventory) == "access"
