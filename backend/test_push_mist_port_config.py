import pytest

from push_mist_port_config import evaluate_rule, validate_rules_doc


def test_evaluate_rule_matches_allowed_vlans_list():
    intf = {
        "mode": "trunk",
        "allowed_vlans": [10, 20, 30],
    }

    when = {"mode": "trunk", "allowed_vlans": [30, 20, 10]}

    assert evaluate_rule(when, intf) is True

    mismatch = {"mode": "trunk", "allowed_vlans": [10, 20]}
    assert evaluate_rule(mismatch, intf) is False


def test_evaluate_rule_normalizes_allowed_vlans_string():
    intf = {"allowed_vlans": "10,20"}
    when = {"allowed_vlans": [20, 10]}

    assert evaluate_rule(when, intf) is True


def test_validate_rules_doc_accepts_allowed_vlans_condition():
    doc = {
        "rules": [
            {
                "name": "trunk-with-allowed",
                "when": {"allowed_vlans": [10, 20]},
                "set": {"usage": "ap"},
            }
        ]
    }

    validate_rules_doc(doc)


@pytest.mark.parametrize("value", [None, 42, {"invalid": True}])
def test_validate_rules_doc_rejects_invalid_allowed_vlans(value):
    doc = {
        "rules": [
            {
                "name": "bad",
                "when": {"allowed_vlans": value},
                "set": {"usage": "ap"},
            }
        ]
    }

    with pytest.raises(ValueError):
        validate_rules_doc(doc)
