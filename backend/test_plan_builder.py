import json
from pathlib import Path

import pytest

from plan_builder import (
    PlannerError,
    build_plan_documents,
    generate_plan,
)


@pytest.fixture()
def sample_converter() -> dict:
    return {
        "meta": {"derived_vc_members": 1},
        "interfaces": [
            {
                "name": "GigabitEthernet1/0/1",
                "juniper_if": "ge-0/0/0",
                "mode": "access",
                "description": "Desk port",
                "data_vlan": 10,
                "voice_vlan": 15,
                "native_vlan": None,
                "allowed_vlans": [],
                "uplink": False,
            },
            {
                "name": "GigabitEthernet1/1/1",
                "juniper_if": "xe-0/2/0",
                "mode": "trunk",
                "description": "Uplink",
                "data_vlan": None,
                "voice_vlan": None,
                "native_vlan": 100,
                "allowed_vlans": [10, 15, 20],
                "uplink": True,
            },
        ],
    }


@pytest.fixture()
def sample_data_mapping() -> dict:
    return {
        "defaults": {
            "temp_profile": "TEMP-DATA-DEFAULT",
            "final_profile": "Access - Default",
            "final_vlan": None,
        },
        "management": {
            "temp_profile": "TEMP-UPLINK",
            "final_profile": "Uplink - Distribution",
            "final_vlan": None,
        },
        "vlans": {
            "10": {
                "temp_profile": "TEMP-DATA-10",
                "final_profile": "Access - Corp Wired",
                "final_vlan": 210,
            }
        },
    }


@pytest.fixture()
def sample_voice_mapping() -> dict:
    return {
        "defaults": {"final_vlan": None},
        "vlans": {"15": {"final_vlan": 315}},
    }


def test_build_plan_documents_happy_path(sample_converter, sample_data_mapping, sample_voice_mapping):
    plan_doc, final_doc, errors = build_plan_documents(
        sample_converter,
        sample_data_mapping,
        sample_voice_mapping,
        available_profiles={"Access - Corp Wired", "Uplink - Distribution"},
    )

    assert not errors
    assert plan_doc["temp_vlans"] == [10, 15, 20, 100]
    assert "temporary_profile" in plan_doc["ports"][0]
    assert final_doc["ports"][0]["final_profile"] == "Access - Corp Wired"
    assert final_doc["ports"][0]["final_vlan"] == 210
    assert final_doc["ports"][0]["final_voice_vlan"] == 315
    assert final_doc["ports"][1]["final_profile"] == "Uplink - Distribution"


def test_build_plan_documents_flags_missing_mappings(sample_converter, sample_data_mapping, sample_voice_mapping):
    sample_converter["interfaces"][0]["data_vlan"] = 99
    plan_doc, final_doc, errors = build_plan_documents(
        sample_converter,
        sample_data_mapping,
        sample_voice_mapping,
        available_profiles={"Access - Corp Wired", "Uplink - Distribution"},
    )
    assert errors
    assert any("VLAN 99" in err for err in errors)
    assert plan_doc["ports"][0]["issues"], "Expected issues recorded on port"
    assert final_doc["ports"][0]["issues"], "Expected issues recorded on port"


def test_generate_plan_writes_artifacts(tmp_path: Path, sample_data_mapping, sample_voice_mapping):
    converter = {
        "meta": {},
        "interfaces": [
            {
                "name": "GigabitEthernet1/0/1",
                "juniper_if": "ge-0/0/0",
                "mode": "access",
                "description": "Desk port",
                "data_vlan": 10,
                "voice_vlan": 15,
                "native_vlan": None,
                "allowed_vlans": [],
                "uplink": False,
            }
        ],
    }
    converter_path = tmp_path / "switch_converted.json"
    converter_path.write_text(json.dumps(converter), encoding="utf-8")

    data_path = tmp_path / "data.json"
    data_path.write_text(json.dumps(sample_data_mapping), encoding="utf-8")
    voice_path = tmp_path / "voice.json"
    voice_path.write_text(json.dumps(sample_voice_mapping), encoding="utf-8")

    result = generate_plan(
        converter_path,
        data_mapping_path=data_path,
        voice_mapping_path=voice_path,
        output_dir=tmp_path,
        available_profiles=["Access - Corp Wired"],
        persist_dir=tmp_path / "persist",
    )

    assert result.plan_path.exists()
    assert result.final_path.exists()
    assert (tmp_path / "persist" / "switch" / result.plan_path.name).exists()
    assert result.plan_doc["ports"], "Expected plan document to include ports"
    assert not result.errors


def test_generate_plan_missing_converter(tmp_path: Path):
    with pytest.raises(PlannerError):
        generate_plan(tmp_path / "missing.json", available_profiles=["profile"])  # type: ignore[arg-type]
