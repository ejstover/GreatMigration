from pathlib import Path

import conversion_sets as csets


def test_save_and_load_conversion_set_round_trip(monkeypatch, tmp_path):
    monkeypatch.setattr(csets, "DATA_DIR", tmp_path / "conversion_sets")

    summary = csets.save_conversion_set(
        "Campus Core Upgrade",
        {
            "label": "Campus Core Upgrade mapped targets",
            "rows": [
                {
                    "source_file": "switch-a.cfg",
                    "site_id": "site-1",
                    "device_id": "device-1",
                    "member_offset": 0,
                    "port_offset": 0,
                }
            ],
        },
    )

    assert summary["project_key"] == "Campus_Core_Upgrade"
    assert summary["row_count"] == 1

    loaded = csets.load_conversion_set(summary["project_key"], summary["conversion_set_id"])
    assert loaded is not None
    assert loaded["project_name"] == "Campus Core Upgrade"
    assert loaded["project_key"] == "Campus_Core_Upgrade"
    assert loaded["rows"][0]["device_id"] == "device-1"

    index = csets.list_conversion_sets(summary["project_key"])
    assert index["project_key"] == "Campus_Core_Upgrade"
    assert len(index["items"]) == 1
    assert index["items"][0]["conversion_set_id"] == summary["conversion_set_id"]


def test_save_conversion_set_replaces_existing_index_entry(monkeypatch, tmp_path):
    monkeypatch.setattr(csets, "DATA_DIR", tmp_path / "conversion_sets")

    first = csets.save_conversion_set(
        "Project 42",
        {
            "conversion_set_id": "run-1",
            "label": "Initial",
            "rows": [{"site_id": "site-a", "device_id": "device-a"}],
        },
    )
    second = csets.save_conversion_set(
        "Project 42",
        {
            "conversion_set_id": "run-1",
            "label": "Updated",
            "rows": [
                {"site_id": "site-a", "device_id": "device-a"},
                {"site_id": "site-b", "device_id": "device-b"},
            ],
        },
    )

    assert first["conversion_set_id"] == second["conversion_set_id"] == "run-1"

    index = csets.list_conversion_sets("Project 42")
    assert len(index["items"]) == 1
    assert index["items"][0]["label"] == "Updated"
    assert index["items"][0]["row_count"] == 2

    record_path = Path(csets.DATA_DIR) / "Project_42" / "run-1.json"
    assert record_path.exists()


def test_list_conversion_sets_returns_newest_first(monkeypatch, tmp_path):
    monkeypatch.setattr(csets, "DATA_DIR", tmp_path / "conversion_sets")

    csets.save_conversion_set(
        "Project 99",
        {
            "conversion_set_id": "20240101T000000Z",
            "label": "Older",
            "rows": [{"site_id": "site-a", "device_id": "device-a"}],
        },
    )
    csets.save_conversion_set(
        "Project 99",
        {
            "conversion_set_id": "20240201T000000Z",
            "label": "Newer",
            "rows": [{"site_id": "site-b", "device_id": "device-b"}],
        },
    )

    index = csets.list_conversion_sets("Project 99")
    assert [item["conversion_set_id"] for item in index["items"]] == [
        "20240201T000000Z",
        "20240101T000000Z",
    ]
