import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

os.environ.setdefault("AUTH_METHOD", "local")

import io
import asyncio
from fastapi import UploadFile

from backend.translate_showtech import build_report, find_copper_10g_ports
from backend.app import api_showtech


def test_find_copper_10g_ports():
    text = (
        "Switch 1\n"
        "TenGigabitEthernet1/1/1 is up, line protocol is up\n"
        "  Hardware is Ten Gigabit Ethernet\n"
        "  Media Type is 10GBaseT\n"
        "Te1/1/2 is up\n"
        "  Media Type is 10GBaseSR\n"
        "Te1/1/3 is up, line protocol is up\n"
        "  Full-duplex, 10Gb/s, media type is 100/1000/2.5G/5G/10GBaseTX\n"

        "Switch 2\n"
        "Te2/1/1 is up, line protocol is up\n"
        "  Hardware is Ten Gigabit Ethernet\n"
        "  media type is 10GBaseT\n"
    )
    ports = find_copper_10g_ports(text)
    assert ports == {
        "Switch 1": ["TenGigabitEthernet1/1/1", "Te1/1/3"],
        "Switch 2": ["Te2/1/1"],
    }


def test_build_report_totals():
    inventory = {"Switch 1": {"PID1": 1}}
    mapping = {"PID1": "JUN-1"}
    copper_ports = {"Switch 1": ["Te1/0/1", "Te1/0/2"], "Switch 2": ["Te2/0/1"]}
    report = build_report(inventory, mapping, copper_ports)
    assert "Additional needed 10Gb copper SFP for EX4650: 3" in report


def test_api_showtech_copper_ports():
    text = (
        "Switch 1\n"
        "TenGigabitEthernet1/1/1 is up, line protocol is up\n"
        "  Hardware is Ten Gigabit Ethernet\n"
        "  Media Type is 10GBaseT\n"
        "Te1/1/2 is up\n"
        "  Media Type is 10GBaseSR\n"
        "Te1/1/3 is up, line protocol is up\n"
        "  Full-duplex, 10Gb/s, media type is 100/1000/2.5G/5G/10GBaseTX\n"
        "Switch 2\n"
        "Te2/1/1 is up, line protocol is up\n"
        "  Hardware is Ten Gigabit Ethernet\n"
        "  media type is 10GBaseT\n"
    )
    upload = UploadFile(filename="test.txt", file=io.BytesIO(text.encode()))
    data = asyncio.run(api_showtech([upload]))
    assert data["ok"]
    assert data["results"][0]["copper_10g_ports"]["total"] == 3
