import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

os.environ.setdefault("AUTH_METHOD", "local")

import io
import asyncio
from fastapi import UploadFile

from backend.translate_showtech import build_report, find_copper_10g_ports, parse_showtech
from backend.app import api_showtech


def test_find_copper_10g_ports():
    text = (
        "Switch 1\n"
        "TenGigabitEthernet1/1/1 is up, line protocol is up\n"
        "  Full-duplex, 10Gb/s\n"
        "  Media Type is 10GBaseT\n"
        "Te1/1/2 is up\n"
        "  Media Type is 10GBaseSR\n"
        "Te1/1/3 is up, line protocol is up\n"
        "  Full-duplex, 10Gb/s, media type is 100/1000/2.5G/5G/10GBaseTX\n"
        "Te1/1/4 is up, line protocol is up\n"
        "  Full-duplex, 1000Mb/s, media type is 100/1000/2.5G/5G/10GBaseTX\n"
        "Te1/1/5 is down, line protocol is down\n"
        "  Full-duplex, 10Gb/s\n"
        "  Media Type is 10GBaseT\n"
        "Te1/1/1 connected trunk a-full a-10G 10GBaseT\n"
        "Switch 2\n"
        "Te2/1/1 is up, line protocol is up\n"
        "  Full-duplex, 10Gb/s\n"
        "  media type is 10GBaseT\n"
    )
    ports = find_copper_10g_ports(text)
    assert ports == {
        "Switch 1": ["Te1/1/3", "TenGigabitEthernet1/1/1"],
        "Switch 2": ["Te2/1/1"],
    }
    assert "Te1/1/5" not in ports.get("Switch 1", [])


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
        "  Full-duplex, 10Gb/s\n"
        "  Media Type is 10GBaseT\n"
        "Te1/1/2 is up\n"
        "  Media Type is 10GBaseSR\n"
        "Te1/1/3 is up, line protocol is up\n"
        "  Full-duplex, 10Gb/s, media type is 100/1000/2.5G/5G/10GBaseTX\n"
        "Te1/1/4 is up, line protocol is up\n"
        "  Full-duplex, 1000Mb/s, media type is 100/1000/2.5G/5G/10GBaseTX\n"
        "Te1/1/5 is down, line protocol is down\n"
        "  Full-duplex, 10Gb/s\n"
        "  Media Type is 10GBaseT\n"
        "Te1/1/1 connected trunk a-full a-10G 10GBaseT\n"
        "Switch 2\n"
        "Te2/1/1 is up, line protocol is up\n"
        "  Full-duplex, 10Gb/s\n"
        "  media type is 10GBaseT\n"
    )
    upload = UploadFile(filename="test.txt", file=io.BytesIO(text.encode()))
    data = asyncio.run(api_showtech([upload]))
    assert data["ok"]
    assert data["results"][0]["copper_10g_ports"]["total"] == 3
    assert "Te1/1/5" not in data["results"][0]["copper_10g_ports"]["Switch 1"]


def test_parse_showtech_handles_switch_prefixed_interfaces():
    text = (
        "TenGigabitEthernet1/1/1 is up, line protocol is up\n"
        "TenGigabitEthernet2/1/1 is up, line protocol is up\n"
        "TenGigabitEthernet2/1/2 is up, line protocol is up\n"
        "------------------ show inventory ------------------\n"
        'NAME: "Switch 1"\n'
        'DESCR: "Switch 1"\n'
        'PID: WS-C3850-24XS-S\n'
        'NAME: "Switch 1 - TenGigabitEthernet1/1/1"\n'
        'DESCR: "10GBase-SR"\n'
        'PID: SFP-10G-SR\n'
        'NAME: "Switch 2 - TenGigabitEthernet2/1/1"\n'
        'DESCR: "10GBase-SR"\n'
        'PID: SFP-10G-SR\n'
        'NAME: "TenGigabitEthernet2/1/2"\n'
        'DESCR: "10GBase-LR"\n'
        'PID: SFP-10G-LR\n'
    )
    inventory = parse_showtech(text)
    assert inventory == {
        "Switch 1": {"WS-C3850-24XS-S": 1, "SFP-10G-SR": 1},
        "Switch 2": {"SFP-10G-SR": 1, "SFP-10G-LR": 1},
    }
