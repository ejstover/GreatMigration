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


def test_parse_showtech_counts_sfps_without_interface_status():
    text = (
        "------------------ show inventory ------------------\n"
        'NAME: "c93xx Stack", DESCR: "c93xx Stack"\n'
        'PID: C9300-48UXM       , VID: V03  , SN: FJB2413A0NK\n'
        'NAME: "Switch 1", DESCR: "C9300-48UXM"\n'
        'PID: C9300-48UXM       , VID: V03  , SN: FJB2413A0NK\n'
        'NAME: "StackPort1/1", DESCR: "StackPort1/1"\n'
        'PID: STACK-T1-50CM     , VID: V01  , SN: LCC2403GJW6\n'
        'NAME: "StackPort1/2", DESCR: "StackPort1/2"\n'
        'PID: STACK-T1-50CM     , VID: V01  , SN: LCC2403GJW9\n'
        'NAME: "Switch 1 - Power Supply A", DESCR: "Switch 1 - Power Supply A"\n'
        'PID: PWR-C1-1100WAC-P  , VID: V01  , SN: DCC2411D7RG\n'
        'NAME: "Switch 1 - Power Supply B", DESCR: "Switch 1 - Power Supply B"\n'
        'PID: PWR-C1-1100WAC-P  , VID: V01  , SN: DCC2350D1AA\n'
        'NAME: "Switch 1 FRU Uplink Module 1", DESCR: "8x10G Uplink Module"\n'
        'PID: C9300-NM-8X       , VID: V03  , SN: FJZ24091JCQ\n'
        'NAME: "Te1/1/1", DESCR: "1000BaseSX SFP"\n'
        'PID: GLC-SX-MMD          , VID: V02  , SN: OPM2350103E\n'
        'NAME: "Te1/1/2", DESCR: "1000BaseSX SFP"\n'
        'PID: GLC-SX-MMD          , VID: V02  , SN: OPM2350103F\n'
        'NAME: "Te1/1/3", DESCR: "1000BaseSX SFP"\n'
        'PID: GLC-SX-MMD          , VID: V02  , SN: OPM23501032\n'
        'NAME: "Te1/1/4", DESCR: "1000BaseSX SFP"\n'
        'PID:                     , VID:      , SN: FNS163010RN\n'
        'NAME: "Te1/1/5", DESCR: "SFP-10GBase-CX1"\n'
        'PID: SFP-H10GB-CU5M      , VID: V03  , SN: APF2831061C\n'
        'NAME: "Te1/1/6", DESCR: "SFP-10GBase-CX1"\n'
        'PID: SFP-H10GB-CU5M      , VID: V03  , SN: APF283105V6\n'
        'NAME: "Te1/1/7", DESCR: "SFP-10GBase-CX1"\n'
        'PID: SFP-H10GB-CU3M      , VID: V03  , SN: TED2548B0SW\n'
        'NAME: "Te1/1/8", DESCR: "SFP-10GBase-CX1"\n'
        'PID: SFP-H10GB-CU3M      , VID: V03  , SN: TED2546B1SK\n'
        'NAME: "Switch 2", DESCR: "C9300-48UXM"\n'
        'PID: C9300-48UXM       , VID: V03  , SN: FJC2413T0QR\n'
        'NAME: "StackPort2/1", DESCR: "StackPort2/1"\n'
        'PID: STACK-T1-50CM     , VID: V01  , SN: LCC2403GJW6\n'
        'NAME: "StackPort2/2", DESCR: "StackPort2/2"\n'
        'PID: STACK-T1-50CM     , VID: V01  , SN: LCC2403GJW9\n'
        'NAME: "Switch 2 - Power Supply A", DESCR: "Switch 2 - Power Supply A"\n'
        'PID: PWR-C1-1100WAC-P  , VID: V01  , SN: DCC2411D7R3\n'
        'NAME: "Switch 2 - Power Supply B", DESCR: "Switch 2 - Power Supply B"\n'
        'PID: PWR-C1-1100WAC-P  , VID: V01  , SN: DCC2350D19S\n'
        'NAME: "Switch 2 FRU Uplink Module 1", DESCR: "8x10G Uplink Module"\n'
        'PID: C9300-NM-8X       , VID: V03  , SN: FJZ24091LL2\n'
        'NAME: "Te2/1/1", DESCR: "1000BaseSX SFP"\n'
        'PID: GLC-SX-MMD          , VID: V02  , SN: FNS24020AFG\n'
        'NAME: "Te2/1/2", DESCR: "1000BaseSX SFP"\n'
        'PID:                     , VID:      , SN: FNS163012BF\n'
        'NAME: "Te2/1/3", DESCR: "10/100/1000BaseTX SFP"\n'
        'PID: GLC-T               , VID:      , SN: 00000MTC134005SU\n'
        'NAME: "Te2/1/4", DESCR: "1000BaseSX SFP"\n'
        'PID:                     , VID:      , SN: FNS163010SC\n'
        'NAME: "Te2/1/5", DESCR: "SFP-10GBase-CX1"\n'
        'PID: SFP-H10GB-CU5M      , VID: V03  , SN: APF283105VJ\n'
        'NAME: "Te2/1/6", DESCR: "SFP-10GBase-CX1"\n'
        'PID: SFP-H10GB-CU5M      , VID: V03  , SN: APF283105TV\n'
        'NAME: "Te2/1/7", DESCR: "SFP-10GBase-CX1"\n'
        'PID: SFP-H10GB-CU3M      , VID: V03  , SN: TED2546B0DZ\n'
        'NAME: "Te2/1/8", DESCR: "SFP-10GBase-CX1"\n'
        'PID: SFP-H10GB-CU3M      , VID: V03  , SN: TED2546B0FK\n'
    )
    inventory = parse_showtech(text)
    assert inventory == {
        "Switch 1": {
            "C9300-48UXM": 1,
            "STACK-T1-50CM": 2,
            "PWR-C1-1100WAC-P": 2,
            "C9300-NM-8X": 1,
            "GLC-SX-MMD": 3,
            "SFP-H10GB-CU5M": 2,
            "SFP-H10GB-CU3M": 2,
        },
        "Switch 2": {
            "C9300-48UXM": 1,
            "STACK-T1-50CM": 2,
            "PWR-C1-1100WAC-P": 2,
            "C9300-NM-8X": 1,
            "GLC-SX-MMD": 1,
            "GLC-T": 1,
            "SFP-H10GB-CU5M": 2,
            "SFP-H10GB-CU3M": 2,
        },
    }
