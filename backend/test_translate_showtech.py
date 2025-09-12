import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from backend.translate_showtech import find_copper_10g_ports


def test_find_copper_10g_ports():
    text = (
        "Switch 1\n"
        "TenGigabitEthernet1/1/1 is up, line protocol is up\n"
        "  Hardware is Ten Gigabit Ethernet\n"
        "  Media Type is 10GBaseT\n"
        "Te1/1/2 is up\n"
        "  Media Type is 10GBaseSR\n"
        "Switch 2\n"
        "Te2/1/1 is up, line protocol is up\n"
        "  Hardware is Ten Gigabit Ethernet\n"
        "  media type is 10GBaseT\n"
    )
    ports = find_copper_10g_ports(text)
    assert ports == {
        "Switch 1": ["TenGigabitEthernet1/1/1"],
        "Switch 2": ["Te2/1/1"],
    }
