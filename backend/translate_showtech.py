#!/usr/bin/env python3
"""Translate Cisco show tech-support inventory to Juniper replacements.

This utility parses the output of a Cisco ``show tech-support`` command, collects
all product identifiers (PIDs) reported in the ``show inventory`` section and
generates a summary per switch member.  Each Cisco PID is looked up in a simple
mapping table to determine the recommended Juniper replacement hardware.  It
also scans the broader diagnostic output for TenGigabit Ethernet ports that are
using copper media (``10GBaseT``).  These copper 10G connections will require
SFP modules when migrating to an SFP-based core, so they are reported as
exceptions.

The mapping data is loaded from ``backend/device_map.json`` if present.  The
repository ships with ``device_map.sample.json`` which provides a starting set
of common mappings.  Administrators can copy this sample to
``device_map.json`` and extend it with their own hardware rules without
committing sensitive or organization specific information back to the
repository.  Any rules defined in ``replacement_rules.json`` (such as those
managed through the web UI) are layered on top of this base mapping.

Example:

    python translate_showtech.py /path/to/showtech.txt

The script prints a report showing the Cisco inventory discovered for each
switch and the Juniper models suggested for migration.
"""

from __future__ import annotations

import argparse
import json
import re
from collections import defaultdict
from pathlib import Path
from typing import Dict, DefaultDict, List


def load_mapping() -> Dict[str, str]:
    """Load the Cisco PID -> Juniper model mapping.

    ``device_map.json`` provides the baseline mapping.  If present,
    ``replacement_rules.json`` (or its sample file) is merged on top so that
    locally defined replacement rules override the defaults.
    """

    base = Path(__file__).resolve().parent

    # Start with the built-in device map (local file wins over sample).
    local_map = base / "device_map.json"
    sample_map = base / "device_map.sample.json"
    path = local_map if local_map.exists() else sample_map
    with path.open() as fh:
        mapping: Dict[str, str] = json.load(fh)

    # Overlay any replacement rules so they take precedence.
    repl_local = base / "replacement_rules.json"
    repl_sample = base / "replacement_rules.sample.json"
    repl_path = repl_local if repl_local.exists() else repl_sample
    if repl_path.exists():
        try:
            data = json.loads(repl_path.read_text(encoding="utf-8"))
            for rule in data.get("rules", []):
                cisco = rule.get("cisco")
                juniper = rule.get("juniper")
                if cisco and juniper:
                    mapping[cisco] = juniper
        except Exception:
            pass

    return mapping


def parse_showtech(text: str) -> Dict[str, Dict[str, int]]:
    """Parse ``show tech-support`` text and count PIDs per switch.

    Only the ``show inventory`` section is inspected.  Other parts of the
    diagnostic output may contain ``PID`` strings that are unrelated to the
    hardware inventory so they are intentionally ignored.
    """

    inventory: DefaultDict[str, DefaultDict[str, int]] = defaultdict(
        lambda: defaultdict(int)
    )
    current_switch: str | None = None
    in_inventory = False

    for line in text.splitlines():
        line = line.strip()

        # Track whether we are inside the ``show inventory`` section.  The
        # section boundaries in a ``show tech-support`` file are usually marked
        # with lines such as ``------------------ show inventory ------------------``.
        if re.match(r"-+\s*show inventory\s*-+", line, re.IGNORECASE):
            in_inventory = True
            current_switch = None
            continue
        if in_inventory and re.match(r"-+\s*show ", line, re.IGNORECASE):
            # Encountered the next ``show`` section; stop recording PIDs.
            in_inventory = False
            continue
        if not in_inventory:
            continue

        # Detect a new switch section (e.g. "Switch 1" or NAME: "1")
        m_switch = re.match(r"^Switch\s+(\d+)", line, re.IGNORECASE)
        if not m_switch:
            m_switch = re.match(r"NAME:\s*\"(?:Switch\s*)?(\d+)\"", line, re.IGNORECASE)
        if m_switch:
            current_switch = f"Switch {m_switch.group(1)}"
            continue

        m_pid = re.search(r"PID:\s*([^,\s]+)", line, re.IGNORECASE)
        if m_pid and current_switch:
            pid = m_pid.group(1)
            inventory[current_switch][pid] += 1

    return inventory


def find_copper_10g_ports(text: str) -> Dict[str, List[str]]:
    """Return TenGigabit interfaces that report ``10GBaseT``/``10GBaseTX`` media.

    The ``show inventory`` section does not list built-in copper links, so we
    scan the broader ``show tech`` output for interface blocks that mention
    copper 10G media types such as ``10GBaseT`` or ``10GBaseTX``.  The result is
    a mapping of switch identifier to interface names using copper media,
    indicating where an SFP will be required during migration.
    """

    ports: DefaultDict[str, List[str]] = defaultdict(list)
    current_switch = "global"
    current_intf: str | None = None
    current_intf_switch: str | None = None

    for line in text.splitlines():
        line = line.strip()

        m_switch = re.match(r"^Switch\s+(\d+)", line, re.IGNORECASE)
        if not m_switch:
            m_switch = re.match(r"NAME:\s*\"(?:Switch\s*)?(\d+)\"", line, re.IGNORECASE)
        if m_switch:
            current_switch = f"Switch {m_switch.group(1)}"
            continue

        m_intf = re.match(r"^(?:Interface\s*)?(?P<intf>(?:Te|TenGigabitEthernet)[\d/]+)", line)
        if m_intf:
            current_intf = m_intf.group("intf")
            # Determine switch number from the interface name if present
            m_intf_sw = re.match(r"(?:Te|TenGigabitEthernet)(\d+)/", current_intf)
            if m_intf_sw:
                current_intf_switch = f"Switch {m_intf_sw.group(1)}"
            else:
                current_intf_switch = current_switch
            continue

        if current_intf and re.search(r"10GBase[-]?T(?:X)?", line, re.IGNORECASE):
            switch = current_intf_switch or current_switch
            ports[switch].append(current_intf)
            current_intf = None
            current_intf_switch = None

    return ports


def build_report(
    inventory: Dict[str, Dict[str, int]],
    mapping: Dict[str, str],
    copper_ports: Dict[str, List[str]],
) -> str:
    """Generate a human friendly report."""

    lines = []
    for switch, items in inventory.items():
        if switch.lower() == "global":
            continue
        lines.append(f"{switch}:")
        lines.append("  Cisco inventory:")
        for pid, count in sorted(items.items()):
            lines.append(f"    {pid} x{count}")
        lines.append("  Recommended Juniper replacements:")
        for pid, count in sorted(items.items()):
            replacement = mapping.get(pid, "UNKNOWN")
            lines.append(f"    {replacement} x{count}")
        if copper_ports.get(switch):
            lines.append("  Copper 10G ports requiring SFPs:")
            for port in sorted(copper_ports[switch]):
                lines.append(f"    {port}")
        lines.append("")
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Translate Cisco show tech-support inventory to Juniper models"
    )
    parser.add_argument("file", help="Path to show tech-support text file")
    args = parser.parse_args()

    with open(args.file, encoding="utf-8", errors="ignore") as fh:
        text = fh.read()

    mapping = load_mapping()
    inventory = parse_showtech(text)
    copper_ports = find_copper_10g_ports(text)
    report = build_report(inventory, mapping, copper_ports)
    print(report)


if __name__ == "__main__":  # pragma: no cover - CLI entry point
    main()

