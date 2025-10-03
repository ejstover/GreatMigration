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
    hardware inventory so they are intentionally ignored.  To avoid reporting
    optics that are present in ``show inventory`` but not actually in service,
    the routine cross-references interface states from ``show interface`` and
    skips any pluggables found on ports that are down.
    """

    # Record interfaces that are operationally up/down so that optics on
    # administratively disabled ports can be ignored.  The ``show
    # tech-support`` dump is not guaranteed to include interface state for
    # every port, so interfaces default to "unknown" and are only skipped when
    # we positively identify them as down.
    intf_state: dict[str, bool] = {}
    current_state_intf: str | None = None
    intf_status_re = re.compile(
        r"^(?:Interface\s*)?(?P<intf>(?:Te|TenGigabitEthernet)[\d/]+)\s+is\s+(?P<state>administratively down|down|up)",
        re.IGNORECASE,
    )
    for raw_line in text.splitlines():
        line = raw_line.strip()
        m_status = intf_status_re.match(line)
        if m_status:
            current_state_intf = m_status.group("intf")
            state = m_status.group("state").lower()
            is_up = state == "up"
            if "line protocol is down" in line.lower():
                is_up = False
            elif "line protocol is up" in line.lower():
                is_up = True
            intf_state[current_state_intf] = is_up
            continue

        if current_state_intf:
            lowered = line.lower()
            if "line protocol is down" in lowered:
                intf_state[current_state_intf] = False
            elif "line protocol is up" in lowered:
                intf_state[current_state_intf] = True

        # Reset the context once we leave the indented block that describes a
        # particular interface.  These detail lines are typically indented with
        # spaces; encountering a non-indented line means the next match should
        # stand on its own.
        if raw_line and not raw_line.startswith(" "):
            current_state_intf = None

    inventory: DefaultDict[str, DefaultDict[str, int]] = defaultdict(
        lambda: defaultdict(int)
    )
    current_switch: str | None = None
    current_intf: str | None = None
    current_intf_switch: str | None = None
    in_inventory = False

    for line in text.splitlines():
        line = line.strip()

        # Track whether we are inside the ``show inventory`` section.  The
        # section boundaries in a ``show tech-support`` file are usually marked
        # with lines such as ``------------------ show inventory ------------------``.
        if re.match(r"-+\s*show inventory\s*-+", line, re.IGNORECASE):
            in_inventory = True
            current_switch = None
            current_intf = None
            current_intf_switch = None
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
            m_switch = re.match(
                r"NAME:\s*\"Switch\s*(\d+)\b",
                line,
                re.IGNORECASE,
            )
        if m_switch:
            current_switch = f"Switch {m_switch.group(1)}"
            current_intf = None
            current_intf_switch = None
            continue

        # Track individual interface names from NAME lines so we can skip
        # their PIDs if the interface is down and so we can derive the switch
        # number when explicit switch headers are missing.
        m_name = re.match(
            r'NAME:\s*"(?:Switch\s*(\d+)\s*-\s*)?((?:Te|TenGigabitEthernet)[\d/]+)"',
            line,
            re.IGNORECASE,
        )
        if m_name:
            current_intf = m_name.group(2)
            switch_hint = m_name.group(1)
            if switch_hint:
                current_intf_switch = f"Switch {switch_hint}"
                current_switch = current_switch or current_intf_switch
            else:
                m_intf_sw = re.match(r"(?:Te|TenGigabitEthernet)(\d+)/", current_intf)
                if m_intf_sw:
                    current_intf_switch = f"Switch {m_intf_sw.group(1)}"
                else:
                    current_intf_switch = current_switch
            continue
        elif line.startswith("NAME:"):
            current_intf = None
            current_intf_switch = None

        m_pid = re.search(r"PID:\s*([^,\s]+)", line, re.IGNORECASE)
        if m_pid:
            pid = m_pid.group(1)
            switch = current_intf_switch or current_switch
            # If this PID corresponds to an interface that is not up, skip it.
            if current_intf:
                state = intf_state.get(current_intf)
                if state is False:
                    continue
            if switch:
                inventory[switch][pid] += 1

    return inventory


def find_copper_10g_ports(text: str) -> Dict[str, List[str]]:
    """Return 10G copper interfaces from ``show interface status`` output.

    Copper 10G links do not appear in the ``show inventory`` section, so this
    routine scans the ``show interface status`` table for TenGigabit Ethernet
    ports that are *connected* at 10G speed and report a ``10GBaseT``/``10GBaseTX``
    media type.  The result maps switch identifiers to interface names where an
    SFP will be required during migration.
    """

    ports: DefaultDict[str, set[str]] = defaultdict(set)
    current_intf: str | None = None
    current_speed_10g = False
    current_intf_up = False

    for raw_line in text.splitlines():
        line = raw_line.rstrip()

        # Match interface identifiers at the start of a line
        m_intf = re.match(r"^(?P<intf>(?:Te|TenGigabitEthernet)\S+)", line)
        if m_intf:
            intf = m_intf.group("intf")
            # Handle compact ``show interface status`` style rows
            if re.search(r"\bconnected\b", line):
                parts = line.split()
                if len(parts) >= 7:
                    speed = parts[-2]
                    media = parts[-1]
                    if re.search(r"10G", speed, re.IGNORECASE) and re.search(
                        r"10GBaseT(?:X)?", media, re.IGNORECASE
                    ):
                        m_sw = re.match(r"(?:Te|TenGigabitEthernet)(\d+)/", intf)
                        switch = f"Switch {m_sw.group(1)}" if m_sw else "global"
                        ports[switch].add(intf)
                continue
            # Otherwise remember interface and examine following lines
            current_intf = intf
            current_speed_10g = False
            current_intf_up = bool(
                re.search(r"is up", line, re.IGNORECASE)
                and re.search(r"line protocol is up", line, re.IGNORECASE)
            )
            continue

        if current_intf:
            if re.search(r"10Gb/s|10000Mb/s", line, re.IGNORECASE):
                current_speed_10g = True
            if (
                current_intf_up
                and re.search(r"media type is", line, re.IGNORECASE)
                and re.search(r"10GBaseT(?:X)?", line, re.IGNORECASE)
            ):
                if current_speed_10g or re.search(
                    r"10Gb/s|10000Mb/s", line, re.IGNORECASE
                ):
                    m_sw = re.match(
                        r"(?:Te|TenGigabitEthernet)(\d+)/",
                        current_intf,
                    )
                    switch = f"Switch {m_sw.group(1)}" if m_sw else "global"
                    ports[switch].add(current_intf)
                current_intf = None
                current_speed_10g = False
                current_intf_up = False

    return {sw: sorted(list(p)) for sw, p in ports.items()}


def build_report(
    inventory: Dict[str, Dict[str, int]],
    mapping: Dict[str, str],
    copper_ports: Dict[str, List[str]],
) -> str:
    """Generate a human friendly report."""

    lines = []
    total_copper_ports = sum(len(ports) for ports in copper_ports.values())
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
    if total_copper_ports:
        lines.append(
            f"Additional needed 10Gb copper SFP for EX4650: {total_copper_ports}"
        )
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

