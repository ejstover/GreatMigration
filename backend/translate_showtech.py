#!/usr/bin/env python3
"""Translate Cisco show tech-support inventory to Juniper replacements.

This utility parses the output of a Cisco ``show tech-support`` command, collects
all product identifiers (PIDs) reported in the ``show inventory`` section and
generates a summary per switch member.  Each Cisco PID is looked up in a simple
mapping table to determine the recommended Juniper replacement hardware.

The mapping data is loaded from ``backend/device_map.json`` if present.  The
repository ships with ``device_map.sample.json`` which provides a starting set
of common mappings.  Administrators can copy this sample to
``device_map.json`` and extend it with their own hardware rules without
committing sensitive or organization specific information back to the
repository.

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
from typing import Dict, DefaultDict


def load_mapping() -> Dict[str, str]:
    """Load the Cisco PID -> Juniper model mapping.

    ``device_map.json`` takes precedence if present so users can maintain their
    own local overrides.  Otherwise ``device_map.sample.json`` is used.
    """

    base = Path(__file__).resolve().parent
    local = base / "device_map.json"
    sample = base / "device_map.sample.json"

    path = local if local.exists() else sample
    with path.open() as fh:
        return json.load(fh)


def parse_showtech(text: str) -> Dict[str, Dict[str, int]]:
    """Parse ``show tech-support`` text and count PIDs per switch.

    Only the ``show inventory`` section is considered. Anything before or
    after that section is ignored to avoid false matches from other commands.
    """

    inventory: DefaultDict[str, DefaultDict[str, int]] = defaultdict(
        lambda: defaultdict(int)
    )

    # Find the show inventory block and ignore everything else
    in_section = False
    section: list[str] = []
    for line in text.splitlines():
        if not in_section:
            if re.match(r"\s*(?:-+\s*)?show\s+inventory(?:\s*-+)?\s*$", line, re.IGNORECASE):
                in_section = True
            continue
        if re.match(r"\s*(?:-+\s*)?show\s+\S+", line, re.IGNORECASE):
            break
        section.append(line)

    current_switch = "global"
    for raw in section:
        line = raw.strip()

        # NAME lines indicate the switch member
        m_name = re.match(r'NAME:\s*"([^"]+)"', line, re.IGNORECASE)
        if m_name:
            name = m_name.group(1)
            m_switch = re.match(r"Switch\s+(\d+)", name, re.IGNORECASE)
            if m_switch:
                current_switch = f"Switch {m_switch.group(1)}"
            continue

        m_pid = re.search(r"PID:\s*([^,\s]+)", line)
        if m_pid:
            pid = m_pid.group(1)
            inventory[current_switch][pid] += 1

    return inventory


def build_report(
    inventory: Dict[str, Dict[str, int]], mapping: Dict[str, str]
) -> str:
    """Generate a human friendly report."""

    lines = []
    for switch, items in inventory.items():
        lines.append(f"{switch}:")
        lines.append("  Cisco inventory:")
        for pid, count in sorted(items.items()):
            lines.append(f"    {pid} x{count}")
        lines.append("  Recommended Juniper replacements:")
        for pid, count in sorted(items.items()):
            replacement = mapping.get(pid, "UNKNOWN")
            lines.append(f"    {replacement} x{count}")
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
    report = build_report(inventory, mapping)
    print(report)


if __name__ == "__main__":  # pragma: no cover - CLI entry point
    main()

