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
from typing import DefaultDict, Dict, Iterable, List, Optional, Set

from ssh_utils import prompt_for_credentials, run_ssh_commands


SHOWTECH_COMMANDS: List[str] = ["show inventory", "show interface status"]


def _expand_tengig_interface(intf: str) -> Set[str]:
    variations = {intf}
    lowered = intf.lower()
    if lowered.startswith("tengigabitethernet"):
        suffix = intf[len("TenGigabitEthernet") :]
        variations.add(f"Te{suffix}")
    elif lowered.startswith("te") and not lowered.startswith("ten"):
        suffix = intf[2:]
        variations.add(f"TenGigabitEthernet{suffix}")
    return variations


def extract_oper_up_interfaces_from_status(text: str) -> Set[str]:
    """Return interfaces that are operationally up from status table output."""

    status_tokens = {
        "connected",
        "notconnect",
        "disabled",
        "err-disabled",
        "inactive",
        "monitor",
        "sfpnotinserted",
        "up",
        "down",
    }
    up_tokens = {"connected", "up"}

    up_interfaces: Set[str] = set()
    for raw_line in text.splitlines():
        line = raw_line.rstrip()
        m_intf = re.match(r"^(?P<intf>(?:Te|TenGigabitEthernet)\S+)", line)
        if not m_intf:
            continue
        tokens = line.split()
        if len(tokens) < 2:
            continue
        status = None
        for token in tokens[1:]:
            token_clean = token.strip().lower().rstrip(",")
            if token_clean in status_tokens:
                status = token_clean
                break
        if status in up_tokens:
            for variant in _expand_tengig_interface(m_intf.group("intf")):
                up_interfaces.add(variant)

    return up_interfaces


def _infer_oper_up_interfaces(text: str) -> Set[str]:
    up_intfs: Set[str] = set()
    intf_status_re = re.compile(
        r"^(?:Interface\s*)?(?P<intf>(?:Te|TenGigabitEthernet)[\d/]+) is up, line protocol is up",
        re.IGNORECASE,
    )
    for line in text.splitlines():
        line = line.strip()
        m_status = intf_status_re.match(line)
        if m_status:
            for variant in _expand_tengig_interface(m_status.group("intf")):
                up_intfs.add(variant)

    up_intfs.update(extract_oper_up_interfaces_from_status(text))
    return up_intfs


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


def parse_showtech(
    text: str, *, oper_up_interfaces: Optional[Iterable[str]] = None
) -> Dict[str, Dict[str, int]]:
    """Parse ``show tech-support`` text and count PIDs per switch.

    Only the ``show inventory`` section is inspected.  Other parts of the
    diagnostic output may contain ``PID`` strings that are unrelated to the
    hardware inventory so they are intentionally ignored.  To avoid reporting
    optics that are present in ``show inventory`` but not actually in service,
    the routine cross-references interface states. When *oper_up_interfaces*
    is provided it is used directly; otherwise interface state is inferred
    from the diagnostic text itself.
    """

    # Record interfaces that are operationally up so that only active optics
    # are counted towards the inventory.  This prevents a 1G SFP in a down
    # port from appearing as a migration requirement.
    if oper_up_interfaces is None:
        up_intfs: Set[str] = _infer_oper_up_interfaces(text)
    else:
        up_intfs = {intf for intf in oper_up_interfaces}

    inventory: DefaultDict[str, DefaultDict[str, int]] = defaultdict(
        lambda: defaultdict(int)
    )
    current_switch: str | None = None
    current_intf: str | None = None
    current_intf_switch: str | None = None
    header_present = bool(
        re.search(r"-+\s*show inventory\s*-+", text, re.IGNORECASE)
    )
    in_inventory = not header_present

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
            m_switch = re.match(r"NAME:\s*\"(?:Switch\s*)?(\d+)\"", line, re.IGNORECASE)
        if m_switch:
            current_switch = f"Switch {m_switch.group(1)}"
            current_intf = None
            current_intf_switch = None
            continue

        # Track individual interface names from NAME lines so we can skip
        # their PIDs if the interface is down and so we can derive the switch
        # number when explicit switch headers are missing.
        m_name = re.match(r'NAME:\s*"((?:Te|TenGigabitEthernet)[\d/]+)"', line)
        if m_name:
            current_intf = m_name.group(1)
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
            if current_intf and up_intfs and current_intf not in up_intfs:
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
                if len(parts) >= 6:
                    speed = parts[-2]
                    media = parts[-1]
                    if re.search(r"10G", speed, re.IGNORECASE) and re.search(
                        r"10GBaseT(?:X)?", media, re.IGNORECASE
                    ):
                        m_sw = re.match(r"(?:Te|TenGigabitEthernet)(\d+)/", intf)
                        switch = f"Switch {m_sw.group(1)}" if m_sw else "global"
                        variants = _expand_tengig_interface(intf)
                        preferred = next(
                            (
                                variant
                                for variant in variants
                                if variant.lower().startswith("tengigabitethernet")
                            ),
                            intf,
                        )
                        ports[switch].add(preferred)
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
    parser.add_argument("file", nargs="?", help="Path to show tech-support text file")
    parser.add_argument(
        "--hosts",
        nargs="+",
        help="One or more hostnames/IPs to pull 'show tech-support' over SSH.",
    )
    parser.add_argument(
        "--ssh-username",
        help="Default SSH username when connecting with --hosts.",
    )
    parser.add_argument(
        "--ssh-timeout",
        type=float,
        default=120.0,
        help="SSH connect/command timeout in seconds (default 120).",
    )
    args = parser.parse_args()

    if not (args.file or args.hosts):
        parser.error("Provide a file or --hosts <device ...>")

    mapping = load_mapping()

    if args.hosts:
        default_username = args.ssh_username
        successes = 0
        total = len(args.hosts)
        for host in args.hosts:
            username, password = prompt_for_credentials(host, default_username)
            default_username = username
            try:
                outputs = run_ssh_commands(
                    host,
                    username,
                    password,
                    SHOWTECH_COMMANDS,
                    timeout=args.ssh_timeout,
                )
                inventory_text = outputs.get("show inventory", "")
                status_text = outputs.get("show interface status", "")
            except KeyboardInterrupt:  # pragma: no cover - CLI convenience
                raise
            except Exception as exc:  # pragma: no cover - network interaction
                print(f"❌ {host}: {exc}")
                password = None
                continue
            finally:
                password = None

            oper_up = (
                extract_oper_up_interfaces_from_status(status_text)
                if status_text.strip()
                else None
            )
            inventory = parse_showtech(inventory_text, oper_up_interfaces=oper_up)
            copper_ports = find_copper_10g_ports(status_text)
            report = build_report(inventory, mapping, copper_ports)
            print(f"===== Report for {host} =====")
            print(report)
            print()
            successes += 1

        failures = total - successes
        print(f"✅ Reports generated: {successes} | Failed: {failures}")
        return

    with open(args.file, encoding="utf-8", errors="ignore") as fh:
        text = fh.read()

    inventory = parse_showtech(text)
    copper_ports = find_copper_10g_ports(text)
    report = build_report(inventory, mapping, copper_ports)
    print(report)


if __name__ == "__main__":  # pragma: no cover - CLI entry point
    main()

