"""CLI compatibility checks use temporary inputs and synthetic credentials."""
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.parametrize("script", ["backend/convertciscotojson.py", "backend/push_mist_port_config.py", "backend/translate_showtech.py", "backend/security_setup.py", "quickstart.py"])
def test_cli_help_works_with_windows_encoding(script):
    env = dict(os.environ, PYTHONIOENCODING="cp1252")
    result = subprocess.run([sys.executable, str(ROOT / script), "--help"], capture_output=True, env=env, timeout=15)
    assert result.returncode == 0, result.stderr.decode(errors="replace")


def test_conversion_and_push_preview_cli(tmp_path):
    source = tmp_path / "switch.txt"
    source.write_text("hostname legacy\ninterface GigabitEthernet1/0/1\n switchport mode access\n switchport access vlan 10\n!\n")
    result = subprocess.run([sys.executable, str(ROOT / "backend/convertciscotojson.py"), str(source), "--force-model", "ex4100-48mp"], capture_output=True, timeout=15)
    assert result.returncode == 0, result.stderr.decode(errors="replace")
    output = tmp_path / "switch_converted.json"
    assert json.loads(output.read_text())["interfaces"]
    result = subprocess.run([sys.executable, str(ROOT / "backend/push_mist_port_config.py"), "--site-id", "synthetic-site", "--device-id", "synthetic-device", "--input", str(output), "--model", "ex4100-48mp", "--dry-run"],
                            capture_output=True, env=dict(os.environ, MIST_TOKEN="synthetic-token"), timeout=15)
    assert result.returncode == 0, result.stderr.decode(errors="replace")
    assert b"port_config" in result.stdout
