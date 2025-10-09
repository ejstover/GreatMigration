"""Utilities for collecting switch data over SSH.

This module coordinates multi-threaded SSH collection for Cisco switches
using Netmiko.  It is designed to gather the discrete commands that the
application needs (``show inventory``, ``show interface status``,
``show interfaces`` and ``show running-config``) so that we avoid the
long-running ``show tech-support`` command while still producing the same
parsing output.

Each device gets its own temporary directory under the job directory and
every command response is persisted to disk.  The raw text is also returned
to the caller so downstream code can continue to feed existing parsing
pipelines.
"""

from __future__ import annotations

import threading
import time
import uuid
from concurrent.futures import Future, ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterable, List, Optional

try:
    from netmiko import ConnectHandler  # type: ignore
except Exception as exc:  # pragma: no cover - optional dependency
    ConnectHandler = None  # type: ignore
    NETMIKO_IMPORT_ERROR = exc
else:
    NETMIKO_IMPORT_ERROR = None


def _raise_missing_netmiko() -> None:
    message = (
        "netmiko is required for SSH collection. Install the optional dependency to enable this feature."
    )
    if NETMIKO_IMPORT_ERROR is not None:
        message = f"{message} (Import error: {NETMIKO_IMPORT_ERROR})"
    raise RuntimeError(message)

from translate_showtech import find_copper_10g_ports, load_mapping, parse_showtech


@dataclass
class DeviceInput:
    host: str
    label: Optional[str] = None


@dataclass
class DeviceResult:
    host: str
    label: str
    status: str
    error: Optional[str] = None
    command_outputs: Dict[str, str] = field(default_factory=dict)
    temp_files: Dict[str, str] = field(default_factory=dict)
    hardware: Optional[Dict[str, object]] = None
    running_config: Optional[Dict[str, str]] = None


@dataclass
class JobState:
    id: str
    created: float
    status: str = "pending"
    total: int = 0
    completed: int = 0
    message: str = ""
    error: Optional[str] = None
    results: List[DeviceResult] = field(default_factory=list)
    updates: List[Dict[str, object]] = field(default_factory=list)
    temp_dir: Path | None = None
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def to_dict(self) -> Dict[str, object]:
        return {
            "id": self.id,
            "created": self.created,
            "status": self.status,
            "total": self.total,
            "completed": self.completed,
            "message": self.message,
            "error": self.error,
            "updates": list(self.updates),
            "results": [
                {
                    "host": r.host,
                    "label": r.label,
                    "status": r.status,
                    "error": r.error,
                    "hardware": r.hardware,
                    "running_config": r.running_config,
                    "temp_files": r.temp_files,
                }
                for r in self.results
            ],
        }


_JOBS: Dict[str, JobState] = {}


def get_job(job_id: str) -> Optional[JobState]:
    return _JOBS.get(job_id)


def sanitize_label(value: str) -> str:
    safe = "".join(ch for ch in value if ch.isalnum() or ch in ("-", "_", "."))
    return safe or "device"


def build_showtech_text(outputs: Dict[str, str]) -> str:
    sections: List[str] = []
    for title in ("show inventory", "show interface status", "show interfaces"):
        data = outputs.get(title)
        if not data:
            continue
        sections.append(f"{'-' * 26} {title} {'-' * 26}")
        sections.append(data)
    return "\n".join(sections)


def _collect_one_device(
    *,
    base_dir: Path,
    device: DeviceInput,
    username: str,
    password: str,
    delay_factor: float,
    read_timeout: int,
) -> DeviceResult:
    if ConnectHandler is None:  # pragma: no cover - handled in start_job
        _raise_missing_netmiko()

    label = device.label or device.host
    safe_label = sanitize_label(label.replace(" ", "_"))
    device_dir = base_dir / safe_label
    device_dir.mkdir(parents=True, exist_ok=True)

    result = DeviceResult(host=device.host, label=label, status="running")
    result.temp_files["directory"] = str(device_dir)

    conn = None
    try:
        params = {
            "device_type": "cisco_ios",
            "host": device.host,
            "username": username,
            "password": password,
            "fast_cli": False,
            "timeout": read_timeout,
            "global_delay_factor": delay_factor,
        }
        conn = ConnectHandler(**params)
        transport = getattr(conn, "protocol", "ssh")
        if str(transport).lower() != "ssh":
            try:
                conn.disconnect()
            except Exception:
                pass
            finally:
                conn = None
            raise RuntimeError(
                "This tool only supports SSH connections; Netmiko negotiated a"
                f" '{transport}' transport."
            )
        try:
            conn.enable()
        except Exception:
            # not all devices require enable
            pass

        try:
            conn.send_command("terminal length 0", expect_string=r"#", read_timeout=20)
        except Exception:
            # continue even if terminal length fails
            pass

        commands = {
            "show inventory": {"filename": "show_inventory.txt", "timeout": read_timeout},
            "show interface status": {
                "filename": "show_interface_status.txt",
                "timeout": max(read_timeout, 60),
            },
            "show interfaces": {
                "filename": "show_interfaces.txt",
                "timeout": max(read_timeout, 120),
            },
            "show running-config": {
                "filename": "show_running_config.txt",
                "timeout": max(read_timeout, 120),
            },
        }

        for command, meta in commands.items():
            output = conn.send_command(
                command,
                expect_string=r"#",
                read_timeout=meta["timeout"],
                delay_factor=delay_factor,
            )
            result.command_outputs[command] = output
            path = device_dir / meta["filename"]
            path.write_text(output, encoding="utf-8")
            result.temp_files[command] = str(path)

        combined_text = build_showtech_text(result.command_outputs)
        combined_path = device_dir / "synthetic_showtech.txt"
        combined_path.write_text(combined_text, encoding="utf-8")
        result.temp_files["combined_showtech"] = str(combined_path)

        mapping = load_mapping()
        inventory = parse_showtech(combined_text)
        copper_ports = find_copper_10g_ports(combined_text)
        switches = []
        for sw, items in inventory.items():
            if sw.lower() == "global":
                continue
            sw_items = [
                {
                    "pid": pid,
                    "count": count,
                    "replacement": mapping.get(pid, "no replacement model defined"),
                }
                for pid, count in items.items()
            ]
            switches.append({"switch": sw, "items": sw_items})
        copper_total = sum(len(v) for v in copper_ports.values())
        result.hardware = {
            "filename": label,
            "switches": switches,
            "copper_10g_ports": {**copper_ports, "total": copper_total},
        }

        running_cfg = result.command_outputs.get("show running-config", "")
        result.running_config = {
            "filename": f"{safe_label or 'device'}.running-config.txt",
            "text": running_cfg,
        }

        result.status = "ok"
        return result
    except Exception as exc:  # pragma: no cover - network dependent
        result.status = "error"
        result.error = str(exc)
        return result
    finally:
        try:
            if conn is not None:
                conn.disconnect()
        except Exception:
            pass


def start_job(
    *,
    devices: Iterable[DeviceInput],
    username: str,
    password_bytes: bytearray,
    delay_factor: float,
    read_timeout: int,
    max_workers: int,
) -> JobState:
    if ConnectHandler is None:
        _raise_missing_netmiko()

    job_id = uuid.uuid4().hex
    job_dir = Path(Path.cwd() / "tmp_ssh_jobs")
    job_dir.mkdir(parents=True, exist_ok=True)
    base_dir = job_dir / job_id
    base_dir.mkdir(parents=True, exist_ok=True)

    job = JobState(id=job_id, created=time.time(), status="pending", temp_dir=base_dir)
    device_list = [DeviceInput(host=d.host.strip(), label=(d.label or "").strip() or d.host.strip()) for d in devices if d.host.strip()]
    job.total = len(device_list)
    _JOBS[job_id] = job

    def _run() -> None:
        password = password_bytes.decode("utf-8")
        try:
            if not device_list:
                with job._lock:
                    job.status = "complete"
                    job.message = "No devices provided"
                return

            with job._lock:
                job.status = "running"
                job.message = "Connecting to devices"

            futures: Dict[Future[DeviceResult], DeviceInput] = {}
            with ThreadPoolExecutor(max_workers=max_workers) as executor:
                for device in device_list:
                    future = executor.submit(
                        _collect_one_device,
                        base_dir=base_dir,
                        device=device,
                        username=username,
                        password=password,
                        delay_factor=delay_factor,
                        read_timeout=read_timeout,
                    )
                    futures[future] = device

                for fut in as_completed(futures):
                    device = futures[fut]
                    try:
                        result = fut.result()
                    except Exception as exc:  # pragma: no cover
                        result = DeviceResult(
                            host=device.host,
                            label=device.label or device.host,
                            status="error",
                            error=str(exc),
                        )

                    with job._lock:
                        job.results.append(result)
                        job.completed = len(job.results)
                        job.message = f"Processed {job.completed}/{job.total}"
                        job.updates.append(
                            {
                                "timestamp": time.time(),
                                "device": result.label,
                                "status": result.status,
                                "error": result.error,
                                "completed": job.completed,
                                "total": job.total,
                            }
                        )

            with job._lock:
                job.status = "complete"
                job.message = f"Finished {job.completed} device(s)"
        finally:
            for i in range(len(password_bytes)):
                password_bytes[i] = 0

    thread = threading.Thread(target=_run, name=f"ssh-job-{job_id}", daemon=True)
    thread.start()
    return job


def cleanup_old_jobs(max_age: float = 3600.0) -> None:
    now = time.time()
    to_remove: List[str] = []
    for job_id, job in list(_JOBS.items()):
        if now - job.created > max_age:
            to_remove.append(job_id)
    for job_id in to_remove:
        job = _JOBS.pop(job_id, None)
        if job and job.temp_dir and job.temp_dir.exists():
            try:
                for child in job.temp_dir.rglob("*"):
                    if child.is_file():
                        try:
                            child.unlink()
                        except Exception:
                            pass
                job.temp_dir.rmdir()
            except Exception:
                pass

