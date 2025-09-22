"""Utility helpers for securely retrieving command output over SSH."""
from __future__ import annotations

import getpass
import re
from typing import Iterable, Optional

try:  # pragma: no cover - import guard for optional dependency
    import paramiko  # type: ignore
except ImportError as exc:  # pragma: no cover - handled at runtime
    paramiko = None  # type: ignore
    _PARAMIKO_IMPORT_ERROR = exc
else:  # pragma: no cover - simple import path
    _PARAMIKO_IMPORT_ERROR = None


class SSHCommandError(RuntimeError):
    """Raised when a remote SSH command fails."""


def prompt_for_credentials(host: str, default_username: Optional[str] = None) -> tuple[str, str]:
    """Prompt the operator for SSH credentials."""

    while True:
        prompt = f"Enter SSH username for {host}"
        if default_username:
            prompt += f" [{default_username}]"
        prompt += ": "
        username = input(prompt).strip()
        if not username:
            if default_username:
                username = default_username
            else:
                print("Username is required.")
                continue
        password = getpass.getpass(f"Password for {username}@{host}: ")
        if not password:
            print("Password cannot be empty.")
            continue
        return username, password


def run_ssh_command(
    host: str,
    username: str,
    password: str,
    command: str,
    *,
    timeout: float = 60.0,
) -> str:
    """Execute *command* over SSH and return the textual output."""

    if paramiko is None:  # pragma: no cover - dependency guard
        raise RuntimeError(
            "paramiko is required to run SSH commands. Install paramiko to enable remote collection."
        ) from _PARAMIKO_IMPORT_ERROR

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(
            hostname=host,
            username=username,
            password=password,
            look_for_keys=False,
            allow_agent=False,
            timeout=timeout,
            banner_timeout=timeout,
        )
        try:
            _, stdout, _ = client.exec_command("terminal length 0", timeout=timeout, get_pty=True)
            stdout.channel.recv_exit_status()
        except Exception:
            pass
        stdin, stdout, stderr = client.exec_command(command, timeout=timeout, get_pty=True)
        output = stdout.read().decode(errors="ignore")
        error = stderr.read().decode(errors="ignore")
        exit_status = stdout.channel.recv_exit_status()
        if exit_status != 0:
            raise SSHCommandError(
                f"{host}: command '{command}' failed with exit status {exit_status}: {error.strip() or 'no stderr'}"
            )
        output = output.replace("\r\n", "\n")
        if not output.strip():
            if error.strip():
                raise SSHCommandError(
                    f"{host}: no output received for '{command}': {error.strip()}"
                )
            raise SSHCommandError(f"{host}: no output received for '{command}'")
        return output
    finally:
        try:
            client.close()
        except Exception:
            pass


def sanitize_label(value: str, fallback: str = "device") -> str:
    """Return a filesystem-friendly label based on *value*."""

    safe = re.sub(r"[^A-Za-z0-9_.-]", "_", value)
    return safe or fallback


def _stringify_args(args: Iterable[object]) -> str:
    """Return a joined/stripped representation of *args*."""

    parts: list[str] = []
    for value in args:
        text = str(value).strip()
        if text:
            parts.append(text)
    return "; ".join(parts)


def summarize_ssh_error(host: str, exc: Exception, command: Optional[str] = None) -> str:
    """Return a user-friendly message for an SSH collection exception.

    The returned string intentionally excludes the *host* prefix since the
    calling code already associates the error with the device. When available,
    the executed command is appended so operators know what failed.
    """

    message = ""

    if isinstance(exc, SSHCommandError):
        raw = exc.args[0] if exc.args else str(exc)
        message = str(raw).strip()
        if message.startswith(f"{host}:"):
            message = message[len(host) + 1 :].lstrip()

    if not message:
        message = str(exc).strip()

    if not message and getattr(exc, "args", None):
        message = _stringify_args(exc.args)

    if not message:
        message = exc.__class__.__name__

    if command and command not in message:
        message = f"{message} (command: {command})"

    return message
