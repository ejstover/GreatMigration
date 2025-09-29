"""Utility helpers for securely retrieving command output over SSH."""
from __future__ import annotations

import getpass
import re
import time
from typing import Iterable, Mapping, Optional

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

    primary_exc: Optional[Exception] = None

    client = _connect_ssh_client(host, username, password, timeout)
    try:
        try:
            return _run_command_via_exec(client, host, command, timeout)
        except (paramiko.SSHException, EOFError, OSError) as exc:
            primary_exc = exc
    finally:
        _safe_close(client)

    if primary_exc is None:
        # Unreachable, but keeps mypy/pyright satisfied.
        raise SSHCommandError(f"{host}: failed to execute '{command}'")

    client = _connect_ssh_client(host, username, password, timeout)
    try:
        return _run_command_via_shell(client, host, command, timeout)
    except Exception as fallback_exc:
        raise primary_exc from fallback_exc
    finally:
        _safe_close(client)


def run_ssh_commands(
    host: str,
    username: str,
    password: str,
    commands: Iterable[str],
    *,
    timeout: float = 60.0,
) -> Mapping[str, str]:
    """Execute multiple *commands* over SSH and return their outputs.

    The commands are executed within a single interactive shell session so the
    connection overhead is paid only once. Each command is mapped to its output
    text. If any command fails or produces no output an :class:`SSHCommandError`
    is raised identifying the offending command.
    """

    if paramiko is None:  # pragma: no cover - dependency guard
        raise RuntimeError(
            "paramiko is required to run SSH commands. Install paramiko to enable remote collection."
        ) from _PARAMIKO_IMPORT_ERROR

    command_list = [c for c in (cmd.strip() for cmd in commands) if c]
    if not command_list:
        raise ValueError("At least one command must be provided for run_ssh_commands().")

    if len(command_list) == 1:
        single = command_list[0]
        return {single: run_ssh_command(host, username, password, single, timeout=timeout)}

    client = _connect_ssh_client(host, username, password, timeout)
    try:
        return _run_commands_via_shell(client, host, command_list, timeout)
    finally:
        _safe_close(client)


def _connect_ssh_client(
    host: str, username: str, password: str, timeout: float
) -> "paramiko.SSHClient":
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(
        hostname=host,
        username=username,
        password=password,
        look_for_keys=False,
        allow_agent=False,
        timeout=timeout,
        banner_timeout=timeout,
        auth_timeout=timeout,
    )
    return client


def _safe_close(client: "paramiko.SSHClient") -> None:
    try:
        client.close()
    except Exception:
        pass


def _run_command_via_exec(
    client: "paramiko.SSHClient",
    host: str,
    command: str,
    timeout: float,
) -> str:
    try:
        _, stdout, _ = client.exec_command("terminal length 0", timeout=timeout, get_pty=True)
        stdout.channel.recv_exit_status()
    except Exception:
        pass

    stdin, stdout, stderr = client.exec_command(command, timeout=timeout, get_pty=True)
    try:
        output = stdout.read().decode(errors="ignore")
        error = stderr.read().decode(errors="ignore")
    finally:
        try:
            stdin.close()
        except Exception:
            pass

    exit_status = stdout.channel.recv_exit_status()
    if exit_status != 0:
        raise SSHCommandError(
            f"{host}: command '{command}' failed with exit status {exit_status}: {error.strip() or 'no stderr'}"
        )

    output = _normalize_newlines(output)
    if not output.strip():
        if error.strip():
            raise SSHCommandError(f"{host}: no output received for '{command}': {error.strip()}")
        raise SSHCommandError(f"{host}: no output received for '{command}'")

    return output


def _run_command_via_shell(
    client: "paramiko.SSHClient",
    host: str,
    command: str,
    timeout: float,
) -> str:
    channel = client.invoke_shell()
    channel.settimeout(timeout)
    try:
        prompt = _establish_prompt(channel, host, timeout)
        _send_and_discard(channel, host, "terminal length 0", prompt, timeout)
        raw_output = _send_and_capture(channel, host, command, prompt, timeout)
    finally:
        try:
            channel.close()
        except Exception:
            pass

    output = _extract_command_output(raw_output, host, command, prompt)
    if not output.strip():
        raise SSHCommandError(f"{host}: no output received for '{command}'")

    return output


def _run_commands_via_shell(
    client: "paramiko.SSHClient",
    host: str,
    commands: Iterable[str],
    timeout: float,
) -> Mapping[str, str]:
    channel = client.invoke_shell()
    channel.settimeout(timeout)
    try:
        prompt = _establish_prompt(channel, host, timeout)
        try:
            _send_and_discard(channel, host, "terminal length 0", prompt, timeout)
        except Exception:
            pass
        try:
            _send_and_discard(channel, host, "terminal width 0", prompt, timeout)
        except Exception:
            pass

        outputs: dict[str, str] = {}
        for command in commands:
            raw_output = _send_and_capture(channel, host, command, prompt, timeout)
            output = _extract_command_output(raw_output, host, command, prompt)
            if not output.strip():
                raise SSHCommandError(f"{host}: no output received for '{command}'")
            outputs[command] = output
        return outputs
    finally:
        try:
            channel.close()
        except Exception:
            pass


def _establish_prompt(
    channel: "paramiko.Channel", host: str, timeout: float
) -> str:
    """Return the detected device prompt for the interactive session."""

    end_time = time.monotonic() + timeout
    buffer = ""
    channel.send("\n")

    while time.monotonic() < end_time:
        if channel.recv_ready():
            data = channel.recv(65535)
            if not data:
                continue
            buffer += data.decode(errors="ignore")
            prompt = _detect_prompt(buffer)
            if prompt:
                return prompt
        else:
            prompt = _detect_prompt(buffer)
            if prompt:
                return prompt
            time.sleep(0.1)
            channel.send("\n")

    raise SSHCommandError(f"{host}: timed out waiting for device prompt")


_PROMPT_SUFFIXES = ("#", ">", "]", "$")


def _detect_prompt(buffer: str) -> Optional[str]:
    normalized = _normalize_newlines(buffer)
    lines = [line.strip() for line in normalized.split("\n") if line.strip()]
    if not lines:
        return None

    for line in reversed(lines):
        for suffix in _PROMPT_SUFFIXES:
            if line.endswith(suffix):
                return line

    return lines[-1]


def _send_and_discard(
    channel: "paramiko.Channel",
    host: str,
    command: str,
    prompt: str,
    timeout: float,
) -> None:
    channel.send(f"{command}\n")
    _read_until_prompt(channel, host, command, prompt, timeout)


def _send_and_capture(
    channel: "paramiko.Channel",
    host: str,
    command: str,
    prompt: str,
    timeout: float,
) -> str:
    channel.send(f"{command}\n")
    return _read_until_prompt(channel, host, command, prompt, timeout)


def _read_until_prompt(
    channel: "paramiko.Channel",
    host: str,
    command: str,
    prompt: str,
    timeout: float,
) -> str:
    buffer = ""
    end_time = time.monotonic() + timeout
    prompt_clean = prompt.strip()

    while time.monotonic() < end_time:
        if channel.recv_ready():
            data = channel.recv(65535)
            if not data:
                continue
            buffer += data.decode(errors="ignore")
            normalized = _normalize_newlines(buffer)
            if normalized.rstrip().endswith(prompt_clean):
                return normalized
        else:
            if buffer:
                normalized = _normalize_newlines(buffer)
                if normalized.rstrip().endswith(prompt_clean):
                    return normalized
            time.sleep(0.1)

    raise SSHCommandError(f"{host}: timed out waiting for '{command}' response")


def _extract_command_output(
    raw_output: str,
    host: str,
    command: str,
    prompt: str,
) -> str:
    normalized = _normalize_newlines(raw_output)
    lines = normalized.split("\n")
    prompt_clean = prompt.strip()
    prompt_lower = prompt_clean.lower()
    command_clean = command.strip()
    command_lower = command_clean.lower()

    output_lines: list[str] = []
    command_seen = False

    for line in lines:
        stripped = line.strip()
        lowered = stripped.lower()

        if not command_seen:
            if lowered == command_lower:
                command_seen = True
                continue
            if prompt_clean and lowered.startswith(prompt_lower):
                remainder = stripped[len(prompt_clean) :].strip()
                if remainder.lower() == command_lower:
                    command_seen = True
                    continue
            if lowered.endswith(command_lower):
                command_seen = True
                continue
            continue

        if prompt_clean and stripped.startswith(prompt_clean):
            break

        output_lines.append(line)

    return _normalize_newlines("\n".join(output_lines)).strip("\n")


def _normalize_newlines(value: str) -> str:
    return value.replace("\r\n", "\n").replace("\r", "\n")


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
