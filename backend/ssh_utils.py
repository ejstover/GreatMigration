"""Utility helpers for securely retrieving command output over SSH."""
from __future__ import annotations

import getpass
import logging
import re
from typing import Iterable, Mapping, Optional, Sequence, TYPE_CHECKING

try:  # pragma: no cover - import guard for optional dependency
    from netmiko import ConnectHandler
    from netmiko.ssh_exception import (
        NetmikoAuthenticationException,
        NetmikoTimeoutException,
    )
except ImportError as exc:  # pragma: no cover - handled at runtime
    ConnectHandler = None  # type: ignore[assignment]
    NetmikoAuthenticationException = NetmikoTimeoutException = None  # type: ignore[assignment]
    _NETMIKO_IMPORT_ERROR = exc
else:  # pragma: no cover - simple import path
    _NETMIKO_IMPORT_ERROR = None

if TYPE_CHECKING:  # pragma: no cover - imported only for typing
    from netmiko.base_connection import BaseConnection as NetmikoBaseConnection
else:  # pragma: no cover - runtime fallback when netmiko is unavailable
    NetmikoBaseConnection = object


logger = logging.getLogger(__name__)


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
    device_type: str = "cisco_ios",
    global_delay_factor: float = 1.0,
) -> str:
    """Execute *command* over SSH and return the textual output."""

    if ConnectHandler is None:  # pragma: no cover - dependency guard
        raise RuntimeError(
            "netmiko is required to run SSH commands. Install netmiko to enable remote collection."
        ) from _NETMIKO_IMPORT_ERROR

    connection = _connect_ssh_client(host, username, password, timeout, device_type)
    try:
        _prepare_session(connection, host, timeout, global_delay_factor)
        return _execute_command(
            connection,
            host,
            command,
            timeout,
            global_delay_factor,
        )
    finally:
        _safe_disconnect(connection)


def run_ssh_commands(
    host: str,
    username: str,
    password: str,
    commands: Iterable[str],
    *,
    timeout: float = 60.0,
    device_type: str = "cisco_ios",
    global_delay_factor: float = 1.0,
) -> Mapping[str, str]:
    """Execute multiple *commands* over SSH and return their outputs."""

    if ConnectHandler is None:  # pragma: no cover - dependency guard
        raise RuntimeError(
            "netmiko is required to run SSH commands. Install netmiko to enable remote collection."
        ) from _NETMIKO_IMPORT_ERROR

    command_list = [c for c in (cmd.strip() for cmd in commands) if c]
    if not command_list:
        raise ValueError("At least one command must be provided for run_ssh_commands().")

    if len(command_list) == 1:
        single = command_list[0]
        return {
            single: run_ssh_command(
                host,
                username,
                password,
                single,
                timeout=timeout,
                device_type=device_type,
                global_delay_factor=global_delay_factor,
            )
        }

    connection = _connect_ssh_client(host, username, password, timeout, device_type)
    try:
        _prepare_session(connection, host, timeout, global_delay_factor)
        outputs: dict[str, str] = {}
        for command in command_list:
            outputs[command] = _execute_command(
                connection,
                host,
                command,
                timeout,
                global_delay_factor,
            )
        return outputs
    finally:
        _safe_disconnect(connection)


def _connect_ssh_client(
    host: str,
    username: str,
    password: str,
    timeout: float,
    device_type: str,
) -> NetmikoBaseConnection:
    return ConnectHandler(
        device_type=device_type,
        host=host,
        username=username,
        password=password,
        conn_timeout=timeout,
        auth_timeout=timeout,
        banner_timeout=timeout,
        fast_cli=False,
    )


def _prepare_session(
    connection: NetmikoBaseConnection,
    host: str,
    timeout: float,
    global_delay_factor: float,
) -> None:
    try:
        if global_delay_factor > 0:
            connection.global_delay_factor = max(
                getattr(connection, "global_delay_factor", 1.0),
                global_delay_factor,
            )
    except Exception:  # pragma: no cover - defensive
        logger.debug("Failed to adjust global delay factor for %s", host, exc_info=True)

    _send_setup_commands(
        connection,
        host,
        ("terminal length 0", "terminal width 0"),
        timeout,
        global_delay_factor,
    )


def _send_setup_commands(
    connection: NetmikoBaseConnection,
    host: str,
    commands: Sequence[str],
    timeout: float,
    global_delay_factor: float,
) -> None:
    for setup_command in commands:
        try:
            connection.send_command(
                setup_command,
                expect_string=None,
                read_timeout=timeout,
                delay_factor=max(global_delay_factor, 1.0),
                strip_command=True,
                strip_prompt=True,
                normalize=True,
            )
        except Exception:
            logger.debug(
                "Setup command '%s' failed on %s", setup_command, host, exc_info=True
            )


def _execute_command(
    connection: NetmikoBaseConnection,
    host: str,
    command: str,
    timeout: float,
    global_delay_factor: float,
) -> str:
    try:
        output = connection.send_command(
            command,
            expect_string=None,
            read_timeout=timeout,
            delay_factor=max(global_delay_factor, 1.0),
            strip_command=True,
            strip_prompt=True,
            normalize=True,
        )
    except EOFError as exc:
        logger.error(
            "SSH session closed while executing '%s' on %s", command, host, exc_info=True
        )
        raise _connection_closed_error(host, f"the '{command}' response", command) from exc
    except NetmikoTimeoutException as exc:  # type: ignore[arg-type]
        logger.error(
            "Timed out waiting for '%s' response on %s", command, host, exc_info=True
        )
        raise SSHCommandError(f"{host}: timed out waiting for '{command}' response") from exc
    except NetmikoAuthenticationException as exc:  # type: ignore[arg-type]
        logger.error("Authentication failed for %s", host, exc_info=True)
        raise SSHCommandError(f"{host}: authentication failed: {exc}") from exc
    except Exception as exc:
        logger.error(
            "SSH command '%s' failed on %s", command, host, exc_info=True
        )
        raise SSHCommandError(f"{host}: failed to execute '{command}': {exc}") from exc

    normalized = _normalize_newlines(output)
    if not normalized.strip():
        raise SSHCommandError(f"{host}: no output received for '{command}'")

    return normalized


def _safe_disconnect(connection: NetmikoBaseConnection) -> None:
    try:
        connection.disconnect()
    except Exception:
        logger.debug("Failed to close SSH session cleanly", exc_info=True)


def _normalize_newlines(value: str) -> str:
    return value.replace("\r\n", "\n").replace("\r", "\n")


def _connection_closed_error(host: str, context: str, command: Optional[str]) -> SSHCommandError:
    if command:
        command_text = f" while handling '{command}'"
    else:
        command_text = ""
    return SSHCommandError(
        f"{host}: the SSH session closed unexpectedly{command_text} — the remote device either terminated the interactive shell"
        " or the network latency exceeded the server's limits. Try increasing the SSH timeout or rerunning the collection on a less busy link."
    )


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
    """Return a user-friendly message for an SSH collection exception."""

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
