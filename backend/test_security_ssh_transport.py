"""Exercise real Netmiko/Paramiko host-key enforcement against a local SSH server."""
import socket
import threading

import paramiko
import pytest

import ssh_collect


@pytest.mark.parametrize("trusted", [False, True])
def test_real_ssh_transport_requires_trusted_key(tmp_path, monkeypatch, trusted):
    key = paramiko.RSAKey.generate(2048)
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    listener.settimeout(8)
    port = listener.getsockname()[1]
    stop = threading.Event()
    transports = []

    class Server(paramiko.ServerInterface):
        def check_auth_password(self, username, password):
            return paramiko.AUTH_SUCCESSFUL if (username, password) == ("operator", "synthetic-password") else paramiko.AUTH_FAILED
        def get_allowed_auths(self, username): return "password"
        def check_channel_request(self, kind, channel_id):
            return paramiko.OPEN_SUCCEEDED if kind == "session" else paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED
        def check_channel_pty_request(self, *args): return True
        def check_channel_shell_request(self, channel): return True

    def serve():
        try:
            connection, _ = listener.accept()
            transport = paramiko.Transport(connection)
            transports.append(transport)
            transport.add_server_key(key)
            transport.start_server(server=Server())
            channel = transport.accept(5)
            if channel is None:
                return
            channel.settimeout(0.5)
            channel.send(b"virtual-switch#")
            buffer = ""
            while not stop.is_set() and transport.is_active():
                try:
                    incoming = channel.recv(4096)
                except socket.timeout:
                    continue
                if not incoming:
                    break
                buffer += incoming.decode(errors="replace").replace("\r", "\n")
                while "\n" in buffer:
                    command, buffer = buffer.split("\n", 1)
                    output = "hostname virtual-switch\r\n!" if command.strip() == "show running-config" else ""
                    channel.send((command + "\r\n" + output + "\r\nvirtual-switch#").encode())
        except (EOFError, OSError, paramiko.SSHException):
            # Rejecting an unknown host key intentionally closes the transport.
            pass
        finally:
            for transport in transports:
                transport.close()

    worker = threading.Thread(target=serve, daemon=True)
    worker.start()
    known_hosts = tmp_path / "known_hosts"
    known_hosts.write_text(f"[127.0.0.1]:{port} {key.get_name()} {key.get_base64()}\n" if trusted else "")
    monkeypatch.setenv("SSH_KNOWN_HOSTS_FILE", str(known_hosts))
    original = ssh_collect.ConnectHandler

    def connect(**kwargs):
        return original(**dict(kwargs, port=port, conn_timeout=3, auth_timeout=3, banner_timeout=3))

    monkeypatch.setattr(ssh_collect, "ConnectHandler", connect)
    try:
        result = ssh_collect._collect_one_device(base_dir=tmp_path / "job", device=ssh_collect.DeviceInput("127.0.0.1"),
            username="operator", password_bytes=b"synthetic-password", delay_factor=0.1, read_timeout=15)
        if trusted:
            assert result.status == "ok", result.error
            assert "hostname virtual-switch" in result.running_config["text"]
        else:
            assert result.status == "error"
            assert result.running_config is None
    finally:
        stop.set()
        listener.close()
        for transport in transports:
            transport.close()
        worker.join(timeout=3)
