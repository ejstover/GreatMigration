"""Native boot registration and service control. No package dependencies."""
from __future__ import annotations

import base64
import hashlib
import json
import os
from pathlib import Path
import plistlib
import shutil
import subprocess
import sys
import tempfile
import time


def encoded_ps(script: str) -> str:
    return base64.b64encode(script.encode("utf-16-le")).decode("ascii")


def systemd_quote(value: str, *, executable: bool = False) -> str:
    value = value.replace("\\", "\\\\").replace('"', '\\"').replace("%", "%%")
    if executable:
        value = value.replace("$", "$$")
    return '"' + value + '"'


class ServiceManager:
    def __init__(self, project: Path):
        self.project = project.resolve()
        if any(c in str(self.project) for c in "\r\n\0"):
            raise RuntimeError("Service paths cannot contain control characters")
        digest = hashlib.sha256(os.path.normcase(str(self.project)).encode()).hexdigest()[:12]
        self.name = f"greatmigration-{digest}"
        self.kind = {"win32": "windows", "linux": "systemd", "darwin": "launchd"}.get(sys.platform, "unsupported")
        self.state = self.project / "backend" / "data" / "quickstart"
        self.log_path = self.project / "backend" / "logs" / "quickstart-service.log"
        self.python = self.project / ".venv" / ("Scripts/python.exe" if self.kind == "windows" else "bin/python")
        self.arguments = [str(self.project / "scripts" / "quickstart_runtime.py"), "--dir", str(self.project), "--managed"]
        self.label = f"org.greatmigration.{digest}"
        self.definition_path = (Path("/Library/LaunchDaemons") / f"{self.label}.plist" if self.kind == "launchd"
                                else Path("/etc/systemd/system") / f"{self.name}.service")

    def _run(self, command, *, check=True):
        result = subprocess.run([str(arg) for arg in command], capture_output=True, text=True)
        if check and result.returncode:
            raise RuntimeError(result.stderr.strip() or f"Service command failed ({result.returncode})")
        return result

    def _ps(self, script: str, *, interactive=False):
        executable = shutil.which("powershell.exe")
        if not executable:
            raise RuntimeError("Windows PowerShell is required for Task Scheduler control")
        command = [executable, "-NoProfile"]
        if not interactive:
            command.append("-NonInteractive")
        command.extend(["-EncodedCommand", encoded_ps("$ErrorActionPreference = 'Stop'; " + script)])
        return self._run(command)

    def _privileged(self, *command):
        if os.geteuid() == 0:
            return self._run(command)
        if not shutil.which("sudo"):
            raise RuntimeError("Administrator access via sudo is required to register/control the boot service.")
        prefix = ["sudo"] if sys.stdin.isatty() else ["sudo", "-n"]
        return self._run([*prefix, *command])

    def _supported(self):
        if self.kind == "unsupported":
            raise RuntimeError("Automatic startup is unsupported on this OS. Use quickstart start manually.")
        if self.kind == "systemd" and (not shutil.which("systemctl") or not Path("/run/systemd/system").is_dir()):
            raise RuntimeError("This Linux environment does not run systemd. Use quickstart start manually.")

    def _windows_state(self):
        # The identifier is generated from a path hash, never interpolated user text.
        result = self._ps("$t = Get-ScheduledTask -TaskPath '\\' -ErrorAction Stop | "
                          f"Where-Object {{ $_.TaskName -eq '{self.name}' }}; "
                          "if ($null -eq $t) { Write-Output 'missing' } else { "
                          "@{ State = [string]$t.State; Execute = $t.Actions[0].Execute; "
                          "Arguments = $t.Actions[0].Arguments } | ConvertTo-Json -Compress }")
        if result.stdout.strip() == "missing":
            return None
        data = json.loads(result.stdout)
        if (os.path.normcase(data["Execute"]) != os.path.normcase(str(self.python))
                or data["Arguments"] != subprocess.list2cmdline(self.arguments)):
            raise RuntimeError("The scheduled task has a different action. Inspect it in Task Scheduler before continuing.")
        return data

    def installed(self) -> bool:
        if self.kind == "windows":
            return self._windows_state() is not None
        return self.definition_path.is_file() if self.kind in {"systemd", "launchd"} else False

    def running(self) -> bool:
        self._supported()
        if self.kind == "windows":
            state = self._windows_state()
            return state is not None and state["State"] in {"Running", "Queued"}
        if self.kind == "systemd":
            result = self._run(["systemctl", "show", self.name, "--property=ActiveState", "--value"])
            return result.stdout.strip() in {"active", "activating", "reloading", "deactivating"}
        result = self._run(["launchctl", "print", f"system/{self.label}"], check=False)
        if result.returncode:
            return False  # bootout is how an intentional stop suppresses KeepAlive.
        return any(line.strip() == "state = running" for line in result.stdout.splitlines())

    def _owner(self):
        if self.kind == "windows":
            return self._run(["whoami"]).stdout.strip()
        import pwd
        username = os.environ.get("SUDO_USER") if os.geteuid() == 0 else None
        user = pwd.getpwnam(username) if username else pwd.getpwuid(os.getuid())
        if user.pw_uid == 0:
            raise RuntimeError("Run boot registration as the normal app user; sudo will be used only for OS registration.")
        return user

    def systemd_definition(self, username: str, home: str | None = None) -> str:
        command = " ".join(systemd_quote(value, executable=True) for value in [str(self.python), *self.arguments])
        environment = f"Environment={systemd_quote('HOME=' + home)}\n" if home else ""
        return ("[Unit]\nDescription=GreatMigration\nWants=network-online.target\nAfter=network-online.target\n"
                "StartLimitIntervalSec=300\nStartLimitBurst=3\n\n[Service]\nType=exec\n"
                f"User={username}\n{environment}WorkingDirectory={systemd_quote(str(self.project))}\nExecStart={command}\n"
                "Restart=on-failure\nRestartSec=10\nTimeoutStopSec=30\nKillMode=control-group\n"
                "UMask=0077\n\n[Install]\nWantedBy=multi-user.target\n")

    def launchd_definition(self, username: str, home: str | None = None) -> bytes:
        definition = {"Label": self.label, "ProgramArguments": [str(self.python), *self.arguments],
                               "UserName": username, "WorkingDirectory": str(self.project),
                               "RunAtLoad": True, "KeepAlive": {"SuccessfulExit": False},
                               "ThrottleInterval": 30, "ExitTimeOut": 30,
                               "StandardOutPath": str(self.log_path), "StandardErrorPath": str(self.log_path)}
        if home:
            definition["EnvironmentVariables"] = {"HOME": home, "USER": username, "LOGNAME": username}
        return plistlib.dumps(definition)

    def windows_registration(self, username: str) -> str:
        # This encoded payload contains paths/account name only. The account password is
        # obtained in the native elevated process and never travels through Python/argv/files.
        payload = base64.b64encode(json.dumps({"name": self.name, "python": str(self.python),
                    "arguments": subprocess.list2cmdline(self.arguments), "directory": str(self.project),
                    "user": username}).encode()).decode()
        return (f"$p = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('{payload}')) | ConvertFrom-Json; "
                "$action = New-ScheduledTaskAction -Execute $p.python -Argument $p.arguments -WorkingDirectory $p.directory; "
                "$trigger = New-ScheduledTaskTrigger -AtStartup; $trigger.Delay = 'PT30S'; "
                "$settings = New-ScheduledTaskSettingsSet -MultipleInstances IgnoreNew "
                "-ExecutionTimeLimit ([TimeSpan]::Zero) -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1) "
                "-AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable; "
                "$existing = Get-ScheduledTask -TaskName $p.name -ErrorAction SilentlyContinue; "
                "if ($null -ne $existing) { "
                "if ($existing.Principal.UserId -ne $p.user) { throw 'Task belongs to another account; inspect Task Scheduler.' }; "
                "Set-ScheduledTask -TaskName $p.name -Action $action -Trigger $trigger -Settings $settings | Out-Null; "
                "Enable-ScheduledTask -TaskName $p.name | Out-Null "
                "} else { "
                "$credential = Get-Credential -UserName $p.user -Message 'GreatMigration: Windows account password for startup before sign-in (not your app password or PIN)'; "
                "if ($null -eq $credential -or $credential.UserName -ne $p.user) { throw 'Registration cancelled or account changed' }; "
                "Register-ScheduledTask -TaskName $p.name -Action $action -Trigger $trigger -Settings $settings "
                "-User $p.user -Password $credential.GetNetworkCredential().Password -RunLevel Limited | Out-Null }")

    def _elevated_windows(self, script: str):
        wrapped = "$ErrorActionPreference = 'Stop'; try { " + script + "; exit 0 } catch { [Console]::Error.WriteLine($_.Exception.Message); exit 1 }"
        encoded = encoded_ps(wrapped)
        # Elevate only this native registration operation, never the app or full setup.
        self._ps(f"$code = '{encoded}'; "
                 "$admin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator); "
                 "if ($admin) { & ([ScriptBlock]::Create([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String($code)))) } else { "
                 f"$p = Start-Process powershell.exe -Verb RunAs -WindowStyle Hidden -Wait -PassThru "
                 "-ArgumentList @('-NoProfile', '-EncodedCommand', $code); "
                 "if ($p.ExitCode -ne 0) { throw 'Task registration/control failed or was cancelled. Check account password, batch-logon rights, and task permissions.' } }", interactive=True)

    def enable(self):
        self._supported()
        owner = self._owner()
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        # Precreate as the app user so launchd cannot create a root-owned log.
        self.log_path.touch(exist_ok=True)
        self.state.mkdir(parents=True, exist_ok=True, mode=0o700)
        if self.kind == "windows":
            if not self.installed() and not sys.stdin.isatty():
                raise RuntimeError("Initial Windows boot registration needs an interactive Windows credential prompt. Run autostart enable in a terminal.")
            self._elevated_windows(self.windows_registration(owner))
            return
        if os.name != "nt" and os.geteuid() == 0:
            os.chown(self.log_path, owner.pw_uid, owner.pw_gid)
            os.chown(self.state, owner.pw_uid, owner.pw_gid)
        content = (self.systemd_definition(owner.pw_name, owner.pw_dir).encode() if self.kind == "systemd"
                   else self.launchd_definition(owner.pw_name, owner.pw_dir))
        previous = self.definition_path.read_bytes() if self.definition_path.exists() else None
        with tempfile.TemporaryDirectory(prefix="greatmigration-service-") as directory:
            source = Path(directory) / "definition"
            source.write_bytes(content)
            try:
                self._privileged("install", "-o", "root", "-m", "644", str(source), str(self.definition_path))
                if self.kind == "systemd":
                    self._privileged("systemctl", "daemon-reload")
                    self._privileged("systemctl", "enable", self.name)
                else:
                    self._privileged("launchctl", "enable", f"system/{self.label}")
            except Exception:
                # Registration failure must not leave a new half-installed service.
                if previous is None:
                    if self.kind == "systemd":
                        try:
                            self._privileged("systemctl", "disable", self.name)
                        except RuntimeError:
                            pass
                    self._privileged("rm", "-f", "--", str(self.definition_path))
                else:
                    source.write_bytes(previous)
                    self._privileged("install", "-o", "root", "-m", "644", str(source), str(self.definition_path))
                if self.kind == "systemd":
                    self._privileged("systemctl", "daemon-reload")
                raise

    def start(self):
        self._supported()
        (self.state / "restart-history.json").unlink(missing_ok=True)
        if self.kind == "windows":
            self._ps(f"Start-ScheduledTask -TaskName '{self.name}'")
        elif self.kind == "systemd":
            self._privileged("systemctl", "reset-failed", self.name)
            self._privileged("systemctl", "start", self.name)
        else:
            loaded = self._run(["launchctl", "print", f"system/{self.label}"], check=False).returncode == 0
            if loaded:
                self._privileged("launchctl", "kickstart", f"system/{self.label}")
            else:
                self._privileged("launchctl", "bootstrap", "system", str(self.definition_path))

    def stop(self):
        self._supported()
        if self.kind == "windows":
            if not self.running():
                return
            # Task Scheduler's End operation can kill Python before it flushes data.
            # Request graceful Uvicorn shutdown through a per-run nonce in private state.
            from quickstart import atomic_json
            try:
                runtime = json.loads((self.state / "runtime.json").read_text(encoding="utf-8"))
            except (OSError, ValueError) as exc:
                raise RuntimeError("Running task has no control record. Stop it manually in Task Scheduler before upgrading.") from exc
            if not runtime.get("managed"):
                raise RuntimeError("The running app is a foreground instance. Stop it with Ctrl+C.")
            atomic_json(self.state / "stop.json", {"token": runtime["token"]})
            deadline = time.monotonic() + 30
            while time.monotonic() < deadline:
                if not self.running():
                    return
                time.sleep(0.25)
            raise RuntimeError("Scheduled task did not stop gracefully. Inspect its logs; upgrade has not modified app files.")
        elif self.kind == "systemd":
            self._privileged("systemctl", "stop", self.name)
        else:
            if self._run(["launchctl", "print", f"system/{self.label}"], check=False).returncode == 0:
                self._privileged("launchctl", "bootout", f"system/{self.label}")

    def disable(self):
        self._supported()
        if self.kind == "windows":
            self._elevated_windows(f"Unregister-ScheduledTask -TaskName '{self.name}' -Confirm:$false")
        else:
            if self.kind == "systemd":
                self._privileged("systemctl", "disable", self.name)
            self._privileged("rm", "-f", "--", str(self.definition_path))
            if self.kind == "systemd":
                self._privileged("systemctl", "daemon-reload")
