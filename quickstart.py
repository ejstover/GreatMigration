#!/usr/bin/env python3
"""Launch the installed app. Setup and network updates are explicit commands."""
from __future__ import annotations

import argparse
import os
import secrets
import sys
import subprocess
import json
from pathlib import Path
import shutil
import re
import socket
import time
from contextlib import contextmanager
from typing import Dict
from getpass import getpass

QUICKSTART_PROTOCOL = 1
DEFAULT_REPO = "https://github.com/ejstover/GreatMigration.git"
DEFAULT_BRANCH = "main"

# ---------- Utilities ----------

def run(cmd, cwd: Path | None = None, env: Dict[str, str] | None = None, check: bool = True):
    print(f"\n> {' '.join(cmd)}" + (f"   (cwd={cwd})" if cwd else ""))
    proc = subprocess.run(cmd, cwd=str(cwd) if cwd else None, env=env)
    if check and proc.returncode != 0:
        raise SystemExit(f"Command failed with exit code {proc.returncode}: {' '.join(cmd)}")
    return proc.returncode

def which_or_die(name: str):
    if shutil.which(name) is None:
        raise SystemExit(f"Required tool '{name}' not found on PATH.")
    return name

def venv_python_path(venv_dir: Path) -> Path:
    # Windows: .venv/Scripts/python.exe ; POSIX: .venv/bin/python
    win = os.name == "nt"
    return venv_dir / ("Scripts/python.exe" if win else "bin/python")

def safe_source(value: str) -> str:
    return re.sub(r"(https?://)([^/\s]+)", lambda match: match[1] + (
        "[redacted]@" + match[2].rsplit("@", 1)[1] if "@" in match[2] else match[2]), value)


def git(project: Path, *args: str, check: bool = True):
    result = subprocess.run(["git", *args], cwd=project, capture_output=True, text=True)
    if check and result.returncode:
        raise RuntimeError(safe_source(result.stderr.strip()) or f"Git {args[0]} failed")
    return result


def update_source(args, project: Path):
    settings = load_env_from_file(project / "backend" / ".env")
    repo = args.repo or settings.get("QUICKSTART_REPO_URL") or os.getenv("QUICKSTART_REPO_URL") or DEFAULT_REPO
    branch = args.branch or settings.get("QUICKSTART_BRANCH") or os.getenv("QUICKSTART_BRANCH") or DEFAULT_BRANCH
    if repo.startswith("-") or "\n" in repo or "\r" in repo or repo.startswith("ext::"):
        raise RuntimeError("Invalid repository source")
    return repo, branch


def ensure_git_repo(repo_url: str, target_dir: Path, branch: str):
    # Setup of an existing checkout (or a source archive) never updates it.
    if (target_dir / "backend" / "app.py").is_file():
        return
    which_or_die("git")
    target_dir.parent.mkdir(parents=True, exist_ok=True)
    git(target_dir.parent, "check-ref-format", "--branch", branch)
    print(f"Cloning {safe_source(repo_url)} ({branch}) into {target_dir}")
    git(target_dir.parent, "clone", "--branch", branch, "--", repo_url, str(target_dir))

def ensure_venv(project_dir: Path) -> Path:
    venv_dir = project_dir / ".venv"
    if not venv_python_path(venv_dir).is_file():
        print("Creating virtual environment (.venv) ...")
        # On some minimal Linux installs the ensurepip module is missing.
        # This results in a cryptic failure from `python -m venv`.  Check for
        # it up front so we can provide a helpful message.
        try:
            import ensurepip  # noqa: F401
        except ModuleNotFoundError:
            raise SystemExit(
                "Python's ensurepip module is required to create virtual environments.\n"
                "Install the 'python3-venv' package and retry.\n"
                "For example on Debian/Ubuntu: sudo apt install python3-venv"
            )

        # Prefer 'py -3' on Windows if available
        py = shutil.which("py")
        if py and os.name == "nt":
            run([py, "-3", "-m", "venv", str(venv_dir)])
        else:
            run([sys.executable, "-m", "venv", str(venv_dir)])
    return venv_dir

def pip(venv_python: Path, *args: str):
    cmd = [str(venv_python), "-m", "pip", *args]
    return run(cmd)

def ensure_requirements(project_dir: Path, venv_python: Path):
    # Some environments may have a venv without pip installed.  Attempt to
    # detect and bootstrap pip in that case so subsequent installs succeed.
    if run([str(venv_python), "-m", "pip", "--version"], check=False) != 0:
        print("pip not found; bootstrapping with ensurepip ...")
        run([str(venv_python), "-m", "ensurepip", "--upgrade"])

    print("Upgrading pip ...")
    pip(venv_python, "install", "--upgrade", "pip", "wheel", "setuptools")

    req = project_dir / "backend" / "requirements.txt"
    if req.exists():
        print(f"Installing dependencies from {req} ...")
        pip(venv_python, "install", "-r", str(req))
    else:
        print("requirements.txt not found; installing core deps ...")
        pip(
            venv_python,
            "install",
            "fastapi==0.163.1",
            "uvicorn==0.54.0",
            "python-multipart==0.0.34",
            "jinja2==3.1.6",
            "requests",
            "ciscoconfparse>=1.6.52",
            "python-dotenv",
        )


def ensure_env_file(project_dir: Path) -> int | None:
    env_file = project_dir / "backend" / ".env"
    if env_file.exists():
        print(f"Found {env_file}")
        env = load_env_from_file(env_file)
        port_val = env.get("API_PORT")
        return int(port_val) if port_val and port_val.isdigit() else None

    if not sys.stdin.isatty():
        raise RuntimeError("Create backend/.env from .env.sample and configure accounts before noninteractive setup.")
    env_sample = project_dir / ".env.sample"
    print("\nCreating backend/.env (first run). Values are stored locally in this file.")
    token = getpass("MIST_TOKEN (input hidden): ").strip()
    base = input("MIST_BASE_URL [default https://api.ac2.mist.com]: ").strip() or "https://api.ac2.mist.com"
    org = input("MIST_ORG_ID (optional): ").strip()
    tmpl = input("SWITCH_TEMPLATE_ID (optional): ").strip()
    port = input("API_PORT [default 8000]: ").strip() or "8000"
    if not port.isdigit() or not 1 <= int(port) <= 65535:
        raise RuntimeError("API_PORT must be between 1 and 65535")
    auth = input("AUTH_METHOD [default local]: ").strip().lower() or "local"
    if auth not in {"local", "ldap"}:
        raise RuntimeError("AUTH_METHOD must be local or ldap")
    syslog_host = input("SYSLOG_HOST (optional): ").strip()
    syslog_port = input("SYSLOG_PORT [default 514]: ").strip() or "514"

    lines = [
        f"AUTH_METHOD={auth}",
        f"SESSION_SECRET={secrets.token_urlsafe(48)}",
        "SESSION_HTTPS_ONLY=false",
        "APP_HOST=127.0.0.1",
        f"QUICKSTART_REPO_URL={DEFAULT_REPO}",
        f"QUICKSTART_BRANCH={DEFAULT_BRANCH}",
        f"MIST_TOKEN={token}",
        f"MIST_BASE_URL={base}",
        f"MIST_ORG_ID={org}",
        f"SWITCH_TEMPLATE_ID={tmpl}",
        "HELP_URL=https://github.com/ejstover/GreatMigration/blob/main/README.md",
    ]

    if auth == "ldap":
        print("LDAP selected. Update backend/.env with correct LDAP settings.")
        if env_sample.exists():
            sample_lines = env_sample.read_text().splitlines()
            ldap_lines = [
                ln.lstrip("# ").rstrip()
                for ln in sample_lines
                if ln.startswith(("# LDAP_", "# PUSH_GROUP_DN", "# READONLY_GROUP_DN"))
            ]
            lines.extend(ldap_lines)
        else:
            lines.extend([
                "LDAP_SERVER_URL=",
                "LDAP_SEARCH_BASE=",
                "LDAP_BIND_TEMPLATE=",
                "PUSH_GROUP_DN=",
                "LDAP_SERVICE_DN=",
                "LDAP_SERVICE_PASSWORD=",
            ])
    else:
        user = input("Local username: ").strip()
        if not user or any(c in user for c in ",:\r\n"):
            raise RuntimeError("Local username must be nonempty and cannot contain commas or colons")
        pwd = getpass("Local password, at least 12 characters (input hidden): ")
        while len(pwd) < 12:
            pwd = getpass("Choose at least 12 characters (input hidden): ")
        pwd_hash = subprocess.run([str(venv_python_path(project_dir / ".venv")), str(project_dir / "backend" / "security_setup.py"), "--hash-password"], input=pwd, encoding="utf-8", capture_output=True, check=True).stdout.strip()
        lines.append(f"LOCAL_USERS={user}:{pwd_hash}")
        lines.append(f"LOCAL_PUSH_USERS={user}")

    lines.append(f"API_PORT={port}")
    if syslog_host:
        lines.append(f"SYSLOG_HOST={syslog_host}")
        if syslog_port:
            lines.append(f"SYSLOG_PORT={syslog_port}")

    env_file.parent.mkdir(parents=True, exist_ok=True)
    env_file.write_text("\n".join(lines) + "\n", encoding="utf-8")
    if os.name != "nt":
        env_file.chmod(0o600)
    print(f"Wrote {env_file}")
    return int(port)

def ensure_standard_fw_versions_file(project_dir: Path):
    backend = project_dir / "backend"
    dest = backend / "standard_fw_versions.json"
    if not dest.exists():
        default_content = {
            "generated_at": None,
            "models": {
                "switch": {},
                "ap": {}
            }
        }
        dest.write_text(json.dumps(default_content, indent=2), encoding="utf-8")
        print(f"Created default {dest}")

def ensure_tmp_dirs(project_dir: Path):
    tmp_ssh_jobs = project_dir / "tmp_ssh_jobs"
    if not tmp_ssh_jobs.exists():
        tmp_ssh_jobs.mkdir(parents=True, exist_ok=True)
        print(f"Created {tmp_ssh_jobs}")
    
    logs_dir = project_dir / "backend" / "logs"
    if not logs_dir.exists():
        logs_dir.mkdir(parents=True, exist_ok=True)
        print(f"Created {logs_dir}")

def ensure_port_rules_file(project_dir: Path):
    backend = project_dir / "backend"
    sample = backend / "port_rules.sample.json"
    dest = backend / "port_rules.json"
    if dest.exists():
        print(f"Found {dest}")
    elif sample.exists():
        shutil.copy(sample, dest)
        print(f"Copied {sample} to {dest}")
    else:
        # Create an empty one if no sample found
        dest.write_text("[]\n", encoding="utf-8")
        print(f"Created empty {dest}")

def load_env_from_file(env_path: Path) -> Dict[str, str]:
    """Very small .env loader to pass vars to uvicorn process in case app doesn't load automatically."""
    out: Dict[str, str] = {}
    if not env_path.exists():
        return out
    for raw in env_path.read_text(encoding="utf-8-sig").splitlines():
        line = raw.strip()
        if line.startswith("export "):
            line = line[7:].lstrip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            continue
        key, val = line.split("=", 1)
        key = key.strip()
        val = val.strip()
        if val.startswith(("\"", "'")):
            quote = val[0]
            end = val.find(quote, 1)
            val = val[1:end] if end >= 0 else val[1:]
        else:
            val = re.split(r"\s+#", val, maxsplit=1)[0].rstrip()
        if key:
            out[key] = val
    return out


def state_dir(project: Path) -> Path:
    return project / "backend" / "data" / "quickstart"


def atomic_json(path: Path, value):
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    temporary = path.with_name(path.name + "." + secrets.token_hex(6) + ".tmp")
    try:
        temporary.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")
        if os.name != "nt":
            temporary.chmod(0o600)
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


@contextmanager
def exclusive_lock(path: Path):
    """An OS-owned lock, released even if the launcher crashes."""
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    with path.open("a+b") as handle:
        if handle.tell() == 0:
            handle.write(b"\0")
            handle.flush()
        handle.seek(0)
        try:
            if os.name == "nt":
                import msvcrt
                msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as exc:
            raise RuntimeError("Another quickstart operation or app instance is already running.") from exc
        try:
            yield
        finally:
            handle.seek(0)
            if os.name == "nt":
                msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                fcntl.flock(handle, fcntl.LOCK_UN)


def listener(project: Path, override: int | None = None):
    values = dict(os.environ)
    values.update(load_env_from_file(project / "backend" / ".env"))
    try:
        port = override if override is not None else int(values.get("API_PORT", "8000"))
        if not 1 <= port <= 65535:
            raise ValueError
    except ValueError:
        raise RuntimeError("API_PORT/--port must be between 1 and 65535") from None
    return values.get("APP_HOST") or "127.0.0.1", port


def listener_open(host: str, port: int) -> bool:
    host = {"0.0.0.0": "127.0.0.1", "::": "::1"}.get(host, host)
    try:
        with socket.create_connection((host, port), timeout=0.3):
            return True
    except OSError:
        return False


def validate_install(project: Path):
    required = [project / "backend" / ".env", project / "backend" / "app.py",
                venv_python_path(project / ".venv"), project / "scripts" / "quickstart_runtime.py"]
    missing = [str(path) for path in required if not path.is_file()]
    if missing:
        raise RuntimeError("Installation is incomplete. Run quickstart setup first. Missing: " + ", ".join(missing))
    listener(project)


def service_manager(project: Path):
    from scripts.quickstart_services import ServiceManager
    return ServiceManager(project)


def start_api(project_dir: Path, venv_python: Path, port: int):
    host, _ = listener(project_dir, port)
    if listener_open(host, port):
        print(f"Listener already in use at {host}:{port}; no second instance started.")
        return
    print(f"Starting API at http://{host}:{port} (Ctrl+C to stop)", flush=True)
    command = [str(venv_python), str(project_dir / "scripts" / "quickstart_runtime.py"),
               "--dir", str(project_dir), "--port", str(port)]
    try:
        run(command, cwd=project_dir)
    except KeyboardInterrupt:
        print("\nStopped by user.")


def launch(project: Path, port: int | None = None):
    validate_install(project)
    with exclusive_lock(state_dir(project) / "upgrade.lock"):
        _launch(project, port)


def _launch(project: Path, port: int | None = None):
    """Launch while the caller owns the installation's maintenance lock."""
    manager = service_manager(project)
    host, configured_port = listener(project)
    if manager.installed():
        if port is not None and port != configured_port:
            raise RuntimeError("Managed startup uses API_PORT. Edit backend/.env and run quickstart restart.")
        if not manager.running():
            if listener_open(host, configured_port):
                raise RuntimeError("A foreground/manual instance occupies the listener. Stop it first.")
            manager.start()
        wait_ready(manager, host, configured_port)
        print(f"GreatMigration is running at http://{host}:{configured_port}. Logs: {manager.log_path}")
    else:
        start_api(project, venv_python_path(project / ".venv"), port or configured_port)


def wait_ready(manager, host: str, port: int, timeout: float = 30):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if manager.running() and listener_open(host, port):
            return
        time.sleep(0.25)
    raise RuntimeError(f"App did not become ready within {timeout:g}s. Logs: {manager.log_path}")


def stop_service(manager, host: str, port: int):
    manager.stop()
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        if not manager.running() and not listener_open(host, port):
            return
        time.sleep(0.25)
    raise RuntimeError("Could not confirm shutdown; no application files have been updated.")


def install_dependencies(project: Path):
    vpython = venv_python_path(ensure_venv(project))
    ensure_requirements(project, vpython)
    run([str(vpython), str(project / "backend" / "security_setup.py")], cwd=project)
    return vpython


def ensure_local_account(project: Path, vpython: Path):
    settings = load_env_from_file(project / "backend" / ".env")
    if settings.get("AUTH_METHOD") != "local":
        return
    filename = settings.get("LOCAL_USERS_FILE") or "data/local_users.json"
    accounts = project / "backend" / filename
    if accounts.exists():
        users = json.loads(accounts.read_text(encoding="utf-8"))
        if not isinstance(users, dict):
            raise RuntimeError("Local account database is invalid; repair it before starting.")
        if users:
            return
    if not sys.stdin.isatty():
        raise RuntimeError("No local accounts exist. Run backend/security_setup.py --add-user USERNAME before starting.")
    user = input("Initial local username (push-enabled): ").strip()
    run([str(vpython), str(project / "backend" / "security_setup.py"), "--add-user", user, "--push"], cwd=project)


def setup(project: Path, args):
    repo, branch = update_source(args, project)
    ensure_git_repo(repo, project, branch)
    # A downloaded launcher can bootstrap another checkout, then use that checkout's code.
    if project / "quickstart.py" != Path(__file__).resolve():
        command = [sys.executable, str(project / "quickstart.py"), "setup", "--dir", str(project)]
        if args.port is not None:
            command.extend(["--port", str(args.port)])
        if args.no_start:
            command.append("--no-start")
        if args.autostart is not None:
            command.append("--autostart" if args.autostart else "--no-autostart")
        run(command, cwd=project)
        return
    with exclusive_lock(state_dir(project) / "upgrade.lock"):
        _setup_existing(project, args)


def _setup_existing(project: Path, args):
    manager = service_manager(project)
    host, port = listener(project)
    if manager.installed() and manager.running():
        if args.autostart is False:
            stop_service(manager, host, port)
        else:
            raise RuntimeError("Stop the managed app before running setup, then start it again afterward.")
    if listener_open(host, port):
        raise RuntimeError("Stop the foreground/manual app before running setup.")
    vpython = venv_python_path(ensure_venv(project))
    ensure_requirements(project, vpython)
    ensure_env_file(project)
    run([str(vpython), str(project / "backend" / "security_setup.py")], cwd=project)
    ensure_local_account(project, vpython)
    ensure_port_rules_file(project)
    ensure_standard_fw_versions_file(project)
    ensure_tmp_dirs(project)
    manager = service_manager(project)
    choice = args.autostart
    if choice is None and not manager.installed() and sys.stdin.isatty():
        choice = input("Start GreatMigration automatically when this computer boots? [y/N] ").strip().lower() in {"y", "yes"}
    if choice is not None:
        try:
            if choice:
                manager.enable()
            elif manager.installed():
                stop_service(manager, *listener(project))
                manager.disable()
        except (RuntimeError, OSError, subprocess.SubprocessError) as exc:
            print(f"Setup succeeded, but automatic startup could not be changed: {exc}")
            if manager.installed():
                raise RuntimeError("Check quickstart autostart status before launching.") from exc
    print("Setup complete.")
    if not args.no_start:
        _launch(project, args.port)


def upgrade_preflight(project: Path, args, record=None):
    which_or_die("git")
    repo, branch = update_source(args, project)
    if record is None:
        record = {}
    record.update(source=safe_source(repo), branch=branch)
    root = Path(git(project, "rev-parse", "--show-toplevel").stdout.strip()).resolve()
    if root != project:
        raise RuntimeError("Upgrade must target the root of an initialized checkout")
    git(project, "check-ref-format", "--branch", branch)
    if git(project, "status", "--porcelain", "--untracked-files=all").stdout.strip():
        raise RuntimeError("Checkout contains local changes or untracked files. Preserve them before upgrading.")
    current_branch = git(project, "symbolic-ref", "--short", "HEAD", check=False)
    if current_branch.returncode:
        raise RuntimeError("Select a local branch before upgrading (HEAD is detached).")
    old = git(project, "rev-parse", "HEAD").stdout.strip()
    record.update(old_revision=old, stage="fetching source")
    git(project, "fetch", "--no-tags", "--", repo, f"refs/heads/{branch}")
    new = git(project, "rev-parse", "FETCH_HEAD").stdout.strip()
    record.update(new_revision=new, stage="validating fast-forward")
    if git(project, "merge-base", "--is-ancestor", old, new, check=False).returncode:
        raise RuntimeError("Source is unrelated or diverges from this checkout; a fast-forward is required.")
    target = git(project, "rev-parse", "--verify", f"refs/heads/{branch}", check=False)
    if not target.returncode and git(project, "merge-base", "--is-ancestor", target.stdout.strip(), new, check=False).returncode:
        raise RuntimeError("Requested local branch has commits that would be lost; resolve it manually.")
    launcher = git(project, "show", f"{new}:quickstart.py").stdout
    if "QUICKSTART_PROTOCOL = 1" not in launcher:
        raise RuntimeError("Selected revision lacks the supported quickstart upgrade protocol; upgrade manually.")
    for path in ("backend/requirements.txt", "backend/security_setup.py", "scripts/quickstart_runtime.py", "scripts/quickstart_services.py"):
        git(project, "cat-file", "-e", f"{new}:{path}")
    print(f"Upgrade source: {safe_source(repo)}\nBranch: {branch}\nCurrent: {old}\nIntended: {new}", flush=True)
    return {"old_revision": old, "new_revision": new, "branch": branch,
            "source": safe_source(repo), "previous_branch": current_branch.stdout.strip()}


def upgrade(project: Path, args):
    validate_install(project)
    with exclusive_lock(state_dir(project) / "upgrade.lock"):
        record = {"stage": "preflight", "status": "running", "restart": False,
                  "token": secrets.token_hex(24)}
        journal = state_dir(project) / "upgrade.json"
        try:
            record.update(upgrade_preflight(project, args, record))
            manager = service_manager(project)
            host, port = listener(project)
            installed = manager.installed()
            running = installed and manager.running()
            if not running and listener_open(host, port):
                raise RuntimeError("Stop the foreground/manual app before upgrading.")
            record["restart"] = bool(running and not args.no_start)
            record["stage"] = "stopping service"
            atomic_json(journal, record)
            # Also unload an idle launchd job so its pending retry cannot race updates.
            if installed:
                stop_service(manager, host, port)
            if git(project, "status", "--porcelain", "--untracked-files=all").stdout.strip():
                raise RuntimeError("Checkout changed during preflight; upgrade stopped.")
            record["stage"] = "updating checkout"
            atomic_json(journal, record)
            if record["previous_branch"] != record["branch"]:
                exists = git(project, "show-ref", "--verify", "--quiet", f"refs/heads/{record['branch']}", check=False).returncode == 0
                git(project, "switch", *([] if exists else ["-c"]), record["branch"])
            git(project, "merge", "--ff-only", record["new_revision"])
            record["stage"] = "updated launcher"
            atomic_json(journal, record)
            result = subprocess.run([str(venv_python_path(project / ".venv")), str(project / "quickstart.py"),
                                     "--dir", str(project), "--_finish-upgrade", record["token"]], cwd=project)
            if result.returncode:
                saved = json.loads(journal.read_text(encoding="utf-8"))
                if saved.get("status") != "failed":
                    saved.update(status="failed", error=f"Updated launcher exited {result.returncode}")
                    atomic_json(journal, saved)
                raise RuntimeError(f"Updated launcher failed. See {journal}; the service remains stopped.")
            saved = json.loads(journal.read_text(encoding="utf-8"))
            if saved.get("token") != record["token"] or saved.get("status") != "complete":
                raise RuntimeError("Updated launcher exited without confirming completion; inspect the recovery record.")
        except (Exception, SystemExit) as exc:
            saved = json.loads(journal.read_text(encoding="utf-8")) if journal.exists() else {}
            if saved.get("token") != record["token"] or saved.get("status") != "failed":
                record.update(status="failed", error=safe_source(str(exc)))
                atomic_json(journal, record)
            raise RuntimeError(f"Upgrade failed: {exc}\nRecovery record: {journal}. Resolve the failing stage, then run setup --no-start and start. No rollback was performed.") from exc


def finish_upgrade(project: Path, token: str):
    journal = state_dir(project) / "upgrade.json"
    record = json.loads(journal.read_text(encoding="utf-8"))
    if record.get("token") != token or record.get("stage") != "updated launcher" or record.get("status") != "running":
        raise RuntimeError("Invalid or already consumed upgrade continuation")
    if git(project, "rev-parse", "HEAD").stdout.strip() != record["new_revision"]:
        raise RuntimeError("Checkout changed before upgrade continuation")
    try:
        record["stage"] = "installing dependencies and migrating security"
        atomic_json(journal, record)
        install_dependencies(project)
        if record["restart"]:
            record["stage"] = "restarting service"
            atomic_json(journal, record)
            _launch(project)
        record.update(stage="complete", status="complete")
        atomic_json(journal, record)
        print(f"Upgrade complete: {record['old_revision']} -> {record['new_revision']}")
    except (Exception, SystemExit) as exc:
        record.update(status="failed", error=safe_source(str(exc)))
        atomic_json(journal, record)
        manager = service_manager(project)
        if manager.installed() and manager.running():
            stop_service(manager, *listener(project))
        raise


def parse_args(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", nargs="?", choices=["start", "setup", "upgrade", "stop", "restart", "status", "autostart"])
    parser.add_argument("action", nargs="?", choices=["enable", "disable", "status"])
    parser.add_argument("--repo", help="Clone/upgrade repository override; defaults to QUICKSTART_REPO_URL.")
    parser.add_argument("--dir", dest="target_dir", default=".", help="Project directory (default: current directory).")
    parser.add_argument("--branch", help="Clone/upgrade branch override; defaults to QUICKSTART_BRANCH or main.")
    parser.add_argument("--port", type=int, help="Foreground port override (default: API_PORT or 8000).")
    parser.add_argument("--no-start", action="store_true", help="Setup without launch, or upgrade without restarting.")
    automatic = parser.add_mutually_exclusive_group()
    automatic.add_argument("--autostart", dest="autostart", action="store_true", default=None, help="Enable boot startup during setup.")
    automatic.add_argument("--no-autostart", dest="autostart", action="store_false", help="Disable boot startup during setup.")
    parser.add_argument("--_finish-upgrade", help=argparse.SUPPRESS)
    args = parser.parse_intermixed_args(argv)
    args.command = args.command or ("setup" if args.no_start else "start")
    if args.command == "autostart" and args.action is None:
        args.action = "status"
    if args.action and args.command != "autostart":
        parser.error("enable/disable/status actions are only valid after autostart")
    if args.autostart is not None and args.command != "setup":
        parser.error("--autostart/--no-autostart require setup")
    if args.no_start and args.command not in {"setup", "upgrade"}:
        parser.error("--no-start requires setup or upgrade")
    if (args.repo or args.branch) and args.command not in {"setup", "upgrade"}:
        parser.error("--repo/--branch require explicit setup or upgrade")
    if args.port is not None and (not 1 <= args.port <= 65535 or args.command not in {"start", "setup"}):
        parser.error("--port requires start/setup and a value from 1 to 65535")
    return args


def main(argv=None):
    args = parse_args(argv)
    project = Path(args.target_dir).expanduser().resolve()
    if args._finish_upgrade:
        finish_upgrade(project, args._finish_upgrade)
    elif args.command == "setup":
        setup(project, args)
    elif args.command == "upgrade":
        upgrade(project, args)
    elif args.command == "start":
        launch(project, args.port)
    else:
        manager = service_manager(project)
        installed = manager.installed()
        if args.command == "status" or (args.command == "autostart" and args.action == "status"):
            print(f"Reboot startup: {'enabled' if installed else 'disabled'} ({manager.kind})")
            print(f"OS service: {'running' if installed and manager.running() else 'stopped'}")
            host, port = listener(project)
            print(f"Listener {host}:{port}: {'in use' if listener_open(host, port) else 'stopped'}")
            print(f"Logs: {manager.log_path}")
        elif args.command == "autostart" and args.action == "enable":
            validate_install(project)
            with exclusive_lock(state_dir(project) / "upgrade.lock"):
                manager.enable()
            print("Reboot startup enabled. Run quickstart start to launch now.")
        elif not installed:
            if args.command == "autostart":
                print("Reboot startup is already disabled.")
            else:
                raise RuntimeError("No OS service is installed. Stop a foreground app with Ctrl+C; use quickstart start to launch.")
        elif args.command in {"stop", "restart"} or args.action == "disable":
            with exclusive_lock(state_dir(project) / "upgrade.lock"):
                stop_service(manager, *listener(project))
                if args.action == "disable":
                    manager.disable()
                    print("Reboot startup disabled and managed instance stopped.")
                elif args.command == "restart":
                    validate_install(project)
                    _launch(project)
                else:
                    print("GreatMigration stopped.")


if __name__ == "__main__":
    try:
        main()
    except (RuntimeError, OSError, subprocess.SubprocessError, ValueError) as error:
        print(f"Error: {safe_source(str(error))}", file=sys.stderr)
        sys.exit(1)
