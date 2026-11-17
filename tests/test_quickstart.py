"""Launcher tests use synthetic installations, local Git sources, and mocked OS services."""
from __future__ import annotations

import base64
import json
import os
from pathlib import Path
import plistlib
import shutil
import socket
import subprocess
import sys
import time
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import quickstart as q  # noqa: E402
from scripts import quickstart_runtime as runtime  # noqa: E402
from scripts import quickstart_services as services  # noqa: E402


@pytest.fixture
def project(tmp_path):
    path = tmp_path / "installation with spaces"
    for name in ("backend/.env", "backend/app.py", "scripts/quickstart_runtime.py", "scripts/quickstart_services.py"):
        file = path / name
        file.parent.mkdir(parents=True, exist_ok=True)
        file.write_text("", encoding="utf-8")
    (path / "backend/.env").write_text("API_PORT=8765\nAPP_HOST=127.0.0.1\n", encoding="utf-8")
    python = q.venv_python_path(path / ".venv")
    python.parent.mkdir(parents=True)
    python.touch()
    return path


@pytest.fixture
def manager(monkeypatch):
    instance = Mock()
    instance.installed.return_value = False
    instance.running.return_value = False
    instance.kind = "synthetic"
    instance.log_path = "synthetic.log"
    monkeypatch.setattr(q, "service_manager", lambda project: instance)
    return instance


@pytest.mark.parametrize("argv,command,action", [([], "start", None), (["--no-start"], "setup", None),
    (["setup", "--no-start"], "setup", None), (["upgrade", "--no-start"], "upgrade", None),
    (["autostart"], "autostart", "status"), (["autostart", "enable"], "autostart", "enable")])
def test_commands(argv, command, action):
    args = q.parse_args(argv)
    assert (args.command, args.action) == (command, action)


@pytest.mark.parametrize("argv", [["--repo", "fork"], ["--branch", "other"], ["start", "--no-start"],
    ["start", "--autostart"], ["setup", "--autostart", "--no-autostart"], ["start", "enable"],
    ["--port", "0"], ["--port", "65536"], ["upgrade", "--port", "8000"]])
def test_invalid_combinations(argv):
    with pytest.raises(SystemExit) as exc:
        q.parse_args(argv)
    assert exc.value.code == 2


def test_default_launch_has_no_setup_git_package_or_prompt(project, manager, monkeypatch):
    for name in ("which_or_die", "ensure_git_repo", "ensure_venv", "ensure_requirements", "ensure_env_file", "install_dependencies"):
        monkeypatch.setattr(q, name, Mock(side_effect=AssertionError(f"unexpected {name}")))
    monkeypatch.setattr("builtins.input", Mock(side_effect=AssertionError("unexpected prompt")))
    monkeypatch.setattr(q, "listener_open", lambda *args: False)
    run = Mock()
    monkeypatch.setattr(q, "run", run)
    q.main(["--dir", str(project)])
    command = run.call_args.args[0]
    assert command[0] == str(q.venv_python_path(project / ".venv"))
    assert command[1] == str(project / "scripts/quickstart_runtime.py")
    assert command[-1] == "8765"
    assert "--managed" not in command


def test_missing_install_only_explains_setup(tmp_path, monkeypatch):
    monkeypatch.setattr(q, "setup", Mock(side_effect=AssertionError("no automatic setup")))
    with pytest.raises(RuntimeError, match="setup first"):
        q.main(["--dir", str(tmp_path)])
    assert list(tmp_path.iterdir()) == []


def test_existing_listener_is_not_duplicated(project, manager, monkeypatch, capsys):
    monkeypatch.setattr(q, "listener_open", lambda *args: True)
    run = Mock()
    monkeypatch.setattr(q, "run", run)
    q.launch(project)
    run.assert_not_called()
    assert "no second instance" in capsys.readouterr().out


def test_service_start_and_existing_service(project, manager, monkeypatch):
    manager.installed.return_value = True
    manager.running.return_value = False
    monkeypatch.setattr(q, "listener_open", lambda *args: False)
    ready = Mock()
    monkeypatch.setattr(q, "wait_ready", ready)
    q.launch(project)
    manager.start.assert_called_once()
    ready.assert_called_once_with(manager, "127.0.0.1", 8765)
    manager.running.return_value = True
    q.launch(project)
    manager.start.assert_called_once()
    with pytest.raises(RuntimeError, match="API_PORT"):
        q.launch(project, 9999)


def test_foreground_blocks_service_start(project, manager, monkeypatch):
    manager.installed.return_value = True
    monkeypatch.setattr(q, "listener_open", lambda *args: True)
    with pytest.raises(RuntimeError, match="foreground/manual"):
        q.launch(project)
    manager.start.assert_not_called()


def test_source_precedence_and_bom(project, monkeypatch):
    monkeypatch.setenv("QUICKSTART_REPO_URL", "environment-fork")
    monkeypatch.setenv("QUICKSTART_BRANCH", "environment-branch")
    args = q.parse_args(["upgrade"])
    assert q.update_source(args, project) == ("environment-fork", "environment-branch")
    env = project / "backend/.env"
    env.write_text('\ufeffQUICKSTART_REPO_URL="file fork" # comment\nexport QUICKSTART_BRANCH=file-branch # note\n', encoding="utf-8")
    assert q.update_source(args, project) == ("file fork", "file-branch")
    args.repo, args.branch = "cli-fork", "cli-branch"
    assert q.update_source(args, project) == ("cli-fork", "cli-branch")
    assert "cli" not in env.read_text(encoding="utf-8")
    env.write_text("", encoding="utf-8")
    monkeypatch.delenv("QUICKSTART_REPO_URL")
    monkeypatch.delenv("QUICKSTART_BRANCH")
    args.repo = args.branch = None
    assert q.update_source(args, project) == (q.DEFAULT_REPO, "main")


def test_setup_existing_checkout_never_fetches(project, monkeypatch):
    monkeypatch.setattr(q, "git", Mock(side_effect=AssertionError("setup cannot contact git")))
    q.ensure_git_repo("offline", project, "main")


def prepare_setup(project, monkeypatch, manager):
    monkeypatch.setattr(q, "__file__", str(project / "quickstart.py"))
    monkeypatch.setattr(q, "listener_open", lambda *args: False)
    for name in ("ensure_requirements", "run", "ensure_local_account"):
        monkeypatch.setattr(q, name, Mock())
    monkeypatch.setattr(q, "ensure_venv", lambda path: path / ".venv")


def test_noninteractive_repeat_setup_preserves_files(project, monkeypatch, manager):
    prepare_setup(project, monkeypatch, manager)
    monkeypatch.setattr(sys.stdin, "isatty", lambda: False)
    monkeypatch.setattr("builtins.input", Mock(side_effect=AssertionError("no prompt")))
    contents = {"backend/.env": "API_PORT=8765\nSESSION_SECRET=keep-me\n", "backend/port_rules.json": "[{\"keep\":1}]",
                "backend/standard_fw_versions.json": "{\"keep\":1}"}
    for name, value in contents.items():
        (project / name).write_text(value, encoding="utf-8")
    q.setup(project, q.parse_args(["setup", "--no-start"]))
    manager.enable.assert_not_called()
    manager.disable.assert_not_called()
    assert (project / "tmp_ssh_jobs").is_dir()
    for name, value in contents.items():
        assert (project / name).read_text(encoding="utf-8") == value


def test_setup_offers_boot_and_existing_registration_is_preserved(project, monkeypatch, manager):
    prepare_setup(project, monkeypatch, manager)
    monkeypatch.setattr(sys.stdin, "isatty", lambda: True)
    prompt = Mock(return_value="yes")
    monkeypatch.setattr("builtins.input", prompt)
    q.setup(project, q.parse_args(["setup", "--no-start"]))
    manager.enable.assert_called_once()
    assert "[y/N]" in prompt.call_args.args[0]
    manager.installed.return_value = True
    q.setup(project, q.parse_args(["setup", "--no-start"]))
    prompt.assert_called_once()
    manager.enable.assert_called_once()


def test_setup_registration_failure_allows_foreground(project, monkeypatch, manager, capsys):
    prepare_setup(project, monkeypatch, manager)
    manager.enable.side_effect = RuntimeError("permission denied")
    launch = Mock()
    monkeypatch.setattr(q, "_launch", launch)
    q.setup(project, q.parse_args(["setup", "--autostart"]))
    assert "Setup succeeded" in capsys.readouterr().out
    launch.assert_called_once_with(project, None)


def test_missing_account_noninteractive_does_not_prompt(project, monkeypatch):
    (project / "backend/.env").write_text("AUTH_METHOD=local\nLOCAL_USERS_FILE=data/local_users.json\n", encoding="utf-8")
    monkeypatch.setattr(sys.stdin, "isatty", lambda: False)
    with pytest.raises(RuntimeError, match="No local accounts"):
        q.ensure_local_account(project, Path(sys.executable))


def test_existing_account_is_preserved(project, monkeypatch):
    (project / "backend/.env").write_text("AUTH_METHOD=local\nLOCAL_USERS_FILE=data/local_users.json\n", encoding="utf-8")
    users = project / "backend/data/local_users.json"
    q.atomic_json(users, {"existing": {"can_push": False}})
    run = Mock()
    monkeypatch.setattr(q, "run", run)
    q.ensure_local_account(project, Path(sys.executable))
    run.assert_not_called()
    assert not json.loads(users.read_text())["existing"]["can_push"]


def git(path, *args):
    result = subprocess.run(["git", "-C", str(path), *args], capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    return result.stdout.strip()


@pytest.fixture
def repositories(tmp_path):
    if not shutil.which("git"):
        pytest.skip("Git unavailable")
    source = tmp_path / "source fork"
    source.mkdir()
    git(source, "init", "-b", "main")
    git(source, "config", "user.name", "Synthetic Tests")
    git(source, "config", "user.email", "synthetic@example.invalid")
    for name in ("backend/app.py", "backend/requirements.txt", "backend/security_setup.py", "scripts/quickstart_runtime.py", "scripts/quickstart_services.py"):
        path = source / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("# synthetic\n", encoding="utf-8")
    (source / "quickstart.py").write_text("QUICKSTART_PROTOCOL = 1\n", encoding="utf-8")
    (source / ".gitignore").write_text(".venv/\nbackend/.env\nbackend/data/\n", encoding="utf-8")
    git(source, "add", ".")
    git(source, "commit", "-m", "initial")
    checkout = tmp_path / "installed checkout"
    git(tmp_path, "clone", str(source), str(checkout))
    git(checkout, "config", "user.name", "Synthetic Tests")
    git(checkout, "config", "user.email", "synthetic@example.invalid")
    (checkout / "backend/.env").write_text("API_PORT=8765\n", encoding="utf-8")
    python = q.venv_python_path(checkout / ".venv")
    python.parent.mkdir(parents=True)
    python.touch()
    return source, checkout


def add_revision(source, filename="incoming.txt", value="incoming"):
    (source / filename).write_text(value, encoding="utf-8")
    git(source, "add", filename)
    git(source, "commit", "-m", "new revision")
    return git(source, "rev-parse", "HEAD")


def test_git_preflight_fetches_fork_without_mutating_head_or_origin(repositories):
    source, checkout = repositories
    old = git(checkout, "rev-parse", "HEAD")
    origin = git(checkout, "remote", "get-url", "origin")
    new = add_revision(source)
    args = q.parse_args(["upgrade", "--repo", str(source)])
    record = q.upgrade_preflight(checkout, args)
    assert (record["old_revision"], record["new_revision"]) == (old, new)
    assert git(checkout, "rev-parse", "HEAD") == old
    assert git(checkout, "remote", "get-url", "origin") == origin


@pytest.mark.parametrize("kind", ["tracked", "untracked", "diverged", "missing-source", "unrelated", "detached", "branch-diverged"])
def test_git_preflight_refuses_unsafe_updates(repositories, tmp_path, kind):
    source, checkout = repositories
    add_revision(source)
    if kind == "tracked":
        (checkout / "backend/app.py").write_text("local edit", encoding="utf-8")
    elif kind == "untracked":
        (checkout / "important.txt").write_text("local work", encoding="utf-8")
    elif kind == "diverged":
        add_revision(checkout, "local.txt", "keep this commit")
    elif kind == "missing-source":
        source = tmp_path / "does not exist"
    elif kind == "unrelated":
        source = tmp_path / "unrelated"
        source.mkdir()
        git(source, "init", "-b", "main")
        git(source, "config", "user.name", "Synthetic")
        git(source, "config", "user.email", "synthetic@example.invalid")
        add_revision(source)
    elif kind == "detached":
        git(checkout, "checkout", "--detach")
    elif kind == "branch-diverged":
        git(checkout, "switch", "-c", "other")
        add_revision(checkout, "local.txt", "keep main")
        git(checkout, "branch", "-f", "main", "HEAD")
        git(checkout, "reset", "--hard", "HEAD~1")
    old = git(checkout, "rev-parse", "HEAD")
    with pytest.raises(RuntimeError):
        q.upgrade_preflight(checkout, q.parse_args(["upgrade", "--repo", str(source)]))
    assert git(checkout, "rev-parse", "HEAD") == old


@pytest.mark.parametrize("branch,other_local_branch", [("main", False), ("release/test", False), ("main", True)])
def test_upgrade_executes_updated_launcher(repositories, monkeypatch, manager, branch, other_local_branch):
    source, checkout = repositories
    if branch != "main":
        git(source, "switch", "-c", branch)
    if other_local_branch:
        git(checkout, "switch", "-c", "installed-feature")
    new_body = '''QUICKSTART_PROTOCOL = 1
import json, pathlib, sys
project = pathlib.Path(sys.argv[sys.argv.index('--dir') + 1])
record_path = project / 'backend/data/quickstart/upgrade.json'
record = json.loads(record_path.read_text())
assert record['token'] == sys.argv[sys.argv.index('--_finish-upgrade') + 1]
record.update(status='complete', stage='complete', executed='updated body')
record_path.write_text(json.dumps(record))
'''
    new = add_revision(source, "quickstart.py", new_body)
    monkeypatch.setattr(q, "venv_python_path", lambda path: Path(sys.executable))
    monkeypatch.setattr(q, "listener_open", lambda *args: False)
    q.upgrade(checkout, q.parse_args(["upgrade", "--repo", str(source), "--branch", branch]))
    record = json.loads((q.state_dir(checkout) / "upgrade.json").read_text())
    assert record["status"] == "complete"
    assert record["executed"] == "updated body"
    assert git(checkout, "rev-parse", "HEAD") == new
    assert git(checkout, "branch", "--show-current") == branch
    manager.stop.assert_not_called()
    manager.start.assert_not_called()


@pytest.mark.parametrize("running,no_start,restart", [(True, False, True), (True, True, False), (False, False, False)])
def test_upgrade_stop_handoff_order(project, monkeypatch, manager, running, no_start, restart):
    events = []
    manager.installed.return_value = True
    manager.running.return_value = running
    monkeypatch.setattr(q, "upgrade_preflight", lambda *args: events.append("fetch-preflight") or {
        "old_revision": "old", "new_revision": "new", "branch": "main", "previous_branch": "main"})
    monkeypatch.setattr(q, "stop_service", lambda *args: events.append("stop"))
    monkeypatch.setattr(q, "listener_open", lambda *args: False)
    monkeypatch.setattr(q, "git", lambda project, *args, **kwargs: events.append(args[0]) or SimpleNamespace(stdout="", returncode=0))
    def handoff(*args, **kwargs):
        events.append("handoff")
        journal = q.state_dir(project) / "upgrade.json"
        record = json.loads(journal.read_text())
        record.update(status="complete", stage="complete")
        q.atomic_json(journal, record)
        return SimpleNamespace(returncode=0)
    monkeypatch.setattr(q.subprocess, "run", handoff)
    argv = ["upgrade", "--no-start"] if no_start else ["upgrade"]
    q.upgrade(project, q.parse_args(argv))
    record = json.loads((q.state_dir(project) / "upgrade.json").read_text())
    assert record["restart"] is restart
    assert events[0] == "fetch-preflight"
    assert events.index("stop") < events.index("merge") < events.index("handoff")


def test_upgrade_unmanaged_instance_refused_before_merge(project, monkeypatch, manager):
    monkeypatch.setattr(q, "upgrade_preflight", lambda *args: {})
    monkeypatch.setattr(q, "listener_open", lambda *args: True)
    mutation = Mock()
    monkeypatch.setattr(q, "git", mutation)
    with pytest.raises(RuntimeError, match="foreground/manual"):
        q.upgrade(project, q.parse_args(["upgrade"]))
    mutation.assert_not_called()
    manager.stop.assert_not_called()


@pytest.mark.parametrize("restart", [True, False])
def test_finish_upgrade_installs_then_restarts(project, monkeypatch, manager, restart):
    journal = q.state_dir(project) / "upgrade.json"
    q.atomic_json(journal, {"token": "test", "stage": "updated launcher", "status": "running", "restart": restart,
                            "old_revision": "old", "new_revision": "new"})
    monkeypatch.setattr(q, "git", lambda *args: SimpleNamespace(stdout="new"))
    events = []
    monkeypatch.setattr(q, "install_dependencies", lambda project: events.append("install"))
    monkeypatch.setattr(q, "_launch", lambda project: events.append("restart"))
    q.finish_upgrade(project, "test")
    assert events == (["install", "restart"] if restart else ["install"])
    assert json.loads(journal.read_text())["status"] == "complete"
    with pytest.raises(RuntimeError, match="consumed"):
        q.finish_upgrade(project, "test")


def test_failed_install_leaves_service_stopped_with_revision_record(project, monkeypatch, manager):
    journal = q.state_dir(project) / "upgrade.json"
    q.atomic_json(journal, {"token": "test", "stage": "updated launcher", "status": "running", "restart": True,
                            "old_revision": "old", "new_revision": "new"})
    monkeypatch.setattr(q, "git", lambda *args: SimpleNamespace(stdout="new"))
    monkeypatch.setattr(q, "install_dependencies", Mock(side_effect=RuntimeError("synthetic pip failure")))
    with pytest.raises(RuntimeError, match="pip failure"):
        q.finish_upgrade(project, "test")
    manager.start.assert_not_called()
    saved = json.loads(journal.read_text())
    assert saved["status"] == "failed"
    assert saved["new_revision"] == "new"
    assert saved["stage"] == "installing dependencies and migrating security"


@pytest.mark.parametrize("platform,kind", [("win32", "windows"), ("linux", "systemd"), ("darwin", "launchd"), ("other", "unsupported")])
def test_platform_and_stable_identity(project, monkeypatch, platform, kind):
    monkeypatch.setattr(services.sys, "platform", platform)
    first, second = services.ServiceManager(project), services.ServiceManager(project / "scripts" / "..")
    assert first.kind == kind
    assert first.name == second.name
    assert first.name != services.ServiceManager(project.parent).name


def test_native_definitions_have_absolute_paths_user_and_no_secrets(project):
    manager = services.ServiceManager(project)
    unit = manager.systemd_definition("operator")
    assert "User=operator" in unit and "--managed" in unit
    assert "Restart=on-failure" in unit and "StartLimitBurst=3" in unit
    assert services.systemd_quote(str(project)) in unit
    daemon = plistlib.loads(manager.launchd_definition("operator"))
    assert daemon["UserName"] == "operator"
    assert daemon["WorkingDirectory"] == str(project)
    assert daemon["ProgramArguments"][-1] == "--managed"
    assert daemon["KeepAlive"] == {"SuccessfulExit": False}
    script = manager.windows_registration("EXAMPLE\\operator")
    assert "Get-Credential" in script and "-RunLevel Limited" in script
    assert "IgnoreNew" in script and "-AtStartup" in script
    assert "-Password $credential.GetNetworkCredential().Password" in script
    for definition in (unit, str(daemon), script):
        assert "SESSION_SECRET" not in definition and "MIST_TOKEN" not in definition


def test_windows_credential_prompt_only_in_elevated_encoded_process(project, monkeypatch):
    manager = services.ServiceManager(project)
    calls = []
    monkeypatch.setattr(manager, "_ps", lambda script, **kwargs: calls.append((script, kwargs)))
    registration = manager.windows_registration("EXAMPLE\\operator")
    manager._elevated_windows(registration)
    outer = calls[0][0]
    assert "-Verb RunAs -WindowStyle Hidden" in outer
    assert calls[0][1]["interactive"]
    assert base64.b64decode(services.encoded_ps(registration)).decode("utf-16-le") == registration


def test_unsupported_linux_does_not_register(project, monkeypatch):
    manager = services.ServiceManager(project)
    manager.kind = "systemd"
    monkeypatch.setattr(services.shutil, "which", lambda name: None)
    privileged = Mock()
    monkeypatch.setattr(manager, "_privileged", privileged)
    with pytest.raises(RuntimeError, match="does not run systemd"):
        manager.enable()
    privileged.assert_not_called()


@pytest.mark.parametrize("kind", ["systemd", "launchd"])
def test_posix_registration_is_idempotent_and_never_launches_app(project, monkeypatch, kind):
    manager = services.ServiceManager(project)
    manager.kind = kind
    manager.definition_path = project / "synthetic-native-definition"
    monkeypatch.setattr(manager, "_supported", lambda: None)
    monkeypatch.setattr(manager, "_owner", lambda: SimpleNamespace(pw_name="operator", pw_dir="/home/operator", pw_uid=1000, pw_gid=1000))
    if os.name != "nt":
        monkeypatch.setattr(services.os, "geteuid", lambda: 1000)
    commands = []
    def privileged(*command):
        commands.append(command)
        if command[0] == "install":
            shutil.copyfile(command[-2], command[-1])
    monkeypatch.setattr(manager, "_privileged", privileged)
    manager.enable()
    content = manager.definition_path.read_bytes()
    manager.enable()
    assert manager.definition_path.read_bytes() == content
    assert all("start" not in command and "bootstrap" not in command for command in commands)
    if kind == "launchd":
        assert plistlib.loads(content)["EnvironmentVariables"]["HOME"] == "/home/operator"
    else:
        assert 'Environment="HOME=/home/operator"' in content.decode()
    assert manager.log_path.is_file()


@pytest.mark.parametrize("existing", [False, True])
def test_failed_posix_registration_removes_new_or_restores_old_definition(project, monkeypatch, existing):
    manager = services.ServiceManager(project)
    manager.kind = "systemd"
    manager.definition_path = project / "synthetic-native-definition"
    if existing:
        manager.definition_path.write_bytes(b"original definition")
    monkeypatch.setattr(manager, "_supported", lambda: None)
    monkeypatch.setattr(manager, "_owner", lambda: SimpleNamespace(pw_name="operator", pw_dir="/home/operator", pw_uid=1000, pw_gid=1000))
    if os.name != "nt":
        monkeypatch.setattr(services.os, "geteuid", lambda: 1000)
    def privileged(*command):
        if command[0] == "install":
            shutil.copyfile(command[-2], command[-1])
        elif command[:2] == ("systemctl", "enable"):
            raise RuntimeError("synthetic registration failure")
        elif command[0] == "rm":
            Path(command[-1]).unlink(missing_ok=True)
    monkeypatch.setattr(manager, "_privileged", privileged)
    with pytest.raises(RuntimeError, match="registration failure"):
        manager.enable()
    if existing:
        assert manager.definition_path.read_bytes() == b"original definition"
    else:
        assert not manager.definition_path.exists()


def test_fetch_failure_does_not_stop_managed_service(project, monkeypatch, manager):
    manager.installed.return_value = manager.running.return_value = True
    monkeypatch.setattr(q, "upgrade_preflight", Mock(side_effect=RuntimeError("fetch failed")))
    with pytest.raises(RuntimeError, match="fetch failed"):
        q.upgrade(project, q.parse_args(["upgrade"]))
    manager.stop.assert_not_called()
    manager.start.assert_not_called()
    record = json.loads((q.state_dir(project) / "upgrade.json").read_text())
    assert record["status"] == "failed" and record["stage"] == "preflight"


def test_disable_stops_before_removing_registration(project, monkeypatch, manager):
    manager.installed.return_value = True
    events = []
    monkeypatch.setattr(q, "stop_service", lambda *args: events.append("stop"))
    manager.disable.side_effect = lambda: events.append("remove")
    q.main(["autostart", "disable", "--dir", str(project)])
    assert events == ["stop", "remove"]


def test_first_env_creation_has_upgrade_defaults_and_hidden_password(project, monkeypatch):
    env = project / "backend/.env"
    env.unlink()
    monkeypatch.setattr(sys.stdin, "isatty", lambda: True)
    answers = iter(["", "", "", "8765", "local", "", "", "operator"])
    monkeypatch.setattr("builtins.input", lambda prompt: next(answers))
    passwords = iter(["synthetic-token", "synthetic-password"])
    monkeypatch.setattr(q, "getpass", lambda prompt: next(passwords))
    hashing = Mock(return_value=SimpleNamespace(stdout="scrypt$synthetic-hash"))
    monkeypatch.setattr(q.subprocess, "run", hashing)
    assert q.ensure_env_file(project) == 8765
    values = q.load_env_from_file(env)
    assert values["QUICKSTART_REPO_URL"] == q.DEFAULT_REPO
    assert values["QUICKSTART_BRANCH"] == "main"
    assert values["LOCAL_USERS"] == "operator:scrypt$synthetic-hash"
    assert values["LOCAL_PUSH_USERS"] == "operator"
    assert "synthetic-password" not in env.read_text()
    assert hashing.call_args.kwargs["input"] == "synthetic-password"


def test_setup_clone_accepts_nonexistent_target(repositories, tmp_path):
    source, _ = repositories
    target = tmp_path / "new target with spaces"
    q.ensure_git_repo(str(source), target, "main")
    assert (target / "backend/app.py").exists()
    assert (target / ".git").is_dir()


def test_windows_stop_uses_nonce_not_task_kill(project, monkeypatch):
    manager = services.ServiceManager(project)
    manager.kind = "windows"
    monkeypatch.setattr(manager, "_supported", lambda: None)
    monkeypatch.setattr(manager, "running", Mock(side_effect=[True, False]))
    q.atomic_json(manager.state / "runtime.json", {"managed": True, "token": "per-run-nonce"})
    shell = Mock(side_effect=AssertionError("must not kill task"))
    monkeypatch.setattr(manager, "_ps", shell)
    manager.stop()
    assert json.loads((manager.state / "stop.json").read_text())["token"] == "per-run-nonce"
    shell.assert_not_called()


def test_runtime_lock_prevents_duplicate_and_recovers(tmp_path):
    path = tmp_path / "runtime.lock"
    with q.exclusive_lock(path):
        with pytest.raises(RuntimeError, match="already running"):
            with q.exclusive_lock(path):
                pytest.fail("duplicate lock")
    with q.exclusive_lock(path):
        pass


def test_maintenance_lock_blocks_launch_and_setup_before_mutation(project, monkeypatch, manager):
    prepare_setup(project, monkeypatch, manager)
    with q.exclusive_lock(q.state_dir(project) / "upgrade.lock"):
        with pytest.raises(RuntimeError, match="already running"):
            q.launch(project)
        with pytest.raises(RuntimeError, match="already running"):
            q.setup(project, q.parse_args(["setup", "--no-start"]))
    q.run.assert_not_called()
    q.ensure_requirements.assert_not_called()
    manager.enable.assert_not_called()


def test_restart_limit_and_expiry(project, monkeypatch):
    monkeypatch.setattr(runtime.time, "time", lambda: 1000)
    assert all(runtime.restart_allowed(project) for _ in range(3))
    assert not runtime.restart_allowed(project)
    monkeypatch.setattr(runtime.time, "time", lambda: 1301)
    assert runtime.restart_allowed(project)


def test_real_listener_check_uses_loopback_for_wildcards():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        sock.listen()
        port = sock.getsockname()[1]
        assert q.listener_open("0.0.0.0", port)
    assert not q.listener_open("127.0.0.1", port)


@pytest.mark.parametrize("managed", [False, True])
def test_real_runtime_loads_env_before_app_and_shuts_down_cleanly(project, managed):
    pytest.importorskip("uvicorn")
    pytest.importorskip("dotenv")
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    (project / "backend/.env").write_text(f"API_PORT={port}\nAPP_HOST=127.0.0.1\nBOOT_IMPORT_CHECK=from-file\n", encoding="utf-8")
    # Pure ASGI: no backend application, account store, or external service access.
    (project / "backend/app.py").write_text('''import os
assert os.environ['BOOT_IMPORT_CHECK'] == 'from-file'
async def app(scope, receive, send):
    if scope['type'] == 'lifespan':
        while True:
            event = await receive()
            if event['type'] == 'lifespan.startup':
                await send({'type': 'lifespan.startup.complete'})
            elif event['type'] == 'lifespan.shutdown':
                await send({'type': 'lifespan.shutdown.complete'})
                return
    elif scope['type'] == 'http':
        await send({'type': 'http.response.start', 'status': 200, 'headers': []})
        await send({'type': 'http.response.body', 'body': b'synthetic'})
''', encoding="utf-8")
    command = [sys.executable, str(ROOT / "scripts/quickstart_runtime.py"), "--dir", str(project)]
    if managed:
        command.append("--managed")
    environment = dict(os.environ, BOOT_IMPORT_CHECK="inherited-must-be-overridden", SYSLOG_HOST="")
    with (project / "captured.log").open("w", encoding="utf-8") as output:
        proc = subprocess.Popen(command, stdout=output, stderr=output, env=environment)
        try:
            deadline = time.monotonic() + 20
            while time.monotonic() < deadline:
                if proc.poll() is not None:
                    pytest.fail((project / "captured.log").read_text() + (project / "backend/logs/quickstart-service.log").read_text() if managed else (project / "captured.log").read_text())
                if q.listener_open("127.0.0.1", port):
                    break
                time.sleep(0.1)
            else:
                pytest.fail("runtime did not listen")
            metadata = json.loads((q.state_dir(project) / "runtime.json").read_text())
            assert metadata["managed"] is managed
            q.atomic_json(q.state_dir(project) / "stop.json", {"token": "wrong-run"})
            time.sleep(0.4)
            assert proc.poll() is None
            q.atomic_json(q.state_dir(project) / "stop.json", {"token": metadata["token"]})
            assert proc.wait(timeout=15) == 0
            assert not (q.state_dir(project) / "runtime.json").exists()
            assert not q.listener_open("127.0.0.1", port)
            if managed:
                log = (project / "backend/logs/quickstart-service.log").read_text()
                assert "Application startup complete" in log
                assert "Application shutdown complete" in log
                assert not (q.state_dir(project) / "restart-history.json").exists()
        finally:
            if proc.poll() is None:
                proc.terminate()
                proc.wait(timeout=10)


@pytest.mark.skipif(os.name != "nt", reason="Windows PowerShell parser")
def test_powershell_wrapper_and_registration_parse_without_execution(project, monkeypatch):
    manager = services.ServiceManager(project)
    script = manager.windows_registration("EXAMPLE\\operator")
    generated = []
    monkeypatch.setattr(manager, "_ps", lambda code, **kwargs: generated.append(code))
    manager._elevated_windows(script)
    assert len(services.encoded_ps(generated[0])) < 30000
    payload = json.dumps({"scripts": [script, generated[0]], "wrapper": str(ROOT / "quickstart.ps1")}).encode()
    check = ("$p = [Console]::In.ReadToEnd() | ConvertFrom-Json; $tokens=$null; $errors=$null; "
             "foreach ($s in $p.scripts) { [Management.Automation.Language.Parser]::ParseInput($s,[ref]$tokens,[ref]$errors) | Out-Null; "
             "if ($errors.Count) { $errors; exit 1 } }; "
             "[Management.Automation.Language.Parser]::ParseFile($p.wrapper,[ref]$tokens,[ref]$errors) | Out-Null; if ($errors.Count) { $errors; exit 1 }")
    result = subprocess.run(["powershell.exe", "-NoProfile", "-NonInteractive", "-EncodedCommand", services.encoded_ps(check)], input=payload, capture_output=True, timeout=30)
    assert result.returncode == 0, result.stdout + result.stderr


@pytest.mark.skipif(os.name != "nt", reason="Windows PowerShell wrapper")
def test_powershell_forwards_named_options_and_exit_code(tmp_path):
    wrapper = tmp_path / "quickstart.ps1"
    shutil.copyfile(ROOT / "quickstart.ps1", wrapper)
    (tmp_path / "quickstart.py").write_text("import json, sys\nprint(json.dumps(sys.argv[1:]))\nsys.exit(23)\n", encoding="utf-8")
    target = tmp_path / "absent target with spaces"
    result = subprocess.run(["powershell.exe", "-NoProfile", "-File", str(wrapper), "setup", "-TargetDir", str(target),
                             "-RepoUrl", "https://example.invalid/fork.git", "-Branch", "feature/test", "-Port", "9000",
                             "-NoStart", "-Autostart"], capture_output=True, text=True, timeout=30)
    assert result.returncode == 23, result.stdout + result.stderr
    assert json.loads(result.stdout) == ["setup", "--dir", str(target), "--repo", "https://example.invalid/fork.git",
                                         "--branch", "feature/test", "--port", "9000", "--no-start", "--autostart"]
    assert not target.exists()
