#!/usr/bin/env python3
"""
Quick start for the Switch Port Config tool.

Features
- Clone (or update) a git repo
- Create a Python virtual environment at ./.venv
- Install dependencies (from backend/requirements.txt if present, else sensible defaults)
- Ensure backend/.env (prompts on first run)
- Start FastAPI via uvicorn (configurable port)

Usage examples
-------------
# First time (clone & run)
python scripts/quickstart.py --repo https://github.com/ejstover/GreatMigration.git --dir "C:/work/GreatMigration" --branch main --port 8000

# Subsequent runs (already cloned)
python scripts/quickstart.py --dir "C:/work/GreatMigration" --port 8000

# Setup only (no server)
python scripts/quickstart.py --dir . --no-start
"""
from __future__ import annotations

import argparse
import os
import sys
import subprocess
from pathlib import Path
import shutil
from typing import Dict
from getpass import getpass

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

def ensure_git_repo(repo_url: str | None, target_dir: Path, branch: str):
    if not target_dir.exists():
        target_dir.mkdir(parents=True, exist_ok=True)

    git_dir = target_dir / ".git"
    if git_dir.exists():
        print(f"Updating existing repo in {target_dir} ...")
        run(["git", "fetch", "origin"], cwd=target_dir)
        run(["git", "checkout", branch], cwd=target_dir)
        run(["git", "pull", "--rebase", "origin", branch], cwd=target_dir)
    else:
        if not repo_url:
            raise SystemExit("Repo not found locally and --repo URL not provided.")
        print(f"Cloning {repo_url} into {target_dir} ...")
        run(["git", "clone", "--branch", branch, repo_url, str(target_dir)])

def ensure_venv(project_dir: Path) -> Path:
    venv_dir = project_dir / ".venv"
    if not venv_dir.exists():
        print("Creating virtual environment (.venv) ...")
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
            "fastapi==0.115.0",
            "uvicorn==0.30.6",
            "python-multipart==0.0.9",
            "jinja2==3.1.4",
            "requests",
            "ciscoconfparse>=1.6.52",
            "python-dotenv",
        )

def ensure_env_file(project_dir: Path):
    env_file = project_dir / "backend" / ".env"
    if env_file.exists():
        print(f"Found {env_file}")
        return

    print("\nCreating backend/.env (first run). Values are stored locally in this file.")
    token = getpass("MIST_TOKEN (input hidden): ").strip()
    base = input("MIST_BASE_URL [default https://api.ac2.mist.com]: ").strip() or "https://api.ac2.mist.com"
    org  = input("MIST_ORG_ID (optional): ").strip()
    tmpl = input("SWITCH_TEMPLATE_ID (optional): ").strip()

    env_file.parent.mkdir(parents=True, exist_ok=True)
    env_file.write_text(
        "MIST_TOKEN={}\nMIST_BASE_URL={}\nMIST_ORG_ID={}\nSWITCH_TEMPLATE_ID={}\n".format(token, base, org, tmpl),
        encoding="utf-8",
    )
    print(f"Wrote {env_file}")

def load_env_from_file(env_path: Path) -> Dict[str, str]:
    """Very small .env loader to pass vars to uvicorn process in case app doesn't load automatically."""
    out: Dict[str, str] = {}
    if not env_path.exists():
        return out
    for raw in env_path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            continue
        key, val = line.split("=", 1)
        key = key.strip()
        val = val.strip().strip('"').strip("'")
        if key:
            out[key] = val
    return out

def start_api(project_dir: Path, venv_python: Path, port: int):
    backend = project_dir / "backend"
    env_file = backend / ".env"
    child_env = os.environ.copy()
    child_env.update(load_env_from_file(env_file))

    print(f"\nStarting API at http://0.0.0.0:{port} (Ctrl+C to stop)")
    cmd = [str(venv_python), "-m", "uvicorn", "app:app", "--host", "0.0.0.0", "--port", str(port), "--app-dir", str(backend)]
    try:
        run(cmd, env=child_env, check=True)
    except KeyboardInterrupt:
        print("\nStopped by user.")

# ---------- Main ----------

def main():
    parser = argparse.ArgumentParser(description="Quick start: clone/update repo, create venv, install, ensure .env, run API.")
    parser.add_argument("--repo", help="Git repo URL (for first-time clone).")
    parser.add_argument("--dir", dest="target_dir", default=".", help="Target project directory (default: current dir).")
    parser.add_argument("--branch", default="main", help="Git branch to use (default: main).")
    parser.add_argument("--port", type=int, default=8000, help="API port (default: 8000).")
    parser.add_argument("--no-start", action="store_true", help="Setup only; do not start the API.")
    args = parser.parse_args()

    which_or_die("git")

    project_dir = Path(args.target_dir).expanduser().resolve()
    ensure_git_repo(args.repo, project_dir, args.branch)

    venv_dir = ensure_venv(project_dir)
    vpython = venv_python_path(venv_dir)

    ensure_requirements(project_dir, vpython)
    ensure_env_file(project_dir)

    if not args.no_start:
        start_api(project_dir, vpython, args.port)
    else:
        print("\nSetup complete. To start later:")
        print(f'  "{vpython}" -m uvicorn app:app --host 0.0.0.0 --port {args.port} --app-dir "{project_dir / "backend"}"')

if __name__ == "__main__":
    main()
