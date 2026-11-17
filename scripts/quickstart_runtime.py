"""Foreground application runner shared by console launches and native services."""
from __future__ import annotations

import argparse
from contextlib import redirect_stderr, redirect_stdout
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import secrets
import sys
import threading
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from quickstart import atomic_json, exclusive_lock, listener, state_dir  # noqa: E402


def restart_allowed(project: Path) -> bool:
    """Also bound launchd retries, which otherwise continue indefinitely."""
    history = state_dir(project) / "restart-history.json"
    try:
        attempts = json.loads(history.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        attempts = []
    now = time.time()
    attempts = [stamp for stamp in attempts if isinstance(stamp, (int, float)) and 0 <= now - stamp < 300]
    if len(attempts) >= 3:
        print("Repeated startup failures: restart limit reached. Inspect logs and run quickstart start.", file=sys.stderr)
        return False
    atomic_json(history, [*attempts, now])
    return True


def serve(project: Path, port: int | None, managed: bool):
    # Explicit dotenv loading happens before importing uvicorn or any app module.
    from dotenv import dotenv_values
    values = dotenv_values(project / "backend" / ".env", encoding="utf-8-sig")
    os.environ.update({key: value for key, value in values.items() if value is not None})
    os.chdir(project)
    host, port = listener(project, port)
    sys.path.insert(0, str(project / "backend"))
    import uvicorn

    with exclusive_lock(state_dir(project) / "runtime.lock"):
        token = secrets.token_hex(32)
        runtime = state_dir(project) / "runtime.json"
        stop_request = state_dir(project) / "stop.json"
        stop_request.unlink(missing_ok=True)
        atomic_json(runtime, {"pid": os.getpid(), "managed": managed, "token": token,
                              "host": host, "port": port, "started": datetime.now(timezone.utc).isoformat()})
        server = uvicorn.Server(uvicorn.Config("app:app", host=host, port=port, workers=1))
        finished = threading.Event()

        def control():
            while not finished.wait(0.25):
                try:
                    request = json.loads(stop_request.read_text(encoding="utf-8"))
                    if secrets.compare_digest(str(request.get("token", "")), token):
                        server.should_exit = True
                        return
                except (OSError, ValueError):
                    pass

        thread = threading.Thread(target=control, name="quickstart-control", daemon=True)
        thread.start()
        try:
            server.run()
            if not server.started:
                raise RuntimeError("Application startup failed; inspect the preceding log messages.")
            if managed:
                # A clean shutdown (including reboot) is not a startup failure.
                (state_dir(project) / "restart-history.json").unlink(missing_ok=True)
        finally:
            finished.set()
            thread.join(timeout=1)
            runtime.unlink(missing_ok=True)
            stop_request.unlink(missing_ok=True)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dir", required=True, type=Path)
    parser.add_argument("--port", type=int)
    parser.add_argument("--managed", action="store_true")
    args = parser.parse_args(argv)
    project = args.dir.resolve()
    if args.managed:
        logs = project / "backend" / "logs"
        logs.mkdir(parents=True, exist_ok=True)
        with (logs / "quickstart-service.log").open("a", encoding="utf-8", buffering=1) as log:
            with redirect_stdout(log), redirect_stderr(log):
                print(f"\nService startup {datetime.now(timezone.utc).isoformat()}", flush=True)
                try:
                    # Count attempts even when dependencies cannot be imported.
                    if not restart_allowed(project):
                        return 0
                    serve(project, args.port, True)
                except Exception as exc:
                    print(f"Startup failed: {exc}", file=sys.stderr, flush=True)
                    return 1
    else:
        try:
            serve(project, args.port, False)
        except (ModuleNotFoundError, RuntimeError) as exc:
            print(f"Cannot start app: {exc}. Run quickstart setup to repair the installation.", file=sys.stderr)
            return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
