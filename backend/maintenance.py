"""Retention for installation-local evidence; never traverses outside its roots."""
import json
import os
import time
from pathlib import Path

from security import BACKEND_DIR, security_db


def purge_evidence(root: Path | None = None, *, now: float | None = None) -> None:
    root = (root or BACKEND_DIR / "data").resolve()
    cutoff = (now or time.time()) - max(1, int(os.getenv("NETWORK_DATA_RETENTION_DAYS", "30"))) * 86400
    for category, key in (("conversion_sets", "items"), ("network_state", "runs")):
        directory = root / category
        if not directory.exists() or directory.is_symlink():
            continue
        for project in directory.iterdir():
            if not project.is_dir() or project.is_symlink() or not project.resolve().is_relative_to(directory.resolve()):
                continue
            removed = set()
            for target in project.glob("*.json"):
                if target.name == "index.json" or target.is_symlink():
                    continue
                resolved = target.resolve()
                if resolved.is_relative_to(project.resolve()) and resolved.stat().st_mtime < cutoff:
                    target.unlink()
                    removed.add(target.stem)
            if removed:
                index = project / "index.json"
                if index.exists() and not index.is_symlink():
                    doc = json.loads(index.read_text(encoding="utf-8"))
                    id_key = "conversion_set_id" if key == "items" else "run_id"
                    doc[key] = [item for item in doc.get(key, []) if item.get(id_key) not in removed]
                    temporary = project / ".retention.tmp"
                    temporary.write_text(json.dumps(doc, indent=2), encoding="utf-8")
                    os.replace(temporary, index)


def maintain(*, data_root: Path | None = None) -> None:
    import ssh_collect
    ssh_collect.cleanup_old_jobs()
    purge_evidence(data_root)
    with security_db():
        pass
