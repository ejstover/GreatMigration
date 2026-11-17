"""Upgrade installation-local credentials without printing or backing up secrets."""
from __future__ import annotations

import argparse
import json
import os
import secrets
import sys
import getpass
from pathlib import Path

from security import hash_password
from dotenv import dotenv_values


def upgrade_env(path: Path) -> bool:
    if not path.exists():
        return False
    lines = path.read_text(encoding="utf-8-sig").splitlines()
    values = {key: value or "" for key, value in dotenv_values(path).items()}
    changes = {}
    key = values.get("SESSION_SECRET", "")
    if len(key) < 32 or key.lower() in {"change_me", "changeme", "replace_me"}:
        changes["SESSION_SECRET"] = secrets.token_urlsafe(48)
    if values.get("LOCAL_USERS"):
        users = {}
        push = set(values.get("LOCAL_PUSH_USERS", "").split(","))
        for pair in values["LOCAL_USERS"].split(","):
            username, separator, password = pair.partition(":")
            if separator and username.strip() and password.strip():
                users[username.strip()] = {"password_hash": password.strip() if password.startswith("scrypt$") else hash_password(password.strip()), "can_push": username.strip() in push}
        target = path.parent / "data" / "local_users.json"
        target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        # Never replace an existing user database during an upgrade.
        if target.exists():
            existing = json.loads(target.read_text(encoding="utf-8"))
            users.update(existing)
        temporary = target.with_suffix(".tmp")
        temporary.write_text(json.dumps(users, indent=2), encoding="utf-8")
        os.chmod(temporary, 0o600)
        os.replace(temporary, target)
        changes.update(LOCAL_USERS="", LOCAL_PUSH_USERS="", LOCAL_USERS_FILE="data/local_users.json")
    if not changes:
        return False
    updated = []
    applied = set()
    for line in lines:
        key = line.split("=", 1)[0].strip() if "=" in line and not line.lstrip().startswith("#") else None
        if key in changes:
            if key not in applied:
                updated.append(f"{key}={changes[key]}")
                applied.add(key)
        else:
            updated.append(line)
    updated.extend(f"{key}={value}" for key, value in changes.items() if key not in applied)
    temporary = path.with_suffix(".secure-tmp")
    temporary.write_text("\n".join(updated) + "\n", encoding="utf-8")
    os.chmod(temporary, 0o600)
    os.replace(temporary, path)
    return True


def scrub_legacy_logs(directory: Path) -> int:
    """Remove historical HTTP body copies while preserving event metadata."""
    changed = 0
    for path in directory.glob("*.log"):
        if path.is_symlink() or not path.resolve().is_relative_to(directory.resolve()):
            continue
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        sanitized = []
        for line in lines:
            for marker in ("payload_sent=", "payload_received="):
                if marker in line:
                    line = line.split(marker, 1)[0] + "payload_omitted=security_upgrade"
                    break
            sanitized.append(line)
        result = "\n".join(sanitized) + "\n"
        if result != "\n".join(lines) + "\n":
            temporary = path.with_suffix(".secure-tmp")
            temporary.write_text(result, encoding="utf-8")
            os.chmod(temporary, 0o600)
            os.replace(temporary, path)
            changed += 1
    return changed


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--env", type=Path, default=Path(__file__).resolve().parent / ".env")
    parser.add_argument("--hash-password", action="store_true", help="Hash a password received on stdin; never put it in command arguments")
    parser.add_argument("--add-user", metavar="USERNAME", help="Create or update a local user with a hidden password prompt")
    parser.add_argument("--push", action="store_true", help="Grant the specified local user push rights")
    parser.add_argument("--revoke-sessions", action="store_true", help="Revoke all installation sessions")
    args = parser.parse_args()
    if args.hash_password:
        print(hash_password(sys.stdin.buffer.read().decode("utf-8").rstrip("\r\n")))
    else:
        upgraded = upgrade_env(args.env)
        if args.add_user:
            if not args.env.exists():
                parser.error("Create the environment file from .env.sample first")
            if not args.add_user.strip() or any(c in args.add_user for c in ",:\r\n"):
                parser.error("Invalid local username")
            password = getpass.getpass("New password (at least 12 characters): ")
            if len(password) < 12 or password != getpass.getpass("Confirm password: "):
                parser.error("Passwords must match and contain at least 12 characters")
            configured = dotenv_values(args.env).get("LOCAL_USERS_FILE") or "data/local_users.json"
            target = args.env.parent / configured
            target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            users = json.loads(target.read_text(encoding="utf-8")) if target.exists() else {}
            users[args.add_user] = {"password_hash": hash_password(password), "can_push": args.push}
            temporary = target.with_suffix(".tmp")
            temporary.write_text(json.dumps(users, indent=2), encoding="utf-8")
            os.chmod(temporary, 0o600)
            os.replace(temporary, target)
            if not dotenv_values(args.env).get("LOCAL_USERS_FILE"):
                with args.env.open("a", encoding="utf-8") as handle:
                    handle.write("\nLOCAL_USERS_FILE=data/local_users.json\n")
            print("Local account updated.")
        if args.revoke_sessions:
            from dotenv import load_dotenv
            load_dotenv(args.env)
            from security import security_db
            with security_db() as db:
                db.execute("DELETE FROM sessions")
            print("All sessions revoked.")
        scrub_legacy_logs(args.env.parent / "logs")
        print("Security configuration upgraded." if upgraded else "Security configuration is current.")
