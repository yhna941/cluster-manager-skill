"""Persist unapproved group plans; applying always requires fresh local approval."""

from __future__ import annotations

import json
import os
import re
import secrets
import time
from pathlib import Path
from typing import Any

from .models import Server
from .provision import group_commands, plan_digest


def plan_dir() -> Path:
    return (
        Path(os.environ.get("XDG_STATE_HOME", Path.home() / ".local/state"))
        / "cluster-manager"
        / "plans"
    )


def validate(plan: dict[str, Any], server: Server, server_name: str) -> None:
    expected = {
        "operation",
        "server",
        "host",
        "port",
        "ssh_username",
        "group",
        "command",
        "verification",
        "expires_at",
        "local_uid",
        "digest",
    }
    if set(plan) != expected or plan.get("operation") != "group.create":
        raise ValueError("unsupported or malformed plan")
    if not isinstance(plan["group"], str):
        raise TypeError("invalid group")
    check, change = group_commands(plan["group"])
    if (
        plan["server"] != server_name
        or plan["host"] != server.host
        or plan["port"] != server.port
        or plan["ssh_username"] != server.ssh.username
        or plan["local_uid"] != os.getuid()
        or plan["command"] != change
        or plan["verification"] != check
    ):
        raise ValueError("plan no longer matches target or allowed operation")
    if not isinstance(plan["expires_at"], int) or time.time() >= plan["expires_at"]:
        raise ValueError("plan expired")
    if not isinstance(plan["digest"], str) or plan["digest"] != plan_digest(plan):
        raise ValueError("plan digest mismatch")


def save(plan: dict[str, Any]) -> str:
    directory = plan_dir()
    directory.mkdir(parents=True, mode=0o700, exist_ok=True)
    ident = secrets.token_hex(16)
    fd = os.open(directory / f"{ident}.json", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as stream:
        json.dump(plan, stream, sort_keys=True)
        stream.flush()
        os.fsync(stream.fileno())
    return ident


def load(ident: str) -> dict[str, Any]:
    if not re.fullmatch(r"[0-9a-f]{32}", ident):
        raise ValueError("invalid plan ID")
    with (plan_dir() / f"{ident}.json").open(encoding="utf-8") as stream:
        value = json.load(stream)
    if not isinstance(value, dict):
        raise TypeError("invalid plan")
    return value
