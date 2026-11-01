"""Narrow, approval-gated local Linux group creation over one SSH session."""

from __future__ import annotations

import asyncio
import copy
import hashlib
import json
import os
import re
import shlex
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

import asyncssh

from .models import Server


def group_commands(name: str) -> tuple[str, str]:
    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_-]{0,31}", name):
        raise ValueError("Invalid Linux group name")
    quoted = shlex.quote(name)
    return f"getent group {quoted}", f"sudo -n -- groupadd -- {quoted}"


def plan_digest(plan: dict[str, Any]) -> str:
    body = {key: value for key, value in plan.items() if key != "digest"}
    return hashlib.sha256(json.dumps(body, sort_keys=True).encode()).hexdigest()


def audit(event: dict[str, Any]) -> None:
    root = Path(os.environ.get("XDG_STATE_HOME", Path.home() / ".local/state")) / "cluster-manager"
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd = os.open(root / "audit.jsonl", os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    with os.fdopen(fd, "a", encoding="utf-8") as stream:
        stream.write(json.dumps(event, sort_keys=True) + "\n")


async def create_group(
    server_name: str,
    server: Server,
    group: str,
    password: str | None,
    approve: Callable[[dict[str, Any]], bool],
) -> dict[str, Any]:
    check, change = group_commands(group)
    kwargs: dict[str, Any] = {
        "username": server.ssh.username,
        "port": server.port,
        "connect_timeout": 10,
        "login_timeout": 15,
    }
    if server.ssh.auth == "password":
        kwargs.update(password=password, client_keys=[], preferred_auth="password")
    else:
        kwargs.update(preferred_auth="publickey")
    async with asyncssh.connect(server.host, **kwargs) as connection:
        platform = await asyncio.wait_for(connection.run("uname -s", check=False), 15)
        if platform.exit_status != 0 or platform.stdout != "Linux\n":
            raise RuntimeError("remote mutation requires a Linux host")
        before = await asyncio.wait_for(connection.run(check, check=False), 15)
        if before.exit_status == 0:
            return {"status": "noop", "reason": "group already resolves through getent"}
        if before.exit_status != 2:
            raise RuntimeError("Unable to establish whether group exists")
        plan: dict[str, Any] = {
            "operation": "group.create",
            "server": server_name,
            "host": server.host,
            "port": server.port,
            "ssh_username": server.ssh.username,
            "group": group,
            "command": change,
            "verification": check,
            "expires_at": int(time.time()) + 300,
            "local_uid": os.getuid(),
        }
        plan["digest"] = plan_digest(plan)
        approved_digest = plan["digest"]
        if not approve(copy.deepcopy(plan)):
            return {"status": "cancelled", "plan": plan}
        if plan_digest(plan) != approved_digest or plan["digest"] != approved_digest:
            raise RuntimeError("Plan changed after approval")
        if time.time() >= plan["expires_at"]:
            raise RuntimeError("Approval expired")
        # Recheck immediately before execution in the same authenticated SSH session.
        current = await asyncio.wait_for(connection.run(check, check=False), 15)
        if current.exit_status != 2:
            raise RuntimeError("Group state changed or could not be verified; plan invalidated")
        audit({"event": "attempt", "plan": plan, "time": int(time.time())})
        try:
            result = await asyncio.wait_for(connection.run(change, check=False), 30)
            after = await asyncio.wait_for(connection.run(check, check=False), 15)
            status = "verified" if result.exit_status == 0 and after.exit_status == 0 else "failed"
            outcome = {
                "status": status,
                "command_exit_status": result.exit_status,
                "verification_exit_status": after.exit_status,
                "plan": plan,
            }
        except Exception:
            audit({"event": "outcome_unknown", "digest": plan["digest"], "time": int(time.time())})
            raise
        audit({"event": "result", "outcome": outcome, "time": int(time.time())})
        return outcome
