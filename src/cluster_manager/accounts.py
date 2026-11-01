"""Constrained local account operations with local approval and secret stdin."""

from __future__ import annotations

import asyncio
import copy
import os
import re
import shlex
import time
from collections.abc import Callable
from typing import Any

import asyncssh

from .models import Server
from .provision import audit, plan_digest


def commands(name: str, operation: str) -> dict[str, str]:
    if not re.fullmatch(r"[a-z_][a-z0-9_-]{0,31}", name):
        raise ValueError("invalid local username")
    q = shlex.quote(name)
    if operation not in ("user.create", "user.password"):
        raise ValueError("unsupported operation")
    return {
        "nss": f"getent passwd {q}",
        "local": f"getent -s files passwd {q}",
        "change": f"sudo -n -- useradd --no-create-home --user-group --password '!' -- {q}"
        if operation == "user.create"
        else "sudo -n -- chpasswd",
        "verify": f"getent -s files passwd {q}"
        if operation == "user.create"
        else f"sudo -n -- passwd -S -- {q}",
    }


def _local_match(nss: Any, local: Any) -> bool:
    return (
        nss.exit_status == 0
        and local.exit_status == 0
        and isinstance(nss.stdout, str)
        and nss.stdout == local.stdout
        and len(nss.stdout.splitlines()) == 1
    )


async def account_operation(
    server_name: str,
    server: Server,
    name: str,
    operation: str,
    ssh_password: str | None,
    approve: Callable[[dict[str, Any]], bool],
    secret: Callable[[], str],
) -> dict[str, Any]:
    cmds = commands(name, operation)
    kwargs: dict[str, Any] = {
        "username": server.ssh.username,
        "port": server.port,
        "connect_timeout": 10,
        "login_timeout": 15,
    }
    if server.ssh.auth == "password":
        kwargs.update(password=ssh_password, client_keys=[], preferred_auth="password")
    else:
        kwargs.update(preferred_auth="publickey")
    async with asyncssh.connect(server.host, **kwargs) as conn:
        platform = await asyncio.wait_for(conn.run("uname -s", check=False), 15)
        if platform.exit_status != 0 or platform.stdout != "Linux\n":
            raise RuntimeError("remote mutation requires a Linux host")

        async def state() -> tuple[Any, Any]:
            nss = await asyncio.wait_for(conn.run(cmds["nss"], check=False), 15)
            local = await asyncio.wait_for(conn.run(cmds["local"], check=False), 15)
            return nss, local

        before_nss, before_local = await state()
        if operation == "user.create":
            if before_nss.exit_status == 0 or before_local.exit_status == 0:
                raise RuntimeError("account already exists; no changes made")
            if before_nss.exit_status != 2 or before_local.exit_status != 2:
                raise RuntimeError("account absence could not be established")
        elif not _local_match(before_nss, before_local):
            raise RuntimeError("account is absent, externally managed, or ambiguous")
        plan: dict[str, Any] = {
            "operation": operation,
            "server": server_name,
            "host": server.host,
            "port": server.port,
            "ssh_username": server.ssh.username,
            "username": name,
            "command": cmds["change"],
            "verification": cmds["verify"],
            "secret_input": "username and password via stdin (redacted)"
            if operation == "user.password"
            else None,
            "local_uid": os.getuid(),
            "expires_at": int(time.time()) + 300,
        }
        plan["digest"] = plan_digest(plan)
        if not approve(copy.deepcopy(plan)):
            return {"status": "cancelled", "plan": plan}
        if time.time() >= plan["expires_at"] or plan["digest"] != plan_digest(plan):
            raise RuntimeError("approval expired or plan changed")
        current_nss, current_local = await state()
        if operation == "user.create":
            if current_nss.exit_status != 2 or current_local.exit_status != 2:
                raise RuntimeError("account state changed")
        elif (
            not _local_match(current_nss, current_local)
            or current_local.stdout != before_local.stdout
        ):
            raise RuntimeError("account state changed")
        stdin: str | None = None
        if operation == "user.password":
            password = secret()
            if not password or any(c in password for c in "\n\r\x00"):
                raise ValueError("password must be nonempty and contain no line breaks or NUL")
            stdin = f"{name}:{password}\n"
        if time.time() >= plan["expires_at"]:
            raise RuntimeError("approval expired")
        audit({"event": "attempt", "plan": plan, "time": int(time.time())})
        try:
            result = await asyncio.wait_for(conn.run(cmds["change"], input=stdin, check=False), 30)
            after = await asyncio.wait_for(conn.run(cmds["verify"], check=False), 15)
            verified = after.exit_status == 0
            if operation == "user.password":
                fields = after.stdout.split() if isinstance(after.stdout, str) else []
                verified = verified and len(fields) >= 2 and fields[0] == name and fields[1] == "P"
            outcome = {
                "status": "verified" if result.exit_status == 0 and verified else "failed",
                "command_exit_status": result.exit_status,
                "verification_exit_status": after.exit_status,
                "plan": plan,
            }
        except Exception:
            audit({"event": "outcome_unknown", "digest": plan["digest"], "time": int(time.time())})
            raise
        audit({"event": "result", "outcome": outcome, "time": int(time.time())})
        return outcome
