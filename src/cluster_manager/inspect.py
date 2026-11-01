"""Narrow read-only probes with typed parameters and per-probe results."""

from __future__ import annotations

import asyncio
import re
import shlex
from typing import Any

import asyncssh

from .models import Server


def command_for(kind: str, name: str | None = None) -> str:
    if kind == "users":
        return "getent passwd"
    if kind == "groups":
        return "getent group"
    if kind == "storage":
        return "df -Pk"
    if kind == "inodes":
        return "df -Pi"
    if kind in ("user", "group"):
        if name is None or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.-]{0,31}\$?", name):
            raise ValueError("invalid identity name")
        return f"getent {'passwd' if kind == 'user' else 'group'} {shlex.quote(name)}"
    raise ValueError("unsupported discovery operation")


async def inspect(
    server: Server, kind: str, name: str | None, password: str | None
) -> dict[str, Any]:
    command = command_for(kind, name)
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
        result = await asyncio.wait_for(connection.run(command, check=False), 15)
        return {
            "command": command,
            "stdout": result.stdout,
            "stderr": result.stderr,
            "exit_status": result.exit_status,
        }
