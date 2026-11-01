"""Fixed, read-only discovery operations; remote content is always untrusted data."""

from __future__ import annotations

import asyncio
from typing import Any

import asyncssh

from .models import Server

# No caller-controlled shell fragments. Commands do not require elevated privileges.
COMMANDS = {
    "os": "cat /etc/os-release",
    "users": "getent passwd",
    "groups": "getent group",
    "filesystems": "df -Pk",
    "inodes": "df -Pi",
    "mounts": "findmnt -J -o TARGET,SOURCE,FSTYPE,OPTIONS",
    "block_devices": "lsblk -J -f",
    "capabilities": 'for x in sudo getent findmnt lsblk testparm smbpasswd; do command -v "$x" || :; done',
}


async def discover(server: Server, password: str | None = None) -> dict[str, Any]:
    # AsyncSSH's default known_hosts uses the user's known_hosts file. Never pass None.
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
    result: dict[str, Any] = {}
    async with asyncssh.connect(server.host, **kwargs) as connection:
        for name, command in COMMANDS.items():
            try:
                response = await asyncio.wait_for(connection.run(command, check=False), timeout=15)
                result[name] = {
                    "stdout": response.stdout,
                    "stderr": response.stderr,
                    "exit_status": response.exit_status,
                }
            except TimeoutError:
                result[name] = {"error": "command timed out"}
    return result
