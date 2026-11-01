from __future__ import annotations

import asyncio
import getpass
import json
import sys
from typing import Any

import asyncssh
import typer
from pydantic import ValidationError

from . import inventory
from .discovery import discover
from .inspect import inspect
from .models import Server, SSHConfig
from .provision import create_group
from .simulation import DATA
from .storage import scan

app = typer.Typer(
    no_args_is_help=True, help="Linux infrastructure inventory and controlled administration."
)
server_app = typer.Typer(no_args_is_help=True)
app.add_typer(server_app, name="server")
group_app = typer.Typer(no_args_is_help=True)
app.add_typer(group_app, name="group")
user_app = typer.Typer(no_args_is_help=True)
storage_app = typer.Typer(no_args_is_help=True)
app.add_typer(user_app, name="user")
app.add_typer(storage_app, name="storage")


def output(value: Any) -> None:
    typer.echo(json.dumps(value, indent=2, ensure_ascii=False))


def fail(message: str, code: int = 1) -> None:
    typer.echo(message, err=True)
    raise typer.Exit(code)


def get_server(name: str) -> Server:
    servers = inventory.load().servers
    if name not in servers:
        fail(f"Unknown server: {name}", 2)
    return servers[name]


@app.command()
def init() -> None:
    """Create an empty local inventory if it does not already exist."""
    path = inventory.config_path()
    if not path.exists():
        inventory.save(inventory.load())
    output({"inventory": str(path)})


@server_app.command("list")
def server_list() -> None:
    """List locally registered servers as JSON."""
    output(inventory.load().model_dump(exclude_none=True))


@server_app.command("show")
def server_show(name: str) -> None:
    output({"name": name, **get_server(name).model_dump(exclude_none=True)})


@server_app.command("add")
def server_add(
    name: str,
    host: str = typer.Option(...),
    username: str = typer.Option(...),
    auth: str = typer.Option("key"),
    port: int = typer.Option(22),
) -> None:
    """Confirm and save a nonsecret server record. Does not contact the host."""
    try:
        server = Server(host=host, port=port, ssh=SSHConfig(username=username, auth=auth))  # type: ignore[arg-type]
        current = inventory.load()
        if name in current.servers:
            fail("Server name already exists", 2)
        proposed = current.model_copy(deep=True)
        proposed.servers[name] = server
        proposed = type(current).model_validate(proposed.model_dump())
    except ValidationError as exc:
        fail(str(exc), 2)
    output({"proposed_name": name, "server": server.model_dump(exclude_none=True)})
    if not sys.stdin.isatty():
        fail("A local interactive terminal is required for confirmation", 2)
    if not typer.confirm("Save this server registration?", default=False, err=True):
        fail("Registration cancelled", 2)
    inventory.save(proposed)
    typer.echo("Saved. Verify the host key out of band before running server check.", err=True)


@server_app.command("remove")
def server_remove(name: str) -> None:
    current = inventory.load()
    if name not in current.servers:
        fail(f"Unknown server: {name}", 2)
    if not sys.stdin.isatty() or not typer.confirm(
        f"Remove {name} from local inventory?", default=False, err=True
    ):
        fail("Removal cancelled or no interactive terminal", 2)
    del current.servers[name]
    inventory.save(current)
    output({"removed": name})


@server_app.command("check")
def server_check(name: str) -> None:
    """Connect using verified known_hosts and collect fixed read-only probes."""
    server = get_server(name)
    password = None
    if server.ssh.auth == "password":
        if not sys.stdin.isatty():
            fail("Password authentication requires a local interactive terminal", 2)
        password = getpass.getpass("SSH password: ")
    try:
        output({"server": name, "discovery": asyncio.run(discover(server, password))})
    except (asyncssh.Error, OSError, TimeoutError) as exc:
        fail(f"SSH discovery failed: {type(exc).__name__}")


@app.command()
def simulate(server: str | None = typer.Option(None)) -> None:
    """Show explicitly labeled fixture data, without network access."""
    if server and server not in DATA:
        fail("Unknown simulated server", 2)
    output({"simulation": True, "servers": {server: DATA[server]} if server else DATA})


@group_app.command("create")
def group_create(name: str, server: str = typer.Option(...)) -> None:
    """Discover, preview, locally approve and create one Linux group."""
    if not sys.stdin.isatty():
        fail("A local interactive terminal is required for approval", 2)
    target = get_server(server)
    password = getpass.getpass("SSH password: ") if target.ssh.auth == "password" else None

    def approve(plan: dict[str, Any]) -> bool:
        output({"plan": plan})
        return typer.confirm("Approve this exact command?", default=False, err=True)

    try:
        outcome = asyncio.run(create_group(server, target, name, password, approve))
        output(outcome)
        if outcome["status"] not in ("verified", "noop"):
            raise typer.Exit(1)
    except (asyncssh.Error, OSError, TimeoutError, ValueError, RuntimeError) as exc:
        fail(f"Group creation failed: {type(exc).__name__}: {exc}")


def run_inspection(server: str, kind: str, name: str | None = None) -> None:
    target = get_server(server)
    password = None
    if target.ssh.auth == "password":
        if not sys.stdin.isatty():
            fail("Password authentication requires a local interactive terminal", 2)
        password = getpass.getpass("SSH password: ")
    try:
        result = asyncio.run(inspect(target, kind, name, password))
        output({"server": server, "result": result})
        if result["exit_status"] != 0:
            raise typer.Exit(1)
    except (asyncssh.Error, OSError, TimeoutError, ValueError) as exc:
        fail(f"Inspection failed: {type(exc).__name__}")


@user_app.command("list")
def user_list(server: str = typer.Option(...)) -> None:
    run_inspection(server, "users")


@user_app.command("inspect")
def user_inspect(name: str, server: str = typer.Option(...)) -> None:
    run_inspection(server, "user", name)


@group_app.command("list")
def group_list(server: str = typer.Option(...)) -> None:
    run_inspection(server, "groups")


@group_app.command("inspect")
def group_inspect(name: str, server: str = typer.Option(...)) -> None:
    run_inspection(server, "group", name)


@storage_app.command("summary")
def storage_summary(server: str = typer.Option(...)) -> None:
    run_inspection(server, "storage")


@storage_app.command("inodes")
def storage_inodes(server: str = typer.Option(...)) -> None:
    run_inspection(server, "inodes")


@storage_app.command("large-files")
def large_files(
    server: str = typer.Option(...),
    path: str = typer.Option(...),
    min_bytes: int = typer.Option(0),
    days: int = typer.Option(0),
    limit: int = typer.Option(20),
    max_entries: int = typer.Option(100000),
    seconds: int = typer.Option(30),
    depth: int = typer.Option(10),
) -> None:
    """Find large files with explicit resource limits; old files are review candidates."""
    target = get_server(server)
    password = None
    if target.ssh.auth == "password":
        if not sys.stdin.isatty():
            fail("Password authentication requires a local interactive terminal", 2)
        password = getpass.getpass("SSH password: ")
    try:
        result = asyncio.run(
            scan(target, path, min_bytes, days, limit, max_entries, seconds, depth, password)
        )
        output({"server": server, "path": path, **result})
    except (asyncssh.Error, OSError, TimeoutError, ValueError, TypeError, RuntimeError) as exc:
        fail(f"Scan failed: {type(exc).__name__}: {exc}")
