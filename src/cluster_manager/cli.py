from __future__ import annotations

import asyncio
import getpass
import json
import sys
from pathlib import Path
from typing import Any, NoReturn

import asyncssh
import typer
import yaml
from pydantic import ValidationError

from . import inventory
from .discovery import discover
from .inspect import inspect
from .managed import engine, worker
from .models import Server, SSHConfig
from .simulation import DATA, run_scenario
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


def fail(message: str, code: int = 1) -> NoReturn:
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
    storage_root: list[str] = typer.Option([], "--storage-root"),
) -> None:
    """Confirm and save a nonsecret server record. Does not contact the host."""
    try:
        server = Server(
            host=host,
            port=port,
            ssh=SSHConfig.model_validate({"username": username, "auth": auth}),
            storage_roots=storage_root,
        )
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
def simulate(
    server: str | None = typer.Option(None), scenario: Path | None = typer.Option(None)
) -> None:
    """Show explicitly labeled fixture data, without network access."""
    if scenario is not None:
        try:
            raw = yaml.safe_load(scenario.read_text(encoding="utf-8"))
            if (
                not isinstance(raw, dict)
                or set(raw) != {"server", "operations"}
                or not isinstance(raw["operations"], list)
            ):
                fail("Scenario requires server and operations", 2)
            output(run_scenario(raw["server"], raw["operations"]))
            return
        except (OSError, ValueError, yaml.YAMLError, worker.Refusal) as exc:
            managed_error(exc)
    if server and server not in DATA:
        fail("Unknown simulated server", 2)
    output({"simulation": True, "servers": {server: DATA[server]} if server else DATA})


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


plan_app = typer.Typer(invoke_without_command=True, no_args_is_help=True)
workspace_app = typer.Typer(no_args_is_help=True)
permission_app = typer.Typer(no_args_is_help=True)
samba_app = typer.Typer(no_args_is_help=True)
audit_app = typer.Typer(no_args_is_help=True)
app.add_typer(plan_app, name="plan")
app.add_typer(workspace_app, name="workspace")
app.add_typer(permission_app, name="permissions")
app.add_typer(samba_app, name="samba")
app.add_typer(audit_app, name="audit")


def managed_error(exc: Exception) -> None:
    # Machine-safe rendering for errors containing remote or filesystem data.
    typer.echo(json.dumps({"error": str(exc), "type": type(exc).__name__}), err=True)
    raise typer.Exit(1)


def propose(server: str, operation: dict[str, Any]) -> None:
    try:
        plan = asyncio.run(engine.make_plan(server, operation))
        output(
            {
                "plan_id": plan.id,
                "approved": False,
                "plan": plan.model_dump(),
                "next": "cluster-manager apply " + plan.id,
            }
        )
    except (asyncssh.Error, OSError, TimeoutError, ValueError, worker.Refusal, KeyError) as exc:
        managed_error(exc)


@plan_app.callback()
def plan_file(ctx: typer.Context, file: Path | None = typer.Option(None, "--file")) -> None:
    """Discover and save a plan from YAML containing server and operation."""
    if ctx.invoked_subcommand:
        return
    if file is None:
        fail("Provide --file desired.yaml or use plan show PLAN_ID", 2)
    try:
        value = yaml.safe_load(file.read_text(encoding="utf-8"))
        if not isinstance(value, dict) or set(value) != {"server", "operation"}:
            fail("Desired YAML must contain exactly server and operation", 2)
        if not isinstance(value["server"], str):
            fail("server must be a registered server name", 2)
        propose(value["server"], value["operation"])
    except (OSError, ValueError, yaml.YAMLError) as exc:
        managed_error(exc)


@plan_app.command("show")
def plan_show(plan_id: str) -> None:
    try:
        plan = engine.load(plan_id)
        output(plan.model_dump())
    except (OSError, ValueError, worker.Refusal) as exc:
        managed_error(exc)


@app.command("apply")
def apply_plan(plan_id: str, independent_samba: bool = typer.Option(False)) -> None:
    """Approve in a local terminal, execute and verify a saved plan."""
    if not sys.stdin.isatty() or not sys.stdout.isatty():
        fail("Apply requires a local interactive terminal", 2)
    try:
        result = asyncio.run(engine.apply(plan_id, independent_samba))
        output(result)
        if result.get("status") not in ("verified", "noop"):
            raise typer.Exit(1)
    except (asyncssh.Error, OSError, TimeoutError, ValueError, worker.Refusal, KeyError) as exc:
        managed_error(exc)


@app.command("verify")
def verify_plan(plan_id: str) -> None:
    try:
        result = asyncio.run(engine.verify(plan_id))
        output(result)
        if not result.get("verified"):
            raise typer.Exit(1)
    except (asyncssh.Error, OSError, TimeoutError, ValueError, worker.Refusal, KeyError) as exc:
        managed_error(exc)


@audit_app.command("show")
def audit_show(plan_id: str) -> None:
    try:
        output({"plan_id": plan_id, "events": engine.history(plan_id)})
    except (OSError, ValueError, worker.Refusal) as exc:
        managed_error(exc)


@group_app.command("create")
@group_app.command("plan")
def group_create(name: str, server: str = typer.Option(...)) -> None:
    propose(server, {"type": "group.create", "group": name})


@user_app.command("create")
def user_create(
    name: str,
    server: str = typer.Option(...),
    group: list[str] = typer.Option([], "--group"),
    home: str | None = typer.Option(None),
    password: bool = typer.Option(True),
    samba: bool = typer.Option(False),
) -> None:
    propose(
        server,
        {
            "type": "user.create",
            "username": name,
            "groups": group,
            "home": home,
            "password": password,
            "samba": samba,
        },
    )


@user_app.command("password")
def user_password(
    name: str, server: str = typer.Option(...), samba: bool = typer.Option(False)
) -> None:
    propose(server, {"type": "user.password", "username": name, "samba": samba})


@user_app.command("add-group")
def user_add_group(name: str, group: str, server: str = typer.Option(...)) -> None:
    propose(server, {"type": "user.membership", "username": name, "group": group, "action": "add"})


@user_app.command("remove-group")
def user_remove_group(name: str, group: str, server: str = typer.Option(...)) -> None:
    propose(
        server, {"type": "user.membership", "username": name, "group": group, "action": "remove"}
    )


@user_app.command("lock")
def user_lock(name: str, server: str = typer.Option(...)) -> None:
    propose(server, {"type": "user.lock", "username": name})


@user_app.command("unlock")
def user_unlock(name: str, server: str = typer.Option(...)) -> None:
    propose(server, {"type": "user.unlock", "username": name})


@workspace_app.command("create")
def workspace_create(
    server: str = typer.Option(...),
    path: str = typer.Option(...),
    group: str = typer.Option(...),
    mode: str = typer.Option("2775"),
    samba: str = typer.Option("existing"),
) -> None:
    propose(
        server,
        {"type": "workspace.create", "path": path, "group": group, "mode": mode, "samba": samba},
    )


@permission_app.command("set")
def permissions_set(
    server: str = typer.Option(...),
    path: str = typer.Option(...),
    group: str = typer.Option(...),
    mode: str = typer.Option(...),
) -> None:
    propose(server, {"type": "permissions.set", "path": path, "group": group, "mode": mode})


@workspace_app.command("list")
def workspace_list(server: str = typer.Option(...)) -> None:
    try:
        output(asyncio.run(engine.inspect_remote(server, "workspace.inspect")))
    except (asyncssh.Error, OSError, TimeoutError, ValueError, worker.Refusal) as exc:
        managed_error(exc)


@workspace_app.command("inspect")
@permission_app.command("audit")
def workspace_inspect(server: str = typer.Option(...), path: str = typer.Option(...)) -> None:
    try:
        output(asyncio.run(engine.inspect_remote(server, "workspace.inspect", path)))
    except (asyncssh.Error, OSError, TimeoutError, ValueError, worker.Refusal) as exc:
        managed_error(exc)


@samba_app.command("shares")
def samba_shares(server: str = typer.Option(...)) -> None:
    try:
        output(asyncio.run(engine.samba_inspect(server)))
    except (asyncssh.Error, OSError, TimeoutError, ValueError, worker.Refusal) as exc:
        managed_error(exc)


@samba_app.command("users")
def samba_users(server: str = typer.Option(...)) -> None:
    try:
        output(asyncio.run(engine.inspect_remote(server, "samba.users")))
    except (asyncssh.Error, OSError, TimeoutError, ValueError, worker.Refusal) as exc:
        managed_error(exc)


@samba_app.command("audit")
def samba_audit(server: str = typer.Option(...), path: str = typer.Option(...)) -> None:
    try:
        worker.canonical(path)
        state = asyncio.run(engine.samba_inspect(server))
        output(
            {
                "config_changes": False,
                "covering_shares": worker.covering_shares(path, state),
                "filesystem": asyncio.run(engine.inspect_remote(server, "workspace.inspect", path)),
                "note": "Share policy and Unix permissions are separate. This does not test an SMB login.",
            }
        )
    except (asyncssh.Error, OSError, TimeoutError, ValueError, worker.Refusal) as exc:
        managed_error(exc)


@samba_app.command("user-add")
def samba_add(name: str, server: str = typer.Option(...)) -> None:
    propose(server, {"type": "samba.user.ensure", "username": name})


@samba_app.command("password")
def samba_password(name: str, server: str = typer.Option(...)) -> None:
    propose(server, {"type": "samba.user.password", "username": name})


@samba_app.command("user-disable")
def samba_disable(name: str, server: str = typer.Option(...)) -> None:
    propose(server, {"type": "samba.user.disable", "username": name})
