"""Persisted, digest-bound plans and local-only approval for all supported mutations."""

from __future__ import annotations

import asyncio
import base64
import getpass
import hashlib
import json
import os
import re
import secrets
import shlex
import sqlite3
import stat
import sys
import time
import zlib
from collections.abc import AsyncIterator, Iterator
from contextlib import asynccontextmanager, contextmanager
from enum import StrEnum
from pathlib import Path
from typing import Any

import asyncssh
from pydantic import BaseModel, ConfigDict, Field

from ..inventory import load as load_inventory
from ..models import Server
from . import worker


class Stage(StrEnum):
    DISCOVER = "discover"
    PLAN = "plan"
    VALIDATE = "validate"
    PREVIEW = "preview"
    APPROVE = "approve"
    AUTHENTICATE = "authenticate"
    EXECUTE = "execute"
    VERIFY = "verify"
    AUDIT = "audit"


class Plan(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    schema_version: int = 2
    id: str = Field(pattern=r"^[0-9a-f]{32}$")
    server_name: str
    server: dict[str, Any]
    host_key: str
    operation: dict[str, Any]
    current_state: dict[str, Any]
    preview: dict[str, Any]
    worker_digest: str
    remote_command: str
    created_at: int
    expires_at: int
    local_uid: int
    risk: str = "privileged change"
    digest: str = ""

    def computed_digest(self) -> str:
        return worker.digest(self.model_dump(exclude={"digest"}))

    def validate_for(self, server: Server) -> None:
        if self.schema_version != 2 or self.digest != self.computed_digest():
            raise worker.Refusal("plan was modified or has an unsupported schema")
        if self.local_uid != os.getuid() or not self.created_at <= time.time() < self.expires_at:
            raise worker.Refusal("plan expired or belongs to another local user")
        if self.server != server.model_dump():
            raise worker.Refusal("registered server or storage policy changed")
        if self.worker_digest != source_digest() or self.remote_command != remote_command(
            server.sudo.authentication
        ):
            raise worker.Refusal("execution engine changed; regenerate plan")
        normalized = worker.normalize(self.operation)
        if (
            normalized != self.operation
            or worker.compile_steps(normalized, self.current_state) != self.preview
        ):
            raise worker.Refusal("plan is not the independently compiled allowed operation")


def source_bytes() -> bytes:
    return Path(worker.__file__).read_bytes()


def source_digest() -> str:
    return hashlib.sha256(source_bytes()).hexdigest()


def remote_command(authentication: str = "interactive") -> str:
    payload = base64.b64encode(zlib.compress(source_bytes(), 9)).decode("ascii")
    code = (
        "import base64,zlib;exec(compile(zlib.decompress(base64.b64decode("
        + repr(payload)
        + ")), '<cluster-manager-worker>', 'exec'))"
    )
    prefix = (
        ["sudo", "-n", "--"]
        if authentication == "noninteractive"
        else ["sudo", "-k", "-S", "-p", "CM_SUDO_PASSWORD_V2:", "--"]
    )
    return shlex.join(prefix + ["/usr/bin/python3", "-I", "-S", "-c", code])


def state_dir() -> Path:
    directory = (
        Path(os.environ.get("XDG_STATE_HOME", Path.home() / ".local/state")) / "cluster-manager"
    )
    directory.mkdir(parents=True, mode=0o700, exist_ok=True)
    info = directory.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
        raise worker.Refusal("state directory must be owned by you and mode 0700")
    return directory


def _plan_path(ident: str) -> Path:
    if not re.fullmatch(r"[0-9a-f]{32}", ident):
        raise worker.Refusal("invalid plan ID")
    return state_dir() / (ident + ".plan.json")


def save(plan: Plan) -> None:
    fd = os.open(_plan_path(plan.id), os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as stream:
        stream.write(plan.model_dump_json(indent=2))
        stream.flush()
        os.fsync(stream.fileno())


def load(ident: str) -> Plan:
    fd = os.open(_plan_path(ident), os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, encoding="utf-8") as stream:
        info = os.fstat(stream.fileno())
        if info.st_uid != os.getuid() or info.st_mode & 0o077 or not stat.S_ISREG(info.st_mode):
            raise worker.Refusal("plan file has unsafe ownership or permissions")
        plan = Plan.model_validate_json(stream.read(2_000_001))
    if plan.id != ident:
        raise worker.Refusal("plan ID does not match filename")
    return plan


@contextmanager
def database() -> Iterator[sqlite3.Connection]:
    path = state_dir() / "operations.sqlite3"
    fd = os.open(path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    info = os.fstat(fd)
    os.close(fd)
    if info.st_uid != os.getuid() or info.st_mode & 0o077 or not stat.S_ISREG(info.st_mode):
        raise worker.Refusal("audit database has unsafe permissions")
    connection = sqlite3.connect(path, timeout=5)
    connection.execute(
        "CREATE TABLE IF NOT EXISTS events (id INTEGER PRIMARY KEY, plan_id TEXT NOT NULL, stage TEXT NOT NULL, at INTEGER NOT NULL, data TEXT NOT NULL)"
    )
    connection.execute(
        "CREATE TABLE IF NOT EXISTS attempts (plan_id TEXT PRIMARY KEY, digest TEXT NOT NULL, at INTEGER NOT NULL)"
    )
    try:
        yield connection
        connection.commit()
    finally:
        connection.close()


def event(plan_id: str, stage: Stage, data: dict[str, Any]) -> None:
    with database() as conn:
        conn.execute(
            "INSERT INTO events(plan_id,stage,at,data) VALUES(?,?,?,?)",
            (plan_id, stage.value, int(time.time()), json.dumps(data, sort_keys=True)),
        )


def claim(plan: Plan) -> None:
    try:
        with database() as conn:
            conn.execute(
                "INSERT INTO attempts VALUES(?,?,?)", (plan.id, plan.digest, int(time.time()))
            )
    except sqlite3.IntegrityError as exc:
        raise worker.Refusal(
            "plan already attempted; verify its result and generate a new plan"
        ) from exc


def history(ident: str) -> list[dict[str, Any]]:
    _plan_path(ident)
    with database() as conn:
        return [
            {"stage": stage, "at": at, "data": json.loads(data)}
            for stage, at, data in conn.execute(
                "SELECT stage,at,data FROM events WHERE plan_id=? ORDER BY id", (ident,)
            )
        ]


def registered(name: str) -> Server:
    servers = load_inventory().servers
    if name not in servers:
        raise worker.Refusal("unknown registered server")
    return servers[name]


@asynccontextmanager
async def connect(server: Server) -> AsyncIterator[asyncssh.SSHClientConnection]:
    kwargs: dict[str, Any] = {
        "username": server.ssh.username,
        "port": server.port,
        "connect_timeout": 10,
        "login_timeout": 15,
    }
    if server.ssh.auth == "password":
        if not sys.stdin.isatty():
            raise worker.Refusal("SSH password requires a local terminal")
        kwargs.update(
            password=getpass.getpass("SSH password: "), client_keys=[], preferred_auth="password"
        )
    else:
        kwargs.update(preferred_auth="publickey")
    async with asyncssh.connect(server.host, **kwargs) as connection:
        yield connection


def host_key(conn: asyncssh.SSHClientConnection) -> str:
    key = conn.get_server_host_key()
    if key is None:
        raise worker.Refusal("server key missing")
    return key.get_fingerprint()


async def invoke(
    conn: asyncssh.SSHClientConnection,
    request: dict[str, Any],
    privileged: bool = True,
    authentication: str = "interactive",
) -> dict[str, Any]:
    request = {**request, "protocol": worker.PROTOCOL}
    argv = shlex.split(remote_command(authentication))
    command = shlex.join(argv if privileged else argv[argv.index("--") + 1 :])
    async with conn.create_process(command, encoding="utf-8") as process:

        async def read_bounded(stream: Any) -> str:
            text = ""
            while True:
                part = await stream.read(65536)
                if not part:
                    return text
                text += part
                if len(text) > 2_000_000:
                    raise worker.Refusal("worker output limit exceeded")

        async def stdout_protocol() -> str:
            greeting = ""
            while not greeting.endswith("\n"):
                char = await process.stdout.read(1)
                if not char or len(greeting) > 64:
                    raise worker.Refusal(
                        "worker did not start; check sudo authorization and Python availability"
                    )
                greeting += char
            if greeting != "CM_WORKER_READY_V2\n":
                raise worker.Refusal("unexpected worker greeting")
            # Only send JSON after sudo has consumed its password (if any) and the worker is ready.
            process.stdin.write(json.dumps(request))
            process.stdin.write_eof()
            return await read_bounded(process.stdout)

        async def stderr_protocol() -> None:
            pending = ""
            prompted = False
            total = 0
            while True:
                part = await process.stderr.read(1024)
                if not part:
                    return
                total += len(part)
                if total > 65536:
                    raise worker.Refusal("sudo diagnostic output limit exceeded")
                pending = (pending + part)[-2048:]
                if "CM_SUDO_PASSWORD_V2:" in pending:
                    if authentication != "interactive" or prompted or not sys.stdin.isatty():
                        raise worker.Refusal(
                            "sudo needs local authentication or rejected the password"
                        )
                    prompted = True
                    pending = ""
                    password = getpass.getpass("sudo password (local prompt): ")
                    if any(c in password for c in "\n\r\x00"):
                        raise worker.Refusal("invalid sudo password input")
                    process.stdin.write(password + "\n")
                    password = ""  # Best effort; no claim of memory erasure.

        tasks = [asyncio.create_task(stdout_protocol()), asyncio.create_task(stderr_protocol())]
        try:
            stdout, _ = await asyncio.wait_for(asyncio.gather(*tasks), 180)
            await asyncio.wait_for(process.wait_closed(), 5)
        finally:
            for task in tasks:
                if not task.done():
                    task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
        if not isinstance(stdout, str):
            raise worker.Refusal("worker returned no output")
        if process.exit_status != 0:
            try:
                message = json.loads(stdout).get("error", "remote operation failed")
            except (ValueError, AttributeError):
                message = "worker failed; check sudo authorization and Python availability"
            raise worker.Refusal(str(message))
        result = json.loads(stdout)
        if not isinstance(result, dict) or "error" in result:
            raise worker.Refusal("invalid worker response")
        return result


async def make_plan(name: str, raw: dict[str, Any], ttl: int = 900) -> Plan:
    if not 60 <= ttl <= 3600:
        raise worker.Refusal("plan lifetime must be 60..3600 seconds")
    op = worker.normalize(raw)
    server = registered(name)
    async with connect(server) as conn:
        observed = await invoke(
            conn,
            {"phase": "discover", "operation": op, "roots": server.storage_roots},
            authentication=server.sudo.authentication,
        )
        # Ignore remote executable previews. Compile them independently from typed operation/state.
        compiled = worker.compile_steps(op, observed["snapshot"])
        plan = Plan(
            id=secrets.token_hex(16),
            server_name=name,
            server=server.model_dump(),
            host_key=host_key(conn),
            operation=op,
            current_state=observed["snapshot"],
            preview=compiled,
            worker_digest=source_digest(),
            remote_command=remote_command(server.sudo.authentication),
            created_at=int(time.time()),
            expires_at=int(time.time()) + ttl,
            local_uid=os.getuid(),
        )
    plan.digest = plan.computed_digest()
    plan.validate_for(server)
    save(plan)
    for stage in (Stage.DISCOVER, Stage.PLAN, Stage.VALIDATE):
        event(plan.id, stage, {"digest": plan.digest})
    return plan


def terminal_approval(plan: Plan) -> None:
    if not sys.stdin.isatty() or not sys.stdout.isatty():
        raise worker.Refusal(
            "apply requires a local interactive terminal; piped approval is forbidden"
        )
    from ..presentation import render

    render(
        {
            "server": plan.server_name,
            "plan_id": plan.id,
            "digest": plan.digest,
            "operation": plan.operation,
            "preview": plan.preview,
        },
        "Review change plan",
    )
    event(plan.id, Stage.PREVIEW, {"digest": plan.digest})
    required = "approve " + plan.digest[:12]
    with (
        open("/dev/tty", "r", encoding="utf-8") as tty_in,
        open("/dev/tty", "w", encoding="utf-8") as tty_out,
    ):
        tty_out.write("Type '" + required + "' to approve this exact plan: ")
        tty_out.flush()
        if tty_in.readline().strip() != required:
            raise worker.Refusal("approval declined")
    plan.validate_for(registered(plan.server_name))
    event(plan.id, Stage.APPROVE, {"digest": plan.digest, "uid": os.getuid(), "pid": os.getpid()})


def collect_secrets(plan: Plan, independent_samba: bool = False) -> dict[str, str]:
    keys = {s.get("secret") for s in plan.preview["steps"]} - {None}
    result: dict[str, str] = {}
    for key in ("linux", "samba"):
        if key not in keys:
            continue
        if key == "samba" and "linux" in result and not independent_samba:
            result[key] = result["linux"]
            continue
        first = getpass.getpass(f"Initial {key} password: ")
        second = getpass.getpass(f"Confirm {key} password: ")
        if not first or first != second or any(c in first for c in "\n\r\x00"):
            raise worker.Refusal("password confirmation failed or invalid password format")
        result[key] = first
    return result


async def apply(ident: str, independent_samba: bool = False) -> dict[str, Any]:
    plan = load(ident)
    server = registered(plan.server_name)
    plan.validate_for(server)
    with database() as db:
        if db.execute("SELECT 1 FROM attempts WHERE plan_id=?", (plan.id,)).fetchone():
            raise worker.Refusal("plan already attempted; verify and generate a new plan")
    async with connect(server) as conn:
        if host_key(conn) != plan.host_key:
            raise worker.Refusal("host key differs from planned server identity")
        fresh = await invoke(
            conn,
            {"phase": "discover", "operation": plan.operation, "roots": server.storage_roots},
            authentication=server.sudo.authentication,
        )
        if fresh["snapshot"] != plan.current_state:
            raise worker.Refusal("state changed since planning; create a new plan")
        if not plan.preview["steps"]:
            event(plan.id, Stage.VERIFY, {"status": "noop"})
            return {"status": "noop", "plan_id": ident}
        terminal_approval(plan)
        passwords = collect_secrets(plan, independent_samba)
        plan.validate_for(registered(plan.server_name))
        event(
            plan.id,
            Stage.AUTHENTICATE,
            {"method": "SSH + configured sudo", "secrets_logged": False},
        )
        claim(plan)
        event(plan.id, Stage.EXECUTE, {"digest": plan.digest})
        try:
            result = await invoke(
                conn,
                {
                    "phase": "execute",
                    "operation": plan.operation,
                    "roots": server.storage_roots,
                    "snapshot_digest": worker.digest(plan.current_state),
                    "compiled_digest": worker.digest(plan.preview),
                    "expires_at": plan.expires_at,
                    "secrets": passwords,
                },
                authentication=server.sudo.authentication,
            )
        except BaseException:
            event(
                plan.id,
                Stage.AUDIT,
                {"status": "outcome_unknown", "recovery": "verify before replanning"},
            )
            raise
        finally:
            passwords.clear()  # Best effort only; Python cannot guarantee secret memory erasure.
        event(plan.id, Stage.VERIFY, result)
        event(plan.id, Stage.AUDIT, {"status": result.get("status"), "digest": plan.digest})
        return {"plan_id": ident, **result}


async def verify(ident: str) -> dict[str, Any]:
    plan = load(ident)
    if plan.digest != plan.computed_digest():
        raise worker.Refusal("modified plan")
    server = registered(plan.server_name)
    if server.model_dump() != plan.server:
        raise worker.Refusal("target configuration changed")
    async with connect(server) as conn:
        if host_key(conn) != plan.host_key:
            raise worker.Refusal("target host key changed")
        result = await invoke(
            conn,
            {
                "phase": "verify",
                "operation": worker.normalize(plan.operation),
                "roots": server.storage_roots,
            },
            authentication=server.sudo.authentication,
        )
    event(plan.id, Stage.VERIFY, result)
    return result


async def samba_inspect(name: str) -> dict[str, Any]:
    async with connect(registered(name)) as conn:
        return await invoke(conn, {"phase": "samba.inspect"}, privileged=False)


async def inspect_remote(name: str, phase: str, path: str | None = None) -> dict[str, Any]:
    if phase not in ("workspace.inspect", "files.inspect", "samba.users"):
        raise worker.Refusal("unsupported inspection")
    server = registered(name)
    async with connect(server) as conn:
        return await invoke(
            conn,
            {"phase": phase, "roots": server.storage_roots, "path": path},
            privileged=phase == "samba.users",
            authentication=server.sudo.authentication,
        )
