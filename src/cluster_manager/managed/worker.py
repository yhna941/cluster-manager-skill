"""Self-contained, constrained Linux worker. Shipped over SSH; no daemon or config writes.

Only this constant module is executed remotely. Request data never becomes Python or shell code.
The module also exposes pure compilation functions for local independent plan validation.
"""

from __future__ import annotations

import contextlib
import fcntl
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import time
from pathlib import PurePosixPath
from typing import Any

PROTOCOL = 2
NAME = r"[A-Za-z_][A-Za-z0-9_-]{0,31}"
KINDS = {
    "group.create",
    "user.create",
    "user.password",
    "user.membership",
    "user.lock",
    "user.unlock",
    "workspace.create",
    "permissions.set",
    "samba.user.ensure",
    "samba.user.password",
    "samba.user.disable",
}
FIELDS = {
    "group.create": {"group"},
    "user.create": {"username", "groups", "home", "password", "samba"},
    "user.password": {"username", "samba"},
    "user.membership": {"username", "group", "action"},
    "user.lock": {"username"},
    "user.unlock": {"username"},
    "workspace.create": {"path", "group", "mode", "samba"},
    "permissions.set": {"path", "group", "mode"},
    "samba.user.ensure": {"username"},
    "samba.user.password": {"username"},
    "samba.user.disable": {"username"},
}


class Refusal(RuntimeError):
    """A precondition or safety invariant was not satisfied."""


def digest(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def canonical(path: Any) -> str:
    if not isinstance(path, str) or not re.fullmatch(r"/[A-Za-z0-9_./-]+", path):
        raise Refusal("managed paths must be absolute and use letters, digits, /, ., _, -")
    p = PurePosixPath(path)
    if str(p) != path or ".." in p.parts or path == "/":
        raise Refusal("noncanonical or filesystem-root path")
    return path


def normalize(raw: Any) -> dict[str, Any]:
    if not isinstance(raw, dict) or raw.get("type") not in KINDS:
        raise Refusal("unsupported operation")
    kind = raw["type"]
    if set(raw) - FIELDS[kind] - {"type"}:
        raise Refusal("unknown operation fields (secrets and arbitrary commands are forbidden)")
    op = dict(raw)
    if kind == "user.create":
        op.setdefault("groups", [])
        op.setdefault("home", None)
        op.setdefault("password", True)
        op.setdefault("samba", False)
    if kind == "user.password":
        op.setdefault("samba", False)
    if kind == "workspace.create":
        op.setdefault("mode", "2775")
        op.setdefault("samba", "existing")
    if set(op) != FIELDS[kind] | {"type"}:
        raise Refusal("missing required operation fields")
    for key in ("username", "group"):
        if key in op and (not isinstance(op[key], str) or not re.fullmatch(NAME, op[key])):
            raise Refusal("invalid identity name")
    if "groups" in op:
        if (
            not isinstance(op["groups"], list)
            or len(op["groups"]) > 32
            or any(not isinstance(g, str) or not re.fullmatch(NAME, g) for g in op["groups"])
        ):
            raise Refusal("invalid supplementary groups")
        op["groups"] = sorted(set(op["groups"]))
    if "path" in op:
        canonical(op["path"])
    if op.get("home") is not None:
        canonical(op["home"])
    if "mode" in op and op["mode"] not in ("2770", "2775"):
        raise Refusal("workspace mode must be 2770 or 2775; recursive changes are unsupported")
    if "password" in op and type(op["password"]) is not bool:
        raise Refusal("password is a boolean request, never a secret value")
    if "samba" in op:
        if kind == "workspace.create":
            if op["samba"] not in ("existing", "off"):
                raise Refusal("Samba policy must be existing or off; config editing is forbidden")
        elif type(op["samba"]) is not bool:
            raise Refusal("samba must be boolean")
    if kind == "user.create" and op["samba"] and not op["password"]:
        raise Refusal("combined provisioning requires an initial password")
    if kind == "user.membership" and op["action"] not in ("add", "remove"):
        raise Refusal("membership action must be add or remove")
    if op.get("username") == "root":
        raise Refusal("root account mutation is outside the supported scope")
    return op


def run(argv: list[str], input_data: str | None = None, allowed: tuple[int, ...] = (0,)) -> str:
    # No shell; fixed safe PATH; command stdout/stderr never enters exception messages.
    try:
        result = subprocess.run(
            argv,
            check=False,
            input=input_data,
            text=True,
            capture_output=True,
            timeout=30,
            env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"},
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise Refusal("command unavailable or timed out: " + argv[0]) from exc
    if result.returncode not in allowed:
        raise Refusal("command failed: " + argv[0] + " (exit " + str(result.returncode) + ")")
    return result.stdout


def identity(database: str, name: str) -> dict[str, Any] | None:
    nss = run(["getent", database, name], allowed=(0, 2))
    local = run(["getent", "-s", "files", database, name], allowed=(0, 2))
    if not nss and not local:
        return None
    if not nss or nss != local or len(nss.splitlines()) != 1:
        raise Refusal("identity is externally managed or ambiguous: " + name)
    fields = nss.rstrip("\n").split(":")
    if fields[0] != name:
        raise Refusal("identity mismatch")
    if database == "passwd":
        if len(fields) != 7 or int(fields[2]) < 1000:
            raise Refusal("system account mutation is outside the supported scope")
        return {
            "name": name,
            "uid": int(fields[2]),
            "gid": int(fields[3]),
            "home": fields[5],
            "shell": fields[6],
        }
    if len(fields) != 4:
        raise Refusal("invalid group database")
    return {
        "name": name,
        "gid": int(fields[2]),
        "members": sorted(filter(None, fields[3].split(","))),
    }


def file_hash(path: str) -> str:
    with open(path, "rb") as stream:
        return hashlib.sha256(stream.read(4_194_304)).hexdigest()


def meta(fd: int) -> dict[str, int]:
    value = os.fstat(fd)
    return {
        "device": value.st_dev,
        "inode": value.st_ino,
        "uid": value.st_uid,
        "gid": value.st_gid,
        "mode": stat.S_IMODE(value.st_mode),
    }


@contextlib.contextmanager
def directory(path: str) -> Any:
    """Walk every component using O_NOFOLLOW and pin the resulting directory inode."""
    canonical(path)
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
    try:
        for component in PurePosixPath(path).parts[1:]:
            child = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = child
        yield fd
    finally:
        os.close(fd)


def path_state(path: str, missing_ok: bool = False) -> dict[str, int] | None:
    try:
        with directory(path) as fd:
            return meta(fd)
    except FileNotFoundError:
        if missing_ok:
            return None
        raise Refusal("required directory is missing") from None
    except OSError as exc:
        raise Refusal("path is not a safe directory") from exc


def xattr_names(path: str) -> list[str]:
    function = getattr(os, "listxattr", None)
    if function is None:
        raise Refusal("ACL feature detection unavailable")
    return list(function(path))


def mount_state(root: str) -> dict[str, Any]:
    # Exact mountpoint required; no writes to a fallback directory on the root disk.
    with open("/proc/self/mountinfo", encoding="utf-8") as stream:
        for line in stream:
            parts = line.split()
            separator = parts.index("-")
            target = re.sub(r"\\([0-7]{3})", lambda m: chr(int(m[1], 8)), parts[4])
            if target == root:
                if parts[separator + 1] not in ("ext2", "ext3", "ext4", "xfs", "btrfs", "tmpfs"):
                    raise Refusal("filesystem lacks a supported Unix-permission adapter")
                if "rw" not in parts[5].split(",") or "rw" not in parts[separator + 3].split(","):
                    raise Refusal("storage filesystem is read-only")
                return {
                    "id": parts[0],
                    "device": parts[2],
                    "root": parts[3],
                    "target": target,
                    "options": parts[5],
                    "filesystem": parts[separator + 1],
                    "source": parts[separator + 2],
                }
    raise Refusal("configured storage root is not an actual mounted filesystem")


def storage_state(path: str, roots: list[str], home: bool = False) -> dict[str, Any]:
    for root in roots:
        canonical(root)
    candidates = [r for r in roots if path.startswith(r + "/")]
    if not candidates:
        raise Refusal("path is outside registered storage roots")
    root = max(candidates, key=len)
    if any(
        root == p or root.startswith(p + "/")
        for p in ("/etc", "/usr", "/bin", "/sbin", "/boot", "/proc", "/sys", "/dev", "/run")
    ):
        raise Refusal("system paths cannot be storage roots")
    rel = PurePosixPath(path).relative_to(root).parts
    if (not home and len(rel) != 1) or (home and (len(rel) != 3 or rel[1] != "usr")):
        raise Refusal("workspace must be a direct child; home must be WORKSPACE/usr/USERNAME")
    mounted = mount_state(root)
    chain = []
    for ancestor in reversed(PurePosixPath(root).parents):
        if str(ancestor) == "/":
            continue
        info = path_state(str(ancestor))
        if info is None or info["uid"] != 0 or info["mode"] & 0o022:
            raise Refusal("storage ancestors must be root-owned and not group/world writable")
        chain.append(info)
    root_info = path_state(root)
    if root_info is None or root_info["uid"] != 0 or root_info["mode"] & 0o022:
        raise Refusal("storage mountpoint must be root-owned and not group/world writable")
    value: dict[str, Any] = {
        "root": root,
        "mount": mounted,
        "root_stat": root_info,
        "ancestors": chain,
    }
    parent = str(PurePosixPath(path).parent)
    if home:
        workspace = path_state(str(PurePosixPath(parent).parent))
        parent_info = path_state(parent)
        if workspace is None or workspace["uid"] != 0 or parent_info is None:
            raise Refusal("home requires an existing root-owned workspace and usr directory")
        if parent_info["uid"] != 0 or parent_info["mode"] & 0o022:
            raise Refusal("home parent must be root-owned and not group/world writable")
        if (
            parent_info["device"] != root_info["device"]
            or workspace["device"] != root_info["device"]
        ):
            raise Refusal("home parents cross a filesystem boundary")
        value.update(parent=parent_info, workspace=workspace)
    acl_parent = parent if home else root
    if "system.posix_acl_default" in xattr_names(acl_parent):
        raise Refusal(
            "default ACL inheritance requires explicit ACL support; refusing implicit change"
        )
    value["target"] = path_state(path, True)
    if value["target"] is not None and value["target"]["device"] != root_info["device"]:
        raise Refusal("target crosses a filesystem boundary")
    if not home and value["target"] is not None:
        if value["target"]["uid"] != 0:
            raise Refusal("existing workspace is not owned by root")
        if any(a.startswith("system.posix_acl_") for a in xattr_names(path)):
            raise Refusal("existing ACL requires explicit ACL support; refusing chmod mask changes")
        value["usr"] = path_state(path + "/usr", True)
    else:
        value["usr"] = None
    if os.statvfs(root).f_bavail * os.statvfs(root).f_frsize < 1024 * 1024:
        raise Refusal("less than 1 MiB available on storage filesystem")
    return value


def samba_state(username: str | None = None) -> dict[str, Any]:
    if shutil.which("testparm") is None:
        return {"available": False, "reason": "testparm unavailable"}
    text = run(["testparm", "-s", "/etc/samba/smb.conf"])
    sections: dict[str, dict[str, str]] = {}
    current: dict[str, str] = {}
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("[") and line.endswith("]"):
            current = sections.setdefault(line[1:-1], {})
        elif "=" in line and not line.startswith(("#", ";")):
            key, value = line.split("=", 1)
            current[key.strip().lower()] = value.strip()
    global_config = next((v for k, v in sections.items() if k.lower() == "global"), {})
    role = global_config.get("server role", "auto").lower()
    security = global_config.get("security", "user").lower()
    backend = global_config.get("passdb backend", "tdbsam").lower()
    supported = (
        role in ("auto", "standalone server")
        and security == "user"
        and backend in ("tdbsam", "smbpasswd")
        and global_config.get("domain logons", "no").lower() == "no"
        and not global_config.get("realm")
        and global_config.get("unix password sync", "no").lower() == "no"
    )
    db_path = (
        global_config.get("private dir", "/var/lib/samba/private") + "/passdb.tdb"
        if backend == "tdbsam"
        else global_config.get("smb passwd file", "/etc/samba/smbpasswd")
    )
    result: dict[str, Any] = {
        "passdb_exists": os.path.exists(db_path),
        "available": True,
        "supported": supported,
        "config_digest": digest(text),
        "role": role,
        "security": security,
        "shares": {k: v for k, v in sections.items() if k.lower() != "global"},
    }
    if username is not None:
        if not supported:
            raise Refusal("Samba is not a supported standalone local-auth server")
        # pdbedit may initialize an absent database even for -L. Do not do that in discovery.
        users = run(["pdbedit", "-L"]) if os.path.exists(db_path) else ""
        result["user_exists"] = any(
            line.split(":", 1)[0] == username for line in users.splitlines()
        )
        result["disabled"] = False
        if result["user_exists"]:
            detail = run(["pdbedit", "-L", "-v", "-u", username])
            flags = next(
                (
                    line.split(":", 1)[1]
                    for line in detail.splitlines()
                    if line.lower().startswith("account flags:")
                ),
                "",
            )
            result["disabled"] = "D" in flags
    return result


def covering_shares(path: str, samba: dict[str, Any]) -> list[dict[str, Any]]:
    rows = []
    for name, values in samba.get("shares", {}).items():
        base = values.get("path", "")
        if not base or "%" in base:
            continue
        base = base.rstrip("/") or "/"
        if base == "/" or path == base or path.startswith(base + "/"):
            rows.append(
                {
                    "name": name,
                    "path": base,
                    "valid_users": values.get("valid users", ""),
                    "read_only": values.get("read only", "yes"),
                    "write_list": values.get("write list", ""),
                    "force_user": values.get("force user", ""),
                    "force_group": values.get("force group", ""),
                    "guest_ok": values.get("guest ok", "no"),
                }
            )
    return rows


def snapshot(op: dict[str, Any], roots: list[str]) -> dict[str, Any]:
    if sys.platform != "linux":
        raise Refusal("Linux is required")
    with open("/etc/nsswitch.conf", encoding="utf-8") as stream:
        for line in stream:
            if line.split(":", 1)[0].strip() in ("passwd", "group"):
                providers = re.sub(r"\[[^]]*\]", "", line.split(":", 1)[1].split("#", 1)[0]).split()
                if set(providers) - {"files", "systemd"}:
                    raise Refusal(
                        "centrally managed or unsupported identity providers require a separate adapter"
                    )
    state: dict[str, Any] = {
        "nsswitch": file_hash("/etc/nsswitch.conf"),
        "user": None,
        "groups": {},
    }
    username = op.get("username")
    if username:
        state["user"] = identity("passwd", username)
        if state["user"] is not None:
            state["password_status"] = run(["passwd", "-S", username]).split()[1]
    names = list(op.get("groups", []))
    if "group" in op:
        names.append(op["group"])
    if op["type"] == "user.create":
        names.append(username)
    for name in sorted(set(names)):
        state["groups"][name] = identity("group", name)
    path = op.get("path") or op.get("home")
    if path:
        state["storage"] = storage_state(path, roots, home=bool(op.get("home")))
    wants_samba = op["type"].startswith("samba.") or bool(
        op.get("samba") not in (None, False, "off")
    )
    if wants_samba or op.get("home"):
        state["samba"] = samba_state(
            username if wants_samba and op["type"] != "workspace.create" else None
        )
    return state


def observation_commands(op: dict[str, Any]) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []

    def add(argv: list[str], when: str = "always") -> None:
        result.append({"argv": argv, "when": when})

    username = op.get("username")
    if username:
        add(["getent", "passwd", username])
        add(["getent", "-s", "files", "passwd", username])
        add(["passwd", "-S", username], "account exists")
    names = list(op.get("groups", [])) + ([op["group"]] if "group" in op else [])
    if op["type"] == "user.create":
        names.append(username)
    for name in sorted(set(names)):
        add(["getent", "group", name])
        add(["getent", "-s", "files", "group", name])
    samba = op["type"].startswith("samba.") or op.get("samba") not in (None, False, "off")
    if samba or op.get("home"):
        add(["testparm", "-s", "/etc/samba/smb.conf"], "testparm is installed")
        if samba and username:
            add(["pdbedit", "-L"], "local passdb already exists")
            add(["pdbedit", "-L", "-v", "-u", username], "Samba account exists")
    return result


def compile_steps(op: dict[str, Any], state: dict[str, Any]) -> dict[str, Any]:
    """Pure deterministic compiler. Never accepts executable commands from plan data."""
    op = normalize(op)
    kind = op["type"]
    steps: list[dict[str, Any]] = []
    warnings: list[str] = []

    def command(argv: list[str], secret: str | None = None) -> None:
        steps.append({"kind": "command", "argv": argv, "secret": secret})

    user = state.get("user")
    username = op.get("username", "")
    exposed_path = op.get("home") or op.get("path")
    if exposed_path and any(
        s["force_user"] for s in covering_shares(exposed_path, state.get("samba", {}))
    ):
        raise Refusal(
            "existing Samba share forces a user; use a separately isolated layout before creating private or group-owned paths"
        )
    if kind == "group.create":
        if state["groups"][op["group"]] is None:
            command(["groupadd", "--", op["group"]])
    elif kind == "user.create":
        for group in op["groups"]:
            if state["groups"][group] is None:
                raise Refusal("supplementary group missing: " + group)
        if user is not None:
            if op["password"] and state.get("password_status") != "P":
                raise Refusal(
                    "existing account is locked or lacks a password; use user.password explicitly"
                )
            expected_home = op["home"] or "/home/" + username
            if user["home"] != expected_home or any(
                username not in state["groups"][g]["members"]
                and user["gid"] != state["groups"][g]["gid"]
                for g in op["groups"]
            ):
                raise Refusal("existing account conflicts with requested state")
            # Idempotent create never resets an existing user's password.
            if op["home"]:
                target = state["storage"]["target"]
                if not target or target["uid"] != user["uid"] or target["mode"] != 0o700:
                    raise Refusal("existing home conflicts with private-home policy")
            if op["samba"] and not state.get("samba", {}).get("user_exists"):
                raise Refusal(
                    "existing Linux user lacks Samba account; use samba user-add explicitly"
                )
        else:
            if state["groups"][username] is not None:
                raise Refusal("private group name already exists")
            if op["home"] and (
                PurePosixPath(op["home"]).name != username or state["storage"]["target"] is not None
            ):
                raise Refusal("home must be absent and end with the username")
            argv = [
                "useradd",
                "--no-create-home",
                "--user-group",
                "--password",
                "!",
                "--shell",
                "/bin/bash",
            ]
            if op["home"]:
                argv += ["--home-dir", op["home"]]
            if op["groups"]:
                argv += ["--groups", ",".join(op["groups"])]
            command(argv + ["--", username])
            if op["home"]:
                steps.append(
                    {"kind": "home", "path": op["home"], "username": username, "mode": "0700"}
                )
            if op["password"]:
                command(["chpasswd"], "linux")
            if op["samba"]:
                command(["smbpasswd", "-s", "-a", username], "samba")
    elif kind in ("workspace.create", "permissions.set"):
        group = state["groups"][op["group"]]
        if group is None:
            raise Refusal("workspace group must exist; create it in a separate approved plan")
        target = state["storage"]["target"]
        if kind == "permissions.set" and target is None:
            raise Refusal("permission target does not exist")
        if kind == "workspace.create" and target is not None:
            if target["gid"] != group["gid"] or target["mode"] != int(op["mode"], 8):
                raise Refusal("existing workspace conflicts; use permissions.set explicitly")
            usr = state["storage"].get("usr")
            if (
                usr is None
                or usr["uid"] != 0
                or usr["gid"] != group["gid"]
                or usr["mode"] != 0o2755
            ):
                raise Refusal("existing usr directory conflicts; no silent reconciliation")
        elif (
            target is None or target["gid"] != group["gid"] or target["mode"] != int(op["mode"], 8)
        ):
            steps.append(
                {
                    "kind": "workspace" if target is None else "permissions",
                    "path": op["path"],
                    "gid": group["gid"],
                    "mode": op["mode"],
                    "owner": "root",
                    "recursive": False,
                    "creates_usr_mode": "2755" if target is None else None,
                }
            )
        if op.get("samba") == "existing":
            samba = state.get("samba", {})
            shares = covering_shares(op["path"], samba)
            if not shares:
                warnings.append(
                    "No confirmed existing Samba share covers this workspace; no configuration will be changed."
                )
            for share in shares:
                if share["force_user"] or share["force_group"]:
                    warnings.append(
                        "Existing share forces a user/group; Unix isolation needs separate review."
                    )
                if share["read_only"].lower() not in ("no", "false", "0"):
                    warnings.append(
                        "Existing share is read-only unless its write list permits this user."
                    )
            warnings.append(
                "Existing Samba configuration is preserved. This plan does not prove SMB login/access."
            )
    else:
        if user is None:
            raise Refusal("local account does not exist")
        if kind == "user.password":
            command(["chpasswd"], "linux")
            if op["samba"]:
                command(["smbpasswd", "-s", "-a", username], "samba")
        elif kind == "user.membership":
            group = state["groups"][op["group"]]
            if group is None:
                raise Refusal("supplementary group does not exist")
            member = username in group["members"] or user["gid"] == group["gid"]
            if op["action"] == "add" and not member:
                command(["usermod", "--append", "--groups", op["group"], "--", username])
            if op["action"] == "remove" and member:
                if user["gid"] == group["gid"]:
                    raise Refusal("cannot remove primary group membership")
                command(["gpasswd", "--delete", username, op["group"]])
        elif kind in ("user.lock", "user.unlock"):
            locked = state.get("password_status") == "L"
            if kind == "user.lock" and not locked:
                command(["usermod", "--lock", "--", username])
            if kind == "user.unlock" and locked:
                command(["usermod", "--unlock", "--", username])
            warnings.append("Password locking does not disable SSH keys or existing sessions.")
        elif kind == "samba.user.ensure":
            if state["samba"].get("disabled"):
                raise Refusal(
                    "existing Samba account is disabled; enabling it requires separate administration"
                )
            if not state["samba"].get("user_exists"):
                command(["smbpasswd", "-s", "-a", username], "samba")
        elif kind == "samba.user.password":
            if not state["samba"].get("user_exists"):
                raise Refusal("Samba account missing; use samba.user.ensure")
            command(["smbpasswd", "-s", username], "samba")
        elif kind == "samba.user.disable":
            if not state["samba"].get("user_exists"):
                raise Refusal("Samba account missing")
            if not state["samba"].get("disabled"):
                command(["smbpasswd", "-d", username])
    if (kind.startswith("samba.") or op.get("samba") is True) and (
        not state.get("samba", {}).get("available") or not state["samba"].get("supported")
    ):
        raise Refusal(
            "standalone Samba tools/configuration are required; no packages or configuration will be changed"
        )
    return {
        "steps": steps,
        "warnings": warnings,
        "config_diffs": [],
        "observation_commands": observation_commands(op),
        "verification": "rediscover and compare account, membership, mode, owner and Samba status; no SMB login assertion",
    }


def _mkdir_at(parent: int, name: str, uid: int, gid: int, mode: int) -> None:
    os.mkdir(name, 0o700, dir_fd=parent)
    fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
    try:
        os.fchown(fd, uid, gid)
        os.fchmod(fd, mode)
        os.fsync(fd)
    finally:
        os.close(fd)


def filesystem_step(step: dict[str, Any], expected: dict[str, Any]) -> None:
    path = step["path"]
    if step["kind"] == "permissions":
        if mount_state(expected["root"]) != expected["mount"]:
            raise Refusal("mount changed before permission mutation")
        with directory(path) as fd:
            if meta(fd) != expected["target"]:
                raise Refusal("target inode or permissions changed")
            os.fchown(fd, 0, step["gid"])
            os.fchmod(fd, int(step["mode"], 8))
        return
    parent = str(PurePosixPath(path).parent)
    with directory(parent) as fd:
        expected_parent = (
            expected["root_stat"] if step["kind"] == "workspace" else expected["parent"]
        )
        if meta(fd) != expected_parent:
            raise Refusal("parent inode or permissions changed")
        if mount_state(expected["root"]) != expected["mount"]:
            raise Refusal("mount changed before filesystem mutation")
        if step["kind"] == "home":
            user = identity("passwd", step["username"])
            if user is None:
                raise Refusal("new account not found")
            _mkdir_at(fd, PurePosixPath(path).name, user["uid"], user["gid"], 0o700)
        else:
            _mkdir_at(fd, PurePosixPath(path).name, 0, step["gid"], int(step["mode"], 8))
            with directory(path) as workspace:
                _mkdir_at(workspace, "usr", 0, step["gid"], 0o2755)


def verification(op: dict[str, Any], state: dict[str, Any]) -> bool:
    kind = op["type"]
    if kind in ("user.password", "samba.user.password"):
        return (state.get("password_status") == "P" if kind == "user.password" else True) and (
            not op.get("samba")
            and not kind.startswith("samba.")
            or bool(state.get("samba", {}).get("user_exists"))
        )
    if kind == "user.create":
        if not state.get("user"):
            return False
        if op["password"] and state.get("password_status") != "P":
            return False
    try:
        return not compile_steps(op, state)["steps"]
    except Refusal:
        return False


def execute(request: dict[str, Any]) -> dict[str, Any]:
    if os.geteuid() != 0:
        raise Refusal("privileged execution requires root through configured sudo")
    op = normalize(request["operation"])
    if time.time() >= request["expires_at"]:
        raise Refusal("plan expired")
    roots = request["roots"]
    current = snapshot(op, roots)
    if digest(current) != request["snapshot_digest"]:
        raise Refusal("remote preconditions changed; generate a new plan")
    compiled = compile_steps(op, current)
    if digest(compiled) != request["compiled_digest"]:
        raise Refusal("compiled operations changed")
    secrets = request.get("secrets", {})
    for step in compiled["steps"]:
        key = step.get("secret")
        if key:
            value = secrets.get(key)
            if not isinstance(value, str) or not value or any(c in value for c in "\n\r\x00"):
                raise Refusal("missing or invalid secret input")
    results = []
    for step in compiled["steps"]:
        try:
            if time.time() >= request["expires_at"]:
                raise Refusal("plan expired during execution")
            if step["kind"] == "command":
                key = step.get("secret")
                payload = None
                if key == "linux":
                    payload = op["username"] + ":" + secrets[key] + "\n"
                elif key == "samba":
                    payload = secrets[key] + "\n" + secrets[key] + "\n"
                run(step["argv"], payload)
            else:
                filesystem_step(step, current["storage"])
            results.append({"step": step, "status": "succeeded"})
        except (Refusal, OSError):
            results.append({"step": step, "status": "failed_or_unknown"})
            results += [
                {"step": s, "status": "unattempted"} for s in compiled["steps"][len(results) :]
            ]
            return {
                "status": "partial_failure",
                "results": results,
                "recovery": "Rediscover before retrying. Created accounts/data are retained; no destructive rollback.",
            }
    after = snapshot(op, roots)
    ok = verification(op, after)
    return {
        "status": "verified" if ok else "verification_failed",
        "results": results,
        "observed": after,
    }


def inspect_workspaces(roots: list[str], path: str | None = None) -> dict[str, Any]:
    if path is not None:
        canonical(path)
        return {"path": path, "state": storage_state(path, roots)}
    rows = []
    errors = []
    complete = True
    for root in roots:
        try:
            canonical(root)
            mount_state(root)
            with directory(root) as fd, os.scandir(fd) as entries:
                for index, entry in enumerate(entries):
                    if index >= 1000:
                        complete = False
                        break
                    info = entry.stat(follow_symlinks=False)
                    if stat.S_ISDIR(info.st_mode) and info.st_mode & stat.S_ISGID:
                        rows.append(
                            {
                                "path": root + "/" + entry.name,
                                "uid": info.st_uid,
                                "gid": info.st_gid,
                                "mode": format(stat.S_IMODE(info.st_mode), "04o"),
                            }
                        )
        except (OSError, Refusal):
            errors.append(root)
            complete = False
    return {"workspace_candidates": rows, "complete": complete, "unreadable_roots": errors}


def samba_users() -> dict[str, Any]:
    state = samba_state()
    if not state.get("available") or not state.get("supported"):
        raise Refusal("supported standalone Samba is required")
    lines = run(["pdbedit", "-L"]).splitlines() if state["passdb_exists"] else []
    return {
        "users": [
            {"name": f[0], "uid": f[1]} for line in lines if len(f := line.split(":", 2)) >= 2
        ]
    }


def main() -> None:
    os.environ["PATH"] = "/usr/sbin:/usr/bin:/sbin:/bin"
    os.umask(0o077)
    print("CM_WORKER_READY_V2", flush=True)
    try:
        request = json.loads(sys.stdin.read(2_000_001))
        if request.get("protocol") != PROTOCOL:
            raise Refusal("unsupported worker protocol")
        phase = request.get("phase")
        if phase == "samba.inspect":
            result = samba_state()
        elif phase == "samba.users":
            result = samba_users()
        elif phase == "workspace.inspect":
            result = inspect_workspaces(request["roots"], request.get("path"))
        elif phase in ("discover", "verify", "execute"):
            op = normalize(request["operation"])
            if phase == "execute":
                # Serializes this tool's mutations. Other administrators remain independent.
                fd = os.open(
                    "/run/cluster-manager.lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600
                )
                try:
                    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    result = execute(request)
                finally:
                    os.close(fd)
            else:
                observed = snapshot(op, request["roots"])
                result = {"snapshot": observed, "compiled": compile_steps(op, observed)}
                if phase == "verify":
                    result["verified"] = verification(op, observed)
        else:
            raise Refusal("unsupported worker phase")
        print(json.dumps(result, sort_keys=True))
    except Exception as exc:  # noqa: BLE001 -- protocol boundary must redact all secret-bearing exceptions
        # Secrets and subprocess output are never included, including unexpected failures.
        print(json.dumps({"error": str(exc) if isinstance(exc, Refusal) else type(exc).__name__}))
        sys.exit(2)


if __name__ == "__main__":
    main()
