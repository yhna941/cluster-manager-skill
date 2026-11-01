"""Tests exercise the compiler/executor with a fake OS, never real SSH or root changes."""

import copy
import json
import os
import time
from pathlib import Path

import pytest

from cluster_manager.managed import engine, worker
from cluster_manager.models import Server, SSHConfig


class FakeHost:
    def __init__(self):
        self.users = {}
        self.groups = {
            "RA": {"name": "RA", "gid": 2000, "members": []},
            "smbuser": {"name": "smbuser", "gid": 2001, "members": []},
        }
        self.directories = {}
        self.smb_users = {}
        self.commands = []
        self.fail_on = None
        self.root = {"device": 20, "inode": 1, "uid": 0, "gid": 0, "mode": 0o755}
        self.mount = {"id": "3", "source": "/dev/test", "target": "/disk1"}

    def state(self, op, roots):
        user = copy.deepcopy(self.users.get(op.get("username")))
        names = set(op.get("groups", []))
        if "group" in op:
            names.add(op["group"])
        if op["type"] == "user.create":
            names.add(op["username"])
        result = {
            "user": user,
            "nsswitch": "files",
            "groups": {g: copy.deepcopy(self.groups.get(g)) for g in names},
        }
        if user:
            result["password_status"] = user.pop("status")
        path = op.get("path") or op.get("home")
        if path:
            result["storage"] = {
                "root": "/disk1",
                "root_stat": self.root.copy(),
                "mount": self.mount.copy(),
                "ancestors": [],
                "target": copy.deepcopy(self.directories.get(path)),
                "usr": copy.deepcopy(self.directories.get(path + "/usr")),
            }
            if op.get("home"):
                result["storage"]["parent"] = copy.deepcopy(
                    self.directories.get(str(Path(path).parent))
                )
        if op.get("samba") or op["type"].startswith("samba."):
            result["samba"] = {
                "available": True,
                "supported": True,
                "config_digest": "unchanged",
                "shares": {
                    "disk1": {"path": "/disk1", "read only": "no", "valid users": "@smbuser"}
                },
                "user_exists": op.get("username") in self.smb_users,
                "disabled": self.smb_users.get(op.get("username"), False),
            }
        return result

    def run(self, argv, payload=None):
        self.commands.append((argv, payload))
        if argv[0] == self.fail_on:
            raise worker.Refusal("injected failure")
        if argv[0] == "groupadd":
            name = argv[-1]
            self.groups[name] = {"name": name, "gid": 2002, "members": []}
        elif argv[0] == "useradd":
            name = argv[-1]
            self.groups[name] = {"name": name, "gid": 3000, "members": []}
            self.users[name] = {
                "name": name,
                "uid": 3000,
                "gid": 3000,
                "home": argv[argv.index("--home-dir") + 1]
                if "--home-dir" in argv
                else "/home/" + name,
                "shell": "/bin/bash",
                "status": "L",
            }
            if "--groups" in argv:
                for group in argv[argv.index("--groups") + 1].split(","):
                    self.groups[group]["members"].append(name)
        elif argv[0] == "chpasswd":
            self.users[payload.split(":")[0]]["status"] = "P"
        elif argv[0] == "smbpasswd":
            self.smb_users[argv[-1]] = "-d" in argv
        elif argv[0] == "usermod":
            if "--append" in argv:
                self.groups[argv[argv.index("--groups") + 1]]["members"].append(argv[-1])
            elif "--lock" in argv:
                self.users[argv[-1]]["status"] = "L"
            else:
                self.users[argv[-1]]["status"] = "P"
        elif argv[0] == "gpasswd":
            self.groups[argv[-1]]["members"].remove(argv[-2])
        else:
            pytest.fail("unexpected command " + argv[0])
        return ""

    def filesystem(self, step, expected):
        assert expected["mount"] == self.mount
        if step["kind"] == "home":
            user = self.users[step["username"]]
            self.directories[step["path"]] = {
                "uid": user["uid"],
                "gid": user["gid"],
                "mode": 0o700,
                "device": 20,
                "inode": 5,
            }
        else:
            self.directories[step["path"]] = {
                "uid": 0,
                "gid": step["gid"],
                "mode": int(step["mode"], 8),
                "device": 20,
                "inode": 4,
            }
            if step["kind"] == "workspace":
                self.directories[step["path"] + "/usr"] = {
                    "uid": 0,
                    "gid": step["gid"],
                    "mode": 0o2755,
                    "device": 20,
                    "inode": 6,
                }

    def apply(self, raw, secrets=None):
        op = worker.normalize(raw)
        state = self.state(op, ["/disk1"])
        preview = worker.compile_steps(op, state)
        return worker.execute(
            {
                "operation": op,
                "roots": ["/disk1"],
                "snapshot_digest": worker.digest(state),
                "compiled_digest": worker.digest(preview),
                "expires_at": time.time() + 30,
                "secrets": secrets or {},
            }
        )


@pytest.fixture
def host(monkeypatch):
    value = FakeHost()
    monkeypatch.setattr(worker, "snapshot", value.state)
    monkeypatch.setattr(worker, "run", value.run)
    monkeypatch.setattr(worker, "filesystem_step", value.filesystem)
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    return value


def test_full_workspace_identity_samba_lifecycle(host):
    workspace = {"type": "workspace.create", "path": "/disk1/RA", "group": "RA"}
    result = host.apply(workspace)
    assert result["status"] == "verified"
    assert host.directories["/disk1/RA"]["mode"] == 0o2775
    assert host.apply(workspace)["results"] == []
    # A second workspace belongs to the same group, not a duplicate Linux group.
    host.apply({**workspace, "path": "/disk1/RA-second"})
    create = {
        "type": "user.create",
        "username": "alice",
        "groups": ["RA", "smbuser"],
        "home": "/disk1/RA/usr/alice",
        "samba": True,
    }
    result = host.apply(create, {"linux": "redacted-test", "samba": "redacted-test"})
    assert result["status"] == "verified"
    assert host.directories["/disk1/RA/usr/alice"]["mode"] == 0o700
    assert "alice" in host.smb_users
    assert "redacted-test" not in json.dumps(result)
    assert host.apply(create)["results"] == []
    assert host.apply({"type": "samba.user.disable", "username": "alice"})["status"] == "verified"
    assert host.smb_users["alice"]


def test_memberships_are_additive_and_removal_preserves_others(host):
    host.apply({"type": "user.create", "username": "alice", "groups": ["RA"], "password": False})
    host.apply(
        {"type": "user.membership", "username": "alice", "group": "smbuser", "action": "add"}
    )
    assert host.groups["RA"]["members"] == ["alice"]
    assert host.groups["smbuser"]["members"] == ["alice"]
    host.apply(
        {"type": "user.membership", "username": "alice", "group": "smbuser", "action": "remove"}
    )
    assert host.groups["RA"]["members"] == ["alice"]
    assert host.groups["smbuser"]["members"] == []


def test_partial_failure_retains_created_account_and_reports(host):
    host.fail_on = "smbpasswd"
    result = host.apply(
        {"type": "user.create", "username": "alice", "samba": True},
        {"linux": "secret", "samba": "secret"},
    )
    assert result["status"] == "partial_failure"
    assert "alice" in host.users
    assert result["results"][-1]["status"] == "failed_or_unknown"
    assert "secret" not in json.dumps(result).replace('"secret":', '"stdin_kind":')  # no values


def test_permission_change_is_nonrecursive(host):
    host.apply({"type": "workspace.create", "path": "/disk1/RA", "group": "RA"})
    result = host.apply(
        {"type": "permissions.set", "path": "/disk1/RA", "group": "RA", "mode": "2770"}
    )
    assert result["status"] == "verified"
    assert host.directories["/disk1/RA"]["mode"] == 0o2770
    assert host.directories["/disk1/RA/usr"]["mode"] == 0o2755


@pytest.mark.parametrize(
    "raw",
    [
        {"type": "group.create", "group": "RA;id"},
        {"type": "workspace.create", "path": "/disk1/../etc", "group": "RA"},
        {"type": "workspace.create", "path": "/disk1/RA", "group": "RA", "mode": "2777"},
        {
            "type": "permissions.set",
            "path": "/disk1/RA",
            "group": "RA",
            "mode": "2775",
            "recursive": True,
        },
        {"type": "user.password", "username": "root"},
        {"type": "user.create", "username": "alice", "password": "plaintext"},
        {"type": "samba.share.create", "path": "/disk1"},
    ],
)
def test_unsafe_operation_rejected(raw):
    with pytest.raises(worker.Refusal):
        worker.normalize(raw)


def test_changed_mount_prevents_mutation(host):
    op = worker.normalize({"type": "workspace.create", "path": "/disk1/RA", "group": "RA"})
    before = host.state(op, ["/disk1"])
    preview = worker.compile_steps(op, before)
    host.mount["id"] = "4"
    with pytest.raises(worker.Refusal, match="preconditions changed"):
        worker.execute(
            {
                "operation": op,
                "roots": ["/disk1"],
                "snapshot_digest": worker.digest(before),
                "compiled_digest": worker.digest(preview),
                "expires_at": time.time() + 30,
            }
        )
    assert host.directories == {}


def test_missing_secret_fails_before_account_creation(host):
    with pytest.raises(worker.Refusal, match="secret"):
        host.apply({"type": "user.create", "username": "alice"})
    assert not host.commands


def test_existing_home_not_overwritten(host):
    host.directories["/disk1/RA/usr/alice"] = {"uid": 123, "mode": 0o777}
    with pytest.raises(worker.Refusal, match="home must be absent"):
        host.apply({"type": "user.create", "username": "alice", "home": "/disk1/RA/usr/alice"})
    assert not host.commands


def test_share_coverage_uses_path_boundary_and_flags_force_user():
    samba = {"shares": {"disk": {"path": "/disk1", "force user": "root", "read only": "no"}}}
    assert not worker.covering_shares("/disk11/RA", samba)
    assert worker.covering_shares("/disk1/RA", samba)[0]["force_user"] == "root"


def make_plan():
    host = FakeHost()
    op = worker.normalize({"type": "group.create", "group": "newgroup"})
    state = host.state(op, [])
    server = Server(host="example.invalid", ssh=SSHConfig(username="admin"))
    plan = engine.Plan(
        id="a" * 32,
        server_name="test",
        server=server.model_dump(),
        host_key="SHA256:test",
        operation=op,
        current_state=state,
        preview=worker.compile_steps(op, state),
        worker_digest=engine.source_digest(),
        remote_command=engine.remote_command(),
        created_at=int(time.time()),
        expires_at=int(time.time()) + 60,
        local_uid=os.getuid(),
    )
    plan.digest = plan.computed_digest()
    return plan, server


def test_plan_store_claim_and_history(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path))
    plan, server = make_plan()
    engine.save(plan)
    engine.load(plan.id).validate_for(server)
    engine.claim(plan)
    with pytest.raises(worker.Refusal, match="already attempted"):
        engine.claim(plan)
    engine.event(plan.id, engine.Stage.VERIFY, {"status": "verified"})
    assert engine.history(plan.id)[0]["data"]["status"] == "verified"


def test_rehashed_arbitrary_command_cannot_execute():
    plan, server = make_plan()
    plan.preview["steps"][0]["argv"] = ["sh", "-c", "id"]
    plan.digest = plan.computed_digest()
    with pytest.raises(worker.Refusal, match="compiled"):
        plan.validate_for(server)


def test_plan_expiry_identity_and_server_binding():
    plan, server = make_plan()
    plan.expires_at = plan.created_at - 1
    plan.digest = plan.computed_digest()
    with pytest.raises(worker.Refusal, match="expired"):
        plan.validate_for(server)
    plan, server = make_plan()
    server.port = 2222
    with pytest.raises(worker.Refusal, match="registered server"):
        plan.validate_for(server)


def test_path_walk_rejects_symlink(tmp_path):
    target = tmp_path / "actual"
    target.mkdir()
    link = tmp_path / "link"
    link.symlink_to(target, target_is_directory=True)
    # macOS /var is itself a symlink; resolve the test root to avoid testing that instead.
    with (
        pytest.raises((worker.Refusal, OSError)),
        worker.directory(str(tmp_path.resolve() / "link")),
    ):
        pytest.fail("followed a symlink")


def test_all_samba_operations_have_no_config_write_steps(host):
    host.apply({"type": "user.create", "username": "alice", "password": False})
    host.apply({"type": "samba.user.ensure", "username": "alice"}, {"samba": "test-value"})
    host.apply({"type": "samba.user.password", "username": "alice"}, {"samba": "new-value"})
    host.apply({"type": "samba.user.disable", "username": "alice"})
    assert all(argv[0] in ("useradd", "smbpasswd") for argv, _ in host.commands)
    assert all("/etc/samba/smb.conf" not in argv for argv, _ in host.commands)


def test_existing_locked_user_requires_explicit_password_plan(host):
    host.apply({"type": "user.create", "username": "alice", "password": False})
    with pytest.raises(worker.Refusal, match="user.password explicitly"):
        host.apply({"type": "user.create", "username": "alice"})


def test_forced_user_parent_share_refuses_private_workspace(host):
    op = worker.normalize({"type": "workspace.create", "path": "/disk1/RA", "group": "RA"})
    state = host.state(op, ["/disk1"])
    state["samba"]["shares"]["disk1"]["force user"] = "root"
    with pytest.raises(worker.Refusal, match="forces a user"):
        worker.compile_steps(op, state)


def test_readonly_samba_list_does_not_initialize_absent_passdb(monkeypatch):
    monkeypatch.setattr(
        worker,
        "samba_state",
        lambda: {"available": True, "supported": True, "passdb_exists": False},
    )
    monkeypatch.setattr(
        worker, "run", lambda *args: pytest.fail("pdbedit would initialize database")
    )
    assert worker.samba_users() == {"users": []}
