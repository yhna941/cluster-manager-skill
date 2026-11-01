import asyncio
import copy
import json
import time
from contextlib import asynccontextmanager
from types import SimpleNamespace

import pytest
from typer.testing import CliRunner

from cluster_manager.cli import app
from cluster_manager.managed import engine, worker
from cluster_manager.models import Server, SSHConfig


@pytest.fixture
def rig(monkeypatch, tmp_path):
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path))
    server = Server(host="example.invalid", ssh=SSHConfig(username="admin"))
    state = {"user": None, "groups": {"RA": None}, "nsswitch": "files"}
    calls = []

    @asynccontextmanager
    async def connect(_server):
        yield object()

    async def invoke(_conn, request, privileged=True, authentication="interactive"):
        calls.append(copy.deepcopy(request))
        if request["phase"] == "execute":
            return {"status": "verified", "results": []}
        return {"snapshot": copy.deepcopy(state)}

    monkeypatch.setattr(engine, "registered", lambda name: server)
    monkeypatch.setattr(engine, "connect", connect)
    monkeypatch.setattr(engine, "host_key", lambda conn: "SHA256:fixture")
    monkeypatch.setattr(engine, "invoke", invoke)
    plan = asyncio.run(engine.make_plan("gpu", {"type": "group.create", "group": "RA"}))
    return SimpleNamespace(plan=plan, calls=calls, state=state, server=server)


def test_approval_denial_never_executes(rig, monkeypatch):
    def reject(_plan):
        raise worker.Refusal("declined")

    monkeypatch.setattr(engine, "terminal_approval", reject)
    with pytest.raises(worker.Refusal, match="declined"):
        asyncio.run(engine.apply(rig.plan.id))
    assert all(c["phase"] != "execute" for c in rig.calls)


def test_remote_state_drift_rejects_before_approval(rig, monkeypatch):
    rig.state["groups"]["RA"] = {"gid": 1001}
    monkeypatch.setattr(engine, "terminal_approval", lambda p: pytest.fail("approved stale state"))
    with pytest.raises(worker.Refusal, match="state changed"):
        asyncio.run(engine.apply(rig.plan.id))
    assert all(c["phase"] != "execute" for c in rig.calls)


def test_successful_apply_is_single_use_and_audited(rig, monkeypatch):
    monkeypatch.setattr(engine, "terminal_approval", lambda p: None)
    result = asyncio.run(engine.apply(rig.plan.id))
    assert result["status"] == "verified"
    with pytest.raises(worker.Refusal, match="already attempted"):
        asyncio.run(engine.apply(rig.plan.id))
    assert len([c for c in rig.calls if c["phase"] == "execute"]) == 1
    assert engine.history(rig.plan.id)[-1]["data"]["status"] == "verified"


def test_host_key_binding(rig, monkeypatch):
    monkeypatch.setattr(engine, "host_key", lambda conn: "SHA256:changed")
    with pytest.raises(worker.Refusal, match="host key"):
        asyncio.run(engine.apply(rig.plan.id))


def test_expiry_during_password_prompt(rig, monkeypatch):
    monkeypatch.setattr(engine, "terminal_approval", lambda p: None)

    def expire(*args):
        monkeypatch.setattr(time, "time", lambda: rig.plan.expires_at + 1)
        return {}

    monkeypatch.setattr(engine, "collect_secrets", expire)
    with pytest.raises(worker.Refusal, match="expired"):
        asyncio.run(engine.apply(rig.plan.id))
    assert all(c["phase"] != "execute" for c in rig.calls)


def test_cli_cannot_pipe_approval(rig):
    result = CliRunner().invoke(
        app, ["apply", rig.plan.id], input="approve " + rig.plan.digest[:12] + "\n"
    )
    assert result.exit_code == 2
    assert all(c["phase"] != "execute" for c in rig.calls)


def test_secrets_same_by_default_independent_optional(rig, monkeypatch):
    plan = rig.plan.model_copy(deep=True)
    plan.preview["steps"] = [{"secret": "linux"}, {"secret": "samba"}]
    values = iter(["local-test-value", "local-test-value"])
    monkeypatch.setattr(engine.getpass, "getpass", lambda prompt: next(values))
    assert engine.collect_secrets(plan) == {
        "linux": "local-test-value",
        "samba": "local-test-value",
    }
    values = iter(["linux-value", "linux-value", "samba-value", "samba-value"])
    assert engine.collect_secrets(plan, True) == {"linux": "linux-value", "samba": "samba-value"}
    assert "local-test-value" not in json.dumps(engine.history(plan.id))


def test_unknown_server_rejected_without_connect(monkeypatch):
    monkeypatch.setattr(engine, "load_inventory", lambda: SimpleNamespace(servers={}))
    with pytest.raises(worker.Refusal, match="unknown registered"):
        engine.registered("absent")


def test_password_request_cannot_be_yaml_secret(tmp_path):
    request = tmp_path / "secret.yaml"
    request.write_text(
        "server: unknown\noperation:\n  type: user.create\n  username: alice\n  password: do-not-print-this-secret\n"
    )
    result = CliRunner().invoke(app, ["plan", "--file", str(request)])
    assert result.exit_code != 0
    assert "do-not-print-this-secret" not in result.output
