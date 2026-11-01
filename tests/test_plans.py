import os
import time

import pytest

from cluster_manager.models import Server, SSHConfig
from cluster_manager.plans import load, save, validate
from cluster_manager.provision import plan_digest


def make_plan():
    plan = {
        "operation": "group.create",
        "server": "gpu",
        "host": "example.invalid",
        "port": 22,
        "ssh_username": "admin",
        "group": "RA",
        "command": "sudo -n -- groupadd -- RA",
        "verification": "getent group RA",
        "expires_at": int(time.time()) + 60,
        "local_uid": os.getuid(),
    }
    plan["digest"] = plan_digest(plan)
    return plan


def test_plan_roundtrip_and_tampering(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path))
    plan = make_plan()
    ident = save(plan)
    loaded = load(ident)
    server = Server(host="example.invalid", ssh=SSHConfig(username="admin"))
    validate(loaded, server, "gpu")
    loaded["command"] = "sudo -n -- id"
    loaded["digest"] = plan_digest(loaded)
    with pytest.raises(ValueError):
        validate(loaded, server, "gpu")


def test_reject_path_traversal():
    with pytest.raises(ValueError):
        load("../../etc/passwd")


def test_expired_plan_rejected():
    plan = make_plan()
    plan["expires_at"] = 1
    plan["digest"] = plan_digest(plan)
    with pytest.raises(ValueError, match="expired"):
        validate(plan, Server(host="example.invalid", ssh=SSHConfig(username="admin")), "gpu")
