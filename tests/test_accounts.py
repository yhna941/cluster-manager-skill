import asyncio
from types import SimpleNamespace

import pytest

from cluster_manager.accounts import account_operation, commands
from cluster_manager.models import Server, SSHConfig


@pytest.mark.parametrize("name", ["root;id", "-a", "$(id)", "a b"])
def test_reject_injection(name):
    with pytest.raises(ValueError):
        commands(name, "user.create")


def test_password_not_sent_without_approval(monkeypatch):
    calls = []
    line = "alice:x:1001:1001::/home/alice:/bin/bash\n"

    class Connection:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            pass

        async def run(self, command, **kwargs):
            calls.append(command)
            return SimpleNamespace(
                exit_status=0, stdout="Linux\n" if command == "uname -s" else line
            )

    monkeypatch.setattr("cluster_manager.accounts.asyncssh.connect", lambda *a, **k: Connection())
    target = Server(host="example.invalid", ssh=SSHConfig(username="admin"))

    def secret():
        pytest.fail("password requested before approval")

    result = asyncio.run(
        account_operation("demo", target, "alice", "user.password", None, lambda p: False, secret)
    )
    assert result["status"] == "cancelled"
    assert not any("chpasswd" in command for command in calls)


def test_non_linux_rejected(monkeypatch):
    class Connection:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            pass

        async def run(self, command, **kwargs):
            assert command == "uname -s"
            return SimpleNamespace(exit_status=0, stdout="Darwin\n")

    monkeypatch.setattr("cluster_manager.accounts.asyncssh.connect", lambda *a, **k: Connection())
    target = Server(host="example.invalid", ssh=SSHConfig(username="admin"))
    with pytest.raises(RuntimeError, match="Linux"):
        asyncio.run(
            account_operation(
                "demo", target, "alice", "user.create", None, lambda p: True, lambda: ""
            )
        )
