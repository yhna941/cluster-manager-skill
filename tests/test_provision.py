import pytest

from cluster_manager.provision import group_commands


@pytest.mark.parametrize("name", ["RA;id", "$(id)", "-root", "a b", "a\nfoo"])
def test_group_injection_rejected(name):
    with pytest.raises(ValueError):
        group_commands(name)


def test_command_is_narrow():
    assert group_commands("research")[1] == "sudo -n -- groupadd -- research"


def test_approval_and_verification_without_network(monkeypatch, tmp_path):
    import asyncio
    from types import SimpleNamespace

    from cluster_manager.models import Server, SSHConfig
    from cluster_manager.provision import create_group

    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path))
    commands = []

    class Connection:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            return None

        async def run(self, command, check):
            commands.append(command)
            return SimpleNamespace(exit_status=0 if len(commands) >= 3 else 2)

    monkeypatch.setattr("cluster_manager.provision.asyncssh.connect", lambda *a, **k: Connection())
    target = Server(host="example.invalid", ssh=SSHConfig(username="admin"))
    outcome = asyncio.run(create_group("demo", target, "RA", None, lambda plan: True))
    assert outcome["status"] == "verified"
    assert commands == [
        "getent group RA",
        "getent group RA",
        "sudo -n -- groupadd -- RA",
        "getent group RA",
    ]
    assert "attempt" in (tmp_path / "cluster-manager" / "audit.jsonl").read_text()


def test_denial_does_not_mutate(monkeypatch):
    import asyncio
    from types import SimpleNamespace

    from cluster_manager.models import Server, SSHConfig
    from cluster_manager.provision import create_group

    commands = []

    class Connection:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            return None

        async def run(self, command, check):
            commands.append(command)
            return SimpleNamespace(exit_status=2)

    monkeypatch.setattr("cluster_manager.provision.asyncssh.connect", lambda *a, **k: Connection())
    target = Server(host="example.invalid", ssh=SSHConfig(username="admin"))
    outcome = asyncio.run(create_group("demo", target, "RA", None, lambda plan: False))
    assert outcome["status"] == "cancelled"
    assert commands == ["getent group RA"]
