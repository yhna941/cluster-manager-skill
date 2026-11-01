import json

import pytest
from pydantic import ValidationError
from typer.testing import CliRunner

from cluster_manager.cli import app
from cluster_manager.inventory import load, save
from cluster_manager.models import Inventory, Server, SSHConfig


def server():
    return Server(host="10.50.10.86", ssh=SSHConfig(username="admin1"))


def test_inventory_roundtrip(tmp_path):
    path = tmp_path / "servers.yaml"
    save(Inventory(servers={"gpu-01": server()}), path)
    assert load(path).servers["gpu-01"] == server()
    assert path.stat().st_mode & 0o077 == 0


@pytest.mark.parametrize("host", ["host;id", "$(id)", "-oProxyCommand=x", "a..b"])
def test_reject_host_injection(host):
    with pytest.raises(ValidationError):
        Server(host=host, ssh=SSHConfig(username="admin1"))


@pytest.mark.parametrize("username", ["root;id", "-root", "a b"])
def test_reject_bad_user(username):
    with pytest.raises(ValidationError):
        SSHConfig(username=username)


def test_unknown_fields_reject_password():
    with pytest.raises(ValidationError):
        SSHConfig.model_validate({"username": "admin", "password": "secret"})


def test_simulation_never_uses_network(monkeypatch):
    import socket

    monkeypatch.setattr(socket.socket, "connect", lambda *args: pytest.fail("network access"))
    result = CliRunner().invoke(app, ["simulate"])
    assert result.exit_code == 0
    assert json.loads(result.stdout)["simulation"] is True


def test_registration_requires_terminal(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    result = CliRunner().invoke(
        app,
        ["server", "add", "gpu-01", "--host", "10.50.10.86", "--username", "admin1"],
        input="y\n",
    )
    assert result.exit_code != 0
    assert not (tmp_path / "cluster-manager" / "servers.yaml").exists()


def test_full_simulator_never_connects(monkeypatch):
    import socket
    from pathlib import Path

    monkeypatch.setattr(socket.socket, "connect", lambda *args: pytest.fail("network access"))
    result = CliRunner().invoke(
        app, ["simulate", "--scenario", str(Path(__file__).parents[1] / "examples/simulation.yaml")]
    )
    assert result.exit_code == 0, result.output
    data = json.loads(result.stdout)
    assert data["simulation"]
    assert all(r["simulated_verified"] for r in data["results"])
    assert data["state"]["directories"]["/disk1/RA/usr/alice"]["mode"] == 0o700


def test_human_output_keeps_json_available():
    readable = CliRunner().invoke(app, ["--human", "simulate"])
    assert readable.exit_code == 0, readable.output
    assert "Simulation" in readable.stdout
    machine = CliRunner().invoke(app, ["--json", "simulate"])
    assert machine.exit_code == 0
    assert json.loads(machine.stdout)["simulation"] is True
