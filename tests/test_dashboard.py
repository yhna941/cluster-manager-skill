from pathlib import Path

import pytest

pytest.importorskip("streamlit")
from streamlit.testing.v1 import AppTest

from cluster_manager import dashboard_app, dashboard_data
from cluster_manager.models import Server, SSHConfig


@pytest.fixture
def ui(monkeypatch, tmp_path):
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    return AppTest.from_file(str(Path(dashboard_app.__file__)), default_timeout=15)


def test_empty_inventory_and_empty_plans_do_not_connect(ui, monkeypatch):
    async def forbidden(*args):
        raise AssertionError("Unexpected network access")

    monkeypatch.setattr(dashboard_data, "discover", forbidden)
    ui.run()
    assert not ui.exception
    assert "Add your first server" in ui.info[0].value
    ui.sidebar.radio[0].set_value("Plans & audit").run()
    assert not ui.exception
    assert any("No saved plans" in item.value for item in ui.info)


def test_demo_navigation_is_english_and_has_no_remote_calls(ui, monkeypatch):
    async def forbidden(*args):
        raise AssertionError("Unexpected network access")

    monkeypatch.setattr(dashboard_data, "discover", forbidden)
    ui.run()
    ui.sidebar.toggle[0].set_value(True).run()
    assert not ui.exception
    assert len(ui.metric) == 4
    assert ui.metric[1].value == "3"
    for page in ["Storage", "Workspaces", "Accounts", "Samba"]:
        ui.sidebar.radio[0].set_value(page).run()
        assert not ui.exception
        assert ui.dataframe
    ui.sidebar.radio[0].set_value("Accounts").run()
    ui.text_input[0].set_value("alice").run()
    assert len(ui.dataframe[0].value) == 1


def test_dashboard_parsers_handle_invalid_rows_and_do_not_expose_password_field():
    assert dashboard_data.filesystems("header\nbad row\n/dev/a 10 invalid 5 50% /\n") == []
    rows = dashboard_data.identities("alice:secret:1001:1001::/home/alice:/bin/bash\n")
    assert len(rows) == 1
    assert "secret" not in str(rows)
    assert dashboard_data.identities("bad:x:invalid:4::/:/bin/sh\n") == []


def test_password_auth_is_rejected_before_network(monkeypatch):
    import asyncio

    server = Server(host="example.com", ssh=SSHConfig(username="user", auth="password"))
    with pytest.raises(ValueError, match="SSH keys only"):
        asyncio.run(dashboard_data.refresh("test", server))


def test_permission_rows_resolve_names_and_preserve_numeric_ids():
    rows = dashboard_data.permission_rows(
        [{"path": "/disk1/ra", "uid": 1001, "gid": 1005, "mode": "2770"}],
        [{"User": "alice", "UID": 1001}],
        [{"Group": "ra", "GID": 1005}],
    )
    assert rows[0]["Owner"] == "alice"
    assert rows[0]["Group"] == "ra"
    assert rows[0]["Permissions"] == "drwxrws---"
    assert rows[0]["UID"] == 1001


def test_refresh_failure_preserves_last_snapshot(ui, monkeypatch):
    from cluster_manager import inventory
    from cluster_manager.models import Inventory

    server = Server(host="example.invalid", ssh=SSHConfig(username="admin"))
    inventory.save(Inventory(servers={"lab": server}))
    calls = []

    async def fake_refresh(name, selected):
        calls.append(name)
        if len(calls) > 1:
            raise OSError("private diagnostic")
        return dict(dashboard_data.demo_snapshot(), server=selected.model_dump())

    monkeypatch.setattr(dashboard_data, "refresh", fake_refresh)
    ui.run()
    assert not calls
    ui.button[0].click().run()
    assert len(calls) == 1
    assert len(ui.metric) == 4
    ui.button[0].click().run()
    assert "Refresh failed" in ui.error[0].value
    assert "private diagnostic" not in ui.error[0].value
    assert len(ui.metric) == 4
    assert not ui.exception


def test_saved_plan_has_readable_steps_and_terminal_handoff(ui):
    import time

    from cluster_manager import inventory
    from cluster_manager.managed import engine, worker
    from cluster_manager.models import Inventory

    server = Server(host="example.invalid", ssh=SSHConfig(username="admin"))
    inventory.save(Inventory(servers={"lab": server}))
    operation = worker.normalize({"type": "group.create", "group": "research"})
    state = {"user": None, "groups": {"research": None}, "nsswitch": "files"}
    plan = engine.Plan(
        id="a" * 32,
        server_name="lab",
        server=server.model_dump(),
        host_key="SHA256:test",
        operation=operation,
        current_state=state,
        preview=worker.compile_steps(operation, state),
        worker_digest=engine.source_digest(),
        remote_command=engine.remote_command(),
        created_at=int(time.time()),
        expires_at=int(time.time()) + 900,
        local_uid=__import__("os").getuid(),
    )
    plan.digest = plan.computed_digest()
    engine.save(plan)
    ui.run()
    ui.sidebar.radio[0].set_value("Plans & audit").run()
    assert not ui.exception
    assert not ui.error
    assert any("Create group" in item.value for item in ui.text)
    assert any("cluster-manager apply " + plan.id in item.value for item in ui.code)
    assert ui.metric[1].value == "Awaiting approval"
