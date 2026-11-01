"""Destructive only inside the explicitly selected disposable CI container.

Never enable CM_LINUX_INTEGRATION on a real managed machine.
"""

import hashlib
import json
import os
import subprocess
import time
from pathlib import Path

import pytest

from cluster_manager.managed import worker

pytestmark = pytest.mark.skipif(
    os.environ.get("CM_LINUX_INTEGRATION") != "1", reason="disposable Linux container only"
)


def apply(raw, secrets=None):
    op = worker.normalize(raw)
    state = worker.snapshot(op, ["/cm-disk", "/cm-disk2"])
    compiled = worker.compile_steps(op, state)
    return worker.execute(
        {
            "operation": op,
            "roots": ["/cm-disk", "/cm-disk2"],
            "expires_at": time.time() + 60,
            "snapshot_digest": worker.digest(state),
            "compiled_digest": worker.digest(compiled),
            "secrets": secrets or {},
        }
    )


def test_linux_full_lifecycle_preserves_existing_samba_config():
    assert Path("/.dockerenv").exists(), "integration suite must run in disposable Docker"
    assert os.geteuid() == 0
    config = Path("/etc/samba/smb.conf")
    # Test fixture setup, never part of the application implementation.
    config.write_text(
        "[global]\nserver role = standalone server\nsecurity = user\npassdb backend = tdbsam\n"
        "[disk]\npath = /cm-disk\nread only = no\nvalid users = @cmsmb\n"
    )
    before = hashlib.sha256(config.read_bytes()).hexdigest()
    assert apply({"type": "group.create", "group": "CMRA"})["status"] == "verified"
    assert apply({"type": "group.create", "group": "cmsmb"})["status"] == "verified"
    for disk in ("/cm-disk", "/cm-disk2"):
        raw = {"type": "workspace.create", "path": disk + "/CMRA", "group": "CMRA"}
        assert apply(raw)["status"] == "verified"
        assert apply(raw)["results"] == []
        assert Path(disk + "/CMRA").stat().st_mode & 0o7777 == 0o2775
        assert Path(disk + "/CMRA/usr").stat().st_mode & 0o7777 == 0o2755
    user = {
        "type": "user.create",
        "username": "cmalice",
        "groups": ["CMRA", "cmsmb"],
        "home": "/cm-disk/CMRA/usr/cmalice",
        "samba": True,
    }
    result = apply(user, {"linux": "Test-Only-Initial!42", "samba": "Test-Only-Initial!42"})
    assert result["status"] == "verified", result
    assert "Test-Only-Initial" not in json.dumps(result)
    assert Path(user["home"]).stat().st_mode & 0o7777 == 0o700
    assert not Path("/cm-disk2/CMRA/usr/cmalice").exists()
    assert apply(user)["results"] == []
    assert (
        apply(
            {"type": "permissions.set", "path": "/cm-disk/CMRA", "group": "CMRA", "mode": "2770"}
        )["status"]
        == "verified"
    )
    assert Path(user["home"]).stat().st_mode & 0o7777 == 0o700
    assert (
        apply(
            {"type": "user.membership", "username": "cmalice", "group": "cmsmb", "action": "remove"}
        )["status"]
        == "verified"
    )
    assert (
        apply(
            {"type": "user.membership", "username": "cmalice", "group": "cmsmb", "action": "add"}
        )["status"]
        == "verified"
    )
    assert apply({"type": "user.lock", "username": "cmalice"})["status"] == "verified"
    assert apply({"type": "user.unlock", "username": "cmalice"})["status"] == "verified"
    assert (
        apply(
            {"type": "samba.user.password", "username": "cmalice"}, {"samba": "Test-Only-New!42"}
        )["status"]
        == "verified"
    )
    assert apply({"type": "samba.user.disable", "username": "cmalice"})["status"] == "verified"
    assert hashlib.sha256(config.read_bytes()).hexdigest() == before


def test_linux_symlink_and_unmounted_root_rejected():
    assert Path("/.dockerenv").exists()
    Path("/cm-disk/symlink").symlink_to("/etc", target_is_directory=True)
    with pytest.raises(worker.Refusal):
        worker.storage_state("/cm-disk/symlink", ["/cm-disk"])
    Path("/not-a-mount").mkdir(exist_ok=True)
    with pytest.raises(worker.Refusal, match="not an actual mounted"):
        worker.storage_state("/not-a-mount/RA", ["/not-a-mount"])


def test_linux_worker_protocol_redacts_failures():
    assert Path("/.dockerenv").exists()
    request = {
        "protocol": worker.PROTOCOL,
        "phase": "unsupported",
        "secrets": {"linux": "must-not-leak"},
    }
    result = subprocess.run(
        ["python3", worker.__file__],
        input=json.dumps(request),
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode != 0
    assert "must-not-leak" not in result.stdout + result.stderr
