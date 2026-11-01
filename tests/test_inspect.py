import pytest

from cluster_manager.inspect import command_for
from cluster_manager.managed.worker import digest


@pytest.mark.parametrize("name", ["x;id", "$(id)", "-x", "x\nwhoami"])
def test_reject_identity_injection(name):
    with pytest.raises(ValueError):
        command_for("user", name)


def test_digest_changes_with_scope():
    plan = {"server": "gpu-01", "group": "RA"}
    first = digest(plan)
    assert digest(plan) == first
    plan["group"] = "AI"
    assert digest(plan) != first
