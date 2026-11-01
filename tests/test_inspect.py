import pytest

from cluster_manager.inspect import command_for
from cluster_manager.provision import plan_digest


@pytest.mark.parametrize("name", ["x;id", "$(id)", "-x", "x\nwhoami"])
def test_reject_identity_injection(name):
    with pytest.raises(ValueError):
        command_for("user", name)


def test_digest_changes_with_scope():
    plan = {"server": "gpu-01", "group": "RA"}
    first = plan_digest(plan)
    plan["digest"] = first
    assert plan_digest(plan) == first
    plan["group"] = "AI"
    assert plan_digest(plan) != first
