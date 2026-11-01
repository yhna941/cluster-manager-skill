import pytest

from cluster_manager.provision import group_commands


@pytest.mark.parametrize("name", ["RA;id", "$(id)", "-root", "a b", "a\nfoo"])
def test_group_injection_rejected(name):
    with pytest.raises(ValueError):
        group_commands(name)


def test_command_is_narrow():
    assert group_commands("research")[1] == "sudo -n -- groupadd -- research"
