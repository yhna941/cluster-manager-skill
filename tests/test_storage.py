import json
import subprocess

import pytest

from cluster_manager.storage import SCANNER, scan_command


def test_scanner_limits_and_unusual_names(tmp_path):
    (tmp_path / "odd name\nfile").write_bytes(b"x" * 20)
    (tmp_path / "small").write_bytes(b"x")
    result = subprocess.run(
        ["python3", "-c", SCANNER, str(tmp_path), "10", "0", "20", "100", "5", "5"],
        capture_output=True,
        text=True,
        check=True,
    )
    data = json.loads(result.stdout)
    assert data["complete"]
    assert len(data["files"]) == 1
    assert data["files"][0]["path"].endswith("odd name\nfile")


def test_scan_marks_limit_partial(tmp_path):
    (tmp_path / "a").touch()
    (tmp_path / "b").touch()
    result = subprocess.run(
        ["python3", "-c", SCANNER, str(tmp_path), "0", "0", "20", "1", "5", "5"],
        capture_output=True,
        text=True,
        check=True,
    )
    assert json.loads(result.stdout)["complete"] is False


@pytest.mark.parametrize("path", ["/a/../b", "relative", "/a//b"])
def test_reject_noncanonical(path):
    with pytest.raises(ValueError):
        scan_command(path, 0, 0, 20, 100, 5, 5)
