import os

import pytest

from cluster_manager.managed import worker


def test_metadata_listing_does_not_follow_links_or_read_contents(tmp_path):
    root = tmp_path / "disk"
    root.mkdir()
    (root / "notes.txt").write_text("private contents must not be returned")
    (root / "link").symlink_to(tmp_path)
    result = worker.inspect_files([str(root)], str(root))
    assert result["complete"]
    assert "private contents" not in str(result)
    rows = {r["name"]: r for r in result["entries"]}
    assert rows["notes.txt"]["uid"] == os.getuid()
    assert rows["link"]["kind"] == "Symlink"
    assert rows["link"]["symbolic"].startswith("l")
    with pytest.raises((OSError, worker.Refusal)):
        worker.inspect_files([str(root)], str(root / "link"))
    with pytest.raises(worker.Refusal, match="outside"):
        worker.inspect_files([str(root)], str(tmp_path))


def test_listing_is_bounded(tmp_path):
    for i in range(501):
        (tmp_path / f"file-{i}").touch()
    result = worker.inspect_files([str(tmp_path)], str(tmp_path))
    assert not result["complete"]
    assert len(result["entries"]) == 500
