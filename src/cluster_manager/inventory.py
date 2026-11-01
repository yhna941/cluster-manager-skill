from __future__ import annotations

import os
import tempfile
from pathlib import Path

import yaml

from .models import Inventory


def config_path() -> Path:
    return (
        Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config"))
        / "cluster-manager"
        / "servers.yaml"
    )


def load(path: Path | None = None) -> Inventory:
    path = path or config_path()
    if not path.exists():
        return Inventory()
    with path.open(encoding="utf-8") as stream:
        return Inventory.model_validate(yaml.safe_load(stream))


def save(inventory: Inventory, path: Path | None = None) -> None:
    path = path or config_path()
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(dir=path.parent, prefix=".servers-")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            yaml.safe_dump(inventory.model_dump(exclude_none=True), stream, sort_keys=True)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)
