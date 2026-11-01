"""Static demonstration data; this backend never opens a network connection."""

from typing import Any

DATA: dict[str, Any] = {
    "gpu-01": {
        "host": "10.50.10.86",
        "mounts": ["/disk1", "/disk2"],
        "groups": ["RA"],
        "workspaces": [{"path": "/disk1/RA", "group": "RA", "mode": "2775"}],
    },
    "gpu-02": {
        "host": "10.50.10.144",
        "mounts": ["/data", "/disk3"],
        "groups": [],
        "workspaces": [],
    },
}
