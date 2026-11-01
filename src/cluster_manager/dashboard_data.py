"""Read-only dashboard adapters; no cached credentials or implicit SSH requests."""

from __future__ import annotations

import asyncio
import stat
from datetime import UTC, datetime
from typing import Any

from cluster_manager.discovery import discover
from cluster_manager.managed import engine
from cluster_manager.models import Server


def timestamp(value: float) -> str:
    return datetime.fromtimestamp(value, UTC).strftime("%Y-%m-%d %H:%M UTC")


def filesystems(text: str) -> list[dict[str, Any]]:
    rows = []
    for line in text.splitlines()[1:]:
        parts = line.split(maxsplit=5)
        if len(parts) != 6:
            continue
        device, total, used, available, percent, mount = parts
        try:
            rows.append(
                {
                    "Mount": mount,
                    "Device": device,
                    "Size (GiB)": round(int(total) / 1024**2, 1),
                    "Used (GiB)": round(int(used) / 1024**2, 1),
                    "Available (GiB)": round(int(available) / 1024**2, 1),
                    "Used (%)": int(percent.rstrip("%")),
                }
            )
        except ValueError:
            continue
    return rows


def identities(text: str, groups: bool = False) -> list[dict[str, Any]]:
    rows = []
    for line in text.splitlines():
        p = line.split(":")
        try:
            if groups and len(p) == 4:
                rows.append({"Group": p[0], "GID": int(p[2]), "Members": p[3]})
            elif not groups and len(p) == 7:
                rows.append(
                    {"User": p[0], "UID": int(p[2]), "GID": int(p[3]), "Home": p[5], "Shell": p[6]}
                )
        except ValueError:
            continue
    return rows


async def refresh(name: str, server: Server) -> dict[str, Any]:
    if server.ssh.auth != "key":
        raise ValueError("Use the CLI for password-based SSH. The dashboard uses SSH keys only.")
    # All probes are unprivileged. A Samba failure does not discard other observations.
    probes = await asyncio.wait_for(discover(server), timeout=150)
    try:
        samba = await asyncio.wait_for(engine.samba_inspect(name), timeout=30)
    except Exception:  # noqa: BLE001 — isolate failed/untrusted data from the UI
        samba = {"available": False, "reason": "Samba inspection failed; check CLI diagnostics."}
    try:
        workspaces = await asyncio.wait_for(engine.inspect_remote(name, "workspace.inspect"), 30)
    except Exception:  # noqa: BLE001 — isolate remote inspection errors
        workspaces = {
            "workspace_candidates": [],
            "complete": False,
            "unreadable_roots": server.storage_roots,
        }
    return {
        "workspaces": workspaces,
        "probes": probes,
        "samba": samba,
        "at": datetime.now(UTC).timestamp(),
        "server": server.model_dump(),
    }


def saved_plans() -> tuple[list[engine.Plan], int]:
    plans = []
    skipped = 0
    for path in sorted(engine.state_dir().glob("*.plan.json")):
        try:
            plan = engine.load(path.name.removesuffix(".plan.json"))
            if plan.digest != plan.computed_digest():
                raise ValueError("modified plan")
            plans.append(plan)
        except Exception:  # noqa: BLE001 — isolate failed/untrusted data from the UI
            skipped += 1
    return sorted(plans, key=lambda p: p.created_at, reverse=True), skipped


def demo_snapshot() -> dict[str, Any]:
    def probe(text: str) -> dict[str, Any]:
        return {"stdout": text, "exit_status": 0, "stderr": ""}

    return {
        "at": datetime.now(UTC).timestamp(),
        "probes": {
            "filesystems": probe(
                "Filesystem 1024-blocks Used Available Capacity Mounted on\n"
                "/dev/sda1 104857600 27262976 77594624 26% /\n"
                "/dev/sdb1 2147483648 1245540515 901943133 58% /disk1\n"
                "/dev/sdc1 2147483648 429496730 1717986918 20% /disk2\n"
            ),
            "users": probe(
                "alice:x:1001:1001::/disk1/ra/usr/alice:/bin/bash\n"
                "ben:x:1002:1002::/disk1/ra/usr/ben:/bin/bash\n"
            ),
            "groups": probe("ra:x:1005:alice,ben\nsmbuser:x:1006:alice,ben\n"),
            "os": probe('PRETTY_NAME="Ubuntu 24.04 LTS"\n'),
        },
        "workspaces": {
            "workspace_candidates": [
                {"path": "/disk1/ra", "uid": 0, "gid": 1005, "mode": "2770"},
                {"path": "/disk2/ra", "uid": 0, "gid": 1005, "mode": "2775"},
            ],
            "complete": True,
            "unreadable_roots": [],
        },
        "samba": {
            "available": True,
            "supported": True,
            "shares": {
                "disk1": {"path": "/disk1", "valid users": "@smbuser", "read only": "no"},
                "disk2": {"path": "/disk2", "valid users": "@smbuser", "read only": "no"},
            },
        },
    }


def permission_rows(
    rows: list[dict[str, Any]], users: list[dict[str, Any]], groups: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    user_names = {u["UID"]: u["User"] for u in users}
    group_names = {g["GID"]: g["Group"] for g in groups}
    return [
        {
            "Path": r.get("path", r.get("name", "")),
            "Owner": user_names.get(r["uid"], str(r["uid"])),
            "UID": r["uid"],
            "Group": group_names.get(r["gid"], str(r["gid"])),
            "GID": r["gid"],
            "Mode": r["mode"],
            "Permissions": r.get("symbolic", stat.filemode(stat.S_IFDIR | int(r["mode"], 8))),
            **(
                {"Type": r["kind"], "Bytes": r["bytes"], "Modified": timestamp(r["modified"])}
                if "kind" in r
                else {}
            ),
        }
        for r in rows
    ]
