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


def run_scenario(server: str, operations: list[dict[str, Any]]) -> dict[str, Any]:
    """Run deterministic typed operations against in-memory fixtures, without SSH or subprocesses."""
    import copy
    from pathlib import PurePosixPath

    from .managed import worker

    if server not in DATA:
        raise worker.Refusal("unknown simulated server")
    if len(operations) > 100:
        raise worker.Refusal("simulation is limited to 100 operations")
    fixture = DATA[server]
    groups: dict[str, Any] = {
        g: {"name": g, "gid": 2000 + i, "members": []} for i, g in enumerate(fixture["groups"])
    }
    users: dict[str, Any] = {}
    directories: dict[str, Any] = {}
    smb: dict[str, bool] = {}
    for workspace in fixture["workspaces"]:
        directories[workspace["path"]] = {
            "uid": 0,
            "gid": groups[workspace["group"]]["gid"],
            "mode": 0o2775,
        }
        directories[workspace["path"] + "/usr"] = {
            "uid": 0,
            "gid": groups[workspace["group"]]["gid"],
            "mode": 0o2755,
        }
    results = []

    def snapshot(op: dict[str, Any]) -> dict[str, Any]:
        names = list(op.get("groups", [])) + ([op["group"]] if "group" in op else [])
        if op["type"] == "user.create":
            names.append(op["username"])
        value: dict[str, Any] = {
            "user": copy.deepcopy(users.get(str(op.get("username", "")))),
            "groups": {g: copy.deepcopy(groups.get(g)) for g in names},
        }
        if value["user"]:
            value["password_status"] = value["user"].pop("status")
        path = op.get("path") or op.get("home")
        if path:
            roots = [r for r in fixture["mounts"] if path.startswith(r + "/")]
            if not roots:
                raise worker.Refusal("simulated path is outside fixture storage roots")
            relative = PurePosixPath(path).relative_to(max(roots, key=len)).parts
            if op.get("home"):
                if (
                    len(relative) != 3
                    or relative[1] != "usr"
                    or str(PurePosixPath(path).parent) not in directories
                ):
                    raise worker.Refusal("simulated home parent is missing or invalid")
            elif len(relative) != 1:
                raise worker.Refusal("workspace must be a direct child of a fixture mount")
            value["storage"] = {
                "target": copy.deepcopy(directories.get(path)),
                "usr": copy.deepcopy(directories.get(path + "/usr")),
            }
        if op.get("samba") or op["type"].startswith("samba."):
            value["samba"] = {
                "available": True,
                "supported": True,
                "user_exists": op.get("username") in smb,
                "disabled": smb.get(str(op.get("username", "")), False),
                "shares": {r.strip("/"): {"path": r, "read only": "no"} for r in fixture["mounts"]},
            }
        return value

    for raw in operations:
        op = worker.normalize(raw)
        before = snapshot(op)
        compiled = worker.compile_steps(op, before)
        for step in compiled["steps"]:
            if step["kind"] == "command":
                argv = step["argv"]
                name = op.get("username", "")
                if argv[0] == "groupadd":
                    groups[argv[-1]] = {"name": argv[-1], "gid": 2000 + len(groups), "members": []}
                elif argv[0] == "useradd":
                    uid = 3000 + len(users)
                    users[name] = {
                        "name": name,
                        "uid": uid,
                        "gid": uid,
                        "status": "L",
                        "home": op["home"] or "/home/" + name,
                        "shell": "/bin/bash",
                    }
                    groups[name] = {"name": name, "gid": uid, "members": []}
                    for group in op["groups"]:
                        groups[group]["members"].append(name)
                elif argv[0] == "chpasswd":
                    users[name]["status"] = "P"
                elif argv[0] == "smbpasswd":
                    smb[name] = "-d" in argv
                elif argv[0] == "gpasswd":
                    groups[op["group"]]["members"].remove(name)
                elif argv[0] == "usermod":
                    if "--append" in argv:
                        groups[op["group"]]["members"].append(name)
                    else:
                        users[name]["status"] = "L" if "--lock" in argv else "P"
            elif step["kind"] == "home":
                user = users[step["username"]]
                directories[step["path"]] = {"uid": user["uid"], "gid": user["gid"], "mode": 0o700}
            else:
                directories[step["path"]] = {
                    "uid": 0,
                    "gid": step["gid"],
                    "mode": int(step["mode"], 8),
                }
                if step["kind"] == "workspace":
                    directories[step["path"] + "/usr"] = {
                        "uid": 0,
                        "gid": step["gid"],
                        "mode": 0o2755,
                    }
        results.append(
            {
                "operation": op,
                "preview": compiled,
                "simulated_verified": worker.verification(op, snapshot(op)),
            }
        )
    return {
        "simulation": True,
        "server": server,
        "results": results,
        "state": {"users": users, "groups": groups, "directories": directories, "samba_users": smb},
    }
