"""Streamlit entrypoint. Launch with cluster-manager-dashboard."""

from __future__ import annotations

import asyncio
import time
from typing import Any

import streamlit as st

from cluster_manager import inventory
from cluster_manager.dashboard_data import (
    demo_snapshot,
    filesystems,
    identities,
    permission_rows,
    refresh,
    saved_plans,
    timestamp,
)
from cluster_manager.dashboard_style import CSS, disk_card, empty_card, section, server_card
from cluster_manager.managed import engine, worker
from cluster_manager.presentation import step_label


def table(rows: list[dict[str, Any]]) -> None:
    if rows:
        st.dataframe(rows, hide_index=True, width="stretch")
    else:
        st.info("No records to display.")


def plans_view() -> None:
    st.subheader("Change plans")
    st.caption(
        "Review the target and intended changes. Approval and execution stay in your terminal."
    )
    plans, skipped = saved_plans()
    if skipped:
        st.warning(f"{skipped} unreadable or modified plan files were excluded.")
    if not plans:
        st.info("No saved plans yet. Create a plan with the CLI to review it here.")
        st.code("cluster-manager group create SERVER GROUP", language="bash")
        return
    selected = st.selectbox(
        "Saved plan",
        plans,
        format_func=lambda p: (
            f"{p.server_name} · {p.operation.get('kind', p.operation.get('type', 'change'))} · {p.id[:8]}"
        ),
    )
    if selected is None:
        return
    plan = selected
    history = engine.history(plan.id)
    attempted = any(e["stage"] == "execute" for e in history)
    expired = time.time() >= plan.expires_at
    invalid = None
    try:
        plan.validate_for(engine.registered(plan.server_name))
    except (worker.Refusal, ValueError) as exc:
        invalid = str(exc)
    status = (
        "Attempted — review audit"
        if attempted
        else "Expired"
        if expired
        else "Needs new plan"
        if invalid
        else "Awaiting approval"
    )
    if invalid and not expired:
        st.warning(invalid)
    a, b, c = st.columns(3)
    a.metric("Server", plan.server_name)
    b.metric("Status", status)
    c.metric("Steps", len(plan.preview.get("steps", [])))
    table(
        [
            {"Property": k.replace("_", " ").title(), "Value": str(v)}
            for k, v in plan.operation.items()
        ]
    )
    st.caption(f"Created {timestamp(plan.created_at)} · Expires {timestamp(plan.expires_at)}")
    for warning in plan.preview.get("warnings", []):
        st.warning(str(warning))
    st.markdown("#### Planned steps")
    for index, step in enumerate(plan.preview.get("steps", []), 1):
        with st.container(border=True):
            st.text(f"{index:02d}  {step_label(step)}")
            table(
                [
                    {"Property": k.replace("_", " ").title(), "Value": str(v)}
                    for k, v in step.items()
                ]
            )
    if not attempted and not expired and not invalid:
        st.code(f"cluster-manager apply {plan.id}", language="bash")
        st.caption("The CLI revalidates the plan and server state before asking for approval.")
    else:
        st.code(f"cluster-manager verify {plan.id}", language="bash")
    st.markdown("#### Audit trail")
    table(
        [
            {
                "Time": timestamp(e["at"]),
                "Stage": e["stage"],
                "Result": str(e["data"].get("status", "Recorded")),
            }
            for e in history
        ]
    )
    with st.expander("Technical details"):
        st.json(plan.model_dump(exclude={"remote_command"}))
        st.json(history)


def main() -> None:
    st.set_page_config(
        page_title="Cluster Manager", page_icon="◈", layout="wide", initial_sidebar_state="expanded"
    )
    st.markdown(CSS, unsafe_allow_html=True)
    with st.sidebar:
        st.markdown(
            '<div class="brand"><div class="brand-icon">c</div><div>'
            '<div class="brand-name">cluster</div>'
            '<div class="brand-sub">Infrastructure management</div></div></div>'
            '<div class="eyebrow">WORKSPACE</div>',
            unsafe_allow_html=True,
        )
        page = st.radio(
            "Navigation",
            ["Overview", "Storage", "Workspaces", "Accounts", "Samba", "Plans & audit"],
            label_visibility="collapsed",
        )
        st.divider()
        demo = st.toggle("Demo mode", value=False)
        st.markdown(
            '<div class="safety">Local interface<br>Read-only inspections.<br>'
            "Changes require terminal approval.</div>",
            unsafe_allow_html=True,
        )
    st.markdown('<div class="eyebrow">CLUSTER MANAGER</div>', unsafe_allow_html=True)
    st.title(page)
    st.caption(
        {
            "Overview": "Server status and resource usage.",
            "Storage": "Filesystem capacity and inode usage.",
            "Workspaces": "File and directory ownership, groups, and permissions.",
            "Accounts": "Unix users and group membership.",
            "Samba": "Existing Samba share configuration.",
            "Plans & audit": "Saved changes and execution history.",
        }[page]
    )
    if demo:
        st.info("Demo data — no servers are contacted and no changes are made.")
    if page == "Plans & audit":
        if demo:
            st.info("Switch off demo mode to review your saved plans.")
        else:
            plans_view()
        return
    servers = inventory.load().servers
    snapshot: dict[str, Any] | None
    if demo:
        st.selectbox("Server", ["research-01 · Demo"])
        snapshot = demo_snapshot()
        count = 1
    else:
        if not servers:
            st.info("No registered servers.")
            st.code(
                "cluster-manager server add research-01 --host HOST --username USER "
                "--storage-root /disk1",
                language="bash",
            )
            st.caption("Demo mode displays sample data.")
            return
        left, right = st.columns([5, 1], vertical_alignment="bottom")
        name = left.selectbox("Server", list(servers))
        server = servers[name]
        refresh_clicked = right.button("Refresh", type="primary", width="stretch")
        st.caption(f"{server.ssh.username}@{server.host}:{server.port} · SSH {server.ssh.auth}")
        key = "snapshot:" + name
        error_key = "error:" + name
        if refresh_clicked:
            with st.spinner("Inspecting server…"):
                try:
                    st.session_state[key] = asyncio.run(refresh(name, server))
                    st.session_state.pop(error_key, None)
                except Exception:  # noqa: BLE001 — redact remote/local diagnostics at the UI boundary
                    st.session_state[error_key] = (
                        "Refresh failed. Check SSH key access, the trusted host key, and CLI "
                        "diagnostics. Password-based SSH requires the CLI."
                    )
        if error_key in st.session_state:
            st.error(st.session_state[error_key])
        snapshot = st.session_state.get(key)
        if snapshot and snapshot.get("server") != server.model_dump():
            snapshot = None
        count = len(servers)
        if snapshot is None:
            section("Registered servers", f"{len(servers)} registered")
            columns = st.columns(2)
            for index, (server_name, registered_server) in enumerate(servers.items()):
                with columns[index % 2]:
                    server_card(
                        server_name, registered_server.host, registered_server.storage_roots
                    )
            empty_card(
                "No snapshot loaded",
                "Choose a server and refresh to see its storage, accounts, and shares.",
            )
            return
    assert snapshot is not None
    st.caption(f"Snapshot · {timestamp(snapshot['at'])} · Updates only when you refresh")
    probes = snapshot["probes"]
    for probe, result in probes.items():
        if result.get("error") or result.get("exit_status") != 0:
            st.warning(f"{probe.replace('_', ' ').title()} is unavailable in this snapshot.")
    disks = filesystems(probes.get("filesystems", {}).get("stdout", ""))
    users = identities(probes.get("users", {}).get("stdout", ""))
    groups = identities(probes.get("groups", {}).get("stdout", ""), groups=True)
    samba = snapshot["samba"]
    if page == "Overview":
        a, b, c, d = st.columns(4)
        a.metric("Registered servers", count)
        b.metric("Mounted filesystems", len(disks) if disks else "—")
        c.metric("Unix users", len(users) if users else "—")
        d.metric("Samba shares", len(samba.get("shares", {})) if samba.get("available") else "—")
        section("Storage usage", "Last observed capacity")
        if not disks:
            empty_card(
                "Storage data unavailable", "Refresh to inspect this server’s mounted filesystems."
            )
        columns = st.columns(2)
        for index, disk in enumerate(disks):
            with columns[index % 2]:
                disk_card(disk)
        with st.expander("System details"):
            st.text(probes.get("os", {}).get("stdout", "Unavailable"))
    elif page == "Storage":
        st.subheader("Mounted filesystems")
        st.caption("Capacity reported by df. Bind mounts may refer to the same underlying storage.")
        table(disks)
        with st.expander("Inodes and mount details"):
            st.text(probes.get("inodes", {}).get("stdout", "Unavailable"))
            st.text(probes.get("mounts", {}).get("stdout", "Unavailable"))
    elif page == "Workspaces":
        section("Group workspaces", "Owner · Group · Permissions")
        workspaces = snapshot.get("workspaces", {})
        candidates = workspaces.get("workspace_candidates", [])
        rows = permission_rows(candidates, users, groups)
        for row, candidate in zip(rows, candidates, strict=True):
            row["Samba shares"] = (
                ", ".join(
                    share["name"] for share in worker.covering_shares(candidate["path"], samba)
                )
                or "Not confirmed"
            )
        table(rows)
        st.caption(
            "Candidates are top-level directories with setgid enabled. Unix mode bits do not include ACL rules."
        )
        if not workspaces.get("complete", False):
            st.warning(
                "Workspace discovery is incomplete. Some roots are unreadable, unsupported, or exceed the scan limit."
            )
        section("Files & permissions", "Metadata only · No file contents")
        if demo:
            table(
                permission_rows(
                    [
                        {
                            "name": "analysis.csv",
                            "uid": 1001,
                            "gid": 1005,
                            "mode": "0660",
                            "symbolic": "-rw-rw----",
                            "kind": "File",
                            "bytes": 20480,
                            "modified": int(snapshot["at"]),
                        },
                        {
                            "name": "usr",
                            "uid": 0,
                            "gid": 1005,
                            "mode": "2755",
                            "symbolic": "drwxr-sr-x",
                            "kind": "Directory",
                            "bytes": 4096,
                            "modified": int(snapshot["at"]),
                        },
                    ],
                    users,
                    groups,
                )
            )
        else:
            with st.form("browse-files"):
                path = st.text_input(
                    "Directory path",
                    value=server.storage_roots[0] if server.storage_roots else "",
                    placeholder="/disk1/ra",
                )
                browse = st.form_submit_button("Inspect directory", type="primary")
            if browse:
                try:
                    if server.ssh.auth != "key":
                        raise ValueError("SSH key required")
                    listing = asyncio.run(engine.inspect_remote(name, "files.inspect", path))
                    st.session_state["files:" + name] = {
                        "listing": listing,
                        "server": server.model_dump(),
                        "at": time.time(),
                    }
                except Exception:  # noqa: BLE001 — no remote diagnostic text in UI
                    st.session_state.pop("files:" + name, None)
                    st.error(
                        "Cannot inspect this directory. Check the registered roots, path, and SSH user's permissions. Symlinks are not followed."
                    )
            stored = st.session_state.get("files:" + name)
            if stored and stored["server"] == server.model_dump():
                listing = stored["listing"]
                st.text(listing["path"])
                st.caption(f"Inspected {timestamp(stored['at'])}")
                current = dict(listing["directory"], path=listing["path"])
                current["mode"] = format(current["mode"], "04o")
                table(permission_rows([current], users, groups))
                table(permission_rows(listing["entries"], users, groups))
                if not listing["complete"]:
                    st.warning(
                        "Partial listing: at most 500 entries; some entries may be unreadable."
                    )
            st.caption(
                "Inspection uses your SSH account without sudo. No owners, groups, permissions, or Samba settings are changed."
            )
    elif page == "Accounts":
        query = st.text_input(
            "Filter users and groups", placeholder="Search by name, group, or home…"
        )
        show_system = st.checkbox("Include system users", value=False)
        st.subheader("Users")
        table(
            [
                r
                for r in users
                if (show_system or r["UID"] >= 1000) and query.casefold() in str(r).casefold()
            ]
        )
        st.subheader("Groups")
        table([r for r in groups if query.casefold() in str(r).casefold()])
    elif page == "Samba":
        st.subheader("Existing shares")
        st.caption("Parent shares can cover workspaces beneath them. No smb.conf edits are made.")
        if not samba.get("available"):
            st.warning(samba.get("reason", "Samba inspection is unavailable."))
        else:
            table(
                [
                    {
                        "Share": name,
                        "Path": values.get("path", "—"),
                        "Valid users": values.get("valid users", "Not restricted here"),
                        "Read only": values.get("read only", "Default"),
                        "Force user": values.get("force user", "—"),
                    }
                    for name, values in samba.get("shares", {}).items()
                ]
            )
            st.caption("Share visibility does not verify login or filesystem access permissions.")
            with st.expander("Effective configuration details"):
                st.json(samba)


if __name__ == "__main__":
    try:
        main()
    except Exception:  # noqa: BLE001 — redact remote/local diagnostics at the UI boundary
        st.error(
            "Unable to load local data. Check inventory and state-file permissions with the CLI."
        )
