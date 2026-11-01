"""Readable CLI output without interpreting remote strings as terminal markup."""

from __future__ import annotations

import json
import shlex
from typing import Any

from rich.console import Console
from rich.table import Table
from rich.text import Text


def step_label(step: dict[str, Any]) -> str:
    argv = step.get("argv", [])
    labels = {
        "groupadd": "Create group",
        "useradd": "Create user",
        "usermod": "Update user",
        "gpasswd": "Update group membership",
        "chpasswd": "Set Linux password",
        "smbpasswd": "Update Samba account",
    }
    if argv:
        return labels.get(argv[0], "Run approved command")
    return {
        "workspace": "Create workspace",
        "home": "Create private home",
        "permissions": "Update directory permissions",
    }.get(step.get("kind", ""), "Change")


def value_text(value: Any) -> str:
    if isinstance(value, (dict, list)):
        return json.dumps(value, ensure_ascii=False)
    return str(value)


def render(value: Any, title: str = "Cluster Manager", console: Console | None = None) -> None:
    console = console or Console(highlight=False)
    if isinstance(value, dict):
        summary = Table(title=Text(title), show_header=False, expand=True)
        summary.add_column("Property", style="cyan", no_wrap=True)
        summary.add_column("Value")
        nested = []
        for key, item in value.items():
            if key == "remote_command":
                continue
            if isinstance(item, (dict, list)):
                nested.append((key, item))
            else:
                summary.add_row(Text(key.replace("_", " ").title()), Text(value_text(item)))
        if summary.row_count:
            console.print(summary)
        for key, item in nested:
            render(item, key.replace("_", " ").title(), console)
    elif isinstance(value, list):
        table = Table(title=Text(title), expand=True)
        if value and all(isinstance(row, dict) for row in value):
            keys = list(dict.fromkeys(k for row in value for k in row if k != "remote_command"))
            for key in keys:
                table.add_column(Text(key.replace("_", " ").title()))
            for row in value:
                table.add_row(
                    *(
                        Text(shlex.join(row.get(k, [])) if k == "argv" else value_text(row.get(k, "—")))
                        for k in keys
                    )
                )
        else:
            table.add_column("Value")
            for item in value:
                table.add_row(Text(value_text(item)))
        if table.row_count:
            console.print(table)
    else:
        console.print(Text(f"{title}: {value_text(value)}"))
