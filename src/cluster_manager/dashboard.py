"""Local dashboard launcher. No approval or password handling in the web process."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path


def launch() -> None:
    try:
        import streamlit  # noqa: F401
    except ImportError:
        raise SystemExit("Install the dashboard extra: uv tool install --force '.[dashboard]'")
    raise SystemExit(
        subprocess.call(
            [
                sys.executable,
                "-m",
                "streamlit",
                "run",
                str(Path(__file__).with_name("dashboard_app.py")),
                "--server.address=127.0.0.1",
                "--server.headless=true",
                "--server.enableXsrfProtection=true",
                "--server.enableCORS=true",
                "--browser.gatherUsageStats=false",
                "--theme.base=light",
                "--theme.primaryColor=#2563eb",
                "--theme.backgroundColor=#ffffff",
                "--theme.secondaryBackgroundColor=#f5f7fb",
                "--theme.textColor=#172033",
            ]
        )
    )
