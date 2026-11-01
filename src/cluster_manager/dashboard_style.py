"""Dashboard presentation: static CSS and escaped, non-interactive cards."""

from __future__ import annotations

from html import escape
from typing import Any

import streamlit as st

CSS = """<style>
:root {--blue:#3182f6; --ink:#191f28; --muted:#8b95a1;}
.stApp {background:#f2f4f6; color:var(--ink);}
.block-container {max-width:1260px; padding:2.5rem 3rem 4rem;}
[data-testid="stHeader"] {background:transparent;}
[data-testid="stAppDeployButton"] {display:none;}
h1 {font-size:32px !important; font-weight:750 !important; letter-spacing:-1.2px;
    padding-bottom:6px !important; color:#191f28;}
h2,h3 {font-size:21px !important; font-weight:700 !important; letter-spacing:-.5px;}
[data-testid="stSidebar"] {background:#fff; border:0;}
[data-testid="stSidebarUserContent"] {padding:30px 20px;}
[data-testid="stSidebar"] [role="radiogroup"] {gap:6px;}
[data-testid="stSidebar"] [role="radiogroup"] label {
 padding:12px 14px; border-radius:14px; margin:0; width:100%; transition:background .15s;}
[data-testid="stSidebar"] [role="radiogroup"] label:hover {background:#f2f4f6;}
[data-testid="stSidebar"] [role="radiogroup"] label:has(input:checked) {
 background:#e8f3ff; color:#1b64da; font-weight:650;}
[data-testid="stSidebar"] [role="radiogroup"] label>div:first-child {display:none;}
[data-testid="stSidebar"] [role="radiogroup"] label p {font-size:15px;}
[data-testid="stMetric"] {background:#fff; padding:24px; border:0; border-radius:22px;}
[data-testid="stMetricLabel"] {color:#6b7684; font-size:13px;}
[data-testid="stMetricValue"] {font-size:34px; font-weight:700; letter-spacing:-1px;}
[data-testid="stVerticalBlockBorderWrapper"] {border-radius:22px;}
[data-testid="stDataFrame"] {border-radius:16px; overflow:hidden;}
[data-testid="stExpander"] {background:#fff; border:0; border-radius:16px;}
[data-testid="stAlert"] {border-radius:14px;}
.stButton>button {border-radius:12px; min-height:43px; font-weight:600; border:0;}
.stButton>button[kind="primary"] {background:#3182f6;}
[data-testid="stSelectbox"] {max-width:360px;}
[data-testid="stSelectbox"] [role="combobox"] {border-radius:12px; background:#fff;}
[data-testid="stCaptionContainer"] {color:#8b95a1;}
.brand {display:flex;gap:10px;align-items:center;margin:8px 0 42px;}
.brand-icon {background:#3182f6;color:white;border-radius:13px;width:38px;height:38px;
 display:grid;place-items:center;font-size:25px;font-weight:700;}
.brand-name {font-size:18px;font-weight:750;letter-spacing:-.6px;line-height:1.2;}
.brand-sub {font-size:11px;color:#8b95a1;letter-spacing:.2px;margin-top:4px;}
.eyebrow {font-size:11px;letter-spacing:1.6px;font-weight:700;color:#8b95a1;margin-bottom:10px;}
.section-head {display:flex;align-items:center;justify-content:space-between;margin:24px 0 14px;}
.section-head h3 {margin:0;padding:0;}.section-head span {color:#8b95a1;font-size:13px;}
.tile {background:#fff;border-radius:22px;padding:25px 27px;margin-bottom:14px;}
.tile-head {display:flex;align-items:center;gap:14px;margin-bottom:22px;}
.tile-icon {width:44px;height:44px;border-radius:15px;background:#e8f3ff;color:#3182f6;
 display:grid;place-items:center;font-size:23px;font-weight:600;flex-shrink:0;}
.tile-name {font-size:17px;font-weight:700;letter-spacing:-.3px;overflow-wrap:anywhere;}
.tile-sub {color:#8b95a1;font-size:12px;margin-top:4px;overflow-wrap:anywhere;}
.pill {margin-left:auto;padding:6px 10px;border-radius:8px;font-size:11px;
 font-weight:600;background:#f2f4f6;color:#6b7684;white-space:nowrap;}
.capacity {font-size:28px;font-weight:750;letter-spacing:-1px;margin-bottom:12px;}
.capacity small {font-size:13px;color:#8b95a1;font-weight:500;letter-spacing:0;}
.bar {height:7px;background:#f2f4f6;border-radius:10px;overflow:hidden;margin:10px 0 13px;}
.bar-fill {height:100%;background:#3182f6;border-radius:10px;}
.tile-foot {display:flex;justify-content:space-between;color:#8b95a1;font-size:12px;gap:12px;}
.empty-card {background:#fff;border-radius:24px;padding:48px 32px;text-align:center;}
.empty-card h3 {margin:16px 0 10px;}.empty-card p {color:#8b95a1;font-size:14px;}
.empty-icon {width:64px;height:64px;margin:auto;border-radius:23px;background:#e8f3ff;
 color:#3182f6;font-size:32px;display:grid;place-items:center;}
.safety {background:#f9fafb;border-radius:16px;padding:16px;color:#6b7684;
 font-size:12px;line-height:1.7;margin-top:28px;}
@media(max-width:700px) {.block-container {padding:2rem 1rem;} .tile {padding:20px;}}
</style>"""


def section(title: str, subtitle: str = "") -> None:
    st.markdown(
        f'<div class="section-head"><h3>{escape(title)}</h3><span>{escape(subtitle)}</span></div>',
        unsafe_allow_html=True,
    )


def disk_card(disk: dict[str, Any]) -> None:
    percent = min(max(int(disk["Used (%)"]), 0), 100)
    color = "#f04452" if percent >= 90 else "#3182f6"
    st.markdown(
        f"""<div class="tile"><div class="tile-head">
<div class="tile-icon">▤</div><div><div class="tile-name">{escape(disk["Mount"])}</div>
<div class="tile-sub">{escape(disk["Device"])}</div></div>
<span class="pill">{percent}% used</span></div>
<div class="capacity">{disk["Available (GiB)"]:,.1f} <small>GiB available</small></div>
<div class="bar"><div class="bar-fill" style="width:{percent}%;background:{color}"></div></div>
<div class="tile-foot"><span>{disk["Used (GiB)"]:,.1f} GiB used</span>
<span>{disk["Size (GiB)"]:,.1f} GiB total</span></div></div>""",
        unsafe_allow_html=True,
    )


def server_card(name: str, host: str, roots: list[str]) -> None:
    st.markdown(
        f"""<div class="tile"><div class="tile-head">
<div class="tile-icon">▥</div><div><div class="tile-name">{escape(name)}</div>
<div class="tile-sub">{escape(host)}</div></div><span class="pill">Not checked</span></div>
<div class="tile-foot"><span>Storage roots</span>
<span>{escape(", ".join(roots) or "Not configured")}</span></div></div>""",
        unsafe_allow_html=True,
    )


def empty_card(title: str, description: str) -> None:
    st.markdown(
        f'<div class="empty-card"><div class="empty-icon">▤</div>'
        f"<h3>{escape(title)}</h3><p>{escape(description)}</p></div>",
        unsafe_allow_html=True,
    )
