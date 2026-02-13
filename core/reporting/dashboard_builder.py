from __future__ import annotations
from typing import Dict
from jinja2 import Environment, FileSystemLoader, select_autoescape
from utils.file_manager import write_text, write_json
from utils.helpers import now_iso

def _env(templates_dir: str) -> Environment:
    return Environment(loader=FileSystemLoader(templates_dir), autoescape=select_autoescape(["html","xml"]))

def _bar_svg(label: str, value: float, maxv: float) -> str:
    w = 320
    h = 14
    fill_w = 0 if maxv == 0 else int((value / maxv) * w)
    return f"""<div style='margin:6px 0;'><div style='font-size:12px'>{label}: {value}</div>
    <svg width='{w}' height='{h}'><rect x='0' y='0' width='{w}' height='{h}' rx='6' ry='6' fill='#eee'/>
    <rect x='0' y='0' width='{fill_w}' height='{h}' rx='6' ry='6' fill='#666'/></svg></div>"""

def build_dashboard(summary: Dict, out_html: str, out_json: str, templates_dir: str, meta: Dict) -> None:
    env = _env(templates_dir)
    tpl = env.get_template("dashboard.html")

    # Build simple bar charts
    by_label = summary.get("by_label", {})
    by_type = summary.get("by_type", {})
    max_label = max(by_label.values()) if by_label else 0
    max_type = max(by_type.values()) if by_type else 0
    bars_label = [_bar_svg(k, v, max_label) for k, v in by_label.items()]
    bars_type = [_bar_svg(k, v, max_type) for k, v in by_type.items()]

    rendered = tpl.render(
        meta=meta,
        summary=summary,
        generated_at=now_iso(),
        bars_label=bars_label,
        bars_type=bars_type
    )
    write_text(out_html, rendered)
    write_json(out_json, {"meta": {**meta, "generated_at": now_iso()}, "summary": summary})
