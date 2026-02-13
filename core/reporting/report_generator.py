from __future__ import annotations
from pathlib import Path
from typing import List, Dict
from jinja2 import Environment, FileSystemLoader, select_autoescape
from reportlab.lib.pagesizes import LETTER
from reportlab.pdfgen import canvas as pdf_canvas
from jsonschema import validate

from utils.file_manager import write_text, write_json, ensure_dir
from utils.helpers import ScoredVulnerability, now_iso

def _env(templates_dir: str) -> Environment:
    return Environment(loader=FileSystemLoader(templates_dir), autoescape=select_autoescape(["html","xml"]))

def generate_html_report(items: List[ScoredVulnerability], out_path: str, templates_dir: str, meta: Dict) -> None:
    env = _env(templates_dir)
    tpl = env.get_template("contract_report.html")
    rendered = tpl.render(
        meta=meta,
        generated_at=now_iso(),
        findings=[{
            "vuln_id": it.vuln.vuln_id,
            "vtype": it.vuln.vtype,
            "function": it.vuln.function,
            "location": it.vuln.location,
            "description": it.vuln.description,
            "severity": it.severity,
            "label": it.label,
            "trace": it.vuln.trace,
            "features": it.vuln.features,
            "score_breakdown": it.score_breakdown,
            "remediation": it.remediation,
        } for it in items]
    )
    write_text(out_path, rendered)

def generate_pdf_report(items: List[ScoredVulnerability], out_path: str, meta: Dict) -> None:
    ensure_dir(Path(out_path).parent)
    c = pdf_canvas.Canvas(out_path, pagesize=LETTER)
    width, height = LETTER
    y = height - 50

    c.setFont("Helvetica-Bold", 14)
    c.drawString(50, y, f"{meta.get('project_name','AutoVeriAudit')} Security Report")
    y -= 18
    c.setFont("Helvetica", 10)
    c.drawString(50, y, f"Contract: {meta.get('contract_id')}    Generated: {now_iso()}")
    y -= 20

    for it in items:
        if y < 120:
            c.showPage()
            y = height - 50
        c.setFont("Helvetica-Bold", 11)
        c.drawString(50, y, f"{it.label} | {it.vuln.vtype} | score={it.severity:.2f}")
        y -= 14
        c.setFont("Helvetica", 10)
        c.drawString(50, y, f"Location: {it.vuln.location}")
        y -= 12
        c.drawString(50, y, f"Description: {it.vuln.description[:120]}")
        y -= 12
        if meta.get("include_score_breakdown", True):
            bd = it.score_breakdown
            c.drawString(50, y, f"Score breakdown: ex={bd.get('weighted_exploitability',0):.2f}, im={bd.get('weighted_impact',0):.2f}, cr={bd.get('weighted_exposure',0):.2f}")
            y -= 12
        if it.remediation:
            c.drawString(50, y, f"Fix: {it.remediation.get('title','')[:120]}")
            y -= 12
        if meta.get("include_execution_traces", True) and it.vuln.trace:
            c.drawString(50, y, "Trace:")
            y -= 12
            for step in it.vuln.trace[:6]:
                c.drawString(65, y, f"- {step[:120]}")
                y -= 12
        y -= 8

    c.save()

def export_json_contract(items: List[ScoredVulnerability], out_path: str, meta: Dict, schema: dict | None = None, strict: bool = False) -> dict:
    payload = {
        "meta": {**meta, "generated_at": now_iso()},
        "findings": [{
            "vuln_id": it.vuln.vuln_id,
            "contract_id": it.vuln.contract_id,
            "vtype": it.vuln.vtype,
            "function": it.vuln.function,
            "location": it.vuln.location,
            "description": it.vuln.description,
            "severity": it.severity,
            "label": it.label,
            "trace": it.vuln.trace,
            "features": it.vuln.features,
            "score_breakdown": it.score_breakdown,
            "remediation": it.remediation,
        } for it in items]
    }
    if schema is not None:
        try:
            validate(instance=payload, schema=schema)
        except Exception as e:
            if strict:
                raise
    write_json(out_path, payload)
    return payload
