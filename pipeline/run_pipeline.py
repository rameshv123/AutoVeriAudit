from __future__ import annotations
import argparse
from pathlib import Path
import yaml
from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor, as_completed
from rich.console import Console
from rich.table import Table

from utils.logger import get_logger
from utils.file_manager import ensure_dir, write_json
from utils.helpers import ScoredVulnerability
from core.benchmarking.timer import BenchTimer
from core.ingestion.batch_loader import load_contracts
from core.ingestion.scheduler import schedule_batch
from core.verification.verichain_interface import run_verification
from core.analysis.feature_extractor import extract_features
from core.analysis.aggregator import build_portfolio_metrics
from core.analysis.dependency_graph import build_dependency_graph, dependency_edges, propagate_severity
from core.scoring.severity_model import SeverityWeights, compute_severity
from core.scoring.classifier import Thresholds, classify_severity
from core.scoring.ranking import rank_vulnerabilities
from core.remediation.remediation_engine import RemediationEngine
from core.reporting.report_generator import generate_html_report, generate_pdf_report, export_json_contract
from core.reporting.dashboard_builder import build_dashboard

def load_yaml(path: str) -> dict:
    return yaml.safe_load(Path(path).read_text(encoding="utf-8"))

def load_json(path: str) -> dict:
    import json
    return json.loads(Path(path).read_text(encoding="utf-8"))

def main():
    console = Console()
    ap = argparse.ArgumentParser(description="AutoVeriAudit full SCI implementation runner.")
    ap.add_argument("--contracts_dir", default=str(Path(__file__).resolve().parents[1] / "data" / "contracts"))
    ap.add_argument("--out_dir", default=str(Path(__file__).resolve().parents[1] / "data" / "outputs"))
    ap.add_argument("--config_dir", default=str(Path(__file__).resolve().parents[1] / "config"))
    ap.add_argument("--templates_dir", default=str(Path(__file__).resolve().parents[1] / "templates"))
    ap.add_argument("--kb_path", default=str(Path(__file__).resolve().parents[1] / "core" / "remediation" / "knowledge_base.json"))
    args = ap.parse_args()

    cfg_dir = Path(args.config_dir)
    pipeline_cfg = load_yaml(str(cfg_dir / "pipeline_config.yaml"))
    weights_cfg = load_yaml(str(cfg_dir / "weights.yaml"))
    th_cfg = load_yaml(str(cfg_dir / "thresholds.yaml"))
    schema = load_json(str(cfg_dir / "report_schema.json"))

    timer = BenchTimer()
    timer.start("total")

    out_dir = Path(args.out_dir)
    reports_dir = ensure_dir(out_dir / "reports")
    dashboards_dir = ensure_dir(out_dir / "dashboards")
    json_dir = ensure_dir(out_dir / "json")
    bench_dir = ensure_dir(out_dir / "benchmarks")
    logs_dir = ensure_dir(Path(__file__).resolve().parents[1] / "data" / "logs")

    logger = get_logger("AutoVeriAudit", str(logs_dir / "pipeline.log"))
    max_workers = int(pipeline_cfg["pipeline"]["max_workers"])
    exts = pipeline_cfg["pipeline"]["input_extensions"]
    formats = pipeline_cfg["pipeline"]["output_formats"]
    executor_kind = pipeline_cfg["pipeline"].get("executor", "thread")
    strict_schema = bool(pipeline_cfg["pipeline"].get("strict_schema", False))

    meta_global = {
        "project_name": pipeline_cfg["reporting"]["project_name"],
        "include_execution_traces": bool(pipeline_cfg["reporting"]["include_execution_traces"]),
        "include_score_breakdown": bool(pipeline_cfg["reporting"]["include_score_breakdown"]),
    }

    timer.start("load_contracts")
    batch = load_contracts(args.contracts_dir, exts)
    timer.stop("load_contracts")

    if not batch:
        console.print(f"[red]No contracts found in {args.contracts_dir}[/red]")
        return

    schedule = schedule_batch(batch, max_workers=max_workers)

    timer.start("verification_and_features")
    vulns_by_contract = {}

    def _analyze(item):
        contract = item.contract
        vulns = run_verification(contract)
        for v in vulns:
            v.features = extract_features(v)
        return contract.contract_id, contract, vulns

    Executor = ThreadPoolExecutor if executor_kind == "thread" else ProcessPoolExecutor
    with Executor(max_workers=max_workers) as ex:
        futures = [ex.submit(_analyze, it) for it in schedule]
        for fut in as_completed(futures):
            cid, contract, vulns = fut.result()
            vulns_by_contract[cid] = {"contract": contract, "vulns": vulns}
            logger.info("Analyzed %s: %d findings", cid, len(vulns))
    timer.stop("verification_and_features")

    # Build dependency graph
    timer.start("dependency_graph")
    all_vulns = [v for bundle in vulns_by_contract.values() for v in bundle["vulns"]]
    dep_graph = build_dependency_graph(all_vulns)
    edges = dependency_edges(dep_graph)
    timer.stop("dependency_graph")

    weights = SeverityWeights(
        alpha=float(weights_cfg["severity_weights"]["alpha"]),
        beta=float(weights_cfg["severity_weights"]["beta"]),
        gamma=float(weights_cfg["severity_weights"]["gamma"]),
    )
    th = Thresholds(
        tau1=float(th_cfg["severity_thresholds"]["tau1"]),
        tau2=float(th_cfg["severity_thresholds"]["tau2"]),
        tau3=float(th_cfg["severity_thresholds"]["tau3"]),
    )
    lam = float(weights_cfg["dependency"]["lambda"])
    max_iter = int(weights_cfg["dependency"].get("max_iter", 3))
    normalize = bool(weights_cfg["dependency"].get("normalize", True))

    # Score & classify with breakdown
    timer.start("scoring_and_classification")
    scored = []
    score_map = {}
    by_id = {}
    for cid, bundle in vulns_by_contract.items():
        for v in bundle["vulns"]:
            s, bd = compute_severity(v, weights)
            label = classify_severity(s, th)
            sv = ScoredVulnerability(vuln=v, severity=s, label=label, score_breakdown=bd, remediation=None)
            scored.append(sv)
            by_id[v.vuln_id] = sv
            score_map[v.vuln_id] = s

    # Dependency propagation
    score_map2 = propagate_severity(score_map, edges, lam=lam, max_iter=max_iter, normalize=normalize)
    for vid, new_s in score_map2.items():
        if vid in by_id:
            by_id[vid].severity = float(new_s)
            by_id[vid].label = classify_severity(float(new_s), th)
            by_id[vid].score_breakdown["severity_after_dependency"] = float(new_s)

    scored = rank_vulnerabilities(scored)
    timer.stop("scoring_and_classification")

    # Remediation
    timer.start("remediation")
    rem = RemediationEngine(args.kb_path)
    for sv in scored:
        sv.remediation = rem.recommend(sv.vuln)
    timer.stop("remediation")

    # Reporting
    timer.start("reporting")
    per_contract_scored = {}
    scored_rows = []
    for sv in scored:
        cid = sv.vuln.contract_id
        per_contract_scored.setdefault(cid, []).append(sv)
        scored_rows.append({
            "contract_id": cid,
            "vuln_id": sv.vuln.vuln_id,
            "vtype": sv.vuln.vtype,
            "severity": sv.severity,
            "label": sv.label
        })

    for cid, items in per_contract_scored.items():
        meta = {**meta_global, "contract_id": cid}
        if "html" in formats:
            generate_html_report(items, str(reports_dir / f"{cid}_report.html"), args.templates_dir, meta)
        if "pdf" in formats:
            generate_pdf_report(items, str(reports_dir / f"{cid}_report.pdf"), meta)
        if "json" in formats:
            export_json_contract(items, str(json_dir / f"{cid}_report.json"), meta, schema=schema, strict=strict_schema)
    timer.stop("reporting")

    # Dashboard
    timer.start("dashboard")
    df, summary = build_portfolio_metrics(scored_rows)
    if pipeline_cfg["pipeline"].get("include_dashboard", True):
        build_dashboard(
            summary=summary,
            out_html=str(dashboards_dir / "dashboard.html"),
            out_json=str(json_dir / "dashboard.json"),
            templates_dir=args.templates_dir,
            meta=meta_global
        )
    timer.stop("dashboard")

    # Benchmarks
    timer.stop("total")
    if pipeline_cfg["pipeline"].get("include_benchmarks", True):
        write_json(bench_dir / "timings.json", timer.as_dict())

    # Run manifest
    write_json(json_dir / "run_manifest.json", {
        "run_at": datetime.datetime.utcnow().isoformat() + "Z",
        "contracts_dir": args.contracts_dir,
        "num_contracts": len(batch),
        "num_findings": len(scored),
        "executor": executor_kind,
        "outputs": {
            "reports_dir": str(reports_dir),
            "dashboards_dir": str(dashboards_dir),
            "json_dir": str(json_dir),
            "bench_dir": str(bench_dir)
        }
    })

    # Console summary table
    t = Table(title="AutoVeriAudit Run Summary")
    t.add_column("Contracts", justify="right")
    t.add_column("Findings", justify="right")
    t.add_column("Mean Severity", justify="right")
    t.add_column("Max Severity", justify="right")
    t.add_row(
        str(summary.get("total_contracts", 0)),
        str(summary.get("total_vulnerabilities", 0)),
        f"{summary.get('severity_mean', 0.0):.3f}",
        f"{summary.get('severity_max', 0.0):.3f}",
    )
    console.print(t)
    console.print(f"[green]Done[/green]. Reports in: {reports_dir}")

if __name__ == "__main__":
    main()
