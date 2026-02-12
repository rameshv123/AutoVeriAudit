from __future__ import annotations
from typing import Dict, List, Tuple
import pandas as pd
from utils.helpers import Vulnerability

def aggregate_vulnerabilities(vulns_by_contract: Dict[str, List[Vulnerability]]) -> List[Vulnerability]:
    all_v = []
    for vs in vulns_by_contract.values():
        all_v.extend(vs)
    return all_v

def build_portfolio_metrics(scored_rows: List[dict]) -> Tuple[pd.DataFrame, dict]:
    df = pd.DataFrame(scored_rows)
    if df.empty:
        return df, {"total_vulnerabilities": 0, "total_contracts": 0, "by_label": {}, "by_type": {}}

    summary = {
        "total_contracts": int(df["contract_id"].nunique()),
        "total_vulnerabilities": int(len(df)),
        "severity_mean": float(df["severity"].mean()),
        "severity_max": float(df["severity"].max()),
        "by_label": df["label"].value_counts().to_dict(),
        "by_type": df["vtype"].value_counts().to_dict(),
    }
    return df, summary
