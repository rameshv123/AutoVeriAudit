from __future__ import annotations
from typing import Dict
from utils.helpers import Vulnerability

_TYPE_PRIORS: Dict[str, Dict[str, float]] = {
    "reentrancy": {"exploitability": 0.90, "impact": 0.90, "exposure": 0.80},
    "arithmetic_overflow": {"exploitability": 0.60, "impact": 0.70, "exposure": 0.60},
    "access_control": {"exploitability": 0.80, "impact": 0.85, "exposure": 0.75},
    "unchecked_call": {"exploitability": 0.65, "impact": 0.60, "exposure": 0.55},
    "dos_gas": {"exploitability": 0.45, "impact": 0.60, "exposure": 0.60},
    "info": {"exploitability": 0.10, "impact": 0.10, "exposure": 0.10},
}

def extract_features(vuln: Vulnerability) -> Dict[str, float]:
    priors = _TYPE_PRIORS.get(vuln.vtype, {"exploitability": 0.50, "impact": 0.50, "exposure": 0.50})
    trace_len = max(1, len(vuln.trace) if vuln.trace else 1)
    # Slight exposure bump with longer traces (more complex reachable behavior)
    exposure_adj = min(0.15, 0.02 * max(0, trace_len - 3))
    return {
        "exploitability": float(priors["exploitability"]),
        "impact": float(priors["impact"]),
        "exposure": float(min(1.0, priors["exposure"] + exposure_adj)),
    }
