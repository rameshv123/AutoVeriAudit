from __future__ import annotations
from dataclasses import dataclass
from typing import Dict
from utils.helpers import Vulnerability

@dataclass
class SeverityWeights:
    alpha: float
    beta: float
    gamma: float

def compute_severity(vuln: Vulnerability, weights: SeverityWeights) -> tuple[float, Dict[str, float]]:
    ex = vuln.features.get("exploitability", 0.5)
    im = vuln.features.get("impact", 0.5)
    cr = vuln.features.get("exposure", 0.5)

    s_ex = weights.alpha * ex
    s_im = weights.beta * im
    s_cr = weights.gamma * cr
    s = s_ex + s_im + s_cr
    s = float(max(0.0, min(1.0, s)))

    breakdown = {
        "exploitability": float(ex),
        "impact": float(im),
        "exposure": float(cr),
        "weighted_exploitability": float(s_ex),
        "weighted_impact": float(s_im),
        "weighted_exposure": float(s_cr),
        "severity": float(s),
    }
    return s, breakdown
