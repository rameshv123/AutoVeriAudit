from __future__ import annotations
from dataclasses import dataclass

@dataclass
class Thresholds:
    tau1: float
    tau2: float
    tau3: float

def classify_severity(score: float, th: Thresholds) -> str:
    if score < th.tau1:
        return "Low"
    if score < th.tau2:
        return "Medium"
    if score < th.tau3:
        return "High"
    return "Critical"
