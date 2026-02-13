from __future__ import annotations
from typing import List
from utils.helpers import ScoredVulnerability

def rank_vulnerabilities(items: List[ScoredVulnerability]) -> List[ScoredVulnerability]:
    return sorted(items, key=lambda x: x.severity, reverse=True)
