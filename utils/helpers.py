from __future__ import annotations
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

@dataclass
class ContractArtifact:
    contract_id: str
    path: str
    source: str
    metadata: Dict[str, Any]

@dataclass
class Vulnerability:
    vuln_id: str
    contract_id: str
    vtype: str
    function: str
    location: str
    description: str
    trace: List[str]
    features: Dict[str, float]

@dataclass
class ScoredVulnerability:
    vuln: Vulnerability
    severity: float
    label: str
    score_breakdown: Dict[str, float]
    remediation: Optional[Dict[str, str]] = None

def now_iso() -> str:
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).isoformat()
