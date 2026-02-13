from __future__ import annotations
import json
from pathlib import Path
from typing import Dict, Optional
from utils.helpers import Vulnerability

class RemediationEngine:
    def __init__(self, kb_path: str):
        self.kb_path = kb_path
        self.kb: Dict[str, Dict[str, str]] = {}
        self.load()

    def load(self) -> None:
        self.kb = json.loads(Path(self.kb_path).read_text(encoding="utf-8"))

    def recommend(self, vuln: Vulnerability) -> Optional[Dict[str, str]]:
        return self.kb.get(vuln.vtype)
