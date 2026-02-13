from __future__ import annotations
import re
from typing import Dict, Any

def extract_metadata(source: str) -> Dict[str, Any]:
    size_chars = len(source)
    func_count = len(re.findall(r"\bfunction\b", source))
    pragma = None
    m = re.search(r"pragma\s+solidity\s+([^;]+);", source)
    if m:
        pragma = m.group(1).strip()
    return {
        "size_chars": size_chars,
        "function_count": func_count,
        "compiler_pragma": pragma or "unknown"
    }
