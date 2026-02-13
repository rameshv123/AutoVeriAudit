from __future__ import annotations
from pathlib import Path
import json

def ensure_dir(path: str | Path) -> Path:
    p = Path(path)
    p.mkdir(parents=True, exist_ok=True)
    return p

def read_text(path: str | Path) -> str:
    return Path(path).read_text(encoding="utf-8", errors="ignore")

def write_text(path: str | Path, content: str) -> None:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content, encoding="utf-8")

def write_json(path: str | Path, obj) -> None:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(obj, indent=2), encoding="utf-8")

def list_contract_files(contracts_dir: str | Path, exts: list[str]) -> list[Path]:
    d = Path(contracts_dir)
    files = []
    for ext in exts:
        files.extend(d.rglob(f"*{ext}"))
    return sorted(set(files))
