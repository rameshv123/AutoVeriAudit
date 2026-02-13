from __future__ import annotations
from pathlib import Path
from typing import List
from utils.file_manager import list_contract_files, read_text
from utils.helpers import ContractArtifact
from core.ingestion.metadata_extractor import extract_metadata

def standardize_contract(contract_path: Path) -> ContractArtifact:
    source = read_text(contract_path)
    metadata = extract_metadata(source)
    return ContractArtifact(
        contract_id=contract_path.stem,
        path=str(contract_path),
        source=source,
        metadata=metadata
    )

def load_contracts(contracts_dir: str, exts: list[str]) -> List[ContractArtifact]:
    files = list_contract_files(contracts_dir, exts)
    return [standardize_contract(p) for p in files]
