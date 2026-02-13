from __future__ import annotations
from dataclasses import dataclass
from typing import List
from utils.helpers import ContractArtifact

@dataclass
class ScheduleItem:
    contract: ContractArtifact
    worker_id: int

def assign_worker(contract: ContractArtifact, max_workers: int) -> int:
    return abs(hash(contract.contract_id)) % max_workers

def schedule_batch(batch: List[ContractArtifact], max_workers: int) -> List[ScheduleItem]:
    return [ScheduleItem(contract=c, worker_id=assign_worker(c, max_workers)) for c in batch]
