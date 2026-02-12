from __future__ import annotations
import time
from dataclasses import dataclass, field
from typing import Dict

@dataclass
class BenchTimer:
    marks: Dict[str, float] = field(default_factory=dict)
    durations: Dict[str, float] = field(default_factory=dict)

    def start(self, key: str) -> None:
        self.marks[key] = time.perf_counter()

    def stop(self, key: str) -> None:
        if key not in self.marks:
            return
        self.durations[key] = time.perf_counter() - self.marks[key]

    def as_dict(self) -> Dict[str, float]:
        return dict(self.durations)
