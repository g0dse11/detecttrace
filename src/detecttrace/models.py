from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class Status(str, Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    BLOCKED = "BLOCKED"
    UNKNOWN = "UNKNOWN"
    SKIPPED = "SKIPPED"


@dataclass
class Evidence:
    message: str
    data: dict[str, Any] = field(default_factory=dict)


@dataclass
class StageResult:
    name: str
    status: Status
    summary: str
    evidence: list[Evidence] = field(default_factory=list)


@dataclass
class TraceResult:
    spec_id: str
    title: str
    profile: str
    stages: list[StageResult]
    root_cause: str | None = None
    confidence: str | None = None

    @property
    def healthy(self) -> bool:
        return all(stage.status in {Status.PASS, Status.SKIPPED} for stage in self.stages)
