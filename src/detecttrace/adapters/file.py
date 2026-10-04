from __future__ import annotations
import json
from pathlib import Path
from typing import Any


class FileAdapter:
    def __init__(self, max_bytes: int = 10_000_000, max_events: int = 100_000):
        self.max_bytes = max_bytes
        self.max_events = max_events

    def _check(self, path: Path) -> None:
        if not path.exists():
            raise FileNotFoundError(path)
        if not path.is_file():
            raise ValueError(f"not a file: {path}")
        if path.stat().st_size > self.max_bytes:
            raise ValueError(f"input exceeds {self.max_bytes} bytes: {path}")

    def load_object(self, path: Path) -> dict[str, Any]:
        self._check(path)
        obj = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(obj, dict):
            raise ValueError(f"expected JSON object: {path}")
        return obj

    def load_events(self, path: Path) -> list[dict[str, Any]]:
        self._check(path)
        if path.suffix.lower() == ".json":
            obj = json.loads(path.read_text(encoding="utf-8"))
            if isinstance(obj, dict):
                return [obj]
            if not isinstance(obj, list) or not all(isinstance(x, dict) for x in obj):
                raise ValueError(f"expected JSON object/list of objects: {path}")
            return obj[: self.max_events]

        events: list[dict[str, Any]] = []
        with path.open("r", encoding="utf-8") as fh:
            for lineno, line in enumerate(fh, start=1):
                if not line.strip():
                    continue
                if len(events) >= self.max_events:
                    raise ValueError(f"too many events in {path}")
                obj = json.loads(line)
                if not isinstance(obj, dict):
                    raise ValueError(f"line {lineno}: expected object")
                events.append(obj)
        return events
