from __future__ import annotations
from pathlib import Path
from typing import Any


MISSING = object()


def get_path(obj: Any, dotted: str, default: Any = MISSING) -> Any:
    cur = obj
    for part in dotted.split("."):
        if isinstance(cur, dict) and part in cur:
            cur = cur[part]
        else:
            return default
    return cur


def flatten_leaves(obj: Any, prefix: str = "") -> dict[str, Any]:
    out: dict[str, Any] = {}
    if isinstance(obj, dict):
        for key, value in obj.items():
            child = f"{prefix}.{key}" if prefix else str(key)
            out.update(flatten_leaves(value, child))
    elif isinstance(obj, list):
        for i, value in enumerate(obj):
            child = f"{prefix}.{i}" if prefix else str(i)
            out.update(flatten_leaves(value, child))
    else:
        out[prefix] = obj
    return out


def parse_iso8601(value: str) -> datetime.datetime:
    import datetime
    if not isinstance(value, str):
        raise ValueError("timestamp must be a string")
    normalized = value[:-1] + "+00:00" if value.endswith("Z") else value
    dt = datetime.datetime.fromisoformat(normalized)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=datetime.timezone.utc)
    return dt


def safe_resolve(base: Path, relative: str) -> Path:
    base = base.resolve()
    target = (base / relative).resolve()
    try:
        target.relative_to(base)
    except ValueError as exc:
        raise ValueError(f"path escapes spec directory: {relative}") from exc
    return target
