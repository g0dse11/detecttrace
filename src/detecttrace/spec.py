from __future__ import annotations
from pathlib import Path
from typing import Any
import yaml


class SpecError(ValueError):
    pass


STAGES = ("execution", "source", "collector", "normalization", "rule", "alert")


def load_spec(path: Path) -> dict[str, Any]:
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise SpecError(f"spec not found: {path}") from exc
    except yaml.YAMLError as exc:
        raise SpecError(f"invalid YAML: {exc}") from exc

    if not isinstance(raw, dict):
        raise SpecError("spec root must be an object")
    validate_spec(raw)
    return raw


def validate_spec(spec: dict[str, Any]) -> None:
    if spec.get("spec_version") != "detectspec/v1":
        raise SpecError("spec_version must be 'detectspec/v1'")
    for key in ("id", "title"):
        if not isinstance(spec.get(key), str) or not spec[key].strip():
            raise SpecError(f"{key} must be a non-empty string")

    inputs = spec.get("inputs")
    if not isinstance(inputs, dict):
        raise SpecError("inputs must be an object")
    profiles = inputs.get("profiles")
    if not isinstance(profiles, dict) or not profiles:
        raise SpecError("inputs.profiles must be a non-empty object")
    for name, profile in profiles.items():
        if not isinstance(name, str) or not isinstance(profile, dict):
            raise SpecError("each profile must be an object")
        for stage in ("execution", "source", "collector", "normalized", "alerts"):
            if stage in profile and not isinstance(profile[stage], str):
                raise SpecError(f"profile '{name}' field '{stage}' must be a path string")

    checkpoints = spec.get("checkpoints")
    if not isinstance(checkpoints, dict) or not checkpoints:
        raise SpecError("checkpoints must be a non-empty object")
    unknown = set(checkpoints) - set(STAGES)
    if unknown:
        raise SpecError(f"unknown checkpoints: {', '.join(sorted(unknown))}")

    exe = checkpoints.get("execution", {})
    if exe:
        req = exe.get("require", [])
        if not isinstance(req, list):
            raise SpecError("checkpoints.execution.require must be a list")

    for stage in ("source", "collector", "normalization", "alert"):
        cfg = checkpoints.get(stage, {})
        if cfg and "require_event" in cfg and not isinstance(cfg["require_event"], dict):
            raise SpecError(f"checkpoints.{stage}.require_event must be an object")

    norm = checkpoints.get("normalization", {})
    if "required_fields" in norm:
        fields = norm["required_fields"]
        if not isinstance(fields, list):
            raise SpecError("normalization.required_fields must be a list")
        for item in fields:
            if isinstance(item, str) and item:
                continue
            if (
                isinstance(item, dict)
                and isinstance(item.get("field"), str)
                and item["field"]
                and ("from" not in item or isinstance(item["from"], str))
            ):
                continue
            raise SpecError(
                "normalization.required_fields entries must be field names or "
                "{field: ..., from: ...} objects"
            )

    rule = checkpoints.get("rule", {})
    if rule and not isinstance(rule.get("match"), dict):
        raise SpecError("checkpoints.rule.match must be an object")
