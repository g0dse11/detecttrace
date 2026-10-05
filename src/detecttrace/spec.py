from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml


class SpecError(ValueError):
    pass


STAGES = ("execution", "source", "collector", "normalization", "rule", "alert")
TOP_LEVEL_KEYS = {
    "spec_version",
    "id",
    "title",
    "behavior",
    "inputs",
    "test",
    "checkpoints",
}
PROFILE_KEYS = {"execution", "source", "collector", "normalized", "alerts"}


def _unknown_keys(
    value: dict[str, Any],
    allowed: set[str],
    path: str,
) -> None:
    unknown = set(value) - allowed
    if unknown:
        raise SpecError(
            f"{path} contains unknown field(s): "
            + ", ".join(sorted(str(key) for key in unknown))
        )


def _non_empty_string(value: Any, path: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise SpecError(f"{path} must be a non-empty string")
    return value


def _object(value: Any, path: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise SpecError(f"{path} must be an object")
    return value


def _validate_predicate(value: Any, path: str) -> None:
    node = _object(value, path)

    composition_keys = [key for key in ("all", "any", "not") if key in node]

    if composition_keys:
        if len(composition_keys) != 1:
            raise SpecError(
                f"{path} must use exactly one of 'all', 'any', or 'not'"
            )

        key = composition_keys[0]
        _unknown_keys(node, {key}, path)

        if key in ("all", "any"):
            children = node[key]
            if not isinstance(children, list) or not children:
                raise SpecError(
                    f"{path}.{key} must be a non-empty list"
                )
            for index, child in enumerate(children):
                _validate_predicate(
                    child,
                    f"{path}.{key}[{index}]",
                )
            return

        _validate_predicate(node["not"], f"{path}.not")
        return

    _unknown_keys(node, {"field", "op", "value"}, path)

    if "field" not in node:
        raise SpecError(f"{path}.field is required")
    if "op" not in node:
        raise SpecError(f"{path}.op is required")

    _non_empty_string(node["field"], f"{path}.field")
    _non_empty_string(node["op"], f"{path}.op")


def load_spec(path: Path) -> dict[str, Any]:
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise SpecError(f"spec not found: {path}") from exc
    except UnicodeDecodeError as exc:
        raise SpecError(
            f"spec must be UTF-8 text: {path}"
        ) from exc
    except yaml.YAMLError as exc:
        raise SpecError(f"invalid YAML: {exc}") from exc

    if not isinstance(raw, dict):
        raise SpecError("spec root must be an object")

    validate_spec(raw)
    return raw


def validate_spec(spec: dict[str, Any]) -> None:
    _unknown_keys(spec, TOP_LEVEL_KEYS, "spec")

    if spec.get("spec_version") != "detectspec/v1":
        raise SpecError("spec_version must be 'detectspec/v1'")

    for key in ("id", "title"):
        if key not in spec:
            raise SpecError(f"{key} is required")
        _non_empty_string(spec[key], key)

    if "behavior" in spec:
        _object(spec["behavior"], "behavior")

    if "inputs" not in spec:
        raise SpecError("inputs is required")

    inputs = _object(spec["inputs"], "inputs")
    _unknown_keys(inputs, {"profiles"}, "inputs")

    profiles = inputs.get("profiles")
    if not isinstance(profiles, dict) or not profiles:
        raise SpecError("inputs.profiles must be a non-empty object")

    for name, profile_value in profiles.items():
        _non_empty_string(name, "inputs.profiles profile name")
        profile = _object(
            profile_value,
            f"inputs.profiles.{name}",
        )
        _unknown_keys(
            profile,
            PROFILE_KEYS,
            f"inputs.profiles.{name}",
        )

        for stage in PROFILE_KEYS:
            if stage in profile:
                _non_empty_string(
                    profile[stage],
                    f"inputs.profiles.{name}.{stage}",
                )

    if "test" in spec:
        test = _object(spec["test"], "test")
        _unknown_keys(test, {"cases"}, "test")

        cases = test.get("cases")
        if not isinstance(cases, dict) or not cases:
            raise SpecError("test.cases must be a non-empty object")

        for name, case_value in cases.items():
            _non_empty_string(name, "test.cases case name")
            case = _object(case_value, f"test.cases.{name}")
            _unknown_keys(case, {"event"}, f"test.cases.{name}")

            if "event" not in case:
                raise SpecError(f"test.cases.{name}.event is required")
            _object(case["event"], f"test.cases.{name}.event")

    if "checkpoints" not in spec:
        raise SpecError("checkpoints is required")

    checkpoints = _object(spec["checkpoints"], "checkpoints")
    if not checkpoints:
        raise SpecError("checkpoints must be a non-empty object")

    unknown = set(checkpoints) - set(STAGES)
    if unknown:
        raise SpecError(
            "checkpoints contains unknown checkpoint(s): "
            + ", ".join(sorted(unknown))
        )

    if "execution" in checkpoints:
        execution = _object(
            checkpoints["execution"],
            "checkpoints.execution",
        )
        _unknown_keys(
            execution,
            {"require"},
            "checkpoints.execution",
        )
        if "require" in execution:
            required = execution["require"]
            if not isinstance(required, list):
                raise SpecError(
                    "checkpoints.execution.require must be a list"
                )
            for index, item in enumerate(required):
                _validate_predicate(
                    item,
                    f"checkpoints.execution.require[{index}]",
                )

    for stage in ("source", "collector"):
        if stage not in checkpoints:
            continue

        cfg = _object(
            checkpoints[stage],
            f"checkpoints.{stage}",
        )
        _unknown_keys(
            cfg,
            {"require_event"},
            f"checkpoints.{stage}",
        )
        if "require_event" in cfg:
            _validate_predicate(
                cfg["require_event"],
                f"checkpoints.{stage}.require_event",
            )

    if "alert" in checkpoints:
        alert = _object(
            checkpoints["alert"],
            "checkpoints.alert",
        )
        _unknown_keys(
            alert,
            {
                "require_event",
                "within_seconds",
                "execution_time_field",
                "alert_time_field",
            },
            "checkpoints.alert",
        )

        if "require_event" in alert:
            _validate_predicate(
                alert["require_event"],
                "checkpoints.alert.require_event",
            )

        if "within_seconds" in alert:
            within = alert["within_seconds"]
            if (
                isinstance(within, bool)
                or not isinstance(within, (int, float))
                or within < 0
            ):
                raise SpecError(
                    "checkpoints.alert.within_seconds must be "
                    "a non-negative number"
                )

        for field_name in (
            "execution_time_field",
            "alert_time_field",
        ):
            if field_name in alert:
                _non_empty_string(
                    alert[field_name],
                    f"checkpoints.alert.{field_name}",
                )

    if "normalization" in checkpoints:
        norm = _object(
            checkpoints["normalization"],
            "checkpoints.normalization",
        )
        _unknown_keys(
            norm,
            {"require_event", "required_fields"},
            "checkpoints.normalization",
        )

        if "require_event" in norm:
            _validate_predicate(
                norm["require_event"],
                "checkpoints.normalization.require_event",
            )

        if "required_fields" in norm:
            fields = norm["required_fields"]
            if not isinstance(fields, list):
                raise SpecError(
                    "checkpoints.normalization.required_fields "
                    "must be a list"
                )

            for index, item in enumerate(fields):
                path = (
                    "checkpoints.normalization.required_fields"
                    f"[{index}]"
                )

                if isinstance(item, str):
                    _non_empty_string(item, path)
                    continue

                entry = _object(item, path)
                _unknown_keys(entry, {"field", "from"}, path)

                if "field" not in entry:
                    raise SpecError(f"{path}.field is required")

                _non_empty_string(entry["field"], f"{path}.field")

                if "from" in entry:
                    _non_empty_string(entry["from"], f"{path}.from")

    if "rule" in checkpoints:
        rule = _object(
            checkpoints["rule"],
            "checkpoints.rule",
        )
        _unknown_keys(
            rule,
            {"match"},
            "checkpoints.rule",
        )

        if rule and "match" not in rule:
            raise SpecError(
                "checkpoints.rule.match is required when "
                "the rule checkpoint is configured"
            )

        if "match" in rule:
            _validate_predicate(
                rule["match"],
                "checkpoints.rule.match",
            )
