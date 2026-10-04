from __future__ import annotations
import re
from typing import Any
from .util import MISSING, get_path


class RuleError(ValueError):
    pass


def _predicate(event: dict[str, Any], node: dict[str, Any]) -> bool:
    field = node.get("field")
    op = node.get("op")
    if not isinstance(field, str) or not isinstance(op, str):
        raise RuleError("predicate requires string 'field' and 'op'")

    value = get_path(event, field)
    expected = node.get("value")

    if op == "exists":
        want = True if "value" not in node else bool(expected)
        return (value is not MISSING) is want

    if value is MISSING:
        return False

    if op == "equals":
        return value == expected
    if op == "not_equals":
        return value != expected
    if op == "contains":
        if isinstance(value, (list, tuple, set)):
            return expected in value
        return str(expected) in str(value)
    if op == "startswith":
        return str(value).startswith(str(expected))
    if op == "endswith":
        return str(value).endswith(str(expected))
    if op == "regex":
        if not isinstance(expected, str):
            raise RuleError("regex value must be a string")
        if len(expected) > 2048:
            raise RuleError("regex is too long")
        return re.search(expected, str(value)) is not None
    if op == "in":
        if not isinstance(expected, list):
            raise RuleError("'in' requires a list value")
        return value in expected
    if op in {"gt", "gte", "lt", "lte"}:
        try:
            if op == "gt":
                return value > expected
            if op == "gte":
                return value >= expected
            if op == "lt":
                return value < expected
            return value <= expected
        except TypeError:
            return False
    raise RuleError(f"unsupported operator: {op}")


def evaluate(event: dict[str, Any], node: dict[str, Any]) -> bool:
    if not isinstance(node, dict):
        raise RuleError("rule node must be an object")

    keys = [k for k in ("all", "any", "not", "field") if k in node]
    if len(keys) != 1:
        raise RuleError("rule node must contain exactly one of: all, any, not, field")

    if "all" in node:
        children = node["all"]
        if not isinstance(children, list) or not children:
            raise RuleError("'all' must be a non-empty list")
        return all(evaluate(event, child) for child in children)

    if "any" in node:
        children = node["any"]
        if not isinstance(children, list) or not children:
            raise RuleError("'any' must be a non-empty list")
        return any(evaluate(event, child) for child in children)

    if "not" in node:
        return not evaluate(event, node["not"])

    return _predicate(event, node)


def first_matching(events: list[dict[str, Any]], rule: dict[str, Any]) -> tuple[int, dict[str, Any]] | None:
    for i, event in enumerate(events):
        if evaluate(event, rule):
            return i, event
    return None
