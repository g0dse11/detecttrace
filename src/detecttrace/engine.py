from __future__ import annotations
from pathlib import Path
from typing import Any

from .adapters.file import FileAdapter
from .models import Evidence, StageResult, Status, TraceResult
from .rules import RuleError, evaluate, first_matching
from .util import MISSING, flatten_leaves, get_path, parse_iso8601, safe_resolve


class TraceEngine:
    STAGE_ORDER = ("execution", "source", "collector", "normalization", "rule", "alert")

    def __init__(self, adapter: FileAdapter | None = None):
        self.adapter = adapter or FileAdapter()

    def run(self, spec: dict[str, Any], spec_path: Path, profile_name: str) -> TraceResult:
        profiles = spec["inputs"]["profiles"]
        if profile_name not in profiles:
            raise ValueError(
                f"unknown profile '{profile_name}'. Available: {', '.join(sorted(profiles))}"
            )

        base = spec_path.parent.resolve()
        profile = profiles[profile_name]
        checkpoints = spec["checkpoints"]
        results: list[StageResult] = []
        blocked_by: str | None = None

        execution_obj: dict[str, Any] | None = None
        event_sets: dict[str, list[dict[str, Any]]] = {}

        if "execution" in profile:
            execution_obj = self.adapter.load_object(safe_resolve(base, profile["execution"]))
        for stage, input_key in (
            ("source", "source"),
            ("collector", "collector"),
            ("normalization", "normalized"),
            ("alert", "alerts"),
        ):
            if input_key in profile:
                event_sets[stage] = self.adapter.load_events(
                    safe_resolve(base, profile[input_key])
                )

        for stage in self.STAGE_ORDER:
            cfg = checkpoints.get(stage)
            if cfg is None:
                results.append(StageResult(stage, Status.SKIPPED, "No checkpoint declared."))
                continue

            if blocked_by is not None:
                results.append(
                    StageResult(
                        stage,
                        Status.BLOCKED,
                        f"Blocked by failed checkpoint: {blocked_by}.",
                    )
                )
                continue

            try:
                if stage == "execution":
                    result = self._execution(cfg, execution_obj)
                elif stage in {"source", "collector"}:
                    result = self._event_checkpoint(stage, cfg, event_sets.get(stage))
                elif stage == "normalization":
                    result = self._normalization(
                        cfg,
                        event_sets.get("normalization"),
                        source_events=event_sets.get("source"),
                        collector_events=event_sets.get("collector"),
                    )
                elif stage == "rule":
                    result = self._rule(cfg, event_sets.get("normalization"))
                elif stage == "alert":
                    result = self._alert(cfg, event_sets.get("alert"), execution_obj)
                else:
                    result = StageResult(stage, Status.UNKNOWN, "Unsupported checkpoint.")
            except (RuleError, ValueError, TypeError) as exc:
                result = StageResult(
                    stage,
                    Status.FAIL,
                    f"Checkpoint evaluation error: {exc}",
                    [Evidence("Evaluation error", {"error": str(exc)})],
                )

            results.append(result)
            if result.status == Status.FAIL:
                blocked_by = stage

        root, confidence = self._root_cause(results)
        return TraceResult(
            spec_id=spec["id"],
            title=spec["title"],
            profile=profile_name,
            stages=results,
            root_cause=root,
            confidence=confidence,
        )

    def _execution(
        self, cfg: dict[str, Any], obj: dict[str, Any] | None
    ) -> StageResult:
        if obj is None:
            return StageResult("execution", Status.UNKNOWN, "No execution evidence available.")
        failures: list[Evidence] = []
        for pred in cfg.get("require", []):
            ok = evaluate(obj, pred)
            if not ok:
                failures.append(Evidence("Execution assertion failed.", {"predicate": pred}))
        if failures:
            return StageResult(
                "execution", Status.FAIL, "Execution evidence did not satisfy the contract.", failures
            )
        return StageResult(
            "execution",
            Status.PASS,
            "Test execution is evidenced.",
            [Evidence("Execution object satisfied all assertions.", obj)],
        )

    def _event_checkpoint(
        self, stage: str, cfg: dict[str, Any], events: list[dict[str, Any]] | None
    ) -> StageResult:
        if events is None:
            return StageResult(stage, Status.UNKNOWN, "No checkpoint evidence available.")
        rule = cfg.get("require_event")
        if rule is None:
            return StageResult(
                stage,
                Status.PASS,
                f"{len(events)} event(s) observed.",
                [Evidence("Event count", {"count": len(events)})],
            )
        match = first_matching(events, rule)
        if match is None:
            return StageResult(
                stage,
                Status.FAIL,
                f"No event satisfied the {stage} contract.",
                [
                    Evidence("Observed event count", {"count": len(events)}),
                    Evidence("Required predicate", {"rule": rule}),
                ],
            )
        idx, event = match
        return StageResult(
            stage,
            Status.PASS,
            f"Observed event #{idx} satisfying the {stage} contract.",
            [Evidence("Matching event", event)],
        )

    def _field_specs(self, cfg: dict[str, Any]) -> list[dict[str, str]]:
        specs = []
        for item in cfg.get("required_fields", []):
            if isinstance(item, str):
                specs.append({"field": item})
            else:
                specs.append(dict(item))
        return specs

    def _lineage_hint(
        self,
        field_spec: dict[str, str],
        normalized_event: dict[str, Any],
        source_events: list[dict[str, Any]] | None,
        collector_events: list[dict[str, Any]] | None,
    ) -> dict[str, Any] | None:
        source_path = field_spec.get("from")
        if not source_path:
            return None

        expected = MISSING
        origin = None
        for stage_name, events in (("collector", collector_events), ("source", source_events)):
            for event in events or []:
                candidate = get_path(event, source_path)
                if candidate is not MISSING and candidate not in (None, ""):
                    expected = candidate
                    origin = stage_name
                    break
            if expected is not MISSING:
                break

        if expected is MISSING:
            return None

        leaves = flatten_leaves(normalized_event)
        exact_paths = [path for path, value in leaves.items() if value == expected]
        if exact_paths:
            return {
                "required_field": field_spec["field"],
                "source_field": source_path,
                "source_stage": origin,
                "source_value": expected,
                "observed_at": exact_paths,
                "diagnosis": "value_survived_under_different_field",
            }
        return {
            "required_field": field_spec["field"],
            "source_field": source_path,
            "source_stage": origin,
            "source_value": expected,
            "observed_at": [],
            "diagnosis": "value_not_found_after_normalization",
        }

    def _normalization(
        self,
        cfg: dict[str, Any],
        events: list[dict[str, Any]] | None,
        source_events: list[dict[str, Any]] | None = None,
        collector_events: list[dict[str, Any]] | None = None,
    ) -> StageResult:
        if events is None:
            return StageResult(
                "normalization", Status.UNKNOWN, "No normalized evidence available."
            )

        candidate_events = events
        selector = cfg.get("require_event")
        if selector is not None:
            candidate_events = [e for e in events if evaluate(e, selector)]
            if not candidate_events:
                return StageResult(
                    "normalization",
                    Status.FAIL,
                    "Normalized telemetry exists, but no event matched the normalization selector.",
                    [
                        Evidence("Observed event count", {"count": len(events)}),
                        Evidence("Selector", {"rule": selector}),
                    ],
                )

        field_specs = self._field_specs(cfg)
        best_missing: list[dict[str, str]] | None = None
        best_event: dict[str, Any] | None = None

        for event in candidate_events:
            missing = [
                fs
                for fs in field_specs
                if get_path(event, fs["field"]) is MISSING
                or get_path(event, fs["field"]) in (None, "")
            ]
            if best_missing is None or len(missing) < len(best_missing):
                best_missing, best_event = missing, event
            if not missing:
                return StageResult(
                    "normalization",
                    Status.PASS,
                    "Normalized event satisfies required field contract.",
                    [Evidence("Matching normalized event", event)],
                )

        evidence = [
            Evidence(
                "Missing required fields",
                {"fields": [fs["field"] for fs in (best_missing or field_specs)]},
            ),
            Evidence("Closest normalized event", best_event or {}),
        ]
        for fs in best_missing or []:
            hint = self._lineage_hint(
                fs, best_event or {}, source_events, collector_events
            )
            if hint:
                evidence.append(Evidence("Field lineage analysis", hint))

        return StageResult(
            "normalization",
            Status.FAIL,
            "Normalized telemetry violates the required field contract.",
            evidence,
        )

    def _rule(
        self, cfg: dict[str, Any], events: list[dict[str, Any]] | None
    ) -> StageResult:
        if events is None:
            return StageResult("rule", Status.UNKNOWN, "No rule input evidence available.")
        rule = cfg.get("match")
        match = first_matching(events, rule)
        if match is None:
            return StageResult(
                "rule",
                Status.FAIL,
                "Rule predicate did not match any normalized event.",
                [
                    Evidence("Observed event count", {"count": len(events)}),
                    Evidence("Rule predicate", {"rule": rule}),
                ],
            )
        idx, event = match
        return StageResult(
            "rule",
            Status.PASS,
            f"Rule predicate matched normalized event #{idx}.",
            [Evidence("Matched rule input", event)],
        )

    def _alert(
        self,
        cfg: dict[str, Any],
        events: list[dict[str, Any]] | None,
        execution: dict[str, Any] | None,
    ) -> StageResult:
        base = self._event_checkpoint("alert", cfg, events)
        if base.status != Status.PASS:
            return base

        within = cfg.get("within_seconds")
        if within is None:
            return base
        if not isinstance(within, (int, float)) or within < 0:
            raise ValueError("alert.within_seconds must be a non-negative number")
        if execution is None:
            return StageResult(
                "alert", Status.UNKNOWN, "Alert exists, but execution time is unavailable."
            )

        execution_time_field = cfg.get("execution_time_field", "timestamp")
        alert_time_field = cfg.get("alert_time_field", "timestamp")
        start = get_path(execution, execution_time_field)
        if start is MISSING:
            return StageResult(
                "alert", Status.UNKNOWN, f"Execution timestamp field '{execution_time_field}' missing."
            )

        matching = first_matching(events or [], cfg.get("require_event"))
        assert matching is not None
        _, alert_event = matching
        end = get_path(alert_event, alert_time_field)
        if end is MISSING:
            return StageResult(
                "alert", Status.UNKNOWN, f"Alert timestamp field '{alert_time_field}' missing."
            )

        delta = (parse_iso8601(end) - parse_iso8601(start)).total_seconds()
        timing = Evidence(
            "Alert latency",
            {"seconds": delta, "required_within_seconds": within},
        )
        if delta < 0 or delta > within:
            return StageResult(
                "alert",
                Status.FAIL,
                f"Expected alert exists but timing contract failed ({delta:.3f}s > {within}s).",
                base.evidence + [timing],
            )
        return StageResult(
            "alert",
            Status.PASS,
            f"Expected alert observed within {delta:.3f}s.",
            base.evidence + [timing],
        )

    def _root_cause(self, results: list[StageResult]) -> tuple[str | None, str | None]:
        first_fail = next((r for r in results if r.status == Status.FAIL), None)
        if first_fail is None:
            unknown = next((r for r in results if r.status == Status.UNKNOWN), None)
            if unknown:
                return (
                    f"Unable to prove end-to-end health because checkpoint '{unknown.name}' "
                    "has no conclusive evidence.",
                    "LOW",
                )
            return ("Detection contract passed end-to-end.", "HIGH")

        if first_fail.name == "normalization":
            missing = None
            lineage: list[dict[str, Any]] = []
            for ev in first_fail.evidence:
                if ev.message == "Missing required fields":
                    missing = ev.data.get("fields")
                elif ev.message == "Field lineage analysis":
                    lineage.append(ev.data)

            remapped = [
                x for x in lineage
                if x.get("diagnosis") == "value_survived_under_different_field"
                and x.get("observed_at")
            ]
            if remapped:
                x = remapped[0]
                observed = ", ".join(x["observed_at"])
                return (
                    f"Normalization/schema contract failed. Required field "
                    f"'{x['required_field']}' is absent, but the same upstream value from "
                    f"'{x['source_field']}' survived normalization at '{observed}'. "
                    "This strongly indicates a field-mapping/schema drift issue. "
                    "Downstream rule and alert stages were blocked.",
                    "HIGH",
                )
            if missing:
                return (
                    "Normalization/schema contract failed. Required field(s) "
                    f"{', '.join(missing)} were absent or empty in the closest matching "
                    "normalized event. Downstream rule and alert stages were therefore blocked.",
                    "HIGH",
                )

        explanations = {
            "execution": "The expected test execution could not be proven.",
            "source": "Expected source telemetry was not observed.",
            "collector": "Source telemetry did not satisfy the collection checkpoint.",
            "rule": "Normalized telemetry reached the rule stage, but the rule predicate did not match.",
            "alert": "The rule path succeeded, but the expected alert contract was not satisfied.",
        }
        return (explanations.get(first_fail.name, first_fail.summary), "HIGH")
