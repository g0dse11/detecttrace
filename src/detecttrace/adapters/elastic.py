from __future__ import annotations

import json
import os
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import Request, urlopen

from ..rules import evaluate
from ..util import MISSING, flatten_leaves, get_path


class ElasticAdapter:
    """Elasticsearch adapter for DetectTrace."""

    def __init__(self, base_url: str | None = None) -> None:
        self.base_url = (
            base_url
            or os.getenv("DETECTTRACE_ELASTIC_URL")
            or "http://localhost:9200"
        ).rstrip("/")

    def _request(
        self,
        method: str,
        path: str,
        body: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        data = None
        headers = {"Accept": "application/json"}

        if body is not None:
            data = json.dumps(body).encode("utf-8")
            headers["Content-Type"] = "application/json"

        request = Request(
            f"{self.base_url}{path}",
            data=data,
            headers=headers,
            method=method,
        )

        with urlopen(request, timeout=10) as response:
            payload = response.read().decode("utf-8")
            return json.loads(payload) if payload else {}

    def check_connection(self) -> tuple[bool, str]:
        try:
            response = self._request("GET", "/")
            version = response.get("version", {}).get("number", "unknown")
            cluster = response.get("cluster_name", "unknown")
            return True, (
                f"Connected to Elasticsearch {version} "
                f"(cluster: {cluster})."
            )
        except (HTTPError, URLError, TimeoutError, OSError) as exc:
            return False, f"Elasticsearch connection failed: {exc}"

    def check_index(self, index: str = "detecttrace-events") -> tuple[bool, str]:
        try:
            response = self._request("GET", f"/{quote(index)}/_count")
            count = response.get("count", 0)
            return True, f"Index '{index}' contains {count} document(s)."
        except HTTPError as exc:
            if exc.code == 404:
                return False, f"Index '{index}' does not exist."
            return False, f"Index check failed: HTTP {exc.code}."
        except (URLError, TimeoutError, OSError) as exc:
            return False, f"Index check failed: {exc}"

    def search(
        self,
        index: str,
        query: dict[str, Any],
        size: int = 10,
        sort: list[Any] | None = None,
    ) -> list[dict[str, Any]]:
        body: dict[str, Any] = {
            "size": size,
            "query": query,
        }
        if sort:
            body["sort"] = sort

        response = self._request(
            "POST",
            f"/{quote(index)}/_search",
            body,
        )
        return response.get("hits", {}).get("hits", [])

    def latest_events(
        self,
        index: str = "detecttrace-events",
        size: int = 10,
    ) -> list[dict[str, Any]]:
        try:
            hits = self.search(
                index=index,
                query={"match_all": {}},
                size=size,
                sort=[{"@timestamp": {"order": "desc", "unmapped_type": "date"}}],
            )
        except HTTPError as exc:
            if exc.code == 400:
                hits = self.search(
                    index=index,
                    query={"match_all": {}},
                    size=size,
                )
            else:
                raise

        return [
            hit.get("_source", {})
            for hit in hits
            if isinstance(hit.get("_source"), dict)
        ]

    def status(
        self,
        index: str = "detecttrace-events",
    ) -> dict[str, tuple[bool, str]]:
        connection = self.check_connection()

        if not connection[0]:
            return {
                "connection": connection,
                "index": (False, "Blocked: Elasticsearch is unavailable."),
            }

        return {
            "connection": connection,
            "index": self.check_index(index),
        }

    @staticmethod
    def _required_field_specs(cfg: dict[str, Any]) -> list[dict[str, Any]]:
        specs: list[dict[str, Any]] = []
        for item in cfg.get("required_fields", []):
            if isinstance(item, str):
                specs.append({"field": item})
            elif isinstance(item, dict):
                specs.append(dict(item))
        return specs

    @staticmethod
    def _lineage_diagnosis(
        field_spec: dict[str, Any],
        event: dict[str, Any],
    ) -> str | None:
        required = field_spec.get("field")
        source = field_spec.get("from")
        if not isinstance(required, str) or not isinstance(source, str):
            return None

        expected = get_path(event, source)
        if expected is MISSING or expected in (None, ""):
            return None

        leaves = flatten_leaves(event)
        observed = [
            path
            for path, value in leaves.items()
            if path != source and value == expected
        ]

        if observed:
            return (
                f"Required field '{required}' is absent, but the value from "
                f"'{source}' survived at '{observed[0]}'. "
                "Probable schema/mapping drift."
            )

        return (
            f"Required field '{required}' is absent. Upstream field "
            f"'{source}' exists, but its value was not found at another "
            "normalized field."
        )

    def trace_spec(
        self,
        spec: dict[str, Any],
        index: str = "detecttrace-events",
        limit: int = 10,
    ) -> dict[str, Any]:
        stages: list[dict[str, str]] = []

        connection = self.check_connection()
        stages.append(
            {
                "name": "Backend connection",
                "status": "PASS" if connection[0] else "FAIL",
                "summary": connection[1],
            }
        )
        if not connection[0]:
            return {
                "stages": stages,
                "root_cause": "Elasticsearch is unavailable.",
                "confidence": "HIGH",
                "healthy": False,
            }

        index_check = self.check_index(index)
        stages.append(
            {
                "name": "Telemetry index",
                "status": "PASS" if index_check[0] else "FAIL",
                "summary": index_check[1],
            }
        )
        if not index_check[0]:
            return {
                "stages": stages,
                "root_cause": "The configured telemetry index is unavailable.",
                "confidence": "HIGH",
                "healthy": False,
            }

        events = self.latest_events(index=index, size=limit)
        if not events:
            stages.append(
                {
                    "name": "Telemetry located",
                    "status": "FAIL",
                    "summary": "No telemetry documents were returned.",
                }
            )
            return {
                "stages": stages,
                "root_cause": "No telemetry was available for evaluation.",
                "confidence": "HIGH",
                "healthy": False,
            }

        stages.append(
            {
                "name": "Telemetry located",
                "status": "PASS",
                "summary": f"Loaded {len(events)} recent document(s).",
            }
        )

        checkpoints = spec.get("checkpoints", {})
        normalization = checkpoints.get("normalization", {})
        selector = normalization.get("require_event")

        candidates = events
        if selector:
            candidates = [event for event in events if evaluate(event, selector)]

        if not candidates:
            stages.append(
                {
                    "name": "Normalization",
                    "status": "FAIL",
                    "summary": "Telemetry exists, but no document matched the normalization selector.",
                }
            )
            stages.append(
                {
                    "name": "Rule",
                    "status": "BLOCKED",
                    "summary": "Blocked by failed checkpoint: normalization.",
                }
            )
            return {
                "stages": stages,
                "root_cause": (
                    "Live telemetry was found, but none matched the "
                    "normalization selector declared by the DetectSpec."
                ),
                "confidence": "HIGH",
                "healthy": False,
            }

        required = self._required_field_specs(normalization)

        best_event: dict[str, Any] | None = None
        best_missing: list[dict[str, Any]] | None = None

        for event in candidates:
            missing = []
            for field_spec in required:
                field = field_spec.get("field")
                value = get_path(event, field) if isinstance(field, str) else MISSING
                if value is MISSING or value in (None, ""):
                    missing.append(field_spec)

            if best_missing is None or len(missing) < len(best_missing):
                best_event = event
                best_missing = missing

            if not missing:
                break

        if best_missing:
            names = [
                str(item.get("field"))
                for item in best_missing
                if item.get("field")
            ]
            stages.append(
                {
                    "name": "Normalization",
                    "status": "FAIL",
                    "summary": "Missing required field(s): " + ", ".join(names),
                }
            )
            stages.append(
                {
                    "name": "Rule",
                    "status": "BLOCKED",
                    "summary": "Blocked by failed checkpoint: normalization.",
                }
            )

            diagnoses = [
                self._lineage_diagnosis(field_spec, best_event or {})
                for field_spec in best_missing
            ]
            diagnoses = [item for item in diagnoses if item]

            root = (
                diagnoses[0]
                if diagnoses
                else "Normalization/schema contract failed because required fields are missing."
            )

            return {
                "stages": stages,
                "root_cause": root,
                "confidence": "HIGH" if diagnoses else "MEDIUM",
                "healthy": False,
            }

        stages.append(
            {
                "name": "Normalization",
                "status": "PASS",
                "summary": "Live telemetry satisfies the required field contract.",
            }
        )

        rule_cfg = checkpoints.get("rule", {})
        rule = rule_cfg.get("match")
        if not rule:
            stages.append(
                {
                    "name": "Rule",
                    "status": "SKIPPED",
                    "summary": "No rule predicate declared in the DetectSpec.",
                }
            )
            return {
                "stages": stages,
                "root_cause": "Live telemetry contract passed; no rule predicate was declared.",
                "confidence": "HIGH",
                "healthy": True,
            }

        matched = any(evaluate(event, rule) for event in candidates)
        if matched:
            stages.append(
                {
                    "name": "Rule",
                    "status": "PASS",
                    "summary": "DetectSpec rule predicate matched live telemetry.",
                }
            )
            return {
                "stages": stages,
                "root_cause": (
                    "Live Elasticsearch telemetry satisfies the normalization "
                    "contract and rule predicate."
                ),
                "confidence": "HIGH",
                "healthy": True,
            }

        stages.append(
            {
                "name": "Rule",
                "status": "FAIL",
                "summary": "DetectSpec rule predicate did not match live telemetry.",
            }
        )
        return {
            "stages": stages,
            "root_cause": (
                "Required telemetry is present and normalized correctly, "
                "but the rule predicate did not match."
            ),
            "confidence": "HIGH",
            "healthy": False,
        }
