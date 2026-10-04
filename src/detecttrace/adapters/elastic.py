from __future__ import annotations

import base64
import copy
from datetime import datetime, timezone
import json
import os
import ssl
import time
from typing import Any
import uuid
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import Request, urlopen

from ..rules import evaluate
from ..util import MISSING, flatten_leaves, get_path


class ElasticAdapter:
    """Elasticsearch adapter for DetectTrace."""

    def __init__(
        self,
        base_url: str | None = None,
        username: str | None = None,
        password: str | None = None,
        verify_tls: bool = True,
        ca_cert: str | None = None,
    ) -> None:
        self.base_url = (
            base_url
            or os.getenv("DETECTTRACE_ELASTIC_URL")
            or "http://localhost:9200"
        ).rstrip("/")
        self.username = (
            username
            or os.getenv("DETECTTRACE_ELASTIC_USERNAME")
            or "elastic"
        )
        self.password = password or os.getenv("DETECTTRACE_ELASTIC_PASSWORD")
        self.verify_tls = verify_tls
        self.ca_cert = ca_cert or os.getenv("DETECTTRACE_ELASTIC_CA_CERT")

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

        if self.password:
            token = base64.b64encode(
                f"{self.username}:{self.password}".encode("utf-8")
            ).decode("ascii")
            headers["Authorization"] = f"Basic {token}"

        request = Request(
            f"{self.base_url}{path}",
            data=data,
            headers=headers,
            method=method,
        )

        context = None
        if self.base_url.startswith("https://"):
            if self.ca_cert:
                context = ssl.create_default_context(cafile=self.ca_cert)
            elif not self.verify_tls:
                context = ssl._create_unverified_context()

        with urlopen(request, timeout=10, context=context) as response:
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

    def _kibana_request(
        self,
        method: str,
        kibana_url: str,
        path: str,
        body: dict[str, Any] | None = None,
        username: str = "elastic",
        password: str | None = None,
    ) -> dict[str, Any]:
        if password is None:
            password = os.getenv("DETECTTRACE_ELASTIC_PASSWORD")
        if not password:
            raise ValueError(
                "No Elastic password supplied. Set DETECTTRACE_ELASTIC_PASSWORD."
            )

        token = base64.b64encode(
            f"{username}:{password}".encode("utf-8")
        ).decode("ascii")

        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "kbn-xsrf": "true",
            "Authorization": f"Basic {token}",
        }
        data = json.dumps(body).encode("utf-8") if body is not None else None

        request = Request(
            f"{kibana_url.rstrip('/')}{path}",
            data=data,
            headers=headers,
            method=method,
        )
        with urlopen(request, timeout=10) as response:
            payload = response.read().decode("utf-8")
            return json.loads(payload) if payload else {}

    def ingest_correlated_test_event(
        self,
        spec: dict[str, Any],
        index: str,
        case: str = "healthy",
    ) -> dict[str, Any]:
        test_cfg = spec.get("test", {})
        cases = test_cfg.get("cases", {})

        if not isinstance(cases, dict) or case not in cases:
            available = ", ".join(sorted(cases)) if isinstance(cases, dict) else ""
            raise ValueError(
                f"DetectSpec test case '{case}' not found."
                + (f" Available: {available}" if available else "")
            )

        case_cfg = cases[case]
        if not isinstance(case_cfg, dict) or not isinstance(case_cfg.get("event"), dict):
            raise ValueError(f"DetectSpec test case '{case}' must contain an event object.")

        event = copy.deepcopy(case_cfg["event"])
        run_id = "dt-" + uuid.uuid4().hex[:16]
        sent_at = datetime.now(timezone.utc)

        event["@timestamp"] = sent_at.isoformat().replace("+00:00", "Z")

        event_obj = event.setdefault("event", {})
        if not isinstance(event_obj, dict):
            event_obj = {}
            event["event"] = event_obj
        event_obj["id"] = run_id

        detecttrace_obj = event.setdefault("detecttrace", {})
        if not isinstance(detecttrace_obj, dict):
            detecttrace_obj = {}
            event["detecttrace"] = detecttrace_obj
        detecttrace_obj["run_id"] = run_id
        detecttrace_obj["case"] = case
        detecttrace_obj["sent_at"] = event["@timestamp"]

        started = time.perf_counter()
        response = self._request(
            "POST",
            f"/{quote(index)}/_doc?refresh=true",
            event,
        )
        indexing_ms = (time.perf_counter() - started) * 1000.0

        if response.get("result") not in {"created", "updated"}:
            raise ValueError(
                "Elasticsearch did not confirm test event ingestion: "
                f"{response.get('result', 'unknown')}"
            )

        return {
            "run_id": run_id,
            "sent_at": sent_at,
            "indexing_ms": indexing_ms,
            "event": event,
            "document_id": response.get("_id"),
        }

    def events_for_run_id(
        self,
        index: str,
        run_id: str,
        size: int = 10,
    ) -> list[dict[str, Any]]:
        hits = self.search(
            index=index,
            size=size,
            query={
                "bool": {
                    "should": [
                        {"match_phrase": {"detecttrace.run_id": run_id}},
                        {"match_phrase": {"event.id": run_id}},
                    ],
                    "minimum_should_match": 1,
                }
            },
        )
        return [
            hit.get("_source", {})
            for hit in hits
            if isinstance(hit.get("_source"), dict)
        ]

    def find_alerts(
        self,
        rule_name: str,
        kibana_url: str = "http://localhost:5602",
        username: str = "elastic",
        password: str | None = None,
        size: int = 5,
        run_id: str | None = None,
    ) -> list[dict[str, Any]]:
        must: list[dict[str, Any]] = [
            {
                "match_phrase": {
                    "kibana.alert.rule.name": rule_name
                }
            }
        ]

        if run_id:
            must.append(
                {
                    "bool": {
                        "should": [
                            {"match_phrase": {"detecttrace.run_id": run_id}},
                            {"match_phrase": {"event.id": run_id}},
                            {
                                "match_phrase": {
                                    "kibana.alert.original_event.id": run_id
                                }
                            },
                        ],
                        "minimum_should_match": 1,
                    }
                }
            )

        response = self._kibana_request(
            "POST",
            kibana_url,
            "/api/detection_engine/signals/search",
            body={
                "size": size,
                "query": {
                    "bool": {
                        "must": must
                    }
                },
                "sort": [
                    {
                        "@timestamp": {
                            "order": "desc"
                        }
                    }
                ],
            },
            username=username,
            password=password,
        )
        return response.get("hits", {}).get("hits", [])

    def verify_alert(
        self,
        rule_name: str,
        kibana_url: str = "http://localhost:5602",
        username: str = "elastic",
        password: str | None = None,
        run_id: str | None = None,
    ) -> dict[str, Any]:
        try:
            hits = self.find_alerts(
                rule_name=rule_name,
                kibana_url=kibana_url,
                username=username,
                password=password,
                run_id=run_id,
            )
        except ValueError as exc:
            return {"healthy": False, "status": "FAIL", "summary": str(exc), "alert": None}
        except HTTPError as exc:
            return {
                "healthy": False,
                "status": "FAIL",
                "summary": f"Kibana alert query failed: HTTP {exc.code}.",
                "alert": None,
            }
        except (URLError, TimeoutError, OSError) as exc:
            return {
                "healthy": False,
                "status": "FAIL",
                "summary": f"Kibana alert query failed: {exc}",
                "alert": None,
            }

        if not hits:
            return {
                "healthy": False,
                "status": "FAIL",
                "summary": (
                    f"No alert found for rule '{rule_name}'"
                    + (f" and run_id '{run_id}'." if run_id else ".")
                ),
                "alert": None,
            }

        source = hits[0].get("_source", {})
        if not isinstance(source, dict):
            source = {}

        return {
            "healthy": True,
            "status": "PASS",
            "summary": (
                f"Found {len(hits)} alert(s) for rule '{rule_name}'"
                + (f" with matching run_id '{run_id}'." if run_id else ".")
            ),
            "alert": {
                "id": hits[0].get("_id"),
                "timestamp": source.get("@timestamp", "unknown"),
                "rule_name": source.get("kibana.alert.rule.name", rule_name),
                "status": (
                    source.get("kibana.alert.workflow_status")
                    or source.get("kibana.alert.status")
                    or "unknown"
                ),
                "severity": source.get("kibana.alert.severity", "unknown"),
                "risk_score": source.get("kibana.alert.risk_score"),
                "run_id": (
                    get_path(source, "detecttrace.run_id")
                    if get_path(source, "detecttrace.run_id") is not MISSING
                    else (
                        get_path(source, "event.id")
                        if get_path(source, "event.id") is not MISSING
                        else None
                    )
                ),
            },
        }

    def correlated_test(
        self,
        spec: dict[str, Any],
        index: str,
        rule_name: str,
        kibana_url: str,
        case: str = "healthy",
        kibana_username: str = "elastic",
        kibana_password: str | None = None,
        limit: int = 10,
        alert_timeout: float = 90.0,
        poll_interval: float = 5.0,
    ) -> dict[str, Any]:
        try:
            injected = self.ingest_correlated_test_event(
                spec=spec,
                index=index,
                case=case,
            )
        except (ValueError, HTTPError, URLError, TimeoutError, OSError) as exc:
            return {
                "healthy": False,
                "run_id": None,
                "case": case,
                "indexing_ms": None,
                "alert_latency_s": None,
                "stages": [
                    {
                        "name": "Test event",
                        "status": "FAIL",
                        "summary": f"Could not inject correlated test event: {exc}",
                    }
                ],
                "root_cause": "The correlated test event could not be ingested.",
                "confidence": "HIGH",
                "alert": None,
            }

        run_id = injected["run_id"]
        stages: list[dict[str, str]] = [
            {
                "name": "Test event",
                "status": "PASS",
                "summary": (
                    f"Injected case '{case}' with run_id '{run_id}' "
                    f"in {injected['indexing_ms']:.1f} ms."
                ),
            }
        ]

        trace = self.trace_spec(
            spec=spec,
            index=index,
            limit=limit,
            run_id=run_id,
        )
        stages.extend(trace.get("stages", []))

        if not trace.get("healthy", False):
            stages.append(
                {
                    "name": "Elastic alert",
                    "status": "BLOCKED",
                    "summary": (
                        "Blocked because the correlated telemetry failed an "
                        "upstream DetectSpec checkpoint."
                    ),
                }
            )
            return {
                "healthy": False,
                "run_id": run_id,
                "case": case,
                "indexing_ms": injected["indexing_ms"],
                "alert_latency_s": None,
                "stages": stages,
                "root_cause": trace.get(
                    "root_cause",
                    "Upstream detection validation failed.",
                ),
                "confidence": trace.get("confidence", "MEDIUM"),
                "alert": None,
            }

        deadline = time.monotonic() + alert_timeout
        alert_result: dict[str, Any] | None = None

        while True:
            alert_result = self.verify_alert(
                rule_name=rule_name,
                kibana_url=kibana_url,
                username=kibana_username,
                password=kibana_password,
                run_id=run_id,
            )

            if alert_result.get("healthy"):
                break

            if time.monotonic() >= deadline:
                break

            time.sleep(max(0.2, poll_interval))

        if not alert_result or not alert_result.get("healthy"):
            stages.append(
                {
                    "name": "Elastic alert",
                    "status": "FAIL",
                    "summary": (
                        f"No alert correlated to run_id '{run_id}' was "
                        f"observed within {alert_timeout:.0f}s."
                    ),
                }
            )
            return {
                "healthy": False,
                "run_id": run_id,
                "case": case,
                "indexing_ms": injected["indexing_ms"],
                "alert_latency_s": None,
                "stages": stages,
                "root_cause": (
                    "Telemetry and DetectSpec rule checks passed, but Elastic "
                    "Security did not produce an alert correlated to this "
                    "specific test run within the allowed window."
                ),
                "confidence": "HIGH",
                "alert": None,
            }

        alert = alert_result.get("alert")
        latency = None
        if alert and isinstance(alert.get("timestamp"), str):
            try:
                alert_time = datetime.fromisoformat(
                    alert["timestamp"].replace("Z", "+00:00")
                )
                latency = max(
                    0.0,
                    (alert_time - injected["sent_at"]).total_seconds(),
                )
            except ValueError:
                latency = None

        stages.append(
            {
                "name": "Elastic alert",
                "status": "PASS",
                "summary": (
                    f"Alert matched the same run_id '{run_id}'."
                    + (
                        f" Approximate alert latency: {latency:.2f}s."
                        if latency is not None
                        else ""
                    )
                ),
            }
        )

        return {
            "healthy": True,
            "run_id": run_id,
            "case": case,
            "indexing_ms": injected["indexing_ms"],
            "alert_latency_s": latency,
            "stages": stages,
            "root_cause": (
                "Detection passed end-to-end with exact test-run correlation: "
                "the injected telemetry, DetectSpec evaluation, and Elastic "
                "Security alert all belong to the same run_id."
            ),
            "confidence": "HIGH",
            "alert": alert,
        }

    def end_to_end_test(
        self,
        spec: dict[str, Any],
        index: str,
        rule_name: str,
        kibana_url: str,
        kibana_username: str = "elastic",
        kibana_password: str | None = None,
        limit: int = 10,
    ) -> dict[str, Any]:
        trace = self.trace_spec(
            spec=spec,
            index=index,
            limit=limit,
        )

        stages = list(trace.get("stages", []))

        if not trace.get("healthy", False):
            stages.append(
                {
                    "name": "Elastic alert",
                    "status": "BLOCKED",
                    "summary": "Blocked by an upstream failed checkpoint.",
                }
            )
            return {
                "healthy": False,
                "stages": stages,
                "root_cause": trace.get(
                    "root_cause",
                    "Upstream detection validation failed.",
                ),
                "confidence": trace.get("confidence", "MEDIUM"),
                "alert": None,
            }

        alert_result = self.verify_alert(
            rule_name=rule_name,
            kibana_url=kibana_url,
            username=kibana_username,
            password=kibana_password,
        )

        stages.append(
            {
                "name": "Elastic alert",
                "status": "PASS" if alert_result["healthy"] else "FAIL",
                "summary": alert_result["summary"],
            }
        )

        if not alert_result["healthy"]:
            return {
                "healthy": False,
                "stages": stages,
                "root_cause": (
                    "Telemetry and DetectSpec rule checks passed, but no "
                    "corresponding Elastic Security alert was observed."
                ),
                "confidence": "HIGH",
                "alert": None,
            }

        return {
            "healthy": True,
            "stages": stages,
            "root_cause": (
                "Detection passed end-to-end: live telemetry satisfied the "
                "DetectSpec and Elastic Security generated the expected alert."
            ),
            "confidence": "HIGH",
            "alert": alert_result.get("alert"),
        }

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
        run_id: str | None = None,
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

        events = (
            self.events_for_run_id(index=index, run_id=run_id, size=limit)
            if run_id
            else self.latest_events(index=index, size=limit)
        )
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
                "summary": (
                    f"Loaded {len(events)} document(s)"
                    + (f" matching run_id '{run_id}'." if run_id else ".")
                ),
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
