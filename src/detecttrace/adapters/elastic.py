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
from urllib.parse import quote, urlencode
from urllib.request import Request, urlopen

from ..diagnostics import finalize_result
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

                # Python 3.13+ enables OpenSSL's strict RFC 5280 checks in
                # create_default_context(). Some locally generated/private
                # CA certificates (including certain Elasticsearch lab CAs)
                # omit extensions required by strict mode. We disable only
                # VERIFY_X509_STRICT while retaining certificate validation,
                # hostname verification, and the configured CA trust anchor.
                strict_flag = getattr(ssl, "VERIFY_X509_STRICT", 0)
                if strict_flag:
                    context.verify_flags &= ~strict_flag
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

    def find_detection_rule(
        self,
        rule_name: str,
        kibana_url: str = "http://localhost:5602",
        username: str = "elastic",
        password: str | None = None,
    ) -> dict[str, Any]:
        """Find one Elastic Security detection rule by exact display name."""

        query = urlencode(
            {
                "page": 1,
                "per_page": 100,
            }
        )

        response = self._kibana_request(
            "GET",
            kibana_url,
            f"/api/detection_engine/rules/_find?{query}",
            username=username,
            password=password,
        )

        rules = response.get("data", [])
        if not isinstance(rules, list):
            rules = []

        exact = [
            rule
            for rule in rules
            if isinstance(rule, dict) and rule.get("name") == rule_name
        ]

        if not exact:
            return {
                "found": False,
                "ambiguous": False,
                "rule": None,
                "summary": f"Detection rule '{rule_name}' was not found.",
            }

        if len(exact) > 1:
            return {
                "found": False,
                "ambiguous": True,
                "rule": None,
                "summary": (
                    f"Found {len(exact)} detection rules named "
                    f"'{rule_name}'. Rule name is ambiguous."
                ),
            }

        candidate = exact[0]
        rule_id = candidate.get("id")

        if not rule_id:
            return {
                "found": True,
                "ambiguous": False,
                "rule": candidate,
                "summary": f"Found detection rule '{rule_name}'.",
            }

        detail_query = urlencode({"id": rule_id})
        try:
            detailed = self._kibana_request(
                "GET",
                kibana_url,
                f"/api/detection_engine/rules?{detail_query}",
                username=username,
                password=password,
            )
        except HTTPError:
            # The _find result still proves existence and enabled state.
            detailed = candidate

        return {
            "found": True,
            "ambiguous": False,
            "rule": detailed,
            "summary": f"Found detection rule '{rule_name}'.",
        }

    @staticmethod
    def classify_rule_execution(
        rule: dict[str, Any] | None,
        correlated_alert_found: bool = False,
    ) -> dict[str, Any]:
        """Interpret Elastic's latest rule execution evidence conservatively."""

        if correlated_alert_found:
            summary = (
                "A correlated Elastic Security alert proves the rule executed "
                "successfully for this test run."
            )

            last_execution = (
                (rule or {})
                .get("execution_summary", {})
                .get("last_execution", {})
            )
            status = last_execution.get("status")
            if status:
                summary += f" Latest reported execution status: {status}."

            return {
                "status": "PASS",
                "summary": summary,
                "message": last_execution.get("message"),
            }

        last_execution = (
            (rule or {})
            .get("execution_summary", {})
            .get("last_execution", {})
        )

        if not isinstance(last_execution, dict) or not last_execution:
            return {
                "status": "UNKNOWN",
                "summary": (
                    "Elastic did not expose a latest execution summary. "
                    "Rule execution health cannot be proven."
                ),
                "message": None,
            }

        raw_status = str(last_execution.get("status", "")).strip()
        normalized = raw_status.casefold()
        message = last_execution.get("message")

        if normalized == "succeeded":
            return {
                "status": "PASS",
                "summary": (
                    "Elastic reports the latest rule execution as succeeded."
                    + (f" {message}" if message else "")
                ),
                "message": message,
            }

        if "fail" in normalized or "error" in normalized:
            return {
                "status": "FAIL",
                "summary": (
                    f"Elastic reports rule execution status '{raw_status}'."
                    + (f" {message}" if message else "")
                ),
                "message": message,
            }

        return {
            "status": "UNKNOWN",
            "summary": (
                f"Elastic reports rule execution status '{raw_status or 'unknown'}'; "
                "DetectTrace will not guess whether that represents success."
                + (f" {message}" if message else "")
            ),
            "message": message,
        }

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
            return finalize_result(
                {
                    "healthy": False,
                    "run_id": None,
                    "case": case,
                    "indexing_ms": None,
                    "alert_latency_s": None,
                    "stages": [
                        {
                            "name": "Test event",
                            "status": "FAIL",
                            "summary": (
                                f"Could not inject correlated test event: {exc}"
                            ),
                        }
                    ],
                    "root_cause": (
                        "The correlated test event could not be ingested."
                    ),
                    "confidence": "HIGH",
                    "alert": None,
                },
                failure_code="INGESTION_FAILURE",
                remediation=(
                    "Restore Elasticsearch connectivity, authentication, "
                    "and write access before rerunning the test."
                ),
            )

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
            stages.extend(
                [
                    {
                        "name": "Elastic rule exists",
                        "status": "BLOCKED",
                        "summary": "Blocked by an upstream DetectSpec failure.",
                    },
                    {
                        "name": "Elastic rule enabled",
                        "status": "BLOCKED",
                        "summary": "Blocked by an upstream DetectSpec failure.",
                    },
                    {
                        "name": "Rule execution",
                        "status": "BLOCKED",
                        "summary": "Blocked by an upstream DetectSpec failure.",
                    },
                    {
                        "name": "Elastic alert",
                        "status": "BLOCKED",
                        "summary": (
                            "Blocked because the correlated telemetry failed an "
                            "upstream DetectSpec checkpoint."
                        ),
                    },
                ]
            )
            return finalize_result(
                {
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
                },
                failure_code=trace.get("failure_code", "UNKNOWN"),
                remediation=trace.get("remediation"),
            )

        try:
            lookup = self.find_detection_rule(
                rule_name=rule_name,
                kibana_url=kibana_url,
                username=kibana_username,
                password=kibana_password,
            )
        except ValueError as exc:
            lookup = {
                "found": False,
                "ambiguous": False,
                "rule": None,
                "summary": str(exc),
            }
        except HTTPError as exc:
            lookup = {
                "found": False,
                "ambiguous": False,
                "rule": None,
                "summary": f"Elastic rule lookup failed: HTTP {exc.code}.",
            }
        except (URLError, TimeoutError, OSError) as exc:
            lookup = {
                "found": False,
                "ambiguous": False,
                "rule": None,
                "summary": f"Elastic rule lookup failed: {exc}",
            }

        if not lookup.get("found"):
            stages.extend(
                [
                    {
                        "name": "Elastic rule exists",
                        "status": "FAIL",
                        "summary": lookup.get(
                            "summary",
                            f"Detection rule '{rule_name}' was not found.",
                        ),
                    },
                    {
                        "name": "Elastic rule enabled",
                        "status": "BLOCKED",
                        "summary": "Blocked because the detection rule was not found.",
                    },
                    {
                        "name": "Rule execution",
                        "status": "BLOCKED",
                        "summary": "Blocked because the detection rule was not found.",
                    },
                    {
                        "name": "Elastic alert",
                        "status": "BLOCKED",
                        "summary": "Blocked because the detection rule was not found.",
                    },
                ]
            )
            return finalize_result(
                {
                    "healthy": False,
                    "run_id": run_id,
                    "case": case,
                    "indexing_ms": injected["indexing_ms"],
                    "alert_latency_s": None,
                    "stages": stages,
                    "root_cause": lookup.get(
                        "summary",
                        f"Elastic detection rule '{rule_name}' was not found.",
                    ),
                    "confidence": "HIGH",
                    "alert": None,
                },
                failure_code="RULE_NOT_FOUND",
                remediation=(
                    "Create the expected Elastic detection rule or correct "
                    "the configured rule name."
                ),
            )

        rule = lookup.get("rule") or {}
        stages.append(
            {
                "name": "Elastic rule exists",
                "status": "PASS",
                "summary": lookup.get("summary", f"Found rule '{rule_name}'."),
            }
        )

        enabled = rule.get("enabled")
        if enabled is not True:
            stages.extend(
                [
                    {
                        "name": "Elastic rule enabled",
                        "status": "FAIL",
                        "summary": (
                            f"Detection rule '{rule_name}' is disabled."
                            if enabled is False
                            else (
                                f"Could not prove that detection rule "
                                f"'{rule_name}' is enabled."
                            )
                        ),
                    },
                    {
                        "name": "Rule execution",
                        "status": "BLOCKED",
                        "summary": "Blocked because the detection rule is not enabled.",
                    },
                    {
                        "name": "Elastic alert",
                        "status": "BLOCKED",
                        "summary": "Blocked because the detection rule is not enabled.",
                    },
                ]
            )
            return finalize_result(
                {
                    "healthy": False,
                    "run_id": run_id,
                    "case": case,
                    "indexing_ms": injected["indexing_ms"],
                    "alert_latency_s": None,
                    "stages": stages,
                    "root_cause": (
                        f"Elastic detection rule '{rule_name}' is disabled. "
                        "Enable the rule before running the detection test."
                        if enabled is False
                        else (
                            f"DetectTrace could not prove that Elastic "
                            f"detection rule '{rule_name}' is enabled."
                        )
                    ),
                    "confidence": "HIGH" if enabled is False else "MEDIUM",
                    "alert": None,
                },
                failure_code=(
                    "RULE_DISABLED" if enabled is False else "UNKNOWN"
                ),
                remediation=(
                    f"Enable Elastic detection rule '{rule_name}'."
                    if enabled is False
                    else (
                        "Inspect the Elastic rule object and permissions so "
                        "DetectTrace can determine the enabled state."
                    )
                ),
            )

        stages.append(
            {
                "name": "Elastic rule enabled",
                "status": "PASS",
                "summary": f"Detection rule '{rule_name}' is enabled.",
            }
        )

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

        # Re-read the rule after the run so execution evidence reflects the
        # most recent state available from Elastic.
        try:
            refreshed = self.find_detection_rule(
                rule_name=rule_name,
                kibana_url=kibana_url,
                username=kibana_username,
                password=kibana_password,
            )
            if refreshed.get("found"):
                rule = refreshed.get("rule") or rule
        except Exception:
            # The original existence/enabled evidence remains valid. If the
            # refresh fails, classify execution conservatively below.
            pass

        execution = self.classify_rule_execution(
            rule=rule,
            correlated_alert_found=bool(
                alert_result and alert_result.get("healthy")
            ),
        )

        if not alert_result or not alert_result.get("healthy"):
            if execution["status"] == "FAIL":
                stages.extend(
                    [
                        {
                            "name": "Rule execution",
                            "status": "FAIL",
                            "summary": execution["summary"],
                        },
                        {
                            "name": "Elastic alert",
                            "status": "BLOCKED",
                            "summary": (
                                "Blocked because Elastic reported a rule "
                                "execution failure."
                            ),
                        },
                    ]
                )
                return finalize_result(
                    {
                        "healthy": False,
                        "run_id": run_id,
                        "case": case,
                        "indexing_ms": injected["indexing_ms"],
                        "alert_latency_s": None,
                        "stages": stages,
                        "root_cause": (
                            "Elastic reports that the detection rule failed "
                            "during execution. "
                            + (
                                f"Execution message: {execution['message']}"
                                if execution.get("message")
                                else (
                                    "Review the rule execution details "
                                    "in Kibana."
                                )
                            )
                        ),
                        "confidence": "HIGH",
                        "alert": None,
                    },
                    failure_code="RULE_EXECUTION_ERROR",
                    remediation=(
                        "Fix the Elastic rule execution error shown in the "
                        "rule execution details, then rerun DetectTrace."
                    ),
                )

            stages.append(
                {
                    "name": "Rule execution",
                    "status": execution["status"],
                    "summary": execution["summary"],
                }
            )
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
            return finalize_result(
                {
                    "healthy": False,
                    "run_id": run_id,
                    "case": case,
                    "indexing_ms": injected["indexing_ms"],
                    "alert_latency_s": None,
                    "stages": stages,
                    "root_cause": (
                        "Telemetry and DetectSpec rule checks passed and the "
                        "Elastic rule is enabled, but no alert correlated to "
                        "this specific test run was observed within the "
                        "allowed window."
                    ),
                    "confidence": "HIGH",
                    "alert": None,
                },
                failure_code="ALERT_TIMEOUT",
                remediation=(
                    "Inspect the Elastic rule schedule, look-back window, "
                    "suppression settings, and alert-generation path."
                ),
            )

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
                "name": "Rule execution",
                "status": execution["status"],
                "summary": execution["summary"],
            }
        )
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

        return finalize_result(
            {
                "healthy": True,
                "run_id": run_id,
                "case": case,
                "indexing_ms": injected["indexing_ms"],
                "alert_latency_s": latency,
                "stages": stages,
                "root_cause": (
                    "Detection passed end-to-end with exact test-run "
                    "correlation: the injected telemetry, DetectSpec "
                    "evaluation, Elastic rule state, and Elastic Security "
                    "alert all belong to the expected detection path."
                ),
                "confidence": "HIGH",
                "alert": alert,
            }
        )

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
            return finalize_result(
                {
                    "stages": stages,
                    "root_cause": "Elasticsearch is unavailable.",
                    "confidence": "HIGH",
                    "healthy": False,
                },
                failure_code="INGESTION_FAILURE",
                remediation=(
                    "Restore Elasticsearch connectivity and authentication "
                    "before rerunning the detection test."
                ),
            )

        index_check = self.check_index(index)
        stages.append(
            {
                "name": "Telemetry index",
                "status": "PASS" if index_check[0] else "FAIL",
                "summary": index_check[1],
            }
        )
        if not index_check[0]:
            return finalize_result(
                {
                    "stages": stages,
                    "root_cause": "The configured telemetry index is unavailable.",
                    "confidence": "HIGH",
                    "healthy": False,
                },
                failure_code="INGESTION_FAILURE",
                remediation=(
                    "Verify the telemetry index name and confirm that the "
                    "ingestion pipeline creates the expected index."
                ),
            )

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
            return finalize_result(
                {
                    "stages": stages,
                    "root_cause": "No telemetry was available for evaluation.",
                    "confidence": "HIGH",
                    "healthy": False,
                },
                failure_code="TELEMETRY_MISSING",
                remediation=(
                    "Verify that the test generated telemetry and that the "
                    "event reached the configured Elasticsearch index."
                ),
            )

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
            return finalize_result(
                {
                    "stages": stages,
                    "root_cause": (
                        "Live telemetry was found, but none matched the "
                        "normalization selector declared by the DetectSpec."
                    ),
                    "confidence": "HIGH",
                    "healthy": False,
                },
                failure_code="REQUIRED_FIELD_MISSING",
                remediation=(
                    "Compare the live event shape with the DetectSpec "
                    "normalization selector and correct the field contract "
                    "or upstream mapping."
                ),
            )

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

            return finalize_result(
                {
                    "stages": stages,
                    "root_cause": root,
                    "confidence": "HIGH" if diagnoses else "MEDIUM",
                    "healthy": False,
                },
                failure_code=(
                    "SCHEMA_DRIFT"
                    if diagnoses
                    else "REQUIRED_FIELD_MISSING"
                ),
                remediation=(
                    "Correct the normalization or field mapping before "
                    "rule evaluation."
                    if diagnoses
                    else (
                        "Restore the required field or update the DetectSpec "
                        "only if the schema change is intentional."
                    )
                ),
            )

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
            return finalize_result(
                {
                    "stages": stages,
                    "root_cause": (
                        "Live telemetry contract passed; no rule predicate "
                        "was declared."
                    ),
                    "confidence": "HIGH",
                    "healthy": True,
                }
            )

        matched = any(evaluate(event, rule) for event in candidates)
        if matched:
            stages.append(
                {
                    "name": "Rule",
                    "status": "PASS",
                    "summary": "DetectSpec rule predicate matched live telemetry.",
                }
            )
            return finalize_result(
                {
                    "stages": stages,
                    "root_cause": (
                        "Live Elasticsearch telemetry satisfies the "
                        "normalization contract and rule predicate."
                    ),
                    "confidence": "HIGH",
                    "healthy": True,
                }
            )

        stages.append(
            {
                "name": "Rule",
                "status": "FAIL",
                "summary": "DetectSpec rule predicate did not match live telemetry.",
            }
        )
        return finalize_result(
            {
                "stages": stages,
                "root_cause": (
                    "Required telemetry is present and normalized correctly, "
                    "but the rule predicate did not match."
                ),
                "confidence": "HIGH",
                "healthy": False,
            },
            failure_code="RULE_LOGIC_MISMATCH",
            remediation=(
                "Review the DetectSpec rule predicate and the backend "
                "detection logic against the observed telemetry."
            ),
        )
