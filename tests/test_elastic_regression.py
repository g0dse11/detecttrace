from __future__ import annotations

from datetime import datetime, timedelta, timezone
import unittest
from unittest.mock import patch

from detecttrace.adapters.elastic import ElasticAdapter


RULE_NAME = "DetectTrace - Encoded PowerShell"
RUN_ID = "dt-regression0001"
INDEX = "detecttrace-events"
KIBANA_URL = "http://localhost:5602"

SENT_AT = datetime(2026, 10, 5, 12, 0, 0, tzinfo=timezone.utc)

HEALTHY_EVENT = {
    "@timestamp": "2026-10-05T12:00:00Z",
    "event": {
        "code": 1,
        "id": RUN_ID,
    },
    "detecttrace": {
        "run_id": RUN_ID,
        "case": "healthy",
    },
    "process": {
        "name": "powershell.exe",
        "command_line": "powershell.exe -enc AAA",
    },
}

SCHEMA_DRIFT_EVENT = {
    "@timestamp": "2026-10-05T12:00:00Z",
    "event": {
        "code": 1,
        "id": RUN_ID,
    },
    "detecttrace": {
        "run_id": RUN_ID,
        "case": "broken",
    },
    "winlog": {
        "event_data": {
            "CommandLine": "powershell.exe -enc AAA",
        }
    },
    "process": {
        "name": "powershell.exe",
        "args": "powershell.exe -enc AAA",
    },
}

RULE_MISMATCH_EVENT = {
    "@timestamp": "2026-10-05T12:00:00Z",
    "event": {
        "code": 1,
        "id": RUN_ID,
    },
    "detecttrace": {
        "run_id": RUN_ID,
        "case": "healthy",
    },
    "process": {
        "name": "powershell.exe",
        "command_line": "powershell.exe -nop",
    },
}

SPEC = {
    "spec_version": "detectspec/v1",
    "id": "DET-PS-LIVE-001",
    "title": "Live Encoded PowerShell",
    "test": {
        "cases": {
            "healthy": {
                "event": HEALTHY_EVENT,
            },
            "broken": {
                "event": SCHEMA_DRIFT_EVENT,
            },
        }
    },
    "checkpoints": {
        "normalization": {
            "require_event": {
                "all": [
                    {
                        "field": "process.name",
                        "op": "endswith",
                        "value": "powershell.exe",
                    }
                ]
            },
            "required_fields": [
                {
                    "field": "process.command_line",
                    "from": "winlog.event_data.CommandLine",
                }
            ],
        },
        "rule": {
            "match": {
                "all": [
                    {
                        "field": "process.name",
                        "op": "endswith",
                        "value": "powershell.exe",
                    },
                    {
                        "field": "process.command_line",
                        "op": "regex",
                        "value": r"(?i)(?:\s|^)-(?:enc|encodedcommand)\b",
                    },
                ]
            }
        },
    },
}


def enabled_rule() -> dict:
    return {
        "found": True,
        "ambiguous": False,
        "summary": f"Found detection rule '{RULE_NAME}'.",
        "rule": {
            "id": "rule-regression-001",
            "name": RULE_NAME,
            "enabled": True,
            "execution_summary": {
                "last_execution": {
                    "status": "succeeded",
                    "message": "Rule executed successfully.",
                }
            },
        },
    }


def disabled_rule() -> dict:
    return {
        "found": True,
        "ambiguous": False,
        "summary": f"Found detection rule '{RULE_NAME}'.",
        "rule": {
            "id": "rule-regression-001",
            "name": RULE_NAME,
            "enabled": False,
            "execution_summary": {
                "last_execution": {
                    "status": "succeeded",
                    "message": "Previous execution succeeded.",
                }
            },
        },
    }


def correlated_alert() -> dict:
    alert_time = SENT_AT + timedelta(seconds=8)
    return {
        "healthy": True,
        "status": "PASS",
        "summary": (
            f"Found 1 alert for rule '{RULE_NAME}' "
            f"with matching run_id '{RUN_ID}'."
        ),
        "alert": {
            "id": "alert-regression-001",
            "timestamp": alert_time.isoformat().replace("+00:00", "Z"),
            "rule_name": RULE_NAME,
            "status": "open",
            "severity": "medium",
            "risk_score": 50,
            "run_id": RUN_ID,
        },
    }


def no_alert() -> dict:
    return {
        "healthy": False,
        "status": "FAIL",
        "summary": (
            f"No alert found for rule '{RULE_NAME}' "
            f"and run_id '{RUN_ID}'."
        ),
        "alert": None,
    }


class ElasticRegressionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.adapter = ElasticAdapter(
            base_url="http://example.invalid",
            username="elastic",
            password="test-only-password",
        )

    def _run_with_event(
        self,
        event: dict,
        *,
        rule_lookup: dict | None = None,
        alert_result: dict | None = None,
        case: str = "healthy",
        timeout: float = 0.0,
    ) -> dict:
        injection = {
            "run_id": RUN_ID,
            "sent_at": SENT_AT,
            "indexing_ms": 10.0,
            "event": event,
            "document_id": "doc-regression-001",
        }

        with (
            patch.object(
                self.adapter,
                "ingest_correlated_test_event",
                return_value=injection,
            ),
            patch.object(
                self.adapter,
                "check_connection",
                return_value=(
                    True,
                    "Connected to Elasticsearch test cluster.",
                ),
            ),
            patch.object(
                self.adapter,
                "check_index",
                return_value=(
                    True,
                    f"Index '{INDEX}' contains 1 document(s).",
                ),
            ),
            patch.object(
                self.adapter,
                "events_for_run_id",
                return_value=[event],
            ),
            patch.object(
                self.adapter,
                "find_detection_rule",
                return_value=rule_lookup or enabled_rule(),
            ),
            patch.object(
                self.adapter,
                "verify_alert",
                return_value=alert_result or correlated_alert(),
            ),
        ):
            return self.adapter.correlated_test(
                spec=SPEC,
                index=INDEX,
                rule_name=RULE_NAME,
                kibana_url=KIBANA_URL,
                case=case,
                kibana_username="elastic",
                kibana_password="test-only-password",
                alert_timeout=timeout,
                poll_interval=0.0,
            )

    @staticmethod
    def _stage_status(result: dict, name: str) -> str:
        for stage in result["stages"]:
            if stage["name"] == name:
                return stage["status"]
        raise AssertionError(f"Stage '{name}' was not present in result.")

    def test_healthy_end_to_end(self) -> None:
        result = self._run_with_event(
            HEALTHY_EVENT,
            rule_lookup=enabled_rule(),
            alert_result=correlated_alert(),
        )

        self.assertTrue(result["healthy"])
        self.assertIsNone(result["first_failed_stage"])
        self.assertIsNone(result["failure_code"])

        self.assertEqual(
            self._stage_status(result, "Normalization"),
            "PASS",
        )
        self.assertEqual(
            self._stage_status(result, "Rule"),
            "PASS",
        )
        self.assertEqual(
            self._stage_status(result, "Elastic rule exists"),
            "PASS",
        )
        self.assertEqual(
            self._stage_status(result, "Elastic rule enabled"),
            "PASS",
        )
        self.assertEqual(
            self._stage_status(result, "Rule execution"),
            "PASS",
        )
        self.assertEqual(
            self._stage_status(result, "Elastic alert"),
            "PASS",
        )

    def test_schema_drift_is_first_failure(self) -> None:
        result = self._run_with_event(
            SCHEMA_DRIFT_EVENT,
            case="broken",
        )

        self.assertFalse(result["healthy"])
        self.assertEqual(
            result["first_failed_stage"],
            "NORMALIZATION",
        )
        self.assertEqual(
            result["failure_code"],
            "SCHEMA_DRIFT",
        )

        self.assertEqual(
            self._stage_status(result, "Normalization"),
            "FAIL",
        )
        self.assertEqual(
            self._stage_status(result, "Rule"),
            "BLOCKED",
        )
        self.assertEqual(
            self._stage_status(result, "Elastic rule exists"),
            "BLOCKED",
        )
        self.assertIn(
            "Probable schema/mapping drift",
            result["root_cause"],
        )

    def test_disabled_rule_is_first_failure(self) -> None:
        result = self._run_with_event(
            HEALTHY_EVENT,
            rule_lookup=disabled_rule(),
        )

        self.assertFalse(result["healthy"])
        self.assertEqual(
            result["first_failed_stage"],
            "RULE_EVALUATION",
        )
        self.assertEqual(
            result["failure_code"],
            "RULE_DISABLED",
        )

        self.assertEqual(
            self._stage_status(result, "Elastic rule exists"),
            "PASS",
        )
        self.assertEqual(
            self._stage_status(result, "Elastic rule enabled"),
            "FAIL",
        )
        self.assertEqual(
            self._stage_status(result, "Rule execution"),
            "BLOCKED",
        )
        self.assertEqual(
            self._stage_status(result, "Elastic alert"),
            "BLOCKED",
        )

    def test_rule_logic_mismatch_is_first_failure(self) -> None:
        result = self._run_with_event(
            RULE_MISMATCH_EVENT,
        )

        self.assertFalse(result["healthy"])
        self.assertEqual(
            result["first_failed_stage"],
            "RULE_EVALUATION",
        )
        self.assertEqual(
            result["failure_code"],
            "RULE_LOGIC_MISMATCH",
        )

        self.assertEqual(
            self._stage_status(result, "Normalization"),
            "PASS",
        )
        self.assertEqual(
            self._stage_status(result, "Rule"),
            "FAIL",
        )
        self.assertEqual(
            self._stage_status(result, "Elastic rule exists"),
            "BLOCKED",
        )

    def test_alert_timeout_is_first_failure(self) -> None:
        result = self._run_with_event(
            HEALTHY_EVENT,
            rule_lookup=enabled_rule(),
            alert_result=no_alert(),
            timeout=0.0,
        )

        self.assertFalse(result["healthy"])
        self.assertEqual(
            result["first_failed_stage"],
            "ALERT_GENERATION",
        )
        self.assertEqual(
            result["failure_code"],
            "ALERT_TIMEOUT",
        )

        self.assertEqual(
            self._stage_status(result, "Normalization"),
            "PASS",
        )
        self.assertEqual(
            self._stage_status(result, "Rule"),
            "PASS",
        )
        self.assertEqual(
            self._stage_status(result, "Elastic rule enabled"),
            "PASS",
        )
        self.assertEqual(
            self._stage_status(result, "Rule execution"),
            "PASS",
        )
        self.assertEqual(
            self._stage_status(result, "Elastic alert"),
            "FAIL",
        )


if __name__ == "__main__":
    unittest.main()
