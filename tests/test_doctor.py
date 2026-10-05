from __future__ import annotations

import unittest
from unittest.mock import patch

from detecttrace.doctor import run_doctor


SETTINGS = {
    "url": "https://localhost:9201",
    "kibana_url": "http://localhost:5602",
    "username": "elastic",
    "index": "detecttrace-events",
    "ca_cert": "C:/detecttrace/certs/http_ca.crt",
    "insecure": False,
    "config_path": "C:/detecttrace/.detecttrace.yaml",
}


class FakeHealthyAdapter:
    def __init__(self, **kwargs):
        self.kwargs = kwargs

    def check_connection(self):
        return (
            True,
            "Connected to Elasticsearch 8.15.3 "
            "(cluster: docker-cluster).",
        )

    def check_index(self, index):
        return True, f"Index '{index}' contains 12 document(s)."


class FakeDisconnectedAdapter(FakeHealthyAdapter):
    def check_connection(self):
        return False, "Elasticsearch connection failed: refused."

    def check_index(self, index):
        raise AssertionError(
            "Index must not be checked when Elasticsearch is unavailable."
        )


class FakeMissingIndexAdapter(FakeHealthyAdapter):
    def check_index(self, index):
        return False, f"Index '{index}' does not exist."


class DoctorTests(unittest.TestCase):
    @patch(
        "detecttrace.doctor.check_kibana",
        return_value=(True, "Kibana is reachable."),
    )
    @patch(
        "detecttrace.doctor.ElasticAdapter",
        FakeHealthyAdapter,
    )
    def test_healthy_environment_passes(self, _kibana):
        result = run_doctor(
            settings=dict(SETTINGS),
            password="test-only-password",
        )

        self.assertTrue(result["healthy"])

        statuses = {
            check["name"]: check["status"]
            for check in result["checks"]
        }

        self.assertEqual(
            statuses["DetectTrace config"],
            "PASS",
        )
        self.assertEqual(
            statuses["Elasticsearch CA"],
            "PASS",
        )
        self.assertEqual(
            statuses["Elasticsearch"],
            "PASS",
        )
        self.assertEqual(
            statuses["Telemetry index"],
            "PASS",
        )
        self.assertEqual(
            statuses["Kibana"],
            "PASS",
        )

    @patch(
        "detecttrace.doctor.check_kibana",
        return_value=(True, "Kibana is reachable."),
    )
    @patch(
        "detecttrace.doctor.ElasticAdapter",
        FakeDisconnectedAdapter,
    )
    def test_elasticsearch_failure_blocks_index_check(self, _kibana):
        result = run_doctor(
            settings=dict(SETTINGS),
            password="test-only-password",
        )

        self.assertFalse(result["healthy"])

        statuses = {
            check["name"]: check["status"]
            for check in result["checks"]
        }

        self.assertEqual(
            statuses["Elasticsearch"],
            "FAIL",
        )
        self.assertEqual(
            statuses["Telemetry index"],
            "UNKNOWN",
        )

    @patch(
        "detecttrace.doctor.check_kibana",
        return_value=(True, "Kibana is reachable."),
    )
    @patch(
        "detecttrace.doctor.ElasticAdapter",
        FakeMissingIndexAdapter,
    )
    def test_missing_index_fails_environment(self, _kibana):
        result = run_doctor(
            settings=dict(SETTINGS),
            password="test-only-password",
        )

        self.assertFalse(result["healthy"])

        statuses = {
            check["name"]: check["status"]
            for check in result["checks"]
        }

        self.assertEqual(
            statuses["Telemetry index"],
            "FAIL",
        )

    @patch(
        "detecttrace.doctor.check_kibana",
        return_value=(
            False,
            "Kibana authentication failed: HTTP 401.",
        ),
    )
    @patch(
        "detecttrace.doctor.ElasticAdapter",
        FakeHealthyAdapter,
    )
    def test_kibana_failure_fails_environment(self, _kibana):
        result = run_doctor(
            settings=dict(SETTINGS),
            password="test-only-password",
        )

        self.assertFalse(result["healthy"])

        statuses = {
            check["name"]: check["status"]
            for check in result["checks"]
        }

        self.assertEqual(
            statuses["Kibana"],
            "FAIL",
        )

    @patch(
        "detecttrace.doctor.check_kibana",
        return_value=(True, "Kibana is reachable."),
    )
    @patch(
        "detecttrace.doctor.ElasticAdapter",
        FakeHealthyAdapter,
    )
    def test_no_config_is_unknown_but_runtime_can_still_pass(
        self,
        _kibana,
    ):
        settings = dict(SETTINGS)
        settings["config_path"] = None

        result = run_doctor(
            settings=settings,
            password="test-only-password",
        )

        self.assertTrue(result["healthy"])

        config = next(
            check
            for check in result["checks"]
            if check["name"] == "DetectTrace config"
        )
        self.assertEqual(config["status"], "UNKNOWN")


if __name__ == "__main__":
    unittest.main()
