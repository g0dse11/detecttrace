from __future__ import annotations

from copy import deepcopy
import unittest

from detecttrace.spec import SpecError, validate_spec


BASE_SPEC = {
    "spec_version": "detectspec/v1",
    "id": "DET-PS-LIVE-001",
    "title": "Live Encoded PowerShell",
    "inputs": {
        "profiles": {
            "live": {},
        }
    },
    "test": {
        "cases": {
            "healthy": {
                "event": {
                    "event": {"code": 1},
                    "process": {
                        "name": "powershell.exe",
                        "command_line": "powershell.exe -enc AAA",
                    },
                }
            },
            "broken": {
                "event": {
                    "event": {"code": 1},
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


class DetectSpecValidationTests(unittest.TestCase):
    def test_current_elastic_shape_is_valid(self):
        validate_spec(deepcopy(BASE_SPEC))

    def test_existing_offline_execution_and_alert_shape_is_valid(self):
        spec = deepcopy(BASE_SPEC)
        spec["checkpoints"]["execution"] = {
            "require": [
                {
                    "field": "executed",
                    "op": "equals",
                    "value": True,
                }
            ]
        }
        spec["checkpoints"]["alert"] = {
            "require_event": {
                "all": [
                    {
                        "field": "alert.rule_id",
                        "op": "equals",
                        "value": "DET-PS-001",
                    }
                ]
            },
            "within_seconds": 60,
            "execution_time_field": "timestamp",
            "alert_time_field": "timestamp",
        }

        validate_spec(spec)

    def test_execution_require_rejects_non_predicate(self):
        spec = deepcopy(BASE_SPEC)
        spec["checkpoints"]["execution"] = {
            "require": ["executed"],
        }

        with self.assertRaisesRegex(
            SpecError,
            r"checkpoints\.execution\.require\[0\] must be an object",
        ):
            validate_spec(spec)

    def test_alert_rejects_negative_within_seconds(self):
        spec = deepcopy(BASE_SPEC)
        spec["checkpoints"]["alert"] = {
            "within_seconds": -1,
        }

        with self.assertRaisesRegex(
            SpecError,
            r"checkpoints\.alert\.within_seconds must be "
            r"a non-negative number",
        ):
            validate_spec(spec)

    def test_unknown_top_level_field_is_rejected(self):
        spec = deepcopy(BASE_SPEC)
        spec["mystery"] = True

        with self.assertRaisesRegex(
            SpecError,
            r"spec contains unknown field\(s\): mystery",
        ):
            validate_spec(spec)

    def test_unknown_profile_field_is_rejected(self):
        spec = deepcopy(BASE_SPEC)
        spec["inputs"]["profiles"]["live"]["unexpected"] = "x"

        with self.assertRaisesRegex(
            SpecError,
            r"inputs\.profiles\.live contains unknown field",
        ):
            validate_spec(spec)

    def test_unknown_checkpoint_is_rejected(self):
        spec = deepcopy(BASE_SPEC)
        spec["checkpoints"]["magic"] = {}

        with self.assertRaisesRegex(
            SpecError,
            r"unknown checkpoint\(s\): magic",
        ):
            validate_spec(spec)

    def test_unknown_normalization_field_is_rejected(self):
        spec = deepcopy(BASE_SPEC)
        spec["checkpoints"]["normalization"]["typo"] = True

        with self.assertRaisesRegex(
            SpecError,
            r"checkpoints\.normalization contains unknown field",
        ):
            validate_spec(spec)

    def test_test_case_requires_event_object(self):
        spec = deepcopy(BASE_SPEC)
        del spec["test"]["cases"]["healthy"]["event"]

        with self.assertRaisesRegex(
            SpecError,
            r"test\.cases\.healthy\.event is required",
        ):
            validate_spec(spec)

    def test_predicate_all_must_be_non_empty_list(self):
        spec = deepcopy(BASE_SPEC)
        spec["checkpoints"]["rule"]["match"] = {"all": []}

        with self.assertRaisesRegex(
            SpecError,
            r"checkpoints\.rule\.match\.all must be a non-empty list",
        ):
            validate_spec(spec)

    def test_predicate_leaf_requires_operator(self):
        spec = deepcopy(BASE_SPEC)
        spec["checkpoints"]["rule"]["match"] = {
            "field": "process.name",
        }

        with self.assertRaisesRegex(
            SpecError,
            r"checkpoints\.rule\.match\.op is required",
        ):
            validate_spec(spec)

    def test_recursive_any_and_not_predicates_are_valid(self):
        spec = deepcopy(BASE_SPEC)
        spec["checkpoints"]["rule"]["match"] = {
            "any": [
                {
                    "field": "process.name",
                    "op": "endswith",
                    "value": "powershell.exe",
                },
                {
                    "not": {
                        "field": "process.name",
                        "op": "endswith",
                        "value": "cmd.exe",
                    }
                },
            ]
        }

        validate_spec(spec)

    def test_required_field_object_rejects_unknown_keys(self):
        spec = deepcopy(BASE_SPEC)
        spec["checkpoints"]["normalization"]["required_fields"] = [
            {
                "field": "process.command_line",
                "from": "winlog.event_data.CommandLine",
                "typo": "unexpected",
            }
        ]

        with self.assertRaisesRegex(
            SpecError,
            r"required_fields\[0\] contains unknown field",
        ):
            validate_spec(spec)


if __name__ == "__main__":
    unittest.main()
