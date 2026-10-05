from __future__ import annotations

import json
from typing import Any
from xml.etree import ElementTree as ET


RESULT_SCHEMA_VERSION = "detecttrace.result/v1"

FAILURE_CODES = {
    "EXECUTION_NOT_CONFIRMED",
    "TELEMETRY_MISSING",
    "COLLECTION_FAILURE",
    "INGESTION_FAILURE",
    "SCHEMA_DRIFT",
    "REQUIRED_FIELD_MISSING",
    "RULE_NOT_FOUND",
    "RULE_DISABLED",
    "RULE_LOGIC_MISMATCH",
    "RULE_EXECUTION_ERROR",
    "CORRELATION_FAILURE",
    "ALERT_SUPPRESSED",
    "ALERT_TIMEOUT",
    "ALERT_NOT_GENERATED",
    "ALERT_ROUTING_FAILURE",
    "UNKNOWN",
}

STAGE_NAME_MAP = {
    "Test event": "EXECUTION",
    "Backend connection": "INGESTION",
    "Telemetry index": "INGESTION",
    "Telemetry located": "TELEMETRY",
    "Normalization": "NORMALIZATION",
    "Rule": "RULE_EVALUATION",
    "Elastic rule exists": "RULE_EVALUATION",
    "Elastic rule enabled": "RULE_EVALUATION",
    "Rule execution": "RULE_EVALUATION",
    "Elastic alert": "ALERT_GENERATION",
}


def first_failed_stage(stages: list[dict[str, Any]]) -> str | None:
    """Return the canonical first stage whose status is FAIL."""
    for stage in stages:
        if str(stage.get("status", "")).upper() == "FAIL":
            return STAGE_NAME_MAP.get(
                str(stage.get("name", "")),
                str(stage.get("name", "UNKNOWN")).upper().replace(" ", "_"),
            )
    return None


def finalize_result(
    result: dict[str, Any],
    *,
    failure_code: str | None = None,
    remediation: str | None = None,
) -> dict[str, Any]:
    """Attach stable diagnostic metadata to a DetectTrace result."""
    result["schema_version"] = RESULT_SCHEMA_VERSION
    result["first_failed_stage"] = first_failed_stage(
        result.get("stages", [])
    )

    if result.get("healthy"):
        result["failure_code"] = None
        result["remediation"] = None
        return result

    code = failure_code or result.get("failure_code") or "UNKNOWN"
    if code not in FAILURE_CODES:
        code = "UNKNOWN"

    result["failure_code"] = code
    result["remediation"] = remediation or result.get("remediation")
    return result


def enrich_result(
    result: dict[str, Any],
    *,
    spec_id: str,
    spec_title: str,
    backend: str,
    rule_name: str,
) -> dict[str, Any]:
    result["schema_version"] = RESULT_SCHEMA_VERSION
    result["spec"] = {
        "id": spec_id,
        "title": spec_title,
    }
    result["backend"] = backend
    result["rule_name"] = rule_name
    return result


def render_result_json(result: dict[str, Any]) -> str:
    return json.dumps(
        result,
        indent=2,
        sort_keys=True,
        ensure_ascii=False,
    )


def render_result_junit(result: dict[str, Any]) -> str:
    spec = result.get("spec", {})
    spec_id = str(spec.get("id", "unknown"))
    backend = str(result.get("backend", "unknown"))
    healthy = bool(result.get("healthy"))

    suite = ET.Element(
        "testsuite",
        {
            "name": "DetectTrace",
            "tests": "1",
            "failures": "0" if healthy else "1",
            "errors": "0",
        },
    )

    case = ET.SubElement(
        suite,
        "testcase",
        {
            "classname": f"detecttrace.{backend}",
            "name": spec_id,
        },
    )

    properties = ET.SubElement(case, "properties")
    for name, value in (
        ("schema_version", result.get("schema_version")),
        ("run_id", result.get("run_id")),
        ("case", result.get("case")),
        ("rule_name", result.get("rule_name")),
        ("first_failed_stage", result.get("first_failed_stage")),
        ("failure_code", result.get("failure_code")),
        ("confidence", result.get("confidence")),
    ):
        if value is not None:
            ET.SubElement(
                properties,
                "property",
                {"name": str(name), "value": str(value)},
            )

    if not healthy:
        failure_code = str(result.get("failure_code") or "UNKNOWN")
        root_cause = str(
            result.get("root_cause") or "DetectTrace test failed."
        )
        remediation = result.get("remediation")
        detail = root_cause
        if remediation:
            detail += f"\nRecommended remediation: {remediation}"

        failure = ET.SubElement(
            case,
            "failure",
            {
                "type": failure_code,
                "message": root_cause,
            },
        )
        failure.text = detail

    lines = []
    for stage in result.get("stages", []):
        lines.append(
            f"{stage.get('name', 'Unknown')}: "
            f"{stage.get('status', 'UNKNOWN')} - "
            f"{stage.get('summary', '')}"
        )

    system_out = ET.SubElement(case, "system-out")
    system_out.text = "\n".join(lines)

    ET.indent(suite, space="  ")
    return ET.tostring(
        suite,
        encoding="unicode",
        xml_declaration=False,
    )
