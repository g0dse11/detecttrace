from __future__ import annotations

import argparse
import os
from pathlib import Path
import sys

from .diagnostics import (
    enrich_result,
    render_result_json,
    render_result_junit,
)
from .engine import TraceEngine
from .report import render_json, render_text
from .spec import SpecError, load_spec


STARTER = """spec_version: detectspec/v1
id: DET-EXAMPLE-001
title: Example detection

behavior:
  mitre:
    technique: T1059.001

inputs:
  profiles:
    local:
      execution: execution.json
      source: source.jsonl
      collector: collector.jsonl
      normalized: normalized.jsonl
      alerts: alerts.jsonl

checkpoints:
  execution:
    require:
      - field: executed
        op: equals
        value: true

  source:
    require_event:
      all:
        - field: event.code
          op: equals
          value: 1

  collector:
    require_event:
      all:
        - field: event.code
          op: equals
          value: 1

  normalization:
    required_fields:
      - process.name
      - process.command_line

  rule:
    match:
      all:
        - field: process.name
          op: endswith
          value: powershell.exe

  alert:
    require_event:
      all:
        - field: alert.rule_id
          op: equals
          value: DET-EXAMPLE-001
"""


def cmd_validate(args: argparse.Namespace) -> int:
    path = Path(args.spec)
    load_spec(path)
    print(f"VALID  {path}")
    return 0


def cmd_test(args: argparse.Namespace) -> int:
    path = Path(args.spec)
    spec = load_spec(path)
    engine = TraceEngine()
    result = engine.run(spec, path, args.profile)

    if args.format == "json":
        print(render_json(result))
    else:
        print(render_text(result, verbose=args.verbose))

    return 0 if result.healthy else 1


def cmd_init(args: argparse.Namespace) -> int:
    directory = Path(args.directory)
    directory.mkdir(parents=True, exist_ok=True)
    target = directory / "detectspec.yaml"

    if target.exists() and not args.force:
        raise ValueError(f"{target} already exists; use --force to overwrite")

    target.write_text(STARTER, encoding="utf-8")

    for name, contents in {
        "execution.json": '{"executed": true}\n',
        "source.jsonl": (
            '{"event":{"code":1},"process":{"name":"powershell.exe",'
            '"command_line":"powershell.exe -enc AAA"}}\n'
        ),
        "collector.jsonl": (
            '{"event":{"code":1},"process":{"name":"powershell.exe",'
            '"command_line":"powershell.exe -enc AAA"}}\n'
        ),
        "normalized.jsonl": (
            '{"event":{"code":1},"process":{"name":"powershell.exe",'
            '"command_line":"powershell.exe -enc AAA"}}\n'
        ),
        "alerts.jsonl": '{"alert":{"rule_id":"DET-EXAMPLE-001"}}\n',
    }.items():
        (directory / name).write_text(contents, encoding="utf-8")

    print(f"Created starter project in {directory}")
    return 0


def cmd_sentinel_status(args: argparse.Namespace) -> int:
    try:
        from .adapters.sentinel import SentinelAdapter
    except ImportError as exc:
        print(
            "ERROR: Sentinel support requires Azure dependencies. "
            "Run: pip install -e .",
            file=sys.stderr,
        )
        print(f"DETAIL: {exc}", file=sys.stderr)
        return 2

    adapter = SentinelAdapter(workspace_id=args.workspace_id)
    checks = adapter.status()

    print()
    print("DETECTTRACE — SENTINEL STATUS")
    print("=" * 72)

    labels = {
        "authentication": "Azure authentication",
        "workspace": "Workspace configured",
        "query": "Log Analytics query",
    }

    healthy = True

    for key, (passed, message) in checks.items():
        state = "PASS" if passed else "FAIL"
        print(f"{labels.get(key, key):<26} {state:<8} {message}")
        healthy = healthy and passed

    print()
    return 0 if healthy else 1


def cmd_elastic_status(args: argparse.Namespace) -> int:
    try:
        from .adapters.elastic import ElasticAdapter
    except ImportError as exc:
        print("ERROR: Elastic adapter could not be loaded.", file=sys.stderr)
        print(f"DETAIL: {exc}", file=sys.stderr)
        return 2

    adapter = ElasticAdapter(base_url=args.url)
    checks = adapter.status(index=args.index)

    print()
    print("DETECTTRACE — ELASTIC STATUS")
    print("=" * 72)

    labels = {
        "connection": "Elasticsearch connection",
        "index": "Telemetry index",
    }

    healthy = True

    for key, (passed, message) in checks.items():
        state = "PASS" if passed else "FAIL"
        print(f"{labels.get(key, key):<26} {state:<8} {message}")
        healthy = healthy and passed

    print()
    return 0 if healthy else 1



def cmd_elastic_trace(args: argparse.Namespace) -> int:
    try:
        from .adapters.elastic import ElasticAdapter
    except ImportError as exc:
        print("ERROR: Elastic adapter could not be loaded.", file=sys.stderr)
        print(f"DETAIL: {exc}", file=sys.stderr)
        return 2

    spec_path = Path(args.spec)
    spec = load_spec(spec_path)
    adapter = ElasticAdapter(base_url=args.url)
    result = adapter.trace_spec(
        spec=spec,
        index=args.index,
        limit=args.limit,
    )

    print()
    print("DETECTTRACE — ELASTIC LIVE TRACE")
    print("=" * 72)
    print(f"{spec['id']} — {spec['title']}")
    print()

    for stage in result["stages"]:
        print(
            f"{stage['name']:<26} "
            f"{stage['status']:<8} "
            f"{stage['summary']}"
        )

    print()
    print("ROOT CAUSE")
    print("-" * 72)
    print(result["root_cause"])
    print(f"Confidence: {result['confidence']}")
    print()

    return 0 if result["healthy"] else 1


def cmd_elastic_alert(args: argparse.Namespace) -> int:
    try:
        from .adapters.elastic import ElasticAdapter
    except ImportError as exc:
        print("ERROR: Elastic adapter could not be loaded.", file=sys.stderr)
        print(f"DETAIL: {exc}", file=sys.stderr)
        return 2

    import getpass

    password = os.getenv("DETECTTRACE_ELASTIC_PASSWORD")
    if not password:
        password = getpass.getpass("Elastic password: ")

    adapter = ElasticAdapter(base_url=args.url)
    result = adapter.verify_alert(
        rule_name=args.rule_name,
        kibana_url=args.kibana_url,
        username=args.username,
        password=password,
    )

    print()
    print("DETECTTRACE — ELASTIC ALERT VERIFICATION")
    print("=" * 72)
    print(f"Kibana alert query         {result['status']:<8} {result['summary']}")

    alert = result.get("alert")
    if alert:
        print(f"Rule                       PASS     {alert['rule_name']}")
        print(f"Alert timestamp            PASS     {alert['timestamp']}")
        print(f"Alert status               PASS     {alert['status']}")
        print(f"Severity                   PASS     {alert['severity']}")
        if alert.get("risk_score") is not None:
            print(f"Risk score                 PASS     {alert['risk_score']}")
        print()
        print("ALERT CONFIRMED")
        print("-" * 72)
        print("Elastic Security generated a real alert for the requested rule.")
    else:
        print()
        print("ALERT NOT CONFIRMED")
        print("-" * 72)
        print(result["summary"])

    print()
    return 0 if result["healthy"] else 1


def cmd_elastic_test(args: argparse.Namespace) -> int:
    try:
        from .adapters.elastic import ElasticAdapter
    except ImportError as exc:
        print("ERROR: Elastic adapter could not be loaded.", file=sys.stderr)
        print(f"DETAIL: {exc}", file=sys.stderr)
        return 2

    import getpass

    spec_path = Path(args.spec)
    spec = load_spec(spec_path)

    password = os.getenv("DETECTTRACE_ELASTIC_PASSWORD")
    if not password:
        password = getpass.getpass("Elastic password: ")

    adapter = ElasticAdapter(
        base_url=args.url,
        username=args.username,
        password=password,
        verify_tls=not args.insecure,
        ca_cert=args.ca_cert,
    )

    result = adapter.correlated_test(
        spec=spec,
        index=args.index,
        rule_name=args.rule_name,
        kibana_url=args.kibana_url,
        case=args.case,
        kibana_username=args.username,
        kibana_password=password,
        limit=args.limit,
        alert_timeout=args.timeout,
        poll_interval=args.poll_interval,
    )

    enrich_result(
        result,
        spec_id=spec["id"],
        spec_title=spec["title"],
        backend="elastic",
        rule_name=args.rule_name,
    )

    if args.format == "json":
        print(render_result_json(result))
        return 0 if result["healthy"] else 1

    if args.format == "junit":
        print(render_result_junit(result))
        return 0 if result["healthy"] else 1

    print()
    print("DETECTTRACE — CORRELATED END-TO-END TEST")
    print("=" * 72)
    print(f"{spec['id']} — {spec['title']}")
    if result.get("run_id"):
        print(f"Run ID: {result['run_id']}")
    print(f"Case: {result.get('case', args.case)}")
    print()

    for stage in result["stages"]:
        print(
            f"{stage['name']:<26} "
            f"{stage['status']:<8} "
            f"{stage['summary']}"
        )

    print()
    print("RESULT")
    print("-" * 72)
    print(result["root_cause"])
    print(f"Confidence: {result['confidence']}")

    if not result["healthy"]:
        print(
            "First failing stage: "
            f"{result.get('first_failed_stage') or 'UNKNOWN'}"
        )
        print(
            "Failure code: "
            f"{result.get('failure_code') or 'UNKNOWN'}"
        )
        if result.get("remediation"):
            print(f"Recommended remediation: {result['remediation']}")

    if result.get("indexing_ms") is not None:
        print(f"Indexing round-trip: {result['indexing_ms']:.1f} ms")
    if result.get("alert_latency_s") is not None:
        print(f"Approx. alert latency: {result['alert_latency_s']:.2f} s")

    alert = result.get("alert")
    if alert:
        print()
        print(f"Alert status: {alert.get('status', 'unknown')}")
        print(f"Severity: {alert.get('severity', 'unknown')}")
        if alert.get("risk_score") is not None:
            print(f"Risk score: {alert['risk_score']}")

    print()
    return 0 if result["healthy"] else 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="detecttrace",
        description="Executable contracts and causal tracing for security detections.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("validate", help="validate a DetectSpec")
    p.add_argument("spec")
    p.set_defaults(func=cmd_validate)

    p = sub.add_parser("test", help="execute a DetectSpec trace")
    p.add_argument("spec")
    p.add_argument("--profile", default="broken")
    p.add_argument("--format", choices=("text", "json"), default="text")
    p.add_argument("-v", "--verbose", action="store_true")
    p.set_defaults(func=cmd_test)

    p = sub.add_parser("init", help="create a starter DetectSpec project")
    p.add_argument("directory")
    p.add_argument("--force", action="store_true")
    p.set_defaults(func=cmd_init)

    p = sub.add_parser(
        "sentinel",
        help="Microsoft Sentinel / Log Analytics operations",
    )
    sentinel_sub = p.add_subparsers(
        dest="sentinel_command",
        required=True,
    )
    status = sentinel_sub.add_parser(
        "status",
        help="check Sentinel connectivity",
    )
    status.add_argument(
        "--workspace-id",
        help=(
            "Log Analytics workspace ID "
            "(or set DETECTTRACE_SENTINEL_WORKSPACE_ID)"
        ),
    )
    status.set_defaults(func=cmd_sentinel_status)

    p = sub.add_parser(
        "elastic",
        help="Elasticsearch operations",
    )
    elastic_sub = p.add_subparsers(
        dest="elastic_command",
        required=True,
    )
    elastic_status = elastic_sub.add_parser(
        "status",
        help="check Elasticsearch connectivity and telemetry index",
    )
    elastic_status.add_argument(
        "--url",
        default=None,
        help=(
            "Elasticsearch base URL "
            "(default: DETECTTRACE_ELASTIC_URL or http://localhost:9200)"
        ),
    )
    elastic_status.add_argument(
        "--index",
        default="detecttrace-events",
        help="Telemetry index to check (default: detecttrace-events)",
    )
    elastic_status.set_defaults(func=cmd_elastic_status)

    elastic_trace = elastic_sub.add_parser(
        "trace",
        help="evaluate a DetectSpec against live Elasticsearch telemetry",
    )
    elastic_trace.add_argument(
        "spec",
        help="Path to a DetectSpec YAML file",
    )
    elastic_trace.add_argument(
        "--url",
        default=None,
        help=(
            "Elasticsearch base URL "
            "(default: DETECTTRACE_ELASTIC_URL or http://localhost:9200)"
        ),
    )
    elastic_trace.add_argument(
        "--index",
        default="detecttrace-events",
        help="Telemetry index to evaluate (default: detecttrace-events)",
    )
    elastic_trace.add_argument(
        "--limit",
        type=int,
        default=10,
        help="Number of recent documents to evaluate (default: 10)",
    )
    elastic_trace.set_defaults(func=cmd_elastic_trace)

    elastic_alert = elastic_sub.add_parser(
        "alert",
        help="verify that Elastic Security generated a real alert",
    )
    elastic_alert.add_argument(
        "--rule-name",
        required=True,
        help="Elastic Security detection rule name",
    )
    elastic_alert.add_argument(
        "--kibana-url",
        default=os.getenv("DETECTTRACE_KIBANA_URL", "http://localhost:5602"),
        help="Kibana URL",
    )
    elastic_alert.add_argument(
        "--username",
        default=os.getenv("DETECTTRACE_ELASTIC_USERNAME", "elastic"),
        help="Elastic username",
    )
    elastic_alert.add_argument(
        "--url",
        default=None,
        help="Elasticsearch base URL",
    )
    elastic_alert.set_defaults(func=cmd_elastic_alert)

    elastic_test = elastic_sub.add_parser(
        "test",
        help="run an end-to-end DetectSpec test against secured Elastic",
    )
    elastic_test.add_argument(
        "spec",
        help="Path to a DetectSpec YAML file",
    )
    elastic_test.add_argument(
        "--rule-name",
        required=True,
        help="Elastic Security detection rule name",
    )
    elastic_test.add_argument(
        "--url",
        default=os.getenv("DETECTTRACE_ELASTIC_URL", "https://localhost:9201"),
        help="Elasticsearch URL (default: https://localhost:9201)",
    )
    elastic_test.add_argument(
        "--kibana-url",
        default=os.getenv("DETECTTRACE_KIBANA_URL", "http://localhost:5602"),
        help="Kibana URL (default: http://localhost:5602)",
    )
    elastic_test.add_argument(
        "--username",
        default=os.getenv("DETECTTRACE_ELASTIC_USERNAME", "elastic"),
        help="Elastic username (default: elastic)",
    )
    elastic_test.add_argument(
        "--index",
        default="detecttrace-events",
        help="Telemetry index (default: detecttrace-events)",
    )
    elastic_test.add_argument(
        "--limit",
        type=int,
        default=10,
        help="Number of recent telemetry documents to inspect (default: 10)",
    )
    elastic_test.add_argument(
        "--case",
        default="healthy",
        help="DetectSpec test case to run (default: healthy)",
    )
    elastic_test.add_argument(
        "--timeout",
        type=float,
        default=90.0,
        help="Seconds to wait for a correlated Elastic alert (default: 90)",
    )
    elastic_test.add_argument(
        "--poll-interval",
        type=float,
        default=5.0,
        help="Alert polling interval in seconds (default: 5)",
    )
    elastic_test.add_argument(
        "--format",
        choices=("text", "json", "junit"),
        default="text",
        help="Output format (default: text)",
    )
    elastic_test.add_argument(
        "--ca-cert",
        default=None,
        help="Path to Elasticsearch HTTP CA certificate",
    )
    elastic_test.add_argument(
        "--insecure",
        action="store_true",
        help="Disable TLS certificate verification (local lab only)",
    )
    elastic_test.set_defaults(func=cmd_elastic_test)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        return args.func(args)
    except (SpecError, ValueError, FileNotFoundError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
