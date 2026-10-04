from __future__ import annotations
import argparse
from pathlib import Path
import sys

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
        "execution.json": '{"executed": true}\\n',
        "source.jsonl": '{"event":{"code":1},"process":{"name":"powershell.exe","command_line":"powershell.exe -enc AAA"}}\\n',
        "collector.jsonl": '{"event":{"code":1},"process":{"name":"powershell.exe","command_line":"powershell.exe -enc AAA"}}\\n',
        "normalized.jsonl": '{"event":{"code":1},"process":{"name":"powershell.exe","command_line":"powershell.exe -enc AAA"}}\\n',
        "alerts.jsonl": '{"alert":{"rule_id":"DET-EXAMPLE-001"}}\\n',
    }.items():
        (directory / name).write_text(contents, encoding="utf-8")
    print(f"Created starter project in {directory}")
    return 0


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
