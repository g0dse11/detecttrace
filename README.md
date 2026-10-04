# DetectTrace + DetectSpec

**DetectTrace** explains why an expected security detection did not happen.

It treats a detection as an end-to-end contract rather than only a SIEM query:

```text
attack -> source telemetry -> collection -> normalization -> rule -> alert
```

A **DetectSpec** declares the assumptions that must hold at each checkpoint. DetectTrace evaluates those assumptions, preserves evidence, and marks downstream stages **BLOCKED** when an upstream dependency fails.

## What this MVP does

- `detecttrace validate <spec>` — validates DetectSpec structure.
- `detecttrace test <spec> --profile broken|healthy` — runs an end-to-end deterministic trace.
- `detecttrace init <directory>` — creates a starter spec.
- Safe rule DSL; no `eval`.
- Nested-field assertions (`process.command_line`, etc.).
- PASS / FAIL / BLOCKED / UNKNOWN / SKIPPED semantics.
- Evidence-backed root-cause explanation.
- Field-lineage hints that identify likely remaps (for example `process.command_line` -> `process.args`).
- Alert latency contracts (`within_seconds`).
- File adapter using JSON/JSONL so the engine is easy to test and extend.
- JSON output for CI with `--format json`.
- Exit code `0` when healthy, `1` when the detection contract fails, `2` for invalid input.

## Quick start

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e .

detecttrace validate examples/powershell/detectspec.yaml
detecttrace test examples/powershell/detectspec.yaml --profile broken
detecttrace test examples/powershell/detectspec.yaml --profile healthy
```

The broken profile deliberately maps the original PowerShell command line to `process.args` instead of `process.command_line`.

Expected result:

```text
Execution          PASS
Source telemetry   PASS
Collector          PASS
Normalization      FAIL
Rule               BLOCKED
Alert              BLOCKED
```

The healthy profile then proves the same detection can pass end-to-end.

## DetectSpec philosophy

A detection is more than a rule.

A useful contract should describe:

1. **Behaviour** — what security behaviour is being exercised.
2. **Execution evidence** — how we know the test action happened.
3. **Telemetry dependency** — which events must exist.
4. **Field contract** — which fields must be present and usable.
5. **Rule semantics** — what must match.
6. **Alert expectation** — what alert must exist and by when.
7. **Negative tests** — benign events that must not alert.
8. **Evidence** — why each stage passed or failed.

## Example DetectSpec

```yaml
spec_version: detectspec/v1
id: DET-PS-001
title: Suspicious Encoded PowerShell

behavior:
  mitre:
    technique: T1059.001

inputs:
  profiles:
    broken:
      execution: broken/execution.json
      source: broken/source.jsonl
      collector: broken/collector.jsonl
      normalized: broken/normalized.jsonl
      alerts: broken/alerts.jsonl
    healthy:
      execution: healthy/execution.json
      source: healthy/source.jsonl
      collector: healthy/collector.jsonl
      normalized: healthy/normalized.jsonl
      alerts: healthy/alerts.jsonl

checkpoints:
  execution:
    require:
      - field: executed
        op: equals
        value: true

  source:
    require_event:
      all:
        - field: event.provider
          op: equals
          value: Microsoft-Windows-Sysmon
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
    require_event:
      all:
        - field: process.name
          op: endswith
          value: powershell.exe
    required_fields:
      - field: process.command_line
        from: winlog.event_data.CommandLine
      - field: process.parent.name
        from: winlog.event_data.ParentImage

  rule:
    match:
      all:
        - field: process.name
          op: endswith
          value: powershell.exe
        - field: process.command_line
          op: regex
          value: "(?i)(?:\\s|^)-(?:enc|encodedcommand)\\b"

  alert:
    require_event:
      all:
        - field: alert.rule_id
          op: equals
          value: DET-PS-001
    within_seconds: 60
```

## Rule DSL

Predicates:

- `exists`
- `equals`
- `not_equals`
- `contains`
- `startswith`
- `endswith`
- `regex`
- `in`
- `gt`, `gte`, `lt`, `lte`

Composition:

```yaml
all:
  - field: process.name
    op: endswith
    value: powershell.exe
  - any:
      - field: process.command_line
        op: contains
        value: "-enc"
      - field: process.command_line
        op: contains
        value: "-EncodedCommand"
```

`not:` is also supported.

## Adapter architecture

The MVP ships with a `file` adapter. A production version should add adapters for:

- Microsoft Sentinel / Log Analytics
- Elastic Security
- Splunk
- Sysmon / Windows Event Log
- Cribl / Kafka / data pipelines
- EDRs
- BAS / Atomic Red Team orchestration
- alert routing systems

The core engine is intentionally vendor-neutral. Adapters should return evidence, not hidden pass/fail decisions.

## CI example

```bash
detecttrace test detections/DET-PS-001.yaml --profile staging --format json > result.json
```

A failed contract exits non-zero, so CI can prevent a parser, connector, or rule change from silently degrading detection coverage.

## Security design choices

- No arbitrary Python/shell evaluation from specs.
- Regex uses Python's standard engine and is treated as untrusted configuration; production deployments should add time/size limits or use a guaranteed-linear engine.
- File paths are resolved relative to the spec and must remain within the spec directory.
- JSONL inputs are read with configurable size limits in code.
- Root-cause output is based on observed evidence; it avoids claiming certainty when a checkpoint is missing.

## Roadmap

1. Sentinel adapter + Azure Monitor query execution.
2. Elastic adapter.
3. Splunk adapter.
4. Atomic Red Team test launcher (explicit opt-in).
5. Field lineage and transform-diff engine.
6. Latency / time-window assertions.
7. Negative fixtures and false-positive testing.
8. GitHub Action.
9. JSON Schema publishing and VS Code autocomplete.
10. Historical drift monitoring and contract health dashboard.

## License

Apache-2.0.
