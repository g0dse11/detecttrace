# DetectTrace

**A detection should have fired. It didn't. DetectTrace tells you exactly why.**

DetectTrace is an open-source detection engineering tool for testing security
detections end to end and localising the **first failing stage**.

Instead of testing only a SIEM query, DetectTrace treats a detection as a
pipeline:

```text
test behaviour
    -> telemetry
    -> ingestion
    -> normalization/schema
    -> rule evaluation
    -> rule execution
    -> alert generation
```

A **DetectSpec** declares what should happen. DetectTrace gathers evidence for
what actually happened, evaluates the contract, stops causal reasoning at the
first proven failure, and marks dependent downstream stages **BLOCKED**.

The current live backend is **Elastic Security**. DetectTrace also includes a
deterministic file-backed mode for local development and regression testing.

## Why DetectTrace exists

Detection failures are often diagnosed manually:

- Did the test actually run?
- Was telemetry generated?
- Did it reach the backend?
- Did a field get renamed or dropped?
- Does the rule still match?
- Is the rule disabled or unhealthy?
- Did the alert appear, and did it belong to this exact test run?

DetectTrace turns those questions into executable checks and evidence.

Example failure:

```text
Test event                 PASS
Backend connection         PASS
Telemetry index            PASS
Telemetry located          PASS
Normalization              FAIL
Rule                       BLOCKED
Elastic rule exists        BLOCKED
Elastic rule enabled       BLOCKED
Rule execution             BLOCKED
Elastic alert              BLOCKED

RESULT
------------------------------------------------------------------------
Required field 'process.command_line' is absent, but the value from
'winlog.event_data.CommandLine' survived at 'process.args'.
Probable schema/mapping drift.

Confidence: HIGH
First failing stage: NORMALIZATION
Failure code: SCHEMA_DRIFT
```

The important part is not only that the detection failed. DetectTrace explains
**where the detection path first became invalid and why**.

## What DetectTrace currently supports

- DetectSpec v1 validation
- deterministic offline traces from JSON/JSONL evidence
- safe declarative predicate DSL; no arbitrary Python or shell execution
- nested field checks
- field-lineage hints for likely schema/mapping drift
- PASS / FAIL / BLOCKED / UNKNOWN / SKIPPED stage semantics
- first-failing-stage diagnostics
- stable failure codes and remediation text
- correlated Elastic Security tests using a unique `detecttrace.run_id`
- real Elastic rule existence/enabled/execution checks
- correlated Elastic alert verification
- alert latency measurement
- secure Elasticsearch TLS with a configured CA
- `detecttrace doctor` environment checks
- text, JSON, and JUnit-compatible output
- regression tests and GitHub Actions CI
- reproducible local Elasticsearch + Kibana lab

## What DetectTrace is not

DetectTrace is not:

- an attack-simulation platform
- a BAS replacement
- a SIEM rule editor
- a generic vulnerability scanner
- an AI system that guesses whether a detection worked

Attack/test execution can be integrated later. DetectTrace's job is to verify
the **detection path** and diagnose failures from observed evidence.

## Requirements

- Python 3.10+
- Docker with Compose v2 only if you want to run the supplied Elastic lab

The CI suite currently tests Python 3.10, 3.11, 3.12, and 3.13.

## Five-minute offline quick start

Clone the repository, create a virtual environment, and install DetectTrace.

### Windows PowerShell

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -e .
```

### Linux/macOS

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install -e .
```

Check the installation:

```text
detecttrace --version
```

Create a runnable starter project:

```text
detecttrace init demo
```

Then:

```text
cd demo
detecttrace validate detectspec.yaml
detecttrace test detectspec.yaml
```

The generated project is self-contained. It does not require Elasticsearch,
Kibana, Docker, or network access.

A healthy run ends with:

```text
Detection contract passed end-to-end.
Confidence: HIGH
```

## Offline healthy and broken examples

The repository includes a PowerShell fixture with both known-good and
deliberately broken evidence.

Healthy:

```text
detecttrace test examples/powershell/detectspec.yaml --profile healthy
```

Broken:

```text
detecttrace test examples/powershell/detectspec.yaml --profile broken
```

The broken profile deliberately preserves the original command line under
`process.args` instead of the required `process.command_line`. DetectTrace
localises that failure to normalization and blocks rule/alert evaluation.

## DetectSpec

DetectSpec is the declarative contract. DetectTrace is the engine that evaluates
that contract against evidence.

A DetectSpec can describe:

1. execution evidence
2. source telemetry
3. collection evidence
4. normalization requirements
5. rule semantics
6. alert expectations and timing
7. correlated live test cases

Example:

```yaml
spec_version: detectspec/v1
id: DET-PS-LIVE-001
title: Live Encoded PowerShell

inputs:
  profiles:
    live: {}

test:
  cases:
    healthy:
      event:
        event:
          code: 1
        process:
          name: powershell.exe
          command_line: powershell.exe -enc AAA

    broken:
      event:
        event:
          code: 1
        winlog:
          event_data:
            CommandLine: powershell.exe -enc AAA
        process:
          name: powershell.exe
          args: powershell.exe -enc AAA

checkpoints:
  normalization:
    require_event:
      all:
        - field: process.name
          op: endswith
          value: powershell.exe
    required_fields:
      - field: process.command_line
        from: winlog.event_data.CommandLine

  rule:
    match:
      all:
        - field: process.name
          op: endswith
          value: powershell.exe
        - field: process.command_line
          op: regex
          value: "(?i)(?:\\s|^)-(?:enc|encodedcommand)\\b"
```

The JSON Schema is in:

```text
schemas/detectspec-v1.schema.json
```

The runtime validator and JSON Schema are intentionally strict about unknown
DetectSpec structure so spelling mistakes fail early.

## Predicate DSL

Leaf predicates use:

```yaml
field: process.name
op: equals
value: powershell.exe
```

Supported operators include:

```text
exists
equals
not_equals
contains
startswith
endswith
regex
in
gt
gte
lt
lte
```

Predicates can be composed with `all`, `any`, and `not`.

Example:

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

## First-failing-stage semantics

DetectTrace follows a simple rule:

> **Evidence before inference. First failing stage wins.**

If normalization fails, DetectTrace does not pretend it knows whether a
downstream rule or alert would have succeeded. Those stages are reported as
`BLOCKED`.

If evidence is unavailable rather than disproven, DetectTrace reports
`UNKNOWN` instead of guessing.

The stable machine-readable result schema is:

```text
detecttrace.result/v1
```

Important fields include:

```text
healthy
first_failed_stage
failure_code
confidence
root_cause
remediation
run_id
stages
```

Current failure codes include categories such as:

```text
INGESTION_FAILURE
TELEMETRY_MISSING
SCHEMA_DRIFT
REQUIRED_FIELD_MISSING
RULE_NOT_FOUND
RULE_DISABLED
RULE_LOGIC_MISMATCH
RULE_EXECUTION_ERROR
ALERT_TIMEOUT
UNKNOWN
```

## Local Elastic Security lab

A reproducible secured lab is included at:

```text
lab/elastic
```

It provides:

```text
Elasticsearch 8.15.3   https://localhost:9201
Kibana 8.15.3          http://localhost:5602
Elasticsearch security enabled
Elasticsearch HTTP TLS enabled
Persistent Elasticsearch data
Persistent certificates
Kibana encryption keys
detecttrace-events index
```

See `lab/elastic/README.md` for the complete setup.

The short version is:

```powershell
cd lab\elastic
Copy-Item .env.example .env
docker compose up -d
```

After the services are healthy, return to the repository root and export the
public CA:

```powershell
New-Item -ItemType Directory -Force .\certs | Out-Null
docker cp detecttrace-es:/usr/share/elasticsearch/config/certs/http_ca.crt .\certs\http_ca.crt
Copy-Item .detecttrace.example.yaml .detecttrace.yaml
```

Then verify the environment:

```text
detecttrace doctor
```

A ready environment reports PASS for:

```text
DetectTrace config
Elasticsearch CA
Elasticsearch
Telemetry index
Kibana
```

The local `.env`, `.detecttrace.yaml`, and exported `certs/` material are
environment-specific and are not committed.

## Elastic end-to-end test

The supplied live example is:

```text
examples/elastic_live_detectspec.yaml
```

The example Elastic Security rule used by the lab is:

```text
Name:
DetectTrace - Encoded PowerShell

Index:
detecttrace-events

Query:
process.name : "powershell.exe" and process.command_line : "powershell.exe -enc AAA"
```

Run the healthy correlated test:

```powershell
detecttrace elastic test examples\elastic_live_detectspec.yaml `
  --rule-name "DetectTrace - Encoded PowerShell" `
  --case healthy
```

DetectTrace:

1. generates a unique run ID
2. injects the exact test event
3. retrieves telemetry for that run ID
4. evaluates normalization
5. evaluates the DetectSpec rule predicate
6. verifies the Elastic rule exists
7. verifies the Elastic rule is enabled
8. checks rule execution evidence
9. polls for an Elastic Security alert carrying the same run ID
10. reports approximate alert latency

An old alert cannot make a new test pass because the alert must correlate to the
current run ID.

The deliberately broken case is:

```powershell
detecttrace elastic test examples\elastic_live_detectspec.yaml `
  --rule-name "DetectTrace - Encoded PowerShell" `
  --case broken
```

## `detecttrace doctor`

Before running live Elastic tests:

```text
detecttrace doctor
```

`doctor` performs read-only checks for:

- DetectTrace configuration
- Elasticsearch CA configuration
- Elasticsearch TLS/authentication/connectivity
- telemetry index availability
- Kibana availability

Exit codes:

```text
0  environment ready
2  configuration/environment problem
```

Passwords are not stored in `.detecttrace.yaml`. Supply the Elastic password
through the interactive prompt or `DETECTTRACE_ELASTIC_PASSWORD`.

## Configuration

Example:

```yaml
config_version: detecttrace/config-v1

elastic:
  url: https://localhost:9201
  kibana_url: http://localhost:5602
  username: elastic
  index: detecttrace-events
  ca_cert: certs/http_ca.crt
```

Configuration precedence is:

```text
CLI argument > environment variable > .detecttrace.yaml > default
```

DetectTrace rejects password/token/API-key fields in its YAML config.

`--insecure` exists for temporary troubleshooting, but verified TLS with a CA
certificate is the normal path.

## Machine-readable output

### JSON

Elastic end-to-end tests:

```powershell
detecttrace elastic test examples\elastic_live_detectspec.yaml `
  --rule-name "DetectTrace - Encoded PowerShell" `
  --case broken `
  --format json
```

Example fields:

```json
{
  "schema_version": "detecttrace.result/v1",
  "healthy": false,
  "first_failed_stage": "NORMALIZATION",
  "failure_code": "SCHEMA_DRIFT",
  "confidence": "HIGH",
  "run_id": "dt-..."
}
```

Offline fixture tests also support JSON:

```text
detecttrace test examples/powershell/detectspec.yaml --profile healthy --format json
```

### JUnit

Elastic end-to-end tests can emit JUnit-compatible XML:

```powershell
detecttrace elastic test examples\elastic_live_detectspec.yaml `
  --rule-name "DetectTrace - Encoded PowerShell" `
  --case broken `
  --format junit
```

A failed detection is represented as a failed testcase, including the failure
code, root cause, remediation, and stage evidence.

## Exit codes

For detection tests:

```text
0  detection contract passed
1  detection contract failed
2  configuration, usage, or environment error
```

This separation is useful in CI: a broken detection is different from a runner
that was never configured correctly.

## CI

The repository's GitHub Actions workflow runs:

- Python 3.10
- Python 3.11
- Python 3.12
- Python 3.13
- the full unit/regression suite
- DetectSpec validation
- an offline healthy smoke test
- JUnit test-result artifacts

Because DetectTrace returns non-zero for failed contracts, it can be used as a
detection regression gate.

A simple CI pattern is:

```bash
detecttrace test detections/example.yaml --profile healthy --format json > result.json
```

For a live Elastic runner with access to the target environment:

```bash
detecttrace elastic test detections/example.yaml \
  --rule-name "Example Rule" \
  --format junit > detecttrace.xml
```

Keep credentials in the CI secret store and provide the password through
`DETECTTRACE_ELASTIC_PASSWORD`.

## Security design

- DetectSpec is declarative and does not execute arbitrary Python or shell code.
- Secret fields are rejected from DetectTrace YAML configuration.
- Elasticsearch TLS verification remains enabled when a CA is configured.
- Test runs use explicit correlation IDs for end-to-end claims.
- Root-cause output is based on observed evidence.
- Unknown evidence is reported as `UNKNOWN`, not guessed.
- Downstream stages are `BLOCKED` after an upstream failure.
- File-backed evidence paths are constrained to the spec directory.

## Public CLI surface

The first-release CLI intentionally stays narrow:

```text
detecttrace validate
detecttrace test
detecttrace init
detecttrace doctor
detecttrace elastic test
```

Experimental or parked backend/debug commands are not exposed as part of the
public release surface.

## Project status

DetectTrace is under active development.

The first public release is intentionally focused on one strong path:

```text
DetectSpec
  -> deterministic tracing
  -> Elastic Security
  -> first-failing-stage diagnosis
  -> CI-friendly output
```

Additional SIEM backends, hosted dashboards, managed runners, large-scale
orchestration, AI remediation, and enterprise features are intentionally out of
scope for the initial release.

## Contributing

Issues and focused pull requests are welcome. Keep changes aligned with the
core goal:

> improve detection reliability, diagnosis, reproducibility, or developer
> workflow.

Avoid expanding DetectTrace into a general security platform.

## License

Apache-2.0.
