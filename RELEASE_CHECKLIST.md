# DetectTrace v0.13 Release-Candidate Checklist

This milestone adds no detection capability. It exists to prove that the
release artifact, documentation surface, tests, and real Elastic path are
coherent before a public release.

## Automated release check

From the repository root:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\release_check.ps1
```

This must pass all of the following:

- required release files exist
- no local config, CA material, virtual environments, build directories, or
  package metadata directories are tracked accidentally
- full unit/regression suite passes
- offline example DetectSpecs validate
- offline healthy example passes
- wheel builds
- source distribution builds
- built wheel installs into a fresh virtual environment
- installed `detecttrace --version` matches `pyproject.toml`
- installed wheel can `init`, `validate`, and `test` a fresh starter project

The script builds and tests in a temporary directory and cleans it afterwards.

## Live Elastic release check

The live check uses the **built wheel**, not the editable development install.

Requirements:

1. `lab/elastic` is running and healthy.
2. `certs/http_ca.crt` is the CA for that running lab.
3. `.detecttrace.yaml` points to the current lab.
4. The Elastic Security rule `DetectTrace - Encoded PowerShell` exists and is
   enabled.
5. `DETECTTRACE_ELASTIC_PASSWORD` is set in the current PowerShell process.

Load the lab password without printing it:

```powershell
$line = Get-Content .\lab\elastic\.env |
    Where-Object { $_ -match '^ELASTIC_PASSWORD=' } |
    Select-Object -First 1

$env:DETECTTRACE_ELASTIC_PASSWORD = $line.Substring(
    'ELASTIC_PASSWORD='.Length
)
```

Run:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\release_check.ps1 -Live
```

The live portion must pass:

- `detecttrace doctor`
- exact-run correlated healthy Elastic test
- rule existence
- rule enabled state
- rule execution evidence
- correlated alert
- verified TLS

Remove the password from the shell afterwards:

```powershell
Remove-Item Env:DETECTTRACE_ELASTIC_PASSWORD
```

## GitHub CI

The latest commit must have all CI matrix jobs green:

- Python 3.10
- Python 3.11
- Python 3.12
- Python 3.13

## Repository review

Before tagging the release candidate:

```powershell
git status
git diff --cached --stat
git ls-files
```

Confirm that these local files are **not** tracked:

```text
.detecttrace.yaml
lab/elastic/.env
certs/http_ca.crt
.venv/
build/
dist/
*.egg-info/
```

Confirm that these release assets **are** tracked:

```text
README.md
LICENSE
schemas/detectspec-v1.schema.json
.detecttrace.example.yaml
lab/elastic/compose.yml
lab/elastic/.env.example
lab/elastic/README.md
.github/workflows/ci.yml
scripts/release_check.ps1
```

## Release-candidate acceptance

v0.13 is accepted only when:

- automated release check passes
- live release check passes
- GitHub CI is green
- working tree is clean after commit
- no new product feature was added during this milestone

Anything discovered here that is a correctness, security, packaging, or
release-blocking defect is **REQUIRED NOW**.

Everything else is **DEFER** until after the first public release.
