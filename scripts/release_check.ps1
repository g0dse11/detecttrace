param(
    [switch]$Live,
    [string]$RuleName = "DetectTrace - Encoded PowerShell"
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

function Write-Step([string]$Message) {
    Write-Host ""
    Write-Host "==> $Message"
}

function Invoke-Checked {
    param(
        [Parameter(Mandatory = $true)]
        [string]$FilePath,

        [Parameter(Mandatory = $false)]
        [string[]]$Arguments = @()
    )

    & $FilePath @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "Command failed with exit code $LASTEXITCODE`: $FilePath $($Arguments -join ' ')"
    }
}

$repo = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
Push-Location $repo

$tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) (
    "detecttrace-release-" + [guid]::NewGuid().ToString("N")
)

try {
    New-Item -ItemType Directory -Force $tempRoot | Out-Null

    Write-Step "Read package version"
    $pyprojectText = Get-Content ".\pyproject.toml" -Raw
    if ($pyprojectText -notmatch '(?m)^version\s*=\s*"([^"]+)"') {
        throw "Could not read project version from pyproject.toml."
    }
    $version = $Matches[1]
    Write-Host "DetectTrace version: $version"

    Write-Step "Verify required release files"
    foreach ($path in @(
        ".\README.md",
        ".\LICENSE",
        ".\pyproject.toml",
        ".\schemas\detectspec-v1.schema.json",
        ".\.github\workflows\ci.yml",
        ".\lab\elastic\compose.yml",
        ".\lab\elastic\README.md"
    )) {
        if (-not (Test-Path $path -PathType Leaf)) {
            throw "Required release file is missing: $path"
        }
        Write-Host "PASS  $path"
    }

    Write-Step "Audit tracked files for local secrets/build junk"
    $tracked = @(git ls-files)
    if ($LASTEXITCODE -ne 0) {
        throw "git ls-files failed."
    }

    $forbiddenPatterns = @(
        '(^|/)\.detecttrace\.yaml$',
        '(^|/)lab/elastic/\.env$',
        '(^|/)certs/',
        '(^|/)\.venv/',
        '(^|/)build/',
        '(^|/)dist/',
        '\.egg-info/',
        '(^|/)TEST_RESULTS\.txt$'
    )

    $badTracked = @()
    foreach ($file in $tracked) {
        foreach ($pattern in $forbiddenPatterns) {
            if ($file -match $pattern) {
                $badTracked += $file
                break
            }
        }
    }

    if ($badTracked.Count -gt 0) {
        Write-Host "Forbidden tracked file(s):"
        $badTracked | Sort-Object -Unique | ForEach-Object {
            Write-Host "  $_"
        }
        throw "Release audit found local secrets or build artifacts tracked by Git."
    }
    Write-Host "PASS  No forbidden local/build files are tracked."

    Write-Step "Run full unit/regression suite"
    Invoke-Checked "python" @(
        "-m", "unittest", "discover",
        "-s", "tests",
        "-v"
    )

    Write-Step "Validate repository examples"
    Invoke-Checked "python" @(
        "-m", "detecttrace.cli",
        "validate",
        "examples\powershell\detectspec.yaml"
    )
    Invoke-Checked "python" @(
        "-m", "detecttrace.cli",
        "validate",
        "examples\elastic_live_detectspec.yaml"
    )

    Write-Step "Run repository offline healthy smoke test"
    Invoke-Checked "python" @(
        "-m", "detecttrace.cli",
        "test",
        "examples\powershell\detectspec.yaml",
        "--profile", "healthy"
    )

    Write-Step "Create isolated build environment"
    $buildVenv = Join-Path $tempRoot "build-venv"
    Invoke-Checked "python" @("-m", "venv", $buildVenv)

    $buildPython = Join-Path $buildVenv "Scripts\python.exe"
    Invoke-Checked $buildPython @(
        "-m", "pip", "install",
        "--disable-pip-version-check",
        "build"
    )

    Write-Step "Build wheel and source distribution"
    $dist = Join-Path $tempRoot "dist"
    Invoke-Checked $buildPython @(
        "-m", "build",
        "--outdir", $dist,
        $repo
    )

    $wheel = Get-ChildItem $dist -Filter "*.whl" |
        Select-Object -First 1
    $sdist = Get-ChildItem $dist -Filter "*.tar.gz" |
        Select-Object -First 1

    if (-not $wheel) {
        throw "Wheel was not produced."
    }
    if (-not $sdist) {
        throw "Source distribution was not produced."
    }

    Write-Host "PASS  Wheel: $($wheel.Name)"
    Write-Host "PASS  sdist: $($sdist.Name)"

    if ($wheel.Name -notmatch [regex]::Escape($version)) {
        throw "Wheel filename does not contain expected version $version."
    }
    if ($sdist.Name -notmatch [regex]::Escape($version)) {
        throw "sdist filename does not contain expected version $version."
    }

    Write-Step "Install built wheel into a fresh virtual environment"
    $smokeVenv = Join-Path $tempRoot "smoke-venv"
    Invoke-Checked "python" @("-m", "venv", $smokeVenv)

    $smokePython = Join-Path $smokeVenv "Scripts\python.exe"
    $smokeExe = Join-Path $smokeVenv "Scripts\detecttrace.exe"

    Invoke-Checked $smokePython @(
        "-m", "pip", "install",
        "--disable-pip-version-check",
        $wheel.FullName
    )

    $reportedVersion = (& $smokeExe --version | Out-String).Trim()
    if ($LASTEXITCODE -ne 0) {
        throw "Installed detecttrace --version failed."
    }

    Write-Host $reportedVersion
    if ($reportedVersion -ne "detecttrace $version") {
        throw (
            "Installed package version mismatch. " +
            "Expected 'detecttrace $version', got '$reportedVersion'."
        )
    }

    Write-Step "Run first-use flow from installed wheel"
    $starter = Join-Path $tempRoot "starter"

    Invoke-Checked $smokeExe @(
        "init", $starter
    )
    Invoke-Checked $smokeExe @(
        "validate",
        (Join-Path $starter "detectspec.yaml")
    )
    Invoke-Checked $smokeExe @(
        "test",
        (Join-Path $starter "detectspec.yaml")
    )

    if ($Live) {
        Write-Step "Run live Elastic release checks from installed wheel"

        if (-not $env:DETECTTRACE_ELASTIC_PASSWORD) {
            throw (
                "-Live requires DETECTTRACE_ELASTIC_PASSWORD to be set " +
                "in the current PowerShell session."
            )
        }

        if (-not (Test-Path ".\.detecttrace.yaml" -PathType Leaf)) {
            throw (
                "-Live requires the local .detecttrace.yaml environment " +
                "configuration."
            )
        }

        Invoke-Checked $smokeExe @("doctor")

        Invoke-Checked $smokeExe @(
            "elastic", "test",
            "examples\elastic_live_detectspec.yaml",
            "--rule-name", $RuleName,
            "--case", "healthy"
        )
    }
    else {
        Write-Host ""
        Write-Host "LIVE CHECKS: SKIPPED"
        Write-Host (
            "Run this script again with -Live after setting " +
            "DETECTTRACE_ELASTIC_PASSWORD and ensuring the example " +
            "Elastic rule exists."
        )
    }

    Write-Host ""
    Write-Host "============================================================"
    Write-Host "DETECTTRACE RELEASE CHECK: PASS"
    Write-Host "Version: $version"
    Write-Host "Temporary artifacts: $tempRoot"
    Write-Host "============================================================"
}
finally {
    Pop-Location

    if (Test-Path $tempRoot) {
        Remove-Item $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
    }
}
