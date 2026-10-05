# DetectTrace local Elastic lab

This directory provides the reproducible Elasticsearch + Kibana environment
used by DetectTrace's Elastic end-to-end example.

It is a **local development lab**, not a production deployment.

## What it creates

- Elasticsearch 8.15.3 at `https://localhost:9201`
- Kibana 8.15.3 at `http://localhost:5602`
- Elasticsearch security enabled
- TLS enabled for Elasticsearch HTTP traffic
- persistent Elasticsearch data
- persistent CA/node certificates
- persistent Kibana encryption settings supplied from `.env`
- a `detecttrace-events` telemetry index
- containers named `detecttrace-es` and `detecttrace-kibana`

Both host ports bind only to `127.0.0.1`.

## Requirements

- Docker Desktop / Docker Engine with Compose v2
- about 2 GB of memory available to the Elasticsearch container
- DetectTrace installed

Run commands from `lab/elastic` unless noted otherwise.

## 1. Create the local environment file

PowerShell:

```powershell
Copy-Item .env.example .env
```

The example values are intended only for a localhost development lab.
Change the passwords/keys before first startup if the machine is shared.

`.env` is ignored by Git.

## 2. Start the lab

```powershell
docker compose up -d
```

Check container state:

```powershell
docker compose ps
```

Wait until Elasticsearch and Kibana report healthy.

Useful logs:

```powershell
docker compose logs -f setup
docker compose logs -f es01
docker compose logs -f kibana
```

The one-shot `setup` container exits successfully after it has:

1. generated the local CA and Elasticsearch node certificate,
2. waited for Elasticsearch,
3. configured the `kibana_system` password, and
4. created the `detecttrace-events` index if needed.

## 3. Export the public Elasticsearch CA for DetectTrace

From the repository root, create the local CA directory if needed:

```powershell
New-Item -ItemType Directory -Force .\certs | Out-Null
```

Then copy only the public CA certificate from the Docker volume:

```powershell
docker cp detecttrace-es:/usr/share/elasticsearch/config/certs/http_ca.crt .\certs\http_ca.crt
```

The repository's `.detecttrace.example.yaml` already expects:

```yaml
elastic:
  url: https://localhost:9201
  kibana_url: http://localhost:5602
  username: elastic
  index: detecttrace-events
  ca_cert: certs/http_ca.crt
```

Create the local config from the repository root if you do not already have one:

```powershell
Copy-Item .detecttrace.example.yaml .detecttrace.yaml
```

`.detecttrace.yaml` and `certs/` are local files and should remain untracked.

## 4. Verify the environment

From the repository root:

```powershell
detecttrace doctor
```

Enter the `ELASTIC_PASSWORD` value from `lab/elastic/.env` when prompted.

A ready environment should show PASS for:

- DetectTrace config
- Elasticsearch CA
- Elasticsearch
- telemetry index
- Kibana

## 5. Open Kibana

Browse to:

```text
http://localhost:5602
```

Sign in with:

```text
Username: elastic
Password: the ELASTIC_PASSWORD value from .env
```

## 6. Create the example detection rule

In Kibana, create and enable a custom query Elastic Security detection rule:

```text
Name:
DetectTrace - Encoded PowerShell

Index:
detecttrace-events

Query:
process.name : "powershell.exe" and process.command_line : "powershell.exe -enc AAA"

Severity:
Medium

Risk score:
50
```

A one-minute schedule with a small look-back window is suitable for this local
lab.

## 7. Run the correlated end-to-end test

From the repository root:

```powershell
detecttrace elastic test examples\elastic_live_detectspec.yaml `
  --rule-name "DetectTrace - Encoded PowerShell" `
  --case healthy
```

A successful run proves that the injected event, normalized telemetry,
DetectSpec rule evaluation, and Elastic Security alert all belong to the same
DetectTrace run ID.

## Stop the lab

Preserve data/certificates:

```powershell
docker compose down
```

Start it again later with:

```powershell
docker compose up -d
```

## Reset the lab completely

This destroys the Elasticsearch data volume and certificate volume:

```powershell
docker compose down -v
```

Then start again:

```powershell
docker compose up -d
```

After a full reset, copy the new CA certificate to `certs/http_ca.crt` again.

## Password changes

`ELASTIC_PASSWORD` initializes the built-in `elastic` account when the
Elasticsearch data volume is first created. Changing it in `.env` after the
volume already exists does not automatically change that account's password.

For a disposable local lab, the simplest clean credential reset is:

```powershell
docker compose down -v
docker compose up -d
```

Then export the newly generated CA again.

## Troubleshooting

If ports 9201 or 5602 are already in use, stop the older lab/containers before
starting this Compose project.

To inspect the current Compose configuration:

```powershell
docker compose config
```

To inspect service status:

```powershell
docker compose ps
```

To inspect the setup result:

```powershell
docker compose logs setup
```

DetectTrace should not require `--insecure` for this lab. If TLS verification
fails, confirm that `certs/http_ca.crt` was copied from the currently running
`detecttrace-es` container and that `.detecttrace.yaml` points to that file.
