from __future__ import annotations

import base64
import json
import ssl
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from .adapters.elastic import ElasticAdapter


def _check(
    name: str,
    status: str,
    summary: str,
) -> dict[str, str]:
    return {
        "name": name,
        "status": status,
        "summary": summary,
    }


def check_kibana(
    kibana_url: str,
    username: str,
    password: str | None,
) -> tuple[bool, str]:
    """Perform a read-only Kibana status request."""

    headers = {
        "Accept": "application/json",
        "kbn-xsrf": "true",
    }

    if password:
        token = base64.b64encode(
            f"{username}:{password}".encode("utf-8")
        ).decode("ascii")
        headers["Authorization"] = f"Basic {token}"

    request = Request(
        f"{kibana_url.rstrip('/')}/api/status",
        headers=headers,
        method="GET",
    )

    context = None
    if kibana_url.startswith("https://"):
        context = ssl.create_default_context()

    try:
        with urlopen(
            request,
            timeout=10,
            context=context,
        ) as response:
            payload = response.read().decode("utf-8")
    except HTTPError as exc:
        if exc.code in (401, 403):
            return False, (
                f"Kibana authentication failed: HTTP {exc.code}."
            )
        return False, f"Kibana status check failed: HTTP {exc.code}."
    except (URLError, TimeoutError, OSError) as exc:
        return False, f"Kibana connection failed: {exc}"

    overall = None
    if payload:
        try:
            decoded = json.loads(payload)
            overall = (
                decoded.get("status", {})
                .get("overall", {})
                .get("level")
            )
        except (json.JSONDecodeError, AttributeError):
            overall = None

    if overall:
        return True, (
            f"Kibana is reachable at {kibana_url} "
            f"(overall status: {overall})."
        )

    return True, f"Kibana is reachable at {kibana_url}."


def run_doctor(
    settings: dict[str, Any],
    password: str | None,
) -> dict[str, Any]:
    """Run read-only environment checks for the Elastic DetectTrace path."""

    checks: list[dict[str, str]] = []

    config_path = settings.get("config_path")
    if config_path:
        checks.append(
            _check(
                "DetectTrace config",
                "PASS",
                f"Loaded and validated {config_path}.",
            )
        )
    else:
        checks.append(
            _check(
                "DetectTrace config",
                "UNKNOWN",
                (
                    "No config file was found. DetectTrace is using "
                    "environment variables and/or defaults."
                ),
            )
        )

    elastic_url = str(settings["url"])

    if elastic_url.startswith("https://"):
        ca_cert = settings.get("ca_cert")
        if ca_cert:
            checks.append(
                _check(
                    "Elasticsearch CA",
                    "PASS",
                    f"CA certificate loaded from {ca_cert}.",
                )
            )
        else:
            checks.append(
                _check(
                    "Elasticsearch CA",
                    "UNKNOWN",
                    (
                        "No custom CA certificate is configured. "
                        "Python system trust will be used."
                    ),
                )
            )
    else:
        checks.append(
            _check(
                "Elasticsearch CA",
                "UNKNOWN",
                (
                    "Elasticsearch is configured over HTTP, so no TLS "
                    "certificate is available to verify."
                ),
            )
        )

    adapter = ElasticAdapter(
        base_url=settings["url"],
        username=settings["username"],
        password=password,
        verify_tls=True,
        ca_cert=settings.get("ca_cert"),
    )

    es_ok, es_summary = adapter.check_connection()
    checks.append(
        _check(
            "Elasticsearch",
            "PASS" if es_ok else "FAIL",
            es_summary,
        )
    )

    if es_ok:
        index_ok, index_summary = adapter.check_index(
            settings["index"]
        )
        checks.append(
            _check(
                "Telemetry index",
                "PASS" if index_ok else "FAIL",
                index_summary,
            )
        )
    else:
        index_ok = False
        checks.append(
            _check(
                "Telemetry index",
                "UNKNOWN",
                (
                    "Not checked because Elasticsearch connectivity "
                    "or authentication failed."
                ),
            )
        )

    kibana_ok, kibana_summary = check_kibana(
        settings["kibana_url"],
        settings["username"],
        password,
    )
    checks.append(
        _check(
            "Kibana",
            "PASS" if kibana_ok else "FAIL",
            kibana_summary,
        )
    )

    healthy = es_ok and index_ok and kibana_ok

    return {
        "healthy": healthy,
        "checks": checks,
        "config_path": config_path,
    }
