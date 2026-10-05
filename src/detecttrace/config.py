from __future__ import annotations

import os
from pathlib import Path
import ssl
from typing import Any

import yaml


CONFIG_VERSION = "detecttrace/config-v1"

_ALLOWED_ROOT_KEYS = {"config_version", "elastic"}
_ALLOWED_ELASTIC_KEYS = {
    "url",
    "kibana_url",
    "username",
    "index",
    "ca_cert",
}
_FORBIDDEN_SECRET_KEYS = {
    "password",
    "api_key",
    "token",
}


def _default_config_candidates() -> list[Path]:
    return [
        Path.cwd() / ".detecttrace.yaml",
        Path.home() / ".detecttrace" / "config.yaml",
    ]


def load_config(
    explicit_path: str | None = None,
) -> tuple[dict[str, Any], Path | None]:
    """Load DetectTrace configuration without ever loading secrets."""

    configured = explicit_path or os.getenv("DETECTTRACE_CONFIG")

    if configured:
        path = Path(configured).expanduser()
        if not path.is_file():
            raise ValueError(
                f"DetectTrace config file does not exist: {path}"
            )
    else:
        path = next(
            (candidate for candidate in _default_config_candidates()
             if candidate.is_file()),
            None,
        )
        if path is None:
            return {}, None

    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        raise ValueError(
            f"Invalid YAML in DetectTrace config '{path}': {exc}"
        ) from exc

    if raw is None:
        raw = {}

    if not isinstance(raw, dict):
        raise ValueError(
            f"DetectTrace config '{path}' must contain a YAML mapping."
        )

    unknown_root = set(raw) - _ALLOWED_ROOT_KEYS
    if unknown_root:
        raise ValueError(
            "Unknown DetectTrace config key(s): "
            + ", ".join(sorted(str(key) for key in unknown_root))
        )

    version = raw.get("config_version", CONFIG_VERSION)
    if version != CONFIG_VERSION:
        raise ValueError(
            f"Unsupported DetectTrace config version '{version}'. "
            f"Expected '{CONFIG_VERSION}'."
        )

    elastic = raw.get("elastic", {})
    if elastic is None:
        elastic = {}
    if not isinstance(elastic, dict):
        raise ValueError(
            "DetectTrace config 'elastic' section must be a mapping."
        )

    forbidden = set(elastic) & _FORBIDDEN_SECRET_KEYS
    if forbidden:
        raise ValueError(
            "Secrets are not allowed in DetectTrace config files "
            f"({', '.join(sorted(forbidden))}). "
            "Use DETECTTRACE_ELASTIC_PASSWORD or the interactive prompt."
        )

    unknown_elastic = set(elastic) - _ALLOWED_ELASTIC_KEYS
    if unknown_elastic:
        raise ValueError(
            "Unknown DetectTrace elastic config key(s): "
            + ", ".join(sorted(str(key) for key in unknown_elastic))
        )

    return {
        "config_version": CONFIG_VERSION,
        "elastic": elastic,
    }, path.resolve()


def _pick(
    cli_value: Any,
    env_name: str,
    config_value: Any,
    default: Any,
) -> Any:
    if cli_value is not None:
        return cli_value

    env_value = os.getenv(env_name)
    if env_value not in (None, ""):
        return env_value

    if config_value not in (None, ""):
        return config_value

    return default


def resolve_elastic_settings(args: Any) -> dict[str, Any]:
    """Resolve secure Elastic settings using documented precedence."""

    config, config_path = load_config(
        getattr(args, "config", None)
    )
    elastic = config.get("elastic", {})

    url = _pick(
        getattr(args, "url", None),
        "DETECTTRACE_ELASTIC_URL",
        elastic.get("url"),
        "https://localhost:9201",
    )
    kibana_url = _pick(
        getattr(args, "kibana_url", None),
        "DETECTTRACE_KIBANA_URL",
        elastic.get("kibana_url"),
        "http://localhost:5602",
    )
    username = _pick(
        getattr(args, "username", None),
        "DETECTTRACE_ELASTIC_USERNAME",
        elastic.get("username"),
        "elastic",
    )
    index = _pick(
        getattr(args, "index", None),
        "DETECTTRACE_ELASTIC_INDEX",
        elastic.get("index"),
        "detecttrace-events",
    )

    cli_ca = getattr(args, "ca_cert", None)
    env_ca = os.getenv("DETECTTRACE_ELASTIC_CA_CERT")
    config_ca = elastic.get("ca_cert")

    if cli_ca not in (None, ""):
        ca_cert = Path(str(cli_ca)).expanduser()
    elif env_ca not in (None, ""):
        ca_cert = Path(env_ca).expanduser()
    elif config_ca not in (None, ""):
        ca_cert = Path(str(config_ca)).expanduser()
        if not ca_cert.is_absolute() and config_path is not None:
            ca_cert = config_path.parent / ca_cert
    else:
        ca_cert = None

    insecure = bool(getattr(args, "insecure", False))

    for label, value in (
        ("Elasticsearch URL", url),
        ("Kibana URL", kibana_url),
        ("Elastic username", username),
        ("telemetry index", index),
    ):
        if not isinstance(value, str) or not value.strip():
            raise ValueError(f"{label} must be a non-empty string.")

    if not (
        str(url).startswith("https://")
        or str(url).startswith("http://")
    ):
        raise ValueError(
            "Elasticsearch URL must start with http:// or https://."
        )

    if not (
        str(kibana_url).startswith("https://")
        or str(kibana_url).startswith("http://")
    ):
        raise ValueError(
            "Kibana URL must start with http:// or https://."
        )

    if insecure and ca_cert is not None:
        raise ValueError(
            "--insecure cannot be combined with a CA certificate. "
            "Remove --insecure for verified TLS."
        )

    resolved_ca: str | None = None
    if ca_cert is not None:
        ca_cert = ca_cert.resolve()

        if not ca_cert.is_file():
            raise ValueError(
                f"Elasticsearch CA certificate does not exist: {ca_cert}"
            )

        try:
            ssl.create_default_context(cafile=str(ca_cert))
        except (OSError, ssl.SSLError) as exc:
            raise ValueError(
                f"Elasticsearch CA certificate could not be loaded "
                f"from '{ca_cert}': {exc}"
            ) from exc

        resolved_ca = str(ca_cert)

    return {
        "url": str(url).rstrip("/"),
        "kibana_url": str(kibana_url).rstrip("/"),
        "username": str(username),
        "index": str(index),
        "ca_cert": resolved_ca,
        "insecure": insecure,
        "config_path": str(config_path) if config_path else None,
    }
