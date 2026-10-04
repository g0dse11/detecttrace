from __future__ import annotations

import json
import os
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import Request, urlopen


class ElasticAdapter:
    """Elasticsearch adapter for DetectTrace."""

    def __init__(self, base_url: str | None = None) -> None:
        self.base_url = (
            base_url
            or os.getenv("DETECTTRACE_ELASTIC_URL")
            or "http://localhost:9200"
        ).rstrip("/")

    def _request(
        self,
        method: str,
        path: str,
        body: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        data = None
        headers = {"Accept": "application/json"}

        if body is not None:
            data = json.dumps(body).encode("utf-8")
            headers["Content-Type"] = "application/json"

        request = Request(
            f"{self.base_url}{path}",
            data=data,
            headers=headers,
            method=method,
        )

        with urlopen(request, timeout=10) as response:
            payload = response.read().decode("utf-8")
            return json.loads(payload) if payload else {}

    def check_connection(self) -> tuple[bool, str]:
        try:
            response = self._request("GET", "/")
            version = response.get("version", {}).get("number", "unknown")
            cluster = response.get("cluster_name", "unknown")
            return True, (
                f"Connected to Elasticsearch {version} "
                f"(cluster: {cluster})."
            )
        except (HTTPError, URLError, TimeoutError, OSError) as exc:
            return False, f"Elasticsearch connection failed: {exc}"

    def check_index(self, index: str = "detecttrace-events") -> tuple[bool, str]:
        try:
            response = self._request("GET", f"/{quote(index)}/_count")
            count = response.get("count", 0)
            return True, f"Index '{index}' contains {count} document(s)."
        except HTTPError as exc:
            if exc.code == 404:
                return False, f"Index '{index}' does not exist."
            return False, f"Index check failed: HTTP {exc.code}."
        except (URLError, TimeoutError, OSError) as exc:
            return False, f"Index check failed: {exc}"

    def search(
        self,
        index: str,
        query: dict[str, Any],
        size: int = 10,
    ) -> list[dict[str, Any]]:
        response = self._request(
            "POST",
            f"/{quote(index)}/_search",
            {
                "size": size,
                "query": query,
            },
        )
        return response.get("hits", {}).get("hits", [])

    def find_process(
        self,
        process_name: str,
        index: str = "detecttrace-events",
    ) -> list[dict[str, Any]]:
        return self.search(
            index=index,
            query={
                "term": {
                    "process.name.keyword": process_name,
                }
            },
        )

    def status(
        self,
        index: str = "detecttrace-events",
    ) -> dict[str, tuple[bool, str]]:
        connection = self.check_connection()

        if not connection[0]:
            return {
                "connection": connection,
                "index": (False, "Blocked: Elasticsearch is unavailable."),
            }

        return {
            "connection": connection,
            "index": self.check_index(index),
        }
