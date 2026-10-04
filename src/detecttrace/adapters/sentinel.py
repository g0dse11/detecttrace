from __future__ import annotations

import os
from datetime import timedelta

from azure.core.exceptions import AzureError
from azure.identity import DefaultAzureCredential
from azure.monitor.query import LogsQueryClient, LogsQueryStatus


class SentinelAdapter:
    """Microsoft Sentinel / Log Analytics adapter for DetectTrace."""

    LOG_ANALYTICS_SCOPE = "https://api.loganalytics.io/.default"

    def __init__(self, workspace_id: str | None = None) -> None:
        self.workspace_id = (
            workspace_id
            or os.getenv("DETECTTRACE_SENTINEL_WORKSPACE_ID")
            or os.getenv("LOGS_WORKSPACE_ID")
        )

        self.credential = DefaultAzureCredential(
            exclude_interactive_browser_credential=False
        )

        self.client = LogsQueryClient(self.credential)

    def check_authentication(self) -> tuple[bool, str]:
        """Prove that DetectTrace can obtain an Azure token."""

        try:
            self.credential.get_token(self.LOG_ANALYTICS_SCOPE)
            return True, "Azure authentication succeeded."
        except Exception as exc:
            return False, f"Azure authentication failed: {exc}"

    def check_workspace(self) -> tuple[bool, str]:
        """Check that a Log Analytics workspace ID is configured."""

        if not self.workspace_id:
            return (
                False,
                "No workspace configured. "
                "Set DETECTTRACE_SENTINEL_WORKSPACE_ID.",
            )

        return True, f"Workspace configured: {self.workspace_id}"

    def check_query(self) -> tuple[bool, str]:
        """Execute a harmless KQL query against Log Analytics."""

        if not self.workspace_id:
            return False, "Cannot query: workspace ID is not configured."

        try:
            response = self.client.query_workspace(
                workspace_id=self.workspace_id,
                query='print DetectTraceStatus="ok"',
                timespan=timedelta(minutes=5),
            )

            if response.status != LogsQueryStatus.SUCCESS:
                error = getattr(response, "partial_error", None)
                return False, f"Log Analytics query incomplete: {error}"

            if not response.tables:
                return False, "Query succeeded but returned no result table."

            return True, "Log Analytics query execution succeeded."

        except AzureError as exc:
            return False, f"Log Analytics query failed: {exc}"

    def status(self) -> dict[str, tuple[bool, str]]:
        """Run all currently supported Sentinel adapter health checks."""

        return {
            "authentication": self.check_authentication(),
            "workspace": self.check_workspace(),
            "query": self.check_query(),
        }