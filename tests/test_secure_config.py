from __future__ import annotations

import argparse
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from detecttrace.config import load_config, resolve_elastic_settings


class SecureConfigTests(unittest.TestCase):
    def _args(self, **overrides):
        values = {
            "config": None,
            "url": None,
            "kibana_url": None,
            "username": None,
            "index": None,
            "ca_cert": None,
            "insecure": False,
        }
        values.update(overrides)
        return argparse.Namespace(**values)

    def test_password_is_rejected_from_config(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "config.yaml"
            path.write_text(
                "config_version: detecttrace/config-v1\n"
                "elastic:\n"
                "  password: do-not-store-this\n",
                encoding="utf-8",
            )

            with self.assertRaisesRegex(
                ValueError,
                "Secrets are not allowed",
            ):
                load_config(str(path))

    def test_cli_overrides_environment_and_config(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "config.yaml"
            path.write_text(
                "config_version: detecttrace/config-v1\n"
                "elastic:\n"
                "  url: https://config.example:9200\n"
                "  username: config-user\n",
                encoding="utf-8",
            )

            args = self._args(
                config=str(path),
                url="https://cli.example:9200",
            )

            with patch.dict(
                os.environ,
                {
                    "DETECTTRACE_ELASTIC_URL":
                        "https://env.example:9200",
                    "DETECTTRACE_ELASTIC_USERNAME": "env-user",
                },
                clear=False,
            ):
                settings = resolve_elastic_settings(args)

            self.assertEqual(
                settings["url"],
                "https://cli.example:9200",
            )
            self.assertEqual(
                settings["username"],
                "env-user",
            )

    def test_insecure_and_ca_certificate_are_mutually_exclusive(self):
        with tempfile.TemporaryDirectory() as directory:
            ca = Path(directory) / "ca.crt"
            ca.write_text("not used", encoding="utf-8")

            args = self._args(
                ca_cert=str(ca),
                insecure=True,
            )

            with self.assertRaisesRegex(
                ValueError,
                "cannot be combined",
            ):
                resolve_elastic_settings(args)

    def test_missing_ca_certificate_has_clear_error(self):
        args = self._args(
            ca_cert="definitely-missing-http-ca.crt",
        )

        with self.assertRaisesRegex(
            ValueError,
            "CA certificate does not exist",
        ):
            resolve_elastic_settings(args)


if __name__ == "__main__":
    unittest.main()
