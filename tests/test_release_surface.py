from __future__ import annotations

import argparse
from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
import unittest

from detecttrace.cli import build_parser, main


def _subcommand_choices(parser: argparse.ArgumentParser) -> set[str]:
    for action in parser._actions:
        if isinstance(action, argparse._SubParsersAction):
            return set(action.choices)
    return set()


class ReleaseCLISurfaceTests(unittest.TestCase):
    def test_top_level_surface_is_release_scoped(self):
        parser = build_parser()
        commands = _subcommand_choices(parser)

        self.assertEqual(
            commands,
            {"validate", "test", "init", "doctor", "elastic"},
        )

    def test_parked_sentinel_command_is_not_parseable(self):
        stdout = StringIO()
        stderr = StringIO()

        with redirect_stdout(stdout), redirect_stderr(stderr):
            with self.assertRaises(SystemExit) as raised:
                main(["sentinel", "status"])

        self.assertEqual(raised.exception.code, 2)

    def test_elastic_surface_exposes_only_correlated_test(self):
        parser = build_parser()

        root_subparsers = next(
            action
            for action in parser._actions
            if isinstance(action, argparse._SubParsersAction)
        )

        elastic_parser = root_subparsers.choices["elastic"]
        elastic_commands = _subcommand_choices(elastic_parser)

        self.assertEqual(elastic_commands, {"test"})

    def test_version_flag_remains_available(self):
        stdout = StringIO()
        stderr = StringIO()

        with redirect_stdout(stdout), redirect_stderr(stderr):
            with self.assertRaises(SystemExit) as raised:
                main(["--version"])

        self.assertEqual(raised.exception.code, 0)
        self.assertIn("detecttrace", stdout.getvalue().lower())


if __name__ == "__main__":
    unittest.main()
