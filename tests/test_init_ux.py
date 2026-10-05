from __future__ import annotations

from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path
import tempfile
import unittest

from detecttrace.cli import main
from detecttrace.spec import load_spec


class InitUXTests(unittest.TestCase):
    def test_init_creates_valid_runnable_project(self):
        with tempfile.TemporaryDirectory() as tmp:
            project = Path(tmp) / "starter"

            with redirect_stdout(StringIO()):
                code = main(["init", str(project)])

            self.assertEqual(code, 0)

            expected = {
                "detectspec.yaml",
                "execution.json",
                "source.jsonl",
                "collector.jsonl",
                "normalized.jsonl",
                "alerts.jsonl",
                "README.md",
            }
            self.assertTrue(
                expected.issubset(
                    {path.name for path in project.iterdir()}
                )
            )

            spec = load_spec(project / "detectspec.yaml")
            self.assertEqual(spec["id"], "DET-EXAMPLE-001")

            with redirect_stdout(StringIO()):
                test_code = main(
                    ["test", str(project / "detectspec.yaml")]
                )

            self.assertEqual(test_code, 0)

    def test_init_refuses_to_overwrite_without_force(self):
        with tempfile.TemporaryDirectory() as tmp:
            project = Path(tmp) / "starter"

            with redirect_stdout(StringIO()):
                self.assertEqual(
                    main(["init", str(project)]),
                    0,
                )

            output = StringIO()
            with redirect_stdout(output):
                code = main(["init", str(project)])

            self.assertEqual(code, 2)

    def test_force_recreates_starter(self):
        with tempfile.TemporaryDirectory() as tmp:
            project = Path(tmp) / "starter"

            with redirect_stdout(StringIO()):
                self.assertEqual(
                    main(["init", str(project)]),
                    0,
                )

            spec_path = project / "detectspec.yaml"
            spec_path.write_text("broken: true\n", encoding="utf-8")

            with redirect_stdout(StringIO()):
                code = main(
                    ["init", str(project), "--force"]
                )

            self.assertEqual(code, 0)
            spec = load_spec(spec_path)
            self.assertEqual(
                spec["spec_version"],
                "detectspec/v1",
            )

    def test_generated_readme_contains_first_run_commands(self):
        with tempfile.TemporaryDirectory() as tmp:
            project = Path(tmp) / "starter"

            with redirect_stdout(StringIO()):
                main(["init", str(project)])

            readme = (project / "README.md").read_text(
                encoding="utf-8"
            )

            self.assertIn(
                "detecttrace validate detectspec.yaml",
                readme,
            )
            self.assertIn(
                "detecttrace test detectspec.yaml",
                readme,
            )


if __name__ == "__main__":
    unittest.main()
