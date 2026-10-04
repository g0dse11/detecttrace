from pathlib import Path
import unittest

from detecttrace.engine import TraceEngine
from detecttrace.models import Status
from detecttrace.spec import load_spec


ROOT = Path(__file__).resolve().parents[1]
SPEC_PATH = ROOT / "examples" / "powershell" / "detectspec.yaml"


class EngineTests(unittest.TestCase):
    def setUp(self):
        self.spec = load_spec(SPEC_PATH)
        self.engine = TraceEngine()

    def test_broken_profile_finds_normalization_root_cause(self):
        result = self.engine.run(self.spec, SPEC_PATH, "broken")
        statuses = {s.name: s.status for s in result.stages}
        self.assertEqual(statuses["execution"], Status.PASS)
        self.assertEqual(statuses["source"], Status.PASS)
        self.assertEqual(statuses["collector"], Status.PASS)
        self.assertEqual(statuses["normalization"], Status.FAIL)
        self.assertEqual(statuses["rule"], Status.BLOCKED)
        self.assertEqual(statuses["alert"], Status.BLOCKED)
        self.assertIn("process.command_line", result.root_cause)
        self.assertIn("process.args", result.root_cause)

    def test_healthy_profile_passes(self):
        result = self.engine.run(self.spec, SPEC_PATH, "healthy")
        self.assertTrue(result.healthy)
        self.assertTrue(all(s.status == Status.PASS for s in result.stages))


if __name__ == "__main__":
    unittest.main()
