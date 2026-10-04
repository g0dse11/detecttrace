import unittest
from detecttrace.rules import evaluate


class RuleTests(unittest.TestCase):
    def test_composition(self):
        event = {"process": {"name": "powershell.exe", "command_line": "powershell -enc AAA"}}
        rule = {
            "all": [
                {"field": "process.name", "op": "endswith", "value": "powershell.exe"},
                {
                    "any": [
                        {"field": "process.command_line", "op": "contains", "value": "-enc"},
                        {"field": "process.command_line", "op": "contains", "value": "-EncodedCommand"},
                    ]
                },
            ]
        }
        self.assertTrue(evaluate(event, rule))

    def test_missing_field_does_not_match(self):
        self.assertFalse(evaluate({}, {"field": "x.y", "op": "equals", "value": 1}))


if __name__ == "__main__":
    unittest.main()
