"""Regression tests for report correctness; run with python -m unittest discover -s scripts."""
import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location("rars_coverage", Path(__file__).with_name("coverage.py"))
coverage = importlib.util.module_from_spec(spec)
spec.loader.exec_module(coverage)


class CoverageTests(unittest.TestCase):
    def test_zero_count_test_helpers_do_not_inflate_production_denominators(self):
        filename = str(coverage.ROOT / "crates/rars/src/example.rs")
        functions = [
            {"name": "helper", "count": 0, "filenames": [filename], "regions": [[10, 1, 12, 2, 0, 0, 0, 0]]},
            {"name": "prod_test_instantiation", "count": 0, "filenames": [filename], "regions": [[20, 1, 22, 2, 0, 0, 0, 0]]},
            {"name": "prod_live_instantiation", "count": 3, "filenames": [filename], "regions": [[20, 1, 22, 2, 3, 0, 0, 0]], "branches": [[21, 1, 21, 9, 3, 0, 0, 0, 4]]},
            {"name": "missing", "count": 0, "filenames": [filename], "regions": [[30, 1, 32, 2, 0, 0, 0, 0]]},
        ]
        names = {"helper": "rars::helper", "prod_test_instantiation": "rars::run::<rars::tests::Callback>", "prod_live_instantiation": "rars::run::<Real>", "missing": "rars::missing"}
        sources = {filename: {"test_ranges": [[9, 12]], "declarations": []}}
        rows, missing, _ = coverage.summarize({"functions": functions}, {filename: {10: 0, 20: 3, 21: 0, 30: 0}}, sources, names)
        self.assertEqual(rows[0]["functions"], {"covered": 1, "total": 2})
        self.assertEqual(rows[0]["regions"], {"covered": 1, "total": 2})
        self.assertEqual(rows[0]["lines"], {"covered": 1, "total": 3})
        self.assertEqual(rows[0]["branches"], {"covered": 1, "total": 2})
        self.assertEqual([entry["names"] for entry in missing], [["rars::missing"]])
        self.assertEqual(rows[0]["uncovered_lines"], [21, 30])

    def test_lcov_preserves_uncovered_lines_and_unions_duplicate_objects(self):
        self.assertEqual(coverage.read_lcov("SF:a.rs\nDA:1,0\nDA:2,7\nend_of_record\nSF:a.rs\nDA:1,3\nDA:2,0\n"), {"a.rs": {1: 3, 2: 7}})

    def test_objects_come_from_cargo_not_a_guessed_artifact_layout(self):
        messages = '\n'.join([
            '{"reason":"compiler-artifact","executable":"/build/debug/deps/test-123"}',
            '{"reason":"compiler-artifact","executable":"/build/debug/build/rars/456/out/test-456"}',
            '{"reason":"compiler-artifact","executable":null,"filenames":["/build/library.rlib"]}',
            'non-JSON compiler diagnostic',
        ])
        self.assertEqual([str(p) for p in coverage.artifact_objects(messages)], ["/build/debug/deps/test-123", "/build/debug/build/rars/456/out/test-456"])

    def test_only_namespace_tests_are_excluded(self):
        self.assertTrue(coverage.test_symbol("rars::tests::example"))
        self.assertFalse(coverage.test_symbol("rars::extract::<rars::tests::Sink>"))


if __name__ == "__main__":
    unittest.main()
