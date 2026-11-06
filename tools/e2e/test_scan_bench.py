"""Small offline tests for the benchmark's fail-closed acceptance gates."""
import copy
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import time
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("scan_bench", Path(__file__).with_name("scan-bench.py"))
bench = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bench)


class AcceptanceTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.output = self.root / "findings.jsonl"
        self.origins = ["http://127.0.0.1:12345", "http://127.0.0.1:23456"]
        self.findings = [{"template-id": bench.template_id(i), "type": "http",
                          "matched-at": origin + bench.request_path(i)}
                         for origin in self.origins for i in range(2)]

    def write_findings(self, findings):
        self.output.write_text("".join(json.dumps(f) + "\n" for f in findings))

    def baseline(self):
        cells = {}
        for cell in bench.MATRIX:
            samples = [{"seconds": seconds, "validated": True, "returncode": 0,
                        "request_count": cell["templates"] * cell["targets"],
                        "unique_pairs": cell["templates"] * cell["targets"]}
                       for seconds in (1.0, 2.0, 3.0)]
            cells[bench.cell_key(cell)] = {"workload": cell, "samples": samples, "median_seconds": 2.0}
        return {"schema_version": bench.SCHEMA, "metadata": {"test": "identity"}, "cells": cells}

    def test_exact_unique_pairs(self):
        self.write_findings(self.findings)
        self.assertEqual(bench.validate_jsonl(self.output, 2, self.origins), 4)

    def test_jsonl_missing_duplicate_unexpected_and_malformed(self):
        cases = [[], self.findings[:-1], self.findings + [self.findings[0]],
                 self.findings[:-1] + [self.findings[0]],
                 [{"type": "http", "template-id": "wrong", "matched-at": "http://127.0.0.1/"}],
                 [None], [{"type": "http", "template-id": []}],
                 [dict(self.findings[0], **{"matcher-status": False})]]
        for case in cases:
            with self.subTest(case=case):
                self.write_findings(case)
                with self.assertRaises(bench.BenchError):
                    bench.validate_jsonl(self.output, 2, self.origins)
        self.output.write_text("not JSON\n")
        with self.assertRaises(bench.BenchError):
            bench.validate_jsonl(self.output, 2, self.origins)

    def test_request_counts_check_pairs_not_only_total(self):
        counts = bench.Counter({(t, "GET", bench.request_path(i)): 1 for t in range(2) for i in range(2)})
        self.assertEqual(bench.validate_requests(counts, 2, 2), 4)
        counts[(0, "GET", bench.request_path(0))] = 2
        del counts[(1, "GET", bench.request_path(1))]
        self.assertEqual(sum(counts.values()), 4)
        with self.assertRaises(bench.BenchError):
            bench.validate_requests(counts, 2, 2)

    def test_baseline_rejects_old_partial_mismatched_and_bad_metrics(self):
        baseline = self.baseline()
        metadata = baseline["metadata"]
        bench.validate_baseline(baseline, metadata)
        cases = [{}, dict(baseline, schema_version=1), dict(baseline, metadata=42),
                 dict(baseline, metadata={"test": "different"}), dict(baseline, cells={})]
        key = next(iter(baseline["cells"]))
        for field, value in (("median_seconds", float("nan")), ("median_seconds", 0),
                             ("median_seconds", 3), ("samples", [])):
            candidate = copy.deepcopy(baseline)
            candidate["cells"][key][field] = value
            cases.append(candidate)
        for field, value in (("returncode", 23), ("validated", False), ("request_count", 4),
                             ("unique_pairs", 0), ("seconds", -1), ("seconds", float("inf"))):
            candidate = copy.deepcopy(baseline)
            candidate["cells"][key]["samples"][0][field] = value
            cases.append(candidate)
        for case in cases:
            with self.subTest(case=case), self.assertRaises(bench.BenchError):
                bench.validate_baseline(case, metadata)

    def test_regression_threshold_is_strictly_greater_than_tolerance(self):
        baseline = self.baseline()["cells"]
        measured = copy.deepcopy(baseline)
        for entry in measured.values():
            entry["median_seconds"] = 3.2
        self.assertFalse(any(v["regression"] for v in bench.compare_cells(measured, baseline, 0.6).values()))
        next(iter(measured.values()))["median_seconds"] = 3.2001
        self.assertTrue(any(v["regression"] for v in bench.compare_cells(measured, baseline, 0.6).values()))

    def test_nonzero_and_empty_success_cannot_accept_timing(self):
        for rc in (23, 0):
            work = self.root / ("work-%d" % rc)
            work.mkdir()

            def fake_run(command, **kwargs):
                kwargs["stderr"].write("deliberate scanner failure\n")
                return subprocess.CompletedProcess(command, rc)

            with patch.object(bench.subprocess, "run", side_effect=fake_run):
                with self.assertRaises(bench.BenchError) as caught:
                    bench.run_sample("nuclei", work, bench.MATRIX[0], 0, self.root, work,
                                     time.monotonic() + 10)
            self.assertEqual(caught.exception.details["returncode"], rc)
            self.assertIn("deliberate scanner failure", caught.exception.details["stderr"])
            self.assertNotIn("seconds", caught.exception.details)

    def test_atomic_baseline_preserves_artifact_references(self):
        report = self.baseline()
        key = next(iter(report["cells"]))
        report["cells"][key]["samples"][0]["stdout_file"] = "sample.jsonl"
        path = self.root / "baseline.json"
        bench.atomic_baseline(path, report)
        saved = json.loads(path.read_text())
        bench.validate_baseline(saved, report["metadata"])
        self.assertNotIn("stdout_file", saved["cells"][key]["samples"][0])
        self.assertIn("stdout_file", report["cells"][key]["samples"][0])

    def test_cli_defaults_and_fixed_full_matrix(self):
        args = bench.argument_parser().parse_args([])
        self.assertEqual(args.image, "jingwei:1.5.0")
        self.assertEqual(args.output_dir, Path("/tmp"))
        self.assertEqual(args.tolerance, 0.6)
        self.assertEqual(len(bench.MATRIX), 18)
        self.assertEqual({c["rate"] for c in bench.MATRIX}, {500})
        self.assertIn("-disable-clustering", bench.FLAGS)
        self.assertIn("-disable-redirects", bench.FLAGS)


if __name__ == "__main__":
    unittest.main()
