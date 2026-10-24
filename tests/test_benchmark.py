import json
import pathlib
import tempfile
import unittest
from appsec_agent.benchmark import evaluate, load_corpus


class BenchmarkTests(unittest.TestCase):
    def setUp(self):
        self.repo = pathlib.Path(__file__).resolve().parents[1]
        self.corpus = self.repo / "benchmarks" / "corpus.json"
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.predictions = pathlib.Path(self.tmp.name) / "predictions.json"

    def test_corpus_has_unique_labeled_positive_and_negative_cases(self):
        corpus = load_corpus(self.corpus)
        self.assertEqual(len(corpus["cases"]), 8)
        self.assertTrue(any(c["label"] for c in corpus["cases"]))
        self.assertTrue(any(not c["label"] for c in corpus["cases"]))

    def test_metric_calculation(self):
        corpus = load_corpus(self.corpus)
        predictions = {c["id"]: c["label"] for c in corpus["cases"]}
        predictions["headers-negative-1"] = True
        self.predictions.write_text(json.dumps({"predictions": predictions, "runtime_seconds": 2.5,
                                                "request_count": 8, "model_cost_usd": 0.01}))
        report = evaluate(self.corpus, self.predictions)
        self.assertEqual((report["true_positive"], report["false_positive"], report["false_negative"]), (4, 1, 0))
        self.assertAlmostEqual(report["precision"], 0.8)
        self.assertEqual(report["runtime_seconds"], 2.5)
        self.assertEqual(report["request_count"], 8)

    def test_incomplete_or_extra_predictions_rejected(self):
        self.predictions.write_text(json.dumps({"predictions": {}}))
        with self.assertRaises(ValueError): evaluate(self.corpus, self.predictions)

    def test_negative_cost_rejected(self):
        corpus = load_corpus(self.corpus)
        self.predictions.write_text(json.dumps({"predictions": {c["id"]: c["label"] for c in corpus["cases"]},
                                                "model_cost_usd": -1}))
        with self.assertRaises(ValueError): evaluate(self.corpus, self.predictions)


    def test_regression_thresholds_compare_quality_and_resource_metrics(self):
        from appsec_agent.benchmark import compare_to_baseline
        baseline = {"baseline_id": "measured-fixture-v1", "measured_baseline": True,
                    "provenance": {"source": "isolated-test-fixture", "collected_at": "2026-10-24", "corpus_sha256": "a" * 64, "scanner_versions": {"fixture": "1.0"}},
                    "precision": 0.9, "recall": 0.8, "f1": 0.847,
                    "runtime_seconds": 10.0, "request_count": 20, "model_cost_usd": 0.02}
        thresholds = {"precision_min_delta": 0.02, "recall_min_delta": 0.02, "f1_min_delta": 0.02,
                      "runtime_max_increase_pct": 20, "request_count_max_increase_pct": 10,
                      "model_cost_max_increase_pct": 10}
        current = {"precision": 0.89, "recall": 0.79, "f1": 0.84,
                   "runtime_seconds": 11.0, "request_count": 21, "model_cost_usd": 0.021}
        self.assertTrue(compare_to_baseline(current, baseline, thresholds)["passed"])
        current["model_cost_usd"] = 0.03
        result = compare_to_baseline(current, baseline, thresholds)
        self.assertFalse(result["passed"])
        self.assertEqual(result["violations"][0]["metric"], "model_cost_usd")


    def test_cli_benchmark_compare_passes_or_returns_nonzero_on_regression(self):
        import subprocess, sys
        repo = pathlib.Path(__file__).resolve().parents[1]
        comparison = pathlib.Path(self.tmp.name) / "comparison.json"
        baseline = {"baseline_id": "fixture-v1", "measured_baseline": True,
                    "provenance": {"source": "isolated-test-fixture", "collected_at": "2026-10-24", "corpus_sha256": "b" * 64, "scanner_versions": {"fixture": "1.0"}},
                    "precision": 0.9, "recall": 0.9, "f1": 0.9,
                    "runtime_seconds": 10, "request_count": 10, "model_cost_usd": 0.01}
        current = {key: baseline[key] for key in ("precision", "recall", "f1", "runtime_seconds", "request_count", "model_cost_usd")}
        thresholds = {"precision_min_delta": 0, "recall_min_delta": 0, "f1_min_delta": 0,
                      "runtime_max_increase_pct": 10, "request_count_max_increase_pct": 10,
                      "model_cost_max_increase_pct": 10}
        comparison.write_text(json.dumps({"current": current, "baseline": baseline, "thresholds": thresholds}))
        passed = subprocess.run([sys.executable, "artemis.py", "--benchmark-compare", str(comparison)], cwd=repo, capture_output=True, text=True)
        self.assertEqual(passed.returncode, 0, passed.stderr)
        current["precision"] = 0.7
        comparison.write_text(json.dumps({"current": current, "baseline": baseline, "thresholds": thresholds}))
        failed = subprocess.run([sys.executable, "artemis.py", "--benchmark-compare", str(comparison)], cwd=repo, capture_output=True, text=True)
        self.assertEqual(failed.returncode, 2)
        self.assertIn('"passed": false', failed.stdout)

    def test_regression_comparison_requires_provenance_and_explicit_thresholds(self):
        from appsec_agent.benchmark import compare_to_baseline
        with self.assertRaises(ValueError):
            compare_to_baseline({}, {"precision": 1}, {})
        with self.assertRaises(ValueError):
            compare_to_baseline({}, {"baseline_id": "unproven", "precision": 1}, {})
        baseline = {"baseline_id": "fixture", "measured_baseline": True,
                    "provenance": {"source": "synthetic-test-fixture", "collected_at": "2026-10-24", "corpus_sha256": "c" * 64, "scanner_versions": {"fixture": "1.0"}},
                    "precision": 1, "recall": 1, "f1": 1,
                    "runtime_seconds": 1, "request_count": 1, "model_cost_usd": 0}
        current = {key: baseline[key] for key in ("precision", "recall", "f1", "runtime_seconds", "request_count", "model_cost_usd")}
        thresholds = {"precision_min_delta": 0, "recall_min_delta": 0, "f1_min_delta": 0,
                      "runtime_max_increase_pct": 0, "request_count_max_increase_pct": 0,
                      "model_cost_max_increase_pct": 0}
        self.assertTrue(compare_to_baseline(current, baseline, thresholds)["passed"])


if __name__ == "__main__": unittest.main()
