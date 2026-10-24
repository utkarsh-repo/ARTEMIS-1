# Benchmark regression gate

ARTEMIS exposes a deterministic CLI comparison suitable for a CI job once a trusted baseline and current measured report exist.

Input file shape:

```json
{
  "current": {
    "precision": 0.91,
    "recall": 0.88,
    "f1": 0.895,
    "runtime_seconds": 12.0,
    "request_count": 30,
    "model_cost_usd": 0.03
  },
  "baseline": {
    "baseline_id": "scanner-image-sha-and-corpus-revision",
    "precision": 0.92,
    "recall": 0.90,
    "f1": 0.91,
    "runtime_seconds": 10.0,
    "request_count": 28,
    "model_cost_usd": 0.025
  },
  "thresholds": {
    "precision_min_delta": 0.02,
    "recall_min_delta": 0.02,
    "f1_min_delta": 0.02,
    "runtime_max_increase_pct": 25,
    "request_count_max_increase_pct": 15,
    "model_cost_max_increase_pct": 15
  }
}
```

The values above are illustrative only. `baseline_id` should identify a measured scanner image/tool version and benchmark corpus revision; do not use these example values as an actual baseline.

Run:

```bash
python artemis.py --benchmark-compare benchmark-comparison.json
```

Exit status `0` means no threshold was exceeded; exit status `2` means the comparison failed or input was invalid. The CLI accepts a regular non-symlink JSON file up to 1 MB and emits a machine-readable result.

The comparison implementation is tested, but ARTEMIS does not yet bundle a real scanner-generated baseline or a CI workflow. This command alone does not satisfy `ART-BENCH-002` until connected to real, reproducible scanner runs.
