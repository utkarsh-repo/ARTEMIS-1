"""Repeatable benchmark corpus validation and metric calculation."""
from __future__ import annotations
import json
import math
import pathlib


def load_corpus(path):
    data = json.loads(pathlib.Path(path).read_text(encoding="utf-8"))
    if not isinstance(data, dict) or data.get("schema_version") != 1 or not isinstance(data.get("cases"), list):
        raise ValueError("unsupported benchmark corpus schema")
    seen = set()
    for case in data["cases"]:
        if not isinstance(case, dict) or not isinstance(case.get("id"), str) or not case["id"]:
            raise ValueError("each benchmark case requires an ID")
        if case["id"] in seen: raise ValueError("duplicate benchmark case ID")
        seen.add(case["id"])
        if not isinstance(case.get("label"), bool) or not isinstance(case.get("fixture"), dict):
            raise ValueError("each case requires a boolean label and fixture object")
    return data


def evaluate(corpus_path, predictions_path):
    corpus = load_corpus(corpus_path)
    predictions = json.loads(pathlib.Path(predictions_path).read_text(encoding="utf-8"))
    if not isinstance(predictions, dict) or not isinstance(predictions.get("predictions"), dict):
        raise ValueError("predictions file must contain a predictions object keyed by case ID")
    expected = {case["id"] for case in corpus["cases"]}
    if set(predictions["predictions"]) != expected:
        raise ValueError("predictions must contain exactly the corpus case IDs")
    tp = fp = tn = fn = 0
    for case in corpus["cases"]:
        value = predictions["predictions"][case["id"]]
        if not isinstance(value, bool): raise ValueError("each prediction must be boolean")
        if value and case["label"]: tp += 1
        elif value and not case["label"]: fp += 1
        elif not value and not case["label"]: tn += 1
        else: fn += 1
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    def nonnegative_number(name):
        value = predictions.get(name, 0)
        if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) or value < 0:
            raise ValueError(f"{name} must be a finite non-negative number")
        return value
    return {"corpus_cases": len(expected), "true_positive": tp, "false_positive": fp,
            "true_negative": tn, "false_negative": fn, "precision": precision, "recall": recall, "f1": f1,
            "runtime_seconds": nonnegative_number("runtime_seconds"),
            "request_count": int(nonnegative_number("request_count")),
            "model_cost_usd": nonnegative_number("model_cost_usd"),
            "measured_baseline": bool(predictions.get("measured_baseline", False))}


def compare_to_baseline(current, baseline, thresholds):
    """Compare a measured report to a supplied measured baseline and fail on regressions.

    Thresholds are explicit operator/CI policy, not silently chosen defaults.
    Quality metrics have minimum allowed absolute deltas; resource metrics have
    maximum allowed relative increases. A baseline must identify its provenance.
    """
    if not isinstance(current, dict) or not isinstance(baseline, dict) or not isinstance(thresholds, dict):
        raise ValueError("current, baseline and thresholds must be objects")
    if not isinstance(baseline.get("baseline_id"), str) or not baseline["baseline_id"].strip():
        raise ValueError("baseline must include a non-empty baseline_id")
    provenance = baseline.get("provenance")
    if (baseline.get("measured_baseline") is not True or not isinstance(provenance, dict)
            or not isinstance(provenance.get("source"), str) or not provenance["source"].strip()
            or not isinstance(provenance.get("collected_at"), str) or not provenance["collected_at"].strip()
            or not isinstance(provenance.get("corpus_sha256"), str)
            or not __import__("re").fullmatch(r"[0-9a-f]{64}", provenance["corpus_sha256"])
            or not isinstance(provenance.get("scanner_versions"), dict) or not provenance["scanner_versions"]
            or any(not isinstance(k, str) or not isinstance(v, str) or not v for k, v in provenance["scanner_versions"].items())):
        raise ValueError("baseline must include measured_baseline=true and provenance: source, collected_at, corpus_sha256 and scanner_versions")
    required = {"precision_min_delta", "recall_min_delta", "f1_min_delta",
                "runtime_max_increase_pct", "request_count_max_increase_pct", "model_cost_max_increase_pct"}
    if set(thresholds) != required:
        raise ValueError("thresholds must define exactly the documented quality and resource bounds")
    values = {}
    for key in required:
        value = thresholds[key]
        if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) or value < 0:
            raise ValueError(f"{key} must be a finite non-negative number")
        values[key] = float(value)
    violations = []
    for metric, threshold_key in (("precision", "precision_min_delta"), ("recall", "recall_min_delta"), ("f1", "f1_min_delta")):
        current_value, baseline_value = current.get(metric), baseline.get(metric)
        if any(isinstance(v, bool) or not isinstance(v, (int, float)) or not math.isfinite(v) for v in (current_value, baseline_value)):
            raise ValueError(f"current and baseline must include finite {metric} metrics")
        delta = float(current_value) - float(baseline_value)
        if delta < -values[threshold_key]:
            violations.append({"metric": metric, "current": current_value, "baseline": baseline_value,
                               "delta": delta, "allowed_regression": values[threshold_key]})
    for metric, threshold_key in (("runtime_seconds", "runtime_max_increase_pct"),
                                  ("request_count", "request_count_max_increase_pct"),
                                  ("model_cost_usd", "model_cost_max_increase_pct")):
        current_value, baseline_value = current.get(metric), baseline.get(metric)
        if any(isinstance(v, bool) or not isinstance(v, (int, float)) or not math.isfinite(v) or v < 0 for v in (current_value, baseline_value)):
            raise ValueError(f"current and baseline must include finite non-negative {metric} metrics")
        if baseline_value == 0:
            increase_pct = 0.0 if current_value == 0 else None
        else:
            increase_pct = (float(current_value) - float(baseline_value)) / float(baseline_value) * 100
        exceeded = (current_value > 0) if baseline_value == 0 else increase_pct > values[threshold_key]
        if exceeded:
            violations.append({"metric": metric, "current": current_value, "baseline": baseline_value,
                               "increase_pct": "infinite" if increase_pct is None else increase_pct,
                               "allowed_increase_pct": values[threshold_key]})
    return {"passed": not violations, "baseline_id": baseline["baseline_id"], "violations": violations}
