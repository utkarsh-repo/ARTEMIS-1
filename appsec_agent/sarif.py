"""Bounded, defensive SARIF 2.1.0 finding importer.

This module imports scanner results only; it never executes a scanner or follows
artifact URIs. Input is treated as untrusted and malformed individual results
are skipped with a redacted audit event.
"""
from __future__ import annotations

import json
import os
import stat
import time
from pathlib import Path
from typing import Any

MAX_FILE_BYTES = 10 * 1024 * 1024
MAX_RUNS = 100
MAX_RULES_PER_RUN = 10_000
MAX_RESULTS_PER_RUN = 20_000
MAX_TOTAL_RESULTS = 50_000
MAX_TITLE_CHARS = 4_000
MAX_URI_CHARS = 2_048
MAX_TAGS = 50


def _bounded_text(value: Any, limit: int) -> str | None:
    if not isinstance(value, str):
        return None
    value = value.strip()
    if not value:
        return None
    # Remove control characters that can forge terminal/log lines.
    value = "".join(ch for ch in value if ch >= " " or ch in "\t")
    return value[:limit]


def _warn(store, code: str, *, file_index: int, run_index: int | None = None,
          result_index: int | None = None) -> None:
    event = {"type": "sarif_import_warning", "reason_code": code, "file_index": file_index}
    if run_index is not None:
        event["run_index"] = run_index
    if result_index is not None:
        event["result_index"] = result_index
    store.event(event)


def _read_document(path_value: Any, file_index: int, store) -> dict[str, Any] | None:
    try:
        path = Path(path_value)
        if path.is_symlink():
            _warn(store, "symlink_input_rejected", file_index=file_index)
            return None
        st = path.stat(follow_symlinks=False)
        if not stat.S_ISREG(st.st_mode):
            _warn(store, "non_regular_input_rejected", file_index=file_index)
            return None
        if st.st_size > MAX_FILE_BYTES:
            _warn(store, "input_too_large", file_index=file_index)
            return None
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(path, flags)
        with os.fdopen(fd, "rb") as stream:
            opened_stat = os.fstat(stream.fileno())
            if not stat.S_ISREG(opened_stat.st_mode):
                _warn(store, "non_regular_input_rejected", file_index=file_index)
                return None
            raw = stream.read(MAX_FILE_BYTES + 1)
        if len(raw) > MAX_FILE_BYTES:
            _warn(store, "input_too_large", file_index=file_index)
            return None
        data = json.loads(raw.decode("utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError, TypeError, ValueError):
        _warn(store, "input_unreadable_or_invalid_json", file_index=file_index)
        return None
    if not isinstance(data, dict):
        _warn(store, "root_not_object", file_index=file_index)
        return None
    version = data.get("version")
    if version not in ("2.1.0", "2.0.0"):
        _warn(store, "unsupported_sarif_version", file_index=file_index)
        return None
    runs = data.get("runs")
    if not isinstance(runs, list) or len(runs) > MAX_RUNS:
        _warn(store, "runs_invalid_or_over_limit", file_index=file_index)
        return None
    return data


def import_sarif(paths, store):
    """Import bounded SARIF records and return the number of accepted findings."""
    count = 0
    total_results = 0
    for file_index, path in enumerate(paths or []):
        data = _read_document(path, file_index, store)
        if data is None:
            continue
        for run_index, run in enumerate(data["runs"]):
            if not isinstance(run, dict):
                _warn(store, "run_not_object", file_index=file_index, run_index=run_index)
                continue
            tool = run.get("tool")
            driver = tool.get("driver") if isinstance(tool, dict) else None
            if not isinstance(driver, dict):
                _warn(store, "tool_driver_invalid", file_index=file_index, run_index=run_index)
                continue
            tool_name = _bounded_text(driver.get("name"), 200) or "Unknown SARIF tool"
            rules = driver.get("rules", [])
            if not isinstance(rules, list) or len(rules) > MAX_RULES_PER_RUN:
                _warn(store, "rules_invalid_or_over_limit", file_index=file_index, run_index=run_index)
                rules = []
            rule_map = {}
            for rule in rules:
                if not isinstance(rule, dict):
                    continue
                rule_id = _bounded_text(rule.get("id"), 256)
                if rule_id:
                    rule_map[rule_id] = rule
            results = run.get("results", [])
            if not isinstance(results, list) or len(results) > MAX_RESULTS_PER_RUN:
                _warn(store, "results_invalid_or_over_limit", file_index=file_index, run_index=run_index)
                continue
            for result_index, result in enumerate(results):
                total_results += 1
                if total_results > MAX_TOTAL_RESULTS:
                    _warn(store, "total_results_over_limit", file_index=file_index, run_index=run_index,
                          result_index=result_index)
                    return count
                if not isinstance(result, dict):
                    _warn(store, "result_not_object", file_index=file_index, run_index=run_index,
                          result_index=result_index)
                    continue
                rule = _bounded_text(result.get("ruleId"), 256) or "unknown"
                rule_meta = rule_map.get(rule, {})
                level = result.get("level", "warning")
                if level not in ("error", "warning", "note", "none"):
                    level = "warning"
                severity = {"error": "high", "warning": "medium", "note": "low", "none": "info"}[level]
                message = result.get("message")
                message_text = message.get("text") if isinstance(message, dict) else None
                short_description = rule_meta.get("shortDescription")
                fallback = short_description.get("text") if isinstance(short_description, dict) else None
                title = _bounded_text(message_text, MAX_TITLE_CHARS) or _bounded_text(fallback, MAX_TITLE_CHARS) or rule
                uri = None
                locations = result.get("locations", [])
                if isinstance(locations, list) and locations and isinstance(locations[0], dict):
                    physical = locations[0].get("physicalLocation")
                    artifact = physical.get("artifactLocation") if isinstance(physical, dict) else None
                    uri = _bounded_text(artifact.get("uri"), MAX_URI_CHARS) if isinstance(artifact, dict) else None
                properties = rule_meta.get("properties", {})
                tags_raw = properties.get("tags", []) if isinstance(properties, dict) else []
                tags = []
                if isinstance(tags_raw, list):
                    for tag in tags_raw[:MAX_TAGS]:
                        safe_tag = _bounded_text(tag, 100)
                        if safe_tag:
                            tags.append(safe_tag)
                help_uri = _bounded_text(rule_meta.get("helpUri"), MAX_URI_CHARS)
                finding_id = store.finding({
                    "timestamp": time.time(), "check": "sarif_import", "title": title,
                    "severity": severity, "confidence": "external-tool", "source_tool": tool_name,
                    "rule_id": rule, "url": uri,
                    "details": {"level": level, "help_uri": help_uri, "tags": tags},
                })
                if finding_id is not None:
                    count += 1
    return count
