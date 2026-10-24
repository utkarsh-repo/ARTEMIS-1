"""Fail-closed per-assessment model request, token and cost budget ledger.

Input token estimates deliberately use UTF-8 byte length as a conservative upper
bound for admission control. Provider-reported usage replaces estimates after a
call; configured per-token rates must be maintained by the operator.
"""
from __future__ import annotations

import json
import math
import os
import pathlib
import tempfile
import threading
from typing import Any


class BudgetExceeded(RuntimeError):
    """The requested model call cannot fit within the remaining budget."""


class BudgetConfigurationError(ValueError):
    pass


_REQUIRED = ("provider", "model", "max_requests", "max_input_tokens", "max_output_tokens", "max_total_tokens",
             "max_cost_usd", "input_cost_per_1k_usd", "output_cost_per_1k_usd")


def validate_budget_config(config: Any) -> dict[str, int | float]:
    if not isinstance(config, dict):
        raise BudgetConfigurationError("llm_budget must be an object for hosted providers")
    missing = [key for key in _REQUIRED if key not in config]
    if missing:
        raise BudgetConfigurationError("llm_budget missing fields: " + ", ".join(missing))
    out: dict[str, Any] = {}
    for key in _REQUIRED:
        value = config[key]
        if key in {"provider", "model"}:
            if not isinstance(value, str) or not value.strip() or len(value) > 200:
                raise BudgetConfigurationError(f"{key} must be a non-empty bounded string")
            out[key] = value.strip()
            continue
        if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value):
            raise BudgetConfigurationError(f"{key} must be a finite number")
        if value < 0 or (key in {"max_requests", "max_input_tokens", "max_output_tokens", "max_total_tokens"} and (not isinstance(value, int) or value < 1)):
            raise BudgetConfigurationError(f"{key} must be positive (rates and max_cost_usd may be zero)")
        out[key] = value
    if out["max_input_tokens"] + out["max_output_tokens"] > out["max_total_tokens"]:
        raise BudgetConfigurationError("max_total_tokens must cover max_input_tokens plus max_output_tokens")
    return out


class ModelBudget:
    """Persisted budget ledger; reservation happens before any hosted API call."""
    def __init__(self, path: str | os.PathLike[str], config: dict[str, Any]):
        self.path = pathlib.Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.config = validate_budget_config(config)
        self._lock = threading.RLock()
        if self.path.exists():
            try:
                state = json.loads(self.path.read_text(encoding="utf-8"))
            except Exception as exc:
                raise BudgetConfigurationError("existing model budget ledger is unreadable") from exc
            if state.get("schema_version") != 1 or state.get("limits") != self.config:
                raise BudgetConfigurationError("existing model budget ledger schema/limits mismatch")
            self.state = state
        else:
            self.state = {"schema_version": 1, "limits": self.config, "requests": 0,
                          "input_tokens": 0, "output_tokens": 0, "total_tokens": 0,
                          "cost_usd": 0.0, "budget_exhausted": False, "reservations": [], "events": []}
            self._save()

    @staticmethod
    def conservative_input_tokens(text: str) -> int:
        return len(text.encode("utf-8"))

    def _save(self) -> None:
        data = json.dumps(self.state, sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n"
        fd, name = tempfile.mkstemp(prefix=".model-budget-", dir=str(self.path.parent))
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as stream:
                stream.write(data); stream.flush(); os.fsync(stream.fileno())
            os.chmod(name, 0o600)
            os.replace(name, self.path)
        finally:
            try: os.unlink(name)
            except FileNotFoundError: pass

    def reserve(self, request_id: str, prompt: str, output_cap: int) -> dict[str, Any]:
        if not isinstance(request_id, str) or not request_id or len(request_id) > 128:
            raise ValueError("request_id must be a non-empty bounded string")
        if isinstance(output_cap, bool) or not isinstance(output_cap, int) or output_cap < 1:
            raise ValueError("output_cap must be a positive integer")
        input_tokens = self.conservative_input_tokens(prompt)
        if input_tokens > self.config["max_input_tokens"]:
            self._event("denied", request_id, "input_token_limit")
            raise BudgetExceeded("model input token budget exceeded")
        if output_cap > self.config["max_output_tokens"]:
            self._event("denied", request_id, "output_token_limit")
            raise BudgetExceeded("model output token budget exceeded")
        with self._lock:
            if self.state.get("budget_exhausted"):
                raise BudgetExceeded("model budget is exhausted after a prior provider usage overrun")
            if any(r["request_id"] == request_id for r in self.state["reservations"]):
                raise BudgetExceeded("duplicate model budget request ID")
            reserved_total = input_tokens + output_cap
            estimated_cost = (input_tokens * self.config["input_cost_per_1k_usd"] +
                              output_cap * self.config["output_cost_per_1k_usd"]) / 1000
            if self.state["requests"] >= self.config["max_requests"]:
                self._event("denied", request_id, "request_limit")
                raise BudgetExceeded("model request budget exceeded")
            if self.state["total_tokens"] + reserved_total > self.config["max_total_tokens"]:
                self._event("denied", request_id, "total_token_limit")
                raise BudgetExceeded("model total-token budget exceeded")
            if self.state["cost_usd"] + estimated_cost > self.config["max_cost_usd"] + 1e-12:
                self._event("denied", request_id, "cost_limit")
                raise BudgetExceeded("model cost budget exceeded")
            reservation = {"request_id": request_id, "input_reserved": input_tokens,
                           "output_reserved": output_cap, "total_reserved": reserved_total,
                           "cost_reserved_usd": estimated_cost, "status": "reserved"}
            self.state["requests"] += 1
            self.state["input_tokens"] += input_tokens
            self.state["output_tokens"] += output_cap
            self.state["total_tokens"] += reserved_total
            self.state["cost_usd"] += estimated_cost
            self.state["reservations"].append(reservation)
            self._event_locked("reserved", request_id, "admitted")
            self._save()
            return dict(reservation)

    def settle(self, request_id: str, *, input_tokens: int | None, output_tokens: int | None) -> None:
        with self._lock:
            reservation = next((r for r in self.state["reservations"] if r["request_id"] == request_id), None)
            if reservation is None or reservation["status"] != "reserved":
                raise BudgetConfigurationError("missing or already settled model budget reservation")
            # If the provider has no usage data, retain the conservative reservation.
            actual_in = reservation["input_reserved"] if input_tokens is None else input_tokens
            actual_out = reservation["output_reserved"] if output_tokens is None else output_tokens
            if any(isinstance(v, bool) or not isinstance(v, int) or v < 0 for v in (actual_in, actual_out)):
                raise BudgetConfigurationError("provider usage must be non-negative integer token counts")
            actual_cost = (actual_in * self.config["input_cost_per_1k_usd"] +
                           actual_out * self.config["output_cost_per_1k_usd"]) / 1000
            delta_in = actual_in - reservation["input_reserved"]
            delta_out = actual_out - reservation["output_reserved"]
            delta_total = delta_in + delta_out
            delta_cost = actual_cost - reservation["cost_reserved_usd"]
            # A provider reporting more than reserved means our admission bound was wrong.
            # Record the overrun and fail closed for subsequent requests.
            self.state["input_tokens"] += delta_in
            self.state["output_tokens"] += delta_out
            self.state["total_tokens"] += delta_total
            self.state["cost_usd"] = max(0.0, self.state["cost_usd"] + delta_cost)
            reservation.update({"status": "settled", "input_actual": actual_in,
                                "output_actual": actual_out, "cost_actual_usd": actual_cost,
                                "overrun": actual_in > reservation["input_reserved"] or actual_out > reservation["output_reserved"]})
            if reservation["overrun"] or self.state["total_tokens"] > self.config["max_total_tokens"] or self.state["cost_usd"] > self.config["max_cost_usd"] + 1e-12:
                self.state["budget_exhausted"] = True
            self._event_locked("settled", request_id, "provider_usage_recorded")
            self._save()
            if reservation["overrun"] or self.state["total_tokens"] > self.config["max_total_tokens"] or self.state["cost_usd"] > self.config["max_cost_usd"] + 1e-12:
                raise BudgetExceeded("provider usage exceeded the pre-call budget reservation; subsequent calls are denied")

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            return {k: self.state[k] for k in ("requests", "input_tokens", "output_tokens", "total_tokens", "cost_usd")}

    def _event(self, event: str, request_id: str, reason: str) -> None:
        with self._lock:
            self._event_locked(event, request_id, reason)
            self._save()

    def _event_locked(self, event: str, request_id: str, reason: str) -> None:
        self.state["events"].append({"event": event, "request_id": request_id, "reason": reason})
