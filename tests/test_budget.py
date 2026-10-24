import json
import pytest
from appsec_agent.budget import BudgetExceeded, BudgetConfigurationError, ModelBudget, validate_budget_config

CONFIG = {
    "provider": "openai",
    "model": "test-model",
    "max_requests": 2,
    "max_input_tokens": 1000,
    "max_output_tokens": 100,
    "max_total_tokens": 1100,
    "max_cost_usd": 0.10,
    "input_cost_per_1k_usd": 0.01,
    "output_cost_per_1k_usd": 0.02,
}


def test_reservation_is_persisted_before_call_and_settled(tmp_path):
    path = tmp_path / "budget.json"
    ledger = ModelBudget(path, CONFIG)
    reservation = ledger.reserve("request-1", "small prompt", 50)
    assert reservation["status"] == "reserved"
    persisted = json.loads(path.read_text())
    assert persisted["requests"] == 1
    assert persisted["reservations"][0]["status"] == "reserved"
    ledger.settle("request-1", input_tokens=10, output_tokens=12)
    snap = ledger.snapshot()
    assert snap["input_tokens"] == 10
    assert snap["output_tokens"] == 12
    assert snap["total_tokens"] == 22
    assert snap["cost_usd"] == pytest.approx(0.00034)


def test_request_limit_blocks_before_api_call(tmp_path):
    ledger = ModelBudget(tmp_path / "budget.json", {**CONFIG, "max_requests": 1})
    ledger.reserve("request-1", "prompt", 20)
    with pytest.raises(BudgetExceeded, match="request budget"):
        ledger.reserve("request-2", "prompt", 20)


def test_input_output_and_total_token_limits(tmp_path):
    ledger = ModelBudget(tmp_path / "budget.json", CONFIG)
    with pytest.raises(BudgetExceeded, match="input token"):
        ledger.reserve("large", "x" * 1001, 10)
    with pytest.raises(BudgetExceeded, match="output token"):
        ledger.reserve("large-output", "ok", 101)
    constrained = ModelBudget(tmp_path / "tight.json", {**CONFIG, "max_total_tokens": 1100})
    constrained.reserve("first", "x" * 1000, 100)
    with pytest.raises(BudgetExceeded, match="total-token"):
        constrained.reserve("second", "x", 100)


def test_cost_limit_blocks_before_call(tmp_path):
    config = {**CONFIG, "max_cost_usd": 0.00001}
    ledger = ModelBudget(tmp_path / "budget.json", config)
    with pytest.raises(BudgetExceeded, match="cost budget"):
        ledger.reserve("costly", "prompt", 100)
    assert ledger.snapshot()["requests"] == 0


def test_provider_usage_overrun_is_recorded_and_blocks_future_calls(tmp_path):
    ledger = ModelBudget(tmp_path / "budget.json", CONFIG)
    ledger.reserve("request-1", "prompt", 10)
    with pytest.raises(BudgetExceeded, match="exceeded the pre-call"):
        ledger.settle("request-1", input_tokens=11, output_tokens=10)
    with pytest.raises(BudgetExceeded, match="exhausted"):
        ledger.reserve("request-2", "prompt", 1)
    state = json.loads((tmp_path / "budget.json").read_text())
    assert state["reservations"][0]["overrun"] is True


def test_ledger_rejects_policy_limit_changes_on_restart(tmp_path):
    path = tmp_path / "budget.json"
    ModelBudget(path, CONFIG)
    with pytest.raises(BudgetConfigurationError, match="limits mismatch"):
        ModelBudget(path, {**CONFIG, "max_requests": 3})


def test_config_rejects_bool_and_non_finite_values():
    with pytest.raises(BudgetConfigurationError):
        validate_budget_config({**CONFIG, "max_requests": True})
    with pytest.raises(BudgetConfigurationError):
        validate_budget_config({**CONFIG, "max_cost_usd": float("nan")})


def test_hosted_planner_stops_before_second_model_call_when_budget_is_exhausted(tmp_path, monkeypatch):
    from appsec_agent.planner import Planner
    from appsec_agent.providers import LLMProvider

    class Board:
        data = {"completed_tests": [], "test_statuses": {}, "traces": [], "facts": [], "claims": []}
        def summary(self):
            return {"facts": [], "claims": []}

    calls = []
    def fake_complete(self, system, payload, *, max_output_tokens=900):
        calls.append(1)
        self.last_usage = {"input_tokens": 10, "output_tokens": 5}
        return {"complete": False, "intents": [{"test_id": "security_headers", "reason": "fixture"}], "summary": "ok"}
    monkeypatch.setattr(LLMProvider, "complete_json", fake_complete)
    monkeypatch.setenv("OPENAI_MODEL", "test-model")
    config = {**CONFIG, "max_requests": 1, "max_input_tokens": 10000,
              "max_output_tokens": 100, "max_total_tokens": 10100,
              "max_cost_usd": 1.0}
    planner = Planner("openai", 1, budget_config=config, budget_path=tmp_path / "budget.json")
    tests = [{"id": "security_headers", "name": "headers", "risk": "low", "kind": "http"}]
    first = planner.decide(Board(), tests, [])
    second = planner.decide(Board(), tests, [])
    assert first["intents"][0]["test_id"] == "security_headers"
    assert second["budget_stopped"] is True
    assert second["intents"] == []
    assert len(calls) == 1


def test_hosted_planner_requires_budget_for_exact_configured_model(tmp_path):
    from appsec_agent.planner import Planner
    with pytest.raises(ValueError, match="provider/model"):
        Planner("openai", budget_config={**CONFIG, "model": "other-model"},
                budget_path=tmp_path / "budget.json")
