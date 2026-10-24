import pytest

from appsec_agent.policy import load_policy
from appsec_agent.integrations import (
    CapabilityDefinition,
    IntegrationDenied,
    MCPAdapterRegistry,
    ScannerAdapterRegistry,
    ScannerDefinition,
)


def _policy():
    from pathlib import Path
    return load_policy(Path(__file__).resolve().parents[1] / "policy.example.json")


def test_scanner_registry_is_closed_world_and_prepares_data_not_shell_args():
    registry = ScannerAdapterRegistry()
    policy = _policy()
    assert registry.names() == ("nuclei", "trivy-config", "zap-baseline")
    request = registry.prepare("nuclei", target="https://staging.example.test/app", policy=policy, assessment_id="assessment-1", timeout_seconds=30)
    assert request["execution_enabled"] is False
    assert request["image"] is None
    assert request["payload"]["target"] == "https://staging.example.test/app"
    assert request["payload"]["assessment_id"] == "assessment-1"
    assert request["payload"]["policy_digest"].startswith("sha256:")
    assert request["payload_sha256"]
    assert ";" not in request["payload"]["target"]
    with pytest.raises(IntegrationDenied):
        registry.prepare("arbitrary-command", target="https://staging.example.test", policy=policy, assessment_id="assessment-1")


@pytest.mark.parametrize("target", [
    "file:///etc/passwd", "https://user:password@example.test/", "https://example.test/#frag",
    "https://example.test:99999/", "https://example.test/\r\nX-Injected: y",
])
def test_scanner_target_validation_rejects_ambiguous_or_unsafe_urls(target):
    with pytest.raises(IntegrationDenied):
        ScannerAdapterRegistry().prepare("nuclei", target=target, policy=_policy(), assessment_id="assessment-1")


def test_scanner_requires_bounded_timeout_and_output():
    registry = ScannerAdapterRegistry()
    with pytest.raises(IntegrationDenied):
        registry.prepare("nuclei", target="https://staging.example.test", policy=_policy(), assessment_id="assessment-1", timeout_seconds=601)
    with pytest.raises(IntegrationDenied):
        registry.prepare("nuclei", target="https://staging.example.test", policy=_policy(), assessment_id="assessment-1", max_output_bytes=99_000_000)


def test_scanner_planning_requires_policy_scope_and_rejects_out_of_scope_host():
    registry = ScannerAdapterRegistry()
    with pytest.raises(IntegrationDenied, match="policy"):
        registry.prepare("nuclei", target="https://staging.example.test/", policy={}, assessment_id="assessment-1")
    with pytest.raises(IntegrationDenied, match="outside"):
        registry.prepare("nuclei", target="https://attacker.example/", policy=_policy(), assessment_id="assessment-1")


def test_scanner_definitions_require_real_digest_when_configured():
    with pytest.raises(ValueError):
        ScannerDefinition("nuclei", "3", "registry.example/scanner:latest", ("/scanner",), 30, 4096).validate()


def _definition(**kwargs):
    return CapabilityDefinition(
        name="docs.search",
        input_schema={"type": "object", "properties": {"query": {"type": "string"}},
                      "required": ["query"], "additionalProperties": False},
        permissions=frozenset({"read"}), max_output_bytes=4096, **kwargs,
    )


def test_mcp_adapter_requires_registration_and_explicit_permissions():
    registry = MCPAdapterRegistry()
    with pytest.raises(IntegrationDenied):
        registry.invoke("docs.search", {"query": "x"}, granted_permissions={"read"})
    registry.register(_definition(), lambda args, timeout: {"matches": [args["query"]]})
    with pytest.raises(IntegrationDenied):
        registry.invoke("docs.search", {"query": "x"}, granted_permissions=set())
    assert registry.invoke("docs.search", {"query": "x"}, granted_permissions={"read"})["result"] == {"matches": ["x"]}


def test_mcp_adapter_rejects_unknown_fields_bad_types_and_oversized_output():
    registry = MCPAdapterRegistry()
    registry.register(_definition(), lambda args, timeout: args)
    with pytest.raises(IntegrationDenied):
        registry.invoke("docs.search", {"query": "x", "admin": True}, granted_permissions={"read"})
    with pytest.raises(IntegrationDenied):
        registry.invoke("docs.search", {"query": 7}, granted_permissions={"read"})
    oversized = MCPAdapterRegistry()
    oversized.register(_definition(), lambda args, timeout: {"data": "x" * 5000})
    with pytest.raises(IntegrationDenied):
        oversized.invoke("docs.search", {"query": "x"}, granted_permissions={"read"})


def test_mcp_adapter_validates_definition_and_records_bounded_metadata():
    registry = MCPAdapterRegistry()
    registry.register(_definition(), lambda args, timeout: {"ok": True})
    result = registry.invoke("docs.search", {"query": "x"}, granted_permissions={"read"})
    assert result["capability"] == "docs.search"
    assert result["output_bytes"] <= 4096
    assert result["transport_execution_enabled"] is True
    assert registry.manifest()[0]["permissions"] == ["read"]
    with pytest.raises(ValueError):
        CapabilityDefinition("unsafe", {"type": "object"}, frozenset()).validate()


def test_mcp_sensitive_capability_requires_exact_action_approval():
    definition = CapabilityDefinition(
        name="deployment.change",
        input_schema={"type": "object", "properties": {"change_id": {"type": "string", "maxLength": 64}},
                      "required": ["change_id"], "additionalProperties": False},
        permissions=frozenset({"write"}), max_output_bytes=4096,
    )
    registry = MCPAdapterRegistry()
    registry.register(definition, lambda args, timeout: {"accepted": args["change_id"]})
    with pytest.raises(IntegrationDenied, match="approval"):
        registry.invoke("deployment.change", {"change_id": "CHG-1"}, granted_permissions={"write"}, approval_id="approval-1")
    audit_events = []
    registry = MCPAdapterRegistry(approval_verifier=lambda name, args, approval_id: (
        name == "deployment.change" and args == {"change_id": "CHG-1"} and approval_id == "approval-1"),
        audit_sink=audit_events.append)
    registry.register(definition, lambda args, timeout: {"accepted": args["change_id"]})
    with pytest.raises(IntegrationDenied, match="approval"):
        registry.invoke("deployment.change", {"change_id": "CHG-2"}, granted_permissions={"write"}, approval_id="approval-1")
    result = registry.invoke("deployment.change", {"change_id": "CHG-1"}, granted_permissions={"write"}, approval_id="approval-1")
    assert result["result"] == {"accepted": "CHG-1"}
    assert result["audit_event_recorded"] is True
    assert registry.manifest()[0]["approval_required"] is True
    assert [event["event"] for event in audit_events] == ["capability_invocation_started", "capability_invocation_completed"]
    assert all("CHG-1" not in str(event) for event in audit_events)
    assert audit_events[-1]["output_sha256"]


def test_sensitive_mcp_capability_fails_before_transport_without_durable_audit_sink():
    calls = []
    definition = CapabilityDefinition(
        name="secrets.read", input_schema={"type": "object", "properties": {}, "required": [], "additionalProperties": False},
        permissions=frozenset({"secrets"}), max_output_bytes=4096,
    )
    registry = MCPAdapterRegistry(approval_verifier=lambda name, args, approval_id: True)
    registry.register(definition, lambda args, timeout: calls.append("called") or {"secret": "never"})
    with pytest.raises(IntegrationDenied, match="audit sink"):
        registry.invoke("secrets.read", {}, granted_permissions={"secrets"}, approval_id="approval-2")
    assert calls == []


def test_scanner_result_validation_records_exit_code_hashes_and_sarif_shape():
    registry = ScannerAdapterRegistry()
    sarif = b'{"version":"2.1.0","runs":[{"results":[{},{}]}]}'
    result = registry.validate_result("nuclei", exit_code=0, stdout=sarif, stderr=b"", elapsed_ms=120)
    assert result["status"] == "completed"
    assert result["output_format"] == "sarif"
    assert result["result_count"] == 2
    assert result["sarif_version"] == "2.1.0"
    assert result["stdout_sha256"]
    failed = registry.validate_result("nuclei", exit_code=2, stdout=b"scanner error", stderr=b"details", elapsed_ms=30)
    assert failed["status"] == "scanner_failed"
    assert failed["exit_code"] == 2
    assert "details" not in str(failed)


def test_scanner_result_validation_rejects_oversized_or_invalid_sarif():
    registry = ScannerAdapterRegistry()
    with pytest.raises(IntegrationDenied, match="output exceeded"):
        registry.validate_result("nuclei", exit_code=0, stdout=b"x" * 2048, stderr=b"", elapsed_ms=1, max_output_bytes=1024)
    with pytest.raises(IntegrationDenied, match="SARIF"):
        registry.validate_result("nuclei", exit_code=0, stdout=b'{"version":"9.9.9","runs":[]}', stderr=b"", elapsed_ms=1)
