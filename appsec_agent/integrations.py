"""Closed-world scanner and MCP/skill adapter contracts.

This module does not spawn processes or make network requests. Scanner plans are
fixed-schema payloads intended for a separately verified isolated worker. MCP /
skill calls require an explicitly supplied trusted transport and a permission
manifest; there is no ambient tool discovery or implicit capability grant.
"""
from __future__ import annotations

import hashlib
import json
import re
import time
from dataclasses import dataclass
from typing import Any, Callable, Mapping
from urllib.parse import urlsplit

from .policy import PolicyError, validate_url
from .runtime_store import policy_digest as compute_policy_digest


class IntegrationDenied(ValueError):
    """An integration request violates the registered contract."""


def _json_size(value: Any) -> int:
    try:
        return len(json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8"))
    except (TypeError, ValueError) as exc:
        raise IntegrationDenied("payload is not JSON serializable") from exc


def _target(value: Any) -> str:
    if not isinstance(value, str) or len(value) > 2048 or any(ord(c) < 0x20 for c in value):
        raise IntegrationDenied("target must be a bounded URL")
    parsed = urlsplit(value)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username or parsed.password:
        raise IntegrationDenied("target must be an HTTP(S) URL without embedded credentials")
    if parsed.fragment:
        raise IntegrationDenied("target URL fragments are not permitted")
    try:
        port = parsed.port
    except ValueError as exc:
        raise IntegrationDenied("target URL has an invalid port") from exc
    if port is not None and not 1 <= port <= 65535:
        raise IntegrationDenied("target URL has an invalid port")
    return value


@dataclass(frozen=True)
class ScannerDefinition:
    name: str
    version: str
    image: str | None
    entrypoint: tuple[str, ...]
    max_timeout_seconds: int
    max_output_bytes: int
    supports_url: bool = True

    def validate(self) -> None:
        if not re.fullmatch(r"[a-z][a-z0-9_-]{1,40}", self.name):
            raise ValueError("invalid scanner name")
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._+-]{0,63}", self.version):
            raise ValueError("invalid scanner version")
        if self.image is not None and not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._/:@-]*@sha256:[0-9a-f]{64}", self.image):
            raise ValueError("scanner image must be pinned by sha256 digest")
        if (not self.entrypoint or any(not isinstance(x, str) or not x or "\x00" in x for x in self.entrypoint)
                or not self.entrypoint[0].startswith("/") or ".." in self.entrypoint[0].split("/")):
            raise ValueError("scanner entrypoint must be a fixed absolute executable path")
        if not 1 <= self.max_timeout_seconds <= 3600 or not 1024 <= self.max_output_bytes <= 64 * 1024 * 1024:
            raise ValueError("scanner resource bounds are invalid")


# Arguments are generated only from these templates; no caller-supplied argv,
# shell fragments, config paths, plugin paths or arbitrary flags are accepted.
_DEFAULT_SCANNERS = (
    ScannerDefinition("nuclei", "3", None,
                      ("/usr/local/bin/artemis-scanner-wrapper",), 600, 8 * 1024 * 1024),
    ScannerDefinition("zap-baseline", "2", None,
                      ("/usr/local/bin/artemis-scanner-wrapper",), 900, 16 * 1024 * 1024),
    ScannerDefinition("trivy-config", "0.0", None,
                      ("/usr/local/bin/artemis-scanner-wrapper",), 600, 8 * 1024 * 1024),
)


class ScannerAdapterRegistry:
    """Registry that produces immutable execution requests, never executes them."""

    def __init__(self, definitions: tuple[ScannerDefinition, ...] = _DEFAULT_SCANNERS):
        self._definitions: dict[str, ScannerDefinition] = {}
        for item in definitions:
            item.validate()
            if item.name in self._definitions:
                raise ValueError("duplicate scanner adapter")
            self._definitions[item.name] = item

    def names(self) -> tuple[str, ...]:
        return tuple(sorted(self._definitions))

    def prepare(self, name: str, *, target: str, policy: dict[str, Any], assessment_id: str, timeout_seconds: int = 60,
                max_output_bytes: int | None = None) -> dict[str, Any]:
        definition = self._definitions.get(name)
        if definition is None:
            raise IntegrationDenied("scanner adapter is not registered")
        normalized_target = _target(target)
        if not isinstance(policy, dict) or not policy:
            raise IntegrationDenied("a validated assessment policy is required for scanner planning")
        if not isinstance(assessment_id, str) or not re.fullmatch(r"[A-Za-z0-9_.:-]{1,128}", assessment_id):
            raise IntegrationDenied("a valid assessment ID is required")
        try:
            validate_url(policy, normalized_target, "GET", resolve_dns=False)
        except (PolicyError, KeyError, TypeError, ValueError) as exc:
            raise IntegrationDenied("scanner target is outside the current assessment policy") from exc
        if isinstance(timeout_seconds, bool) or not isinstance(timeout_seconds, int) or not 1 <= timeout_seconds <= definition.max_timeout_seconds:
            raise IntegrationDenied("timeout exceeds scanner adapter policy")
        output_cap = definition.max_output_bytes if max_output_bytes is None else max_output_bytes
        if isinstance(output_cap, bool) or not isinstance(output_cap, int) or not 1024 <= output_cap <= definition.max_output_bytes:
            raise IntegrationDenied("output cap exceeds scanner adapter policy")
        # The image wrapper interprets a small JSON schema; target is data, not argv.
        payload = {"schema_version": 1, "assessment_id": assessment_id,
                   "policy_digest": compute_policy_digest(policy),
                   "scanner": name, "scanner_version": definition.version,
                   "target": normalized_target, "timeout_seconds": timeout_seconds,
                   "max_output_bytes": output_cap, "output_format": "sarif-or-json"}
        return {"adapter": name, "image": definition.image, "entrypoint": list(definition.entrypoint),
                "payload": payload, "payload_sha256": hashlib.sha256(
                    json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()).hexdigest(),
                "execution_enabled": False,
                "blocked_reason": "pinned scanner image and verified worker integration are not configured"}

    def validate_result(self, name: str, *, exit_code: int, stdout: bytes, stderr: bytes,
                        elapsed_ms: int | float, max_output_bytes: int | None = None) -> dict[str, Any]:
        """Validate bounded scanner output and return metadata without raw output.

        Exit codes are preserved verbatim; no scanner-specific finding semantics
        are guessed. SARIF is recognized only after structural validation.
        """
        definition = self._definitions.get(name)
        if definition is None:
            raise IntegrationDenied("scanner adapter is not registered")
        if isinstance(exit_code, bool) or not isinstance(exit_code, int) or not -255 <= exit_code <= 255:
            raise IntegrationDenied("scanner exit code is invalid")
        if not isinstance(stdout, bytes) or not isinstance(stderr, bytes):
            raise IntegrationDenied("scanner output streams must be bytes")
        cap = definition.max_output_bytes if max_output_bytes is None else max_output_bytes
        if isinstance(cap, bool) or not isinstance(cap, int) or not 1024 <= cap <= definition.max_output_bytes:
            raise IntegrationDenied("scanner output cap exceeds adapter policy")
        if len(stdout) + len(stderr) > cap:
            raise IntegrationDenied("scanner output exceeded the combined output cap")
        if isinstance(elapsed_ms, bool) or not isinstance(elapsed_ms, (int, float)) or elapsed_ms < 0 or elapsed_ms > definition.max_timeout_seconds * 1000:
            raise IntegrationDenied("scanner elapsed time is invalid or exceeds adapter timeout")
        try:
            document = json.loads(stdout.decode("utf-8")) if stdout.strip() else None
        except (UnicodeDecodeError, json.JSONDecodeError, RecursionError):
            document = None
        output_format = "empty" if not stdout.strip() else "text"
        result_count = None
        sarif_version = None
        if isinstance(document, dict):
            output_format = "json"
            if "version" in document and "runs" in document:
                if document.get("version") not in {"2.0.0", "2.1.0"} or not isinstance(document.get("runs"), list):
                    raise IntegrationDenied("scanner emitted structurally invalid SARIF")
                output_format = "sarif"
                sarif_version = document["version"]
                result_count = sum(len(run.get("results", [])) for run in document["runs"] if isinstance(run, dict) and isinstance(run.get("results", []), list))
            elif "results" in document and isinstance(document["results"], list):
                result_count = len(document["results"])
        elif isinstance(document, list):
            output_format = "json-array"
            result_count = len(document)
        return {"scanner": name, "scanner_version": definition.version, "exit_code": exit_code,
                "status": "completed" if exit_code == 0 else "scanner_failed",
                "elapsed_ms": round(float(elapsed_ms), 2), "stdout_bytes": len(stdout), "stderr_bytes": len(stderr),
                "stdout_sha256": hashlib.sha256(stdout).hexdigest(), "stderr_sha256": hashlib.sha256(stderr).hexdigest(),
                "output_format": output_format, "result_count": result_count, "sarif_version": sarif_version}


@dataclass(frozen=True)
class CapabilityDefinition:
    name: str
    input_schema: Mapping[str, Any]
    permissions: frozenset[str]
    timeout_seconds: float = 10.0
    max_input_bytes: int = 16_384
    max_output_bytes: int = 65_536

    @property
    def approval_required(self) -> bool:
        return bool(self.permissions.intersection({"write", "network", "filesystem", "secrets"}))

    def validate(self) -> None:
        if not re.fullmatch(r"[a-z][a-z0-9_.:-]{1,100}", self.name):
            raise ValueError("invalid capability name")
        if not self.permissions or not self.permissions.issubset({"read", "write", "network", "filesystem", "secrets"}):
            raise ValueError("capability permissions must be explicit supported values")
        if not 0.1 <= self.timeout_seconds <= 120:
            raise ValueError("capability timeout out of range")
        if not 1 <= self.max_input_bytes <= 1_048_576 or not 1024 <= self.max_output_bytes <= 1_048_576:
            raise ValueError("capability size limit out of range")
        if not isinstance(self.input_schema, Mapping) or self.input_schema.get("type") != "object":
            raise ValueError("capability input schema must be an object schema")
        properties = self.input_schema.get("properties")
        required = self.input_schema.get("required", [])
        if (not isinstance(properties, Mapping) or self.input_schema.get("additionalProperties") is not False
                or not isinstance(required, list) or any(not isinstance(k, str) or k not in properties for k in required)):
            raise ValueError("capability schema must define properties, valid required keys, and additionalProperties=false")
        supported_types = {"string", "integer", "boolean", "object", "array", "number"}
        for key, spec in properties.items():
            if not isinstance(key, str) or not isinstance(spec, Mapping) or spec.get("type") not in supported_types:
                raise ValueError("capability schema contains an unsupported property definition")


class MCPAdapterRegistry:
    """Explicit capability registry with fail-closed permissions and bounded output.

    The `transport` is an operator-supplied trusted callable. This registry never
    discovers tools, inherits credentials, or grants permissions by tool name.
    A deployment must still put the transport inside ARTEMIS's verified worker.
    """

    def __init__(self, *, approval_verifier: Callable[[str, dict[str, Any], str], bool] | None = None,
                 audit_sink: Callable[[dict[str, Any]], None] | None = None):
        self._capabilities: dict[str, CapabilityDefinition] = {}
        self._transports: dict[str, Callable[[dict[str, Any], float], Any]] = {}
        self._approval_verifier = approval_verifier
        self._audit_sink = audit_sink
        self._audit_events: list[dict[str, Any]] = []

    def _audit(self, event: dict[str, Any], *, required: bool) -> None:
        # Keep only metadata/hashes, never raw tool arguments or results.
        self._audit_events.append(event)
        if self._audit_sink is None:
            if required:
                raise IntegrationDenied("sensitive capability requires a durable audit sink")
            return
        try:
            self._audit_sink(dict(event))
        except Exception as exc:
            raise IntegrationDenied("capability audit persistence failed") from exc

    def audit_events(self) -> list[dict[str, Any]]:
        return [dict(event) for event in self._audit_events]

    def register(self, definition: CapabilityDefinition,
                 transport: Callable[[dict[str, Any], float], Any]) -> None:
        definition.validate()
        if definition.name in self._capabilities:
            raise ValueError("capability already registered")
        if not callable(transport):
            raise ValueError("trusted transport callable is required")
        self._capabilities[definition.name] = definition
        self._transports[definition.name] = transport

    def manifest(self) -> list[dict[str, Any]]:
        return [{"name": d.name, "permissions": sorted(d.permissions), "approval_required": d.approval_required,
                 "timeout_seconds": d.timeout_seconds, "max_input_bytes": d.max_input_bytes, "max_output_bytes": d.max_output_bytes,
                 "input_schema": dict(d.input_schema)} for d in sorted(self._capabilities.values(), key=lambda x: x.name)]

    def invoke(self, name: str, arguments: dict[str, Any], *, granted_permissions: set[str],
               approval_id: str | None = None) -> dict[str, Any]:
        definition = self._capabilities.get(name)
        transport = self._transports.get(name)
        if definition is None or transport is None:
            raise IntegrationDenied("MCP/skill capability is not registered")
        if not isinstance(granted_permissions, set) or not definition.permissions.issubset(granted_permissions):
            raise IntegrationDenied("required capability permissions were not granted")
        if not isinstance(arguments, dict) or _json_size(arguments) > definition.max_input_bytes:
            raise IntegrationDenied("capability input is invalid or exceeds its size cap")
        schema = definition.input_schema
        required = schema.get("required", [])
        properties = schema.get("properties", {})
        if schema.get("additionalProperties", False) is not False or not isinstance(properties, Mapping):
            raise IntegrationDenied("registered schema must explicitly disallow additional properties")
        if not isinstance(required, list) or any(key not in arguments for key in required):
            raise IntegrationDenied("capability input is missing required fields")
        if any(key not in properties for key in arguments):
            raise IntegrationDenied("capability input contains an unregistered field")
        for key, value in arguments.items():
            spec = properties[key]
            expected = spec.get("type") if isinstance(spec, Mapping) else None
            if expected == "string" and not isinstance(value, str): raise IntegrationDenied("invalid string field")
            if expected == "integer" and (isinstance(value, bool) or not isinstance(value, int)): raise IntegrationDenied("invalid integer field")
            if expected == "boolean" and not isinstance(value, bool): raise IntegrationDenied("invalid boolean field")
            if expected == "object" and not isinstance(value, dict): raise IntegrationDenied("invalid object field")
            if expected == "array" and not isinstance(value, list): raise IntegrationDenied("invalid array field")
            if expected == "number" and (isinstance(value, bool) or not isinstance(value, (int, float))): raise IntegrationDenied("invalid number field")
            if isinstance(value, str):
                if "maxLength" in spec and len(value) > spec["maxLength"]: raise IntegrationDenied("string field exceeds its registered length cap")
                if "minLength" in spec and len(value) < spec["minLength"]: raise IntegrationDenied("string field is shorter than its registered minimum")
                if "enum" in spec and value not in spec["enum"]: raise IntegrationDenied("string field is outside its registered enum")
        if definition.approval_required:
            if (not isinstance(approval_id, str) or not approval_id or not callable(self._approval_verifier)
                    or self._approval_verifier(name, arguments, approval_id) is not True):
                raise IntegrationDenied("sensitive capability requires a verified exact-action approval")
        input_digest = hashlib.sha256(json.dumps(arguments, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()).hexdigest()
        audit_base = {"capability": name, "permissions": sorted(definition.permissions),
                      "approval_required": definition.approval_required,
                      "approval_id": approval_id if definition.approval_required else None,
                      "input_bytes": _json_size(arguments), "input_sha256": input_digest,
                      "timestamp": time.time()}
        self._audit({**audit_base, "event": "capability_invocation_started"}, required=definition.approval_required)
        started = time.monotonic()
        try:
            result = transport(arguments, definition.timeout_seconds)
        except TimeoutError as exc:
            raise IntegrationDenied("capability timed out") from exc
        elapsed_ms = round((time.monotonic() - started) * 1000, 2)
        if elapsed_ms > definition.timeout_seconds * 1000:
            raise IntegrationDenied("capability exceeded its declared timeout; transport must enforce hard cancellation")
        size = _json_size(result)
        if size > definition.max_output_bytes:
            raise IntegrationDenied("capability output exceeds its size cap")
        output_digest = hashlib.sha256(json.dumps(result, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()).hexdigest()
        self._audit({**audit_base, "event": "capability_invocation_completed", "elapsed_ms": elapsed_ms,
                     "output_bytes": size, "output_sha256": output_digest, "timestamp": time.time()},
                    required=definition.approval_required)
        return {"capability": name, "permissions": sorted(definition.permissions), "elapsed_ms": elapsed_ms,
                "output_bytes": size, "result": result, "audit_event_recorded": True,
                "transport_execution_enabled": True}
