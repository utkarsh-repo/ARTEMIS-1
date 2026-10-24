"""Deterministic, closed-world schemas for approval-bound tool actions.

Only tools explicitly registered here may be approved. This module validates
arguments; it does not execute tools or replace target/policy authorization.
"""
from __future__ import annotations

import re
from typing import Any


class ToolSchemaError(ValueError):
    """A tool is unknown or its arguments do not match its fixed schema."""


_IDENTIFIER = re.compile(r"^[A-Za-z][A-Za-z0-9_.-]{0,79}$")

# Keep the first registered action intentionally narrow. Authentication material
# is selected by reference to a configured profile, never passed as raw headers.
_TOOL_SCHEMAS: dict[str, dict[str, Any]] = {
    "http_request": {
        "version": "1.0.0",
        "risk": "read_only_network",
        "approval_required": True,
        "timeout_seconds": 15,
        "response_limit_bytes": 250000,
        "required": {"method"},
        "optional": {"auth_profile", "max_response_bytes"},
        "method": {"type": "enum", "values": ["GET", "HEAD", "OPTIONS"]},
        "auth_profile": {"type": "identifier"},
        "max_response_bytes": {"type": "integer", "minimum": 1, "maximum": 250000},
    },
}


def registered_tools() -> tuple[str, ...]:
    """Return a stable list of registered tool names."""
    return tuple(sorted(_TOOL_SCHEMAS))


def tool_definition(tool_name: str) -> dict[str, Any]:
    """Return immutable-by-copy execution metadata for a registered tool."""
    if not isinstance(tool_name, str) or tool_name not in _TOOL_SCHEMAS:
        raise ToolSchemaError(f"tool is not registered: {tool_name!r}")
    schema = _TOOL_SCHEMAS[tool_name]
    return {"name": tool_name, "version": schema["version"], "risk": schema["risk"],
            "approval_required": schema["approval_required"],
            "timeout_seconds": schema["timeout_seconds"],
            "max_response_bytes": schema["response_limit_bytes"]}


def validate_tool_action(tool_name: str, parameters: dict[str, Any]) -> dict[str, Any]:
    """Validate a closed-world tool schema and return a shallow copy.

    Unknown fields are rejected. Methods and identifiers are validated without
    consulting the LLM. The caller must still validate target scope and approval.
    """
    if not isinstance(tool_name, str) or tool_name not in _TOOL_SCHEMAS:
        raise ToolSchemaError(f"tool is not registered: {tool_name!r}")
    if not isinstance(parameters, dict):
        raise ToolSchemaError("tool parameters must be a JSON object")
    schema = _TOOL_SCHEMAS[tool_name]
    keys = set(parameters)
    if any(not isinstance(key, str) for key in keys):
        raise ToolSchemaError("tool parameter names must be strings")
    missing = schema["required"] - keys
    unknown = keys - schema["required"] - schema["optional"]
    if missing:
        raise ToolSchemaError("missing required tool parameters: " + ", ".join(sorted(missing)))
    if unknown:
        raise ToolSchemaError("unknown tool parameters: " + ", ".join(sorted(unknown)))
    result = dict(parameters)
    for key, value in result.items():
        rule = schema[key]
        kind = rule["type"]
        if kind == "enum":
            if not isinstance(value, str) or value not in rule["values"]:
                raise ToolSchemaError(f"{key} must be one of: {', '.join(rule['values'])}")
        elif kind == "identifier":
            if not isinstance(value, str) or not _IDENTIFIER.fullmatch(value):
                raise ToolSchemaError(f"{key} must be a valid configured profile identifier")
        elif kind == "integer":
            if not isinstance(value, int) or isinstance(value, bool) or not rule["minimum"] <= value <= rule["maximum"]:
                raise ToolSchemaError(f"{key} must be an integer between {rule['minimum']} and {rule['maximum']}")
        else:  # Defensive: schema definitions are trusted source, but fail closed.
            raise ToolSchemaError(f"unsupported internal schema type for {key}")
    return result
