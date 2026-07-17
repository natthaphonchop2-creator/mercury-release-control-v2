from __future__ import annotations

import json

import pytest

from mercury_release_control.hosted_collector import (
    HostedProviderCollector,
    _mcp_envelope,
    _parse_json,
    _Response,
    _tool_payload,
)
from mercury_release_control.provider_inspector import InspectionError


def test_hosted_collector_fails_before_network_when_environment_is_incomplete() -> None:
    with pytest.raises(InspectionError, match="^provider_environment_invalid$"):
        HostedProviderCollector().collect(
            policy={},
            environment={"RENDER_API_TOKEN": "present-but-incomplete"},
            reviewed_sha="a" * 40,
            staging=object(),
        )


def test_hosted_json_parser_rejects_duplicate_keys() -> None:
    with pytest.raises(InspectionError, match="^provider_json_invalid$"):
        _parse_json(b'{"status":"ok","status":"forged"}')


def test_mcp_sse_parser_accepts_one_bounded_json_rpc_event() -> None:
    envelope = {"id": 1, "jsonrpc": "2.0", "result": {"tools": []}}
    response = _Response(
        body=b"event: message\ndata: " + json.dumps(envelope).encode() + b"\n\n",
        headers={"content-type": "text/event-stream; charset=utf-8"},
        status=200,
    )

    assert _mcp_envelope(response) == envelope


def test_tool_payload_requires_structured_or_json_text_content() -> None:
    assert _tool_payload({"structuredContent": {"status": "ok"}}) == {"status": "ok"}
    assert _tool_payload({"content": [{"text": '{"status":"ok"}', "type": "text"}]}) == {
        "status": "ok"
    }

    with pytest.raises(InspectionError, match="^public_mcp_response_invalid$"):
        _tool_payload({"content": [{"type": "image"}]})
