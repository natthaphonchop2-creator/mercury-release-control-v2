from __future__ import annotations

import json

import pytest

from mercury_release_control.hosted_collector import (
    HostedProviderCollector,
    _assert_no_secret,
    _live_deploy,
    _mcp_envelope,
    _parse_json,
    _render_log_url,
    _Response,
    _secret_environment_values,
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


def test_live_deploy_reads_official_render_cursor_envelope() -> None:
    reviewed_sha = "a" * 40

    assert _live_deploy(
        {
            "cursor": "next-page-cursor",
            "deploy": {
                "commit": {"id": reviewed_sha, "message": "release"},
                "id": "dep-d9fudtu1a83c73e50o70",
                "status": "live",
            },
        },
        reviewed_sha,
    )
    assert not _live_deploy(
        {"commit": {"id": reviewed_sha}, "id": "dep-flat", "status": "live"},
        reviewed_sha,
    )


@pytest.mark.parametrize("log_type", ("build", "runtime"))
def test_hosted_collector_render_log_urls_bind_owner_id(log_type: str) -> None:
    from urllib.parse import parse_qs, urlsplit

    url = _render_log_url(
        "https://api.render.com/v1",
        service_id="srv-d978tk37uimc73ej52mg",
        owner_id="tea_01HZX6R9HQSPX9K4GTDR",
        log_type=log_type,
    )

    parsed = urlsplit(url)
    assert parsed.path == "/v1/logs"
    assert parse_qs(parsed.query, strict_parsing=True) == {
        "ownerId": ["tea_01HZX6R9HQSPX9K4GTDR"],
        "resource": ["srv-d978tk37uimc73ej52mg"],
        "type": [log_type],
    }


def test_render_log_scan_allows_public_provider_metadata() -> None:
    environment = {
        "MERCURY_PUBLIC_MCP_URL": "https://mercury-tools-mcp.onrender.com",
        "MERCURY_REVIEWED_COMMIT_SHA": "a" * 40,
        "RENDER_OWNER_ID": "tea_01HZX6R9HQSPX9K4GTDR",
        "RENDER_SERVICE_ID": "srv-d978tk37uimc73ej52mg",
        "FLOWACCOUNT_SANDBOX_CLIENT_SECRET": "private-client-secret-value",
        "MERCURY_PUBLIC_MCP_TOKEN": "private-mcp-token-value",
        "SUPABASE_DB_URL": "postgresql://user:private-password@db.example.test/postgres",
    }
    payload = (
        b"deploying aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa to "
        b"https://mercury-tools-mcp.onrender.com "
        b"for tea_01HZX6R9HQSPX9K4GTDR/srv-d978tk37uimc73ej52mg"
    )

    _assert_no_secret(payload, _secret_environment_values(environment))


@pytest.mark.parametrize(
    ("key", "value"),
    (
        ("FLOWACCOUNT_SANDBOX_CLIENT_SECRET", "private-client-secret-value"),
        ("MERCURY_PUBLIC_MCP_TOKEN", "private-mcp-token-value"),
        ("CUSTOM_API_KEY", "private-custom-api-key-value"),
        ("SUPABASE_DB_URL", "postgresql://user:private-password@db.example.test/postgres"),
    ),
)
def test_render_log_scan_rejects_sensitive_environment_values(key: str, value: str) -> None:
    with pytest.raises(InspectionError, match="^render_log_secret_found$"):
        _assert_no_secret(value.encode(), _secret_environment_values({key: value}))
