from __future__ import annotations

import json
from pathlib import Path

import pytest

from mercury_release_control.surface_inspector import (
    InspectionError,
    _render_log_url,
    _render_status_endpoint,
    validate_environment,
    validate_policy,
)

ROOT = Path(__file__).resolve().parents[1]


def _configured_policy() -> dict[str, object]:
    policy = json.loads((ROOT / "policy-v0.3.0.json").read_text(encoding="utf-8"))
    policy["bootstrap_state"] = "configured"
    policy["repository_id"] = 1300000000
    return policy


def test_surface_inspector_accepts_only_configured_v030_policy() -> None:
    assert validate_policy(_configured_policy())["release"] == {
        "tag": "v0.3.0",
        "version": "0.3.0",
    }

    policy = _configured_policy()
    policy["release"] = {"tag": "v0.2.1", "version": "0.2.1"}
    with pytest.raises(InspectionError, match="^policy_release_boundary_invalid$"):
        validate_policy(policy)


def test_surface_inspector_binds_render_to_v030_and_reviewed_commit() -> None:
    endpoint = _render_status_endpoint(
        {
            "deployment_commit": "a" * 40,
            "mcp_endpoint": "https://mercury.example/mcp",
            "status": "ok",
            "version": "0.3.0",
        },
        base_url="https://mercury.example",
        reviewed_sha="a" * 40,
    )
    assert endpoint == "https://mercury.example/mcp"

    with pytest.raises(InspectionError, match="^render_status_invalid$"):
        _render_status_endpoint(
            {
                "deployment_commit": "a" * 40,
                "mcp_endpoint": "https://mercury.example/mcp",
                "status": "ok",
                "version": "0.2.1",
            },
            base_url="https://mercury.example",
            reviewed_sha="a" * 40,
        )


def _valid_environment() -> dict[str, str]:
    return {
        "FLOWACCOUNT_SANDBOX_BASE_URL": "https://openapi.flowaccount.com/test",
        "FLOWACCOUNT_SANDBOX_CLIENT_ID": "client-id",
        "FLOWACCOUNT_SANDBOX_CLIENT_SECRET": "client-secret",
        "INSPECTOR_GIT": "/usr/bin/git",
        "INSPECTOR_GITLEAKS": "/usr/local/bin/gitleaks",
        "INSPECTOR_TRUFFLEHOG": "/usr/local/bin/trufflehog",
        "MERCURY_MARKETPLACE_SNAPSHOT_URL": "https://example.invalid/marketplace.json",
        "MERCURY_PUBLIC_MCP_TOKEN": "public-token",
        "MERCURY_PUBLIC_MCP_URL": "https://mercury.example",
        "MERCURY_STAGING_REPOSITORY_TOKEN": "staging-token",
        "MERCURY_TARGET_REPOSITORY_READ_TOKEN": "read-token",
        "RENDER_API_TOKEN": "render-token",
        "RENDER_API_URL": "https://api.render.com",
        "RENDER_OWNER_ID": "tea_01HZX6R9HQSPX9K4GTDR",
        "RENDER_SERVICE_ID": "srv-d978tk37uimc73ej52mg",
        "STAGING_REPOSITORY": "natthaphonchop2-creator/mercury-tools-staging",
        "SUPABASE_DB_URL": "postgresql://user:password@db.example:5432/postgres",
        "SUPABASE_URL": "https://vbnlkqvauqwnjbxngkas.supabase.co",
        "TARGET_REPOSITORY": "natthaphonchop2-creator/mercury-tools",
    }


def test_surface_inspector_requires_safe_render_owner_id() -> None:
    policy = _configured_policy()
    environment = _valid_environment()

    validate_environment(policy, environment)

    environment.pop("RENDER_OWNER_ID")
    with pytest.raises(InspectionError, match="^environment_value_invalid$"):
        validate_environment(policy, environment)

    environment["RENDER_OWNER_ID"] = "tea_01HZX6R9HQSPX9K4GTDR&forged=true"
    with pytest.raises(InspectionError, match="^render_owner_id_invalid$"):
        validate_environment(policy, environment)


@pytest.mark.parametrize("log_type", ("build", "runtime"))
def test_surface_inspector_render_log_urls_bind_owner_id(log_type: str) -> None:
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
