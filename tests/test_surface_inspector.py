from __future__ import annotations

import json
from pathlib import Path

import pytest

from mercury_release_control.surface_inspector import (
    InspectionError,
    _render_status_endpoint,
    validate_policy,
)

ROOT = Path(__file__).resolve().parents[1]


def _configured_policy() -> dict[str, object]:
    policy = json.loads((ROOT / "policy-v0.2.2.json").read_text(encoding="utf-8"))
    policy["bootstrap_state"] = "configured"
    policy["repository_id"] = 1300000000
    return policy


def test_surface_inspector_accepts_only_configured_v022_policy() -> None:
    assert validate_policy(_configured_policy())["release"] == {
        "tag": "v0.2.2",
        "version": "0.2.2",
    }

    policy = _configured_policy()
    policy["release"] = {"tag": "v0.2.1", "version": "0.2.1"}
    with pytest.raises(InspectionError, match="^policy_release_boundary_invalid$"):
        validate_policy(policy)


def test_surface_inspector_binds_render_to_v022_and_reviewed_commit() -> None:
    endpoint = _render_status_endpoint(
        {
            "deployment_commit": "a" * 40,
            "mcp_endpoint": "https://mercury.example/mcp",
            "status": "ok",
            "version": "0.2.2",
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
