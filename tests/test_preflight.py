from __future__ import annotations

import copy

import pytest

from mercury_release_control.preflight import PreflightError, validate_preflight


@pytest.fixture
def policy() -> dict[str, object]:
    return {
        "branch": "main",
        "environment": "production-release",
        "forbidden_repository_secrets": ["RENDER_API_TOKEN", "SUPABASE_DB_URL"],
        "immutable_releases_required": True,
        "release_tag_ruleset": {
            "bypass_actors": [],
            "conditions": {"ref_name": {"exclude": [], "include": ["refs/tags/v0.2.2"]}},
            "enforcement": "active",
            "rules": [
                {"type": "deletion"},
                {
                    "parameters": {"update_allows_fetch_and_merge": False},
                    "type": "update",
                },
            ],
            "target": "tag",
        },
        "repository": "example/mercury-release-control-v2",
        "repository_id": 42,
        "required_environment_secrets": ["RENDER_API_TOKEN", "SUPABASE_DB_URL"],
        "required_environment_variables": ["TARGET_REPOSITORY"],
        "required_reviewer_ids": [1001],
        "required_status_checks": [
            {"app_id": 15368, "context": "Mercury release-control CI / required"}
        ],
        "reviewed_repository": "example/mercury-tools",
        "reviewed_repository_id": 84,
    }


def _snapshot(policy: dict[str, object]) -> dict[str, object]:
    return {
        "control": {
            "branch_protection": {
                "enforce_admins": True,
                "protected": True,
                "required_approving_review_count": 1,
                "required_status_checks": policy["required_status_checks"],
                "required_status_checks_strict": True,
            },
            "environment": {
                "can_admins_bypass": False,
                "deployment_branch_policy": {
                    "custom_branch_policies": False,
                    "protected_branches": True,
                },
                "name": "production-release",
                "prevent_self_review": True,
                "reviewer_ids": [1001],
            },
            "environment_secrets": policy["required_environment_secrets"],
            "environment_variables": policy["required_environment_variables"],
            "repository": {
                "default_branch": "main",
                "full_name": policy["repository"],
                "id": policy["repository_id"],
                "visibility": "public",
            },
            "repository_secrets": [],
        },
        "target": {
            "branch_protection": {"protected": True},
            "immutable_releases": {"enabled": True},
            "release_tag_rulesets": [policy["release_tag_ruleset"]],
            "repository": {
                "default_branch": "main",
                "full_name": policy["reviewed_repository"],
                "id": policy["reviewed_repository_id"],
                "visibility": "public",
            },
            "repository_secrets": [],
        },
    }


def test_preflight_returns_only_sanitized_protection_receipt(
    policy: dict[str, object],
) -> None:
    receipt = validate_preflight(policy, _snapshot(policy))

    assert receipt.control_repository_id == 42
    assert receipt.target_repository_id == 84
    assert receipt.environment == "production-release"
    assert receipt.required_reviewers == 1
    assert receipt.prevent_self_review is True
    assert receipt.admin_bypass_disabled is True
    assert receipt.protected_branch_only is True
    encoded = receipt.model_dump_json()
    for forbidden in ("token", "secret", "service_role"):
        assert forbidden not in encoded.lower()


@pytest.mark.parametrize(
    ("mutation", "code"),
    [
        (
            lambda snapshot: snapshot["control"]["repository"].update(id=43),
            "control_repository_identity_invalid",
        ),
        (
            lambda snapshot: snapshot["target"]["repository"].update(id=85),
            "target_repository_identity_invalid",
        ),
        (
            lambda snapshot: snapshot["control"]["environment"].update(prevent_self_review=False),
            "control_environment_protection_invalid",
        ),
        (
            lambda snapshot: snapshot["target"]["immutable_releases"].update(enabled=False),
            "target_release_protection_invalid",
        ),
    ],
)
def test_preflight_fails_closed(policy: dict[str, object], mutation, code: str) -> None:
    snapshot = copy.deepcopy(_snapshot(policy))
    mutation(snapshot)

    with pytest.raises(PreflightError, match=f"^{code}$"):
        validate_preflight(policy, snapshot)
