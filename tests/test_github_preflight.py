from __future__ import annotations

import pytest

from mercury_release_control.github_preflight import collect_remote_snapshot
from mercury_release_control.preflight import PreflightError


def _policy() -> dict[str, object]:
    return {
        "branch": "main",
        "environment": "production-release",
        "release_tag_ruleset": {"name": "Mercury v0.3.0 immutable release tag"},
        "repository": "example/control",
        "repository_id": 42,
        "reviewed_repository": "example/target",
        "reviewed_repository_id": 84,
    }


class FakeGitHub:
    def get(self, path: str):
        responses = {
            "/repos/example/control": {
                "default_branch": "main",
                "full_name": "example/control",
                "id": 42,
                "visibility": "public",
            },
            "/repos/example/target": {
                "default_branch": "main",
                "full_name": "example/target",
                "id": 84,
                "visibility": "public",
            },
            "/repos/example/control/environments/production-release": {
                "can_admins_bypass": False,
                "deployment_branch_policy": {
                    "custom_branch_policies": False,
                    "protected_branches": True,
                },
                "name": "production-release",
                "protection_rules": [
                    {
                        "prevent_self_review": False,
                        "reviewers": [{"reviewer": {"id": 1001}}],
                        "type": "required_reviewers",
                    }
                ],
            },
            "/repos/example/control/branches/main/protection": {
                "enforce_admins": {"enabled": True},
                "required_pull_request_reviews": None,
                "required_status_checks": {
                    "checks": [
                        {
                            "app_id": 15368,
                            "context": "required",
                        },
                        {
                            "app_id": 15368,
                            "context": "verify-candidate-as-data",
                        },
                    ],
                    "strict": True,
                },
            },
            "/repos/example/target/branches/main/protection": {"url": "protected"},
            "/repositories/42/environments/production-release/secrets?per_page=100": {
                "secrets": [{"name": "RENDER_API_TOKEN"}]
            },
            "/repositories/42/environments/production-release/variables?per_page=100": {
                "variables": [{"name": "TARGET_REPOSITORY"}]
            },
            "/repos/example/control/actions/secrets?per_page=100": {"secrets": []},
            "/repos/example/target/actions/secrets?per_page=100": {"secrets": []},
            "/repos/example/target/rulesets?per_page=100": [
                {"id": 9, "name": "Mercury v0.3.0 immutable release tag"}
            ],
            "/repos/example/target/rulesets/9": {
                "bypass_actors": [],
                "conditions": {
                    "ref_name": {
                        "exclude": [],
                        "include": ["refs/tags/v0.3.0"],
                    }
                },
                "enforcement": "active",
                "id": 9,
                "name": "Mercury v0.3.0 immutable release tag",
                "rules": [{"type": "deletion"}],
                "target": "tag",
            },
            "/repos/example/target/immutable-releases": {"enabled": True},
        }
        return responses[path]


def test_remote_snapshot_collects_only_preflight_fields() -> None:
    snapshot = collect_remote_snapshot(_policy(), FakeGitHub())

    assert snapshot["control"]["repository"]["id"] == 42
    assert snapshot["control"]["environment"]["prevent_self_review"] is False
    assert snapshot["control"]["branch_protection"]["required_approving_review_count"] == 0
    assert snapshot["control"]["branch_protection"]["required_status_checks"] == [
        {"app_id": 15368, "context": "required"},
        {"app_id": 15368, "context": "verify-candidate-as-data"},
    ]
    assert snapshot["control"]["environment"]["reviewer_ids"] == [1001]
    assert snapshot["target"]["repository"]["id"] == 84
    assert snapshot["target"]["release_tag_rulesets"][0]["target"] == "tag"
    assert snapshot["target"]["immutable_releases"] == {"enabled": True}


def test_remote_snapshot_rejects_missing_nested_prevent_self_review() -> None:
    github = FakeGitHub()
    original_get = github.get

    def get(path: str):
        response = original_get(path)
        if path == "/repos/example/control/environments/production-release":
            response = dict(response)
            response["protection_rules"] = [
                {
                    "reviewers": [{"reviewer": {"id": 1001}}],
                    "type": "required_reviewers",
                }
            ]
        return response

    github.get = get  # type: ignore[method-assign]

    with pytest.raises(PreflightError, match="^github_environment_invalid$"):
        collect_remote_snapshot(_policy(), github)


def test_remote_snapshot_rejects_malformed_pull_review_rule() -> None:
    github = FakeGitHub()
    original_get = github.get

    def get(path: str):
        response = original_get(path)
        if path == "/repos/example/control/branches/main/protection":
            response = dict(response)
            response["required_pull_request_reviews"] = {
                "required_approving_review_count": 0
            }
        return response

    github.get = get  # type: ignore[method-assign]

    with pytest.raises(PreflightError, match="^github_branch_protection_invalid$"):
        collect_remote_snapshot(_policy(), github)
