"""Strict GitHub repository and protected-environment preflight validation."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping

from pydantic import BaseModel, ConfigDict, Field

from mercury_release_control.release_profile import (
    ReleaseProfileError,
    release_profile_from_policy,
)


class PreflightError(RuntimeError):
    """A constant-code trusted preflight failure."""


class PreflightReceipt(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    admin_bypass_disabled: bool
    control_repository_id: int = Field(gt=0)
    environment: str = Field(min_length=1, max_length=128)
    prevent_self_review: bool
    protected_branch_only: bool
    required_configuration_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    required_reviewers: int = Field(gt=0, le=100)
    target_repository_id: int = Field(gt=0)


def validate_preflight(
    policy: Mapping[str, object], snapshot: Mapping[str, object]
) -> PreflightReceipt:
    try:
        profile = release_profile_from_policy(policy)
    except ReleaseProfileError as exc:
        raise PreflightError("policy_schema_invalid") from exc
    control = _mapping(snapshot, "control", "preflight_snapshot_invalid")
    target = _mapping(snapshot, "target", "preflight_snapshot_invalid")
    _repository(
        _mapping(control, "repository", "control_repository_identity_invalid"),
        expected_id=_integer(policy.get("repository_id"), "policy_schema_invalid"),
        expected_name=_string(policy.get("repository"), "policy_schema_invalid"),
        code="control_repository_identity_invalid",
    )
    _repository(
        _mapping(target, "repository", "target_repository_identity_invalid"),
        expected_id=_integer(policy.get("reviewed_repository_id"), "policy_schema_invalid"),
        expected_name=_string(policy.get("reviewed_repository"), "policy_schema_invalid"),
        code="target_repository_identity_invalid",
    )
    branch = _string(policy.get("branch"), "policy_schema_invalid")
    if branch != "main":
        raise PreflightError("policy_schema_invalid")
    control_repo = _mapping(control, "repository", "control_repository_identity_invalid")
    target_repo = _mapping(target, "repository", "target_repository_identity_invalid")
    if control_repo.get("default_branch") != branch or control_repo.get("visibility") != "public":
        raise PreflightError("control_repository_protection_invalid")
    if target_repo.get("default_branch") != branch or target_repo.get("visibility") != "public":
        raise PreflightError("target_repository_protection_invalid")
    _control_branch(
        policy,
        control,
        required_approving_review_count=profile.required_approving_review_count,
    )
    environment = _control_environment(
        policy,
        control,
        prevent_self_review=profile.prevent_self_review,
    )
    if (
        _mapping(target, "branch_protection", "target_branch_protection_invalid").get("protected")
        is not True
    ):
        raise PreflightError("target_branch_protection_invalid")
    if (
        policy.get("immutable_releases_required") is not True
        or _mapping(target, "immutable_releases", "target_release_protection_invalid").get(
            "enabled"
        )
        is not True
    ):
        raise PreflightError("target_release_protection_invalid")
    rulesets = target.get("release_tag_rulesets")
    if not isinstance(rulesets, list) or rulesets != [policy.get("release_tag_ruleset")]:
        raise PreflightError("target_release_protection_invalid")
    forbidden = _string_list(policy.get("forbidden_repository_secrets"))
    if set(_string_list(target.get("repository_secrets"))) & set(forbidden):
        raise PreflightError("target_repository_secret_forbidden")
    if set(_string_list(control.get("repository_secrets"))) & set(forbidden):
        raise PreflightError("control_repository_secret_forbidden")
    reviewers = _integer_list(policy.get("required_reviewer_ids"))
    configuration = {
        "branch": branch,
        "environment": policy.get("environment"),
        "release_tag_ruleset": policy.get("release_tag_ruleset"),
        "required_approving_review_count": profile.required_approving_review_count,
        "required_environment_secrets": policy.get("required_environment_secrets"),
        "required_environment_variables": policy.get("required_environment_variables"),
        "required_reviewer_ids": reviewers,
        "required_status_checks": policy.get("required_status_checks"),
        "prevent_self_review": profile.prevent_self_review,
    }
    digest = hashlib.sha256(
        json.dumps(configuration, separators=(",", ":"), sort_keys=True).encode()
    ).hexdigest()
    return PreflightReceipt(
        admin_bypass_disabled=True,
        control_repository_id=_integer(policy.get("repository_id"), "policy_schema_invalid"),
        environment=environment,
        prevent_self_review=profile.prevent_self_review,
        protected_branch_only=True,
        required_configuration_sha256=digest,
        required_reviewers=len(reviewers),
        target_repository_id=_integer(
            policy.get("reviewed_repository_id"), "policy_schema_invalid"
        ),
    )


def _repository(
    repository: Mapping[str, object],
    *,
    expected_id: int,
    expected_name: str,
    code: str,
) -> None:
    observed_id = repository.get("id")
    if (
        isinstance(observed_id, bool)
        or observed_id != expected_id
        or repository.get("full_name") != expected_name
    ):
        raise PreflightError(code)


def _control_branch(
    policy: Mapping[str, object],
    control: Mapping[str, object],
    *,
    required_approving_review_count: int,
) -> None:
    protection = _mapping(control, "branch_protection", "control_branch_protection_invalid")
    if (
        protection.get("protected") is not True
        or protection.get("enforce_admins") is not True
        or protection.get("required_approving_review_count")
        != required_approving_review_count
        or protection.get("required_status_checks_strict") is not True
        or protection.get("required_status_checks") != policy.get("required_status_checks")
    ):
        raise PreflightError("control_branch_protection_invalid")


def _control_environment(
    policy: Mapping[str, object],
    control: Mapping[str, object],
    *,
    prevent_self_review: bool,
) -> str:
    expected = _string(policy.get("environment"), "policy_schema_invalid")
    environment = _mapping(control, "environment", "control_environment_protection_invalid")
    deployment = _mapping(
        environment,
        "deployment_branch_policy",
        "control_environment_protection_invalid",
    )
    reviewers = _integer_list(policy.get("required_reviewer_ids"))
    if (
        environment.get("name") != expected
        or environment.get("reviewer_ids") != reviewers
        or environment.get("prevent_self_review") is not prevent_self_review
        or environment.get("can_admins_bypass") is not False
        or deployment.get("protected_branches") is not True
        or deployment.get("custom_branch_policies") is not False
        or control.get("environment_secrets") != policy.get("required_environment_secrets")
        or control.get("environment_variables") != policy.get("required_environment_variables")
    ):
        raise PreflightError("control_environment_protection_invalid")
    return expected


def _mapping(value: Mapping[str, object], key: str, code: str) -> Mapping[str, object]:
    observed = value.get(key)
    if not isinstance(observed, dict):
        raise PreflightError(code)
    return observed


def _integer(value: object, code: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise PreflightError(code)
    return value


def _string(value: object, code: str) -> str:
    if not isinstance(value, str) or not value or len(value) > 256:
        raise PreflightError(code)
    return value


def _integer_list(value: object) -> list[int]:
    if not isinstance(value, list) or not value:
        raise PreflightError("policy_schema_invalid")
    output: list[int] = []
    for item in value:
        output.append(_integer(item, "policy_schema_invalid"))
    if len(output) != len(set(output)):
        raise PreflightError("policy_schema_invalid")
    return output


def _string_list(value: object) -> list[str]:
    if not isinstance(value, list):
        raise PreflightError("policy_schema_invalid")
    output: list[str] = []
    for item in value:
        output.append(_string(item, "policy_schema_invalid"))
    if len(output) != len(set(output)):
        raise PreflightError("policy_schema_invalid")
    return output
