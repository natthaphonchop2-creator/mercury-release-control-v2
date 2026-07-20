"""Bounded GitHub snapshot collection for trusted preflight validation."""

from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Mapping
from typing import Protocol

from pydantic import SecretStr

from mercury_release_control.preflight import PreflightError

_RULESET_FIELDS = (
    "bypass_actors",
    "conditions",
    "enforcement",
    "name",
    "rules",
    "target",
)


class GitHubReader(Protocol):
    def get(self, path: str): ...


class GitHubApiReader:
    def __init__(self, *, token: SecretStr) -> None:
        self._token = token

    def get(self, path: str):
        if not path.startswith("/") or ".." in path or len(path) > 4096:
            raise PreflightError("github_path_invalid")
        request = urllib.request.Request(
            f"https://api.github.com{path}",
            headers={
                "Accept": "application/vnd.github+json",
                "Authorization": f"Bearer {self._token.get_secret_value()}",
                "User-Agent": "mercury-release-control-v2",
                "X-GitHub-Api-Version": "2026-03-10",
            },
        )
        try:
            with urllib.request.urlopen(request, timeout=20) as response:
                body = response.read(8 * 1024 * 1024 + 1)
        except (urllib.error.HTTPError, urllib.error.URLError, OSError, TimeoutError) as exc:
            raise PreflightError("github_query_failed") from exc
        if len(body) > 8 * 1024 * 1024:
            raise PreflightError("github_response_invalid")
        try:
            return json.loads(body, object_pairs_hook=_unique_object)
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
            raise PreflightError("github_response_invalid") from exc


def collect_remote_snapshot(
    policy: Mapping[str, object], reader: GitHubReader
) -> dict[str, object]:
    control_name = _text(policy.get("repository"))
    control_id = _positive_int(policy.get("repository_id"))
    target_name = _text(policy.get("reviewed_repository"))
    target_id = _positive_int(policy.get("reviewed_repository_id"))
    branch = urllib.parse.quote(_text(policy.get("branch")), safe="")
    environment_name = _text(policy.get("environment"))
    environment = urllib.parse.quote(environment_name, safe="")
    ruleset_policy = policy.get("release_tag_ruleset")
    if not isinstance(ruleset_policy, dict):
        raise PreflightError("policy_schema_invalid")
    ruleset_name = _text(ruleset_policy.get("name"))

    control_repository = _repository(reader.get(f"/repos/{control_name}"), control_name, control_id)
    target_repository = _repository(reader.get(f"/repos/{target_name}"), target_name, target_id)
    environment_payload = _mapping(reader.get(f"/repos/{control_name}/environments/{environment}"))
    control_protection = _mapping(reader.get(f"/repos/{control_name}/branches/{branch}/protection"))
    reader.get(f"/repos/{target_name}/branches/{branch}/protection")
    rule_summaries = reader.get(f"/repos/{target_name}/rulesets?per_page=100")
    if not isinstance(rule_summaries, list) or len(rule_summaries) >= 100:
        raise PreflightError("github_ruleset_inventory_invalid")
    matched_rulesets: list[dict[str, object]] = []
    for summary in rule_summaries:
        if not isinstance(summary, dict) or summary.get("name") != ruleset_name:
            continue
        ruleset_id = _positive_int(summary.get("id"))
        ruleset = _mapping(reader.get(f"/repos/{target_name}/rulesets/{ruleset_id}"))
        if ruleset.get("id") != ruleset_id or ruleset.get("name") != ruleset_name:
            raise PreflightError("github_ruleset_inventory_invalid")
        matched_rulesets.append({key: ruleset.get(key) for key in _RULESET_FIELDS})
    enforce_admins = _mapping(control_protection.get("enforce_admins"))
    pull_reviews = _mapping(control_protection.get("required_pull_request_reviews"))
    status_checks = _mapping(control_protection.get("required_status_checks"))
    checks = status_checks.get("checks")
    if not isinstance(checks, list) or len(checks) > 100:
        raise PreflightError("github_branch_protection_invalid")
    normalized_checks: list[dict[str, object]] = []
    for check in checks:
        if not isinstance(check, dict):
            raise PreflightError("github_branch_protection_invalid")
        normalized_checks.append(
            {"app_id": _positive_int(check.get("app_id")), "context": _text(check.get("context"))}
        )
    return {
        "control": {
            "branch_protection": {
                "enforce_admins": enforce_admins.get("enabled"),
                "protected": True,
                "required_approving_review_count": pull_reviews.get(
                    "required_approving_review_count"
                ),
                "required_status_checks": sorted(
                    normalized_checks, key=lambda item: str(item["context"])
                ),
                "required_status_checks_strict": status_checks.get("strict"),
            },
            "environment": {
                "can_admins_bypass": environment_payload.get("can_admins_bypass"),
                "deployment_branch_policy": environment_payload.get("deployment_branch_policy"),
                "name": environment_payload.get("name"),
                "prevent_self_review": _prevent_self_review(environment_payload),
                "reviewer_ids": _reviewer_ids(environment_payload),
            },
            "environment_secrets": _inventory(
                reader.get(
                    f"/repositories/{control_id}/environments/{environment}/secrets?per_page=100"
                ),
                "secrets",
            ),
            "environment_variables": _inventory(
                reader.get(
                    f"/repositories/{control_id}/environments/{environment}/variables?per_page=100"
                ),
                "variables",
            ),
            "repository": control_repository,
            "repository_secrets": _inventory(
                reader.get(f"/repos/{control_name}/actions/secrets?per_page=100"),
                "secrets",
            ),
        },
        "target": {
            "branch_protection": {"protected": True},
            "immutable_releases": {
                "enabled": _mapping(reader.get(f"/repos/{target_name}/immutable-releases")).get(
                    "enabled"
                )
            },
            "release_tag_rulesets": matched_rulesets,
            "repository": target_repository,
            "repository_secrets": _inventory(
                reader.get(f"/repos/{target_name}/actions/secrets?per_page=100"),
                "secrets",
            ),
        },
    }


def _repository(raw: object, name: str, repository_id: int) -> dict[str, object]:
    payload = _mapping(raw)
    if payload.get("full_name") != name or payload.get("id") != repository_id:
        raise PreflightError("github_repository_identity_invalid")
    return {
        "default_branch": payload.get("default_branch"),
        "full_name": payload.get("full_name"),
        "id": payload.get("id"),
        "visibility": payload.get("visibility"),
    }


def _reviewer_ids(environment: Mapping[str, object]) -> list[int]:
    rules = environment.get("protection_rules")
    if not isinstance(rules, list):
        raise PreflightError("github_environment_invalid")
    output: set[int] = set()
    for rule in rules:
        if not isinstance(rule, dict) or rule.get("type") != "required_reviewers":
            continue
        reviewers = rule.get("reviewers")
        if not isinstance(reviewers, list):
            raise PreflightError("github_environment_invalid")
        for record in reviewers:
            reviewer = _mapping(_mapping(record).get("reviewer", record))
            output.add(_positive_int(reviewer.get("id")))
    return sorted(output)


def _prevent_self_review(environment: Mapping[str, object]) -> bool:
    rules = environment.get("protection_rules")
    if not isinstance(rules, list):
        raise PreflightError("github_environment_invalid")
    reviewer_rules = [
        rule
        for rule in rules
        if isinstance(rule, dict) and rule.get("type") == "required_reviewers"
    ]
    if len(reviewer_rules) != 1 or not isinstance(
        reviewer_rules[0].get("prevent_self_review"), bool
    ):
        raise PreflightError("github_environment_invalid")
    return reviewer_rules[0]["prevent_self_review"]


def _inventory(raw: object, key: str) -> list[str]:
    payload = _mapping(raw)
    records = payload.get(key)
    if not isinstance(records, list) or len(records) >= 100:
        raise PreflightError("github_inventory_invalid")
    output = [_text(_mapping(record).get("name")) for record in records]
    return sorted(output)


def _mapping(value: object) -> dict[str, object]:
    if not isinstance(value, dict):
        raise PreflightError("github_response_invalid")
    return value


def _text(value: object) -> str:
    if not isinstance(value, str) or not value or len(value) > 256:
        raise PreflightError("policy_schema_invalid")
    return value


def _positive_int(value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise PreflightError("policy_schema_invalid")
    return value


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    output: dict[str, object] = {}
    for key, value in pairs:
        if key in output:
            raise ValueError("duplicate JSON key")
        output[key] = value
    return output
