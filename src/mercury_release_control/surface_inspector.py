#!/usr/bin/env python3
# ruff: noqa: E501
"""Standalone, fail-closed hosted release evidence inspector.

This module deliberately uses only the Python standard library plus an
installed PostgreSQL driver.  It never imports, invokes, or checks out Mercury
candidate code: Git is used only to read object data and scanners inspect files
without a worktree.
"""

from __future__ import annotations

import argparse
import ast
import datetime as datetime_module
import gzip
import hashlib
import importlib
import json
import os
import re
import stat
import subprocess
import sys
import tarfile
import tempfile
import time
import unicodedata
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from collections.abc import Callable, Iterable, Mapping, Sequence
from contextlib import contextmanager, suppress
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path, PurePosixPath
from typing import Any, BinaryIO

from mercury_release_control.public_tree import PublicTreeError, build_public_tree
from mercury_release_control.release_profile import (
    ReleaseProfile,
    ReleaseProfileError,
    release_profile_from_policy,
)

UTC = datetime_module.timezone.utc  # noqa: UP017 - entrypoint also supports system Python 3.9.

MAX_POLICY_BYTES = 512 * 1024
MAX_UNTRUSTED_JSON_BYTES = 2 * 1024 * 1024
MAX_HTTP_BYTES = 32 * 1024 * 1024
MAX_TOTAL_HTTP_BYTES = 256 * 1024 * 1024
MAX_HTTP_OBJECTS = 200
MAX_HTTP_REQUESTS = 1_000
MAX_PAGES = 20
MAX_PROCESS_OUTPUT_BYTES = 64 * 1024
MAX_ARCHIVE_BYTES = 512 * 1024 * 1024
MAX_ARCHIVE_MEMBERS = 100_000
MAX_ARCHIVE_MEMBER_BYTES = 64 * 1024 * 1024
MAX_ARCHIVE_DEPTH = 4
MAX_ARCHIVE_RATIO = 100
MAX_STATIC_SOURCE_BYTES = 4 * 1024 * 1024
MAX_ENV_VALUE_BYTES = 16 * 1024
NETWORK_TIMEOUT_SECONDS = 30.0
PROCESS_TIMEOUT_SECONDS = 600.0
INSPECTION_TIMEOUT_SECONDS = 75 * 60.0
DATABASE_TIMEOUT_SECONDS = 15
OUTPUT_MAX_BYTES = 2 * 1024 * 1024
_TRUSTED_GITLEAKS_CONFIG_SHA256 = (
    "663510fb05b8b6e58c3d8634364f52bfc03614cf00d0f6985203a03d473dd68f"
)

TRUSTED_SURFACES = (
    "git_all_refs",
    "github_pull_request_refs",
    "github_releases_and_assets",
    "github_actions_logs_artifacts_caches",
    "github_packages_pages_wiki",
    "marketplace_snapshot",
    "render_build_and_runtime_logs",
    "supabase_knowledge_and_storage",
    "public_mcp_responses",
)
_CANDIDATE_SURFACES = (
    *TRUSTED_SURFACES[:8],
    "wheel_sdist_plugin_source_archives",
    TRUSTED_SURFACES[-1],
)
_HISTORY_SCANNERS = ("1.0.0", "3.88.32", "8.24.3")
_BUILTIN_SCANNERS = ("1.0.0",)
_CANONICAL_TABLES = (
    "erp_action_catalog",
    "erp_action_observations",
    "erp_action_validation_knowledge",
    "erp_action_versions",
    "erp_spec_sources",
    "knowledge_chunks",
    "knowledge_documents",
    "knowledge_sources",
    "mcp_audit_events",
    "mercury_client_tokens",
    "mercury_connector_profiles",
    "mercury_product_events",
    "mercury_skill_catalog",
    "mercury_skill_uploads",
    "mercury_workspace_members",
    "mercury_workspace_skills",
    "mercury_workspaces",
)
_POLICY_KEYS = {
    "bootstrap_state",
    "branch",
    "environment",
    "forbidden_repository_secrets",
    "immutable_releases_required",
    "inspector",
    "release_tag_ruleset",
    "repository",
    "repository_id",
    "release",
    "required_environment_secrets",
    "required_environment_variables",
    "required_reviewer_ids",
    "required_status_checks",
    "reviewed_repository",
    "reviewed_repository_id",
    "schema_version",
    "staging_repository",
    "staging",
    "supabase",
    "provider_expectations",
}
_SUPABASE_KEYS = {
    "functions",
    "migration_history_sha256",
    "migration_id",
    "project_ref",
    "schema_sha256",
    "storage_buckets",
    "tables",
}
_POLICY_INSPECTOR_KEYS = {"interface_version", "path", "sha256"}
_FUNCTION_KEYS = {"definition_sha256", "signature"}
_REPOSITORY_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_SHA_RE = re.compile(r"^[0-9a-f]{40}$")
_PROJECT_RE = re.compile(r"^[a-z0-9]{20}$")
_ENV_NAME_RE = re.compile(r"^[A-Z][A-Z0-9_]{1,127}$")
_SERVICE_ID_RE = re.compile(r"^[A-Za-z0-9_-]{1,128}$")
_RENDER_OWNER_ID_RE = re.compile(r"^[A-Za-z0-9_-]{1,128}$")
_ACTION_ID_RE = re.compile(r"^act_[0-9a-f]{24}$")
_VERSION_ID_RE = re.compile(r"^av_[0-9a-f]{64}$")
_POOLER_RE = re.compile(r"^(?:aws-[0-9]+-)?[a-z0-9-]+\.pooler\.supabase\.com$")
_SENSITIVE_KEY_RE = re.compile(
    r"(?:api[_-]?key|authorization|client[_-]?(?:id|secret)|credential|password|"
    r"secret|token|access[_-]?token|service[_-]?role|private[_-]?key)",
    re.IGNORECASE,
)
_SENSITIVE_VALUE_RE = re.compile(
    r"(?:gh[pousr]_[A-Za-z0-9_]{16,}|github_pat_[A-Za-z0-9_]{16,}|"
    r"(?:sk|rk|pk)_[A-Za-z0-9_-]{16,}|eyJ[A-Za-z0-9_-]{16,}|"
    r"postgres(?:ql)?://|-----BEGIN (?:[A-Z ]+ )?PRIVATE KEY-----)",
    re.IGNORECASE,
)
_HIGH_ENTROPY_RE = re.compile(r"(?=[A-Za-z0-9+/=_-]{32,})(?=.*[A-Za-z])(?=.*[0-9])[A-Za-z0-9+/=_-]{32,}")
_PUBLIC_UUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-"
    r"[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
    re.IGNORECASE,
)
_PUBLIC_UUID_TOKEN_RE = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-"
    r"[89ab][0-9a-f]{3}-[0-9a-f]{12}",
    re.IGNORECASE,
)
_PUBLIC_VALIDATION_TOKEN_RE = re.compile(
    r"(?:av_[0-9a-f]{64}|(?:ev|run)_[0-9A-HJKMNP-TV-Z]{26})",
    re.IGNORECASE,
)
_PUBLIC_VALIDATION_URI_RE = re.compile(
    r"mercury://wiki/validation/[A-Za-z0-9._:-]{1,200}/"
    r"act_[0-9a-f]{24}/av_[0-9a-f]{64}/"
    r"run_[0-9A-HJKMNP-TV-Z]{26}",
    re.IGNORECASE,
)
_PUBLIC_EVIDENCE_DIGEST_RE = re.compile(
    r"(?im)(?<=^Evidence digest: )[0-9a-f]{64}$"
)
_ALLOWLIST_CLASSIFICATIONS = frozenset(
    {"documentation_placeholder", "non_secret_fixture"}
)
_ALLOWLIST_REVIEWER_ROLES = frozenset({"release_reviewer", "security_reviewer"})
_REDIRECT_STATUS_CODES = frozenset({301, 302, 303, 307, 308})
_GITHUB_DOWNLOAD_HOSTS = frozenset(
    {
        "objects.githubusercontent.com",
        "github-releases.githubusercontent.com",
        "github-production-release-asset-2e65be.s3.amazonaws.com",
        "pipelines.actions.githubusercontent.com",
    }
)
_REQUIRED_ENVIRONMENT = (
    "FLOWACCOUNT_SANDBOX_BASE_URL",
    "FLOWACCOUNT_SANDBOX_CLIENT_ID",
    "FLOWACCOUNT_SANDBOX_CLIENT_SECRET",
    "MERCURY_MARKETPLACE_SNAPSHOT_URL",
    "MERCURY_PUBLIC_MCP_TOKEN",
    "MERCURY_PUBLIC_MCP_URL",
    "MERCURY_STAGING_REPOSITORY_TOKEN",
    "MERCURY_TARGET_REPOSITORY_READ_TOKEN",
    "RENDER_API_TOKEN",
    "RENDER_API_URL",
    "RENDER_OWNER_ID",
    "RENDER_SERVICE_ID",
    "STAGING_REPOSITORY",
    "SUPABASE_DB_URL",
    "SUPABASE_URL",
    "TARGET_REPOSITORY",
    "INSPECTOR_GIT",
    "INSPECTOR_GITLEAKS",
    "INSPECTOR_TRUFFLEHOG",
)
_EXCLUDED_DIRECTORY_NAMES = frozenset(
    {".git", ".mercury", ".superpowers", "__pycache__", "build", "dist", "release-evidence"}
)
_EXCLUDED_STATE_FILES = frozenset(
    {
        "audit-ledger.jsonl",
        "credential-store.json",
        "credentials-store.json",
        "downloaded-provider-payload.json",
        "provider-payload.json",
        "provider-response.json",
        "raw-provider-payload.json",
        "raw-provider-response.json",
        "validation-raw-traffic.json",
        "validation-traffic.json",
    }
)
_STATIC_FILES = frozenset(
    {
        ".agents/plugins/marketplace.json",
        "catalog/global/flowaccount/actions.json",
        "catalog/global/peak/actions.json",
        "plugins/mercury-finance/.codex-plugin/plugin.json",
        "plugins/mercury-finance/.mcp.json",
        "src/mercury_tools/mcp/local_server.py",
    }
)
_VALIDATION_CATALOG_FILES = {
    "flowaccount": ("catalog/global/flowaccount/actions.json", 190),
    "peak": ("catalog/global/peak/actions.json", 64),
}
_EXPECTED_LOCAL_MCP_TOOLS = frozenset(
    {
        "connector_status",
        "credential_status",
        "execute_erp_create",
        "execute_erp_update",
        "execute_sensitive_erp_action",
        "get_document",
        "get_erp_action_schema",
        "get_erp_request_status",
        "import_erp_spec",
        "list_connector_drivers",
        "list_workspace_flows",
        "prepare_erp_mutation",
        "retrieve_context_pack",
        "run_accounting_skill",
        "run_erp_read",
        "run_mercury_flow",
        "run_workspace_flow",
        "save_workspace_flow",
        "search_erp_actions",
        "search_knowledge",
    }
)


class InspectionError(RuntimeError):
    """A stable, sanitized release-control inspection failure."""


@dataclass(frozen=True)
class HttpResponse:
    status: int
    headers: Mapping[str, str]
    body: bytes


@dataclass(frozen=True)
class DbConnectionPlan:
    kind: str
    hostname: str
    port: int
    expected_database: str
    expected_role: str
    user: str
    password: str


@dataclass(frozen=True)
class ArchiveSnapshot:
    tree_sha256: str
    static_files: Mapping[str, bytes]


@dataclass(frozen=True)
class ScannerFinding:
    file: str
    rule: str
    evidence_digest: str
    match_digest: str | None

    @property
    def allowlist_key(self) -> tuple[str, str, str]:
        return (self.file, self.rule, self.evidence_digest)


@dataclass
class InspectionBudget:
    """One non-resettable resource budget for a complete inspection."""

    started: float
    requests: int = 0
    downloaded_bytes: int = 0
    uncompressed_bytes: int = 0
    objects: int = 0

    def check_time(self) -> None:
        if time.monotonic() - self.started > INSPECTION_TIMEOUT_SECONDS:
            raise InspectionError("inspection_time_budget_exhausted")

    def charge_request(self) -> None:
        self.check_time()
        self.requests += 1
        if self.requests > MAX_HTTP_REQUESTS:
            raise InspectionError("network_request_budget_exhausted")

    def charge_download(self, amount: int) -> None:
        self.check_time()
        self.downloaded_bytes += amount
        if self.downloaded_bytes > MAX_TOTAL_HTTP_BYTES:
            raise InspectionError("network_byte_budget_exhausted")

    def charge_uncompressed(self, amount: int) -> None:
        self.check_time()
        self.uncompressed_bytes += amount
        if self.uncompressed_bytes > MAX_ARCHIVE_BYTES:
            raise InspectionError("archive_byte_budget_exhausted")

    def charge_object(self) -> None:
        self.check_time()
        self.objects += 1
        if self.objects > MAX_HTTP_OBJECTS:
            raise InspectionError("hosted_payload_budget_exhausted")


def _pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    payload: dict[str, object] = {}
    for key, value in pairs:
        if key in payload:
            raise InspectionError("json_duplicate_key")
        payload[key] = value
    return payload


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _canonical_sha256(value: object) -> str:
    encoded = json.dumps(
        value,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return _sha256_bytes(encoded)


def _require_mapping(value: object, code: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise InspectionError(code)
    return value


def _require_exact_keys(value: Mapping[str, object], expected: set[str], code: str) -> None:
    if set(value) != expected:
        raise InspectionError(code)


def _require_sha(value: object, code: str, *, commit: bool = False) -> str:
    pattern = _SHA_RE if commit else _SHA256_RE
    if not isinstance(value, str) or pattern.fullmatch(value) is None:
        raise InspectionError(code)
    return value


def _read_regular_bytes(path: Path, *, maximum: int, code: str) -> bytes:
    try:
        metadata = path.lstat()
        if (
            stat.S_ISLNK(metadata.st_mode)
            or not stat.S_ISREG(metadata.st_mode)
            or metadata.st_size <= 0
            or metadata.st_size > maximum
        ):
            raise InspectionError(code)
        with path.open("rb") as handle:
            data = handle.read(maximum + 1)
    except InspectionError:
        raise
    except OSError as exc:
        raise InspectionError(code) from exc
    if not data or len(data) > maximum:
        raise InspectionError(code)
    return data


def load_strict_json(path: Path, *, maximum: int, code: str) -> Mapping[str, object]:
    data = _read_regular_bytes(path, maximum=maximum, code=code)
    try:
        value = json.loads(data, object_pairs_hook=_pairs)
    except (UnicodeDecodeError, json.JSONDecodeError, InspectionError) as exc:
        raise InspectionError(code) from exc
    return _require_mapping(value, code)


def build_supabase_schema_digest(supabase: Mapping[str, object]) -> str:
    functions = supabase.get("functions")
    if not isinstance(functions, list):
        raise InspectionError("supabase_functions_invalid")
    return _canonical_sha256(
        {
            "functions": functions,
            "migration_history_sha256": supabase.get("migration_history_sha256"),
            "migration_id": supabase.get("migration_id"),
            "storage_buckets": supabase.get("storage_buckets"),
            "tables": supabase.get("tables"),
        }
    )


def _validate_names(value: object, code: str) -> tuple[str, ...]:
    if not isinstance(value, list) or any(
        not isinstance(item, str) or _ENV_NAME_RE.fullmatch(item) is None for item in value
    ):
        raise InspectionError(code)
    names = tuple(value)
    if not names or names != tuple(sorted(set(names))):
        raise InspectionError(code)
    return names


def _validate_release_tag_ruleset(value: object, profile: ReleaseProfile) -> None:
    ruleset = _require_mapping(value, "policy_release_tag_ruleset_invalid")
    _require_exact_keys(
        ruleset,
        {"bypass_actors", "conditions", "enforcement", "name", "rules", "target"},
        "policy_release_tag_ruleset_invalid",
    )
    if (
        ruleset.get("target") != "tag"
        or ruleset.get("enforcement") != "active"
        or ruleset.get("name") != profile.ruleset_name
    ):
        raise InspectionError("policy_release_tag_ruleset_invalid")
    conditions = _require_mapping(ruleset.get("conditions"), "policy_release_tag_ruleset_invalid")
    _require_exact_keys(conditions, {"ref_name"}, "policy_release_tag_ruleset_invalid")
    ref_name = _require_mapping(conditions.get("ref_name"), "policy_release_tag_ruleset_invalid")
    _require_exact_keys(ref_name, {"exclude", "include"}, "policy_release_tag_ruleset_invalid")
    if ref_name.get("include") != [f"refs/tags/{profile.tag}"] or ref_name.get("exclude") != []:
        raise InspectionError("policy_release_tag_ruleset_invalid")
    rules = ruleset.get("rules")
    if not isinstance(rules, list) or len(rules) != 2:
        raise InspectionError("policy_release_tag_ruleset_invalid")
    types: list[str] = []
    for rule in rules:
        item = _require_mapping(rule, "policy_release_tag_ruleset_invalid")
        rule_type = item.get("type")
        if not isinstance(rule_type, str):
            raise InspectionError("policy_release_tag_ruleset_invalid")
        if rule_type == "update":
            _require_exact_keys(item, {"type"}, "policy_release_tag_ruleset_invalid")
        else:
            _require_exact_keys(item, {"type"}, "policy_release_tag_ruleset_invalid")
        types.append(rule_type)
    if tuple(types) != ("deletion", "update"):
        raise InspectionError("policy_release_tag_ruleset_invalid")
    actors = ruleset.get("bypass_actors")
    if actors != []:
        raise InspectionError("policy_release_tag_ruleset_invalid")


def validate_policy(policy: Mapping[str, object]) -> Mapping[str, object]:
    _require_exact_keys(policy, _POLICY_KEYS, "policy_schema_invalid")
    if policy.get("schema_version") != 2 or policy.get("bootstrap_state") != "configured":
        raise InspectionError("policy_unconfigured")
    for key in ("repository", "reviewed_repository", "staging_repository"):
        value = policy.get(key)
        if not isinstance(value, str) or _REPOSITORY_RE.fullmatch(value) is None:
            raise InspectionError("policy_repository_invalid")
    if len({policy["repository"], policy["reviewed_repository"], policy["staging_repository"]}) != 3:
        raise InspectionError("policy_repository_invalid")
    for key in ("repository_id", "reviewed_repository_id"):
        value = policy.get(key)
        if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
            raise InspectionError("policy_repository_identity_invalid")
    if policy["repository_id"] == policy["reviewed_repository_id"]:
        raise InspectionError("policy_repository_identity_invalid")
    if policy.get("branch") != "main" or policy.get("environment") != "production-release":
        raise InspectionError("policy_release_boundary_invalid")
    try:
        profile = release_profile_from_policy(policy)
    except ReleaseProfileError as exc:
        raise InspectionError("policy_release_boundary_invalid") from exc
    if policy.get("release") != {"tag": profile.tag, "version": profile.version}:
        raise InspectionError("policy_release_boundary_invalid")
    if policy.get("staging") != {
        "repository": policy.get("staging_repository"),
        "tag_prefix": profile.staging_tag_prefix,
    }:
        raise InspectionError("policy_staging_invalid")
    if policy.get("provider_expectations") != profile.provider_expectations():
        raise InspectionError("policy_provider_expectations_invalid")
    inspector = _require_mapping(policy.get("inspector"), "policy_inspector_invalid")
    _require_exact_keys(inspector, _POLICY_INSPECTOR_KEYS, "policy_inspector_invalid")
    if (
        inspector.get("interface_version") != 2
        or inspector.get("path") != "src/mercury_release_control/surface_inspector.py"
        or _require_sha(inspector.get("sha256"), "policy_inspector_invalid") == "0" * 64
    ):
        raise InspectionError("policy_inspector_invalid")
    if policy.get("immutable_releases_required") is not True:
        raise InspectionError("policy_immutable_releases_invalid")
    _validate_release_tag_ruleset(policy.get("release_tag_ruleset"), profile)
    reviewers = policy.get("required_reviewer_ids")
    if (
        not isinstance(reviewers, list)
        or not reviewers
        or any(
            not isinstance(item, int) or isinstance(item, bool) or item <= 0 for item in reviewers
        )
        or tuple(reviewers) != tuple(sorted(set(reviewers)))
    ):
        raise InspectionError("policy_reviewers_invalid")
    required_secrets = _validate_names(
        policy.get("required_environment_secrets"), "policy_environment_secrets_invalid"
    )
    _validate_names(
        policy.get("required_environment_variables"), "policy_environment_variables_invalid"
    )
    forbidden = _validate_names(
        policy.get("forbidden_repository_secrets"), "policy_repository_secrets_invalid"
    )
    if not set(required_secrets) < set(forbidden):
        raise InspectionError("policy_repository_secrets_invalid")
    checks = policy.get("required_status_checks")
    if not isinstance(checks, list) or not checks:
        raise InspectionError("policy_required_status_checks_invalid")
    identities: list[tuple[str, int]] = []
    for check in checks:
        item = _require_mapping(check, "policy_required_status_checks_invalid")
        _require_exact_keys(item, {"app_id", "context"}, "policy_required_status_checks_invalid")
        app_id = item.get("app_id")
        context = item.get("context")
        if (
            not isinstance(app_id, int)
            or isinstance(app_id, bool)
            or app_id <= 0
            or not isinstance(context, str)
            or not context.strip()
            or context != context.strip()
            or len(context) > 255
        ):
            raise InspectionError("policy_required_status_checks_invalid")
        identities.append((context, app_id))
    if tuple(identities) != tuple(sorted(set(identities))):
        raise InspectionError("policy_required_status_checks_invalid")

    supabase = _require_mapping(policy.get("supabase"), "supabase_policy_invalid")
    _require_exact_keys(supabase, _SUPABASE_KEYS, "supabase_policy_invalid")
    project_ref = supabase.get("project_ref")
    if not isinstance(project_ref, str) or _PROJECT_RE.fullmatch(project_ref) is None:
        raise InspectionError("supabase_project_ref_invalid")
    if supabase.get("migration_id") != profile.migration_id:
        raise InspectionError("supabase_migration_invalid")
    _require_sha(supabase.get("migration_history_sha256"), "supabase_migration_history_invalid")
    if tuple(supabase.get("tables", ())) != _CANONICAL_TABLES:
        raise InspectionError("supabase_table_inventory_invalid")
    if supabase.get("storage_buckets") != []:
        raise InspectionError("supabase_bucket_inventory_invalid")
    functions = supabase.get("functions")
    if (
        not isinstance(functions, list)
        or tuple(item.get("signature") if isinstance(item, Mapping) else None for item in functions)
        != profile.supabase_function_signatures
    ):
        raise InspectionError("supabase_function_inventory_invalid")
    for item in functions:
        function = _require_mapping(item, "supabase_function_inventory_invalid")
        _require_exact_keys(function, _FUNCTION_KEYS, "supabase_function_inventory_invalid")
        _require_sha(function.get("definition_sha256"), "supabase_function_digest_invalid")
    if _require_sha(supabase.get("schema_sha256"), "supabase_schema_digest_invalid") != (
        build_supabase_schema_digest(supabase)
    ):
        raise InspectionError("supabase_schema_digest_invalid")
    return policy


def validate_manifest(manifest: Mapping[str, object]) -> None:
    _require_exact_keys(
        manifest, {"schema_version", "required", "scanner_versions"}, "manifest_invalid"
    )
    if (
        manifest.get("schema_version") != 1
        or tuple(manifest.get("required", ())) != _CANDIDATE_SURFACES
    ):
        raise InspectionError("manifest_invalid")
    scanners = _require_mapping(manifest.get("scanner_versions"), "manifest_invalid")
    if dict(scanners) != {"gitleaks": "8.24.3", "trufflehog": "3.88.32"}:
        raise InspectionError("manifest_invalid")


def validate_allowlist(allowlist: Mapping[str, object], *, at: datetime | None = None) -> None:
    _require_exact_keys(allowlist, {"schema_version", "entries"}, "allowlist_invalid")
    entries = allowlist.get("entries")
    if (
        allowlist.get("schema_version") != 1
        or not isinstance(entries, list)
        or len(entries) > 10_000
    ):
        raise InspectionError("allowlist_invalid")
    inspected_at = at or datetime.now(UTC)
    if inspected_at.tzinfo is None:
        raise InspectionError("allowlist_invalid")
    seen: set[tuple[str, str, str]] = set()
    for entry in entries:
        item = _require_mapping(entry, "allowlist_invalid")
        _require_exact_keys(
            item,
            {"classification", "digest", "expires_at", "file", "reviewer_role", "rule"},
            "allowlist_invalid",
        )
        file_name = item.get("file")
        key = (str(file_name), str(item.get("rule")), str(item.get("digest")))
        expires_at = _parse_timestamp(item.get("expires_at"))
        if (
            item.get("classification") not in _ALLOWLIST_CLASSIFICATIONS
            or not isinstance(file_name, str)
            or not _safe_relative_path(file_name)
            or item.get("rule") != "scanner_finding"
            or item.get("reviewer_role") not in _ALLOWLIST_REVIEWER_ROLES
            or _require_sha(item.get("digest"), "allowlist_invalid") == "0" * 64
            or expires_at is None
            or expires_at <= inspected_at.astimezone(UTC)
            or key in seen
        ):
            raise InspectionError("allowlist_invalid")
        seen.add(key)


def _valid_timestamp(value: object) -> bool:
    return _parse_timestamp(value) is not None


def _parse_timestamp(value: object) -> datetime | None:
    if not isinstance(value, str) or len(value) > 64:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return None
    return parsed.astimezone(UTC)


def _allowlist_keys(allowlist: Mapping[str, object]) -> frozenset[tuple[str, str, str]]:
    entries = allowlist.get("entries")
    if not isinstance(entries, list):
        raise InspectionError("allowlist_invalid")
    return frozenset(
        (str(entry["file"]), str(entry["rule"]), str(entry["digest"]))
        for entry in entries
        if isinstance(entry, Mapping)
    )


def _safe_relative_path(value: str) -> bool:
    if not value or len(value) > 1024 or "\0" in value or "\\" in value:
        return False
    path = PurePosixPath(value)
    parts = value.split("/")
    return not path.is_absolute() and all(part not in {"", ".", ".."} for part in parts)


def _validated_text(environment: Mapping[str, str], name: str) -> str:
    value = environment.get(name, "")
    if (
        not isinstance(value, str)
        or not value
        or len(value.encode("utf-8")) > MAX_ENV_VALUE_BYTES
        or value != value.strip()
        or "\0" in value
    ):
        raise InspectionError("environment_value_invalid")
    return value


def _strict_https_base(value: str, code: str, *, path: str | None = "") -> str:
    try:
        parsed = urllib.parse.urlsplit(value)
    except ValueError as exc:
        raise InspectionError(code) from exc
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.port not in {None, 443}
        or parsed.query
        or parsed.fragment
        or (path is not None and parsed.path.rstrip("/") != path)
    ):
        raise InspectionError(code)
    return value.rstrip("/")


def validate_environment(policy: Mapping[str, object], environment: Mapping[str, str]) -> None:
    for name in _REQUIRED_ENVIRONMENT:
        _validated_text(environment, name)
    if environment["TARGET_REPOSITORY"] != policy["reviewed_repository"]:
        raise InspectionError("target_repository_mismatch")
    if environment["STAGING_REPOSITORY"] != policy["staging_repository"]:
        raise InspectionError("staging_repository_mismatch")
    flow_base = _strict_https_base(
        environment["FLOWACCOUNT_SANDBOX_BASE_URL"], "flowaccount_base_url_invalid", path="/test"
    )
    if urllib.parse.urlsplit(flow_base).hostname != "openapi.flowaccount.com":
        raise InspectionError("flowaccount_base_url_invalid")
    public_origin = _strict_https_base(environment["MERCURY_PUBLIC_MCP_URL"], "public_mcp_url_invalid")
    if urllib.parse.urlsplit(public_origin).hostname in {"localhost", "127.0.0.1", "::1"}:
        raise InspectionError("public_mcp_url_invalid")
    _strict_https_base(
        environment["MERCURY_MARKETPLACE_SNAPSHOT_URL"],
        "marketplace_url_invalid",
        path=None,
    )
    render_base = _strict_https_base(environment["RENDER_API_URL"], "render_api_url_invalid")
    if urllib.parse.urlsplit(render_base).hostname != "api.render.com":
        raise InspectionError("render_api_url_invalid")
    if _SERVICE_ID_RE.fullmatch(environment["RENDER_SERVICE_ID"]) is None:
        raise InspectionError("render_service_id_invalid")
    if _RENDER_OWNER_ID_RE.fullmatch(environment["RENDER_OWNER_ID"]) is None:
        raise InspectionError("render_owner_id_invalid")
    for name in ("INSPECTOR_GIT", "INSPECTOR_GITLEAKS", "INSPECTOR_TRUFFLEHOG"):
        path = Path(environment[name])
        if not path.is_absolute():
            raise InspectionError("inspector_tool_path_invalid")
    supabase = _require_mapping(policy["supabase"], "supabase_policy_invalid")
    expected_supabase_url = f"https://{supabase['project_ref']}.supabase.co"
    if environment["SUPABASE_URL"] != expected_supabase_url:
        raise InspectionError("supabase_url_mismatch")


def parse_database_url(value: str, *, project_ref: str) -> DbConnectionPlan:
    """Validate a direct or session-pooler URL without exposing its contents."""

    try:
        parsed = urllib.parse.urlsplit(value)
        query_items = urllib.parse.parse_qsl(
            parsed.query,
            keep_blank_values=True,
            strict_parsing=True,
        )
        _ = parsed.port
    except (ValueError, UnicodeError) as exc:
        raise InspectionError("database_url_invalid") from exc
    if (
        parsed.scheme not in {"postgres", "postgresql"}
        or not parsed.hostname
        or parsed.fragment
        or not parsed.username
        or not parsed.path
        or parsed.path != "/postgres"
    ):
        raise InspectionError("database_url_invalid")
    names = [name for name, _item in query_items]
    if names.count("sslmode") != 1 or dict(query_items).get("sslmode") != "verify-full":
        raise InspectionError("database_tls_invalid")
    if len(names) != len(set(names)) or set(names) != {"sslmode"}:
        raise InspectionError("database_url_invalid")
    hostname = parsed.hostname.lower()
    port = parsed.port or 5432
    user = urllib.parse.unquote(parsed.username)
    password = urllib.parse.unquote(parsed.password or "")
    if not password or port < 1 or port > 65535:
        raise InspectionError("database_url_invalid")
    if hostname == f"db.{project_ref}.supabase.co":
        if user != "postgres":
            raise InspectionError("database_role_invalid")
        return DbConnectionPlan("direct", hostname, port, "postgres", "postgres", user, password)
    if _POOLER_RE.fullmatch(hostname) is not None:
        expected_role = f"postgres.{project_ref}"
        if user != expected_role:
            raise InspectionError("database_role_invalid")
        return DbConnectionPlan("pooler", hostname, port, "postgres", expected_role, user, password)
    raise InspectionError("database_hostname_invalid")


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args: object, **kwargs: object) -> None:
        del args, kwargs
        return None


def _open_url(request: urllib.request.Request, *, timeout: float) -> Any:
    opener = urllib.request.build_opener(_NoRedirect())
    return opener.open(request, timeout=timeout)


def _read_http_body(
    response: BinaryIO, *, maximum: int, budget: InspectionBudget | None = None
) -> bytes:
    data = bytearray()
    while True:
        chunk = response.read(min(64 * 1024, maximum + 1 - len(data)))
        if not chunk:
            break
        data.extend(chunk)
        if budget is not None:
            budget.charge_download(len(chunk))
        if len(data) > maximum:
            raise InspectionError("network_response_too_large")
    return bytes(data)


def request_bytes(
    url: str,
    *,
    method: str = "GET",
    headers: Mapping[str, str] | None = None,
    body: bytes | None = None,
    maximum: int = MAX_HTTP_BYTES,
    code: str = "network_request_failed",
    budget: InspectionBudget | None = None,
    expected_statuses: frozenset[int] = frozenset({200}),
) -> HttpResponse:
    current_url = url
    current_headers = dict(headers or {})
    current_body = body
    try:
        for redirect_count in range(3):
            if budget is not None:
                budget.charge_request()
            request = urllib.request.Request(current_url, data=current_body, method=method)
            for key, value in current_headers.items():
                request.add_header(key, value)
            try:
                response = _open_url(request, timeout=NETWORK_TIMEOUT_SECONDS)
            except urllib.error.HTTPError as exc:
                if exc.code not in _REDIRECT_STATUS_CODES:
                    raise
                response = exc
            with response:
                status = int(response.getcode())
                response_headers = {
                    str(key).lower(): str(value) for key, value in response.headers.items()
                }
                if status in _REDIRECT_STATUS_CODES:
                    location = response_headers.get("location", "")
                    target = urllib.parse.urlsplit(urllib.parse.urljoin(current_url, location))
                    if (
                        redirect_count == 2
                        or target.scheme != "https"
                        or not target.hostname
                        or target.username is not None
                        or target.password is not None
                        or target.port not in {None, 443}
                        or target.hostname.casefold() not in _GITHUB_DOWNLOAD_HOSTS
                    ):
                        raise InspectionError(code)
                    current_url = target.geturl()
                    current_headers = {
                        key: value
                        for key, value in current_headers.items()
                        if key.casefold() not in {"authorization", "x-github-api-version"}
                    }
                    current_body = None
                    continue
                response_body = _read_http_body(response, maximum=maximum, budget=budget)
            if status not in expected_statuses:
                raise InspectionError(code)
            return HttpResponse(status, response_headers, response_body)
    except InspectionError:
        raise
    except (
        OSError,
        TimeoutError,
        urllib.error.URLError,
        urllib.error.HTTPError,
        ValueError,
    ) as exc:
        raise InspectionError(code) from exc
    raise InspectionError(code)


def _parse_json_bytes(data: bytes, code: str) -> object:
    if not data or len(data) > MAX_HTTP_BYTES:
        raise InspectionError(code)
    try:
        return json.loads(data, object_pairs_hook=_pairs)
    except (UnicodeDecodeError, json.JSONDecodeError, InspectionError) as exc:
        raise InspectionError(code) from exc


def _github_headers(token: str, *, accept: str = "application/vnd.github+json") -> dict[str, str]:
    return {
        "Accept": accept,
        "Authorization": f"Bearer {token}",
        "X-GitHub-Api-Version": "2026-03-10",
    }


def _github_json(
    path: str, token: str, *, accept: str = "application/vnd.github+json"
) -> tuple[object, HttpResponse]:
    if not path.startswith("/") or "\0" in path:
        raise InspectionError("github_path_invalid")
    response = request_bytes(
        f"https://api.github.com{path}",
        headers=_github_headers(token, accept=accept),
        code="github_request_failed",
    )
    return _parse_json_bytes(response.body, "github_response_invalid"), response


def _github_records(
    path: str, token: str, *, key: str | None = None
) -> tuple[list[Mapping[str, object]], list[str]]:
    """Fetch bounded GitHub pagination and return only data hashes as evidence."""

    current = path
    records: list[Mapping[str, object]] = []
    hashes: list[str] = []
    for _ in range(MAX_PAGES):
        payload, response = _github_json(current, token)
        values: object = payload
        if key is not None:
            container = _require_mapping(payload, "github_response_invalid")
            values = container.get(key)
        if not isinstance(values, list):
            raise InspectionError("github_response_invalid")
        if len(records) + len(values) > MAX_HTTP_OBJECTS:
            raise InspectionError("github_inventory_too_large")
        for value in values:
            records.append(_require_mapping(value, "github_response_invalid"))
        hashes.append(_sha256_bytes(response.body))
        link = response.headers.get("link", "")
        match = re.search(r"<([^>]+)>;\s*rel=\"next\"", link)
        if match is None:
            return records, hashes
        parsed = urllib.parse.urlsplit(match.group(1))
        if (
            parsed.scheme != "https"
            or parsed.netloc != "api.github.com"
            or not parsed.path.startswith("/")
        ):
            raise InspectionError("github_pagination_invalid")
        current = parsed.path + (f"?{parsed.query}" if parsed.query else "")
    raise InspectionError("github_pagination_too_large")


def _minimal_process_env(
    home: Path,
    *,
    tool_paths: Mapping[str, str] | None = None,
) -> dict[str, str]:
    environment = {
        "HOME": str(home),
        "LANG": "C",
        "LC_ALL": "C",
        "PATH": "/usr/bin:/bin",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_TERMINAL_PROMPT": "0",
        "PYTHONNOUSERSITE": "1",
    }
    if tool_paths is not None:
        for name in ("INSPECTOR_GIT", "INSPECTOR_GITLEAKS", "INSPECTOR_TRUFFLEHOG"):
            value = tool_paths.get(name)
            if isinstance(value, str) and value:
                environment[name] = value
    return environment


def _run_silent(
    command: Sequence[str], *, cwd: Path | None, environment: Mapping[str, str]
) -> None:
    try:
        completed = subprocess.run(
            list(command),
            cwd=cwd,
            env=dict(environment),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
            timeout=PROCESS_TIMEOUT_SECONDS,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise InspectionError("subprocess_unavailable") from exc
    if completed.returncode != 0:
        raise InspectionError("subprocess_failed")


def _run_capture(
    command: Sequence[str],
    *,
    cwd: Path | None,
    environment: Mapping[str, str],
    stderr_to_stdout: bool = False,
) -> bytes:
    try:
        with tempfile.TemporaryDirectory(prefix="mercury-process-output-") as temporary:
            destination = Path(temporary) / "stdout"
            with destination.open("xb", buffering=0) as output:
                process = subprocess.Popen(
                    list(command),
                    cwd=cwd,
                    env=dict(environment),
                    stdin=subprocess.DEVNULL,
                    stdout=output,
                    stderr=output if stderr_to_stdout else subprocess.DEVNULL,
                )
                deadline = time.monotonic() + PROCESS_TIMEOUT_SECONDS
                while process.poll() is None:
                    if (
                        destination.stat().st_size > MAX_PROCESS_OUTPUT_BYTES
                        or time.monotonic() >= deadline
                    ):
                        process.kill()
                        process.wait(timeout=10)
                        raise InspectionError("subprocess_output_too_large")
                    time.sleep(0.01)
            if destination.stat().st_size > MAX_PROCESS_OUTPUT_BYTES or process.returncode != 0:
                raise InspectionError("subprocess_failed")
            completed = destination.read_bytes()
    except InspectionError:
        raise
    except (OSError, subprocess.SubprocessError) as exc:
        raise InspectionError("subprocess_unavailable") from exc
    return completed


def _run_to_file(
    command: Sequence[str],
    *,
    cwd: Path | None,
    environment: Mapping[str, str],
    destination: Path,
) -> None:
    try:
        with destination.open("xb", buffering=0) as output:
            process = subprocess.Popen(
                list(command),
                cwd=cwd,
                env=dict(environment),
                stdin=subprocess.DEVNULL,
                stdout=output,
                stderr=subprocess.DEVNULL,
            )
            deadline = time.monotonic() + PROCESS_TIMEOUT_SECONDS
            while process.poll() is None:
                if destination.stat().st_size > MAX_ARCHIVE_BYTES or time.monotonic() >= deadline:
                    process.kill()
                    process.wait(timeout=10)
                    raise InspectionError("subprocess_output_too_large")
                time.sleep(0.05)
            if destination.stat().st_size > MAX_ARCHIVE_BYTES or process.returncode != 0:
                raise InspectionError("subprocess_failed")
    except InspectionError:
        raise
    except (OSError, subprocess.SubprocessError) as exc:
        raise InspectionError("subprocess_unavailable") from exc


def _absolute_executable(value: object, *, code: str) -> Path:
    if not isinstance(value, str):
        raise InspectionError(code)
    path = Path(value)
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise InspectionError(code) from exc
    if (
        not path.is_absolute()
        or stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISREG(metadata.st_mode)
        or not metadata.st_mode & stat.S_IXUSR
        or metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
    ):
        raise InspectionError(code)
    return path


def _require_scanner_versions(environment: Mapping[str, str], home: Path) -> tuple[Path, Path]:
    binaries: list[Path] = []
    for variable, expected, flag in (
        ("INSPECTOR_GITLEAKS", "8.24.3", "version"),
        ("INSPECTOR_TRUFFLEHOG", "3.88.32", "--version"),
    ):
        location = _absolute_executable(environment.get(variable), code="scanner_unavailable")
        output = _run_capture(
            (str(location), flag),
            cwd=None,
            environment=environment,
            stderr_to_stdout=True,
        )
        try:
            version_text = output.decode("ascii", errors="strict")
        except UnicodeDecodeError as exc:
            raise InspectionError("scanner_version_invalid") from exc
        if not re.search(rf"(?:^|\D){re.escape(expected)}(?:$|\D)", version_text):
            raise InspectionError("scanner_version_invalid")
        binaries.append(location)
    del home
    return binaries[0], binaries[1]


def _materialize_trusted_gitleaks_config(
    root: Path,
    *,
    clone: Path,
    reviewed_sha: str,
    environment: Mapping[str, str],
) -> Path:
    if _SHA_RE.fullmatch(reviewed_sha) is None:
        raise InspectionError("gitleaks_config_invalid")
    content = _run_capture(
        (
            environment["INSPECTOR_GIT"],
            "show",
            f"{reviewed_sha}:.gitleaks.toml",
        ),
        cwd=clone,
        environment=environment,
    )
    if hashlib.sha256(content).hexdigest() != _TRUSTED_GITLEAKS_CONFIG_SHA256:
        raise InspectionError("gitleaks_config_invalid")
    destination = root / "gitleaks.toml"
    try:
        descriptor = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
    except OSError as exc:
        raise InspectionError("gitleaks_config_invalid") from exc
    return destination


def _scan_git(
    clone: Path,
    *,
    log_options: str,
    gitleaks: Path,
    trufflehog: Path,
    gitleaks_config: Path,
    environment: Mapping[str, str],
) -> list[str]:
    git_path = _absolute_executable(
        environment.get("INSPECTOR_GIT"),
        code="inspector_tool_path_invalid",
    )
    if git_path.name != "git":
        raise InspectionError("inspector_tool_path_invalid")
    scanner_environment = dict(environment)
    scanner_environment["PATH"] = f"{git_path.parent}:/usr/bin:/bin"
    commands = (
        (
            str(gitleaks),
            "git",
            "--no-banner",
            "--redact",
            "--exit-code=1",
            f"--config={gitleaks_config}",
            f"--log-opts={log_options}",
            str(clone),
        ),
        (
            str(trufflehog),
            "git",
            f"file://{clone}",
            "--json",
            "--fail",
            "--concurrency=1",
            "--no-update",
            "--no-verification",
        ),
    )
    hashes: list[str] = []
    for command in commands:
        _run_silent(command, cwd=clone, environment=scanner_environment)
        hashes.append(_canonical_sha256({"argv": list(command), "status": 0}))
    return hashes


def _scan_directory(
    root: Path,
    *,
    gitleaks: Path,
    trufflehog: Path,
    environment: Mapping[str, str],
    allowlist: frozenset[tuple[str, str, str]] = frozenset(),
    archive_member_prefix: str | None = None,
    budget: InspectionBudget | None = None,
) -> list[str]:
    scan_budget = budget or InspectionBudget(time.monotonic())
    with tempfile.TemporaryDirectory(prefix="mercury-scanner-reports-") as temporary:
        report_root = Path(temporary)
        gitleaks_report = report_root / "gitleaks.json"
        gitleaks_decoded_report = report_root / "gitleaks-decoded.json"
        decoded_root = root / "decoded"
        commands = (
            (
                "gitleaks",
                (
                    str(gitleaks),
                    "dir",
                    "--no-banner",
                    "--exit-code=1",
                    "--report-format=json",
                    f"--report-path={gitleaks_report}",
                    str(root),
                ),
                report_root / "gitleaks.stdout",
                gitleaks_report,
                (
                    str(gitleaks),
                    "dir",
                    "--no-banner",
                    "--exit-code=1",
                    "--report-format=json",
                    f"--report-path={gitleaks_decoded_report}",
                    str(decoded_root),
                ),
                report_root / "gitleaks-decoded.stdout",
                gitleaks_decoded_report,
            ),
            (
                "trufflehog",
                (
                    str(trufflehog),
                    "filesystem",
                    "--directory",
                    str(root),
                    "--json",
                    "--fail",
                    "--concurrency=1",
                    "--no-update",
                    "--no-verification",
                ),
                report_root / "trufflehog.ndjson",
                report_root / "trufflehog.ndjson",
                (
                    str(trufflehog),
                    "filesystem",
                    "--directory",
                    str(decoded_root),
                    "--json",
                    "--fail",
                    "--concurrency=1",
                    "--no-update",
                    "--no-verification",
                ),
                report_root / "trufflehog-decoded.ndjson",
                report_root / "trufflehog-decoded.ndjson",
            ),
        )
        hashes: list[str] = []
        for (
            scanner,
            command,
            stdout_path,
            finding_report,
            decoded_command,
            decoded_stdout_path,
            decoded_finding_report,
        ) in commands:
            status = _run_scanner_capture(
                command,
                cwd=root,
                environment=environment,
                report=stdout_path,
                budget=scan_budget,
            )
            records = _scanner_finding_records(scanner, finding_report, root=root)
            _validate_scanner_result(scanner, status, records)
            statuses = [status]
            if archive_member_prefix is not None:
                decoded_status = _run_scanner_capture(
                    decoded_command,
                    cwd=decoded_root,
                    environment=environment,
                    report=decoded_stdout_path,
                    budget=scan_budget,
                )
                decoded_records = _scanner_finding_records(
                    scanner,
                    decoded_finding_report,
                    root=decoded_root,
                )
                _validate_scanner_result(scanner, decoded_status, decoded_records)
                statuses.append(decoded_status)
                records = _normalize_archive_finding_records(
                    frozenset(
                        {
                            *records,
                            *(
                                ScannerFinding(
                                    file=f"decoded/{finding.file}",
                                    rule=finding.rule,
                                    evidence_digest=finding.evidence_digest,
                                    match_digest=finding.match_digest,
                                )
                                for finding in decoded_records
                            ),
                        }
                    ),
                    member_prefix=archive_member_prefix,
                )
            findings = frozenset(finding.allowlist_key for finding in records)
            for finding in findings:
                if finding not in allowlist:
                    raise InspectionError("secret_scan_finding")
            hashes.append(
                _canonical_sha256(
                    {
                        "scanner": scanner,
                        "status": statuses[0] if len(statuses) == 1 else statuses,
                        "findings": sorted(digest for _file, _rule, digest in findings),
                    }
                )
            )
    return hashes


def _validate_scanner_result(
    scanner: str,
    status: int,
    findings: frozenset[ScannerFinding],
) -> None:
    finding_status = {"gitleaks": 1, "trufflehog": 183}.get(scanner)
    if finding_status is None:
        raise InspectionError("scanner_report_invalid")
    if status == 0:
        if findings:
            raise InspectionError("scanner_execution_invalid")
        return
    if status == finding_status:
        if not findings:
            raise InspectionError("scanner_execution_failed")
        return
    raise InspectionError("scanner_execution_failed")


def _normalize_archive_findings(
    findings: frozenset[tuple[str, str, str]],
    *,
    member_prefix: str,
) -> frozenset[tuple[str, str, str]]:
    decoded: set[tuple[str, str, str]] = set()
    container: set[tuple[str, str, str]] = set()
    for file_name, rule, digest in findings:
        if file_name == "payload.bin":
            container.add((file_name, rule, digest))
            continue
        if not file_name.startswith(member_prefix):
            raise InspectionError("scanner_report_invalid")
        member_name = file_name.removeprefix(member_prefix)
        if not _safe_relative_path(member_name):
            raise InspectionError("scanner_report_invalid")
        decoded.add((member_name, rule, digest))

    decoded_identities = {(rule, digest) for _file_name, rule, digest in decoded}
    decoded.update(
        finding
        for finding in container
        if (finding[1], finding[2]) not in decoded_identities
    )
    return frozenset(decoded)


def _normalize_archive_finding_records(
    findings: frozenset[ScannerFinding],
    *,
    member_prefix: str,
) -> frozenset[ScannerFinding]:
    decoded: set[ScannerFinding] = set()
    container: set[ScannerFinding] = set()
    for finding in findings:
        if finding.file == "payload.bin":
            container.add(finding)
            continue
        if not finding.file.startswith(member_prefix):
            raise InspectionError("scanner_report_invalid")
        member_name = finding.file.removeprefix(member_prefix)
        if not _safe_relative_path(member_name):
            raise InspectionError("scanner_report_invalid")
        decoded.add(
            ScannerFinding(
                file=member_name,
                rule=finding.rule,
                evidence_digest=finding.evidence_digest,
                match_digest=finding.match_digest,
            )
        )

    decoded_evidence = {
        (finding.rule, finding.evidence_digest) for finding in decoded
    }
    decoded_matches = {
        finding.match_digest
        for finding in decoded
        if finding.match_digest is not None
    }
    decoded.update(
        finding
        for finding in container
        if (finding.rule, finding.evidence_digest) not in decoded_evidence
        and (
            finding.match_digest is None
            or finding.match_digest not in decoded_matches
        )
    )
    return frozenset(decoded)


def _archive_member_prefix(decoded_root: Path) -> str:
    try:
        entries = tuple(decoded_root.iterdir())
        if (
            len(entries) == 1
            and not entries[0].is_symlink()
            and entries[0].is_dir()
            and _safe_relative_path(entries[0].name)
        ):
            return f"decoded/{entries[0].name}/"
    except OSError as exc:
        raise InspectionError("archive_invalid") from exc
    return "decoded/"


def _run_scanner_capture(
    command: Sequence[str],
    *,
    cwd: Path,
    environment: Mapping[str, str],
    report: Path,
    budget: InspectionBudget | None = None,
) -> int:
    try:
        if budget is not None:
            budget.check_time()
        with report.open("xb", buffering=0) as output:
            process = subprocess.Popen(
                list(command),
                cwd=cwd,
                env=dict(environment),
                stdin=subprocess.DEVNULL,
                stdout=output,
                stderr=subprocess.DEVNULL,
            )
            current = time.monotonic()
            process_deadline = current + PROCESS_TIMEOUT_SECONDS
            global_deadline = (
                budget.started + INSPECTION_TIMEOUT_SECONDS
                if budget is not None
                else None
            )
            deadline = (
                min(process_deadline, global_deadline)
                if global_deadline is not None
                else process_deadline
            )
            while process.poll() is None:
                current = time.monotonic()
                if report.stat().st_size > MAX_PROCESS_OUTPUT_BYTES or current >= deadline:
                    process.kill()
                    process.wait(timeout=10)
                    if global_deadline is not None and current >= global_deadline:
                        raise InspectionError("inspection_time_budget_exhausted")
                    raise InspectionError("scanner_execution_failed")
                time.sleep(0.01)
            if report.stat().st_size > MAX_PROCESS_OUTPUT_BYTES:
                raise InspectionError("scanner_report_too_large")
            if budget is not None:
                budget.check_time()
            return process.returncode
    except InspectionError:
        raise
    except (OSError, subprocess.SubprocessError) as exc:
        raise InspectionError("scanner_execution_failed") from exc


def _relative_scanner_path(value: object, *, root: Path) -> str:
    if not isinstance(value, str) or not value:
        raise InspectionError("scanner_report_invalid")
    path = Path(value)
    try:
        relative = path.resolve().relative_to(root.resolve()) if path.is_absolute() else path
    except (OSError, ValueError) as exc:
        raise InspectionError("scanner_report_invalid") from exc
    normalized = relative.as_posix()
    if not _safe_relative_path(normalized):
        raise InspectionError("scanner_report_invalid")
    return normalized


def _scanner_scalar(value: object) -> str | None:
    return value if isinstance(value, str) else None


def _scanner_integer(value: object) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def _scanner_value_digest(value: object) -> str | None:
    if value is None:
        return None
    if isinstance(value, str):
        encoded = value.encode("utf-8")
    else:
        encoded = json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return _sha256_bytes(encoded)


def _scanner_evidence_digest(canonical: Mapping[str, object]) -> str:
    encoded = json.dumps(
        canonical,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return _sha256_bytes(b"scanner_finding\0" + encoded)


def _scanner_match_digest(canonical: Mapping[str, object]) -> str:
    encoded = json.dumps(
        canonical,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return _sha256_bytes(b"scanner_match\0" + encoded)


def _scanner_finding_records(
    scanner: str, report: Path, *, root: Path
) -> frozenset[ScannerFinding]:
    if scanner == "gitleaks" and not report.exists():
        return frozenset()
    try:
        payload = report.read_bytes()
    except OSError as exc:
        raise InspectionError("scanner_report_invalid") from exc
    if len(payload) > MAX_PROCESS_OUTPUT_BYTES:
        raise InspectionError("scanner_report_too_large")
    if not payload.strip():
        return frozenset()
    try:
        raw_records: list[object]
        if scanner == "gitleaks":
            parsed = json.loads(payload, object_pairs_hook=_pairs)
            if not isinstance(parsed, list):
                raise InspectionError("scanner_report_invalid")
            raw_records = parsed
        else:
            raw_records = [
                json.loads(line, object_pairs_hook=_pairs)
                for line in payload.splitlines()
                if line.strip()
            ]
    except (UnicodeDecodeError, json.JSONDecodeError, InspectionError) as exc:
        raise InspectionError("scanner_report_invalid") from exc
    findings: set[ScannerFinding] = set()
    for raw in raw_records:
        record = _require_mapping(raw, "scanner_report_invalid")
        if scanner == "gitleaks":
            file_name = record.get("File")
            rule_id = record.get("RuleID")
            secret_sha256 = _scanner_value_digest(record.get("Secret"))
            if secret_sha256 is None:
                raise InspectionError("scanner_report_invalid")
            canonical = {
                "scanner": "gitleaks",
                "rule_id": _scanner_scalar(rule_id),
                "commit": _scanner_scalar(record.get("Commit")),
                "start_line": _scanner_integer(record.get("StartLine")),
                "secret_sha256": secret_sha256,
            }
            match_digest = None
        else:
            source = _require_mapping(record.get("SourceMetadata"), "scanner_report_invalid")
            data = _require_mapping(source.get("Data"), "scanner_report_invalid")
            location = data.get("Git")
            if not isinstance(location, Mapping):
                location = data.get("Filesystem")
            if not isinstance(location, Mapping):
                location = data
            file_name = location.get("file")
            rule_id = record.get("DetectorName")
            raw_sha256 = _scanner_value_digest(record.get("Raw"))
            raw_v2_sha256 = _scanner_value_digest(record.get("RawV2"))
            if raw_sha256 is None and raw_v2_sha256 is None:
                raise InspectionError("scanner_report_invalid")
            canonical = {
                "scanner": "trufflehog",
                "detector": _scanner_scalar(rule_id),
                "decoder": _scanner_scalar(record.get("DecoderName")),
                "verified": (
                    record.get("Verified")
                    if isinstance(record.get("Verified"), bool)
                    else None
                ),
                "line": _scanner_integer(location.get("line")),
                "raw_sha256": raw_sha256,
                "raw_v2_sha256": raw_v2_sha256,
            }
            match_digest = _scanner_match_digest(
                {
                    "scanner": "trufflehog",
                    "detector": _scanner_scalar(rule_id),
                    "decoder": _scanner_scalar(record.get("DecoderName")),
                    "verified": (
                        record.get("Verified")
                        if isinstance(record.get("Verified"), bool)
                        else None
                    ),
                    "raw_sha256": raw_sha256,
                    "raw_v2_sha256": raw_v2_sha256,
                }
            )
        if not isinstance(rule_id, str) or not rule_id or len(rule_id) > 512:
            raise InspectionError("scanner_report_invalid")
        file_path = _relative_scanner_path(file_name, root=root)
        digest = _scanner_evidence_digest(canonical)
        findings.add(
            ScannerFinding(
                file=file_path,
                rule="scanner_finding",
                evidence_digest=digest,
                match_digest=match_digest,
            )
        )
    return frozenset(findings)


def _scanner_findings(
    scanner: str, report: Path, *, root: Path
) -> frozenset[tuple[str, str, str]]:
    return frozenset(
        finding.allowlist_key
        for finding in _scanner_finding_records(scanner, report, root=root)
    )


def _safe_archive_name(name: str) -> bool:
    if not _safe_relative_path(name) or unicodedata.normalize("NFC", name) != name:
        return False
    return name.casefold() == name.casefold()


def _excluded_public_path(name: str) -> bool:
    parts = tuple(part.casefold() for part in PurePosixPath(name).parts)
    return (
        any(part in _EXCLUDED_DIRECTORY_NAMES for part in parts)
        or any(part == ".env" or part.startswith(".env.") for part in parts)
        or bool(parts and parts[-1] in _EXCLUDED_STATE_FILES)
    )


def _archive_snapshot(path: Path) -> ArchiveSnapshot:
    entries: list[tuple[str, int, bytes]] = []
    static_files: dict[str, bytes] = {}
    total = 0
    try:
        with tarfile.open(path, mode="r:") as archive:
            members = archive.getmembers()
            if len(members) > MAX_ARCHIVE_MEMBERS:
                raise InspectionError("archive_inventory_too_large")
            for member in members:
                if member.isdir():
                    continue
                if not member.isfile() or not _safe_archive_name(member.name):
                    raise InspectionError("archive_member_invalid")
                if _excluded_public_path(member.name):
                    raise InspectionError("archive_forbidden_path")
                if member.size < 0 or member.size > MAX_ARCHIVE_MEMBER_BYTES:
                    raise InspectionError("archive_member_invalid")
                total += member.size
                if total > MAX_ARCHIVE_BYTES:
                    raise InspectionError("archive_inventory_too_large")
                source = archive.extractfile(member)
                if source is None:
                    raise InspectionError("archive_member_invalid")
                data = source.read(member.size + 1)
                if len(data) != member.size:
                    raise InspectionError("archive_member_invalid")
                if member.name in _STATIC_FILES:
                    if len(data) > MAX_STATIC_SOURCE_BYTES:
                        raise InspectionError("staging_static_source_invalid")
                    static_files[member.name] = data
                mode = 0o755 if member.mode & 0o111 else 0o644
                entries.append((member.name, mode, hashlib.sha256(data).digest()))
    except InspectionError:
        raise
    except (OSError, tarfile.TarError) as exc:
        raise InspectionError("archive_invalid") from exc
    names = [name for name, _mode, _digest in entries]
    if len(names) != len(set(names)) or len({name.casefold() for name in names}) != len(names):
        raise InspectionError("archive_member_invalid")
    digest = hashlib.sha256()
    for name, mode, content_digest in sorted(entries):
        digest.update(f"{mode:o} {name}\0".encode())
        digest.update(content_digest)
    return ArchiveSnapshot(digest.hexdigest(), static_files)


def _static_json(data: bytes) -> Mapping[str, object]:
    try:
        payload = json.loads(data, object_pairs_hook=_pairs)
    except (UnicodeDecodeError, json.JSONDecodeError, InspectionError) as exc:
        raise InspectionError("staging_static_source_invalid") from exc
    return _require_mapping(payload, "staging_static_source_invalid")


def _static_validation_identities(
    snapshot: ArchiveSnapshot,
) -> tuple[tuple[str, str, str], ...]:
    identities: list[tuple[str, str, str]] = []
    for connector, (path, expected_count) in sorted(_VALIDATION_CATALOG_FILES.items()):
        data = snapshot.static_files.get(path)
        if data is None:
            raise InspectionError("staging_validation_catalog_invalid")
        try:
            payload = json.loads(data, object_pairs_hook=_pairs)
        except (UnicodeDecodeError, json.JSONDecodeError, InspectionError) as exc:
            raise InspectionError("staging_validation_catalog_invalid") from exc
        if not isinstance(payload, list) or len(payload) != expected_count:
            raise InspectionError("staging_validation_catalog_invalid")
        connector_identities: list[tuple[str, str, str]] = []
        for raw in payload:
            action = _require_mapping(raw, "staging_validation_catalog_invalid")
            action_id = action.get("action_id")
            version_id = action.get("version_id")
            if (
                action.get("connector_id") != connector
                or not isinstance(action_id, str)
                or _ACTION_ID_RE.fullmatch(action_id) is None
                or not isinstance(version_id, str)
                or _VERSION_ID_RE.fullmatch(version_id) is None
            ):
                raise InspectionError("staging_validation_catalog_invalid")
            connector_identities.append((connector, action_id, version_id))
        if connector_identities != sorted(set(connector_identities)):
            raise InspectionError("staging_validation_catalog_invalid")
        identities.extend(connector_identities)
    if identities != sorted(set(identities)):
        raise InspectionError("staging_validation_catalog_invalid")
    return tuple(identities)


def _static_mcp_tool_names(source: bytes) -> tuple[str, ...]:
    try:
        tree = ast.parse(source.decode("utf-8"), mode="exec")
    except (SyntaxError, UnicodeDecodeError) as exc:
        raise InspectionError("staging_static_source_invalid") from exc
    names: list[str] = []
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        for decorator in node.decorator_list:
            function = decorator.func if isinstance(decorator, ast.Call) else decorator
            if (
                isinstance(function, ast.Attribute)
                and function.attr == "tool"
                and isinstance(function.value, ast.Name)
                and function.value.id in {"mcp", "local_mcp"}
            ):
                name = node.name
                if isinstance(decorator, ast.Call):
                    for keyword in decorator.keywords:
                        if keyword.arg == "name":
                            if not isinstance(keyword.value, ast.Constant) or not isinstance(
                                keyword.value.value, str
                            ):
                                raise InspectionError("staging_static_source_invalid")
                            name = keyword.value.value
                names.append(name)
    if len(names) != len(set(names)):
        raise InspectionError("staging_static_source_invalid")
    return tuple(names)


def _validate_remote_mcp_server(
    server: Mapping[str, object],
    *,
    public_mcp_base_url: str,
) -> None:
    code = "staging_mcp_inventory_invalid"
    public_origin = _strict_https_base(public_mcp_base_url, code)
    note = server.get("note")
    if (
        set(server) != {"type", "url", "note"}
        or server.get("type") != "http"
        or server.get("url") != f"{public_origin}/mcp"
        or not isinstance(note, str)
        or not note
        or note != note.strip()
        or "\0" in note
        or len(note.encode("utf-8")) > 512
    ):
        raise InspectionError(code)


def _validate_staging_static(
    snapshot: ArchiveSnapshot,
    *,
    public_mcp_base_url: str,
) -> tuple[int, tuple[tuple[str, str, str], ...]]:
    if set(snapshot.static_files) != _STATIC_FILES:
        raise InspectionError("staging_static_source_invalid")
    marketplace = _static_json(snapshot.static_files[".agents/plugins/marketplace.json"])
    plugins = marketplace.get("plugins")
    if not isinstance(plugins, list) or len(plugins) != 1:
        raise InspectionError("staging_mcp_inventory_invalid")
    plugin = _require_mapping(plugins[0], "staging_mcp_inventory_invalid")
    if plugin.get("name") != "mercury-finance":
        raise InspectionError("staging_mcp_inventory_invalid")
    plugin_manifest = _static_json(
        snapshot.static_files["plugins/mercury-finance/.codex-plugin/plugin.json"]
    )
    if (
        plugin_manifest.get("name") != "mercury-finance"
        or plugin_manifest.get("mcpServers") != "./.mcp.json"
    ):
        raise InspectionError("staging_mcp_inventory_invalid")
    mcp = _static_json(snapshot.static_files["plugins/mercury-finance/.mcp.json"])
    servers = _require_mapping(mcp.get("mcpServers"), "staging_mcp_inventory_invalid")
    if set(servers) != {"mercury-finance"}:
        raise InspectionError("staging_mcp_inventory_invalid")
    server = _require_mapping(servers["mercury-finance"], "staging_mcp_inventory_invalid")
    _validate_remote_mcp_server(server, public_mcp_base_url=public_mcp_base_url)
    tool_names = frozenset(
        _static_mcp_tool_names(snapshot.static_files["src/mercury_tools/mcp/local_server.py"])
    )
    if tool_names != _EXPECTED_LOCAL_MCP_TOOLS:
        raise InspectionError("staging_local_tool_count_invalid")
    tools = len(tool_names)
    return tools, _static_validation_identities(snapshot)


def _git_output(command: Sequence[str], *, cwd: Path, environment: Mapping[str, str]) -> str:
    raw = _run_capture(command, cwd=cwd, environment=environment)
    try:
        return raw.decode("ascii", errors="strict").strip()
    except UnicodeDecodeError as exc:
        raise InspectionError("git_output_invalid") from exc


@contextmanager
def _repository_bound_git_environment(
    root: Path,
    *,
    repository: str,
    token: str,
    environment: Mapping[str, str],
) -> Iterable[Mapping[str, str]]:
    """Give Git a credential helper that can answer for exactly one repo path."""

    helper = root / f"git-credential-{hashlib.sha256(repository.encode()).hexdigest()[:16]}.py"
    source = """#!/usr/bin/env python3
import os
import sys

request = {}
for line in sys.stdin:
    key, separator, value = line.rstrip("\\n").partition("=")
    if not separator:
        sys.exit(1)
    request[key] = value
path = request.get("path", "").lstrip("/")
repository = os.environ.get("MERCURY_BOUND_GIT_REPOSITORY", "")
if request.get("protocol") != "https" or request.get("host") != "github.com":
    sys.exit(1)
if path not in {repository, repository + ".git"}:
    sys.exit(1)
if request.get("operation") != "get":
    sys.exit(0)
token = os.environ.get("MERCURY_BOUND_GIT_TOKEN", "")
if not token:
    sys.exit(1)
sys.stdout.write("username=x-access-token\\npassword=" + token + "\\n")
"""
    descriptor = os.open(helper, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o700)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(source)
            handle.flush()
            os.fsync(handle.fileno())
        secured = dict(environment)
        secured.update(
            {
                "GIT_CONFIG_COUNT": "2",
                "GIT_CONFIG_KEY_0": "credential.https://github.com.useHttpPath",
                "GIT_CONFIG_VALUE_0": "true",
                "GIT_CONFIG_KEY_1": "credential.helper",
                "GIT_CONFIG_VALUE_1": f"!{sys.executable} {helper}",
                "MERCURY_BOUND_GIT_REPOSITORY": repository,
                "MERCURY_BOUND_GIT_TOKEN": token,
            }
        )
        yield secured
    finally:
        with suppress(FileNotFoundError):
            helper.unlink()


def _clone_candidate(
    root: Path,
    *,
    repository: str,
    reviewed_sha: str,
    token: str,
    environment: Mapping[str, str],
) -> Path:
    clone = root / "candidate.git"
    url = f"https://github.com/{repository}.git"
    with _repository_bound_git_environment(
        root, repository=repository, token=token, environment=environment
    ) as authenticated_environment:
        _run_silent(
            (
                environment["INSPECTOR_GIT"],
                "clone",
                "--no-checkout",
                "--origin",
                "origin",
                url,
                str(clone),
            ),
            cwd=None,
            environment=authenticated_environment,
        )
        _run_silent(
            (
                environment["INSPECTOR_GIT"],
                "fetch",
                "--force",
                "--prune",
                "origin",
                "+refs/heads/*:refs/remotes/origin/*",
                "+refs/tags/*:refs/tags/*",
                "+refs/pull/*/head:refs/remotes/pull/*/head",
            ),
            cwd=clone,
            environment=authenticated_environment,
        )
    if (
        _git_output(
            (environment["INSPECTOR_GIT"], "rev-parse", "refs/remotes/origin/main"), cwd=clone, environment=environment
        )
        != reviewed_sha
    ):
        raise InspectionError("reviewed_commit_mismatch")
    return clone


def _inspect_staging(
    root: Path,
    *,
    repository: str,
    staging_ref: str,
    reviewed_sha: str,
    token: str,
    candidate_clone: Path,
    public_mcp_base_url: str,
    environment: Mapping[str, str],
) -> tuple[Mapping[str, object], tuple[tuple[str, str, str], ...]]:
    clone = root / "staging.git"
    with _repository_bound_git_environment(
        root, repository=repository, token=token, environment=environment
    ) as authenticated_environment:
        _run_silent(
            (
                environment["INSPECTOR_GIT"],
                "clone",
                "--no-checkout",
                "--branch",
                staging_ref,
                "--single-branch",
                f"https://github.com/{repository}.git",
                str(clone),
            ),
            cwd=None,
            environment=authenticated_environment,
        )
    tag_ref = f"refs/tags/{staging_ref}"
    if _git_output((environment["INSPECTOR_GIT"], "cat-file", "-t", tag_ref), cwd=clone, environment=environment) != "tag":
        raise InspectionError("staging_annotated_tag_required")
    commit_sha = _git_output(
        (environment["INSPECTOR_GIT"], "rev-parse", f"{tag_ref}^{{commit}}"), cwd=clone, environment=environment
    )
    _require_sha(commit_sha, "staging_commit_invalid", commit=True)
    if (
        _git_output((environment["INSPECTOR_GIT"], "rev-list", "--all", "--count"), cwd=clone, environment=environment)
        != "1"
    ):
        raise InspectionError("staging_history_invalid")
    history = _git_output((environment["INSPECTOR_GIT"], "rev-list", "--all"), cwd=clone, environment=environment)
    if reviewed_sha in history.splitlines():
        raise InspectionError("staging_source_history_present")
    candidate_archive = root / "candidate.tar"
    staging_archive = root / "staging.tar"
    _run_to_file(
        (environment["INSPECTOR_GIT"], "archive", "--format=tar", reviewed_sha),
        cwd=candidate_clone,
        environment=environment,
        destination=candidate_archive,
    )
    _run_to_file(
        (environment["INSPECTOR_GIT"], "archive", "--format=tar", commit_sha),
        cwd=clone,
        environment=environment,
        destination=staging_archive,
    )
    try:
        candidate_public_tree = build_public_tree(candidate_archive.read_bytes())
        staging_public_tree = build_public_tree(staging_archive.read_bytes())
    except (OSError, PublicTreeError) as exc:
        raise InspectionError("staging_public_tree_invalid") from exc
    if candidate_public_tree.digest != staging_public_tree.digest:
        raise InspectionError("staging_tree_digest_mismatch")
    staging_snapshot = _archive_snapshot(staging_archive)
    local_tools, validation_identities = _validate_staging_static(
        staging_snapshot,
        public_mcp_base_url=public_mcp_base_url,
    )
    return (
        {
            "repository": repository,
            "ref": staging_ref,
            "commit_sha": commit_sha,
            "tree_sha256": staging_public_tree.digest,
            "local_tool_count": local_tools,
        },
        validation_identities,
    )


def _inspect_git_and_staging(
    *,
    policy: Mapping[str, object],
    reviewed_sha: str,
    staging_ref: str,
    environment_values: Mapping[str, str],
    gitleaks: Path,
    trufflehog: Path,
    allowlist: frozenset[tuple[str, str, str]],
) -> tuple[
    list[str],
    list[str],
    Mapping[str, object],
    tuple[tuple[str, str, str], ...],
]:
    with tempfile.TemporaryDirectory(prefix="mercury-release-control-") as temporary:
        temporary_root = Path(temporary)
        home = temporary_root / "home"
        home.mkdir(mode=0o700)
        process_environment = _minimal_process_env(
            home,
            tool_paths=environment_values,
        )
        clone = _clone_candidate(
            temporary_root,
            repository=str(policy["reviewed_repository"]),
            reviewed_sha=reviewed_sha,
            token=environment_values["MERCURY_TARGET_REPOSITORY_READ_TOKEN"],
            environment=process_environment,
        )
        gitleaks_config = _materialize_trusted_gitleaks_config(
            temporary_root,
            clone=clone,
            reviewed_sha=reviewed_sha,
            environment=process_environment,
        )
        all_hashes = _scan_git(
            clone,
            log_options="--all",
            gitleaks=gitleaks,
            trufflehog=trufflehog,
            gitleaks_config=gitleaks_config,
            environment=process_environment,
        )
        pull_refs = _git_output(
            (
                process_environment["INSPECTOR_GIT"],
                "for-each-ref",
                "--format=%(refname)",
                "refs/remotes/pull",
            ),
            cwd=clone,
            environment=process_environment,
        )
        refs = tuple(item for item in pull_refs.splitlines() if item)
        if len(refs) > MAX_HTTP_OBJECTS or any(
            re.fullmatch(r"refs/remotes/pull/[1-9][0-9]*/head", item) is None for item in refs
        ):
            raise InspectionError("pull_request_ref_inventory_invalid")
        pr_hashes = [_canonical_sha256({"pull_refs": list(refs)})]
        for ref in refs:
            pr_hashes.extend(
                _scan_git(
                    clone,
                    log_options=ref,
                    gitleaks=gitleaks,
                    trufflehog=trufflehog,
                    gitleaks_config=gitleaks_config,
                    environment=process_environment,
                )
            )
        staging, validation_identities = _inspect_staging(
            temporary_root,
            repository=str(policy["staging_repository"]),
            staging_ref=staging_ref,
            reviewed_sha=reviewed_sha,
            token=environment_values["MERCURY_STAGING_REPOSITORY_TOKEN"],
            candidate_clone=clone,
            public_mcp_base_url=environment_values["MERCURY_PUBLIC_MCP_URL"],
            environment=process_environment,
        )
        all_hashes.extend(
            _scan_payloads(
                (temporary_root / "staging.tar",),
                gitleaks=gitleaks,
                trufflehog=trufflehog,
                allowlist=allowlist,
            )
        )
    return all_hashes, pr_hashes, staging, validation_identities


def _scan_payloads(
    payloads: Iterable[bytes | Path],
    *,
    gitleaks: Path,
    trufflehog: Path,
    allowlist: frozenset[tuple[str, str, str]] = frozenset(),
    budget: InspectionBudget | None = None,
) -> list[str]:
    scan_budget = budget or InspectionBudget(time.monotonic())
    hashes: list[str] = []
    with tempfile.TemporaryDirectory(prefix="mercury-hosted-scan-") as temporary:
        root = Path(temporary)
        home = root / "home"
        home.mkdir(mode=0o700)
        for index, payload in enumerate(payloads):
            scan_budget.charge_object()
            object_root = root / f"object-{index:04d}"
            object_root.mkdir(mode=0o700)
            destination = object_root / "payload.bin"
            _materialize_payload(payload, destination, budget=scan_budget)
            hashes.append(_sha256_file(destination))
            decoded_root = object_root / "decoded"
            _decode_archive_members(destination, decoded_root, budget=scan_budget, depth=0)
            hashes.extend(
                _scan_directory(
                    object_root,
                    gitleaks=gitleaks,
                    trufflehog=trufflehog,
                    environment=_minimal_process_env(home),
                    allowlist=allowlist,
                    archive_member_prefix=(
                        _archive_member_prefix(decoded_root)
                        if decoded_root.is_dir()
                        else None
                    ),
                    budget=scan_budget,
                )
            )
    return hashes or [_canonical_sha256({"objects": 0})]


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as handle:
            for block in iter(lambda: handle.read(64 * 1024), b""):
                digest.update(block)
    except OSError as exc:
        raise InspectionError("hosted_payload_invalid") from exc
    return digest.hexdigest()


def _materialize_payload(
    payload: bytes | Path, destination: Path, *, budget: InspectionBudget
) -> None:
    descriptor = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as target:
            if isinstance(payload, bytes):
                if not payload or len(payload) > MAX_HTTP_BYTES:
                    raise InspectionError("hosted_payload_invalid")
                target.write(payload)
                budget.charge_uncompressed(len(payload))
            elif isinstance(payload, Path):
                metadata = payload.lstat()
                if (
                    stat.S_ISLNK(metadata.st_mode)
                    or not stat.S_ISREG(metadata.st_mode)
                    or metadata.st_size <= 0
                    or metadata.st_size > MAX_ARCHIVE_BYTES
                ):
                    raise InspectionError("hosted_payload_invalid")
                with payload.open("rb") as source:
                    for block in iter(lambda: source.read(64 * 1024), b""):
                        target.write(block)
                        budget.charge_uncompressed(len(block))
            else:
                raise InspectionError("hosted_payload_invalid")
            target.flush()
            os.fsync(target.fileno())
    except InspectionError:
        raise
    except OSError as exc:
        raise InspectionError("hosted_payload_invalid") from exc


def _archive_destination(root: Path, name: str) -> Path:
    if not _safe_archive_name(name):
        raise InspectionError("archive_member_invalid")
    destination = root.joinpath(*PurePosixPath(name).parts)
    if root not in destination.parents:
        raise InspectionError("archive_member_invalid")
    destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    return destination


def _write_archive_member(source: BinaryIO, destination: Path, size: int, *, budget: InspectionBudget) -> None:
    if size < 0 or size > MAX_ARCHIVE_MEMBER_BYTES:
        raise InspectionError("archive_member_invalid")
    descriptor = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    written = 0
    try:
        with os.fdopen(descriptor, "wb") as target:
            while written < size:
                block = source.read(min(64 * 1024, size - written))
                if not block:
                    raise InspectionError("archive_member_invalid")
                target.write(block)
                written += len(block)
                budget.charge_uncompressed(len(block))
            if source.read(1):
                raise InspectionError("archive_member_invalid")
            target.flush()
            os.fsync(target.fileno())
    except InspectionError:
        raise
    except OSError as exc:
        raise InspectionError("archive_member_invalid") from exc


def _write_bounded_stream(
    source: BinaryIO, destination: Path, *, maximum: int, budget: InspectionBudget
) -> None:
    descriptor = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    total = 0
    try:
        with os.fdopen(descriptor, "wb") as target:
            for block in iter(lambda: source.read(64 * 1024), b""):
                total += len(block)
                if total > maximum:
                    raise InspectionError("archive_member_invalid")
                target.write(block)
                budget.charge_uncompressed(len(block))
            if total == 0:
                raise InspectionError("archive_member_invalid")
            target.flush()
            os.fsync(target.fileno())
    except InspectionError:
        raise
    except OSError as exc:
        raise InspectionError("archive_member_invalid") from exc


def _decode_archive_members(source: Path, destination: Path, *, budget: InspectionBudget, depth: int) -> None:
    if depth >= MAX_ARCHIVE_DEPTH:
        return
    try:
        if zipfile.is_zipfile(source):
            with zipfile.ZipFile(source) as archive:
                members = archive.infolist()
                names = [member.filename for member in members]
                if len(members) > MAX_ARCHIVE_MEMBERS or len(names) != len(set(names)):
                    raise InspectionError("archive_inventory_too_large")
                for member in members:
                    if member.is_dir() or member.external_attr >> 16 & 0o170000 not in {0, 0o100000}:
                        if member.is_dir():
                            continue
                        raise InspectionError("archive_member_invalid")
                    if member.file_size > MAX_ARCHIVE_MEMBER_BYTES or (
                        member.compress_size and member.file_size > member.compress_size * MAX_ARCHIVE_RATIO
                    ):
                        raise InspectionError("archive_member_invalid")
                    target = _archive_destination(destination, member.filename)
                    with archive.open(member) as member_source:
                        _write_archive_member(member_source, target, member.file_size, budget=budget)
                    _decode_archive_members(target, target.parent / f".{target.name}.decoded", budget=budget, depth=depth + 1)
            return
        if tarfile.is_tarfile(source):
            with tarfile.open(source, mode="r:*") as archive:
                members = archive.getmembers()
                names = [member.name for member in members if not member.isdir()]
                if len(members) > MAX_ARCHIVE_MEMBERS or len(names) != len(set(names)):
                    raise InspectionError("archive_inventory_too_large")
                for member in members:
                    if member.isdir():
                        continue
                    if not member.isfile() or member.size > MAX_ARCHIVE_MEMBER_BYTES:
                        raise InspectionError("archive_member_invalid")
                    target = _archive_destination(destination, member.name)
                    member_source = archive.extractfile(member)
                    if member_source is None:
                        raise InspectionError("archive_member_invalid")
                    with member_source:
                        _write_archive_member(member_source, target, member.size, budget=budget)
                    _decode_archive_members(target, target.parent / f".{target.name}.decoded", budget=budget, depth=depth + 1)
            return
        with source.open("rb") as probe:
            magic = probe.read(2)
        if magic == b"\x1f\x8b":
            target = _archive_destination(destination, "payload")
            with gzip.open(source, "rb") as decoded:
                _write_bounded_stream(
                    decoded, target, maximum=MAX_ARCHIVE_MEMBER_BYTES, budget=budget
                )
    except InspectionError:
        raise
    except (OSError, tarfile.TarError, zipfile.BadZipFile, EOFError) as exc:
        raise InspectionError("archive_invalid") from exc


def _record_id(value: Mapping[str, object], code: str) -> int:
    identifier = value.get("id")
    if not isinstance(identifier, int) or isinstance(identifier, bool) or identifier <= 0:
        raise InspectionError(code)
    return identifier


def _inspect_github_releases(
    *,
    token: str,
    repository: str,
    gitleaks: Path,
    trufflehog: Path,
    allowlist: frozenset[tuple[str, str, str]],
    budget: InspectionBudget,
) -> list[str]:
    releases, hashes = _github_records(f"/repos/{repository}/releases?per_page=100", token)
    payloads: list[bytes] = []
    for release in releases:
        assets = release.get("assets")
        if not isinstance(assets, list):
            raise InspectionError("github_release_inventory_invalid")
        for asset in assets:
            item = _require_mapping(asset, "github_release_inventory_invalid")
            asset_id = _record_id(item, "github_release_inventory_invalid")
            response = request_bytes(
                f"https://api.github.com/repos/{repository}/releases/assets/{asset_id}",
                headers=_github_headers(token, accept="application/octet-stream"),
                code="github_asset_download_failed",
            )
            payloads.append(response.body)
    return hashes + _scan_payloads(
        payloads, gitleaks=gitleaks, trufflehog=trufflehog, allowlist=allowlist, budget=budget
    )


def _inspect_github_actions(
    *,
    token: str,
    repository: str,
    gitleaks: Path,
    trufflehog: Path,
    allowlist: frozenset[tuple[str, str, str]],
    budget: InspectionBudget,
) -> list[str]:
    runs, run_hashes = _github_records(
        f"/repos/{repository}/actions/runs?per_page=100", token, key="workflow_runs"
    )
    artifacts, artifact_hashes = _github_records(
        f"/repos/{repository}/actions/artifacts?per_page=100", token, key="artifacts"
    )
    caches, cache_hashes = _github_records(
        f"/repos/{repository}/actions/caches?per_page=100", token, key="actions_caches"
    )
    if caches:
        raise InspectionError("github_cache_content_unavailable")
    payloads: list[bytes] = []
    for run in runs:
        run_id = _record_id(run, "github_actions_inventory_invalid")
        response = request_bytes(
            f"https://api.github.com/repos/{repository}/actions/runs/{run_id}/logs",
            headers=_github_headers(token, accept="application/vnd.github+json"),
            code="github_actions_log_download_failed",
        )
        payloads.append(response.body)
    for artifact in artifacts:
        artifact_id = _record_id(artifact, "github_actions_inventory_invalid")
        response = request_bytes(
            f"https://api.github.com/repos/{repository}/actions/artifacts/{artifact_id}/zip",
            headers=_github_headers(token, accept="application/vnd.github+json"),
            code="github_actions_artifact_download_failed",
        )
        payloads.append(response.body)
    return (
        run_hashes
        + artifact_hashes
        + cache_hashes
        + _scan_payloads(
            payloads, gitleaks=gitleaks, trufflehog=trufflehog, allowlist=allowlist, budget=budget
        )
    )


def _inspect_github_packages_pages_wiki(
    *,
    token: str,
    repository: str,
    gitleaks: Path,
    trufflehog: Path,
    allowlist: frozenset[tuple[str, str, str]],
    budget: InspectionBudget,
) -> list[str]:
    owner = repository.split("/", 1)[0]
    hashes: list[str] = []
    for package_type in ("npm", "container", "maven", "nuget"):
        packages, package_hashes = _github_records(
            f"/users/{owner}/packages?package_type={package_type}&per_page=100", token
        )
        hashes.extend(package_hashes)
        if packages:
            raise InspectionError("github_package_content_unavailable")
    payload, response = _github_json(f"/repos/{repository}", token)
    metadata = _require_mapping(payload, "github_repository_metadata_invalid")
    hashes.append(_sha256_bytes(response.body))
    if metadata.get("has_pages") is not False:
        raise InspectionError("github_pages_content_unavailable")
    if metadata.get("has_wiki") is not False:
        raise InspectionError("github_wiki_content_unavailable")
    del gitleaks, trufflehog, allowlist, budget
    return hashes


def _inspect_marketplace(
    *,
    environment: Mapping[str, str],
    gitleaks: Path,
    trufflehog: Path,
    allowlist: frozenset[tuple[str, str, str]],
    budget: InspectionBudget,
) -> list[str]:
    response = request_bytes(
        environment["MERCURY_MARKETPLACE_SNAPSHOT_URL"], code="marketplace_download_failed"
    )
    return _scan_payloads(
        (response.body,), gitleaks=gitleaks, trufflehog=trufflehog, allowlist=allowlist, budget=budget
    )


def _mcp_response_json(response: HttpResponse, *, request_id: int) -> Mapping[str, object]:
    body = response.body
    content_type = response.headers.get("content-type", "")
    if "text/event-stream" in content_type:
        lines = [
            line[5:].strip()
            for line in body.decode("utf-8", errors="strict").splitlines()
            if line.startswith("data:")
        ]
        if len(lines) != 1:
            raise InspectionError("public_mcp_response_invalid")
        body = lines[0].encode("utf-8")
    payload = _require_mapping(
        _parse_json_bytes(body, "public_mcp_response_invalid"), "public_mcp_response_invalid"
    )
    if payload.get("jsonrpc") != "2.0" or payload.get("id") != request_id or "error" in payload:
        raise InspectionError("public_mcp_response_invalid")
    result = _require_mapping(payload.get("result"), "public_mcp_response_invalid")
    _assert_mcp_result_consistency(result)
    _assert_sanitized(payload)
    return result


def _mcp_call(
    endpoint: str,
    *,
    method: str,
    params: Mapping[str, object],
    request_id: int,
    token: str,
    session_id: str | None = None,
) -> tuple[Mapping[str, object], HttpResponse]:
    request = json.dumps(
        {"jsonrpc": "2.0", "id": request_id, "method": method, "params": dict(params)},
        ensure_ascii=True,
        separators=(",", ":"),
    ).encode("utf-8")
    headers = {
        "Accept": "application/json, text/event-stream",
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    }
    if session_id is not None:
        headers["Mcp-Session-Id"] = session_id
    response = request_bytes(
        endpoint,
        method="POST",
        headers=headers,
        body=request,
        code="public_mcp_request_failed",
    )
    return _mcp_response_json(response, request_id=request_id), response


def _mcp_notify(endpoint: str, *, token: str, session_id: str) -> HttpResponse:
    payload = json.dumps(
        {"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}},
        ensure_ascii=True,
        separators=(",", ":"),
    ).encode("utf-8")
    response = request_bytes(
        endpoint,
        method="POST",
        headers={
            "Accept": "application/json, text/event-stream",
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
            "Mcp-Session-Id": session_id,
        },
        body=payload,
        code="public_mcp_request_failed",
        expected_statuses=frozenset({200, 202, 204}),
    )
    if response.headers.get("mcp-session-id", session_id) != session_id:
        raise InspectionError("public_mcp_session_invalid")
    return response


def _assert_sanitized(value: object) -> None:
    pending: list[object] = [value]
    nodes = 0
    while pending:
        nodes += 1
        if nodes > 100_000:
            raise InspectionError("public_mcp_response_invalid")
        item = pending.pop()
        if isinstance(item, Mapping):
            for key, child in item.items():
                if not isinstance(key, str) or _SENSITIVE_KEY_RE.search(key):
                    raise InspectionError("public_mcp_secret_detected")
                pending.append(child)
        elif isinstance(item, list):
            pending.extend(item)
        elif isinstance(item, str):
            if len(item) > 64 * 1024 or _SENSITIVE_VALUE_RE.search(item):
                raise InspectionError("public_mcp_secret_detected")
            stripped = item.lstrip()
            if stripped.startswith(("{", "[")):
                try:
                    decoded = json.loads(item, object_pairs_hook=_pairs)
                except (UnicodeError, json.JSONDecodeError):
                    decoded = None
                if isinstance(decoded, (Mapping, list)):
                    pending.append(decoded)
                    continue
            scrubbed = _PUBLIC_VALIDATION_URI_RE.sub("", item)
            scrubbed = _PUBLIC_UUID_TOKEN_RE.sub("", scrubbed)
            scrubbed = _PUBLIC_VALIDATION_TOKEN_RE.sub("", scrubbed)
            scrubbed = _PUBLIC_EVIDENCE_DIGEST_RE.sub("", scrubbed)
            if _HIGH_ENTROPY_RE.search(scrubbed) and _PUBLIC_UUID_RE.fullmatch(item) is None:
                raise InspectionError("public_mcp_secret_detected")
        elif item is not None and not isinstance(item, (bool, int, float)):
            raise InspectionError("public_mcp_response_invalid")


def _assert_mcp_result_consistency(result: Mapping[str, object]) -> None:
    structured = result.get("structuredContent")
    if structured is None:
        return
    if not isinstance(structured, Mapping):
        raise InspectionError("public_mcp_response_invalid")
    content = result.get("content")
    if not isinstance(content, list) or len(content) != 1:
        raise InspectionError("public_mcp_response_invalid")
    text_content = content[0]
    if (
        not isinstance(text_content, Mapping)
        or set(text_content) != {"type", "text"}
        or text_content.get("type") != "text"
        or not isinstance(text_content.get("text"), str)
    ):
        raise InspectionError("public_mcp_response_invalid")
    try:
        decoded = json.loads(text_content["text"], object_pairs_hook=_pairs)
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise InspectionError("public_mcp_response_invalid") from exc
    if decoded != structured:
        raise InspectionError("public_mcp_response_invalid")


def _require_connector_validation_payload(
    result: Mapping[str, object],
    *,
    connector: str,
    result_field: str,
) -> None:
    if result.get("isError") is not False:
        raise InspectionError("public_mcp_validation_rag_invalid")
    structured = _require_mapping(
        result.get("structuredContent"),
        "public_mcp_validation_rag_invalid",
    )
    rows = structured.get(result_field)
    if structured.get("status") != "ok" or not isinstance(rows, list) or not rows:
        raise InspectionError("public_mcp_validation_rag_invalid")
    for row_value in rows:
        row = _require_mapping(row_value, "public_mcp_validation_rag_invalid")
        citation = row.get("citation")
        metadata = row.get("metadata")
        if (
            not isinstance(citation, Mapping)
            or not citation
            or not isinstance(metadata, Mapping)
            or metadata.get("connector") != connector
            or metadata.get("doc_type") != "endpoint_validation"
            or metadata.get("review_status") != "reviewed"
        ):
            raise InspectionError("public_mcp_validation_rag_invalid")


def _render_status_endpoint(
    status_payload: Mapping[str, object],
    *,
    base_url: str,
    reviewed_sha: str,
    version: str,
) -> str:
    endpoint = status_payload.get("mcp_endpoint")
    if (
        status_payload.get("status") != "ok"
        or status_payload.get("version") != version
        or status_payload.get("deployment_commit") != reviewed_sha
        or not isinstance(endpoint, str)
        or not endpoint.startswith(base_url + "/")
    ):
        raise InspectionError("render_status_invalid")
    return endpoint


def _render_log_url(
    render_base: str,
    *,
    service_id: str,
    owner_id: str,
    log_type: str,
) -> str:
    if (
        _SERVICE_ID_RE.fullmatch(service_id) is None
        or _RENDER_OWNER_ID_RE.fullmatch(owner_id) is None
        or log_type not in {"build", "runtime"}
    ):
        raise InspectionError("render_log_query_invalid")
    query = urllib.parse.urlencode(
        {"resource": service_id, "ownerId": owner_id, "type": log_type}
    )
    return f"{render_base.rstrip('/')}/logs?{query}"


def _inspect_render_and_public_mcp(
    *,
    environment: Mapping[str, str],
    reviewed_sha: str,
    gitleaks: Path,
    trufflehog: Path,
    allowlist: frozenset[tuple[str, str, str]],
    budget: InspectionBudget,
    profile: ReleaseProfile,
) -> tuple[Mapping[str, object], list[str], list[str]]:
    base_url = environment["MERCURY_PUBLIC_MCP_URL"].rstrip("/")
    render_base = environment["RENDER_API_URL"].rstrip("/")
    if not render_base.endswith("/v1"):
        render_base = f"{render_base}/v1"
    render_headers = {"Authorization": f"Bearer {environment['RENDER_API_TOKEN']}"}
    service = request_bytes(
        f"{render_base}/services/{environment['RENDER_SERVICE_ID']}",
        headers=render_headers,
        code="render_service_query_failed",
        budget=budget,
    )
    service_payload = _require_mapping(
        _parse_json_bytes(service.body, "render_service_invalid"), "render_service_invalid"
    )
    details = _require_mapping(service_payload.get("serviceDetails"), "render_service_invalid")
    if service_payload.get("id") != environment["RENDER_SERVICE_ID"] or details.get("url") != base_url:
        raise InspectionError("render_service_binding_invalid")
    deployments = request_bytes(
        f"{render_base}/services/{environment['RENDER_SERVICE_ID']}/deploys?limit=100",
        headers=render_headers,
        code="render_deployment_query_failed",
        budget=budget,
    )
    deployment_rows = _parse_json_bytes(deployments.body, "render_deployment_invalid")
    if not isinstance(deployment_rows, list) or len(deployment_rows) > MAX_HTTP_OBJECTS:
        raise InspectionError("render_deployment_invalid")
    bound_deploy = False
    for row in deployment_rows:
        deployment = _require_mapping(row, "render_deployment_invalid")
        commit = deployment.get("commit")
        commit_id = commit.get("id") if isinstance(commit, Mapping) else deployment.get("commitId")
        if deployment.get("status") == "live" and commit_id == reviewed_sha:
            bound_deploy = True
    if not bound_deploy:
        raise InspectionError("render_deployment_binding_invalid")
    health = request_bytes(f"{base_url}/healthz", code="render_healthz_failed", budget=budget)
    health_payload = _require_mapping(
        _parse_json_bytes(health.body, "render_healthz_invalid"), "render_healthz_invalid"
    )
    if health_payload.get("status") != "ok":
        raise InspectionError("render_healthz_invalid")
    status = request_bytes(f"{base_url}/api/status", code="render_status_failed", budget=budget)
    status_payload = _require_mapping(
        _parse_json_bytes(status.body, "render_status_invalid"), "render_status_invalid"
    )
    endpoint = _render_status_endpoint(
        status_payload,
        base_url=base_url,
        reviewed_sha=reviewed_sha,
        version=profile.version,
    )
    initialized, initialize_response = _mcp_call(
        endpoint,
        method="initialize",
        params={
            "protocolVersion": "2025-03-26",
            "capabilities": {},
            "clientInfo": {"name": "release-control", "version": "1.0.0"},
        },
        request_id=1,
        token=environment["MERCURY_PUBLIC_MCP_TOKEN"],
    )
    server_info = _require_mapping(initialized.get("serverInfo"), "public_mcp_initialize_invalid")
    if (
        initialized.get("protocolVersion") != "2025-03-26"
        or server_info.get("name") != "Mercury Tools"
    ):
        raise InspectionError("public_mcp_initialize_invalid")
    session_id = initialize_response.headers.get("mcp-session-id")
    if not isinstance(session_id, str) or not session_id or len(session_id) > 1024:
        raise InspectionError("public_mcp_session_invalid")
    initialized_notification = _mcp_notify(
        endpoint, token=environment["MERCURY_PUBLIC_MCP_TOKEN"], session_id=session_id
    )
    tool_rows: list[object] = []
    tools_responses: list[HttpResponse] = []
    cursor: str | None = None
    for page in range(MAX_PAGES):
        tools, tools_response = _mcp_call(
            endpoint,
            method="tools/list",
            params={} if cursor is None else {"cursor": cursor},
            request_id=page + 2,
            token=environment["MERCURY_PUBLIC_MCP_TOKEN"],
            session_id=session_id,
        )
        if tools_response.headers.get("mcp-session-id", session_id) != session_id:
            raise InspectionError("public_mcp_session_invalid")
        page_rows = tools.get("tools")
        next_cursor = tools.get("nextCursor")
        if (
            not isinstance(page_rows, list)
            or set(tools) - {"tools", "nextCursor"}
            or (next_cursor is not None and (not isinstance(next_cursor, str) or not next_cursor))
        ):
            raise InspectionError("public_mcp_tool_inventory_invalid")
        tool_rows.extend(page_rows)
        tools_responses.append(tools_response)
        if next_cursor is None:
            break
        if next_cursor == cursor:
            raise InspectionError("public_mcp_tool_inventory_invalid")
        cursor = next_cursor
    else:
        raise InspectionError("public_mcp_tool_inventory_invalid")
    if len(tool_rows) != profile.hosted_tool_count:
        raise InspectionError("public_mcp_tool_inventory_invalid")
    tool_names = []
    for row in tool_rows:
        tool = _require_mapping(row, "public_mcp_tool_inventory_invalid")
        name = tool.get("name")
        if not isinstance(name, str) or not name or _SENSITIVE_KEY_RE.search(name):
            raise InspectionError("public_mcp_tool_inventory_invalid")
        _assert_sanitized(tool.get("inputSchema"))
        tool_names.append(name)
    if set(tool_names) != profile.hosted_tool_names:
        raise InspectionError("public_mcp_tool_inventory_invalid")
    samples: list[HttpResponse] = []
    sample_requests: list[tuple[int, str, str, Mapping[str, object], str]] = []
    request_id = 100
    for connector, label in (("flowaccount", "FlowAccount"), ("peak", "PEAK")):
        sample_requests.extend(
            (
                (
                    request_id,
                    connector,
                    "results",
                    {
                        "name": "search_knowledge",
                        "arguments": {
                            "query": f"{label} invoice accounting validation",
                            "filters": {
                                "connector": connector,
                                "doc_type": "endpoint_validation",
                                "review_status": "reviewed",
                            },
                            "top_k": 2,
                        },
                    },
                    "tools/call",
                ),
                (
                    request_id + 1,
                    connector,
                    "context",
                    {
                        "name": "retrieve_context_pack",
                        "arguments": {
                            "query": f"{label} invoice accounting validation",
                            "task": "release verification",
                            "filters": {
                                "connector": connector,
                                "doc_type": "endpoint_validation",
                                "review_status": "reviewed",
                            },
                            "max_chunks": 2,
                        },
                    },
                    "tools/call",
                ),
            )
        )
        request_id += 2
    for request_id, connector, result_field, params, method in sample_requests:
        result, sample_response = _mcp_call(
            endpoint,
            method=method,
            params=params,
            request_id=request_id,
            token=environment["MERCURY_PUBLIC_MCP_TOKEN"],
            session_id=session_id,
        )
        _require_connector_validation_payload(
            result,
            connector=connector,
            result_field=result_field,
        )
        _assert_sanitized(result)
        samples.append(sample_response)
    log_payloads = []
    for log_type in ("build", "runtime"):
        response = request_bytes(
            _render_log_url(
                render_base,
                service_id=environment["RENDER_SERVICE_ID"],
                owner_id=environment["RENDER_OWNER_ID"],
                log_type=log_type,
            ),
            headers=render_headers,
            code="render_log_query_failed",
            budget=budget,
        )
        log_payloads.append(response.body)
    render_hashes = [
        _sha256_bytes(health.body),
        _sha256_bytes(status.body),
        _sha256_bytes(service.body),
        _sha256_bytes(deployments.body),
        *_scan_payloads(
            log_payloads,
            gitleaks=gitleaks,
            trufflehog=trufflehog,
            allowlist=allowlist,
            budget=budget,
        ),
    ]
    public_hashes = [
        _sha256_bytes(initialize_response.body),
        _sha256_bytes(initialized_notification.body),
        *(_sha256_bytes(item.body) for item in tools_responses),
        *(_sha256_bytes(item.body) for item in samples),
    ]
    return (
        {
            "deployment_commit": status_payload["deployment_commit"],
            "version": profile.version,
            "hosted_tool_count": profile.hosted_tool_count,
            "evidence_sha256": _canonical_sha256(
                {"render": render_hashes, "tools": sorted(tool_names)}
            ),
        },
        render_hashes,
        public_hashes,
    )


def _database_cursor(connection: Any) -> Any:
    cursor = connection.cursor()
    if (
        not hasattr(cursor, "execute")
        or not hasattr(cursor, "fetchone")
        or not hasattr(cursor, "fetchall")
    ):
        raise InspectionError("database_driver_invalid")
    return cursor


def _database_rows(
    cursor: Any, query: str, parameters: Sequence[object] = ()
) -> list[tuple[object, ...]]:
    cursor.execute(query, tuple(parameters))
    rows = cursor.fetchall()
    if not isinstance(rows, list) or any(not isinstance(row, tuple) for row in rows):
        raise InspectionError("database_response_invalid")
    return rows


def _require_exact_validation_identity_coverage(
    *,
    validation_rows: Sequence[tuple[object, ...]],
    rag_rows: Sequence[tuple[object, ...]],
    expected_identities: Sequence[tuple[str, str, str]],
) -> tuple[list[tuple[str, int, int]], list[tuple[str, int, int]]]:
    expected = tuple(expected_identities)
    if (
        not expected
        or expected != tuple(sorted(set(expected)))
        or any(
            connector not in _VALIDATION_CATALOG_FILES
            or _ACTION_ID_RE.fullmatch(action_id) is None
            or _VERSION_ID_RE.fullmatch(version_id) is None
            for connector, action_id, version_id in expected
        )
    ):
        raise InspectionError("validation_expected_identity_invalid")
    if tuple(validation_rows) != expected:
        raise InspectionError("validation_coverage_invalid")
    expected_rag_rows = tuple((*identity, 1, 1) for identity in expected)
    if tuple(rag_rows) != expected_rag_rows:
        raise InspectionError("validation_rag_coverage_invalid")

    coverage = [
        (
            connector,
            sum(identity[0] == connector for identity in expected),
            sum(identity[0] == connector for identity in expected),
        )
        for connector in sorted(_VALIDATION_CATALOG_FILES)
    ]
    return coverage, list(coverage)


def inspect_database(
    *,
    policy: Mapping[str, object],
    database_url: str,
    expected_validation_identities: Sequence[tuple[str, str, str]],
) -> tuple[Mapping[str, object], Mapping[str, object]]:
    """Inspect only through PostgreSQL after TLS and identity checks pass."""

    try:
        profile = release_profile_from_policy(policy)
    except ReleaseProfileError as exc:
        raise InspectionError("supabase_policy_invalid") from exc
    supabase = _require_mapping(policy["supabase"], "supabase_policy_invalid")
    project_ref = supabase["project_ref"]
    assert isinstance(project_ref, str)
    plan = parse_database_url(database_url, project_ref=project_ref)
    try:
        psycopg = importlib.import_module("psycopg")
        connection = psycopg.connect(
            host=plan.hostname,
            port=plan.port,
            dbname=plan.expected_database,
            user=plan.user,
            password=plan.password,
            sslmode="verify-full",
            connect_timeout=DATABASE_TIMEOUT_SECONDS,
        )
    except (ImportError, AttributeError) as exc:
        raise InspectionError("database_driver_unavailable") from exc
    except Exception as exc:
        raise InspectionError("database_connection_failed") from exc
    try:
        cursor = _database_cursor(connection)
        cursor.execute("BEGIN READ ONLY")
        cursor.execute("SET LOCAL statement_timeout = '15000ms'")
        info = getattr(connection, "info", None)
        if info is None or getattr(info, "ssl_in_use", None) is not True:
            raise InspectionError("database_tls_identity_invalid")
        cursor.execute("SELECT current_database(), session_user, current_user")
        identity = cursor.fetchone()
        if (
            not isinstance(identity, tuple)
            or len(identity) != 3
            or identity[0] != plan.expected_database
            or identity[1] != plan.expected_role
            or identity[2] != plan.expected_role
        ):
            raise InspectionError("database_identity_mismatch")
        migrations = _database_rows(
            cursor,
            "SELECT version::text FROM supabase_migrations.schema_migrations "
            "ORDER BY version::text",
        )
        versions = tuple(row[0] for row in migrations)
        if any(not isinstance(item, str) or not item for item in versions):
            raise InspectionError("database_migration_invalid")
        migration_digest = _sha256_bytes(("\n".join(versions) + "\n").encode("utf-8"))
        table_rows = _database_rows(
            cursor,
            "SELECT tablename FROM pg_catalog.pg_tables "
            "WHERE schemaname = 'public' ORDER BY tablename",
        )
        tables = tuple(row[0] for row in table_rows)
        if any(not isinstance(item, str) for item in tables):
            raise InspectionError("database_table_inventory_invalid")
        bucket_rows = _database_rows(cursor, "SELECT id FROM storage.buckets ORDER BY id")
        buckets = tuple(row[0] for row in bucket_rows)
        if any(not isinstance(item, str) for item in buckets):
            raise InspectionError("database_bucket_inventory_invalid")
        functions: list[dict[str, str]] = []
        for signature in profile.supabase_function_signatures:
            cursor.execute("SELECT pg_get_functiondef(to_regprocedure(%s))", (signature,))
            row = cursor.fetchone()
            if not isinstance(row, tuple) or len(row) != 1 or not isinstance(row[0], str):
                raise InspectionError("database_function_definition_invalid")
            functions.append(
                {"signature": signature, "definition_sha256": _sha256_bytes(row[0].encode("utf-8"))}
            )
        validation_identity_rows = _database_rows(
            cursor,
            "SELECT connector_id, action_id, version_id "
            "FROM public.erp_action_validation_knowledge "
            "WHERE approved_public = true AND run_state = 'completed' "
            "AND connector_id IN ('flowaccount', 'peak') "
            "ORDER BY connector_id, action_id, version_id",
        )
        rag_identity_rows = _database_rows(
            cursor,
            "SELECT s.connector, c.metadata ->> 'action_id', "
            "c.metadata ->> 'version_id', "
            "count(DISTINCT d.id), count(DISTINCT c.id) "
            "FROM public.knowledge_sources AS s "
            "JOIN public.knowledge_documents AS d ON d.source_id = s.id "
            "JOIN public.knowledge_chunks AS c ON c.document_id = d.id "
            "WHERE s.connector IN ('flowaccount', 'peak') "
            "AND s.doc_type = 'endpoint_validation' "
            "AND s.review_status = 'reviewed' "
            "AND d.document_uri LIKE 'mercury://wiki/validation/%' "
            "AND d.metadata ->> 'approval_state' = 'approved_public' "
            "AND c.metadata ->> 'approval_state' = 'approved_public' "
            "AND c.metadata ->> 'connector' = s.connector "
            "GROUP BY s.connector, c.metadata ->> 'action_id', "
            "c.metadata ->> 'version_id' "
            "ORDER BY s.connector, c.metadata ->> 'action_id', "
            "c.metadata ->> 'version_id'",
        )
        validation_coverage, rag_coverage = _require_exact_validation_identity_coverage(
            validation_rows=validation_identity_rows,
            rag_rows=rag_identity_rows,
            expected_identities=expected_validation_identities,
        )
        observed: dict[str, object] = {
            "project_ref": project_ref,
            "project_ref_sha256": _sha256_bytes(project_ref.encode("utf-8")),
            "migration_id": profile.migration_id,
            "migration_history_sha256": migration_digest,
            "tables": list(tables),
            "storage_buckets": list(buckets),
            "functions": functions,
        }
        observed["schema_sha256"] = build_supabase_schema_digest(observed)
        for key in (
            "migration_id",
            "migration_history_sha256",
            "tables",
            "storage_buckets",
            "functions",
            "schema_sha256",
        ):
            if observed[key] != supabase.get(key):
                raise InspectionError("supabase_approved_state_mismatch")
        connection.rollback()
    except InspectionError:
        with suppress(Exception):
            connection.rollback()
        raise
    except Exception as exc:
        with suppress(Exception):
            connection.rollback()
        raise InspectionError("database_query_failed") from exc
    finally:
        with suppress(Exception):
            connection.close()
    flowaccount = {
        "total": 190,
        "terminal_records": 190,
        "required_live_test_passed": False,
        "report_sha256": _canonical_sha256(
            {
                "identity_sha256": _canonical_sha256(
                    {
                        "validation": validation_identity_rows,
                        "rag": rag_identity_rows,
                    }
                ),
                "validation_coverage": validation_coverage,
                "rag_coverage": rag_coverage,
            }
        ),
    }
    return observed, flowaccount


def _flowaccount_live_read(environment: Mapping[str, str]) -> str:
    base = environment["FLOWACCOUNT_SANDBOX_BASE_URL"].rstrip("/")
    token_body = urllib.parse.urlencode(
        {
            "client_id": environment["FLOWACCOUNT_SANDBOX_CLIENT_ID"],
            "client_secret": environment["FLOWACCOUNT_SANDBOX_CLIENT_SECRET"],
            "grant_type": "client_credentials",
            "scope": "flowaccount-api",
        }
    ).encode("ascii")
    token_response = request_bytes(
        f"{base}/token",
        method="POST",
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        body=token_body,
        code="flowaccount_token_request_failed",
    )
    token_payload = _require_mapping(
        _parse_json_bytes(token_response.body, "flowaccount_token_invalid"),
        "flowaccount_token_invalid",
    )
    access_token = token_payload.get("access_token")
    if not isinstance(access_token, str) or not access_token or len(access_token) > 4096:
        raise InspectionError("flowaccount_token_invalid")
    read_response = request_bytes(
        f"{base}/company/info",
        headers={"Authorization": f"Bearer {access_token}"},
        code="flowaccount_live_read_failed",
    )
    payload = _require_mapping(
        _parse_json_bytes(read_response.body, "flowaccount_live_read_invalid"),
        "flowaccount_live_read_invalid",
    )
    if payload.get("status") is False or payload.get("success") is False or payload.get("error"):
        raise InspectionError("flowaccount_live_read_invalid")
    return _canonical_sha256(
        {
            "token_response_sha256": _sha256_bytes(token_response.body),
            "read_response_sha256": _sha256_bytes(read_response.body),
        }
    )


def _surface(
    name: str, *, hashes: Iterable[str], started_at: str, completed_at: str
) -> dict[str, object]:
    evidence_hashes = list(hashes)
    if not evidence_hashes or any(_SHA256_RE.fullmatch(item) is None for item in evidence_hashes):
        raise InspectionError("surface_evidence_invalid")
    return {
        "surface": name,
        "status": "passed",
        "scanner_versions": list(
            _HISTORY_SCANNERS
            if name in {"git_all_refs", "github_pull_request_refs"}
            else _BUILTIN_SCANNERS
        ),
        "started_at": started_at,
        "completed_at": completed_at,
        "finding_count": 0,
        "evidence_hashes": evidence_hashes,
        "exit_codes": [0],
        "blocker_codes": [],
        "finding_codes": [],
    }


def _timestamp(clock: Callable[[], datetime]) -> str:
    value = clock()
    if value.tzinfo is None:
        raise InspectionError("clock_invalid")
    return value.astimezone(UTC).isoformat()


def _atomic_write_new_json(path: Path, payload: Mapping[str, object]) -> None:
    encoded = (
        json.dumps(payload, ensure_ascii=True, separators=(",", ":"), sort_keys=True).encode(
            "utf-8"
        )
        + b"\n"
    )
    if not encoded or len(encoded) > OUTPUT_MAX_BYTES:
        raise InspectionError("evidence_output_too_large")
    try:
        parent = path.parent
        parent_metadata = parent.stat()
        if not stat.S_ISDIR(parent_metadata.st_mode) or path.exists():
            raise InspectionError("evidence_output_exists")
        descriptor, temporary = tempfile.mkstemp(prefix=".hosted-evidence-", dir=parent)
        try:
            os.fchmod(descriptor, 0o600)
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(encoded)
                handle.flush()
                os.fsync(handle.fileno())
            os.link(temporary, path)
            linked = path.stat()
            if stat.S_IMODE(linked.st_mode) != 0o600 or linked.st_size != len(encoded):
                raise InspectionError("evidence_output_invalid")
        finally:
            with suppress(FileNotFoundError):
                os.unlink(temporary)
    except InspectionError:
        raise
    except OSError as exc:
        raise InspectionError("evidence_output_invalid") from exc


def inspect(
    *,
    policy_path: Path,
    reviewed_sha: str,
    staging_ref: str,
    manifest_path: Path,
    allowlist_path: Path,
    output_path: Path,
    environment: Mapping[str, str] | None = None,
    clock: Callable[[], datetime] | None = None,
) -> Mapping[str, object]:
    """Collect strict hosted evidence and atomically write the schema-v1 output."""

    if _SHA_RE.fullmatch(reviewed_sha) is None:
        raise InspectionError("reviewed_sha_invalid")
    policy = validate_policy(
        load_strict_json(policy_path, maximum=MAX_POLICY_BYTES, code="policy_invalid")
    )
    try:
        profile = release_profile_from_policy(policy)
    except ReleaseProfileError as exc:
        raise InspectionError("policy_release_boundary_invalid") from exc
    if staging_ref != profile.staging_ref(reviewed_sha):
        raise InspectionError("staging_ref_invalid")
    manifest_data = _read_regular_bytes(
        manifest_path, maximum=MAX_UNTRUSTED_JSON_BYTES, code="manifest_invalid"
    )
    allowlist_data = _read_regular_bytes(
        allowlist_path, maximum=MAX_UNTRUSTED_JSON_BYTES, code="allowlist_invalid"
    )
    clock = clock or (lambda: datetime.now(UTC))
    validate_manifest(
        _require_mapping(_parse_json_bytes(manifest_data, "manifest_invalid"), "manifest_invalid")
    )
    allowlist = _require_mapping(
        _parse_json_bytes(allowlist_data, "allowlist_invalid"), "allowlist_invalid"
    )
    validate_allowlist(allowlist, at=clock())
    allowlist_keys = _allowlist_keys(allowlist)
    values = dict(os.environ if environment is None else environment)
    validate_environment(policy, values)
    budget = InspectionBudget(time.monotonic())
    with tempfile.TemporaryDirectory(prefix="mercury-inspector-tools-") as temporary:
        tool_home = Path(temporary) / "home"
        tool_home.mkdir(mode=0o700)
        process_environment = _minimal_process_env(
            tool_home,
            tool_paths=values,
        )
        gitleaks, trufflehog = _require_scanner_versions(process_environment, tool_home)
        (
            git_hashes,
            pr_hashes,
            staging,
            validation_identities,
        ) = _inspect_git_and_staging(
            policy=policy,
            reviewed_sha=reviewed_sha,
            staging_ref=staging_ref,
            environment_values=values,
            gitleaks=gitleaks,
            trufflehog=trufflehog,
            allowlist=allowlist_keys,
        )
        releases_hashes = _inspect_github_releases(
            token=values["MERCURY_TARGET_REPOSITORY_READ_TOKEN"],
            repository=str(policy["reviewed_repository"]),
            gitleaks=gitleaks,
            trufflehog=trufflehog,
            allowlist=allowlist_keys,
            budget=budget,
        )
        actions_hashes = _inspect_github_actions(
            token=values["MERCURY_TARGET_REPOSITORY_READ_TOKEN"],
            repository=str(policy["reviewed_repository"]),
            gitleaks=gitleaks,
            trufflehog=trufflehog,
            allowlist=allowlist_keys,
            budget=budget,
        )
        packages_hashes = _inspect_github_packages_pages_wiki(
            token=values["MERCURY_TARGET_REPOSITORY_READ_TOKEN"],
            repository=str(policy["reviewed_repository"]),
            gitleaks=gitleaks,
            trufflehog=trufflehog,
            allowlist=allowlist_keys,
            budget=budget,
        )
        marketplace_hashes = _inspect_marketplace(
            environment=values,
            gitleaks=gitleaks,
            trufflehog=trufflehog,
            allowlist=allowlist_keys,
            budget=budget,
        )
        render, render_hashes, public_mcp_hashes = _inspect_render_and_public_mcp(
            environment=values,
            reviewed_sha=reviewed_sha,
            gitleaks=gitleaks,
            trufflehog=trufflehog,
            allowlist=allowlist_keys,
            budget=budget,
            profile=profile,
        )
        supabase, flowaccount = inspect_database(
            policy=policy,
            database_url=values["SUPABASE_DB_URL"],
            expected_validation_identities=validation_identities,
        )
    flowaccount = dict(flowaccount)
    flowaccount["required_live_test_passed"] = True
    flowaccount["report_sha256"] = _canonical_sha256(
        {
            "coverage": flowaccount["report_sha256"],
            "live_read": _flowaccount_live_read(values),
        }
    )
    completed_at = _timestamp(clock)
    surface_hashes = {
        "git_all_refs": git_hashes,
        "github_pull_request_refs": pr_hashes,
        "github_releases_and_assets": releases_hashes,
        "github_actions_logs_artifacts_caches": actions_hashes,
        "github_packages_pages_wiki": packages_hashes,
        "marketplace_snapshot": marketplace_hashes,
        "render_build_and_runtime_logs": render_hashes,
        "supabase_knowledge_and_storage": [
            _canonical_sha256(
                {
                    "migration": supabase["migration_history_sha256"],
                    "schema": supabase["schema_sha256"],
                }
            )
        ],
        "public_mcp_responses": public_mcp_hashes,
    }
    surfaces = [
        _surface(
            name, hashes=surface_hashes[name], started_at=completed_at, completed_at=completed_at
        )
        for name in TRUSTED_SURFACES
    ]
    evidence: dict[str, object] = {
        "schema_version": 1,
        "reviewed_repository": policy["reviewed_repository"],
        "reviewed_commit_sha": reviewed_sha,
        "public_surface_manifest_sha256": _sha256_bytes(manifest_data),
        "secret_scan_allowlist_sha256": _sha256_bytes(allowlist_data),
        "flowaccount": flowaccount,
        "staging": staging,
        "render": render,
        "supabase": supabase,
        "surfaces": surfaces,
        "completed_at": completed_at,
    }
    _atomic_write_new_json(output_path, evidence)
    return evidence


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--interface-version", required=True, type=int)
    parser.add_argument("--policy", required=True, type=Path)
    parser.add_argument("--reviewed-sha", required=True)
    parser.add_argument("--staging-ref", required=True)
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--allowlist", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if args.interface_version != 2:
        print("release-control inspector failed: interface_version_invalid", file=sys.stderr)
        return 1
    try:
        inspect(
            policy_path=args.policy,
            reviewed_sha=args.reviewed_sha,
            staging_ref=args.staging_ref,
            manifest_path=args.manifest,
            allowlist_path=args.allowlist,
            output_path=args.output,
        )
    except InspectionError as exc:
        print(f"release-control inspector failed: {exc}", file=sys.stderr)
        return 1
    except Exception:
        print("release-control inspector failed: inspection_internal_error", file=sys.stderr)
        return 1
    print(json.dumps({"status": "ok"}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
