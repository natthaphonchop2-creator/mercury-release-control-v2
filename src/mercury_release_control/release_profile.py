"""Immutable release-specific identities for supported Mercury control paths."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass

SUPPORTED_VERSION_PATTERN = r"^(?:0\.2\.2|0\.3\.0)$"
SUPPORTED_STAGING_REF_PATTERN = r"^v0\.(?:2\.2|3\.0)-rc\.[0-9a-f]{12}$"
SUPPORTED_RELEASE_WORKFLOW_PATTERN = r"^\.github/workflows/release-v0\.(?:2\.2|3\.0)\.yml$"
SUPPORTED_RELEASE_BUNDLE_PATTERN = (
    r"^mercury-v0\.(?:2\.2|3\.0)-release-artifacts-"
    r"[1-9][0-9]*-attempt-[1-9][0-9]*$"
)

_COMMON_FUNCTIONS = (
    "public.jsonb_has_forbidden_validation_key(jsonb)",
    "public.jsonb_has_forbidden_validation_value(jsonb)",
    "public.jsonb_is_safe_validation_response_shape(jsonb)",
    (
        "public.match_knowledge_chunks("
        "text,vector,integer,text,text,text,text,text,date,text,text,text,text,text)"
    ),
    "public.reject_validation_evidence_mutation()",
    "public.resolve_erp_action_validation_batch(jsonb,timestamp with time zone)",
    "public.validation_label_kind(text)",
    "public.validation_text_has_forbidden_value(text)",
    "public.validation_text_has_label_assignment_contamination(text)",
    "public.validation_text_has_safe_label_assignment(text)",
)

_V022_TOOLS = frozenset(
    {
        "check_flow_syntax",
        "connector_capabilities",
        "connector_status",
        "create_public_workspace",
        "flow_cheat_sheet",
        "get_document",
        "get_public_workspace",
        "inspect_flow_files",
        "list_connectors",
        "list_workspace_flows",
        "retrieve_context_pack",
        "retrieve_workspace_context_pack",
        "run_accounting_skill",
        "run_flow",
        "run_flow_files",
        "run_mercury_flow",
        "run_workspace_flow",
        "save_workspace_flow",
        "search_knowledge",
        "start_connector_setup",
    }
)

_V030_TOOLS = frozenset(
    {
        "check_flow_syntax",
        "connector_capabilities",
        "connector_status",
        "create_public_workspace",
        "flow_cheat_sheet",
        "get_accounting_skill_schema",
        "get_connector_setup",
        "get_document",
        "get_public_workspace",
        "inspect_flow_files",
        "link_connector_profile",
        "list_accounting_skills",
        "list_connectors",
        "list_workspace_flows",
        "retrieve_context_pack",
        "retrieve_workspace_context_pack",
        "run_accounting_skill",
        "run_flow_files",
        "run_inline_flow",
        "run_workspace_flow",
        "save_workspace_flow",
        "search_knowledge",
        "unlink_connector_profile",
        "validate_connector_connection",
    }
)


class ReleaseProfileError(ValueError):
    """The requested release is not an exact supported control profile."""


@dataclass(frozen=True, slots=True)
class ReleaseProfile:
    version: str
    tag: str
    staging_tag_prefix: str
    release_workflow_path: str
    migration_id: str
    hosted_tool_names: frozenset[str]
    supabase_function_signatures: tuple[str, ...]
    required_approving_review_count: int
    prevent_self_review: bool
    catalog_action_count: int = 254
    supabase_table_count: int = 17

    @property
    def hosted_tool_count(self) -> int:
        return len(self.hosted_tool_names)

    @property
    def supabase_function_count(self) -> int:
        return len(self.supabase_function_signatures)

    @property
    def release_name(self) -> str:
        return f"Mercury v{self.version}"

    @property
    def ruleset_name(self) -> str:
        return f"Mercury v{self.version} immutable release tag"

    def staging_ref(self, reviewed_sha: str) -> str:
        return f"{self.staging_tag_prefix}{reviewed_sha[:12]}"

    def release_bundle_name(self, run_id: int, run_attempt: int) -> str:
        return f"mercury-v{self.version}-release-artifacts-{run_id}-attempt-{run_attempt}"

    def provider_expectations(self) -> dict[str, object]:
        return {
            "flowaccount_environment": "sandbox",
            "hosted_tool_count": self.hosted_tool_count,
            "catalog_action_count": self.catalog_action_count,
            "supabase_table_count": self.supabase_table_count,
            "supabase_function_count": self.supabase_function_count,
        }


_PROFILES = {
    "0.2.2": ReleaseProfile(
        version="0.2.2",
        tag="v0.2.2",
        staging_tag_prefix="v0.2.2-rc.",
        release_workflow_path=".github/workflows/release-v0.2.2.yml",
        migration_id="20260716100000",
        hosted_tool_names=_V022_TOOLS,
        supabase_function_signatures=_COMMON_FUNCTIONS,
        required_approving_review_count=1,
        prevent_self_review=True,
    ),
    "0.3.0": ReleaseProfile(
        version="0.3.0",
        tag="v0.3.0",
        staging_tag_prefix="v0.3.0-rc.",
        release_workflow_path=".github/workflows/release-v0.3.0.yml",
        migration_id="20260719120000",
        hosted_tool_names=_V030_TOOLS,
        supabase_function_signatures=(
            *_COMMON_FUNCTIONS[:4],
            "public.mercury_capability_states_are_safe(jsonb)",
            *_COMMON_FUNCTIONS[4:],
        ),
        required_approving_review_count=0,
        prevent_self_review=False,
    ),
}


def release_profile(version: object) -> ReleaseProfile:
    if not isinstance(version, str):
        raise ReleaseProfileError("release_version_invalid")
    try:
        return _PROFILES[version]
    except KeyError as exc:
        raise ReleaseProfileError("release_version_invalid") from exc


def release_profile_from_policy(policy: Mapping[str, object]) -> ReleaseProfile:
    release = policy.get("release")
    if not isinstance(release, Mapping):
        raise ReleaseProfileError("release_policy_invalid")
    profile = release_profile(release.get("version"))
    if dict(release) != {"tag": profile.tag, "version": profile.version}:
        raise ReleaseProfileError("release_policy_invalid")
    return profile


def release_profile_from_staging_ref(staging_ref: object) -> ReleaseProfile:
    if not isinstance(staging_ref, str):
        raise ReleaseProfileError("release_staging_ref_invalid")
    matches = [
        profile
        for profile in _PROFILES.values()
        if staging_ref.startswith(profile.staging_tag_prefix)
    ]
    if len(matches) != 1:
        raise ReleaseProfileError("release_staging_ref_invalid")
    return matches[0]
