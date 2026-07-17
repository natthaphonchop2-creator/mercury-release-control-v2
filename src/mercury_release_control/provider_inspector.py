"""Fail-closed provider evidence validation for Mercury v0.2.2."""

from __future__ import annotations

import hashlib
import json
import re
import urllib.parse
from collections.abc import Mapping, Sequence
from typing import Any, Protocol

from pydantic import BaseModel, ConfigDict, Field, ValidationError

_SHA = re.compile(r"^[0-9a-f]{40}$")
_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_MIGRATION = re.compile(r"^[0-9]{14}$")
_PROJECT = re.compile(r"^[a-z0-9]{20}$")


class InspectionError(RuntimeError):
    """A constant-code trusted provider inspection failure."""


class _EvidenceModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)


class RenderEvidence(_EvidenceModel):
    catalog_action_count: int = Field(ge=0, le=10_000)
    commit: str = Field(pattern=r"^[0-9a-f]{40}$")
    hosted_tool_count: int = Field(ge=0, le=1_000)
    logs_scanned: bool
    status: str = Field(max_length=32)
    version: str = Field(max_length=32)


class SupabaseEvidence(_EvidenceModel):
    function_count: int = Field(ge=0, le=1_000)
    migration_id: str = Field(pattern=r"^[0-9]{14}$")
    project_ref_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    rag_identity_count: int = Field(ge=0, le=100_000)
    read_only: bool
    schema_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    table_count: int = Field(ge=0, le=1_000)


class FlowAccountEvidence(_EvidenceModel):
    environment: str = Field(max_length=32)
    read_only: bool
    status: int = Field(ge=100, le=599)


class PublicMcpEvidence(_EvidenceModel):
    catalog_action_count: int = Field(ge=0, le=10_000)
    flowaccount_citations: int = Field(ge=0, le=1_000)
    hosted_tool_count: int = Field(ge=0, le=1_000)
    peak_citations: int = Field(ge=0, le=1_000)
    status: int = Field(ge=100, le=599)
    write_tools_exposed: bool


class ProviderEvidence(_EvidenceModel):
    flowaccount: FlowAccountEvidence
    public_mcp: PublicMcpEvidence
    render: RenderEvidence
    reviewed_sha: str = Field(pattern=r"^[0-9a-f]{40}$")
    supabase: SupabaseEvidence
    version: str = Field(pattern=r"^0\.2\.2$")


class ProviderCollector(Protocol):
    def collect(
        self,
        *,
        policy: Mapping[str, object],
        environment: Mapping[str, str],
        reviewed_sha: str,
        staging: Any,
    ) -> Mapping[str, object]: ...


def inspect_providers(
    policy: Mapping[str, object],
    environment: Mapping[str, str],
    reviewed_sha: str,
    staging: Any,
    *,
    collector: ProviderCollector | None = None,
) -> ProviderEvidence:
    if (
        _SHA.fullmatch(reviewed_sha) is None
        or getattr(staging, "reviewed_sha", None) != reviewed_sha
    ):
        raise InspectionError("staging_identity_mismatch")
    release = policy.get("release")
    if not isinstance(release, dict) or release.get("version") != "0.2.2":
        raise InspectionError("provider_policy_invalid")
    if collector is None:
        from mercury_release_control.hosted_collector import HostedProviderCollector

        collector = HostedProviderCollector()
    try:
        state = collector.collect(
            policy=policy,
            environment=environment,
            reviewed_sha=reviewed_sha,
            staging=staging,
        )
    except InspectionError:
        raise
    except Exception as exc:
        raise InspectionError("provider_collection_failed") from exc
    return inspect_provider_state(state, reviewed_sha=reviewed_sha, version="0.2.2")


def inspect_provider_state(
    state: Mapping[str, object],
    *,
    reviewed_sha: str,
    version: str,
) -> ProviderEvidence:
    if _SHA.fullmatch(reviewed_sha) is None:
        raise InspectionError("reviewed_sha_invalid")
    if version != "0.2.2" or set(state) != {
        "flowaccount",
        "public_mcp",
        "render",
        "supabase",
    }:
        raise InspectionError("provider_state_invalid")
    render = _dictionary(state, "render")
    if render.get("commit") != reviewed_sha:
        raise InspectionError("render_commit_mismatch")
    if render.get("version") != version:
        raise InspectionError("render_version_mismatch")
    if render.get("status") != "live" or render.get("logs_scanned") is not True:
        raise InspectionError("render_deployment_invalid")
    if render.get("hosted_tool_count") != 20:
        raise InspectionError("render_tool_inventory_invalid")
    if render.get("catalog_action_count") != 254:
        raise InspectionError("render_catalog_inventory_invalid")

    supabase = _dictionary(state, "supabase")
    if supabase.get("read_only") is not True:
        raise InspectionError("supabase_read_only_invalid")
    if supabase.get("table_count") != 17:
        raise InspectionError("supabase_table_inventory_invalid")
    if supabase.get("function_count") != 10:
        raise InspectionError("supabase_function_inventory_invalid")
    if supabase.get("rag_identity_count") != 254:
        raise InspectionError("supabase_rag_inventory_invalid")
    if not _valid_digest(supabase.get("schema_sha256")):
        raise InspectionError("supabase_schema_invalid")
    if not _valid_digest(supabase.get("project_ref_sha256")):
        raise InspectionError("supabase_project_invalid")
    migration_id = supabase.get("migration_id")
    if not isinstance(migration_id, str) or _MIGRATION.fullmatch(migration_id) is None:
        raise InspectionError("supabase_migration_invalid")

    flowaccount = _dictionary(state, "flowaccount")
    if (
        flowaccount.get("environment") != "sandbox"
        or flowaccount.get("read_only") is not True
        or flowaccount.get("status") != 200
    ):
        raise InspectionError("flowaccount_sandbox_read_failed")

    public_mcp = _dictionary(state, "public_mcp")
    if public_mcp.get("status") != 200:
        raise InspectionError("public_mcp_unavailable")
    if public_mcp.get("hosted_tool_count") != 20:
        raise InspectionError("public_mcp_tool_inventory_invalid")
    if public_mcp.get("catalog_action_count") != 254:
        raise InspectionError("public_mcp_catalog_inventory_invalid")
    if public_mcp.get("write_tools_exposed") is not False:
        raise InspectionError("public_mcp_boundary_invalid")
    if not _positive_integer(public_mcp.get("flowaccount_citations")):
        raise InspectionError("public_mcp_flowaccount_rag_invalid")
    if not _positive_integer(public_mcp.get("peak_citations")):
        raise InspectionError("public_mcp_peak_rag_invalid")

    try:
        return ProviderEvidence.model_validate(
            {
                "flowaccount": flowaccount,
                "public_mcp": public_mcp,
                "render": render,
                "reviewed_sha": reviewed_sha,
                "supabase": supabase,
                "version": version,
            }
        )
    except ValidationError as exc:
        raise InspectionError("provider_state_invalid") from exc


def validate_database_url(database_url: str, *, project_ref: str) -> None:
    if not isinstance(database_url, str) or len(database_url) > 16 * 1024:
        raise InspectionError("database_url_invalid")
    if _PROJECT.fullmatch(project_ref) is None:
        raise InspectionError("database_identity_invalid")
    try:
        parsed = urllib.parse.urlsplit(database_url)
        query = urllib.parse.parse_qs(parsed.query, strict_parsing=True)
        port = parsed.port
    except (TypeError, ValueError) as exc:
        raise InspectionError("database_url_invalid") from exc
    direct_host = f"db.{project_ref}.supabase.co"
    pooler_suffix = ".pooler.supabase.com"
    if (
        parsed.scheme not in {"postgres", "postgresql"}
        or parsed.hostname is None
        or not (
            parsed.hostname == direct_host
            or (
                parsed.hostname.endswith(pooler_suffix)
                and parsed.username is not None
                and project_ref in parsed.username
            )
        )
        or parsed.path != "/postgres"
        or parsed.username is None
        or parsed.password is None
        or port not in {None, 5432, 6543}
    ):
        raise InspectionError("database_identity_invalid")
    if query.get("sslmode") != ["verify-full"]:
        raise InspectionError("database_tls_invalid")


def inspect_supabase_connection(
    connection: Any,
    *,
    expected_tables: Sequence[str],
    expected_functions: Mapping[str, str],
    expected_migration_id: str,
) -> dict[str, object]:
    if len(expected_tables) != 17 or len(expected_functions) != 10:
        raise InspectionError("supabase_policy_invalid")
    if getattr(getattr(connection, "info", None), "ssl_in_use", None) is not True:
        raise InspectionError("database_tls_invalid")
    cursor = connection.cursor()
    cursor.execute("BEGIN READ ONLY")
    cursor.execute("SET LOCAL statement_timeout = '15000ms'")
    cursor.execute(
        "SELECT tablename FROM pg_catalog.pg_tables WHERE schemaname = 'public' ORDER BY tablename"
    )
    tables = tuple(row[0] for row in cursor.fetchall())
    if tables != tuple(sorted(expected_tables)):
        raise InspectionError("supabase_table_inventory_invalid")
    cursor.execute(
        "SELECT p.oid::regprocedure::text, pg_get_functiondef(p.oid) "
        "FROM pg_catalog.pg_proc p "
        "JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace "
        "WHERE n.nspname = 'public' "
        "AND p.oid::regprocedure::text = ANY(%s::text[]) "
        "ORDER BY p.oid::regprocedure::text",
        (list(sorted(expected_functions)),),
    )
    functions = tuple((row[0], row[1]) for row in cursor.fetchall())
    if tuple(name for name, _definition in functions) != tuple(sorted(expected_functions)):
        raise InspectionError("supabase_function_inventory_invalid")
    for name, definition in functions:
        if _sha256(definition) != expected_functions[name]:
            raise InspectionError("supabase_function_definition_invalid")
    cursor.execute("SELECT version FROM supabase_migrations.schema_migrations ORDER BY version")
    migrations = tuple(str(row[0]) for row in cursor.fetchall())
    if not migrations or migrations[-1] != expected_migration_id:
        raise InspectionError("supabase_migration_invalid")
    cursor.execute("SELECT count(*) FROM public.erp_action_validation_knowledge")
    rows = cursor.fetchall()
    if rows != [(254,)]:
        raise InspectionError("supabase_rag_inventory_invalid")
    schema_payload = {
        "functions": [
            {"definition_sha256": _sha256(definition), "signature": name}
            for name, definition in functions
        ],
        "migration_id": expected_migration_id,
        "tables": list(tables),
    }
    return {
        "function_count": len(functions),
        "migration_id": expected_migration_id,
        "rag_identity_count": 254,
        "read_only": True,
        "schema_sha256": _sha256(json.dumps(schema_payload, separators=(",", ":"), sort_keys=True)),
        "table_count": len(tables),
    }


def _dictionary(state: Mapping[str, object], key: str) -> dict[str, object]:
    value = state.get(key)
    if not isinstance(value, dict) or len(value) > 32:
        raise InspectionError("provider_state_invalid")
    return value


def _valid_digest(value: object) -> bool:
    return isinstance(value, str) and _DIGEST.fullmatch(value) is not None


def _positive_integer(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value > 0


def _sha256(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()
