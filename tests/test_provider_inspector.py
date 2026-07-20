from __future__ import annotations

import copy
import hashlib
from types import SimpleNamespace

import pytest

from mercury_release_control.provider_inspector import (
    InspectionError,
    inspect_provider_state,
    inspect_providers,
    inspect_supabase_connection,
    validate_database_url,
)

REVIEWED_SHA = "a" * 40


@pytest.fixture
def valid_provider_state() -> dict[str, object]:
    return {
        "render": {
            "catalog_action_count": 254,
            "commit": REVIEWED_SHA,
            "hosted_tool_count": 24,
            "logs_scanned": True,
            "status": "live",
            "version": "0.3.0",
        },
        "supabase": {
            "function_count": 11,
            "migration_id": "20260719120000",
            "project_ref_sha256": hashlib.sha256(b"vbnlkqvauqwnjbxngkas").hexdigest(),
            "rag_identity_count": 254,
            "read_only": True,
            "schema_sha256": "1" * 64,
            "table_count": 17,
        },
        "flowaccount": {
            "environment": "sandbox",
            "read_only": True,
            "status": 200,
        },
        "public_mcp": {
            "catalog_action_count": 254,
            "flowaccount_citations": 1,
            "hosted_tool_count": 24,
            "peak_citations": 1,
            "status": 200,
            "write_tools_exposed": False,
        },
    }


@pytest.mark.parametrize(
    ("mutation", "code"),
    [
        (lambda state: state["render"].update(commit="b" * 40), "render_commit_mismatch"),
        (lambda state: state["render"].update(version="0.2.1"), "render_version_mismatch"),
        (
            lambda state: state["render"].update(hosted_tool_count=19),
            "render_tool_inventory_invalid",
        ),
        (
            lambda state: state["supabase"].update(table_count=16),
            "supabase_table_inventory_invalid",
        ),
        (
            lambda state: state["flowaccount"].update(status=500),
            "flowaccount_sandbox_read_failed",
        ),
    ],
)
def test_provider_inspector_fails_closed(
    mutation,
    code: str,
    valid_provider_state: dict[str, object],
) -> None:
    state = copy.deepcopy(valid_provider_state)
    mutation(state)
    with pytest.raises(InspectionError, match=f"^{code}$"):
        inspect_provider_state(state, reviewed_sha=REVIEWED_SHA, version="0.3.0")


def test_provider_evidence_is_bounded_and_sanitized(
    valid_provider_state: dict[str, object],
) -> None:
    evidence = inspect_provider_state(
        valid_provider_state,
        reviewed_sha=REVIEWED_SHA,
        version="0.3.0",
    )
    encoded = evidence.model_dump_json()

    assert evidence.render.hosted_tool_count == 24
    assert evidence.public_mcp.catalog_action_count == 254
    for forbidden in ("client_secret", "access_token", "@", "/Users/"):
        assert forbidden not in encoded


def test_inspect_providers_binds_collector_to_staging_identity(
    valid_provider_state: dict[str, object],
) -> None:
    calls: list[tuple[dict[str, object], dict[str, str], str, str]] = []

    class Collector:
        def collect(self, *, policy, environment, reviewed_sha, staging):
            calls.append((policy, environment, reviewed_sha, staging.reviewed_sha))
            return valid_provider_state

    staging = SimpleNamespace(reviewed_sha=REVIEWED_SHA)
    evidence = inspect_providers(
        policy={"release": {"version": "0.3.0"}},
        environment={"SAFE": "value"},
        reviewed_sha=REVIEWED_SHA,
        staging=staging,
        collector=Collector(),
    )

    assert evidence.reviewed_sha == REVIEWED_SHA
    assert calls == [
        (
            {"release": {"version": "0.3.0"}},
            {"SAFE": "value"},
            REVIEWED_SHA,
            REVIEWED_SHA,
        )
    ]


def test_database_url_requires_verify_full_without_echoing_password() -> None:
    secret = "never-print-this"
    url = (
        "postgresql://postgres:"
        f"{secret}@db.vbnlkqvauqwnjbxngkas.supabase.co/postgres?sslmode=require"
    )

    with pytest.raises(InspectionError, match="^database_tls_invalid$") as raised:
        validate_database_url(url, project_ref="vbnlkqvauqwnjbxngkas")

    assert secret not in str(raised.value)


def test_supabase_inspection_starts_read_only_and_requires_exact_inventory() -> None:
    tables = [f"table_{index:02d}" for index in range(17)]
    definitions = {
        f"public.function_{index}()": f"definition:public.function_{index}()" for index in range(11)
    }
    functions = {
        name: hashlib.sha256(definition.encode()).hexdigest()
        for name, definition in definitions.items()
    }
    calls: list[tuple[str, tuple[object, ...]]] = []

    class Cursor:
        last = ""

        def execute(self, query: str, parameters: tuple[object, ...] = ()) -> None:
            calls.append((query, parameters))
            self.last = query

        def fetchall(self):
            if "pg_catalog.pg_tables" in self.last:
                return [(name,) for name in tables]
            if "pg_get_functiondef" in self.last:
                return sorted(definitions.items())
            if "schema_migrations" in self.last:
                return [("20260719120000",)]
            if "erp_action_validation_knowledge" in self.last:
                return [(254,)]
            raise AssertionError(self.last)

    class Connection:
        info = SimpleNamespace(ssl_in_use=True)

        def cursor(self) -> Cursor:
            return Cursor()

    observed = inspect_supabase_connection(
        Connection(),
        expected_tables=tables,
        expected_functions=functions,
        expected_migration_id="20260719120000",
    )

    assert calls[0][0] == "BEGIN READ ONLY"
    assert observed["table_count"] == 17
    assert observed["function_count"] == 11
    assert observed["rag_identity_count"] == 254


def test_supabase_inspection_rejects_function_definition_hash_drift() -> None:
    tables = [f"table_{index:02d}" for index in range(17)]
    functions = {f"public.function_{index}()": "0" * 64 for index in range(11)}

    class Cursor:
        last = ""

        def execute(self, query: str, parameters: tuple[object, ...] = ()) -> None:
            self.last = query

        def fetchall(self):
            if "pg_catalog.pg_tables" in self.last:
                return [(name,) for name in tables]
            if "pg_get_functiondef" in self.last:
                return [(name, f"drifted:{name}") for name in sorted(functions)]
            raise AssertionError(self.last)

    class Connection:
        info = SimpleNamespace(ssl_in_use=True)

        def cursor(self) -> Cursor:
            return Cursor()

    with pytest.raises(InspectionError, match="^supabase_function_definition_invalid$"):
        inspect_supabase_connection(
            Connection(),
            expected_tables=tables,
            expected_functions=functions,
            expected_migration_id="20260719120000",
        )
