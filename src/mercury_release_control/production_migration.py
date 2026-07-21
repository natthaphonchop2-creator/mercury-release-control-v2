"""Trusted, fail-closed runner for the Mercury v0.3.0 production migration."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
from collections.abc import Sequence
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

from mercury_release_control.surface_inspector import parse_database_url

MIGRATION_VERSION = "20260719120000"
MIGRATION_NAME = "connector_neutral_profiles"
MIGRATION_CREATED_BY = "mercury-v0.3.0-release"
MIGRATION_PATH = "supabase/migrations/20260719120000_connector_neutral_profiles.sql"
EXPECTED_MIGRATION_SHA256 = "2ca702823fd17a7806ead1b829af21984ea54b676700cf443cb69b7e6161c0ca"
PRE_MIGRATION_COUNT = 12
PRE_MIGRATION_LATEST = "20260716100000"
PRE_MIGRATION_HISTORY_SHA256 = "df1a5ed4bea121d74a7c17607015d00d248c5401eedad980f1c53b3680adcb40"
POST_MIGRATION_COUNT = 13
POST_MIGRATION_HISTORY_SHA256 = "324cff822a5a4d8e4a2554fa875471dec2345676fe8768c8ffe7cff283ffe3fb"
SUPABASE_PROJECT_REF = "vbnlkqvauqwnjbxngkas"
DATABASE_ROLE = "postgres"
SUPABASE_CA_URL = (
    "https://supabase-downloads.s3-ap-southeast-1.amazonaws.com/prod/ssl/prod-ca-2021.crt"
)
SUPABASE_CA_SHA256 = "700723581420dd1ac98fd7e9ac529f0ef210eadcaf87fc868a3ad7d114c2f3b7"
ADVISORY_LOCK_ID = 3030202607191200
MAX_MIGRATION_BYTES = 1024 * 1024
TABLE_PRIVILEGE_ORDER = (
    "SELECT",
    "INSERT",
    "UPDATE",
    "DELETE",
    "TRUNCATE",
    "REFERENCES",
    "TRIGGER",
)
TABLE_PRIVILEGES = frozenset(TABLE_PRIVILEGE_ORDER)
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_COMMIT = re.compile(r"^[0-9a-f]{40}$")
_CONNECTOR_COLUMNS = (
    "capability_states",
    "company_ref",
    "connection_mode",
    "evidence_source",
    "external_server_name",
    "validated_at",
)
_PRE_CONNECTOR_COLUMNS = (
    "company_name",
    "connector_id",
    "created_at",
    "display_name",
    "environment",
    "id",
    "metadata",
    "status",
    "updated_at",
    "workspace_id",
)
_PRE_CONNECTOR_CONSTRAINTS = (
    "mercury_connector_profiles_pkey",
    "mercury_connector_profiles_workspace_id_connector_id_enviro_key",
    "mercury_connector_profiles_workspace_id_fkey",
)
POST_UNIQUE_CONSTRAINT_NAME = "mercury_connector_profiles_workspace_connector_mode_environment"
_UNIQUE_CONSTRAINT = POST_UNIQUE_CONSTRAINT_NAME
_FUNCTION_SIGNATURE = "public.mercury_capability_states_are_safe(jsonb)"


class MigrationError(RuntimeError):
    """A sanitized, constant-code production migration failure."""


@dataclass(frozen=True, slots=True)
class PreparedMigration:
    body: str
    body_sha256: str
    source_sha256: str


@dataclass(frozen=True, slots=True)
class HistorySnapshot:
    count: int
    latest: str
    sha256: str
    target_present: bool

    @classmethod
    def pre_migration(cls) -> HistorySnapshot:
        return cls(
            count=PRE_MIGRATION_COUNT,
            latest=PRE_MIGRATION_LATEST,
            sha256=PRE_MIGRATION_HISTORY_SHA256,
            target_present=False,
        )

    @classmethod
    def post_migration(cls) -> HistorySnapshot:
        return cls(
            count=POST_MIGRATION_COUNT,
            latest=MIGRATION_VERSION,
            sha256=POST_MIGRATION_HISTORY_SHA256,
            target_present=True,
        )


@dataclass(frozen=True, slots=True)
class MigrationRecord:
    version: str
    name: str
    created_by: str
    statements: tuple[str, ...]
    idempotency_key: str | None
    rollback: str | None


@dataclass(frozen=True, slots=True)
class TargetFootprint:
    connector_columns: tuple[str, ...]
    connector_constraints: tuple[str, ...]
    required_capabilities_column: bool
    safety_function: bool

    @classmethod
    def clean_pre_migration(cls) -> TargetFootprint:
        return cls(
            connector_columns=_PRE_CONNECTOR_COLUMNS,
            connector_constraints=_PRE_CONNECTOR_CONSTRAINTS,
            required_capabilities_column=False,
            safety_function=False,
        )


@dataclass(frozen=True, slots=True)
class ColumnState:
    table_name: str
    column_name: str
    data_type: str
    nullable: bool
    default: str | None


@dataclass(frozen=True, slots=True)
class SafetyFunctionState:
    language: str
    volatility: str
    security_definer: bool
    leakproof: bool
    search_path: tuple[str, ...]
    return_type: str
    service_role_execute: bool
    anon_execute: bool
    authenticated_execute: bool
    public_execute: bool


@dataclass(frozen=True, slots=True)
class TableSecurityState:
    table_name: str
    rls_enabled: bool
    service_role_privileges: frozenset[str]
    anon_privileges: frozenset[str]
    authenticated_privileges: frozenset[str]


@dataclass(frozen=True, slots=True)
class PostconditionSnapshot:
    columns: tuple[ColumnState, ...]
    unique_constraint_columns: tuple[str, ...]
    unique_constraint_validated: bool
    safety_function: SafetyFunctionState
    table_security: tuple[TableSecurityState, ...]


@dataclass(frozen=True, slots=True)
class MigrationReceipt:
    status: str
    migration_sha256: str
    migration_body_sha256: str
    migration_history_sha256: str
    reviewed_sha: str

    def as_dict(self) -> dict[str, str]:
        return {
            "migration_body_sha256": self.migration_body_sha256,
            "migration_history_sha256": self.migration_history_sha256,
            "migration_sha256": self.migration_sha256,
            "reviewed_sha": self.reviewed_sha,
            "status": self.status,
        }


class MigrationSession(Protocol):
    def begin(self) -> None: ...

    def migration_history(self) -> HistorySnapshot: ...

    def target_footprint(self) -> TargetFootprint: ...

    def apply_migration(self, body: str) -> None: ...

    def insert_migration_record(self, record: MigrationRecord) -> None: ...

    def migration_record(self, version: str) -> MigrationRecord | None: ...

    def collect_postconditions(self) -> PostconditionSnapshot: ...

    def commit(self) -> None: ...

    def rollback(self) -> None: ...


def prepare_migration_source(
    source: bytes,
    *,
    expected_sha256: str = EXPECTED_MIGRATION_SHA256,
) -> PreparedMigration:
    if (
        not isinstance(source, bytes)
        or not source
        or len(source) > MAX_MIGRATION_BYTES
        or _SHA256.fullmatch(expected_sha256) is None
    ):
        raise MigrationError("migration_source_invalid")
    source_sha256 = hashlib.sha256(source).hexdigest()
    if source_sha256 != expected_sha256:
        raise MigrationError("migration_source_hash_mismatch")
    lines = source.splitlines(keepends=True)
    if (
        len(lines) < 3
        or lines[0] != b"begin;\n"
        or lines[-1] != b"commit;\n"
        or any(line in {b"begin;\n", b"commit;\n"} for line in lines[1:-1])
    ):
        raise MigrationError("migration_wrapper_invalid")
    body_bytes = b"".join(lines[1:-1])
    if not body_bytes or b"\0" in body_bytes:
        raise MigrationError("migration_wrapper_invalid")
    try:
        body = body_bytes.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise MigrationError("migration_source_invalid") from exc
    return PreparedMigration(
        body=body,
        body_sha256=hashlib.sha256(body_bytes).hexdigest(),
        source_sha256=source_sha256,
    )


def validate_ca_certificate(
    path: Path,
    *,
    expected_sha256: str = SUPABASE_CA_SHA256,
) -> Path:
    try:
        valid = (
            isinstance(path, Path)
            and path.is_absolute()
            and not path.is_symlink()
            and path.is_file()
            and 0 < path.stat().st_size <= 1024 * 1024
            and _SHA256.fullmatch(expected_sha256) is not None
            and hashlib.sha256(path.read_bytes()).hexdigest() == expected_sha256
        )
    except OSError as exc:
        raise MigrationError("database_ca_invalid") from exc
    if not valid:
        raise MigrationError("database_ca_invalid")
    return path


def expected_postconditions() -> PostconditionSnapshot:
    columns = (
        ColumnState(
            "mercury_connector_profiles",
            "capability_states",
            "jsonb",
            False,
            "'{}'::jsonb",
        ),
        ColumnState("mercury_connector_profiles", "company_ref", "text", True, None),
        ColumnState(
            "mercury_connector_profiles",
            "connection_mode",
            "text",
            False,
            "'api_driver'::text",
        ),
        ColumnState("mercury_connector_profiles", "evidence_source", "text", True, None),
        ColumnState(
            "mercury_connector_profiles",
            "external_server_name",
            "text",
            True,
            None,
        ),
        ColumnState(
            "mercury_connector_profiles",
            "validated_at",
            "timestamp with time zone",
            True,
            None,
        ),
        ColumnState(
            "mercury_skill_catalog",
            "required_capabilities",
            "jsonb",
            False,
            "'[]'::jsonb",
        ),
    )
    safety_function = SafetyFunctionState(
        language="sql",
        volatility="immutable",
        security_definer=False,
        leakproof=False,
        search_path=("search_path=pg_catalog",),
        return_type="boolean",
        service_role_execute=True,
        anon_execute=False,
        authenticated_execute=False,
        public_execute=False,
    )
    table_security = tuple(
        TableSecurityState(
            table_name=table_name,
            rls_enabled=True,
            service_role_privileges=TABLE_PRIVILEGES,
            anon_privileges=frozenset(),
            authenticated_privileges=frozenset(),
        )
        for table_name in ("mercury_connector_profiles", "mercury_skill_catalog")
    )
    return PostconditionSnapshot(
        columns=columns,
        unique_constraint_columns=(
            "workspace_id",
            "connector_id",
            "connection_mode",
            "environment",
        ),
        unique_constraint_validated=True,
        safety_function=safety_function,
        table_security=table_security,
    )


def execute_trusted_migration(
    *,
    session: MigrationSession,
    prepared: PreparedMigration,
    reviewed_sha: str,
) -> MigrationReceipt:
    if _COMMIT.fullmatch(reviewed_sha) is None:
        raise MigrationError("reviewed_sha_invalid")
    expected_record = MigrationRecord(
        version=MIGRATION_VERSION,
        name=MIGRATION_NAME,
        created_by=MIGRATION_CREATED_BY,
        statements=(prepared.body,),
        idempotency_key=None,
        rollback=None,
    )
    try:
        session.begin()
        history = session.migration_history()
        if history == HistorySnapshot.post_migration():
            _verify_record_and_postconditions(session, expected_record)
            session.commit()
            status = "already_applied"
        else:
            if history != HistorySnapshot.pre_migration():
                raise MigrationError("migration_history_invalid")
            if session.target_footprint() != TargetFootprint.clean_pre_migration():
                raise MigrationError("migration_partial_state")
            session.apply_migration(prepared.body)
            session.insert_migration_record(expected_record)
            if session.migration_history() != HistorySnapshot.post_migration():
                raise MigrationError("migration_post_history_invalid")
            _verify_record_and_postconditions(session, expected_record)
            session.commit()
            status = "applied"
    except MigrationError:
        with suppress(Exception):
            session.rollback()
        raise
    except Exception as exc:
        with suppress(Exception):
            session.rollback()
        raise MigrationError("migration_database_failed") from exc
    return MigrationReceipt(
        status=status,
        migration_sha256=prepared.source_sha256,
        migration_body_sha256=prepared.body_sha256,
        migration_history_sha256=POST_MIGRATION_HISTORY_SHA256,
        reviewed_sha=reviewed_sha,
    )


def _verify_record_and_postconditions(
    session: MigrationSession,
    expected_record: MigrationRecord,
) -> None:
    if session.migration_record(MIGRATION_VERSION) != expected_record:
        raise MigrationError("migration_record_invalid")
    if session.collect_postconditions() != expected_postconditions():
        raise MigrationError("migration_postcondition_invalid")


class PostgresMigrationSession:
    """Small SQL adapter; orchestration remains independently unit-testable."""

    def __init__(self, connection: Any, *, expected_database: str, expected_role: str) -> None:
        self._connection = connection
        self._expected_database = expected_database
        self._expected_role = expected_role
        self._cursor: Any | None = None

    @property
    def cursor(self) -> Any:
        if self._cursor is None:
            raise MigrationError("migration_transaction_missing")
        return self._cursor

    def begin(self) -> None:
        self._cursor = self._connection.cursor()
        self.cursor.execute("BEGIN")
        self.cursor.execute("SET LOCAL lock_timeout = '5000ms'")
        self.cursor.execute("SET LOCAL statement_timeout = '120000ms'")
        self.cursor.execute("SET LOCAL idle_in_transaction_session_timeout = '180000ms'")
        self.cursor.execute("SELECT pg_advisory_xact_lock(%s)", (ADVISORY_LOCK_ID,))
        self.cursor.execute("SELECT ssl FROM pg_catalog.pg_stat_ssl WHERE pid = pg_backend_pid()")
        if self.cursor.fetchone() != (True,):
            raise MigrationError("database_tls_invalid")
        self.cursor.execute("SELECT current_database(), current_user")
        identity = self.cursor.fetchone()
        if identity != (
            self._expected_database,
            self._expected_role,
        ):
            raise MigrationError("database_identity_mismatch")

    def migration_history(self) -> HistorySnapshot:
        self.cursor.execute(
            "SELECT version::text FROM supabase_migrations.schema_migrations ORDER BY version::text"
        )
        rows = self.cursor.fetchall()
        versions = tuple(row[0] for row in rows if isinstance(row, (tuple, list)) and len(row) == 1)
        if len(versions) != len(rows) or any(
            not isinstance(item, str) or not item for item in versions
        ):
            raise MigrationError("migration_history_invalid")
        digest = hashlib.sha256(("\n".join(versions) + "\n").encode()).hexdigest()
        return HistorySnapshot(
            count=len(versions),
            latest=versions[-1] if versions else "",
            sha256=digest,
            target_present=MIGRATION_VERSION in versions,
        )

    def target_footprint(self) -> TargetFootprint:
        self.cursor.execute(
            "SELECT column_name FROM information_schema.columns "
            "WHERE table_schema = 'public' "
            "AND table_name = 'mercury_connector_profiles' "
            "ORDER BY column_name"
        )
        connector_columns = _single_text_column(self.cursor.fetchall())
        self.cursor.execute(
            "SELECT constraint_state.conname FROM pg_catalog.pg_constraint AS constraint_state "
            "JOIN pg_catalog.pg_class AS table_state "
            "ON table_state.oid = constraint_state.conrelid "
            "JOIN pg_catalog.pg_namespace AS namespace_state "
            "ON namespace_state.oid = table_state.relnamespace "
            "WHERE namespace_state.nspname = 'public' "
            "AND table_state.relname = 'mercury_connector_profiles' "
            "ORDER BY constraint_state.conname"
        )
        connector_constraints = _single_text_column(self.cursor.fetchall())
        self.cursor.execute(
            "SELECT count(*) FROM information_schema.columns "
            "WHERE table_schema = 'public' AND table_name = 'mercury_skill_catalog' "
            "AND column_name = 'required_capabilities'"
        )
        required_capabilities = _single_int(self.cursor.fetchone()) == 1
        self.cursor.execute("SELECT to_regprocedure(%s) IS NOT NULL", (_FUNCTION_SIGNATURE,))
        safety_function = _single_bool(self.cursor.fetchone())
        return TargetFootprint(
            connector_columns=connector_columns,
            connector_constraints=connector_constraints,
            required_capabilities_column=required_capabilities,
            safety_function=safety_function,
        )

    def apply_migration(self, body: str) -> None:
        self.cursor.execute(body)

    def insert_migration_record(self, record: MigrationRecord) -> None:
        self.cursor.execute(
            "INSERT INTO supabase_migrations.schema_migrations "
            "(version, name, created_by, statements, idempotency_key, rollback) "
            "VALUES (%s, %s, %s, %s::text[], %s, %s)",
            (
                record.version,
                record.name,
                record.created_by,
                list(record.statements),
                record.idempotency_key,
                record.rollback,
            ),
        )

    def migration_record(self, version: str) -> MigrationRecord | None:
        self.cursor.execute(
            "SELECT version::text, name, created_by, statements, "
            "idempotency_key::text, rollback::text "
            "FROM supabase_migrations.schema_migrations WHERE version::text = %s",
            (version,),
        )
        rows = self.cursor.fetchall()
        if len(rows) != 1 or not isinstance(rows[0], (tuple, list)) or len(rows[0]) != 6:
            return None
        row = rows[0]
        statements = row[3]
        if not isinstance(statements, (tuple, list)) or any(
            not isinstance(item, str) for item in statements
        ):
            return None
        scalar_values = (row[0], row[1], row[2], row[4], row[5])
        if any(not isinstance(item, str) for item in scalar_values[:3]) or any(
            item is not None and not isinstance(item, str) for item in scalar_values[3:]
        ):
            return None
        return MigrationRecord(
            version=row[0],
            name=row[1],
            created_by=row[2],
            statements=tuple(statements),
            idempotency_key=row[4],
            rollback=row[5],
        )

    def collect_postconditions(self) -> PostconditionSnapshot:
        columns = self._collect_columns()
        constraint_columns, constraint_validated = self._collect_unique_constraint()
        safety_function = self._collect_safety_function()
        table_security = self._collect_table_security()
        return PostconditionSnapshot(
            columns=columns,
            unique_constraint_columns=constraint_columns,
            unique_constraint_validated=constraint_validated,
            safety_function=safety_function,
            table_security=table_security,
        )

    def _collect_columns(self) -> tuple[ColumnState, ...]:
        self.cursor.execute(
            "SELECT table_name, column_name, data_type, is_nullable, column_default "
            "FROM information_schema.columns WHERE table_schema = 'public' AND "
            "((table_name = 'mercury_connector_profiles' AND column_name = ANY(%s::text[])) "
            "OR (table_name = 'mercury_skill_catalog' "
            "AND column_name = 'required_capabilities')) ORDER BY table_name, column_name",
            (list(_CONNECTOR_COLUMNS),),
        )
        rows = self.cursor.fetchall()
        try:
            return tuple(
                ColumnState(
                    table_name=row[0],
                    column_name=row[1],
                    data_type=row[2],
                    nullable=row[3] == "YES",
                    default=row[4],
                )
                for row in rows
                if isinstance(row, (tuple, list)) and len(row) == 5
            )
        except (IndexError, TypeError) as exc:
            raise MigrationError("migration_postcondition_invalid") from exc

    def _collect_unique_constraint(self) -> tuple[tuple[str, ...], bool]:
        self.cursor.execute(
            "SELECT constraint_state.convalidated, "
            "array_agg(attribute_state.attname ORDER BY key_state.ordinality) "
            "FROM pg_catalog.pg_constraint AS constraint_state "
            "JOIN pg_catalog.pg_class AS table_state "
            "ON table_state.oid = constraint_state.conrelid "
            "JOIN pg_catalog.pg_namespace AS namespace_state "
            "ON namespace_state.oid = table_state.relnamespace "
            "JOIN unnest(constraint_state.conkey) WITH ORDINALITY "
            "AS key_state(attnum, ordinality) ON true "
            "JOIN pg_catalog.pg_attribute AS attribute_state "
            "ON attribute_state.attrelid = table_state.oid "
            "AND attribute_state.attnum = key_state.attnum "
            "WHERE namespace_state.nspname = 'public' "
            "AND table_state.relname = 'mercury_connector_profiles' "
            "AND constraint_state.conname = %s AND constraint_state.contype = 'u' "
            "GROUP BY constraint_state.convalidated",
            (_UNIQUE_CONSTRAINT,),
        )
        rows = self.cursor.fetchall()
        if len(rows) != 1 or len(rows[0]) != 2 or not isinstance(rows[0][1], (tuple, list)):
            raise MigrationError("migration_postcondition_invalid")
        return tuple(rows[0][1]), rows[0][0] is True

    def _collect_safety_function(self) -> SafetyFunctionState:
        self.cursor.execute(
            "SELECT language_state.lanname, function_state.provolatile, "
            "function_state.prosecdef, function_state.proleakproof, "
            "function_state.proconfig, pg_get_function_result(function_state.oid) "
            "FROM pg_catalog.pg_proc AS function_state "
            "JOIN pg_catalog.pg_language AS language_state "
            "ON language_state.oid = function_state.prolang "
            "WHERE function_state.oid = to_regprocedure(%s)",
            (_FUNCTION_SIGNATURE,),
        )
        rows = self.cursor.fetchall()
        if len(rows) != 1 or len(rows[0]) != 6:
            raise MigrationError("migration_postcondition_invalid")
        function_row = rows[0]
        self.cursor.execute(
            "SELECT has_function_privilege('service_role', function_state.oid, 'EXECUTE'), "
            "has_function_privilege('anon', function_state.oid, 'EXECUTE'), "
            "has_function_privilege('authenticated', function_state.oid, 'EXECUTE'), "
            "EXISTS (SELECT 1 FROM "
            "aclexplode(COALESCE(function_state.proacl, "
            "acldefault('f', function_state.proowner))) AS acl_state "
            "WHERE acl_state.grantee = 0 AND acl_state.privilege_type = 'EXECUTE') "
            "FROM pg_catalog.pg_proc AS function_state "
            "WHERE function_state.oid = to_regprocedure(%s)",
            (_FUNCTION_SIGNATURE,),
        )
        privileges = self.cursor.fetchall()
        if len(privileges) != 1 or len(privileges[0]) != 4:
            raise MigrationError("migration_postcondition_invalid")
        volatility = {"i": "immutable", "s": "stable", "v": "volatile"}.get(function_row[1])
        config = function_row[4]
        if volatility is None or not isinstance(config, (tuple, list)):
            raise MigrationError("migration_postcondition_invalid")
        return SafetyFunctionState(
            language=function_row[0],
            volatility=volatility,
            security_definer=function_row[2] is True,
            leakproof=function_row[3] is True,
            search_path=tuple(config),
            return_type=function_row[5],
            service_role_execute=privileges[0][0] is True,
            anon_execute=privileges[0][1] is True,
            authenticated_execute=privileges[0][2] is True,
            public_execute=privileges[0][3] is True,
        )

    def _collect_table_security(self) -> tuple[TableSecurityState, ...]:
        privilege_expressions = ", ".join(
            f"has_table_privilege('{{role}}', table_state.oid, '{privilege}')"
            for privilege in TABLE_PRIVILEGE_ORDER
        )
        query = (
            "SELECT table_state.relname, table_state.relrowsecurity, "
            f"ARRAY[{privilege_expressions.format(role='service_role')}], "
            f"ARRAY[{privilege_expressions.format(role='anon')}], "
            f"ARRAY[{privilege_expressions.format(role='authenticated')}] "
            "FROM pg_catalog.pg_class AS table_state "
            "JOIN pg_catalog.pg_namespace AS namespace_state "
            "ON namespace_state.oid = table_state.relnamespace "
            "WHERE namespace_state.nspname = 'public' "
            "AND table_state.relname = ANY(%s::text[]) ORDER BY table_state.relname"
        )
        self.cursor.execute(
            query,
            (["mercury_connector_profiles", "mercury_skill_catalog"],),
        )
        rows = self.cursor.fetchall()
        output: list[TableSecurityState] = []
        for row in rows:
            if (
                not isinstance(row, (tuple, list))
                or len(row) != 5
                or any(not isinstance(item, (tuple, list)) for item in row[2:])
            ):
                raise MigrationError("migration_postcondition_invalid")
            output.append(
                TableSecurityState(
                    table_name=row[0],
                    rls_enabled=row[1] is True,
                    service_role_privileges=_privilege_set(row[2]),
                    anon_privileges=_privilege_set(row[3]),
                    authenticated_privileges=_privilege_set(row[4]),
                )
            )
        return tuple(output)

    def commit(self) -> None:
        self._connection.commit()

    def rollback(self) -> None:
        self._connection.rollback()


def _privilege_set(values: Sequence[object]) -> frozenset[str]:
    if len(values) != len(TABLE_PRIVILEGE_ORDER) or any(
        not isinstance(item, bool) for item in values
    ):
        raise MigrationError("migration_postcondition_invalid")
    return frozenset(
        privilege
        for privilege, enabled in zip(TABLE_PRIVILEGE_ORDER, values, strict=True)
        if enabled
    )


def _single_int(row: object) -> int:
    if (
        not isinstance(row, (tuple, list))
        or len(row) != 1
        or not isinstance(row[0], int)
        or isinstance(row[0], bool)
        or row[0] < 0
    ):
        raise MigrationError("migration_database_state_invalid")
    return row[0]


def _single_bool(row: object) -> bool:
    if not isinstance(row, (tuple, list)) or len(row) != 1 or not isinstance(row[0], bool):
        raise MigrationError("migration_database_state_invalid")
    return row[0]


def _single_text_column(rows: object) -> tuple[str, ...]:
    if not isinstance(rows, (tuple, list)):
        raise MigrationError("migration_database_state_invalid")
    output: list[str] = []
    for row in rows:
        if (
            not isinstance(row, (tuple, list))
            or len(row) != 1
            or not isinstance(row[0], str)
            or not row[0]
        ):
            raise MigrationError("migration_database_state_invalid")
        output.append(row[0])
    return tuple(output)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--migration", type=Path, required=True)
    parser.add_argument("--reviewed-sha", required=True)
    return parser


def database_identity_for_url(database_url: str) -> tuple[str, str, str]:
    plan = parse_database_url(database_url, project_ref=SUPABASE_PROJECT_REF)
    return plan.expected_database, DATABASE_ROLE, plan.user


def _connect(database_url: str, ca_path: Path) -> tuple[Any, str, str]:
    plan = parse_database_url(database_url, project_ref=SUPABASE_PROJECT_REF)
    try:
        import psycopg

        connection = psycopg.connect(
            host=plan.hostname,
            port=plan.port,
            dbname=plan.expected_database,
            user=plan.user,
            password=plan.password,
            sslmode="verify-full",
            sslrootcert=str(ca_path),
            connect_timeout=10,
            autocommit=False,
        )
    except Exception as exc:
        raise MigrationError("database_connection_failed") from exc
    return connection, plan.expected_database, DATABASE_ROLE


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    connection: Any | None = None
    try:
        if args.migration.name != Path(MIGRATION_PATH).name:
            raise MigrationError("migration_path_invalid")
        source = args.migration.read_bytes()
        prepared = prepare_migration_source(source)
        database_url = os.environ.get("SUPABASE_DB_URL", "")
        ca_value = os.environ.get("PGSSLROOTCERT", "")
        if not database_url:
            raise MigrationError("database_url_missing")
        ca_path = validate_ca_certificate(Path(ca_value))
        connection, expected_database, expected_role = _connect(database_url, ca_path)
        receipt = execute_trusted_migration(
            session=PostgresMigrationSession(
                connection,
                expected_database=expected_database,
                expected_role=expected_role,
            ),
            prepared=prepared,
            reviewed_sha=args.reviewed_sha,
        )
    except MigrationError as exc:
        print(json.dumps({"error": str(exc), "status": "error"}, sort_keys=True), file=sys.stderr)
        return 1
    except (OSError, ValueError):
        print(
            json.dumps({"error": "migration_input_invalid", "status": "error"}, sort_keys=True),
            file=sys.stderr,
        )
        return 1
    except Exception:
        print(
            json.dumps({"error": "migration_failed", "status": "error"}, sort_keys=True),
            file=sys.stderr,
        )
        return 1
    finally:
        if connection is not None:
            with suppress(Exception):
                connection.close()
    print(json.dumps(receipt.as_dict(), separators=(",", ":"), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
