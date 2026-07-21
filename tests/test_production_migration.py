from __future__ import annotations

import hashlib
import importlib.util
import json
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest

import mercury_release_control.production_migration as migration


def test_production_migration_runner_is_an_independent_module() -> None:
    assert importlib.util.find_spec("mercury_release_control.production_migration") is not None


def test_production_migration_runner_exposes_a_narrow_reviewable_interface() -> None:
    assert {
        "MigrationError",
        "MigrationRecord",
        "PostconditionSnapshot",
        "TargetFootprint",
        "execute_trusted_migration",
        "expected_postconditions",
        "prepare_migration_source",
        "validate_ca_certificate",
    }.issubset(vars(migration))


def _source(body: bytes = b"\nselect 1;\n\n") -> bytes:
    return b"begin;\n" + body + b"commit;\n"


def _prepared() -> object:
    source = _source()
    return migration.prepare_migration_source(
        source,
        expected_sha256=hashlib.sha256(source).hexdigest(),
    )


class FakeSession:
    def __init__(
        self,
        *,
        history: object,
        footprint: object | None = None,
        postconditions: object | None = None,
        record: object | None = None,
    ) -> None:
        self.current_history = history
        self.footprint = footprint or migration.TargetFootprint.clean_pre_migration()
        self.current_postconditions = postconditions or migration.expected_postconditions()
        self.record = record
        self.events: list[str] = []
        self.applied_body: str | None = None
        self.inserted_record: object | None = None

    def begin(self) -> None:
        self.events.append("begin")

    def migration_history(self) -> object:
        self.events.append("history")
        return self.current_history

    def target_footprint(self) -> object:
        self.events.append("footprint")
        return self.footprint

    def apply_migration(self, body: str) -> None:
        self.events.append("apply")
        self.applied_body = body

    def insert_migration_record(self, record: object) -> None:
        self.events.append("insert")
        self.inserted_record = record
        self.record = record
        self.current_history = migration.HistorySnapshot.post_migration()

    def migration_record(self, version: str) -> object | None:
        self.events.append("record")
        assert version == migration.MIGRATION_VERSION
        return self.record

    def collect_postconditions(self) -> object:
        self.events.append("postconditions")
        return self.current_postconditions

    def commit(self) -> None:
        self.events.append("commit")

    def rollback(self) -> None:
        self.events.append("rollback")


def test_prepare_migration_source_hashes_then_removes_only_exact_outer_wrapper() -> None:
    source = _source()

    prepared = migration.prepare_migration_source(
        source,
        expected_sha256=hashlib.sha256(source).hexdigest(),
    )

    assert prepared.body == "\nselect 1;\n\n"
    assert prepared.source_sha256 == hashlib.sha256(source).hexdigest()
    assert prepared.body_sha256 == hashlib.sha256(prepared.body.encode()).hexdigest()


@pytest.mark.parametrize(
    "source",
    [
        b"BEGIN;\n\nselect 1;\n\ncommit;\n",
        b"begin;\n\nselect 1;\ncommit;\n\ncommit;\n",
        b"begin;\r\n\r\nselect 1;\r\n\r\ncommit;\r\n",
        b"begin;\n\nselect 1;\n",
    ],
)
def test_prepare_migration_source_rejects_non_exact_transaction_wrapper(source: bytes) -> None:
    with pytest.raises(migration.MigrationError, match="^migration_wrapper_invalid$"):
        migration.prepare_migration_source(
            source,
            expected_sha256=hashlib.sha256(source).hexdigest(),
        )


def test_prepare_migration_source_rejects_hash_mismatch_before_parsing() -> None:
    with pytest.raises(migration.MigrationError, match="^migration_source_hash_mismatch$"):
        migration.prepare_migration_source(_source(), expected_sha256="0" * 64)


def test_happy_path_applies_body_and_history_record_in_one_transaction() -> None:
    prepared = _prepared()
    session = FakeSession(history=migration.HistorySnapshot.pre_migration())

    receipt = migration.execute_trusted_migration(
        session=session,
        prepared=prepared,
        reviewed_sha="a" * 40,
    )

    assert receipt.status == "applied"
    assert session.applied_body == prepared.body
    assert session.inserted_record == migration.MigrationRecord(
        version=migration.MIGRATION_VERSION,
        name="connector_neutral_profiles",
        created_by="mercury-v0.3.0-release",
        statements=(prepared.body,),
        idempotency_key=None,
        rollback=None,
    )
    assert session.events == [
        "begin",
        "history",
        "footprint",
        "apply",
        "insert",
        "history",
        "record",
        "postconditions",
        "commit",
    ]


def test_history_contract_binds_exact_pre_and_post_digests() -> None:
    production_versions = (
        "20260709225539",
        "20260710055630",
        "20260710055639",
        "20260710055815",
        "20260711144412",
        "20260713014321",
        "20260713100000",
        "20260713101000",
        "20260713102000",
        "20260714120000",
        "20260715100000",
        "20260716100000",
    )
    pre_digest = hashlib.sha256(("\n".join(production_versions) + "\n").encode()).hexdigest()
    post_digest = hashlib.sha256(
        ("\n".join((*production_versions, migration.MIGRATION_VERSION)) + "\n").encode()
    ).hexdigest()

    assert migration.HistorySnapshot.pre_migration() == migration.HistorySnapshot(
        count=12,
        latest="20260716100000",
        sha256=pre_digest,
        target_present=False,
    )
    assert migration.HistorySnapshot.post_migration() == migration.HistorySnapshot(
        count=13,
        latest="20260719120000",
        sha256=post_digest,
        target_present=True,
    )


def test_history_mismatch_fails_closed_before_schema_mutation() -> None:
    session = FakeSession(
        history=migration.HistorySnapshot(
            count=12,
            latest="20260716100000",
            sha256="0" * 64,
            target_present=False,
        )
    )

    with pytest.raises(migration.MigrationError, match="^migration_history_invalid$"):
        migration.execute_trusted_migration(
            session=session,
            prepared=_prepared(),
            reviewed_sha="a" * 40,
        )

    assert "apply" not in session.events
    assert session.events[-1] == "rollback"


def test_partial_target_schema_fails_closed_before_schema_mutation() -> None:
    clean = migration.TargetFootprint.clean_pre_migration()
    session = FakeSession(
        history=migration.HistorySnapshot.pre_migration(),
        footprint=replace(
            clean,
            connector_columns=(*clean.connector_columns, "connection_mode"),
        ),
    )

    with pytest.raises(migration.MigrationError, match="^migration_partial_state$"):
        migration.execute_trusted_migration(
            session=session,
            prepared=_prepared(),
            reviewed_sha="a" * 40,
        )

    assert "apply" not in session.events
    assert session.events[-1] == "rollback"


def test_clean_pre_migration_footprint_is_exact_live_sanitized_state() -> None:
    footprint = migration.TargetFootprint.clean_pre_migration()

    assert footprint.connector_columns == (
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
    assert footprint.connector_constraints == (
        "mercury_connector_profiles_pkey",
        "mercury_connector_profiles_workspace_id_connector_id_enviro_key",
        "mercury_connector_profiles_workspace_id_fkey",
    )
    assert footprint.required_capabilities_column is False
    assert footprint.safety_function is False


def test_postcondition_failure_rolls_back_applied_body_and_history_insert() -> None:
    drifted = replace(
        migration.expected_postconditions(),
        unique_constraint_columns=("workspace_id", "connector_id"),
    )
    session = FakeSession(
        history=migration.HistorySnapshot.pre_migration(),
        postconditions=drifted,
    )

    with pytest.raises(migration.MigrationError, match="^migration_postcondition_invalid$"):
        migration.execute_trusted_migration(
            session=session,
            prepared=_prepared(),
            reviewed_sha="a" * 40,
        )

    assert "apply" in session.events
    assert "insert" in session.events
    assert "commit" not in session.events
    assert session.events[-1] == "rollback"


def test_safe_idempotent_rerun_requires_exact_record_and_all_postconditions() -> None:
    prepared = _prepared()
    record = migration.MigrationRecord(
        version=migration.MIGRATION_VERSION,
        name="connector_neutral_profiles",
        created_by="mercury-v0.3.0-release",
        statements=(prepared.body,),
        idempotency_key=None,
        rollback=None,
    )
    session = FakeSession(
        history=migration.HistorySnapshot.post_migration(),
        record=record,
    )

    receipt = migration.execute_trusted_migration(
        session=session,
        prepared=prepared,
        reviewed_sha="b" * 40,
    )

    assert receipt.status == "already_applied"
    assert "apply" not in session.events
    assert "insert" not in session.events
    assert session.events[-1] == "commit"


def test_idempotent_rerun_rejects_unknown_migration_record() -> None:
    prepared = _prepared()
    session = FakeSession(
        history=migration.HistorySnapshot.post_migration(),
        record=migration.MigrationRecord(
            version=migration.MIGRATION_VERSION,
            name="unknown",
            created_by="unknown",
            statements=(prepared.body,),
            idempotency_key=None,
            rollback=None,
        ),
    )

    with pytest.raises(migration.MigrationError, match="^migration_record_invalid$"):
        migration.execute_trusted_migration(
            session=session,
            prepared=prepared,
            reviewed_sha="a" * 40,
        )

    assert session.events[-1] == "rollback"


def test_expected_postconditions_bind_columns_function_constraint_rls_and_privileges() -> None:
    snapshot = migration.expected_postconditions()
    columns = {(item.table_name, item.column_name): item for item in snapshot.columns}

    assert set(columns) == {
        ("mercury_connector_profiles", "capability_states"),
        ("mercury_connector_profiles", "company_ref"),
        ("mercury_connector_profiles", "connection_mode"),
        ("mercury_connector_profiles", "evidence_source"),
        ("mercury_connector_profiles", "external_server_name"),
        ("mercury_connector_profiles", "validated_at"),
        ("mercury_skill_catalog", "required_capabilities"),
    }
    assert columns[("mercury_connector_profiles", "connection_mode")].default == (
        "'api_driver'::text"
    )
    assert columns[("mercury_connector_profiles", "capability_states")].nullable is False
    assert columns[("mercury_skill_catalog", "required_capabilities")].default == "'[]'::jsonb"
    assert snapshot.unique_constraint_columns == (
        "workspace_id",
        "connector_id",
        "connection_mode",
        "environment",
    )
    assert migration.POST_UNIQUE_CONSTRAINT_NAME == (
        "mercury_connector_profiles_workspace_connector_mode_environment"
    )
    assert len(migration.POST_UNIQUE_CONSTRAINT_NAME) == 63
    assert snapshot.unique_constraint_validated is True
    assert snapshot.safety_function.language == "sql"
    assert snapshot.safety_function.volatility == "immutable"
    assert snapshot.safety_function.security_definer is False
    assert snapshot.safety_function.leakproof is False
    assert snapshot.safety_function.search_path == ("search_path=pg_catalog",)
    assert snapshot.safety_function.service_role_execute is True
    assert snapshot.safety_function.public_execute is False
    assert snapshot.safety_function.anon_execute is False
    assert snapshot.safety_function.authenticated_execute is False
    for table in snapshot.table_security:
        assert table.rls_enabled is True
        assert table.service_role_privileges == migration.TABLE_PRIVILEGES
        assert table.anon_privileges == frozenset()
        assert table.authenticated_privileges == frozenset()


def test_receipt_contains_only_status_and_approved_hashes() -> None:
    receipt = migration.execute_trusted_migration(
        session=FakeSession(history=migration.HistorySnapshot.pre_migration()),
        prepared=_prepared(),
        reviewed_sha="c" * 40,
    )

    assert set(receipt.as_dict()) == {
        "migration_body_sha256",
        "migration_history_sha256",
        "migration_sha256",
        "reviewed_sha",
        "status",
    }
    assert "select" not in str(receipt.as_dict()).casefold()


def test_ca_certificate_is_absolute_regular_not_symlinked_and_checksum_pinned(
    tmp_path: Path,
) -> None:
    ca = tmp_path / "prod-ca-2021.crt"
    ca.write_bytes(b"trusted-ca")
    digest = hashlib.sha256(ca.read_bytes()).hexdigest()

    assert migration.validate_ca_certificate(ca, expected_sha256=digest) == ca

    link = tmp_path / "linked.crt"
    link.symlink_to(ca)
    with pytest.raises(migration.MigrationError, match="^database_ca_invalid$"):
        migration.validate_ca_certificate(link, expected_sha256=digest)
    with pytest.raises(migration.MigrationError, match="^database_ca_invalid$"):
        migration.validate_ca_certificate(ca, expected_sha256="0" * 64)


def test_shared_pooler_url_identity_is_separate_from_resolved_database_role() -> None:
    database, database_role, url_user = migration.database_identity_for_url(
        "postgresql://postgres.vbnlkqvauqwnjbxngkas:secret@"
        "aws-1-ap-northeast-2.pooler.supabase.com:5432/postgres?sslmode=verify-full"
    )

    assert database == "postgres"
    assert database_role == "postgres"
    assert url_user == "postgres.vbnlkqvauqwnjbxngkas"


def test_connect_requires_libpq_to_confirm_client_tls(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    import psycopg

    connection = SimpleNamespace(pgconn=SimpleNamespace(ssl_in_use=True))
    observed: dict[str, object] = {}

    def connect(**kwargs: object) -> object:
        observed.update(kwargs)
        return connection

    monkeypatch.setattr(psycopg, "connect", connect)
    ca = tmp_path / "prod-ca-2021.crt"

    result, database, role = migration._connect(
        "postgresql://postgres.vbnlkqvauqwnjbxngkas:secret@"
        "aws-1-ap-northeast-2.pooler.supabase.com:5432/postgres?sslmode=verify-full",
        ca,
    )

    assert result is connection
    assert database == "postgres"
    assert role == "postgres"
    assert observed["sslmode"] == "verify-full"
    assert observed["sslrootcert"] == str(ca)


def test_connect_rejects_and_closes_when_libpq_reports_no_client_tls(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    import psycopg

    class Connection:
        pgconn = SimpleNamespace(ssl_in_use=False)
        closed = False

        def close(self) -> None:
            self.closed = True

    connection = Connection()
    monkeypatch.setattr(psycopg, "connect", lambda **_kwargs: connection)

    with pytest.raises(migration.MigrationError, match="^database_tls_invalid$"):
        migration._connect(
            "postgresql://postgres.vbnlkqvauqwnjbxngkas:secret@"
            "aws-1-ap-northeast-2.pooler.supabase.com:5432/postgres?sslmode=verify-full",
            tmp_path / "prod-ca-2021.crt",
        )

    assert connection.closed is True


def test_postgres_session_starts_one_bounded_locked_transaction_and_checks_identity() -> None:
    calls: list[tuple[str, tuple[object, ...]]] = []

    class Cursor:
        last = ""

        def execute(self, query: str, parameters: tuple[object, ...] = ()) -> None:
            calls.append((query, parameters))
            self.last = query

        def fetchone(self) -> tuple[object, ...]:
            assert "current_database" in self.last
            assert "session_user" not in self.last
            return ("postgres", "postgres")

    class Connection:
        def cursor(self) -> Cursor:
            return Cursor()

        def commit(self) -> None:
            calls.append(("COMMIT_API", ()))

        def rollback(self) -> None:
            calls.append(("ROLLBACK_API", ()))

    session = migration.PostgresMigrationSession(
        Connection(),
        expected_database="postgres",
        expected_role="postgres",
    )

    session.begin()
    session.rollback()

    queries = [query for query, _parameters in calls]
    assert queries.count("BEGIN") == 1
    assert any("SET LOCAL lock_timeout" in query for query in queries)
    assert any("SET LOCAL statement_timeout" in query for query in queries)
    assert any("pg_advisory_xact_lock" in query for query in queries)
    assert not any("pg_stat_ssl" in query for query in queries)
    assert queries.index("BEGIN") < next(
        index for index, query in enumerate(queries) if "pg_advisory_xact_lock" in query
    )
    assert calls[-1][0] == "ROLLBACK_API"


def test_postgres_session_reads_exact_one_element_migration_record() -> None:
    body = "\nselect 1;\n\n"

    class Cursor:
        def execute(self, query: str, parameters: tuple[object, ...] = ()) -> None:
            assert "schema_migrations" in query
            assert parameters == (migration.MIGRATION_VERSION,)

        def fetchall(self) -> list[tuple[object, ...]]:
            return [
                (
                    migration.MIGRATION_VERSION,
                    "connector_neutral_profiles",
                    "mercury-v0.3.0-release",
                    [body],
                    None,
                    None,
                )
            ]

    class Connection:
        def cursor(self) -> Cursor:
            return Cursor()

    session = migration.PostgresMigrationSession(
        Connection(),
        expected_database="postgres",
        expected_role="postgres",
    )
    session._cursor = Cursor()

    assert session.migration_record(migration.MIGRATION_VERSION) == migration.MigrationRecord(
        version=migration.MIGRATION_VERSION,
        name="connector_neutral_profiles",
        created_by="mercury-v0.3.0-release",
        statements=(body,),
        idempotency_key=None,
        rollback=None,
    )


def test_postgres_session_normalizes_exact_postcondition_snapshot() -> None:
    expected = migration.expected_postconditions()

    class Cursor:
        last = ""

        def execute(self, query: str, parameters: tuple[object, ...] = ()) -> None:
            self.last = query

        def fetchall(self) -> list[tuple[object, ...]]:
            if "information_schema.columns" in self.last:
                return [
                    (
                        column.table_name,
                        column.column_name,
                        column.data_type,
                        "YES" if column.nullable else "NO",
                        column.default,
                    )
                    for column in expected.columns
                ]
            if "array_agg" in self.last:
                return [(True, list(expected.unique_constraint_columns))]
            if "language_state.lanname" in self.last:
                return [("sql", "i", False, False, ["search_path=pg_catalog"], "boolean")]
            if "has_function_privilege" in self.last:
                return [(True, False, False, False)]
            if "table_state.relrowsecurity" in self.last:
                return [
                    (table.table_name, True, [True] * 7, [False] * 7, [False] * 7)
                    for table in expected.table_security
                ]
            raise AssertionError(self.last)

    class Connection:
        def cursor(self) -> Cursor:
            return Cursor()

    session = migration.PostgresMigrationSession(
        Connection(),
        expected_database="postgres",
        expected_role="postgres",
    )
    session._cursor = Cursor()

    assert session.collect_postconditions() == expected


def test_cli_failure_output_never_contains_database_secret_or_sql(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    migration_file = tmp_path / "20260719120000_connector_neutral_profiles.sql"
    migration_file.write_bytes(_source())
    ca = tmp_path / "prod-ca-2021.crt"
    ca.write_bytes(b"ca")
    secret = "never-print-this-password"
    monkeypatch.setenv(
        "SUPABASE_DB_URL",
        "postgresql://postgres.vbnlkqvauqwnjbxngkas:"
        f"{secret}@aws-1-ap-northeast-2.pooler.supabase.com:5432/"
        "postgres?sslmode=verify-full",
    )
    monkeypatch.setenv("PGSSLROOTCERT", str(ca))
    prepared = _prepared()
    monkeypatch.setattr(migration, "prepare_migration_source", lambda _source: prepared)
    monkeypatch.setattr(migration, "validate_ca_certificate", lambda _path: ca)

    def fail_connection(_database_url: str, _ca_path: Path) -> object:
        raise migration.MigrationError("database_connection_failed")

    monkeypatch.setattr(migration, "_connect", fail_connection)

    status = migration.main(["--migration", str(migration_file), "--reviewed-sha", "a" * 40])
    captured = capsys.readouterr()

    assert status == 1
    assert secret not in captured.err
    assert "select 1" not in captured.err.casefold()
    assert captured.out == ""
    assert json.loads(captured.err) == {
        "error": "database_connection_failed",
        "status": "error",
    }
