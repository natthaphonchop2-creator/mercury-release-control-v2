from __future__ import annotations

import hashlib
import json
import tarfile
from pathlib import Path
from unittest.mock import create_autospec

import pytest

from mercury_release_control import surface_inspector as inspector
from mercury_release_control.surface_inspector import (
    InspectionError,
    _render_log_url,
    _render_status_endpoint,
    validate_environment,
    validate_policy,
)

ROOT = Path(__file__).resolve().parents[1]


def test_github_download_redirect_hosts_are_exact_and_include_actions_logs() -> None:
    assert frozenset(
        {
            "github-production-release-asset-2e65be.s3.amazonaws.com",
            "github-releases.githubusercontent.com",
            "objects.githubusercontent.com",
            "pipelines.actions.githubusercontent.com",
            "results-receiver.actions.githubusercontent.com",
        }
    ) == inspector._GITHUB_DOWNLOAD_HOSTS


def _configured_policy() -> dict[str, object]:
    policy = json.loads((ROOT / "policy-v0.3.0.json").read_text(encoding="utf-8"))
    policy["bootstrap_state"] = "configured"
    policy["repository_id"] = 1300000000
    return policy


def test_surface_inspector_accepts_only_configured_v030_policy() -> None:
    assert validate_policy(_configured_policy())["release"] == {
        "tag": "v0.3.0",
        "version": "0.3.0",
    }

    policy = _configured_policy()
    policy["release"] = {"tag": "v0.2.1", "version": "0.2.1"}
    with pytest.raises(InspectionError, match="^policy_release_boundary_invalid$"):
        validate_policy(policy)


def test_surface_inspector_binds_render_to_v030_and_reviewed_commit() -> None:
    endpoint = _render_status_endpoint(
        {
            "deployment_commit": "a" * 40,
            "mcp_endpoint": "https://mercury.example/mcp",
            "status": "ok",
            "version": "0.3.0",
        },
        base_url="https://mercury.example",
        reviewed_sha="a" * 40,
        version="0.3.0",
    )
    assert endpoint == "https://mercury.example/mcp"

    with pytest.raises(InspectionError, match="^render_status_invalid$"):
        _render_status_endpoint(
            {
                "deployment_commit": "a" * 40,
                "mcp_endpoint": "https://mercury.example/mcp",
                "status": "ok",
                "version": "0.2.1",
            },
            base_url="https://mercury.example",
            reviewed_sha="a" * 40,
            version="0.3.0",
        )


def test_render_deployments_unwrap_official_cursor_envelopes() -> None:
    reviewed_sha = "a" * 40

    deployments = inspector._render_deployments(
        [
            {
                "cursor": "next-page-cursor",
                "deploy": {
                    "commit": {"id": reviewed_sha, "message": "release"},
                    "id": "dep-d9fudtu1a83c73e50o70",
                    "status": "live",
                },
            }
        ]
    )

    assert deployments == [
        {
            "commit": {"id": reviewed_sha, "message": "release"},
            "id": "dep-d9fudtu1a83c73e50o70",
            "status": "live",
        }
    ]


@pytest.mark.parametrize(
    "payload",
    (
        [{"commit": {"id": "a" * 40}, "id": "dep-flat", "status": "live"}],
        [{"cursor": "", "deploy": {"id": "dep-empty-cursor"}}],
        [{"cursor": 1, "deploy": {"id": "dep-numeric-cursor"}}],
        [{"cursor": "cursor", "deploy": {"id": "dep-extra"}, "unexpected": True}],
    ),
)
def test_render_deployments_reject_malformed_cursor_envelopes(
    payload: list[object],
) -> None:
    with pytest.raises(InspectionError, match="^render_deployment_invalid$"):
        inspector._render_deployments(payload)


def _valid_environment() -> dict[str, str]:
    return {
        "FLOWACCOUNT_SANDBOX_BASE_URL": "https://openapi.flowaccount.com/test",
        "FLOWACCOUNT_SANDBOX_CLIENT_ID": "client-id",
        "FLOWACCOUNT_SANDBOX_CLIENT_SECRET": "client-secret",
        "INSPECTOR_GIT": "/usr/bin/git",
        "INSPECTOR_GITLEAKS": "/usr/local/bin/gitleaks",
        "INSPECTOR_TRUFFLEHOG": "/usr/local/bin/trufflehog",
        "MERCURY_MARKETPLACE_SNAPSHOT_URL": "https://example.invalid/marketplace.json",
        "MERCURY_PUBLIC_MCP_TOKEN": "public-token",
        "MERCURY_PUBLIC_MCP_URL": "https://mercury.example",
        "MERCURY_STAGING_REPOSITORY_TOKEN": "staging-token",
        "MERCURY_TARGET_REPOSITORY_READ_TOKEN": "read-token",
        "RENDER_API_TOKEN": "render-token",
        "RENDER_API_URL": "https://api.render.com",
        "RENDER_OWNER_ID": "tea_01HZX6R9HQSPX9K4GTDR",
        "RENDER_SERVICE_ID": "srv-d978tk37uimc73ej52mg",
        "STAGING_REPOSITORY": "natthaphonchop2-creator/mercury-tools-staging",
        "SUPABASE_DB_URL": "postgresql://user:password@db.example:5432/postgres",
        "SUPABASE_URL": "https://vbnlkqvauqwnjbxngkas.supabase.co",
        "TARGET_REPOSITORY": "natthaphonchop2-creator/mercury-tools",
    }


def test_surface_inspector_requires_safe_render_owner_id() -> None:
    policy = _configured_policy()
    environment = _valid_environment()

    validate_environment(policy, environment)

    environment.pop("RENDER_OWNER_ID")
    with pytest.raises(InspectionError, match="^environment_value_invalid$"):
        validate_environment(policy, environment)

    environment["RENDER_OWNER_ID"] = "tea_01HZX6R9HQSPX9K4GTDR&forged=true"
    with pytest.raises(InspectionError, match="^render_owner_id_invalid$"):
        validate_environment(policy, environment)


def test_scanner_version_probe_accepts_trufflehog_version_on_stderr(
    tmp_path: Path,
) -> None:
    gitleaks = tmp_path / "gitleaks"
    gitleaks.write_text("#!/bin/sh\nprintf '8.24.3\\n'\n", encoding="utf-8")
    gitleaks.chmod(0o700)
    trufflehog = tmp_path / "trufflehog"
    trufflehog.write_text(
        "#!/bin/sh\nprintf 'trufflehog 3.88.32\\n' >&2\n",
        encoding="utf-8",
    )
    trufflehog.chmod(0o700)
    environment = {
        "HOME": str(tmp_path),
        "INSPECTOR_GITLEAKS": str(gitleaks),
        "INSPECTOR_TRUFFLEHOG": str(trufflehog),
        "PATH": "/usr/bin:/bin",
    }

    assert inspector._require_scanner_versions(environment, tmp_path) == (
        gitleaks,
        trufflehog,
    )


def test_trusted_gitleaks_config_is_materialized_from_reviewed_commit(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    content = b'[extend]\nuseDefault = true\n'
    commands: list[tuple[str, ...]] = []

    def capture(
        command: tuple[str, ...],
        *,
        cwd: Path | None,
        environment: dict[str, str],
        stderr_to_stdout: bool = False,
    ) -> bytes:
        del cwd, environment, stderr_to_stdout
        commands.append(command)
        return content

    monkeypatch.setattr(inspector, "_run_capture", capture)
    monkeypatch.setattr(
        inspector,
        "_TRUSTED_GITLEAKS_CONFIG_SHA256",
        hashlib.sha256(content).hexdigest(),
    )

    path = inspector._materialize_trusted_gitleaks_config(
        tmp_path,
        clone=tmp_path,
        reviewed_sha="a" * 40,
        environment={"INSPECTOR_GIT": "/usr/bin/git"},
    )

    assert commands == [("/usr/bin/git", "show", f'{"a" * 40}:.gitleaks.toml')]
    assert path.read_bytes() == content
    assert path.stat().st_mode & 0o777 == 0o600


def test_trusted_gitleaks_config_rejects_unpinned_content(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        inspector,
        "_run_capture",
        lambda *_args, **_kwargs: b"unreviewed config\n",
    )

    with pytest.raises(InspectionError, match="^gitleaks_config_invalid$"):
        inspector._materialize_trusted_gitleaks_config(
            tmp_path,
            clone=tmp_path,
            reviewed_sha="a" * 40,
            environment={"INSPECTOR_GIT": "/usr/bin/git"},
        )


def test_git_scan_passes_trusted_config_only_to_gitleaks(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    binaries = {}
    for name in ("git", "gitleaks", "trufflehog"):
        binary = tmp_path / name
        binary.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        binary.chmod(0o700)
        binaries[name] = binary
    config = tmp_path / "gitleaks.toml"
    config.write_text('[extend]\nuseDefault = true\n', encoding="utf-8")
    commands: list[tuple[str, ...]] = []
    monkeypatch.setattr(
        inspector,
        "_run_silent",
        lambda command, **_kwargs: commands.append(tuple(command)),
    )

    inspector._scan_git(
        tmp_path,
        log_options="--all",
        gitleaks=binaries["gitleaks"],
        trufflehog=binaries["trufflehog"],
        gitleaks_config=config,
        environment={"INSPECTOR_GIT": str(binaries["git"])},
    )

    assert f"--config={config}" in commands[0]
    assert not any(item.startswith("--config=") for item in commands[1])


def test_payload_scan_normalizes_single_root_archive_and_deduplicates_raw_archive(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "fixture.py"
    source.write_text('token = "synthetic-fixture"\n', encoding="utf-8")
    payload = tmp_path / "payload.tar"
    with tarfile.open(payload, mode="w") as archive:
        archive.add(source, arcname="mercury-tools-reviewed/tests/fixture.py")

    raw_value = "synthetic-fixture"
    canonical = {
        "scanner": "gitleaks",
        "rule_id": "generic-api-key",
        "commit": "",
        "start_line": 1,
        "secret_sha256": inspector._scanner_value_digest(raw_value),
    }
    digest = inspector._scanner_evidence_digest(canonical)

    def scanner_probe(
        command: tuple[str, ...],
        *,
        cwd: Path,
        environment: dict[str, str],
        report: Path,
        budget: inspector.InspectionBudget | None = None,
    ) -> int:
        del environment, budget
        if Path(command[0]).name == "gitleaks":
            assert "--redact" not in command
            report_path = Path(
                next(item.split("=", 1)[1] for item in command if item.startswith("--report-path="))
            )
            if (cwd / "payload.bin").is_file():
                records = [
                    {
                        "Commit": "",
                        "File": str(cwd / "payload.bin"),
                        "RuleID": "generic-api-key",
                        "Secret": raw_value,
                        "StartLine": 1,
                    },
                    {
                        "Commit": "",
                        "File": str(
                            cwd
                            / "decoded/mercury-tools-reviewed/tests/fixture.py"
                        ),
                        "RuleID": "generic-api-key",
                        "Secret": raw_value,
                        "StartLine": 1,
                    },
                ]
            else:
                records = [
                    {
                        "Commit": "",
                        "File": str(next(cwd.rglob("fixture.py"))),
                        "RuleID": "generic-api-key",
                        "Secret": raw_value,
                        "StartLine": 1,
                    }
                ]
            report_path.write_text(
                json.dumps(records),
                encoding="utf-8",
            )
            report.write_bytes(b"")
            return 1
        report.write_bytes(b"")
        return 0

    monkeypatch.setattr(inspector, "_run_scanner_capture", scanner_probe)

    hashes = inspector._scan_payloads(
        (payload,),
        gitleaks=tmp_path / "gitleaks",
        trufflehog=tmp_path / "trufflehog",
        allowlist=frozenset({("tests/fixture.py", "scanner_finding", digest)}),
    )

    assert len(hashes) == 3


def test_payload_scan_reconciles_trufflehog_raw_duplicate_by_secret_identity(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "fixture.py"
    source.write_text('token = "synthetic-fixture"\n', encoding="utf-8")
    payload = tmp_path / "payload.tar"
    with tarfile.open(payload, mode="w") as archive:
        archive.add(source, arcname="mercury-tools-reviewed/tests/fixture.py")

    raw_value = "synthetic-fixture"
    canonical = {
        "scanner": "trufflehog",
        "detector": "URI",
        "decoder": "PLAIN",
        "verified": False,
        "line": 1,
        "raw_sha256": inspector._scanner_value_digest(raw_value),
        "raw_v2_sha256": None,
    }
    digest = inspector._scanner_evidence_digest(canonical)

    def scanner_probe(
        command: tuple[str, ...],
        *,
        cwd: Path,
        environment: dict[str, str],
        report: Path,
        budget: inspector.InspectionBudget | None = None,
    ) -> int:
        del cwd, environment, budget
        if Path(command[0]).name == "gitleaks":
            report_path = Path(
                next(item.split("=", 1)[1] for item in command if item.startswith("--report-path="))
            )
            report_path.write_text("[]", encoding="utf-8")
            report.write_bytes(b"")
            return 0

        scan_root = Path(command[command.index("--directory") + 1])
        if (scan_root / "payload.bin").is_file():
            file_name = scan_root / "payload.bin"
            line = 200
        else:
            file_name = next(scan_root.rglob("fixture.py"))
            line = 1
        report.write_text(
            json.dumps(
                {
                    "DetectorName": "URI",
                    "DecoderName": "PLAIN",
                    "Verified": False,
                    "Raw": raw_value,
                    "SourceMetadata": {
                        "Data": {
                            "Filesystem": {
                                "file": str(file_name),
                                "line": line,
                            }
                        }
                    },
                }
            )
            + "\n",
            encoding="utf-8",
        )
        return 183

    monkeypatch.setattr(inspector, "_run_scanner_capture", scanner_probe)

    hashes = inspector._scan_payloads(
        (payload,),
        gitleaks=tmp_path / "gitleaks",
        trufflehog=tmp_path / "trufflehog",
        allowlist=frozenset({("tests/fixture.py", "scanner_finding", digest)}),
    )

    assert len(hashes) == 3


@pytest.mark.parametrize(
    ("scanner", "status"),
    (("gitleaks", 1), ("trufflehog", 1), ("trufflehog", 183)),
)
def test_scanner_result_rejects_nonzero_status_without_findings(
    scanner: str, status: int
) -> None:
    with pytest.raises(InspectionError, match="^scanner_execution_failed$"):
        inspector._validate_scanner_result(scanner, status, frozenset())


def test_gitleaks_fingerprint_is_bound_to_the_unredacted_value(tmp_path: Path) -> None:
    root = tmp_path / "root"
    root.mkdir()

    def fingerprint(value: str, name: str) -> frozenset[inspector.ScannerFinding]:
        report = tmp_path / name
        report.write_text(
            json.dumps(
                [
                    {
                        "Commit": "",
                        "File": "fixture.py",
                        "RuleID": "generic-api-key",
                        "Secret": value,
                        "StartLine": 1,
                    }
                ]
            ),
            encoding="utf-8",
        )
        return inspector._scanner_finding_records("gitleaks", report, root=root)

    assert fingerprint("synthetic-first-value", "first.json") != fingerprint(
        "synthetic-second-value", "second.json"
    )


def test_scanner_process_honors_global_inspection_deadline(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    class Process:
        returncode = 0

        def poll(self) -> None:
            return None

        def kill(self) -> None:
            return None

        def wait(self, timeout: int) -> int:
            del timeout
            return 0

    moments = iter((0.0, 0.0, 6.0))
    monkeypatch.setattr(inspector, "INSPECTION_TIMEOUT_SECONDS", 5.0)
    monkeypatch.setattr(inspector.time, "monotonic", lambda: next(moments))
    monkeypatch.setattr(inspector.subprocess, "Popen", lambda *_args, **_kwargs: Process())

    with pytest.raises(InspectionError, match="^inspection_time_budget_exhausted$"):
        inspector._run_scanner_capture(
            ("/usr/bin/true",),
            cwd=tmp_path,
            environment={},
            report=tmp_path / "scanner.json",
            budget=inspector.InspectionBudget(started=0.0),
        )


def test_archive_finding_normalization_keeps_container_only_evidence_blocking() -> None:
    finding = ("payload.bin", "scanner_finding", "a" * 64)

    assert inspector._normalize_archive_findings(
        frozenset({finding}), member_prefix="decoded/"
    ) == frozenset({finding})


def test_archive_finding_normalization_rejects_paths_outside_wrapper() -> None:
    finding = ("unexpected.txt", "scanner_finding", "a" * 64)

    with pytest.raises(InspectionError, match="^scanner_report_invalid$"):
        inspector._normalize_archive_findings(
            frozenset({finding}), member_prefix="decoded/"
        )


def test_archive_finding_normalization_keeps_nonmatching_container_evidence() -> None:
    decoded = ("decoded/tests/fixture.py", "scanner_finding", "a" * 64)
    container = ("payload.bin", "scanner_finding", "b" * 64)

    assert inspector._normalize_archive_findings(
        frozenset({decoded, container}), member_prefix="decoded/"
    ) == frozenset(
        {
            ("tests/fixture.py", "scanner_finding", "a" * 64),
            container,
        }
    )


def test_archive_record_normalization_keeps_raw_only_secret_identity() -> None:
    raw = inspector.ScannerFinding(
        file="payload.bin",
        rule="scanner_finding",
        evidence_digest="a" * 64,
        match_digest="b" * 64,
    )
    decoded = inspector.ScannerFinding(
        file="decoded/tests/fixture.py",
        rule="scanner_finding",
        evidence_digest="c" * 64,
        match_digest="d" * 64,
    )

    assert inspector._normalize_archive_finding_records(
        frozenset({raw, decoded}), member_prefix="decoded/"
    ) == frozenset(
        {
            raw,
            inspector.ScannerFinding(
                file="tests/fixture.py",
                rule="scanner_finding",
                evidence_digest="c" * 64,
                match_digest="d" * 64,
            ),
        }
    )


def test_archive_record_normalization_drops_exact_allowlisted_raw_fixture() -> None:
    raw = inspector.ScannerFinding(
        file="payload.bin",
        rule="scanner_finding",
        evidence_digest="a" * 64,
        match_digest="b" * 64,
    )

    assert inspector._normalize_archive_finding_records(
        frozenset({raw}),
        member_prefix="decoded/",
        allowlist=frozenset(
            {("tests/fixture.py", "scanner_finding", "a" * 64)}
        ),
    ) == frozenset()


def test_archive_member_prefix_does_not_strip_multi_root_archives(tmp_path: Path) -> None:
    decoded_root = tmp_path / "decoded"
    (decoded_root / "first").mkdir(parents=True)
    (decoded_root / "second").mkdir()

    assert inspector._archive_member_prefix(decoded_root) == "decoded/"


def test_staging_static_requires_exact_remote_public_mcp_endpoint(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    snapshot = inspector.ArchiveSnapshot(
        tree_sha256="a" * 64,
        static_files={
            ".agents/plugins/marketplace.json": json.dumps(
                {"plugins": [{"name": "mercury-finance"}]}
            ).encode(),
            "catalog/global/flowaccount/actions.json": b"[]",
            "catalog/global/peak/actions.json": b"[]",
            "plugins/mercury-finance/.codex-plugin/plugin.json": json.dumps(
                {"name": "mercury-finance", "mcpServers": "./.mcp.json"}
            ).encode(),
            "plugins/mercury-finance/.mcp.json": json.dumps(
                {
                    "mcpServers": {
                        "mercury-finance": {
                            "type": "http",
                            "url": "https://mercury.example/mcp",
                            "note": "Mercury Accounting and ERP connector platform.",
                        }
                    }
                }
            ).encode(),
            "src/mercury_tools/mcp/local_server.py": b"",
        },
    )
    monkeypatch.setattr(
        inspector,
        "_static_mcp_tool_names",
        lambda _source: tuple(sorted(inspector._EXPECTED_LOCAL_MCP_TOOLS)),
    )
    monkeypatch.setattr(inspector, "_static_validation_identities", lambda _snapshot: ())

    assert inspector._validate_staging_static(
        snapshot,
        public_mcp_base_url="https://mercury.example",
    ) == (20, ())

    monkeypatch.setattr(
        inspector,
        "_static_mcp_tool_names",
        lambda _source: tuple(sorted(inspector._EXPECTED_LOCAL_MCP_TOOLS - {"credential_status"})),
    )
    with pytest.raises(InspectionError, match="^staging_local_tool_count_invalid$"):
        inspector._validate_staging_static(
            snapshot,
            public_mcp_base_url="https://mercury.example",
        )


def test_git_staging_propagates_public_mcp_url_outside_minimal_process_env(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    observed: list[str] = []
    clone = tmp_path / "clone"
    clone.mkdir()
    config = tmp_path / "gitleaks.toml"
    config.write_text("[extend]\nuseDefault = true\n", encoding="utf-8")

    monkeypatch.setattr(inspector, "_clone_candidate", lambda *_args, **_kwargs: clone)
    monkeypatch.setattr(
        inspector,
        "_materialize_trusted_gitleaks_config",
        lambda *_args, **_kwargs: config,
    )
    monkeypatch.setattr(inspector, "_scan_git", lambda *_args, **_kwargs: [])
    monkeypatch.setattr(inspector, "_git_output", lambda *_args, **_kwargs: "")
    monkeypatch.setattr(inspector, "_scan_payloads", lambda *_args, **_kwargs: [])

    def staging_probe(
        _root: Path,
        *,
        public_mcp_base_url: str,
        environment: dict[str, str],
        **_kwargs: object,
    ) -> tuple[dict[str, object], tuple[tuple[str, str, str], ...]]:
        assert "MERCURY_PUBLIC_MCP_URL" not in environment
        observed.append(public_mcp_base_url)
        return {}, ()

    monkeypatch.setattr(inspector, "_inspect_staging", staging_probe)

    inspector._inspect_git_and_staging(
        policy={
            "reviewed_repository": "example/mercury-tools",
            "staging_repository": "example/mercury-tools-staging",
        },
        reviewed_sha="a" * 40,
        staging_ref="v0.3.0-rc.aaaaaaaaaaaa",
        environment_values={
            "INSPECTOR_GIT": "/usr/bin/git",
            "INSPECTOR_GITLEAKS": "/usr/bin/true",
            "INSPECTOR_TRUFFLEHOG": "/usr/bin/true",
            "MERCURY_PUBLIC_MCP_URL": "https://mercury.example",
            "MERCURY_STAGING_REPOSITORY_TOKEN": "staging-token",
            "MERCURY_TARGET_REPOSITORY_READ_TOKEN": "read-token",
        },
        gitleaks=Path("/usr/bin/true"),
        trufflehog=Path("/usr/bin/true"),
        allowlist=frozenset(),
    )

    assert observed == ["https://mercury.example"]


@pytest.mark.parametrize(
    "server",
    (
        {"command": "uvx", "args": ["mercury-tools"]},
        {
            "type": "http",
            "url": "https://attacker.example/mcp",
            "note": "wrong host",
        },
        {
            "type": "http",
            "url": "https://mercury.example/mcp?token=secret",
            "note": "query is forbidden",
        },
        {
            "type": "http",
            "url": "https://mercury.example/mcp",
            "note": "unexpected headers",
            "headers": {"Authorization": "Bearer placeholder"},
        },
    ),
)
def test_staging_static_rejects_non_public_or_credential_bearing_mcp_server(
    server: dict[str, object],
) -> None:
    with pytest.raises(InspectionError, match="^staging_mcp_inventory_invalid$"):
        inspector._validate_remote_mcp_server(
            server,
            public_mcp_base_url="https://mercury.example",
        )


@pytest.mark.parametrize("log_type", ("build", "runtime"))
def test_surface_inspector_render_log_urls_bind_owner_id(log_type: str) -> None:
    from urllib.parse import parse_qs, urlsplit

    url = _render_log_url(
        "https://api.render.com/v1",
        service_id="srv-d978tk37uimc73ej52mg",
        owner_id="tea_01HZX6R9HQSPX9K4GTDR",
        log_type=log_type,
    )

    parsed = urlsplit(url)
    assert parsed.path == "/v1/logs"
    assert parse_qs(parsed.query, strict_parsing=True) == {
        "ownerId": ["tea_01HZX6R9HQSPX9K4GTDR"],
        "resource": ["srv-d978tk37uimc73ej52mg"],
        "type": [log_type],
    }


def test_surface_inspector_routes_v022_profile_only_to_versioned_collectors(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    digest = "a" * 64
    reviewed_sha = "b" * 40
    policy = json.loads((ROOT / "policy-v0.2.2.json").read_text(encoding="utf-8"))
    policy["bootstrap_state"] = "configured"
    policy_path = tmp_path / "policy.json"
    policy_path.write_text(json.dumps(policy), encoding="utf-8")
    manifest_path = tmp_path / "manifest.json"
    manifest_path.write_text(
        json.dumps(
            {
                "required": list(inspector._CANDIDATE_SURFACES),
                "scanner_versions": {"gitleaks": "8.24.3", "trufflehog": "3.88.32"},
                "schema_version": 1,
            }
        ),
        encoding="utf-8",
    )
    allowlist_path = tmp_path / "allowlist.json"
    allowlist_path.write_text(
        json.dumps({"entries": [], "schema_version": 1}), encoding="utf-8"
    )

    git_probe = create_autospec(
        inspector._inspect_git_and_staging,
        return_value=([digest], [digest], {"tag": f"v0.2.2-rc.{reviewed_sha[:12]}"}, []),
    )
    release_probe = create_autospec(inspector._inspect_github_releases, return_value=[digest])
    actions_probe = create_autospec(inspector._inspect_github_actions, return_value=[digest])
    packages_probe = create_autospec(
        inspector._inspect_github_packages_pages_wiki, return_value=[digest]
    )
    marketplace_probe = create_autospec(inspector._inspect_marketplace, return_value=[digest])
    render_probe = create_autospec(
        inspector._inspect_render_and_public_mcp,
        return_value=(
            {
                "deployment_commit": reviewed_sha,
                "evidence_sha256": digest,
                "hosted_tool_count": 20,
                "version": "0.2.2",
            },
            [digest],
            [digest],
        ),
    )
    database_probe = create_autospec(
        inspector.inspect_database,
        return_value=(
            {"migration_history_sha256": digest, "schema_sha256": digest},
            {"report_sha256": digest},
        ),
    )
    monkeypatch.setattr(inspector, "validate_environment", lambda *_args: None)
    monkeypatch.setattr(inspector, "_minimal_process_env", lambda *_args, **_kwargs: {})
    monkeypatch.setattr(
        inspector,
        "_require_scanner_versions",
        lambda *_args: (Path("/usr/bin/true"), Path("/usr/bin/true")),
    )
    monkeypatch.setattr(inspector, "_inspect_git_and_staging", git_probe)
    monkeypatch.setattr(inspector, "_inspect_github_releases", release_probe)
    monkeypatch.setattr(inspector, "_inspect_github_actions", actions_probe)
    monkeypatch.setattr(inspector, "_inspect_github_packages_pages_wiki", packages_probe)
    monkeypatch.setattr(inspector, "_inspect_marketplace", marketplace_probe)
    monkeypatch.setattr(inspector, "_inspect_render_and_public_mcp", render_probe)
    monkeypatch.setattr(inspector, "inspect_database", database_probe)
    monkeypatch.setattr(inspector, "_flowaccount_live_read", lambda _environment: digest)

    evidence = inspector.inspect(
        policy_path=policy_path,
        reviewed_sha=reviewed_sha,
        staging_ref=f"v0.2.2-rc.{reviewed_sha[:12]}",
        manifest_path=manifest_path,
        allowlist_path=allowlist_path,
        output_path=tmp_path / "evidence.json",
        environment={
            "MERCURY_TARGET_REPOSITORY_READ_TOKEN": "read-token",
            "SUPABASE_DB_URL": "postgresql://unused",
        },
        clock=lambda: inspector.datetime(2026, 7, 17, tzinfo=inspector.UTC),
    )

    assert evidence["render"]["version"] == "0.2.2"
    assert render_probe.call_args.kwargs["profile"].version == "0.2.2"
    assert "profile" not in release_probe.call_args.kwargs
    assert "profile" not in actions_probe.call_args.kwargs
