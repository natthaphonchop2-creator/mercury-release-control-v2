from __future__ import annotations

import hashlib
import json
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
