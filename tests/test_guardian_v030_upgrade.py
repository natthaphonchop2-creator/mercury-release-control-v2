from __future__ import annotations

import re

import pytest

from mercury_release_control import guardian
from mercury_release_control.guardian import GuardianError
from mercury_release_control.release_profile import release_profile

EXPECTED_PRIVILEGED_PATHS = {
    ".github/workflows/attest-v0.2.2.yml",
    ".github/workflows/attest-v0.3.0.yml",
    ".github/workflows/ci.yml",
    ".github/workflows/guardian.yml",
    ".github/workflows/migrate-v0.3.0.yml",
    ".github/workflows/publish-v0.2.2.yml",
    ".github/workflows/publish-v0.3.0.yml",
    "policy-v0.3.0.json",
    "pyproject.toml",
    "src/mercury_release_control/__init__.py",
    "src/mercury_release_control/attestation.py",
    "src/mercury_release_control/github_preflight.py",
    "src/mercury_release_control/preflight.py",
    "src/mercury_release_control/production_migration.py",
    "src/mercury_release_control/provider_inspector.py",
    "src/mercury_release_control/public_tree.py",
    "src/mercury_release_control/release_profile.py",
    "src/mercury_release_control/staging.py",
    "src/mercury_release_control/surface_inspector.py",
    "src/mercury_release_control/workflow.py",
    "uv.lock",
}


def test_v030_guardian_upgrade_pins_privileged_runtime_closure() -> None:
    assert set(guardian.V030_TRUSTED_FILE_SHA256) == EXPECTED_PRIVILEGED_PATHS
    assert "src/mercury_release_control/guardian.py" not in EXPECTED_PRIVILEGED_PATHS
    assert all(
        re.fullmatch(r"[0-9a-f]{64}", digest)
        for digest in guardian.V030_TRUSTED_FILE_SHA256.values()
    )


def test_v030_guardian_upgrade_rejects_missing_privileged_files() -> None:
    with pytest.raises(GuardianError, match="^candidate_trusted_file_hash_invalid$"):
        guardian._validate_trusted_v030_files({}, v030_present=True)


def test_v030_guardian_upgrade_binds_full_policy_identity() -> None:
    policy = guardian.V030_EXPECTED_POLICY

    assert policy["repository_id"] == 1303413748
    assert policy["reviewed_repository_id"] == 1290137723
    assert policy["required_reviewer_ids"] == [240973204]
    assert "SUPABASE_DB_URL" in policy["required_environment_secrets"]
    assert "SUPABASE_DB_URL" in policy["forbidden_repository_secrets"]
    assert policy["immutable_releases_required"] is True
    assert policy["supabase"]["migration_id"] == "20260719120000"
    assert policy["release"] == {"tag": "v0.3.0", "version": "0.3.0"}


def test_v030_guardian_upgrade_knows_expected_release_profile() -> None:
    profile = release_profile("0.3.0")

    assert profile.migration_id == "20260719120000"
    assert profile.hosted_tool_count == 24
    assert profile.supabase_function_count == 11
