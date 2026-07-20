from __future__ import annotations

import hashlib
import io
import json
import re
import tarfile
from pathlib import Path

import pytest

from mercury_release_control import guardian
from mercury_release_control.guardian import (
    GuardianError,
    build_manifest_payload,
    verify_candidate_archive,
)
from mercury_release_control.release_profile import release_profile

ROOT = Path(__file__).resolve().parents[1]
APPROVED_ARCHIVE = ROOT / "tests/fixtures/v030-approved-candidate.tar.gz"
APPROVED_ARCHIVE_SHA256 = "9f4df4df1c3ac9512e7d1ece0a509fe5cc0c6aac2a5a20fa6883c7c587397687"
EXPECTED_PRIVILEGED_PATHS = {
    ".github/workflows/attest-v0.2.2.yml",
    ".github/workflows/attest-v0.3.0.yml",
    ".github/workflows/ci.yml",
    ".github/workflows/guardian.yml",
    ".github/workflows/migrate-v0.3.0.yml",
    ".github/workflows/publish-v0.2.2.yml",
    ".github/workflows/publish-v0.3.0.yml",
    "policy-v0.2.2.json",
    "policy-v0.3.0.json",
    "pyproject.toml",
    "src/mercury_release_control/__init__.py",
    "src/mercury_release_control/attestation.py",
    "src/mercury_release_control/github_preflight.py",
    "src/mercury_release_control/github_publication.py",
    "src/mercury_release_control/handoff.py",
    "src/mercury_release_control/hosted_collector.py",
    "src/mercury_release_control/preflight.py",
    "src/mercury_release_control/production_migration.py",
    "src/mercury_release_control/provider_inspector.py",
    "src/mercury_release_control/public_tree.py",
    "src/mercury_release_control/publication.py",
    "src/mercury_release_control/publish_workflow.py",
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


def test_v030_guardian_upgrade_has_no_unapproved_runtime_module() -> None:
    runtime_paths = {
        path.relative_to(ROOT).as_posix()
        for path in (ROOT / "src/mercury_release_control").glob("*.py")
        if path.name != "guardian.py"
    }

    assert runtime_paths <= set(guardian.V030_TRUSTED_FILE_SHA256)


def _candidate_archive(files: dict[str, bytes]) -> bytes:
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w:gz", format=tarfile.PAX_FORMAT) as archive:
        for path, content in sorted(files.items()):
            member = tarfile.TarInfo(f"candidate-sha/{path}")
            member.mode = 0o644
            member.size = len(content)
            archive.addfile(member, io.BytesIO(content))
    return output.getvalue()


def test_v030_guardian_upgrade_accepts_exact_approved_candidate_archive() -> None:
    archive = APPROVED_ARCHIVE.read_bytes()

    assert hashlib.sha256(archive).hexdigest() == APPROVED_ARCHIVE_SHA256
    assert set(guardian._read_candidate_archive(archive)) == set(guardian.V030_ALLOWED_FILES)
    assert verify_candidate_archive(archive).status == "passed"


def test_v030_guardian_upgrade_rejects_additive_candidate_path() -> None:
    files = guardian._read_candidate_archive(APPROVED_ARCHIVE.read_bytes())
    files["json.py"] = b"raise RuntimeError('unexpected import')\n"
    files[guardian.MANIFEST_PATH] = json.dumps(
        build_manifest_payload(
            {key: value for key, value in files.items() if key != guardian.MANIFEST_PATH}
        ),
        separators=(",", ":"),
        sort_keys=True,
    ).encode()

    with pytest.raises(GuardianError, match="^candidate_inventory_invalid$"):
        verify_candidate_archive(_candidate_archive(files))


@pytest.mark.parametrize("path", sorted(EXPECTED_PRIVILEGED_PATHS))
def test_v030_guardian_upgrade_rejects_changed_approved_file(path: str) -> None:
    files = guardian._read_candidate_archive(APPROVED_ARCHIVE.read_bytes())
    files[path] += b"\nchanged\n"
    files[guardian.MANIFEST_PATH] = json.dumps(
        build_manifest_payload(
            {key: value for key, value in files.items() if key != guardian.MANIFEST_PATH}
        ),
        separators=(",", ":"),
        sort_keys=True,
    ).encode()

    with pytest.raises(GuardianError, match="^candidate_trusted_file_hash_invalid$"):
        verify_candidate_archive(_candidate_archive(files))


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
