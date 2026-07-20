from __future__ import annotations

import copy
import hashlib
import io
import json
import tarfile
from pathlib import Path

import pytest

from mercury_release_control import guardian
from mercury_release_control.guardian import (
    GuardianError,
    build_manifest_payload,
    verify_candidate_archive,
)

CHECKOUT_PIN = "34e114876b0b11c390a56381ad16ebd13914f8d5"
ROOT = Path(__file__).resolve().parents[1]
POLICY_V022 = ROOT / "policy-v0.2.2.json"
POLICY_V030 = ROOT / "policy-v0.3.0.json"
MIGRATION_WORKFLOW = ROOT / ".github/workflows/migrate-v0.3.0.yml"
TRUSTED_V030_PATHS = (
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
)


def _ci_workflow() -> bytes:
    return f"""name: CI
on: [pull_request, push]
permissions:
  contents: read
jobs:
  test:
    runs-on: ubuntu-24.04
    steps:
      - uses: actions/checkout@{CHECKOUT_PIN}
      - run: uv run pytest -q
""".encode()


def _guardian_workflow() -> bytes:
    return f"""name: Guardian
on: pull_request_target
permissions:
  contents: read
  pull-requests: read
jobs:
  verify:
    runs-on: ubuntu-24.04
    steps:
      - uses: actions/checkout@{CHECKOUT_PIN}
        with:
          ref: ${{{{ github.event.pull_request.base.sha }}}}
          persist-credentials: false
      - run: python -m mercury_release_control.guardian verify --candidate candidate.tar.gz
""".encode()


def _release_workflow(*, action: str, version: str) -> bytes:
    actions_permission = "write" if action == "attest" else "read"
    return f"""name: Mercury v{version} {action}
on: workflow_dispatch
permissions:
  actions: {actions_permission}
  contents: read
jobs:
  verify:
    runs-on: ubuntu-24.04
    steps:
      - run: 'true'
""".encode()


def _candidate_files(marker: Path | None = None) -> dict[str, bytes]:
    payload = b"VALUE = 1\n"
    if marker is not None:
        payload = f"from pathlib import Path\nPath({str(marker)!r}).touch()\n".encode()
    files = {
        ".github/workflows/attest-v0.2.2.yml": _release_workflow(action="attest", version="0.2.2"),
        ".github/workflows/attest-v0.3.0.yml": _release_workflow(action="attest", version="0.3.0"),
        ".github/workflows/ci.yml": _ci_workflow(),
        ".github/workflows/guardian.yml": _guardian_workflow(),
        ".github/workflows/migrate-v0.3.0.yml": MIGRATION_WORKFLOW.read_bytes(),
        ".github/workflows/publish-v0.2.2.yml": _release_workflow(
            action="publish", version="0.2.2"
        ),
        ".github/workflows/publish-v0.3.0.yml": _release_workflow(
            action="publish", version="0.3.0"
        ),
        ".gitignore": b".venv/\n",
        "LICENSE": b"MIT\n",
        "README.md": b"Mercury release control\n",
        "policy-v0.2.2.json": POLICY_V022.read_bytes(),
        "policy-v0.3.0.json": POLICY_V030.read_bytes(),
        "pyproject.toml": b"[project]\nname='mercury-release-control'\nversion='0.3.0'\n",
        "src/mercury_release_control/__init__.py": b"__version__ = '0.3.0'\n",
        "src/mercury_release_control/guardian.py": (
            ROOT / "src/mercury_release_control/guardian.py"
        ).read_bytes(),
        "src/mercury_release_control/production_migration.py": b"VALUE = 1\n",
        "src/mercury_release_control/release_profile.py": b"PROFILES = ('0.2.2', '0.3.0')\n",
        "src/untrusted_candidate.py": payload,
        "uv.lock": b"version = 1\n",
    }
    files.update({path: (ROOT / path).read_bytes() for path in TRUSTED_V030_PATHS})
    files["control-manifest.json"] = json.dumps(
        build_manifest_payload(files),
        separators=(",", ":"),
        sort_keys=True,
    ).encode()
    return files


def _v022_candidate_files() -> dict[str, bytes]:
    files = _candidate_files()
    for path in guardian.V030_MARKER_FILES:
        files.pop(path, None)
    files["control-manifest.json"] = json.dumps(
        build_manifest_payload(
            {key: value for key, value in files.items() if key != "control-manifest.json"}
        ),
        separators=(",", ":"),
        sort_keys=True,
    ).encode()
    return files


def _archive(
    files: dict[str, bytes],
    *,
    global_headers: dict[str, str] | None = None,
) -> bytes:
    output = io.BytesIO()
    with tarfile.open(
        fileobj=output,
        mode="w:gz",
        format=tarfile.PAX_FORMAT,
        pax_headers=global_headers,
    ) as archive:
        for path, content in sorted(files.items()):
            member = tarfile.TarInfo(f"candidate-sha/{path}")
            member.mode = 0o644
            member.size = len(content)
            archive.addfile(member, io.BytesIO(content))
    return output.getvalue()


def test_guardian_reads_candidate_as_data_without_execution(tmp_path: Path) -> None:
    marker = tmp_path / "executed"

    receipt = verify_candidate_archive(_archive(_candidate_files(marker)))

    assert receipt.status == "passed"
    assert receipt.file_count == len(_candidate_files())
    assert not marker.exists()


def test_guardian_accepts_git_commit_global_pax_comment() -> None:
    receipt = verify_candidate_archive(
        _archive(_candidate_files(), global_headers={"comment": "a" * 40})
    )
    assert receipt.status == "passed"


def test_guardian_upgrade_remains_compatible_with_v022_only_candidate() -> None:
    receipt = verify_candidate_archive(_archive(_v022_candidate_files()))

    assert receipt.status == "passed"


def test_guardian_rejects_partial_v030_candidate() -> None:
    files = _v022_candidate_files()
    files["policy-v0.3.0.json"] = POLICY_V030.read_bytes()
    files["control-manifest.json"] = json.dumps(
        build_manifest_payload(
            {key: value for key, value in files.items() if key != "control-manifest.json"}
        ),
        separators=(",", ":"),
        sort_keys=True,
    ).encode()

    with pytest.raises(GuardianError, match="^candidate_inventory_invalid$"):
        verify_candidate_archive(_archive(files))


def test_guardian_rejects_manifest_hash_drift() -> None:
    files = _candidate_files()
    files["src/mercury_release_control/guardian.py"] += b"CHANGED = True\n"

    with pytest.raises(GuardianError, match="^candidate_manifest_mismatch$"):
        verify_candidate_archive(_archive(files))


def test_guardian_rejects_candidate_guardian_tamper_with_regenerated_manifest() -> None:
    files = _candidate_files()
    files["src/mercury_release_control/guardian.py"] += b"CHANGED = True\n"
    files["control-manifest.json"] = json.dumps(
        build_manifest_payload(
            {key: value for key, value in files.items() if key != "control-manifest.json"}
        ),
        separators=(",", ":"),
        sort_keys=True,
    ).encode()

    with pytest.raises(GuardianError, match="^candidate_trusted_file_hash_invalid$"):
        verify_candidate_archive(_archive(files))


def test_guardian_pins_exact_v030_privileged_runtime_import_closure() -> None:
    assert set(guardian.V030_TRUSTED_FILE_SHA256) == set(TRUSTED_V030_PATHS)
    assert "src/mercury_release_control/guardian.py" not in guardian.V030_TRUSTED_FILE_SHA256
    for path in TRUSTED_V030_PATHS:
        assert (
            guardian.V030_TRUSTED_FILE_SHA256[path]
            == hashlib.sha256((ROOT / path).read_bytes()).hexdigest()
        )


def test_guardian_pins_every_release_control_runtime_module_except_itself() -> None:
    runtime_root = ROOT / "src/mercury_release_control"
    runtime_paths = {
        path.relative_to(ROOT).as_posix()
        for path in runtime_root.glob("*.py")
        if path.name != "guardian.py"
    }

    assert runtime_paths <= set(guardian.V030_TRUSTED_FILE_SHA256)


@pytest.mark.parametrize("path", TRUSTED_V030_PATHS)
def test_guardian_rejects_tampered_v030_file_with_regenerated_manifest(path: str) -> None:
    files = _candidate_files()
    files[path] += b"\n "
    files["control-manifest.json"] = json.dumps(
        build_manifest_payload(
            {key: value for key, value in files.items() if key != "control-manifest.json"}
        ),
        separators=(",", ":"),
        sort_keys=True,
    ).encode()

    with pytest.raises(GuardianError, match="^candidate_trusted_file_hash_invalid$"):
        verify_candidate_archive(_archive(files))


def test_guardian_pins_full_v030_policy_shape() -> None:
    policy = json.loads(POLICY_V030.read_text(encoding="utf-8"))

    assert policy == guardian.V030_EXPECTED_POLICY


@pytest.mark.parametrize(
    ("path", "replacement"),
    (
        (("repository_id",), 1),
        (("reviewed_repository_id",), 1),
        (("required_reviewer_ids",), [1]),
        (("required_environment_secrets",), ["SUPABASE_DB_URL"]),
        (("required_environment_variables",), ["SUPABASE_URL"]),
        (("forbidden_repository_secrets",), []),
        (("immutable_releases_required",), False),
        (("release_tag_ruleset", "enforcement"), "disabled"),
        (("supabase", "migration_id"), "20260716100000"),
        (("supabase", "migration_history_sha256"), "0" * 64),
        (("supabase", "schema_sha256"), "0" * 64),
        (("release", "tag"), "v0.3.0-tampered"),
        (("release", "version"), "0.3.1"),
    ),
)
def test_guardian_rejects_v030_security_policy_shape_drift(
    path: tuple[str, ...], replacement: object
) -> None:
    policy = copy.deepcopy(json.loads(POLICY_V030.read_text(encoding="utf-8")))
    target = policy
    for key in path[:-1]:
        target = target[key]
    target[path[-1]] = replacement

    with pytest.raises(GuardianError, match="^candidate_policy_invalid$"):
        guardian._validate_policy(
            json.dumps(policy, separators=(",", ":"), sort_keys=True).encode(),
            version="0.3.0",
        )


def test_guardian_rejects_unpinned_action() -> None:
    files = _v022_candidate_files()
    files[".github/workflows/ci.yml"] = _ci_workflow().replace(CHECKOUT_PIN.encode(), b"main")
    files["control-manifest.json"] = json.dumps(
        build_manifest_payload(
            {key: value for key, value in files.items() if key != "control-manifest.json"}
        ),
        separators=(",", ":"),
        sort_keys=True,
    ).encode()

    with pytest.raises(GuardianError, match="^candidate_workflow_action_unpinned$"):
        verify_candidate_archive(_archive(files))


def test_guardian_rejects_permission_escalation() -> None:
    files = _v022_candidate_files()
    files[".github/workflows/ci.yml"] = _ci_workflow().replace(
        b"contents: read", b"contents: write"
    )
    files["control-manifest.json"] = json.dumps(
        build_manifest_payload(
            {key: value for key, value in files.items() if key != "control-manifest.json"}
        ),
        separators=(",", ":"),
        sort_keys=True,
    ).encode()

    with pytest.raises(GuardianError, match="^candidate_workflow_permissions_invalid$"):
        verify_candidate_archive(_archive(files))


def test_guardian_rejects_production_migration_identity_hash_drift() -> None:
    files = _candidate_files()
    files[".github/workflows/migrate-v0.3.0.yml"] = files[
        ".github/workflows/migrate-v0.3.0.yml"
    ].replace(
        b"2ca702823fd17a7806ead1b829af21984ea54b676700cf443cb69b7e6161c0ca",
        b"0ca702823fd17a7806ead1b829af21984ea54b676700cf443cb69b7e6161c0ca",
    )
    files["control-manifest.json"] = json.dumps(
        build_manifest_payload(
            {key: value for key, value in files.items() if key != "control-manifest.json"}
        ),
        separators=(",", ":"),
        sort_keys=True,
    ).encode()

    with pytest.raises(GuardianError, match="^candidate_trusted_file_hash_invalid$"):
        verify_candidate_archive(_archive(files))


def test_guardian_rejects_forbidden_secret_path() -> None:
    files = _candidate_files()
    files[".env"] = b"TOKEN=secret\n"
    files["control-manifest.json"] = json.dumps(
        build_manifest_payload(
            {key: value for key, value in files.items() if key != "control-manifest.json"}
        ),
        separators=(",", ":"),
        sort_keys=True,
    ).encode()

    with pytest.raises(GuardianError, match="^candidate_path_forbidden$"):
        verify_candidate_archive(_archive(files))


def test_guardian_rejects_literal_secret_assignment() -> None:
    files = _candidate_files()
    files["src/mercury_release_control/guardian.py"] += (
        b'\nclient_secret = "hardcoded-fixture-secret"\n'
    )
    files["control-manifest.json"] = json.dumps(
        build_manifest_payload(
            {key: value for key, value in files.items() if key != "control-manifest.json"}
        ),
        separators=(",", ":"),
        sort_keys=True,
    ).encode()

    with pytest.raises(GuardianError, match="^candidate_secret_detected$"):
        verify_candidate_archive(_archive(files))


def test_guardian_allows_secret_variable_reads() -> None:
    files = _candidate_files()
    files["src/unpinned_helper.py"] = (
        b'\nclient_secret = environment["CLIENT_SECRET"]\n'
    )
    files["control-manifest.json"] = json.dumps(
        build_manifest_payload(
            {key: value for key, value in files.items() if key != "control-manifest.json"}
        ),
        separators=(",", ":"),
        sort_keys=True,
    ).encode()

    assert verify_candidate_archive(_archive(files)).status == "passed"


def test_guardian_rejects_duplicate_policy_keys() -> None:
    files = _candidate_files()
    files["policy-v0.3.0.json"] = b'{"schema_version":2,"schema_version":2}'
    files["control-manifest.json"] = json.dumps(
        build_manifest_payload(
            {key: value for key, value in files.items() if key != "control-manifest.json"}
        ),
        separators=(",", ":"),
        sort_keys=True,
    ).encode()

    with pytest.raises(GuardianError, match="^candidate_trusted_file_hash_invalid$"):
        verify_candidate_archive(_archive(files))


def test_guardian_rejects_policy_without_required_render_owner_variable() -> None:
    files = _candidate_files()
    policy = json.loads(files["policy-v0.3.0.json"])
    policy["required_environment_variables"].remove("RENDER_OWNER_ID")
    files["policy-v0.3.0.json"] = json.dumps(policy, separators=(",", ":"), sort_keys=True).encode()
    files["control-manifest.json"] = json.dumps(
        build_manifest_payload(
            {key: value for key, value in files.items() if key != "control-manifest.json"}
        ),
        separators=(",", ":"),
        sort_keys=True,
    ).encode()

    with pytest.raises(GuardianError, match="^candidate_trusted_file_hash_invalid$"):
        verify_candidate_archive(_archive(files))
