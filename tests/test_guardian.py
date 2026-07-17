from __future__ import annotations

import io
import json
import tarfile
from pathlib import Path

import pytest

from mercury_release_control.guardian import (
    GuardianError,
    build_manifest_payload,
    verify_candidate_archive,
)

CHECKOUT_PIN = "34e114876b0b11c390a56381ad16ebd13914f8d5"


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


def _candidate_files(marker: Path | None = None) -> dict[str, bytes]:
    payload = b"VALUE = 1\n"
    if marker is not None:
        payload = f"from pathlib import Path\nPath({str(marker)!r}).touch()\n".encode()
    files = {
        ".github/workflows/ci.yml": _ci_workflow(),
        ".github/workflows/guardian.yml": _guardian_workflow(),
        ".gitignore": b".venv/\n",
        "LICENSE": b"MIT\n",
        "README.md": b"Mercury release control\n",
        "policy-v0.2.2.json": json.dumps(
            {
                "release": {"tag": "v0.2.2", "version": "0.2.2"},
                "schema_version": 1,
            },
            separators=(",", ":"),
            sort_keys=True,
        ).encode(),
        "pyproject.toml": b"[project]\nname='mercury-release-control'\nversion='0.2.2'\n",
        "src/mercury_release_control/__init__.py": b"__version__ = '0.2.2'\n",
        "src/mercury_release_control/guardian.py": payload,
        "uv.lock": b"version = 1\n",
    }
    files["control-manifest.json"] = json.dumps(
        build_manifest_payload(files),
        separators=(",", ":"),
        sort_keys=True,
    ).encode()
    return files


def _archive(files: dict[str, bytes]) -> bytes:
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w:gz") as archive:
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
    assert receipt.file_count == 11
    assert not marker.exists()


def test_guardian_rejects_manifest_hash_drift() -> None:
    files = _candidate_files()
    files["src/mercury_release_control/guardian.py"] += b"CHANGED = True\n"

    with pytest.raises(GuardianError, match="^candidate_manifest_mismatch$"):
        verify_candidate_archive(_archive(files))


def test_guardian_rejects_unpinned_action() -> None:
    files = _candidate_files()
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
    files = _candidate_files()
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


def test_guardian_rejects_duplicate_policy_keys() -> None:
    files = _candidate_files()
    files["policy-v0.2.2.json"] = b'{"schema_version":1,"schema_version":1}'
    files["control-manifest.json"] = json.dumps(
        build_manifest_payload(
            {key: value for key, value in files.items() if key != "control-manifest.json"}
        ),
        separators=(",", ":"),
        sort_keys=True,
    ).encode()

    with pytest.raises(GuardianError, match="^candidate_policy_invalid$"):
        verify_candidate_archive(_archive(files))
