from __future__ import annotations

import copy
from datetime import UTC, datetime, timedelta

import pytest

from mercury_release_control.handoff import (
    HandoffError,
    ReleaseIdentity,
    verify_handoff,
)

NOW = datetime(2026, 7, 17, 10, 0, tzinfo=UTC)


@pytest.fixture
def expected() -> ReleaseIdentity:
    return ReleaseIdentity(
        control_artifact_digest="1" * 64,
        control_artifact_id=101,
        control_commit="2" * 40,
        control_payload_sha256="3" * 64,
        control_repository_id=42,
        control_run_attempt=1,
        control_run_id=1001,
        mercury_repository_id=84,
        mercury_run_attempt=2,
        mercury_run_id=2002,
        public_tree_digest="4" * 64,
        release_bundle_artifact_digest="8" * 64,
        release_bundle_artifact_id=303,
        reviewed_sha="5" * 40,
        staging_ref="v0.2.2-rc." + "5" * 12,
    )


@pytest.fixture
def payload(expected: ReleaseIdentity) -> dict[str, object]:
    return {
        "artifacts": [
            {
                "name": "mercury_tools-0.2.2-py3-none-any.whl",
                "sha256": "6" * 64,
                "size": 1234,
            },
            {
                "name": "mercury_tools-0.2.2.tar.gz",
                "sha256": "7" * 64,
                "size": 2345,
            },
        ],
        "created_at": NOW.isoformat(),
        "expires_at": (NOW + timedelta(minutes=60)).isoformat(),
        "mercury_workflow": {
            "repository_id": expected.mercury_repository_id,
            "run_attempt": expected.mercury_run_attempt,
            "run_id": expected.mercury_run_id,
            "workflow_path": ".github/workflows/release-v0.2.2.yml",
        },
        "original_release_control": {
            "artifact_digest": expected.control_artifact_digest,
            "artifact_id": expected.control_artifact_id,
            "commit": expected.control_commit,
            "payload_sha256": expected.control_payload_sha256,
            "repository_id": expected.control_repository_id,
            "run_attempt": expected.control_run_attempt,
            "run_id": expected.control_run_id,
        },
        "public_tree_digest": expected.public_tree_digest,
        "release_bundle": {
            "artifact_digest": "8" * 64,
            "artifact_id": 303,
            "name": "mercury-v0.2.2-release-artifacts-2002-attempt-2",
        },
        "reviewed_sha": expected.reviewed_sha,
        "schema_version": 2,
        "staging_ref": expected.staging_ref,
        "version": "0.2.2",
    }


@pytest.mark.parametrize(
    ("path", "value", "code"),
    [
        (("original_release_control", "repository_id"), 43, "handoff_control_identity_mismatch"),
        (("original_release_control", "run_id"), 1002, "handoff_control_identity_mismatch"),
        (("original_release_control", "run_attempt"), 2, "handoff_control_identity_mismatch"),
        (("original_release_control", "artifact_id"), 102, "handoff_control_identity_mismatch"),
        (
            ("original_release_control", "artifact_digest"),
            "0" * 64,
            "handoff_control_identity_mismatch",
        ),
        (("mercury_workflow", "repository_id"), 85, "handoff_mercury_identity_mismatch"),
        (("mercury_workflow", "run_id"), 2003, "handoff_mercury_identity_mismatch"),
        (("mercury_workflow", "run_attempt"), 3, "handoff_mercury_identity_mismatch"),
        (("release_bundle", "artifact_id"), 304, "handoff_mercury_identity_mismatch"),
        (
            ("release_bundle", "artifact_digest"),
            "9" * 64,
            "handoff_mercury_identity_mismatch",
        ),
        (("public_tree_digest",), "0" * 64, "handoff_release_identity_mismatch"),
        (("staging_ref",), "v0.2.2-rc." + "0" * 12, "handoff_release_identity_mismatch"),
    ],
)
def test_handoff_rejects_identity_mismatch(
    payload: dict[str, object],
    expected: ReleaseIdentity,
    path: tuple[str, ...],
    value: object,
    code: str,
) -> None:
    altered = copy.deepcopy(payload)
    target = altered
    for key in path[:-1]:
        target = target[key]
    target[path[-1]] = value

    with pytest.raises(HandoffError, match=f"^{code}$"):
        verify_handoff(altered, expected=expected, now=NOW + timedelta(minutes=5))


def test_handoff_accepts_exact_fresh_bounded_artifacts(
    payload: dict[str, object], expected: ReleaseIdentity
) -> None:
    verified = verify_handoff(payload, expected=expected, now=NOW + timedelta(minutes=5))

    assert verified.reviewed_sha == expected.reviewed_sha
    assert [asset.name for asset in verified.artifacts] == [
        "mercury_tools-0.2.2-py3-none-any.whl",
        "mercury_tools-0.2.2.tar.gz",
    ]


def test_handoff_rejects_stale_unknown_and_duplicate_assets(
    payload: dict[str, object], expected: ReleaseIdentity
) -> None:
    with pytest.raises(HandoffError, match="^handoff_expired$"):
        verify_handoff(payload, expected=expected, now=NOW + timedelta(hours=2))

    unknown = copy.deepcopy(payload)
    unknown["raw_token"] = "forbidden"
    with pytest.raises(HandoffError, match="^handoff_schema_invalid$"):
        verify_handoff(unknown, expected=expected, now=NOW)

    duplicate = copy.deepcopy(payload)
    duplicate["artifacts"].append(copy.deepcopy(duplicate["artifacts"][0]))
    with pytest.raises(HandoffError, match="^handoff_artifact_inventory_invalid$"):
        verify_handoff(duplicate, expected=expected, now=NOW)
