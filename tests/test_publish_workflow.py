from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime, timedelta

import pytest

from mercury_release_control.handoff import HandoffError
from mercury_release_control.publish_workflow import inspect_handoff

NOW = datetime(2026, 7, 17, 10, 0, tzinfo=UTC)
CONTROL_COMMIT = "1" * 40
REVIEWED_SHA = "2" * 40


def _payload() -> dict[str, object]:
    return {
        "artifacts": [
            {
                "name": "mercury_tools-0.2.2-py3-none-any.whl",
                "sha256": "3" * 64,
                "size": 123,
            }
        ],
        "created_at": NOW.isoformat(),
        "expires_at": (NOW + timedelta(minutes=60)).isoformat(),
        "mercury_workflow": {
            "repository_id": 84,
            "run_attempt": 2,
            "run_id": 2002,
            "workflow_path": ".github/workflows/release-v0.2.2.yml",
        },
        "original_release_control": {
            "artifact_digest": "4" * 64,
            "artifact_id": 101,
            "commit": CONTROL_COMMIT,
            "payload_sha256": "5" * 64,
            "repository_id": 42,
            "run_attempt": 1,
            "run_id": 1001,
        },
        "public_tree_digest": "6" * 64,
        "release_bundle": {
            "artifact_digest": "7" * 64,
            "artifact_id": 303,
            "name": "mercury-v0.2.2-release-artifacts-2002-attempt-2",
        },
        "reviewed_sha": REVIEWED_SHA,
        "schema_version": 2,
        "staging_ref": f"v0.2.2-rc.{REVIEWED_SHA[:12]}",
        "version": "0.2.2",
    }


def _write_inputs(tmp_path):
    handoff = tmp_path / "handoff.json"
    handoff.write_text(json.dumps(_payload(), sort_keys=True), encoding="utf-8")
    policy = tmp_path / "policy.json"
    policy.write_text(
        json.dumps({"repository_id": 42, "reviewed_repository_id": 84}),
        encoding="utf-8",
    )
    return handoff, policy


def test_inspect_handoff_emits_normalized_attempt_bound_identity(tmp_path) -> None:
    handoff, policy = _write_inputs(tmp_path)
    output = tmp_path / "identity.json"

    identity = inspect_handoff(
        control_commit=CONTROL_COMMIT,
        handoff_path=handoff,
        handoff_payload_sha256=hashlib.sha256(handoff.read_bytes()).hexdigest(),
        mercury_run_attempt=2,
        mercury_run_id=2002,
        output=output,
        policy_path=policy,
        release_bundle_artifact_digest="7" * 64,
        release_bundle_artifact_id=303,
        reviewed_sha=REVIEWED_SHA,
        now=NOW + timedelta(minutes=5),
    )

    assert identity.control_repository_id == 42
    assert identity.mercury_repository_id == 84
    assert json.loads(output.read_text(encoding="utf-8"))["control_run_id"] == 1001


@pytest.mark.parametrize(
    ("override", "code"),
    [
        ({"control_commit": "9" * 40}, "handoff_control_identity_mismatch"),
        ({"mercury_run_id": 2003}, "handoff_mercury_identity_mismatch"),
        ({"release_bundle_artifact_id": 304}, "handoff_mercury_identity_mismatch"),
        ({"reviewed_sha": "8" * 40}, "handoff_release_identity_mismatch"),
    ],
)
def test_inspect_handoff_rejects_dispatch_identity_drift(
    tmp_path, override: dict[str, object], code: str
) -> None:
    handoff, policy = _write_inputs(tmp_path)
    arguments = {
        "control_commit": CONTROL_COMMIT,
        "handoff_path": handoff,
        "handoff_payload_sha256": hashlib.sha256(handoff.read_bytes()).hexdigest(),
        "mercury_run_attempt": 2,
        "mercury_run_id": 2002,
        "output": tmp_path / "identity.json",
        "policy_path": policy,
        "release_bundle_artifact_digest": "7" * 64,
        "release_bundle_artifact_id": 303,
        "reviewed_sha": REVIEWED_SHA,
        "now": NOW + timedelta(minutes=5),
    }
    arguments.update(override)

    with pytest.raises(HandoffError, match=f"^{code}$"):
        inspect_handoff(**arguments)


def test_inspect_handoff_rejects_payload_digest_before_writing(tmp_path) -> None:
    handoff, policy = _write_inputs(tmp_path)
    output = tmp_path / "identity.json"

    with pytest.raises(HandoffError, match="^handoff_payload_digest_mismatch$"):
        inspect_handoff(
            control_commit=CONTROL_COMMIT,
            handoff_path=handoff,
            handoff_payload_sha256="0" * 64,
            mercury_run_attempt=2,
            mercury_run_id=2002,
            output=output,
            policy_path=policy,
            release_bundle_artifact_digest="7" * 64,
            release_bundle_artifact_id=303,
            reviewed_sha=REVIEWED_SHA,
            now=NOW,
        )

    assert not output.exists()
