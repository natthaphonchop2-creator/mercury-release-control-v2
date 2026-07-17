from __future__ import annotations

import re
from pathlib import Path

import yaml

WORKFLOW = Path(__file__).resolve().parents[1] / ".github/workflows/attest-v0.2.2.yml"
ACTION_PIN = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+@[0-9a-f]{40}$")


def test_attestation_workflow_is_pinned_single_artifact_and_dependency_ordered() -> None:
    text = WORKFLOW.read_text(encoding="utf-8")
    workflow = yaml.load(text, Loader=yaml.BaseLoader)

    assert workflow["permissions"] == {"actions": "write", "contents": "read"}
    job = workflow["jobs"]["attest"]
    assert job["environment"] == "production-release"
    steps = job["steps"]
    names = [step["name"] for step in steps]
    assert names.index("Verify GitHub identities and protected release environment") < names.index(
        "Build and publish exact history-free staging"
    )
    assert names.index("Build and publish exact history-free staging") < names.index(
        "Inspect every hosted and repository surface"
    )
    assert names.index("Inspect every hosted and repository surface") < names.index(
        "Assemble exact sanitized TrustedAttestationV2"
    )
    assert names.index("Assemble exact sanitized TrustedAttestationV2") < names.index(
        "Dispatch secretless Mercury artifact verification"
    )
    actions = [step["uses"] for step in steps if "uses" in step]
    assert len([action for action in actions if action.startswith("actions/upload-artifact@")]) == 1
    assert all(ACTION_PIN.fullmatch(action) for action in actions)
    assert "pull_request_target" not in text
    assert "release-v0.2.2.yml/dispatches" in text


def test_attestation_workflow_never_executes_candidate_files() -> None:
    text = WORKFLOW.read_text(encoding="utf-8")

    assert "pip install ." not in text
    assert "uv run --project $RUNNER_TEMP" not in text
    assert "source $RUNNER_TEMP" not in text
    assert "bash $RUNNER_TEMP" not in text
    assert 'git -C "$MIRROR" archive' in text
