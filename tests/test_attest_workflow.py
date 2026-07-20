from __future__ import annotations

import re
from pathlib import Path

import yaml

WORKFLOW = Path(__file__).resolve().parents[1] / ".github/workflows/attest-v0.3.0.yml"
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
    assert "release-v0.3.0.yml/dispatches" in text


def test_attestation_workflow_never_executes_candidate_files() -> None:
    text = WORKFLOW.read_text(encoding="utf-8")

    assert "pip install ." not in text
    assert "uv run --project $RUNNER_TEMP" not in text
    assert "source $RUNNER_TEMP" not in text
    assert "bash $RUNNER_TEMP" not in text
    assert 'git -C "$MIRROR" archive' in text


def test_attestation_workflow_supplies_render_owner_id_to_surface_inspector() -> None:
    workflow = yaml.load(WORKFLOW.read_text(encoding="utf-8"), Loader=yaml.BaseLoader)
    steps = workflow["jobs"]["attest"]["steps"]
    inspect_step = next(
        step for step in steps if step["name"] == "Inspect every hosted and repository surface"
    )

    assert inspect_step["env"]["RENDER_OWNER_ID"] == "${{ vars.RENDER_OWNER_ID }}"


def test_attestation_dispatch_does_not_relay_caller_supplied_staging_identity() -> None:
    text = WORKFLOW.read_text(encoding="utf-8")
    dispatch = text.split(
        "- name: Dispatch secretless Mercury artifact verification", 1
    )[1]

    assert "--arg staging_ref" not in dispatch
    assert "--arg public_tree_digest" not in dispatch
    assert "staging_ref:" not in dispatch
    assert "public_tree_digest:" not in dispatch
    assert "release_control_attestation_b64" in dispatch
