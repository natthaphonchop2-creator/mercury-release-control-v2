from __future__ import annotations

import re
from pathlib import Path

import yaml

WORKFLOW = Path(__file__).resolve().parents[1] / ".github/workflows/publish-v0.3.0.yml"
ACTION_PIN = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+@[0-9a-f]{40}$")


def test_publish_workflow_is_pinned_bounded_and_dependency_ordered() -> None:
    text = WORKFLOW.read_text(encoding="utf-8")
    workflow = yaml.load(text, Loader=yaml.BaseLoader)

    assert workflow["permissions"] == {"actions": "read", "contents": "read"}
    assert len(workflow["on"]["workflow_dispatch"]["inputs"]) <= 10
    job = workflow["jobs"]["publish"]
    assert job["environment"] == "production-release"
    steps = job["steps"]
    names = [step["name"] for step in steps]
    assert names.index("Verify exact Mercury run and artifact metadata") < names.index(
        "Download exact release-ready handoff"
    )
    assert names.index(
        "Strictly inspect handoff and derive trusted control identity"
    ) < names.index("Verify original control run and attestation artifact metadata")
    assert names.index("Download exact Mercury release bundle") < names.index(
        "Publish draft-verified immutable release"
    )
    assert names.index("Publish draft-verified immutable release") < names.index(
        "Verify anonymous public tag and plugin surface"
    )
    actions = [step["uses"] for step in steps if "uses" in step]
    assert actions.count("actions/download-artifact@d3f86a106a0bac45b974a628896c90dbdf5c8093") == 3
    assert all(ACTION_PIN.fullmatch(action) for action in actions)


def test_publish_workflow_has_no_force_overwrite_or_candidate_execution_path() -> None:
    text = WORKFLOW.read_text(encoding="utf-8")

    assert "contents: write" not in text
    assert "--force" not in text
    assert "git push" not in text
    assert "gh release" not in text
    assert "releases/delete" not in text
    assert "pip install ." not in text
    assert "uv run --project" not in text
    assert "MERCURY_TARGET_REPOSITORY_TOKEN" not in next(
        step
        for step in yaml.load(text, Loader=yaml.BaseLoader)["jobs"]["publish"]["steps"]
        if step["name"] == "Verify anonymous public tag and plugin surface"
    ).get("env", {})
