from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

import yaml

from mercury_release_control import guardian
from mercury_release_control.provider_inspector import inspect_provider_state
from mercury_release_control.surface_inspector import validate_policy

ROOT = Path(__file__).resolve().parents[1]
POLICY_PATH = ROOT / "policy-v0.3.0.json"
ATTEST_WORKFLOW = ROOT / ".github/workflows/attest-v0.3.0.yml"
PUBLISH_WORKFLOW = ROOT / ".github/workflows/publish-v0.3.0.yml"
RELEASE_NOTES = ROOT / "release-notes-v0.3.0.md"
CONTROL_REPOSITORY_ID = 1303413748
MERCURY_REPOSITORY_ID = 1290137723
REVIEWED_SHA = "a" * 40


def _json(path: Path) -> dict[str, object]:
    if not path.is_file():
        return {}
    payload = json.loads(path.read_text(encoding="utf-8"))
    assert isinstance(payload, dict)
    return payload


def _workflow(path: Path) -> dict[str, object]:
    if not path.is_file():
        return {}
    payload = yaml.load(path.read_text(encoding="utf-8"), Loader=yaml.BaseLoader)
    assert isinstance(payload, dict)
    return payload


def _provider_state() -> dict[str, object]:
    return {
        "flowaccount": {
            "environment": "sandbox",
            "read_only": True,
            "status": 200,
        },
        "public_mcp": {
            "catalog_action_count": 254,
            "flowaccount_citations": 1,
            "hosted_tool_count": 24,
            "peak_citations": 1,
            "status": 200,
            "write_tools_exposed": False,
        },
        "render": {
            "catalog_action_count": 254,
            "commit": REVIEWED_SHA,
            "hosted_tool_count": 24,
            "logs_scanned": True,
            "status": "live",
            "version": "0.3.0",
        },
        "supabase": {
            "function_count": 11,
            "migration_id": "20260719120000",
            "project_ref_sha256": "1" * 64,
            "rag_identity_count": 254,
            "read_only": True,
            "schema_sha256": "2" * 64,
            "table_count": 17,
        },
    }


def test_v030_policy_preserves_exact_trust_and_provider_bindings() -> None:
    policy = _json(POLICY_PATH)

    assert policy.get("repository_id") == CONTROL_REPOSITORY_ID
    assert policy.get("reviewed_repository_id") == MERCURY_REPOSITORY_ID
    assert policy.get("release") == {"tag": "v0.3.0", "version": "0.3.0"}
    assert policy.get("staging") == {
        "repository": "natthaphonchop2-creator/mercury-tools-staging",
        "tag_prefix": "v0.3.0-rc.",
    }
    assert policy.get("release_tag_ruleset", {}).get("conditions") == {
        "ref_name": {"exclude": [], "include": ["refs/tags/v0.3.0"]}
    }
    assert policy.get("supabase", {}).get("migration_id") == "20260719120000"
    assert len(policy.get("supabase", {}).get("functions", [])) == 11
    assert policy.get("provider_expectations") == {
        "catalog_action_count": 254,
        "flowaccount_environment": "sandbox",
        "hosted_tool_count": 24,
        "supabase_function_count": 11,
        "supabase_table_count": 17,
    }


def test_committed_v022_policy_is_configured_and_validates_without_mutation() -> None:
    policy = _json(ROOT / "policy-v0.2.2.json")
    original = json.loads(json.dumps(policy))

    validated = validate_policy(policy)

    assert validated["release"] == {"tag": "v0.2.2", "version": "0.2.2"}
    assert policy == original
    assert policy["bootstrap_state"] == "configured"


def test_committed_v030_policy_is_configured_without_claiming_provider_readiness() -> None:
    policy = _json(POLICY_PATH)
    original = json.loads(json.dumps(policy))

    validated = validate_policy(policy)

    assert policy == original
    assert validated["release"] == {"tag": "v0.3.0", "version": "0.3.0"}
    assert policy["bootstrap_state"] == "configured"
    assert policy["supabase"]["migration_id"] == "20260719120000"
    assert (
        policy["supabase"]["migration_history_sha256"]
        == "efc2b2ece5efa30008b7fb86097f43b205abb057acf4e2b470767555fc463db7"
    )


def test_committed_policies_pin_the_version_isolated_shared_inspector() -> None:
    inspector_digest = hashlib.sha256(
        (ROOT / "src/mercury_release_control/surface_inspector.py").read_bytes()
    ).hexdigest()

    for version in ("0.2.2", "0.3.0"):
        policy = _json(ROOT / f"policy-v{version}.json")
        assert policy["inspector"]["sha256"] == inspector_digest


def test_v030_provider_state_is_exact_and_fail_closed() -> None:
    evidence = inspect_provider_state(
        _provider_state(),
        reviewed_sha=REVIEWED_SHA,
        version="0.3.0",
    )

    assert evidence.version == "0.3.0"
    assert evidence.render.hosted_tool_count == 24
    assert evidence.supabase.migration_id == "20260719120000"
    assert evidence.supabase.function_count == 11


def test_v030_workflows_keep_attempt_digest_repository_and_sha_bindings() -> None:
    attest = _workflow(ATTEST_WORKFLOW)
    publish = _workflow(PUBLISH_WORKFLOW)
    attest_text = ATTEST_WORKFLOW.read_text(encoding="utf-8") if ATTEST_WORKFLOW.is_file() else ""
    publish_text = (
        PUBLISH_WORKFLOW.read_text(encoding="utf-8") if PUBLISH_WORKFLOW.is_file() else ""
    )

    assert attest.get("permissions") == {"actions": "write", "contents": "read"}
    assert publish.get("permissions") == {"actions": "read", "contents": "read"}
    assert "policy-v0.3.0.json" in attest_text
    assert "release-v0.3.0.yml/dispatches" in attest_text
    assert (
        "mercury-v0.3.0-attestation-${{ github.run_id }}-attempt-${{ github.run_attempt }}"
    ) in attest_text
    assert "policy-v0.3.0.json" in publish_text
    assert '.path == ".github/workflows/release-v0.3.0.yml"' in publish_text
    assert '.path == ".github/workflows/attest-v0.3.0.yml"' in publish_text
    for binding in (
        "repository_id",
        "run_attempt",
        "artifact_digest",
        "reviewed_commit_sha",
    ):
        assert binding in attest_text
        assert binding in publish_text
    for workflow in (attest, publish):
        for job in workflow.get("jobs", {}).values():
            for step in job.get("steps", []):
                action = step.get("uses")
                if action is not None:
                    assert re.fullmatch(r"[^@]+@[0-9a-f]{40}", action)


def test_v030_guardian_and_manifest_cover_new_critical_controls() -> None:
    expected = {
        ".github/workflows/attest-v0.3.0.yml",
        ".github/workflows/migrate-v0.3.0.yml",
        ".github/workflows/publish-v0.3.0.yml",
        "policy-v0.3.0.json",
        "release-notes-v0.3.0.md",
        "src/mercury_release_control/production_migration.py",
    }
    assert "policy-v0.3.0.json" in guardian.REQUIRED_FILES
    assert guardian._ALLOWED_PERMISSIONS["attest-v0.3.0.yml"] == {
        "actions": "write",
        "contents": "read",
    }
    assert guardian._ALLOWED_PERMISSIONS["migrate-v0.3.0.yml"] == {"contents": "read"}
    assert guardian._ALLOWED_PERMISSIONS["publish-v0.3.0.yml"] == {
        "actions": "read",
        "contents": "read",
    }

    manifest = _json(ROOT / "control-manifest.json").get("files", {})
    assert expected.issubset(manifest)
    for relative_path in expected:
        assert (
            manifest[relative_path]
            == hashlib.sha256((ROOT / relative_path).read_bytes()).hexdigest()
        )


def test_v030_release_notes_are_candidate_only_and_secretless() -> None:
    text = RELEASE_NOTES.read_text(encoding="utf-8") if RELEASE_NOTES.is_file() else ""

    assert text.startswith("# Mercury Finance v0.3.0")
    assert "connector-neutral" in text.casefold()
    assert "20260719120000" in text
    assert "no ERP credentials" in text
    assert "published" not in text.casefold()
