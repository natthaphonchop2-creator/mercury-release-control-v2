from __future__ import annotations

import base64
import copy
import hashlib
import io
import json
import tarfile
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from pydantic import SecretStr

from mercury_release_control import publish_workflow
from mercury_release_control.attestation import assemble_attestation, validate_attestation
from mercury_release_control.handoff import HandoffError, ReleaseIdentity, verify_handoff
from mercury_release_control.preflight import PreflightReceipt
from mercury_release_control.provider_inspector import InspectionError, inspect_provider_state
from mercury_release_control.publication import (
    RemoteAsset,
    RemoteRelease,
    RemoteTag,
    publication_plan,
)
from mercury_release_control.publish_workflow import inspect_handoff, run_publication
from mercury_release_control.staging import build_staging
from mercury_release_control.surface_inspector import validate_policy

ROOT = Path(__file__).resolve().parents[1]
POLICY_PATH = ROOT / "policy-v0.2.2.json"
FIXTURE_PATH = ROOT / "tests/fixtures/public-tree-v1.json"
ATTEST_WORKFLOW = ROOT / ".github/workflows/attest-v0.2.2.yml"
PUBLISH_WORKFLOW = ROOT / ".github/workflows/publish-v0.2.2.yml"
NOW = datetime(2026, 7, 17, 10, 0, tzinfo=UTC)
CONTROL_REPOSITORY_ID = 1303413748
MERCURY_REPOSITORY_ID = 1290137723
REVIEWED_SHA = "a" * 40


def _archive() -> bytes:
    fixture = json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))
    output = io.BytesIO()
    with tarfile.open(
        fileobj=output,
        mode="w",
        format=tarfile.PAX_FORMAT,
        pax_headers={"comment": REVIEWED_SHA},
    ) as archive:
        for raw in fixture["members"]:
            content = base64.b64decode(raw["content_b64"], validate=True)
            member = tarfile.TarInfo(raw["path"])
            member.mode = raw["mode"]
            member.size = len(content)
            archive.addfile(member, io.BytesIO(content))
    return output.getvalue()


def _provider_state() -> dict[str, object]:
    return {
        "flowaccount": {"environment": "sandbox", "read_only": True, "status": 200},
        "public_mcp": {
            "catalog_action_count": 254,
            "flowaccount_citations": 1,
            "hosted_tool_count": 20,
            "peak_citations": 1,
            "status": 200,
            "write_tools_exposed": False,
        },
        "render": {
            "catalog_action_count": 254,
            "commit": REVIEWED_SHA,
            "hosted_tool_count": 20,
            "logs_scanned": True,
            "status": "live",
            "version": "0.2.2",
        },
        "supabase": {
            "function_count": 10,
            "migration_id": "20260716100000",
            "project_ref_sha256": "1" * 64,
            "rag_identity_count": 254,
            "read_only": True,
            "schema_sha256": "2" * 64,
            "table_count": 17,
        },
    }


def _surface_evidence() -> dict[str, object]:
    names = (
        "git_all_refs",
        "github_pull_request_refs",
        "github_releases_and_assets",
        "github_actions_logs_artifacts_caches",
        "github_packages_pages_wiki",
        "marketplace_snapshot",
        "render_build_and_runtime_logs",
        "supabase_knowledge_and_storage",
    )
    return {
        "reviewed_commit_sha": REVIEWED_SHA,
        "surfaces": [
            {
                "blocker_codes": [],
                "completed_at": NOW.isoformat(),
                "evidence_hashes": ["f" * 64],
                "exit_codes": [0],
                "finding_codes": [],
                "finding_count": 0,
                "scanner_versions": (
                    ["1.0.0", "3.88.32", "8.24.3"]
                    if name in {"git_all_refs", "github_pull_request_refs"}
                    else ["1.0.0"]
                ),
                "started_at": (NOW - timedelta(minutes=1)).isoformat(),
                "status": "passed",
                "surface": name,
            }
            for name in names
        ],
    }


def _release_identity() -> ReleaseIdentity:
    return ReleaseIdentity(
        control_artifact_digest="4" * 64,
        control_artifact_id=101,
        control_commit="b" * 40,
        control_payload_sha256="5" * 64,
        control_repository_id=CONTROL_REPOSITORY_ID,
        control_run_attempt=3,
        control_run_id=1001,
        mercury_repository_id=MERCURY_REPOSITORY_ID,
        mercury_run_attempt=2,
        mercury_run_id=2002,
        public_tree_digest="6" * 64,
        release_bundle_artifact_digest="8" * 64,
        release_bundle_artifact_id=303,
        reviewed_sha=REVIEWED_SHA,
        staging_ref=f"v0.2.2-rc.{REVIEWED_SHA[:12]}",
        version="0.2.2",
    )


def _handoff_payload(expected: ReleaseIdentity) -> dict[str, object]:
    return {
        "artifacts": [
            {
                "name": "mercury_tools-0.2.2-py3-none-any.whl",
                "sha256": "7" * 64,
                "size": 123,
            }
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
            "artifact_digest": expected.release_bundle_artifact_digest,
            "artifact_id": expected.release_bundle_artifact_id,
            "name": "mercury-v0.2.2-release-artifacts-2002-attempt-2",
        },
        "reviewed_sha": expected.reviewed_sha,
        "schema_version": 3,
        "staging_ref": expected.staging_ref,
        "version": "0.2.2",
    }


class _PublicationBackend:
    def __init__(self) -> None:
        self.tag: RemoteTag | None = None
        self.release: RemoteRelease | None = None
        self.assets: dict[str, bytes] = {}
        self.immutable = False

    def read_tag(self, _tag: str) -> RemoteTag | None:
        return self.tag

    def create_tag(self, *, tag: str, commit: str, message: str) -> RemoteTag:
        assert message == "Mercury v0.2.2"
        self.tag = RemoteTag(annotated=True, commit=commit, name=tag)
        return self.tag

    def read_release(self, _tag: str) -> RemoteRelease | None:
        return self.release

    def create_draft(self, *, tag: str, name: str, body: str) -> RemoteRelease:
        assert body.startswith("# Mercury Finance v0.2.2")
        self.release = RemoteRelease(
            assets=(),
            draft=True,
            immutable=False,
            name=name,
            release_id=900,
            tag=tag,
        )
        return self.release

    def upload_asset(self, release_id: int, asset, content: bytes) -> None:
        assert release_id == 900
        self.assets[asset.name] = content
        remote = RemoteAsset(name=asset.name, sha256=asset.sha256, size=asset.size)
        self.release = replace(self.release, assets=(*self.release.assets, remote))

    def download_asset(self, release_id: int, name: str) -> bytes:
        assert release_id == 900
        return self.assets[name]

    def immutable_enabled(self) -> bool:
        return self.immutable

    def enable_immutable(self) -> None:
        self.immutable = True
        self.release = replace(self.release, immutable=True)

    def publish(self, release_id: int) -> None:
        assert release_id == 900
        self.release = replace(self.release, draft=False)


def test_v022_shared_controls_execute_exact_release_path_end_to_end(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    policy = json.loads(POLICY_PATH.read_text(encoding="utf-8"))
    policy["bootstrap_state"] = "configured"
    assert validate_policy(policy)["release"] == {"tag": "v0.2.2", "version": "0.2.2"}

    staging = build_staging(
        archive_bytes=_archive(),
        reviewed_sha=REVIEWED_SHA,
        output=tmp_path / "staging",
        version="0.2.2",
    )
    providers = inspect_provider_state(
        _provider_state(), reviewed_sha=REVIEWED_SHA, version="0.2.2"
    )
    preflight = PreflightReceipt(
        admin_bypass_disabled=True,
        control_repository_id=CONTROL_REPOSITORY_ID,
        environment="production-release",
        prevent_self_review=True,
        protected_branch_only=True,
        required_configuration_sha256="3" * 64,
        required_reviewers=1,
        target_repository_id=MERCURY_REPOSITORY_ID,
    )
    attestation = assemble_attestation(
        evidence=providers,
        preflight=preflight,
        staging=staging,
        control_commit="b" * 40,
        run_id=1001,
        run_attempt=3,
        now=NOW,
        surface_evidence=_surface_evidence(),
        version="0.2.2",
    )
    validate_attestation(attestation, now=NOW + timedelta(minutes=5))

    attestation_body = (
        json.dumps(attestation.model_dump(mode="json"), separators=(",", ":"), sort_keys=True)
        + "\n"
    ).encode()
    wheel = b"v0.2.2-wheel"
    release_bundle_digest = "8" * 64
    handoff_payload = {
        "artifacts": [
            {
                "name": "mercury_tools-0.2.2-py3-none-any.whl",
                "sha256": hashlib.sha256(wheel).hexdigest(),
                "size": len(wheel),
            }
        ],
        "created_at": NOW.isoformat(),
        "expires_at": (NOW + timedelta(minutes=60)).isoformat(),
        "mercury_workflow": {
            "repository_id": MERCURY_REPOSITORY_ID,
            "run_attempt": 2,
            "run_id": 2002,
            "workflow_path": ".github/workflows/release-v0.2.2.yml",
        },
        "original_release_control": {
            "artifact_digest": "4" * 64,
            "artifact_id": 101,
            "commit": "b" * 40,
            "payload_sha256": hashlib.sha256(attestation_body).hexdigest(),
            "repository_id": CONTROL_REPOSITORY_ID,
            "run_attempt": 3,
            "run_id": 1001,
        },
        "public_tree_digest": staging.tree_digest,
        "release_bundle": {
            "artifact_digest": release_bundle_digest,
            "artifact_id": 303,
            "name": "mercury-v0.2.2-release-artifacts-2002-attempt-2",
        },
        "reviewed_sha": REVIEWED_SHA,
        "schema_version": 3,
        "staging_ref": staging.tag,
        "version": "0.2.2",
    }
    handoff_path = tmp_path / "handoff.json"
    handoff_path.write_text(json.dumps(handoff_payload, sort_keys=True), encoding="utf-8")
    expected = inspect_handoff(
        control_commit="b" * 40,
        handoff_path=handoff_path,
        handoff_payload_sha256=hashlib.sha256(handoff_path.read_bytes()).hexdigest(),
        mercury_run_attempt=2,
        mercury_run_id=2002,
        output=tmp_path / "identity.json",
        policy_path=POLICY_PATH,
        release_bundle_artifact_digest=release_bundle_digest,
        release_bundle_artifact_id=303,
        reviewed_sha=REVIEWED_SHA,
        now=NOW + timedelta(minutes=5),
    )
    verified = verify_handoff(
        handoff_payload,
        expected=expected,
        now=NOW + timedelta(minutes=5),
    )
    plan = publication_plan(verified, release_notes="Mercury v0.2.2 compatibility")
    assets_path = tmp_path / "assets"
    assets_path.mkdir()
    (assets_path / "mercury_tools-0.2.2-py3-none-any.whl").write_bytes(wheel)
    attestation_path = tmp_path / "attestation.json"
    attestation_path.write_bytes(attestation_body)
    publication_output = tmp_path / "publication.json"
    backend = _PublicationBackend()

    def backend_factory(*, repository: str, token: SecretStr):
        assert repository == "natthaphonchop2-creator/mercury-tools"
        assert token.get_secret_value() == "test-token"
        return backend

    monkeypatch.setattr(publish_workflow, "GitHubPublicationBackend", backend_factory)
    run_publication(
        assets_path=assets_path,
        expected=expected,
        handoff_path=handoff_path,
        handoff_payload_sha256=hashlib.sha256(handoff_path.read_bytes()).hexdigest(),
        original_attestation_path=attestation_path,
        output=publication_output,
        policy_path=POLICY_PATH,
        release_notes_path=ROOT / "release-notes-v0.2.2.md",
        token=SecretStr("test-token"),
        now=NOW + timedelta(minutes=5),
    )

    assert staging.tag == f"v0.2.2-rc.{REVIEWED_SHA[:12]}"
    assert providers.version == "0.2.2"
    assert providers.render.hosted_tool_count == 20
    assert providers.supabase.migration_id == "20260716100000"
    assert preflight.environment == "production-release"
    assert attestation.workflow.repository_id == CONTROL_REPOSITORY_ID
    assert attestation.workflow.attempt == 3
    assert expected.control_artifact_digest == "4" * 64
    assert expected.release_bundle_artifact_digest == release_bundle_digest
    assert expected.reviewed_sha == REVIEWED_SHA
    assert plan.tag == "v0.2.2"
    assert json.loads(publication_output.read_text(encoding="utf-8")) == {
        "release_id": 900,
        "state": "published_immutable",
        "tag": "v0.2.2",
    }


@pytest.mark.parametrize(
    ("mutation", "code"),
    [
        (
            lambda payload: payload["original_release_control"].update(repository_id=1),
            "handoff_control_identity_mismatch",
        ),
        (
            lambda payload: payload["original_release_control"].update(run_attempt=4),
            "handoff_control_identity_mismatch",
        ),
        (
            lambda payload: payload["original_release_control"].update(
                artifact_digest="0" * 64
            ),
            "handoff_control_identity_mismatch",
        ),
        (
            lambda payload: payload["mercury_workflow"].update(repository_id=1),
            "handoff_mercury_identity_mismatch",
        ),
        (
            lambda payload: payload["mercury_workflow"].update(run_attempt=3),
            "handoff_mercury_identity_mismatch",
        ),
        (
            lambda payload: payload["release_bundle"].update(artifact_digest="0" * 64),
            "handoff_mercury_identity_mismatch",
        ),
        (
            lambda payload: payload.update(reviewed_sha="b" * 40),
            "handoff_release_identity_mismatch",
        ),
        (
            lambda payload: payload.update(staging_ref="v0.2.2-rc." + "b" * 12),
            "handoff_release_identity_mismatch",
        ),
    ],
)
def test_v022_handoff_preserves_attempt_digest_repository_sha_and_tag_checks(
    mutation, code: str
) -> None:
    expected = _release_identity()
    payload = copy.deepcopy(_handoff_payload(expected))
    mutation(payload)

    with pytest.raises(HandoffError, match=f"^{code}$"):
        verify_handoff(payload, expected=expected, now=NOW + timedelta(minutes=5))


@pytest.mark.parametrize(
    ("mutation", "code"),
    [
        (
            lambda state: state["render"].update(hosted_tool_count=24),
            "render_tool_inventory_invalid",
        ),
        (
            lambda state: state["flowaccount"].update(environment="production"),
            "flowaccount_sandbox_read_failed",
        ),
        (
            lambda state: state["supabase"].update(migration_id="20260719120000"),
            "supabase_migration_invalid",
        ),
    ],
)
def test_v022_provider_state_preserves_inventory_environment_and_migration_checks(
    mutation, code: str
) -> None:
    state = copy.deepcopy(_provider_state())
    mutation(state)

    with pytest.raises(InspectionError, match=f"^{code}$"):
        inspect_provider_state(state, reviewed_sha=REVIEWED_SHA, version="0.2.2")


def test_v022_dispatch_workflows_bind_every_shared_control_to_v022_policy() -> None:
    attest = ATTEST_WORKFLOW.read_text(encoding="utf-8")
    publish = PUBLISH_WORKFLOW.read_text(encoding="utf-8")

    assert attest.count("--policy policy-v0.2.2.json") == 5
    assert "release-v0.2.2.yml/dispatches" in attest
    assert '.path == ".github/workflows/release-v0.2.2.yml"' in publish
    assert '.path == ".github/workflows/attest-v0.2.2.yml"' in publish
    for binding in ("repository_id", "run_attempt", "artifact_digest", "reviewed_commit_sha"):
        assert binding in attest
        assert binding in publish
