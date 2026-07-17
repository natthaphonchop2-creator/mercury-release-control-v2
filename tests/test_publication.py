from __future__ import annotations

import hashlib
import json
from dataclasses import replace

import pytest

from mercury_release_control.handoff import ReleaseArtifact, VerifiedHandoff
from mercury_release_control.publication import (
    PublicationError,
    PublicationState,
    RemoteAsset,
    RemoteRelease,
    RemoteTag,
    publication_plan,
    publish_release,
    require_transition,
)

COMMIT = "a" * 40
WHEEL = b"wheel-bytes"
SDIST = b"sdist-bytes"


def _handoff() -> VerifiedHandoff:
    return VerifiedHandoff.model_validate_json(
        json.dumps(
            {
                "artifacts": [
                    {
                        "name": "mercury_tools-0.2.2-py3-none-any.whl",
                        "sha256": hashlib.sha256(WHEEL).hexdigest(),
                        "size": len(WHEEL),
                    },
                    {
                        "name": "mercury_tools-0.2.2.tar.gz",
                        "sha256": hashlib.sha256(SDIST).hexdigest(),
                        "size": len(SDIST),
                    },
                ],
                "created_at": "2026-07-17T10:00:00Z",
                "expires_at": "2026-07-17T11:00:00Z",
                "mercury_workflow": {
                    "repository_id": 84,
                    "run_attempt": 1,
                    "run_id": 2002,
                    "workflow_path": ".github/workflows/release-v0.2.2.yml",
                },
                "original_release_control": {
                    "artifact_digest": "1" * 64,
                    "artifact_id": 101,
                    "commit": "2" * 40,
                    "payload_sha256": "3" * 64,
                    "repository_id": 42,
                    "run_attempt": 1,
                    "run_id": 1001,
                },
                "public_tree_digest": "4" * 64,
                "release_bundle": {
                    "artifact_digest": "8" * 64,
                    "artifact_id": 303,
                    "name": "mercury-v0.2.2-release-artifacts-2002-attempt-1",
                },
                "reviewed_sha": COMMIT,
                "schema_version": 3,
                "staging_ref": "v0.2.2-rc." + COMMIT[:12],
                "version": "0.2.2",
            }
        )
    )


class FakeBackend:
    def __init__(self) -> None:
        self.calls: list[str] = []
        self.tag: RemoteTag | None = None
        self.release: RemoteRelease | None = None
        self.contents: dict[str, bytes] = {}
        self.immutability = False

    def read_tag(self, tag: str) -> RemoteTag | None:
        self.calls.append("read_tag")
        return self.tag

    def create_tag(self, *, tag: str, commit: str, message: str) -> RemoteTag:
        self.calls.append("create_tag")
        self.tag = RemoteTag(annotated=True, commit=commit, name=tag)
        return self.tag

    def read_release(self, tag: str) -> RemoteRelease | None:
        self.calls.append("read_release")
        return self.release

    def create_draft(self, *, tag: str, name: str, body: str) -> RemoteRelease:
        self.calls.append("create_draft")
        self.release = RemoteRelease(
            assets=(),
            draft=True,
            immutable=False,
            name=name,
            release_id=900,
            tag=tag,
        )
        return self.release

    def upload_asset(self, release_id: int, asset: ReleaseArtifact, content: bytes) -> None:
        self.calls.append(f"upload:{asset.name}")
        self.contents[asset.name] = content
        remote = RemoteAsset(name=asset.name, sha256=asset.sha256, size=asset.size)
        self.release = replace(
            self.release,
            assets=(*self.release.assets, remote),
        )

    def download_asset(self, release_id: int, name: str) -> bytes:
        self.calls.append(f"download:{name}")
        return self.contents[name]

    def publish(self, release_id: int) -> None:
        self.calls.append("publish")
        self.release = replace(self.release, draft=False)

    def immutable_enabled(self) -> bool:
        self.calls.append("immutable_enabled")
        return self.immutability

    def enable_immutable(self) -> None:
        self.calls.append("enable_immutable")
        self.immutability = True
        self.release = replace(self.release, immutable=True)


class IgnoringImmutableBackend(FakeBackend):
    def enable_immutable(self) -> None:
        self.calls.append("enable_immutable")


def test_publication_state_machine_rejects_skip_and_reverse() -> None:
    require_transition(PublicationState.PRECONDITIONS_VERIFIED, PublicationState.TAG_CREATED)
    with pytest.raises(PublicationError, match="^publication_transition_invalid$"):
        require_transition(
            PublicationState.PRECONDITIONS_VERIFIED,
            PublicationState.PUBLISHED_IMMUTABLE,
        )
    with pytest.raises(PublicationError, match="^publication_transition_invalid$"):
        require_transition(PublicationState.DRAFT_VERIFIED, PublicationState.TAG_CREATED)


def test_publication_checks_all_assets_before_first_tag_api_call() -> None:
    plan = publication_plan(_handoff(), release_notes="Mercury v0.2.2")
    backend = FakeBackend()

    with pytest.raises(PublicationError, match="^publication_asset_digest_mismatch$"):
        publish_release(
            plan,
            backend=backend,
            assets={
                "mercury_tools-0.2.2-py3-none-any.whl": b"tampered",
                "mercury_tools-0.2.2.tar.gz": SDIST,
            },
        )

    assert backend.calls == []


def test_publication_rejects_mismatched_existing_tag_release_and_assets() -> None:
    plan = publication_plan(_handoff(), release_notes="Mercury v0.2.2")
    assets = {
        "mercury_tools-0.2.2-py3-none-any.whl": WHEEL,
        "mercury_tools-0.2.2.tar.gz": SDIST,
    }
    backend = FakeBackend()
    backend.tag = RemoteTag(annotated=True, commit="b" * 40, name="v0.2.2")
    with pytest.raises(PublicationError, match="^publication_tag_mismatch$"):
        publish_release(plan, backend=backend, assets=assets)

    backend = FakeBackend()
    backend.tag = RemoteTag(annotated=True, commit=COMMIT, name="v0.2.2")
    backend.release = RemoteRelease(
        assets=(),
        draft=False,
        immutable=False,
        name="wrong",
        release_id=900,
        tag="v0.2.2",
    )
    with pytest.raises(PublicationError, match="^publication_release_exists$"):
        publish_release(plan, backend=backend, assets=assets)

    backend = FakeBackend()
    backend.tag = RemoteTag(annotated=True, commit=COMMIT, name="v0.2.2")
    backend.release = RemoteRelease(
        assets=(RemoteAsset(name="existing.whl", sha256="0" * 64, size=1),),
        draft=True,
        immutable=False,
        name="Mercury v0.2.2",
        release_id=900,
        tag="v0.2.2",
    )
    with pytest.raises(PublicationError, match="^publication_asset_overwrite_forbidden$"):
        publish_release(plan, backend=backend, assets=assets)


def test_publication_creates_draft_verifies_downloads_then_enables_immutable() -> None:
    plan = publication_plan(_handoff(), release_notes="Mercury v0.2.2")
    backend = FakeBackend()

    result = publish_release(
        plan,
        backend=backend,
        assets={
            "mercury_tools-0.2.2-py3-none-any.whl": WHEEL,
            "mercury_tools-0.2.2.tar.gz": SDIST,
        },
    )

    assert result.state is PublicationState.PUBLISHED_IMMUTABLE
    assert backend.calls.index("create_draft") < backend.calls.index(
        "download:mercury_tools-0.2.2-py3-none-any.whl"
    )
    assert backend.calls.index("download:mercury_tools-0.2.2.tar.gz") < backend.calls.index(
        "publish"
    )
    assert backend.calls.index("enable_immutable") < backend.calls.index("publish")
    assert backend.calls[-2:] == ["publish", "read_release"]


def test_publication_never_publishes_when_immutable_policy_does_not_stick() -> None:
    plan = publication_plan(_handoff(), release_notes="Mercury v0.2.2")
    backend = IgnoringImmutableBackend()

    with pytest.raises(PublicationError, match="^publication_immutable_policy_invalid$"):
        publish_release(
            plan,
            backend=backend,
            assets={
                "mercury_tools-0.2.2-py3-none-any.whl": WHEEL,
                "mercury_tools-0.2.2.tar.gz": SDIST,
            },
        )

    assert "publish" not in backend.calls
