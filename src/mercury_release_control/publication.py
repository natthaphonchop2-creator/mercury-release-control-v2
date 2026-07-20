"""Draft-verified, immutable Mercury GitHub Release publication state machine."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from enum import StrEnum
from typing import Protocol

from mercury_release_control.handoff import ReleaseArtifact, VerifiedHandoff


class PublicationError(RuntimeError):
    """A constant-code trusted publication failure."""


class PublicationState(StrEnum):
    PRECONDITIONS_VERIFIED = "preconditions_verified"
    TAG_CREATED = "tag_created"
    DRAFT_VERIFIED = "draft_verified"
    PUBLISHED_IMMUTABLE = "published_immutable"


@dataclass(frozen=True, slots=True)
class RemoteTag:
    annotated: bool
    commit: str
    name: str


@dataclass(frozen=True, slots=True)
class RemoteAsset:
    name: str
    sha256: str
    size: int


@dataclass(frozen=True, slots=True)
class RemoteRelease:
    assets: tuple[RemoteAsset, ...]
    draft: bool
    immutable: bool
    name: str
    release_id: int
    tag: str


@dataclass(frozen=True, slots=True)
class PublicationPlan:
    assets: tuple[ReleaseArtifact, ...]
    commit: str
    release_name: str
    release_notes: str
    tag: str


@dataclass(frozen=True, slots=True)
class PublicationResult:
    release_id: int
    state: PublicationState
    tag: str


class PublicationBackend(Protocol):
    def read_tag(self, tag: str) -> RemoteTag | None: ...

    def create_tag(self, *, tag: str, commit: str, message: str) -> RemoteTag: ...

    def read_release(self, tag: str) -> RemoteRelease | None: ...

    def create_draft(self, *, tag: str, name: str, body: str) -> RemoteRelease: ...

    def upload_asset(self, release_id: int, asset: ReleaseArtifact, content: bytes) -> None: ...

    def download_asset(self, release_id: int, name: str) -> bytes: ...

    def immutable_enabled(self) -> bool: ...

    def publish(self, release_id: int) -> None: ...

    def enable_immutable(self) -> None: ...


def require_transition(current: PublicationState, target: PublicationState) -> None:
    allowed = {
        PublicationState.PRECONDITIONS_VERIFIED: PublicationState.TAG_CREATED,
        PublicationState.TAG_CREATED: PublicationState.DRAFT_VERIFIED,
        PublicationState.DRAFT_VERIFIED: PublicationState.PUBLISHED_IMMUTABLE,
    }
    if allowed.get(current) is not target:
        raise PublicationError("publication_transition_invalid")


def publication_plan(
    handoff: VerifiedHandoff,
    *,
    release_notes: str,
) -> PublicationPlan:
    if (
        handoff.version != "0.3.0"
        or not isinstance(release_notes, str)
        or not release_notes.strip()
        or release_notes != release_notes.strip()
        or len(release_notes.encode()) > 64 * 1024
    ):
        raise PublicationError("publication_plan_invalid")
    return PublicationPlan(
        assets=handoff.artifacts,
        commit=handoff.reviewed_sha,
        release_name="Mercury v0.3.0",
        release_notes=release_notes,
        tag="v0.3.0",
    )


def publish_release(
    plan: PublicationPlan,
    *,
    backend: PublicationBackend,
    assets: dict[str, bytes],
) -> PublicationResult:
    _verify_local_assets(plan.assets, assets)
    state = PublicationState.PRECONDITIONS_VERIFIED
    expected_tag = RemoteTag(annotated=True, commit=plan.commit, name=plan.tag)
    observed_tag = backend.read_tag(plan.tag)
    if observed_tag is None:
        observed_tag = backend.create_tag(
            tag=plan.tag,
            commit=plan.commit,
            message=f"Mercury {plan.tag}",
        )
    if observed_tag != expected_tag:
        raise PublicationError("publication_tag_mismatch")
    require_transition(state, PublicationState.TAG_CREATED)
    state = PublicationState.TAG_CREATED

    release = backend.read_release(plan.tag)
    if release is None:
        release = backend.create_draft(
            tag=plan.tag,
            name=plan.release_name,
            body=plan.release_notes,
        )
    elif (
        not release.draft
        or release.immutable
        or release.tag != plan.tag
        or release.name != plan.release_name
    ):
        raise PublicationError("publication_release_exists")
    if release.assets:
        raise PublicationError("publication_asset_overwrite_forbidden")
    for asset in plan.assets:
        backend.upload_asset(release.release_id, asset, assets[asset.name])
    for asset in plan.assets:
        downloaded = backend.download_asset(release.release_id, asset.name)
        if len(downloaded) != asset.size or hashlib.sha256(downloaded).hexdigest() != asset.sha256:
            raise PublicationError("publication_asset_download_mismatch")
    verified_draft = backend.read_release(plan.tag)
    if verified_draft is None or not verified_draft.draft:
        raise PublicationError("publication_draft_invalid")
    _verify_remote_assets(plan.assets, verified_draft.assets)
    require_transition(state, PublicationState.DRAFT_VERIFIED)
    state = PublicationState.DRAFT_VERIFIED

    if not backend.immutable_enabled():
        backend.enable_immutable()
    if not backend.immutable_enabled():
        raise PublicationError("publication_immutable_policy_invalid")
    backend.publish(release.release_id)
    final = backend.read_release(plan.tag)
    if (
        final is None
        or final.draft
        or not final.immutable
        or final.release_id != release.release_id
        or final.tag != plan.tag
        or final.name != plan.release_name
    ):
        raise PublicationError("publication_final_state_invalid")
    _verify_remote_assets(plan.assets, final.assets)
    require_transition(state, PublicationState.PUBLISHED_IMMUTABLE)
    return PublicationResult(
        release_id=final.release_id,
        state=PublicationState.PUBLISHED_IMMUTABLE,
        tag=plan.tag,
    )


def _verify_local_assets(expected: tuple[ReleaseArtifact, ...], assets: dict[str, bytes]) -> None:
    expected_names = {asset.name for asset in expected}
    if set(assets) != expected_names or any(
        not isinstance(value, bytes) for value in assets.values()
    ):
        raise PublicationError("publication_asset_inventory_mismatch")
    for asset in expected:
        content = assets[asset.name]
        if len(content) != asset.size or hashlib.sha256(content).hexdigest() != asset.sha256:
            raise PublicationError("publication_asset_digest_mismatch")


def _verify_remote_assets(
    expected: tuple[ReleaseArtifact, ...], observed: tuple[RemoteAsset, ...]
) -> None:
    expected_rows = tuple((asset.name, asset.sha256, asset.size) for asset in expected)
    observed_rows = tuple(sorted((asset.name, asset.sha256, asset.size) for asset in observed))
    if expected_rows != observed_rows:
        raise PublicationError("publication_remote_asset_mismatch")
