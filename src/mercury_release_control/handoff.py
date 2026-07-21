"""Strict attempt-bound Mercury release-ready handoff verification."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError


class HandoffError(RuntimeError):
    """A constant-code release-ready handoff failure."""


class _HandoffModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)


class ReleaseIdentity(_HandoffModel):
    control_artifact_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    control_artifact_id: int = Field(gt=0)
    control_commit: str = Field(pattern=r"^[0-9a-f]{40}$")
    control_payload_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    control_repository_id: int = Field(gt=0)
    control_run_attempt: int = Field(gt=0)
    control_run_id: int = Field(gt=0)
    mercury_repository_id: int = Field(gt=0)
    mercury_run_attempt: int = Field(gt=0)
    mercury_run_id: int = Field(gt=0)
    public_tree_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    release_bundle_artifact_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    release_bundle_artifact_id: int = Field(gt=0)
    reviewed_sha: str = Field(pattern=r"^[0-9a-f]{40}$")
    staging_ref: str = Field(pattern=r"^v0\.2\.2-rc\.[0-9a-f]{12}$")


class ReleaseArtifact(_HandoffModel):
    name: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9_.+-]{0,199}$")
    sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    size: int = Field(gt=0, le=1024 * 1024 * 1024)


class MercuryWorkflowIdentity(_HandoffModel):
    repository_id: int = Field(gt=0)
    run_attempt: int = Field(gt=0)
    run_id: int = Field(gt=0)
    workflow_path: Literal[".github/workflows/release-v0.2.2.yml"]


class OriginalControlIdentity(_HandoffModel):
    artifact_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    artifact_id: int = Field(gt=0)
    commit: str = Field(pattern=r"^[0-9a-f]{40}$")
    payload_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    repository_id: int = Field(gt=0)
    run_attempt: int = Field(gt=0)
    run_id: int = Field(gt=0)


class ReleaseBundleIdentity(_HandoffModel):
    artifact_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    artifact_id: int = Field(gt=0)
    name: str = Field(
        pattern=r"^mercury-v0\.2\.2-release-artifacts-[1-9][0-9]*-attempt-[1-9][0-9]*$"
    )


class VerifiedHandoff(_HandoffModel):
    artifacts: tuple[ReleaseArtifact, ...] = Field(min_length=1, max_length=20)
    created_at: datetime
    expires_at: datetime
    mercury_workflow: MercuryWorkflowIdentity
    original_release_control: OriginalControlIdentity
    public_tree_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    release_bundle: ReleaseBundleIdentity
    reviewed_sha: str = Field(pattern=r"^[0-9a-f]{40}$")
    schema_version: Literal[3]
    staging_ref: str = Field(pattern=r"^v0\.2\.2-rc\.[0-9a-f]{12}$")
    version: Literal["0.2.2"]


def verify_handoff(
    payload: object,
    *,
    expected: ReleaseIdentity,
    now: datetime,
) -> VerifiedHandoff:
    try:
        encoded = json.dumps(payload, separators=(",", ":"), sort_keys=True)
        handoff = VerifiedHandoff.model_validate_json(encoded)
    except (TypeError, ValueError, ValidationError) as exc:
        raise HandoffError("handoff_schema_invalid") from exc
    control = handoff.original_release_control
    if (
        control.repository_id != expected.control_repository_id
        or control.commit != expected.control_commit
        or control.run_id != expected.control_run_id
        or control.run_attempt != expected.control_run_attempt
        or control.artifact_id != expected.control_artifact_id
        or control.artifact_digest != expected.control_artifact_digest
        or control.payload_sha256 != expected.control_payload_sha256
    ):
        raise HandoffError("handoff_control_identity_mismatch")
    mercury = handoff.mercury_workflow
    if (
        mercury.repository_id != expected.mercury_repository_id
        or mercury.run_id != expected.mercury_run_id
        or mercury.run_attempt != expected.mercury_run_attempt
        or handoff.release_bundle.artifact_id != expected.release_bundle_artifact_id
        or handoff.release_bundle.artifact_digest != expected.release_bundle_artifact_digest
        or handoff.release_bundle.name
        != (f"mercury-v0.2.2-release-artifacts-{mercury.run_id}-attempt-{mercury.run_attempt}")
    ):
        raise HandoffError("handoff_mercury_identity_mismatch")
    if (
        handoff.reviewed_sha != expected.reviewed_sha
        or handoff.public_tree_digest != expected.public_tree_digest
        or handoff.staging_ref != expected.staging_ref
        or handoff.staging_ref != f"v0.2.2-rc.{handoff.reviewed_sha[:12]}"
    ):
        raise HandoffError("handoff_release_identity_mismatch")
    observed_at = _utc(now)
    created_at = _utc(handoff.created_at)
    expires_at = _utc(handoff.expires_at)
    if created_at > observed_at + timedelta(minutes=5):
        raise HandoffError("handoff_time_invalid")
    if (
        expires_at <= created_at
        or expires_at > created_at + timedelta(minutes=60)
        or observed_at > expires_at
    ):
        raise HandoffError("handoff_expired")
    names = tuple(asset.name for asset in handoff.artifacts)
    if names != tuple(sorted(set(names))):
        raise HandoffError("handoff_artifact_inventory_invalid")
    return handoff


def _utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        raise HandoffError("handoff_time_invalid")
    return value.astimezone(UTC)
