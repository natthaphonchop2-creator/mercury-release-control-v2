"""Sanitized, identity-bound TrustedAttestationV2 assembly and validation."""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime, timedelta
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from mercury_release_control.preflight import PreflightReceipt
from mercury_release_control.provider_inspector import ProviderEvidence
from mercury_release_control.staging import ExistingStaging


class AttestationError(RuntimeError):
    """A constant-code trusted attestation failure."""


class _AttestationModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)


class StagingReceipt(_AttestationModel):
    commit_sha: str = Field(pattern=r"^[0-9a-f]{40}$")
    ref: str = Field(pattern=r"^v0\.2\.2-rc\.[0-9a-f]{12}$")
    tag_object_sha: str = Field(pattern=r"^[0-9a-f]{40}$")


class WorkflowReceipt(_AttestationModel):
    attempt: int = Field(gt=0)
    control_commit: str = Field(pattern=r"^[0-9a-f]{40}$")
    repository_id: int = Field(gt=0)
    run_id: int = Field(gt=0)


class TrustedAttestationV2(_AttestationModel):
    expires_at: datetime
    issued_at: datetime
    payload_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    preflight: PreflightReceipt
    provider_evidence: ProviderEvidence
    public_tree_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    reviewed_sha: str = Field(pattern=r"^[0-9a-f]{40}$")
    schema_version: Literal[2]
    staging: StagingReceipt
    version: Literal["0.2.2"]
    workflow: WorkflowReceipt


def assemble_attestation(
    *,
    evidence: ProviderEvidence,
    preflight: PreflightReceipt,
    staging: ExistingStaging,
    control_commit: str,
    run_id: int,
    run_attempt: int,
    now: datetime,
) -> TrustedAttestationV2:
    issued_at = _utc(now)
    if evidence.reviewed_sha != staging.reviewed_sha:
        raise AttestationError("attestation_identity_mismatch")
    payload = {
        "expires_at": issued_at + timedelta(minutes=60),
        "issued_at": issued_at,
        "preflight": preflight,
        "provider_evidence": evidence,
        "public_tree_digest": staging.tree_digest,
        "reviewed_sha": evidence.reviewed_sha,
        "schema_version": 2,
        "staging": StagingReceipt(
            commit_sha=staging.staging_commit_sha,
            ref=staging.tag,
            tag_object_sha=staging.tag_object_sha,
        ),
        "version": "0.2.2",
        "workflow": WorkflowReceipt(
            attempt=run_attempt,
            control_commit=control_commit,
            repository_id=preflight.control_repository_id,
            run_id=run_id,
        ),
    }
    digest = _payload_digest(payload)
    return TrustedAttestationV2(payload_sha256=digest, **payload)


def validate_attestation(attestation: TrustedAttestationV2, *, now: datetime) -> None:
    observed_at = _utc(now)
    if (
        attestation.version != "0.2.2"
        or attestation.schema_version != 2
        or attestation.reviewed_sha != attestation.provider_evidence.reviewed_sha
        or attestation.staging.ref != f"v0.2.2-rc.{attestation.reviewed_sha[:12]}"
    ):
        raise AttestationError("attestation_identity_mismatch")
    if attestation.issued_at > observed_at + timedelta(minutes=5):
        raise AttestationError("attestation_time_invalid")
    if (
        attestation.expires_at <= attestation.issued_at
        or attestation.expires_at > attestation.issued_at + timedelta(minutes=60)
        or observed_at > attestation.expires_at
    ):
        raise AttestationError("attestation_expired")
    payload = attestation.model_dump(exclude={"payload_sha256"})
    if _payload_digest(payload) != attestation.payload_sha256:
        raise AttestationError("attestation_digest_mismatch")


def _payload_digest(payload: dict[str, object]) -> str:
    normalized = _jsonable(payload)
    return hashlib.sha256(
        json.dumps(normalized, separators=(",", ":"), sort_keys=True).encode()
    ).hexdigest()


def _jsonable(value):
    if isinstance(value, BaseModel):
        return _jsonable(value.model_dump(mode="json"))
    if isinstance(value, datetime):
        return value.astimezone(UTC).isoformat().replace("+00:00", "Z")
    if isinstance(value, dict):
        return {key: _jsonable(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_jsonable(item) for item in value]
    return value


def _utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        raise AttestationError("attestation_time_invalid")
    return value.astimezone(UTC)
