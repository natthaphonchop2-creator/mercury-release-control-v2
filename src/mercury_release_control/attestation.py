"""Sanitized, identity-bound TrustedAttestationV2 assembly and validation."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
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


class SurfaceReceipt(_AttestationModel):
    blocker_codes: tuple[str, ...]
    completed_at: datetime
    evidence_hashes: tuple[str, ...] = Field(min_length=1, max_length=100)
    exit_codes: tuple[int, ...] = Field(min_length=1, max_length=100)
    finding_codes: tuple[str, ...]
    finding_count: Literal[0]
    scanner_versions: tuple[str, ...] = Field(min_length=1, max_length=3)
    started_at: datetime
    status: Literal["passed"]
    surface: str = Field(pattern=r"^[a-z][a-z0-9_]{0,127}$")


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
    surface_evidence_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    surface_count: Literal[8]
    surfaces: tuple[SurfaceReceipt, ...] = Field(min_length=8, max_length=8)
    version: Literal["0.2.2"]
    workflow: WorkflowReceipt


def assemble_attestation(
    *,
    evidence: ProviderEvidence,
    preflight: PreflightReceipt,
    staging: ExistingStaging,
    surface_evidence: Mapping[str, object],
    control_commit: str,
    run_id: int,
    run_attempt: int,
    now: datetime,
) -> TrustedAttestationV2:
    issued_at = _utc(now)
    if evidence.reviewed_sha != staging.reviewed_sha:
        raise AttestationError("attestation_identity_mismatch")
    if surface_evidence.get("reviewed_commit_sha") != evidence.reviewed_sha:
        raise AttestationError("attestation_identity_mismatch")
    surface_digest, surfaces = _surface_receipts(surface_evidence)
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
        "surface_count": len(surfaces),
        "surface_evidence_sha256": surface_digest,
        "surfaces": surfaces,
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
        or tuple(item.surface for item in attestation.surfaces) != _SURFACE_NAMES
        or any(item.completed_at > attestation.issued_at for item in attestation.surfaces)
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


_SURFACE_NAMES = (
    "git_all_refs",
    "github_pull_request_refs",
    "github_releases_and_assets",
    "github_actions_logs_artifacts_caches",
    "github_packages_pages_wiki",
    "marketplace_snapshot",
    "render_build_and_runtime_logs",
    "supabase_knowledge_and_storage",
)


def _surface_receipts(
    evidence: Mapping[str, object],
) -> tuple[str, tuple[SurfaceReceipt, ...]]:
    surfaces = evidence.get("surfaces")
    reviewed_sha = evidence.get("reviewed_commit_sha")
    if not isinstance(surfaces, list) or len(surfaces) != 8 or not isinstance(reviewed_sha, str):
        raise AttestationError("attestation_surface_evidence_invalid")
    receipts: list[SurfaceReceipt] = []
    for surface in surfaces:
        if not isinstance(surface, dict):
            raise AttestationError("attestation_surface_evidence_invalid")
        try:
            receipt = SurfaceReceipt.model_validate_json(
                json.dumps(surface, separators=(",", ":"), sort_keys=True)
            )
        except Exception as exc:
            raise AttestationError("attestation_surface_evidence_invalid") from exc
        if (
            receipt.blocker_codes
            or receipt.finding_codes
            or any(code != 0 for code in receipt.exit_codes)
            or receipt.completed_at < receipt.started_at
            or receipt.started_at.tzinfo is None
            or receipt.completed_at.tzinfo is None
            or any(
                len(value) != 64 or not set(value) <= set("0123456789abcdef")
                for value in receipt.evidence_hashes
            )
            or receipt.scanner_versions
            != (
                ("1.0.0", "3.88.32", "8.24.3")
                if receipt.surface in {"git_all_refs", "github_pull_request_refs"}
                else ("1.0.0",)
            )
        ):
            raise AttestationError("attestation_surface_evidence_invalid")
        receipts.append(receipt)
    normalized = tuple(receipts)
    if tuple(item.surface for item in normalized) != _SURFACE_NAMES:
        raise AttestationError("attestation_surface_evidence_invalid")
    encoded = json.dumps(_jsonable(dict(evidence)), separators=(",", ":"), sort_keys=True)
    return hashlib.sha256(encoded.encode()).hexdigest(), normalized


def _jsonable(value):
    if isinstance(value, BaseModel):
        return _jsonable(value.model_dump(mode="json"))
    if isinstance(value, datetime):
        return value.astimezone(UTC).isoformat().replace("+00:00", "Z")
    if isinstance(value, dict):
        return {key: _jsonable(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_jsonable(item) for item in value]
    return value


def _utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        raise AttestationError("attestation_time_invalid")
    return value.astimezone(UTC)
