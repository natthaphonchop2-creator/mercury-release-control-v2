from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from pydantic import ValidationError

from mercury_release_control.attestation import (
    AttestationError,
    TrustedAttestationV2,
    assemble_attestation,
    validate_attestation,
)
from mercury_release_control.preflight import PreflightReceipt
from mercury_release_control.provider_inspector import inspect_provider_state
from mercury_release_control.staging import ExistingStaging

NOW = datetime(2026, 7, 17, 8, 0, tzinfo=UTC)
REVIEWED_SHA = "a" * 40


def _provider_evidence():
    return inspect_provider_state(
        {
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
            "flowaccount": {
                "environment": "sandbox",
                "read_only": True,
                "status": 200,
            },
            "public_mcp": {
                "catalog_action_count": 254,
                "flowaccount_citations": 1,
                "hosted_tool_count": 20,
                "peak_citations": 1,
                "status": 200,
                "write_tools_exposed": False,
            },
        },
        reviewed_sha=REVIEWED_SHA,
        version="0.2.2",
    )


def _preflight() -> PreflightReceipt:
    return PreflightReceipt(
        admin_bypass_disabled=True,
        control_repository_id=42,
        environment="production-release",
        prevent_self_review=True,
        protected_branch_only=True,
        required_configuration_sha256="3" * 64,
        required_reviewers=1,
        target_repository_id=84,
    )


def _staging() -> ExistingStaging:
    return ExistingStaging(
        reviewed_sha=REVIEWED_SHA,
        staging_commit_sha="b" * 40,
        tag=f"v0.2.2-rc.{REVIEWED_SHA[:12]}",
        tag_object_sha="c" * 40,
        tree_digest="d" * 64,
    )


def test_attestation_is_exact_fresh_and_sanitized() -> None:
    attestation = assemble_attestation(
        evidence=_provider_evidence(),
        preflight=_preflight(),
        staging=_staging(),
        control_commit="e" * 40,
        run_id=123,
        run_attempt=1,
        now=NOW,
    )

    assert attestation.version == "0.2.2"
    assert attestation.staging.ref == f"v0.2.2-rc.{REVIEWED_SHA[:12]}"
    assert attestation.public_tree_digest == "d" * 64
    encoded = attestation.model_dump_json()
    for forbidden in ("client_secret", "access_token", "@", "/Users/"):
        assert forbidden not in encoded
    validate_attestation(attestation, now=NOW + timedelta(minutes=5))


def test_attestation_schema_rejects_unknown_fields() -> None:
    attestation = assemble_attestation(
        evidence=_provider_evidence(),
        preflight=_preflight(),
        staging=_staging(),
        control_commit="e" * 40,
        run_id=123,
        run_attempt=1,
        now=NOW,
    )
    payload = attestation.model_dump()
    payload["raw_provider_payload"] = {"access_token": "forbidden"}

    with pytest.raises(ValidationError):
        TrustedAttestationV2.model_validate(payload)


def test_attestation_expires_and_rejects_identity_mismatch() -> None:
    attestation = assemble_attestation(
        evidence=_provider_evidence(),
        preflight=_preflight(),
        staging=_staging(),
        control_commit="e" * 40,
        run_id=123,
        run_attempt=1,
        now=NOW,
    )

    with pytest.raises(AttestationError, match="^attestation_expired$"):
        validate_attestation(attestation, now=NOW + timedelta(hours=2))

    altered = attestation.model_copy(update={"reviewed_sha": "f" * 40})
    with pytest.raises(AttestationError, match="^attestation_identity_mismatch$"):
        validate_attestation(altered, now=NOW + timedelta(minutes=5))
