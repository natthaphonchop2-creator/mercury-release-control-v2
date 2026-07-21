"""Trusted publication CLI that verifies handoff and attestation before GitHub writes."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path

from pydantic import SecretStr, ValidationError

from mercury_release_control.attestation import (
    AttestationError,
    TrustedAttestationV2,
    validate_attestation,
)
from mercury_release_control.github_publication import GitHubPublicationBackend
from mercury_release_control.handoff import (
    HandoffError,
    ReleaseIdentity,
    VerifiedHandoff,
    verify_handoff,
)
from mercury_release_control.publication import (
    PublicationError,
    publication_plan,
    publish_release,
)
from mercury_release_control.release_profile import (
    ReleaseProfileError,
    release_profile_from_policy,
)
from mercury_release_control.workflow import WorkflowError, _load_json, _write_new


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    inspect = commands.add_parser("inspect-handoff")
    inspect.add_argument("--control-commit", required=True)
    inspect.add_argument("--handoff", type=Path, required=True)
    inspect.add_argument("--handoff-payload-sha256", required=True)
    inspect.add_argument("--mercury-run-attempt", type=int, required=True)
    inspect.add_argument("--mercury-run-id", type=int, required=True)
    inspect.add_argument("--output", type=Path, required=True)
    inspect.add_argument("--policy", type=Path, required=True)
    inspect.add_argument("--release-bundle-artifact-digest", required=True)
    inspect.add_argument("--release-bundle-artifact-id", type=int, required=True)
    inspect.add_argument("--reviewed-sha", required=True)
    publish = commands.add_parser("publish")
    publish.add_argument("--assets", type=Path, required=True)
    publish.add_argument("--handoff", type=Path, required=True)
    publish.add_argument("--handoff-payload-sha256", required=True)
    publish.add_argument("--identity", type=Path, required=True)
    publish.add_argument("--original-attestation", type=Path, required=True)
    publish.add_argument("--output", type=Path, required=True)
    publish.add_argument("--policy", type=Path, required=True)
    publish.add_argument("--release-notes", type=Path, required=True)
    return parser


def inspect_handoff(
    *,
    control_commit: str,
    handoff_path: Path,
    handoff_payload_sha256: str,
    mercury_run_attempt: int,
    mercury_run_id: int,
    output: Path,
    policy_path: Path,
    release_bundle_artifact_digest: str,
    release_bundle_artifact_id: int,
    reviewed_sha: str,
    now: datetime,
) -> ReleaseIdentity:
    policy = _load_json(policy_path)
    if not isinstance(policy, dict):
        raise WorkflowError("publication_policy_invalid")
    try:
        profile = release_profile_from_policy(policy)
    except ReleaseProfileError as exc:
        raise WorkflowError("publication_policy_invalid") from exc
    control_repository_id = policy.get("repository_id")
    mercury_repository_id = policy.get("reviewed_repository_id")
    if (
        not isinstance(control_repository_id, int)
        or isinstance(control_repository_id, bool)
        or control_repository_id <= 0
        or not isinstance(mercury_repository_id, int)
        or isinstance(mercury_repository_id, bool)
        or mercury_repository_id <= 0
    ):
        raise WorkflowError("publication_policy_invalid")
    handoff_body = _read_regular(handoff_path, 2 * 1024 * 1024)
    if hashlib.sha256(handoff_body).hexdigest() != handoff_payload_sha256:
        raise HandoffError("handoff_payload_digest_mismatch")
    try:
        raw_handoff = _load_json(handoff_path)
        provisional = VerifiedHandoff.model_validate_json(handoff_body)
        expected = ReleaseIdentity(
            control_artifact_digest=provisional.original_release_control.artifact_digest,
            control_artifact_id=provisional.original_release_control.artifact_id,
            control_commit=control_commit,
            control_payload_sha256=provisional.original_release_control.payload_sha256,
            control_repository_id=control_repository_id,
            control_run_attempt=provisional.original_release_control.run_attempt,
            control_run_id=provisional.original_release_control.run_id,
            mercury_repository_id=mercury_repository_id,
            mercury_run_attempt=mercury_run_attempt,
            mercury_run_id=mercury_run_id,
            public_tree_digest=provisional.public_tree_digest,
            release_bundle_artifact_digest=release_bundle_artifact_digest,
            release_bundle_artifact_id=release_bundle_artifact_id,
            reviewed_sha=reviewed_sha,
            staging_ref=provisional.staging_ref,
            version=profile.version,
        )
    except ValidationError as exc:
        raise HandoffError("handoff_schema_invalid") from exc
    verify_handoff(raw_handoff, expected=expected, now=now)
    _write_new(output, expected.model_dump(mode="json"))
    return expected


def run_publication(
    *,
    assets_path: Path,
    expected: ReleaseIdentity,
    handoff_path: Path,
    handoff_payload_sha256: str,
    original_attestation_path: Path,
    output: Path,
    policy_path: Path,
    release_notes_path: Path,
    token: SecretStr,
    now: datetime,
) -> None:
    policy = _load_json(policy_path)
    if not isinstance(policy, dict):
        raise WorkflowError("publication_policy_invalid")
    try:
        profile = release_profile_from_policy(policy)
    except ReleaseProfileError as exc:
        raise WorkflowError("publication_policy_invalid") from exc
    repository = policy.get("reviewed_repository")
    if not isinstance(repository, str) or expected.version != profile.version:
        raise WorkflowError("publication_policy_invalid")
    handoff_body = _read_regular(handoff_path, 2 * 1024 * 1024)
    if hashlib.sha256(handoff_body).hexdigest() != handoff_payload_sha256:
        raise HandoffError("handoff_payload_digest_mismatch")
    handoff_payload = _load_json(handoff_path)
    handoff = verify_handoff(handoff_payload, expected=expected, now=now)
    attestation_body = _read_regular(original_attestation_path, 2 * 1024 * 1024)
    if hashlib.sha256(attestation_body).hexdigest() != expected.control_payload_sha256:
        raise AttestationError("attestation_file_digest_mismatch")
    try:
        attestation = TrustedAttestationV2.model_validate_json(attestation_body)
    except ValidationError as exc:
        raise AttestationError("attestation_schema_invalid") from exc
    validate_attestation(attestation, now=now)
    if (
        attestation.reviewed_sha != expected.reviewed_sha
        or attestation.version != expected.version
        or attestation.public_tree_digest != expected.public_tree_digest
        or attestation.staging.ref != expected.staging_ref
        or attestation.workflow.repository_id != expected.control_repository_id
        or attestation.workflow.control_commit != expected.control_commit
        or attestation.workflow.run_id != expected.control_run_id
        or attestation.workflow.attempt != expected.control_run_attempt
    ):
        raise AttestationError("attestation_identity_mismatch")
    assets = _load_assets(assets_path, handoff.artifacts)
    try:
        release_notes = release_notes_path.read_text(encoding="utf-8").removesuffix("\n")
    except (OSError, UnicodeError) as exc:
        raise PublicationError("publication_notes_invalid") from exc
    plan = publication_plan(handoff, release_notes=release_notes)
    result = publish_release(
        plan,
        backend=GitHubPublicationBackend(repository=repository, token=token),
        assets=assets,
    )
    _write_new(
        output,
        {
            "release_id": result.release_id,
            "state": result.state.value,
            "tag": result.tag,
        },
    )


def _load_assets(path: Path, expected) -> dict[str, bytes]:
    if not path.is_dir() or path.is_symlink():
        raise PublicationError("publication_asset_inventory_mismatch")
    files = tuple(sorted(item for item in path.iterdir() if item.is_file()))
    if any(item.is_symlink() for item in files):
        raise PublicationError("publication_asset_inventory_mismatch")
    expected_names = {asset.name for asset in expected}
    if {item.name for item in files} != expected_names:
        raise PublicationError("publication_asset_inventory_mismatch")
    return {item.name: _read_regular(item, 1024 * 1024 * 1024) for item in files}


def _read_regular(path: Path, maximum: int) -> bytes:
    try:
        if path.is_symlink() or not path.is_file() or path.stat().st_size > maximum:
            raise WorkflowError("publication_input_invalid")
        return path.read_bytes()
    except OSError as exc:
        raise WorkflowError("publication_input_invalid") from exc


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.command == "inspect-handoff":
            inspect_handoff(
                control_commit=args.control_commit,
                handoff_path=args.handoff,
                handoff_payload_sha256=args.handoff_payload_sha256,
                mercury_run_attempt=args.mercury_run_attempt,
                mercury_run_id=args.mercury_run_id,
                output=args.output,
                policy_path=args.policy,
                release_bundle_artifact_digest=args.release_bundle_artifact_digest,
                release_bundle_artifact_id=args.release_bundle_artifact_id,
                reviewed_sha=args.reviewed_sha,
                now=datetime.now(UTC),
            )
            print(json.dumps({"status": "ok"}, separators=(",", ":"), sort_keys=True))
            return 0
        expected_payload = _load_json(args.identity)
        expected = ReleaseIdentity.model_validate(expected_payload)
        value = os.environ.get("MERCURY_TARGET_REPOSITORY_TOKEN", "")
        if not value:
            raise WorkflowError("publication_token_missing")
        run_publication(
            assets_path=args.assets,
            expected=expected,
            handoff_path=args.handoff,
            handoff_payload_sha256=args.handoff_payload_sha256,
            original_attestation_path=args.original_attestation,
            output=args.output,
            policy_path=args.policy,
            release_notes_path=args.release_notes,
            token=SecretStr(value),
            now=datetime.now(UTC),
        )
    except (
        AttestationError,
        HandoffError,
        PublicationError,
        ValidationError,
        WorkflowError,
    ) as exc:
        code = str(exc) if not isinstance(exc, ValidationError) else "publication_schema_invalid"
        print(f"mercury publication failed: {code}", file=sys.stderr)
        return 1
    print(json.dumps({"status": "ok"}, separators=(",", ":"), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
