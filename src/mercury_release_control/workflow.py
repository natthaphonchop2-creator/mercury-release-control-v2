"""Trusted CLI entrypoints used by the v0.2.2 attestation workflow."""

from __future__ import annotations

import argparse
import contextlib
import json
import os
import stat
import sys
import tempfile
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from pathlib import Path

from pydantic import SecretStr, ValidationError

from mercury_release_control.attestation import (
    AttestationError,
    assemble_attestation,
)
from mercury_release_control.github_preflight import (
    GitHubApiReader,
    collect_remote_snapshot,
)
from mercury_release_control.preflight import (
    PreflightError,
    PreflightReceipt,
    validate_preflight,
)
from mercury_release_control.provider_inspector import (
    InspectionError,
    ProviderEvidence,
    inspect_providers,
)
from mercury_release_control.staging import (
    ExistingStaging,
    GitHubStagingPublisher,
    StagingError,
    build_staging,
    publish_staging,
)


class WorkflowError(RuntimeError):
    """A constant-code trusted workflow input or output failure."""


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    preflight = commands.add_parser("preflight")
    preflight.add_argument("--policy", type=Path, required=True)
    preflight.add_argument("--output", type=Path, required=True)
    stage = commands.add_parser("stage")
    stage.add_argument("--archive", type=Path, required=True)
    stage.add_argument("--identity-output", type=Path, required=True)
    stage.add_argument("--output", type=Path, required=True)
    stage.add_argument("--policy", type=Path, required=True)
    stage.add_argument("--reviewed-sha", required=True)
    providers = commands.add_parser("providers")
    providers.add_argument("--identity", type=Path, required=True)
    providers.add_argument("--output", type=Path, required=True)
    providers.add_argument("--policy", type=Path, required=True)
    providers.add_argument("--reviewed-sha", required=True)
    attest = commands.add_parser("attest")
    attest.add_argument("--control-commit", required=True)
    attest.add_argument("--identity", type=Path, required=True)
    attest.add_argument("--output", type=Path, required=True)
    attest.add_argument("--preflight", type=Path, required=True)
    attest.add_argument("--providers", type=Path, required=True)
    attest.add_argument("--run-attempt", type=int, required=True)
    attest.add_argument("--run-id", type=int, required=True)
    attest.add_argument("--surface-evidence", type=Path, required=True)
    return parser


def run_preflight(*, policy_path: Path, output: Path, token: SecretStr) -> None:
    policy = _mapping(_load_json(policy_path))
    snapshot = collect_remote_snapshot(policy, GitHubApiReader(token=token))
    receipt = validate_preflight(policy, snapshot)
    _write_new(output, receipt.model_dump(mode="json"))


def run_stage(
    *,
    archive_path: Path,
    identity_output: Path,
    output: Path,
    policy_path: Path,
    reviewed_sha: str,
    token: SecretStr,
) -> None:
    policy = _mapping(_load_json(policy_path))
    repository = policy.get("staging_repository")
    if not isinstance(repository, str):
        raise WorkflowError("workflow_policy_invalid")
    try:
        archive = archive_path.read_bytes()
    except OSError as exc:
        raise WorkflowError("workflow_archive_invalid") from exc
    identity = build_staging(
        archive_bytes=archive,
        reviewed_sha=reviewed_sha,
        output=output,
    )
    published = publish_staging(
        identity=identity,
        repository=repository,
        publisher=GitHubStagingPublisher(token=token),
    )
    _write_new(identity_output, _existing_payload(published.identity))


def run_providers(
    *,
    identity_path: Path,
    output: Path,
    policy_path: Path,
    reviewed_sha: str,
    environment: Mapping[str, str],
) -> None:
    policy = _mapping(_load_json(policy_path))
    staging = _load_staging(identity_path)
    evidence = inspect_providers(
        policy,
        environment,
        reviewed_sha,
        staging,
    )
    _write_new(output, evidence.model_dump(mode="json"))


def run_attest(
    *,
    control_commit: str,
    identity_path: Path,
    output: Path,
    preflight_path: Path,
    providers_path: Path,
    run_attempt: int,
    run_id: int,
    surface_evidence_path: Path,
    now: datetime,
) -> None:
    preflight = PreflightReceipt.model_validate(_load_json(preflight_path))
    providers = ProviderEvidence.model_validate(_load_json(providers_path))
    staging = _load_staging(identity_path)
    surface_evidence = _mapping(_load_json(surface_evidence_path))
    attestation = assemble_attestation(
        evidence=providers,
        preflight=preflight,
        staging=staging,
        control_commit=control_commit,
        run_id=run_id,
        run_attempt=run_attempt,
        surface_evidence=surface_evidence,
        now=now,
    )
    _write_new(output, attestation.model_dump(mode="json"))


def _load_staging(path: Path) -> ExistingStaging:
    payload = _mapping(_load_json(path))
    if set(payload) != {
        "reviewed_sha",
        "staging_commit_sha",
        "tag",
        "tag_object_sha",
        "tree_digest",
    }:
        raise WorkflowError("workflow_staging_invalid")
    try:
        return ExistingStaging(**payload)
    except TypeError as exc:
        raise WorkflowError("workflow_staging_invalid") from exc


def _existing_payload(identity: ExistingStaging) -> dict[str, str]:
    return {
        "reviewed_sha": identity.reviewed_sha,
        "staging_commit_sha": identity.staging_commit_sha,
        "tag": identity.tag,
        "tag_object_sha": identity.tag_object_sha,
        "tree_digest": identity.tree_digest,
    }


def _load_json(path: Path):
    try:
        body = path.read_bytes()
    except OSError as exc:
        raise WorkflowError("workflow_input_invalid") from exc
    if not body or len(body) > 8 * 1024 * 1024:
        raise WorkflowError("workflow_input_invalid")
    try:
        return json.loads(body, object_pairs_hook=_unique_object)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise WorkflowError("workflow_input_invalid") from exc


def _write_new(path: Path, payload: Mapping[str, object]) -> None:
    body = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode() + b"\n"
    if len(body) > 2 * 1024 * 1024 or path.exists() or not path.parent.is_dir():
        raise WorkflowError("workflow_output_invalid")
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(body)
            handle.flush()
            os.fsync(handle.fileno())
        os.link(temporary, path)
        metadata = path.stat()
        if stat.S_IMODE(metadata.st_mode) != 0o600 or metadata.st_size != len(body):
            raise WorkflowError("workflow_output_invalid")
    except OSError as exc:
        raise WorkflowError("workflow_output_invalid") from exc
    finally:
        with contextlib.suppress(FileNotFoundError):
            temporary.unlink()


def _mapping(value: object) -> dict[str, object]:
    if not isinstance(value, dict):
        raise WorkflowError("workflow_input_invalid")
    return value


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    output: dict[str, object] = {}
    for key, value in pairs:
        if key in output:
            raise ValueError("duplicate JSON key")
        output[key] = value
    return output


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.command == "preflight":
            run_preflight(
                policy_path=args.policy,
                output=args.output,
                token=_secret("RELEASE_CONTROL_PREFLIGHT_TOKEN"),
            )
        elif args.command == "stage":
            run_stage(
                archive_path=args.archive,
                identity_output=args.identity_output,
                output=args.output,
                policy_path=args.policy,
                reviewed_sha=args.reviewed_sha,
                token=_secret("MERCURY_STAGING_REPOSITORY_TOKEN"),
            )
        elif args.command == "providers":
            run_providers(
                identity_path=args.identity,
                output=args.output,
                policy_path=args.policy,
                reviewed_sha=args.reviewed_sha,
                environment=os.environ,
            )
        elif args.command == "attest":
            run_attest(
                control_commit=args.control_commit,
                identity_path=args.identity,
                output=args.output,
                preflight_path=args.preflight,
                providers_path=args.providers,
                run_attempt=args.run_attempt,
                run_id=args.run_id,
                surface_evidence_path=args.surface_evidence,
                now=datetime.now(UTC),
            )
        else:
            raise WorkflowError("workflow_command_invalid")
    except (
        AttestationError,
        InspectionError,
        PreflightError,
        StagingError,
        ValidationError,
        WorkflowError,
    ) as exc:
        code = str(exc) if not isinstance(exc, ValidationError) else "workflow_schema_invalid"
        print(f"mercury release control failed: {code}", file=sys.stderr)
        return 1
    print(json.dumps({"status": "ok"}, separators=(",", ":"), sort_keys=True))
    return 0


def _secret(name: str) -> SecretStr:
    value = os.environ.get(name, "")
    if not value:
        raise WorkflowError("workflow_secret_missing")
    return SecretStr(value)


if __name__ == "__main__":
    raise SystemExit(main())
