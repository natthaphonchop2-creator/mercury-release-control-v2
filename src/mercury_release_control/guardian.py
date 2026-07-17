"""Static, non-executing verifier for release-control pull-request candidates."""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import re
import tarfile
import unicodedata
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

import yaml

MAX_ARCHIVE_BYTES = 32 * 1024 * 1024
MAX_FILES = 2_000
MAX_FILE_BYTES = 4 * 1024 * 1024
MAX_TOTAL_BYTES = 64 * 1024 * 1024
MANIFEST_PATH = "control-manifest.json"
CHECKOUT_PIN = "34e114876b0b11c390a56381ad16ebd13914f8d5"
REQUIRED_FILES = frozenset(
    {
        ".github/workflows/ci.yml",
        ".github/workflows/guardian.yml",
        ".gitignore",
        "LICENSE",
        "README.md",
        MANIFEST_PATH,
        "policy-v0.2.2.json",
        "pyproject.toml",
        "src/mercury_release_control/__init__.py",
        "src/mercury_release_control/guardian.py",
        "uv.lock",
    }
)
_ACTION_PIN = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+@[0-9a-f]{40}$")
_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_COMMIT = re.compile(r"^[0-9a-f]{40}(?:[0-9a-f]{24})?$")
_SECRET_ASSIGNMENT = re.compile(
    rb"(?im)^\s*(?:api[_-]?key|access[_-]?token|client[_-]?secret|password)\s*[:=]\s*[^\s$<{][^\r\n]{7,}$"
)
_ALLOWED_PERMISSIONS = {
    "ci.yml": {"contents": "read"},
    "guardian.yml": {"contents": "read", "pull-requests": "read"},
    "attest-v0.2.2.yml": {"actions": "write", "contents": "read"},
    "publish-v0.2.2.yml": {"actions": "read", "contents": "read"},
}


class GuardianError(RuntimeError):
    """A constant-code candidate guardian failure."""


@dataclass(frozen=True, slots=True)
class GuardianReceipt:
    status: str
    file_count: int
    manifest_sha256: str


def build_manifest_payload(files: Mapping[str, bytes]) -> dict[str, object]:
    inventory = {
        path: hashlib.sha256(content).hexdigest()
        for path, content in sorted(files.items())
        if path != MANIFEST_PATH
    }
    return {"files": inventory, "schema_version": 1}


def verify_candidate_archive(archive_bytes: bytes) -> GuardianReceipt:
    files = _read_candidate_archive(archive_bytes)
    if not REQUIRED_FILES.issubset(files):
        raise GuardianError("candidate_inventory_invalid")
    _reject_forbidden_paths(files)
    _reject_secret_assignments(files)
    manifest = _strict_json(files[MANIFEST_PATH], "candidate_manifest_invalid")
    if set(manifest) != {"files", "schema_version"} or manifest.get("schema_version") != 1:
        raise GuardianError("candidate_manifest_invalid")
    declared = manifest.get("files")
    expected = build_manifest_payload(files)["files"]
    if not isinstance(declared, Mapping) or dict(declared) != expected:
        raise GuardianError("candidate_manifest_mismatch")
    if any(
        not isinstance(value, str) or _DIGEST.fullmatch(value) is None
        for value in declared.values()
    ):
        raise GuardianError("candidate_manifest_invalid")
    _validate_policy(files["policy-v0.2.2.json"])
    for path, content in files.items():
        if path.startswith(".github/workflows/"):
            _validate_workflow(path, content)
    return GuardianReceipt(
        status="passed",
        file_count=len(files),
        manifest_sha256=hashlib.sha256(files[MANIFEST_PATH]).hexdigest(),
    )


def _read_candidate_archive(archive_bytes: bytes) -> dict[str, bytes]:
    if not archive_bytes or len(archive_bytes) > MAX_ARCHIVE_BYTES:
        raise GuardianError("candidate_archive_invalid")
    files: dict[str, bytes] = {}
    total_bytes = 0
    prefix: str | None = None
    try:
        with tarfile.open(fileobj=io.BytesIO(archive_bytes), mode="r:*") as archive:
            global_comment = _git_comment(archive.pax_headers)
            for member in archive.getmembers():
                if member.isdir():
                    continue
                expected_headers = {"comment": global_comment} if global_comment is not None else {}
                if not member.isfile() or member.pax_headers != expected_headers:
                    raise GuardianError("candidate_archive_invalid")
                parts = member.name.split("/", 1)
                if len(parts) != 2 or not parts[0] or not parts[1]:
                    raise GuardianError("candidate_archive_invalid")
                if prefix is None:
                    prefix = parts[0]
                if parts[0] != prefix:
                    raise GuardianError("candidate_archive_invalid")
                path = _canonical_path(parts[1])
                if path in files or member.size < 0 or member.size > MAX_FILE_BYTES:
                    raise GuardianError("candidate_archive_invalid")
                total_bytes += member.size
                if len(files) >= MAX_FILES or total_bytes > MAX_TOTAL_BYTES:
                    raise GuardianError("candidate_archive_invalid")
                stream = archive.extractfile(member)
                if stream is None:
                    raise GuardianError("candidate_archive_invalid")
                content = stream.read(MAX_FILE_BYTES + 1)
                if len(content) != member.size or len(content) > MAX_FILE_BYTES:
                    raise GuardianError("candidate_archive_invalid")
                files[path] = content
    except GuardianError:
        raise
    except (OSError, tarfile.TarError, UnicodeError, ValueError) as exc:
        raise GuardianError("candidate_archive_invalid") from exc
    return files


def _git_comment(headers: dict[str, str]) -> str | None:
    if not headers:
        return None
    comment = headers.get("comment")
    if (
        set(headers) != {"comment"}
        or not isinstance(comment, str)
        or _COMMIT.fullmatch(comment) is None
    ):
        raise GuardianError("candidate_archive_invalid")
    return comment


def _canonical_path(value: str) -> str:
    normalized = unicodedata.normalize("NFC", value)
    path = PurePosixPath(value)
    parts = value.split("/")
    if (
        not value
        or normalized != value
        or "\0" in value
        or "\\" in value
        or path.is_absolute()
        or path.as_posix() != value
        or any(part in {"", ".", ".."} for part in parts)
        or len(value.encode()) > 4096
        or len(parts) > 32
    ):
        raise GuardianError("candidate_archive_invalid")
    return value


def _reject_forbidden_paths(files: Mapping[str, bytes]) -> None:
    for path in files:
        parts = tuple(part.casefold() for part in PurePosixPath(path).parts)
        if (
            any(part in {".git", ".venv", "__pycache__", "release-evidence"} for part in parts)
            or any(part == ".env" or part.startswith(".env.") for part in parts)
            or path.endswith((".pyc", ".pyo"))
        ):
            raise GuardianError("candidate_path_forbidden")


def _reject_secret_assignments(files: Mapping[str, bytes]) -> None:
    for path, content in files.items():
        if path.startswith("tests/"):
            continue
        if _SECRET_ASSIGNMENT.search(content):
            raise GuardianError("candidate_secret_detected")


def _strict_json(content: bytes, code: str) -> Mapping[str, object]:
    def pairs(items: list[tuple[str, object]]) -> dict[str, object]:
        payload: dict[str, object] = {}
        for key, value in items:
            if key in payload:
                raise GuardianError(code)
            payload[key] = value
        return payload

    try:
        payload = json.loads(content, object_pairs_hook=pairs)
    except GuardianError:
        raise
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise GuardianError(code) from exc
    if not isinstance(payload, Mapping):
        raise GuardianError(code)
    return payload


def _validate_policy(content: bytes) -> None:
    policy = _strict_json(content, "candidate_policy_invalid")
    release = policy.get("release")
    staging = policy.get("staging")
    expectations = policy.get("provider_expectations")
    if (
        policy.get("schema_version") != 2
        or not isinstance(release, Mapping)
        or dict(release) != {"tag": "v0.2.2", "version": "0.2.2"}
        or policy.get("repository") != "natthaphonchop2-creator/mercury-release-control-v2"
        or policy.get("reviewed_repository") != "natthaphonchop2-creator/mercury-tools"
        or policy.get("staging_repository") != "natthaphonchop2-creator/mercury-tools-staging"
        or policy.get("branch") != "main"
        or policy.get("environment") != "production-release"
        or not isinstance(staging, Mapping)
        or dict(staging)
        != {
            "repository": "natthaphonchop2-creator/mercury-tools-staging",
            "tag_prefix": "v0.2.2-rc.",
        }
        or not isinstance(expectations, Mapping)
        or dict(expectations)
        != {
            "catalog_action_count": 254,
            "flowaccount_environment": "sandbox",
            "hosted_tool_count": 20,
            "supabase_function_count": 10,
            "supabase_table_count": 17,
        }
        or not isinstance(policy.get("supabase"), Mapping)
    ):
        raise GuardianError("candidate_policy_invalid")


def _validate_workflow(path: str, content: bytes) -> None:
    try:
        text = content.decode("utf-8")
        workflow = yaml.load(text, Loader=yaml.BaseLoader)
    except (UnicodeError, yaml.YAMLError) as exc:
        raise GuardianError("candidate_workflow_invalid") from exc
    if not isinstance(workflow, Mapping):
        raise GuardianError("candidate_workflow_invalid")
    expected_permissions = _ALLOWED_PERMISSIONS.get(PurePosixPath(path).name)
    permissions = workflow.get("permissions")
    if expected_permissions is None or not isinstance(permissions, Mapping):
        raise GuardianError("candidate_workflow_permissions_invalid")
    if dict(permissions) != expected_permissions:
        raise GuardianError("candidate_workflow_permissions_invalid")
    if any(key == "permissions" for job in _mappings(workflow.get("jobs")) for key in job):
        raise GuardianError("candidate_workflow_permissions_invalid")
    for uses in _values_for_key(workflow, "uses"):
        if not isinstance(uses, str) or (
            not uses.startswith("./") and _ACTION_PIN.fullmatch(uses) is None
        ):
            raise GuardianError("candidate_workflow_action_unpinned")
    name = PurePosixPath(path).name
    if name in {"ci.yml", "guardian.yml"} and "secrets." in text:
        raise GuardianError("candidate_workflow_secret_invalid")
    if name == "guardian.yml" and (
        "pull_request_target" not in text or "github.event.pull_request.base.sha" not in text
    ):
        raise GuardianError("candidate_guardian_workflow_invalid")
    if name == "guardian.yml":
        checkout_steps = [
            item
            for item in _mapping_values(workflow)
            if item.get("uses") == f"actions/checkout@{CHECKOUT_PIN}"
        ]
        if len(checkout_steps) != 1:
            raise GuardianError("candidate_guardian_workflow_invalid")
        checkout_with = checkout_steps[0].get("with")
        if (
            not isinstance(checkout_with, Mapping)
            or checkout_with.get("ref") != "${{ github.event.pull_request.base.sha }}"
        ):
            raise GuardianError("candidate_guardian_workflow_invalid")


def _mappings(value: object) -> tuple[Mapping[str, object], ...]:
    if not isinstance(value, Mapping):
        return ()
    return tuple(item for item in value.values() if isinstance(item, Mapping))


def _values_for_key(value: object, key: str) -> tuple[object, ...]:
    found: list[object] = []
    if isinstance(value, Mapping):
        for candidate_key, candidate_value in value.items():
            if candidate_key == key:
                found.append(candidate_value)
            found.extend(_values_for_key(candidate_value, key))
    elif isinstance(value, list):
        for item in value:
            found.extend(_values_for_key(item, key))
    return tuple(found)


def _mapping_values(value: object) -> tuple[Mapping[str, object], ...]:
    found: list[Mapping[str, object]] = []
    if isinstance(value, Mapping):
        found.append(value)
        for item in value.values():
            found.extend(_mapping_values(item))
    elif isinstance(value, list):
        for item in value:
            found.extend(_mapping_values(item))
    return tuple(found)


def _manifest_for_root(root: Path) -> dict[str, object]:
    files: dict[str, bytes] = {}
    for path in sorted(root.rglob("*")):
        relative = path.relative_to(root).as_posix()
        parts = set(PurePosixPath(relative).parts)
        ignored = bool(
            parts
            & {
                ".git",
                ".mypy_cache",
                ".pytest_cache",
                ".ruff_cache",
                ".venv",
                "__pycache__",
                "release-evidence",
            }
        ) or any(part.endswith(".egg-info") for part in parts)
        if path.is_file() and not path.is_symlink() and not ignored:
            if relative == MANIFEST_PATH:
                continue
            files[relative] = path.read_bytes()
    return build_manifest_payload(files)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    manifest = subparsers.add_parser("manifest")
    manifest.add_argument("--root", type=Path, required=True)
    manifest.add_argument("--output", type=Path, required=True)
    verify = subparsers.add_parser("verify")
    verify.add_argument("--candidate", type=Path, required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.command == "manifest":
            payload = _manifest_for_root(args.root)
            args.output.write_text(
                json.dumps(payload, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )
            result: Mapping[str, object] = {"status": "written"}
        else:
            receipt = verify_candidate_archive(args.candidate.read_bytes())
            result = {
                "file_count": receipt.file_count,
                "manifest_sha256": receipt.manifest_sha256,
                "status": receipt.status,
            }
    except (GuardianError, OSError) as exc:
        code = str(exc) if isinstance(exc, GuardianError) else "candidate_io_invalid"
        print(json.dumps({"error": code, "status": "error"}, sort_keys=True))
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
