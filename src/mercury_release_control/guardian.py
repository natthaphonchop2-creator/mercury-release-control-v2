"""Static, non-executing verifier for release-control pull-request candidates."""

# ruff: noqa: E501

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

from mercury_release_control.release_profile import release_profile

MAX_ARCHIVE_BYTES = 32 * 1024 * 1024
MAX_FILES = 2_000
MAX_FILE_BYTES = 4 * 1024 * 1024
MAX_TOTAL_BYTES = 64 * 1024 * 1024
MANIFEST_PATH = "control-manifest.json"
CHECKOUT_PIN = "34e114876b0b11c390a56381ad16ebd13914f8d5"
V030_TRUSTED_FILE_SHA256 = {
    ".github/workflows/attest-v0.2.2.yml": (
        "5ea4aa1cad83979f0cedaabd3afd56a79b3653e1337d9f3769633267e6e87662"
    ),
    ".github/workflows/attest-v0.3.0.yml": (
        "1f8a2fa466b58e42895a8096d09aa188a9ecf3533ac164413e72f46e166f58c4"
    ),
    ".github/workflows/ci.yml": "d147235488ee49c91d82d7ff96eafca704cb0b778548a0bd31265578efda93d9",
    ".github/workflows/guardian.yml": (
        "82c8c4deacfddad4736d89bbbf8bf197a420c5d7585dfd0ca85675871a669fe4"
    ),
    ".github/workflows/migrate-v0.3.0.yml": (
        "022bc7af4ad7e448a49414ea4f3aab6d680ded9077e09c4369ffaec51e41c139"
    ),
    ".github/workflows/publish-v0.2.2.yml": (
        "9e1842ba720916e82fb63d6d3a31719632fe680bd6d8c8902f5f114dde37364d"
    ),
    ".github/workflows/publish-v0.3.0.yml": (
        "a8efdc960dadcabae052dd4f0b80d5f5e1b3bf87175527c04a4201b4d2d8ff16"
    ),
    "policy-v0.2.2.json": "5cd5ae84f8ae04314b0be80c3cc947fd59e65b56ec19fabffc14fa1d0fa2306a",
    "policy-v0.3.0.json": ("b363c4f6cbba42c10cce2c0fb5b594ab46c7e8d1fab0b96417ee0d4fa8e1c907"),
    "pyproject.toml": "f7ea42368cec3da102875f56dc7d70967a77b3794073e28416705d46fbc0663b",
    "src/mercury_release_control/__init__.py": (
        "735f223b0e1fe89a4515496dbec2e3dbc30218c044a9085624e5ada69af22ad9"
    ),
    "src/mercury_release_control/attestation.py": (
        "389a4704b7e5cc7ac35f213b3613ceaa35d032a856e4c53d43f07257ca110962"
    ),
    "src/mercury_release_control/github_preflight.py": (
        "28c7e8340eb691961c2393133cd0e7b6738d404f936ab42ffe5bb1f0535092b4"
    ),
    "src/mercury_release_control/github_publication.py": (
        "27fc391aea9e8301b51a4793e9d11b95c2d5065974495765fcfca720ab1bc626"
    ),
    "src/mercury_release_control/handoff.py": (
        "29d66537b892c2b96fc370e878de73da46b15078ed4778d89aabda634251e4bd"
    ),
    "src/mercury_release_control/hosted_collector.py": (
        "9424effafbddcfd84c4553636f7113f60a9b117946b8dea6b6164c2f37e46a69"
    ),
    "src/mercury_release_control/preflight.py": (
        "52dde96c3954c8cbe1415758fbafbc0977968d9dc8817c7565e993b58c406a32"
    ),
    "src/mercury_release_control/production_migration.py": (
        "9d59f730219c6575558b5e820d826ce4cfd90de37a556d01d4d9a3339975dc2d"
    ),
    "src/mercury_release_control/provider_inspector.py": (
        "410c6baf5f62e5631d41c1fd19f74d08ca73d5f8ba1aa208e070d8a5acb6f7e3"
    ),
    "src/mercury_release_control/public_tree.py": (
        "27b2e3bb0a74348cfc13b270920b68099c9264b751e53c56a54cebaa5431c29d"
    ),
    "src/mercury_release_control/publication.py": (
        "2a6d3b9eab7a66a1e9c302e5bcae988d2d8c4f4e07f571bc4e68a04ecda65184"
    ),
    "src/mercury_release_control/publish_workflow.py": (
        "d08e2df80c9301708f978a117a7581902239b6bb2e32bbf8013d759522577dba"
    ),
    "src/mercury_release_control/release_profile.py": (
        "57e43c24eb370a16034404207b8b7155344192608c7fcf418bb4f615dcbd022d"
    ),
    "src/mercury_release_control/staging.py": (
        "cb537c2f97f697874e92c4acefb17722684c131e3021b982accfbebc6f228d58"
    ),
    "src/mercury_release_control/surface_inspector.py": (
        "60de03a9cbfcbb2307b7966661ba7103d2d75fd1e4fcda00611301637c30e824"
    ),
    "src/mercury_release_control/workflow.py": (
        "d7d8a97b926a183fbd688d59785107a8b4763e60781c297d8cceb2949230e685"
    ),
    "uv.lock": "3f6d58f32c7d8c4f604c1ef04e90d738f2a2bed2296055da09d53a432a3e1182",
}
# This baseline is intentionally inline: the trusted guardian must not derive it
# from candidate-controlled policy or manifest content.
V030_EXPECTED_POLICY: Mapping[str, object] = json.loads(
    r"""
{
  "schema_version": 2,
  "bootstrap_state": "configured",
  "repository": "natthaphonchop2-creator/mercury-release-control-v2",
  "repository_id": 1303413748,
  "reviewed_repository": "natthaphonchop2-creator/mercury-tools",
  "reviewed_repository_id": 1290137723,
  "staging_repository": "natthaphonchop2-creator/mercury-tools-staging",
  "branch": "main",
  "environment": "production-release",
  "inspector": {
    "interface_version": 2,
    "path": "src/mercury_release_control/surface_inspector.py",
    "sha256": "60de03a9cbfcbb2307b7966661ba7103d2d75fd1e4fcda00611301637c30e824"
  },
  "immutable_releases_required": true,
  "release_tag_ruleset": {
    "bypass_actors": [],
    "conditions": {
      "ref_name": {
        "exclude": [],
        "include": ["refs/tags/v0.3.0"]
      }
    },
    "enforcement": "active",
    "name": "Mercury v0.3.0 immutable release tag",
    "rules": [{"type": "deletion"}, {"type": "update"}],
    "target": "tag"
  },
  "required_reviewer_ids": [284163704],
  "required_environment_secrets": [
    "FLOWACCOUNT_SANDBOX_CLIENT_ID",
    "FLOWACCOUNT_SANDBOX_CLIENT_SECRET",
    "MERCURY_PUBLIC_MCP_TOKEN",
    "MERCURY_STAGING_REPOSITORY_TOKEN",
    "MERCURY_TARGET_REPOSITORY_READ_TOKEN",
    "MERCURY_TARGET_REPOSITORY_TOKEN",
    "MERCURY_TARGET_WORKFLOW_DISPATCH_TOKEN",
    "RELEASE_CONTROL_PREFLIGHT_TOKEN",
    "RENDER_API_TOKEN",
    "SUPABASE_DB_URL"
  ],
  "required_environment_variables": [
    "FLOWACCOUNT_SANDBOX_BASE_URL",
    "MERCURY_MARKETPLACE_SNAPSHOT_URL",
    "MERCURY_PUBLIC_MCP_URL",
    "RENDER_API_URL",
    "RENDER_OWNER_ID",
    "RENDER_SERVICE_ID",
    "STAGING_REPOSITORY",
    "SUPABASE_URL",
    "TARGET_REPOSITORY"
  ],
  "required_status_checks": [
    {
      "app_id": 15368,
      "context": "required"
    },
    {
      "app_id": 15368,
      "context": "verify-candidate-as-data"
    }
  ],
  "forbidden_repository_secrets": [
    "FLOWACCOUNT_SANDBOX_CLIENT_ID",
    "FLOWACCOUNT_SANDBOX_CLIENT_SECRET",
    "MERCURY_PUBLIC_MCP_TOKEN",
    "MERCURY_STAGING_REPOSITORY_TOKEN",
    "MERCURY_TARGET_REPOSITORY_READ_TOKEN",
    "MERCURY_TARGET_REPOSITORY_TOKEN",
    "MERCURY_TARGET_WORKFLOW_DISPATCH_TOKEN",
    "MERCURY_TOOLS_HTTP_BEARER_TOKEN",
    "RELEASE_CONTROL_PREFLIGHT_TOKEN",
    "RENDER_API_TOKEN",
    "SUPABASE_DB_URL",
    "SUPABASE_SERVICE_ROLE_KEY"
  ],
  "supabase": {
    "project_ref": "vbnlkqvauqwnjbxngkas",
    "migration_id": "20260719120000",
    "migration_history_sha256": "efc2b2ece5efa30008b7fb86097f43b205abb057acf4e2b470767555fc463db7",
    "tables": [
      "erp_action_catalog",
      "erp_action_observations",
      "erp_action_validation_knowledge",
      "erp_action_versions",
      "erp_spec_sources",
      "knowledge_chunks",
      "knowledge_documents",
      "knowledge_sources",
      "mcp_audit_events",
      "mercury_client_tokens",
      "mercury_connector_profiles",
      "mercury_product_events",
      "mercury_skill_catalog",
      "mercury_skill_uploads",
      "mercury_workspace_members",
      "mercury_workspace_skills",
      "mercury_workspaces"
    ],
    "storage_buckets": [],
    "functions": [
      {
        "signature": "public.jsonb_has_forbidden_validation_key(jsonb)",
        "definition_sha256": "5daff6c305d976cd76f1a90fd3045f675ef8546e1836741aff3a65898589270b"
      },
      {
        "signature": "public.jsonb_has_forbidden_validation_value(jsonb)",
        "definition_sha256": "3c72400dbe096adebe003e3d2c68c574a739ed2ec44b3f2eb13c338a517ff015"
      },
      {
        "signature": "public.jsonb_is_safe_validation_response_shape(jsonb)",
        "definition_sha256": "5826d3ed1fb3d4988600df1e82531c60c245ec7e1d094b8386bf73a39b91cc21"
      },
      {
        "signature": "public.match_knowledge_chunks(text,vector,integer,text,text,text,text,text,date,text,text,text,text,text)",
        "definition_sha256": "2e33fb28da4138e72c26f48b63594dedf4e9929a841fbca27d95909617987206"
      },
      {
        "signature": "public.mercury_capability_states_are_safe(jsonb)",
        "definition_sha256": "e8851d39d439d1ab433492ec0690521d1b0a327741a0d1d259bfd9eeec538427"
      },
      {
        "signature": "public.reject_validation_evidence_mutation()",
        "definition_sha256": "78116567472e5c8be398e54a44e53658952f8984333efc7ed1301b93347c9e71"
      },
      {
        "signature": "public.resolve_erp_action_validation_batch(jsonb,timestamp with time zone)",
        "definition_sha256": "0ae50b4029b2b97751458b00075fdf2eccb292b81b3433c9be6a405bc752b1ed"
      },
      {
        "signature": "public.validation_label_kind(text)",
        "definition_sha256": "1203db7191669c97fb57da20df4ee11ccf58ad49fafc394d94e67b52b84961f6"
      },
      {
        "signature": "public.validation_text_has_forbidden_value(text)",
        "definition_sha256": "876d6eca70d066379c29c46d226d67e3a876536dcdf571302fe5f20f99193a27"
      },
      {
        "signature": "public.validation_text_has_label_assignment_contamination(text)",
        "definition_sha256": "89ba0c3a67fec2043a585a31d725ddc1514567263db7640798357717a48a23b5"
      },
      {
        "signature": "public.validation_text_has_safe_label_assignment(text)",
        "definition_sha256": "534521773977fe6dcea308ec02c4f3ce42ca2c2b4f3c6536325400eeae38d252"
      }
    ],
    "schema_sha256": "e81da9304677ba2bdd2351fc2870cc83e2b9d53c76520d49193572518962efad"
  },
  "release": {"tag": "v0.3.0", "version": "0.3.0"},
  "staging": {
    "repository": "natthaphonchop2-creator/mercury-tools-staging",
    "tag_prefix": "v0.3.0-rc."
  },
  "provider_expectations": {
    "flowaccount_environment": "sandbox",
    "hosted_tool_count": 24,
    "catalog_action_count": 254,
    "supabase_table_count": 17,
    "supabase_function_count": 11
  }
}
"""
)
V030_ALLOWED_FILES = frozenset(
    {
        ".github/workflows/attest-v0.2.2.yml",
        ".github/workflows/attest-v0.3.0.yml",
        ".github/workflows/ci.yml",
        ".github/workflows/guardian.yml",
        ".github/workflows/migrate-v0.3.0.yml",
        ".github/workflows/publish-v0.2.2.yml",
        ".github/workflows/publish-v0.3.0.yml",
        ".gitignore",
        "LICENSE",
        "README.md",
        MANIFEST_PATH,
        "policy-v0.2.2.json",
        "policy-v0.3.0.json",
        "pyproject.toml",
        "release-notes-v0.2.2.md",
        "release-notes-v0.3.0.md",
        "src/mercury_release_control/__init__.py",
        "src/mercury_release_control/attestation.py",
        "src/mercury_release_control/github_preflight.py",
        "src/mercury_release_control/github_publication.py",
        "src/mercury_release_control/guardian.py",
        "src/mercury_release_control/handoff.py",
        "src/mercury_release_control/hosted_collector.py",
        "src/mercury_release_control/preflight.py",
        "src/mercury_release_control/production_migration.py",
        "src/mercury_release_control/provider_inspector.py",
        "src/mercury_release_control/public_tree.py",
        "src/mercury_release_control/publication.py",
        "src/mercury_release_control/publish_workflow.py",
        "src/mercury_release_control/release_profile.py",
        "src/mercury_release_control/staging.py",
        "src/mercury_release_control/surface_inspector.py",
        "src/mercury_release_control/workflow.py",
        "tests/fixtures/public-tree-v1.json",
        "tests/test_attest_workflow.py",
        "tests/test_attestation.py",
        "tests/test_github_preflight.py",
        "tests/test_guardian.py",
        "tests/test_handoff.py",
        "tests/test_hosted_collector.py",
        "tests/test_migration_workflow.py",
        "tests/test_preflight.py",
        "tests/test_production_migration.py",
        "tests/test_provider_inspector.py",
        "tests/test_public_tree.py",
        "tests/test_publication.py",
        "tests/test_publish_workflow.py",
        "tests/test_publish_workflow_structure.py",
        "tests/test_staging.py",
        "tests/test_surface_inspector.py",
        "tests/test_v022_compatibility.py",
        "tests/test_v030_controls.py",
        "tests/test_workflow.py",
        "uv.lock",
    }
)
BASE_REQUIRED_FILES = frozenset(
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
V030_MARKER_FILES = frozenset(
    {
        ".github/workflows/attest-v0.3.0.yml",
        ".github/workflows/migrate-v0.3.0.yml",
        ".github/workflows/publish-v0.3.0.yml",
        "policy-v0.3.0.json",
        "src/mercury_release_control/production_migration.py",
    }
)
REQUIRED_FILES = V030_ALLOWED_FILES
_ACTION_PIN = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+@[0-9a-f]{40}$")
_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_COMMIT = re.compile(r"^[0-9a-f]{40}(?:[0-9a-f]{24})?$")
_SECRET_ASSIGNMENT = re.compile(
    rb"(?im)^\s*(?:api[_-]?key|access[_-]?token|client[_-]?secret|password)\s*[:=]\s*"
    rb"(?:[\"'][^\"'$<{][^\"'\r\n]{7,}[\"']|[A-Za-z0-9+/=_-]{8,})\s*[,;]?\s*$"
)
_ALLOWED_PERMISSIONS = {
    "ci.yml": {"contents": "read"},
    "guardian.yml": {"contents": "read", "pull-requests": "read"},
    "attest-v0.2.2.yml": {"actions": "write", "contents": "read"},
    "publish-v0.2.2.yml": {"actions": "read", "contents": "read"},
    "attest-v0.3.0.yml": {"actions": "write", "contents": "read"},
    "migrate-v0.3.0.yml": {"contents": "read"},
    "publish-v0.3.0.yml": {"actions": "read", "contents": "read"},
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
    _reject_forbidden_paths(files)
    _reject_secret_assignments(files)
    v030_present = bool(V030_MARKER_FILES.intersection(files))
    if v030_present and set(files) != V030_ALLOWED_FILES:
        raise GuardianError("candidate_inventory_invalid")
    if not v030_present and not BASE_REQUIRED_FILES.issubset(files):
        raise GuardianError("candidate_inventory_invalid")
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
    _validate_trusted_v030_files(files, v030_present=v030_present)
    versions = ("0.2.2", "0.3.0") if v030_present else ("0.2.2",)
    for version in versions:
        _validate_policy(files[f"policy-v{version}.json"], version=version)
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


def _validate_trusted_v030_files(
    files: Mapping[str, bytes], *, v030_present: bool
) -> None:
    if not v030_present:
        return
    guardian_path = "src/mercury_release_control/guardian.py"
    candidate_guardian = files.get(guardian_path)
    try:
        trusted_guardian = Path(__file__).resolve().read_bytes()
    except OSError as exc:
        raise GuardianError("trusted_guardian_unavailable") from exc
    if candidate_guardian != trusted_guardian:
        raise GuardianError("candidate_trusted_file_hash_invalid")
    for path, expected_sha256 in V030_TRUSTED_FILE_SHA256.items():
        content = files.get(path)
        if content is None or hashlib.sha256(content).hexdigest() != expected_sha256:
            raise GuardianError("candidate_trusted_file_hash_invalid")


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


def _validate_policy(content: bytes, *, version: str) -> None:
    profile = release_profile(version)
    policy = _strict_json(content, "candidate_policy_invalid")
    if version == "0.3.0" and dict(policy) != V030_EXPECTED_POLICY:
        raise GuardianError("candidate_policy_invalid")
    release = policy.get("release")
    staging = policy.get("staging")
    expectations = policy.get("provider_expectations")
    required_variables = policy.get("required_environment_variables")
    supabase = policy.get("supabase")
    if (
        policy.get("schema_version") != 2
        or not isinstance(release, Mapping)
        or dict(release) != {"tag": profile.tag, "version": profile.version}
        or policy.get("repository") != "natthaphonchop2-creator/mercury-release-control-v2"
        or policy.get("repository_id") != 1303413748
        or policy.get("reviewed_repository") != "natthaphonchop2-creator/mercury-tools"
        or policy.get("reviewed_repository_id") != 1290137723
        or policy.get("staging_repository") != "natthaphonchop2-creator/mercury-tools-staging"
        or policy.get("branch") != "main"
        or policy.get("environment") != "production-release"
        or not isinstance(staging, Mapping)
        or dict(staging)
        != {
            "repository": "natthaphonchop2-creator/mercury-tools-staging",
            "tag_prefix": profile.staging_tag_prefix,
        }
        or not isinstance(expectations, Mapping)
        or dict(expectations)
        != {
            "catalog_action_count": 254,
            "flowaccount_environment": "sandbox",
            "hosted_tool_count": profile.hosted_tool_count,
            "supabase_function_count": profile.supabase_function_count,
            "supabase_table_count": profile.supabase_table_count,
        }
        or required_variables
        != [
            "FLOWACCOUNT_SANDBOX_BASE_URL",
            "MERCURY_MARKETPLACE_SNAPSHOT_URL",
            "MERCURY_PUBLIC_MCP_URL",
            "RENDER_API_URL",
            "RENDER_OWNER_ID",
            "RENDER_SERVICE_ID",
            "STAGING_REPOSITORY",
            "SUPABASE_URL",
            "TARGET_REPOSITORY",
        ]
        or not isinstance(supabase, Mapping)
        or supabase.get("migration_id") != profile.migration_id
        or tuple(
            item.get("signature") if isinstance(item, Mapping) else None
            for item in supabase.get("functions", ())
        )
        != profile.supabase_function_signatures
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
    if name == "migrate-v0.3.0.yml":
        _validate_migration_workflow(workflow, text)


def _validate_migration_workflow(workflow: Mapping[str, object], text: str) -> None:
    expected_on = {
        "workflow_dispatch": {
            "inputs": {
                "reviewed_commit_sha": {
                    "description": "Exact reviewed mercury-tools main commit",
                    "required": "true",
                    "type": "string",
                }
            }
        }
    }
    expected_markers = (
        "production-release",
        "natthaphonchop2-creator/mercury-tools",
        "1290137723",
        "supabase/migrations/20260719120000_connector_neutral_profiles.sql",
        "7e6378206076be0d314c2ffb6636e5ea728150ad29491450e3e397c5b6271300",
        "700723581420dd1ac98fd7e9ac529f0ef210eadcaf87fc868a3ad7d114c2f3b7",
        "git/ref/heads/main",
        "PGSSLROOTCERT",
        "RELEASE_CONTROL_PREFLIGHT_TOKEN",
        "mercury_release_control.workflow preflight",
        "mercury_release_control.production_migration",
    )
    jobs = workflow.get("jobs")
    concurrency = workflow.get("concurrency")
    migrate_job = jobs.get("migrate") if isinstance(jobs, Mapping) else None
    steps = migrate_job.get("steps") if isinstance(migrate_job, Mapping) else None
    preflight_steps = (
        [
            step
            for step in steps
            if isinstance(step, Mapping)
            and step.get("name") == "Verify GitHub identities and protected release environment"
        ]
        if isinstance(steps, list)
        else []
    )
    migration_steps = (
        [
            step
            for step in steps
            if isinstance(step, Mapping) and step.get("name") == "Run trusted production migration"
        ]
        if isinstance(steps, list)
        else []
    )
    preflight = preflight_steps[0] if len(preflight_steps) == 1 else None
    preflight_run = preflight.get("run") if isinstance(preflight, Mapping) else None
    preflight_env = preflight.get("env") if isinstance(preflight, Mapping) else None
    if (
        workflow.get("on") != expected_on
        or not isinstance(jobs, Mapping)
        or set(jobs) != {"migrate", "reject-non-main"}
        or not isinstance(jobs.get("migrate"), Mapping)
        or jobs["migrate"].get("environment") != "production-release"
        or jobs["migrate"].get("if") != "${{ github.ref == 'refs/heads/main' }}"
        or not isinstance(jobs.get("reject-non-main"), Mapping)
        or jobs["reject-non-main"].get("if") != "${{ github.ref != 'refs/heads/main' }}"
        or concurrency
        != {
            "cancel-in-progress": "false",
            "group": "mercury-v0.3.0-production-migration",
        }
        or len(migration_steps) != 1
        or not isinstance(steps, list)
        or preflight is None
        or steps.index(preflight) >= steps.index(migration_steps[0])
        or preflight_env
        != {"RELEASE_CONTROL_PREFLIGHT_TOKEN": ("${{ secrets.RELEASE_CONTROL_PREFLIGHT_TOKEN }}")}
        or not isinstance(preflight_run, str)
        or "--policy policy-v0.3.0.json" not in preflight_run
        or ('--output "$RUNNER_TEMP/mercury-migration/preflight.json"' not in preflight_run)
        or "cat " in preflight_run
        or any(marker not in text for marker in expected_markers)
        or "actions/upload-artifact" in text
        or "actions/download-artifact" in text
        or "pull_request" in text
        or "set -x" in text
    ):
        raise GuardianError("candidate_migration_workflow_invalid")


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
