"""Deterministic history-free staging construction and publication contract."""

from __future__ import annotations

import base64
import hashlib
import io
import json
import os
import re
import shutil
import subprocess
import tarfile
import tempfile
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any, Protocol

from pydantic import SecretStr

from mercury_release_control.public_tree import PublicTreeError, build_public_tree
from mercury_release_control.release_profile import (
    ReleaseProfileError,
    release_profile,
    release_profile_from_staging_ref,
)

_SHA = re.compile(r"^[0-9a-f]{40}$")
_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_REPOSITORY = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
_GIT = Path("/usr/bin/git")
_FIXED_DATE = "2026-07-17T00:00:00Z"


class StagingError(RuntimeError):
    """A constant-code trusted staging failure."""


@dataclass(frozen=True, slots=True)
class StagingIdentity:
    path: Path
    reviewed_sha: str
    staging_commit_sha: str
    tag: str
    tag_object_sha: str
    tree_digest: str


@dataclass(frozen=True, slots=True)
class ExistingStaging:
    reviewed_sha: str
    staging_commit_sha: str
    tag: str
    tag_object_sha: str
    tree_digest: str

    @classmethod
    def from_identity(
        cls,
        identity: StagingIdentity,
        *,
        tree_digest: str | None = None,
    ) -> ExistingStaging:
        observed = cls(
            reviewed_sha=identity.reviewed_sha,
            staging_commit_sha=identity.staging_commit_sha,
            tag=identity.tag,
            tag_object_sha=identity.tag_object_sha,
            tree_digest=identity.tree_digest,
        )
        return replace(observed, tree_digest=tree_digest) if tree_digest is not None else observed


@dataclass(frozen=True, slots=True)
class PublishedStaging:
    identity: ExistingStaging
    repository: str
    created: bool


class StagingPublisher(Protocol):
    def read(self, repository: str, tag: str) -> ExistingStaging | None: ...

    def create(self, repository: str, identity: StagingIdentity) -> ExistingStaging: ...


class GitHubApi(Protocol):
    def read_staging(self, repository: str, tag: str) -> ExistingStaging | None: ...


class RefPusher(Protocol):
    def push(
        self,
        *,
        root: Path,
        repository: str,
        tag: str,
        token: SecretStr,
    ) -> None: ...


class GitHubStagingPublisher:
    """Publish refs without exposing credentials, then verify every remote byte."""

    def __init__(
        self,
        *,
        token: SecretStr,
        api: GitHubApi | None = None,
        pusher: RefPusher | None = None,
    ) -> None:
        self._token = token
        self._api = api or GitHubRestApi(token=token)
        self._pusher = pusher or GitSmartHttpRefPusher()

    def read(self, repository: str, tag: str) -> ExistingStaging | None:
        return self._api.read_staging(repository, tag)

    def create(self, repository: str, identity: StagingIdentity) -> ExistingStaging:
        self._pusher.push(
            root=identity.path,
            repository=repository,
            tag=identity.tag,
            token=self._token,
        )
        observed = self._api.read_staging(repository, identity.tag)
        if observed != ExistingStaging.from_identity(identity):
            raise StagingError("staging_remote_mismatch")
        return observed


class GitSmartHttpRefPusher:
    """Push the initial parentless commit and tag with a token-only child environment."""

    def push(
        self,
        *,
        root: Path,
        repository: str,
        tag: str,
        token: SecretStr,
    ) -> None:
        if _REPOSITORY.fullmatch(repository) is None or not root.is_dir():
            raise StagingError("staging_repository_invalid")
        with tempfile.TemporaryDirectory(prefix="mercury-git-auth-") as temporary:
            directory = Path(temporary)
            askpass = directory / "askpass"
            home = directory / "home"
            template = directory / "template"
            home.mkdir()
            template.mkdir()
            askpass.write_text(
                "#!/bin/sh\n"
                'case "$1" in\n'
                "  *Username*) printf '%s\\n' 'x-access-token' ;;\n"
                "  *) printf '%s\\n' \"$MERCURY_GITHUB_TOKEN\" ;;\n"
                "esac\n",
                encoding="utf-8",
            )
            askpass.chmod(0o700)
            environment = _git_environment(template, home)
            environment.update(
                {
                    "GIT_ASKPASS": str(askpass),
                    "GIT_TERMINAL_PROMPT": "0",
                    "MERCURY_GITHUB_TOKEN": token.get_secret_value(),
                }
            )
            completed = subprocess.run(
                [
                    str(_GIT),
                    "-c",
                    "credential.helper=",
                    "-c",
                    "core.hooksPath=/dev/null",
                    "push",
                    "--atomic",
                    f"https://github.com/{repository}.git",
                    "HEAD:refs/heads/main",
                    f"refs/tags/{tag}:refs/tags/{tag}",
                ],
                cwd=root,
                env=environment,
                check=False,
                capture_output=True,
                text=True,
            )
        if (
            completed.returncode != 0
            or len(completed.stdout) > 64 * 1024
            or len(completed.stderr) > 64 * 1024
        ):
            raise StagingError("staging_push_failed")


class GitHubRestApi:
    """Read a staged GitHub tag and independently reconstruct PublicTreeV1."""

    def __init__(
        self,
        *,
        token: SecretStr,
        api_url: str = "https://api.github.com",
    ) -> None:
        if api_url != "https://api.github.com":
            raise StagingError("staging_github_api_invalid")
        self._token = token
        self._api_url = api_url

    def read_staging(self, repository: str, tag: str) -> ExistingStaging | None:
        try:
            profile = release_profile_from_staging_ref(tag)
        except ReleaseProfileError as exc:
            raise StagingError("staging_repository_invalid") from exc
        suffix = tag.removeprefix(profile.staging_tag_prefix)
        if (
            _REPOSITORY.fullmatch(repository) is None
            or re.fullmatch(r"[0-9a-f]{12}", suffix) is None
        ):
            raise StagingError("staging_repository_invalid")
        encoded_tag = urllib.parse.quote(tag, safe="")
        reference = self._request("GET", f"/repos/{repository}/git/ref/tags/{encoded_tag}")
        if reference is None:
            return None
        reference_object = _mapping(reference, "object")
        tag_object_sha = _sha(reference_object, "sha")
        if reference_object.get("type") != "tag":
            raise StagingError("staging_remote_invalid")
        tag_object = self._required("GET", f"/repos/{repository}/git/tags/{tag_object_sha}")
        if tag_object.get("tag") != tag or _sha(tag_object, "sha") != tag_object_sha:
            raise StagingError("staging_remote_invalid")
        metadata = _tag_metadata(tag_object.get("message"))
        commit_object = _mapping(tag_object, "object")
        if commit_object.get("type") != "commit":
            raise StagingError("staging_remote_invalid")
        staging_commit_sha = _sha(commit_object, "sha")
        commit = self._required("GET", f"/repos/{repository}/git/commits/{staging_commit_sha}")
        if _sha(commit, "sha") != staging_commit_sha:
            raise StagingError("staging_remote_invalid")
        tree_sha = _sha(_mapping(commit, "tree"), "sha")
        tree = self._required("GET", f"/repos/{repository}/git/trees/{tree_sha}?recursive=1")
        if tree.get("truncated") is not False:
            raise StagingError("staging_remote_invalid")
        snapshot = self._remote_snapshot(repository, tree.get("tree"))
        if snapshot.digest != metadata["tree_digest"]:
            raise StagingError("staging_remote_mismatch")
        return ExistingStaging(
            reviewed_sha=metadata["reviewed_sha"],
            staging_commit_sha=staging_commit_sha,
            tag=tag,
            tag_object_sha=tag_object_sha,
            tree_digest=snapshot.digest,
        )

    def _remote_snapshot(self, repository: str, raw_tree: object):
        if not isinstance(raw_tree, list) or len(raw_tree) > 100_000:
            raise StagingError("staging_remote_invalid")
        output = io.BytesIO()
        file_count = 0
        with tarfile.open(fileobj=output, mode="w", format=tarfile.PAX_FORMAT) as archive:
            for raw in raw_tree:
                if not isinstance(raw, dict) or raw.get("type") != "blob":
                    raise StagingError("staging_remote_invalid")
                path = raw.get("path")
                mode = raw.get("mode")
                blob_sha = _sha(raw, "sha")
                if not isinstance(path, str) or mode not in {"100644", "100755"}:
                    raise StagingError("staging_remote_invalid")
                blob = self._required("GET", f"/repos/{repository}/git/blobs/{blob_sha}")
                if blob.get("encoding") != "base64":
                    raise StagingError("staging_remote_invalid")
                content = _decode_blob(blob.get("content"), blob_sha)
                member = tarfile.TarInfo(path)
                member.mode = 0o755 if mode == "100755" else 0o644
                member.size = len(content)
                archive.addfile(member, io.BytesIO(content))
                file_count += 1
        try:
            snapshot = build_public_tree(output.getvalue())
        except PublicTreeError as exc:
            raise StagingError("staging_remote_invalid") from exc
        if len(snapshot.entries) != file_count:
            raise StagingError("staging_remote_invalid")
        return snapshot

    def _required(self, method: str, path: str) -> dict[str, Any]:
        payload = self._request(method, path)
        if payload is None:
            raise StagingError("staging_remote_invalid")
        return payload

    def _request(self, method: str, path: str) -> dict[str, Any] | None:
        request = urllib.request.Request(
            f"{self._api_url}{path}",
            method=method,
            headers={
                "Accept": "application/vnd.github+json",
                "Authorization": f"Bearer {self._token.get_secret_value()}",
                "User-Agent": "mercury-release-control-v2",
                "X-GitHub-Api-Version": "2022-11-28",
            },
        )
        try:
            with urllib.request.urlopen(request, timeout=20) as response:
                body = response.read(8 * 1024 * 1024 + 1)
        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                return None
            raise StagingError("staging_github_api_failed") from exc
        except (OSError, TimeoutError, urllib.error.URLError) as exc:
            raise StagingError("staging_github_api_failed") from exc
        if len(body) > 8 * 1024 * 1024:
            raise StagingError("staging_remote_invalid")
        try:
            payload = json.loads(body, object_pairs_hook=_unique_object)
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
            raise StagingError("staging_remote_invalid") from exc
        if not isinstance(payload, dict):
            raise StagingError("staging_remote_invalid")
        return payload


def build_staging(
    *,
    archive_bytes: bytes,
    reviewed_sha: str,
    output: Path,
    version: str,
) -> StagingIdentity:
    try:
        profile = release_profile(version)
    except ReleaseProfileError as exc:
        raise StagingError("staging_release_invalid") from exc
    if _SHA.fullmatch(reviewed_sha) is None:
        raise StagingError("staging_reviewed_sha_invalid")
    if output.exists() or output.is_symlink():
        raise StagingError("staging_destination_exists")
    if not _GIT.is_file():
        raise StagingError("staging_git_unavailable")
    try:
        snapshot = build_public_tree(archive_bytes)
    except PublicTreeError as exc:
        raise StagingError("staging_public_tree_invalid") from exc
    parent = output.parent.resolve(strict=True)
    temporary = Path(tempfile.mkdtemp(prefix=f".{output.name}.trusted-", dir=parent))
    published = False
    try:
        empty_template = temporary / ".empty-template"
        isolated_home = temporary / ".home"
        empty_template.mkdir()
        isolated_home.mkdir()
        repository = temporary / "repository"
        repository.mkdir()
        for entry in snapshot.entries:
            target = repository.joinpath(*entry.path.split("/"))
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(entry.content)
            os.chmod(target, entry.mode)
        environment = _git_environment(empty_template, isolated_home)
        _run_git(repository, environment, "init", "--initial-branch=main")
        _run_git(repository, environment, "add", "--all")
        tag = profile.staging_ref(reviewed_sha)
        _run_git(
            repository,
            environment,
            "commit",
            "--no-gpg-sign",
            "-m",
            f"Mercury {tag} public candidate",
        )
        staging_commit = _run_git(repository, environment, "rev-parse", "HEAD")
        if staging_commit == reviewed_sha or _SHA.fullmatch(staging_commit) is None:
            raise StagingError("staging_commit_invalid")
        _run_git(
            repository,
            environment,
            "tag",
            "--annotate",
            "--no-sign",
            "--message",
            _tag_message(reviewed_sha, snapshot.digest),
            tag,
        )
        tag_object = _run_git(repository, environment, "rev-parse", f"refs/tags/{tag}")
        if _SHA.fullmatch(tag_object) is None:
            raise StagingError("staging_tag_invalid")
        if output.exists() or output.is_symlink():
            raise StagingError("staging_destination_exists")
        repository.rename(output)
        published = True
        return StagingIdentity(
            path=output,
            reviewed_sha=reviewed_sha,
            staging_commit_sha=staging_commit,
            tag=tag,
            tag_object_sha=tag_object,
            tree_digest=snapshot.digest,
        )
    except StagingError:
        raise
    except OSError as exc:
        raise StagingError("staging_build_failed") from exc
    finally:
        if not published or temporary.exists():
            shutil.rmtree(temporary, ignore_errors=True)


def publish_staging(
    *,
    identity: StagingIdentity,
    repository: str,
    publisher: StagingPublisher,
) -> PublishedStaging:
    if _REPOSITORY.fullmatch(repository) is None:
        raise StagingError("staging_repository_invalid")
    expected = ExistingStaging.from_identity(identity)
    existing = publisher.read(repository, identity.tag)
    if existing is not None:
        if existing != expected:
            raise StagingError("staging_remote_mismatch")
        return PublishedStaging(identity=existing, repository=repository, created=False)
    created = publisher.create(repository, identity)
    if created != expected:
        raise StagingError("staging_remote_mismatch")
    return PublishedStaging(identity=created, repository=repository, created=True)


def _git_environment(template: Path, home: Path) -> dict[str, str]:
    return {
        "GIT_AUTHOR_DATE": _FIXED_DATE,
        "GIT_AUTHOR_EMAIL": "release-control@mercury.invalid",
        "GIT_AUTHOR_NAME": "Mercury Release Control",
        "GIT_COMMITTER_DATE": _FIXED_DATE,
        "GIT_COMMITTER_EMAIL": "release-control@mercury.invalid",
        "GIT_COMMITTER_NAME": "Mercury Release Control",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_TEMPLATE_DIR": str(template),
        "HOME": str(home),
        "LC_ALL": "C",
        "PATH": "/usr/bin:/bin",
    }


def _run_git(root: Path, environment: dict[str, str], *arguments: str) -> str:
    completed = subprocess.run(
        [str(_GIT), "-c", "core.hooksPath=/dev/null", *arguments],
        cwd=root,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
    )
    if completed.returncode != 0 or len(completed.stdout) > 64 * 1024:
        raise StagingError("staging_git_failed")
    return completed.stdout.strip()


def _tag_message(reviewed_sha: str, tree_digest: str) -> str:
    return json.dumps(
        {
            "reviewed_sha": reviewed_sha,
            "schema_version": 1,
            "tree_digest": tree_digest,
        },
        separators=(",", ":"),
        sort_keys=True,
    )


def _tag_metadata(raw: object) -> dict[str, str]:
    if not isinstance(raw, str) or len(raw) > 1024:
        raise StagingError("staging_remote_invalid")
    try:
        payload = json.loads(raw, object_pairs_hook=_unique_object)
    except (json.JSONDecodeError, ValueError) as exc:
        raise StagingError("staging_remote_invalid") from exc
    if not isinstance(payload, dict) or set(payload) != {
        "reviewed_sha",
        "schema_version",
        "tree_digest",
    }:
        raise StagingError("staging_remote_invalid")
    reviewed_sha = payload.get("reviewed_sha")
    tree_digest = payload.get("tree_digest")
    if (
        payload.get("schema_version") != 1
        or not isinstance(reviewed_sha, str)
        or _SHA.fullmatch(reviewed_sha) is None
        or not isinstance(tree_digest, str)
        or _DIGEST.fullmatch(tree_digest) is None
    ):
        raise StagingError("staging_remote_invalid")
    return {"reviewed_sha": reviewed_sha, "tree_digest": tree_digest}


def _mapping(payload: dict[str, Any], key: str) -> dict[str, Any]:
    value = payload.get(key)
    if not isinstance(value, dict):
        raise StagingError("staging_remote_invalid")
    return value


def _sha(payload: dict[str, Any], key: str) -> str:
    value = payload.get(key)
    if not isinstance(value, str) or _SHA.fullmatch(value) is None:
        raise StagingError("staging_remote_invalid")
    return value


def _decode_blob(raw: object, expected_sha: str) -> bytes:
    if not isinstance(raw, str) or len(raw) > 96 * 1024 * 1024:
        raise StagingError("staging_remote_invalid")
    normalized = raw.replace("\r\n", "").replace("\n", "")
    if any(character.isspace() for character in normalized):
        raise StagingError("staging_remote_invalid")
    try:
        content = base64.b64decode(normalized, validate=True)
    except (ValueError, base64.binascii.Error) as exc:
        raise StagingError("staging_remote_invalid") from exc
    object_bytes = f"blob {len(content)}\0".encode() + content
    if hashlib.sha1(object_bytes).hexdigest() != expected_sha:  # noqa: S324
        raise StagingError("staging_remote_invalid")
    return content


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    output: dict[str, Any] = {}
    for key, value in pairs:
        if key in output:
            raise ValueError("duplicate JSON key")
        output[key] = value
    return output
