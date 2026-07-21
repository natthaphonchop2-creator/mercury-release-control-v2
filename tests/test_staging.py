from __future__ import annotations

import base64
import hashlib
import io
import json
import subprocess
import tarfile
import urllib.error
import urllib.request
from pathlib import Path

import pytest
from pydantic import SecretStr

from mercury_release_control.staging import (
    ExistingStaging,
    GitHubRestApi,
    GitHubStagingPublisher,
    StagingError,
    build_staging,
    publish_staging,
)

FIXTURE = Path(__file__).parent / "fixtures/public-tree-v1.json"
REVIEWED_SHA = "a" * 40


def _archive() -> bytes:
    fixture = json.loads(FIXTURE.read_text(encoding="utf-8"))
    output = io.BytesIO()
    with tarfile.open(
        fileobj=output,
        mode="w",
        format=tarfile.PAX_FORMAT,
        pax_headers={"comment": REVIEWED_SHA},
    ) as archive:
        for raw in fixture["members"]:
            content = base64.b64decode(raw["content_b64"], validate=True)
            member = tarfile.TarInfo(raw["path"])
            member.mode = raw["mode"]
            member.size = len(content)
            archive.addfile(member, io.BytesIO(content))
    return output.getvalue()


def _git(root: Path, *arguments: str) -> str:
    return subprocess.run(
        ["git", *arguments],
        cwd=root,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


def test_staging_is_one_unrelated_commit_with_exact_public_tree(tmp_path: Path) -> None:
    output = tmp_path / "staging"

    identity = build_staging(
        archive_bytes=_archive(),
        reviewed_sha=REVIEWED_SHA,
        output=output,
        version="0.3.0",
    )

    assert identity.tag == f"v0.3.0-rc.{REVIEWED_SHA[:12]}"
    assert (
        identity.tree_digest == "ca938b2aaaf87fbc8d9a92fac7e0f355070da77e8588c429742d8d5699084d7a"
    )
    assert _git(output, "rev-list", "--all", "--count") == "1"
    assert REVIEWED_SHA not in _git(output, "rev-list", "--all")
    assert _git(output, "cat-file", "-t", identity.tag) == "tag"
    assert _git(output, "rev-parse", f"{identity.tag}^{{commit}}") == identity.staging_commit_sha
    assert not (output / ".env").exists()


def test_staging_rejects_existing_destination(tmp_path: Path) -> None:
    output = tmp_path / "staging"
    output.mkdir()
    with pytest.raises(StagingError, match="^staging_destination_exists$"):
        build_staging(
            archive_bytes=_archive(),
            reviewed_sha=REVIEWED_SHA,
            output=output,
            version="0.3.0",
        )


def test_staging_ignores_caller_git_template_and_hooks(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    marker = tmp_path / "hook-ran"
    template = tmp_path / "template"
    hooks = template / "hooks"
    hooks.mkdir(parents=True)
    hook = hooks / "pre-commit"
    hook.write_text(f"#!/bin/sh\ntouch {marker}\n", encoding="utf-8")
    hook.chmod(0o755)
    config = tmp_path / "global.gitconfig"
    config.write_text(f"[core]\n\thooksPath = {hooks}\n", encoding="utf-8")
    monkeypatch.setenv("GIT_TEMPLATE_DIR", str(template))
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", str(config))

    build_staging(
        archive_bytes=_archive(),
        reviewed_sha=REVIEWED_SHA,
        output=tmp_path / "staging",
        version="0.3.0",
    )

    assert not marker.exists()


class FakePublisher:
    def __init__(self, existing: ExistingStaging | None = None) -> None:
        self.existing = existing
        self.created = 0

    def read(self, repository: str, tag: str) -> ExistingStaging | None:
        return self.existing

    def create(self, repository: str, identity) -> ExistingStaging:
        self.created += 1
        return ExistingStaging.from_identity(identity)


def test_staging_publication_is_idempotent_only_for_exact_identity(tmp_path: Path) -> None:
    identity = build_staging(
        archive_bytes=_archive(),
        reviewed_sha=REVIEWED_SHA,
        output=tmp_path / "staging",
        version="0.3.0",
    )
    publisher = FakePublisher()
    first = publish_staging(
        identity=identity,
        repository="example/mercury-tools-staging",
        publisher=publisher,
    )
    assert first.created is True
    assert publisher.created == 1

    publisher = FakePublisher(ExistingStaging.from_identity(identity))
    repeated = publish_staging(
        identity=identity,
        repository="example/mercury-tools-staging",
        publisher=publisher,
    )
    assert repeated.created is False
    assert publisher.created == 0

    publisher = FakePublisher(ExistingStaging.from_identity(identity, tree_digest="0" * 64))
    with pytest.raises(StagingError, match="^staging_remote_mismatch$"):
        publish_staging(
            identity=identity,
            repository="example/mercury-tools-staging",
            publisher=publisher,
        )


class FakeGitHubApi:
    def __init__(self, existing: ExistingStaging | None = None) -> None:
        self.existing = existing
        self.reads: list[tuple[str, str]] = []

    def read_staging(self, repository: str, tag: str) -> ExistingStaging | None:
        self.reads.append((repository, tag))
        return self.existing


class FakeRefPusher:
    def __init__(self) -> None:
        self.calls: list[tuple[Path, str, str, str]] = []

    def push(
        self,
        *,
        root: Path,
        repository: str,
        tag: str,
        token: SecretStr,
    ) -> None:
        assert token.get_secret_value() == "github-secret"
        self.calls.append((root, repository, tag, repr(token)))


def test_github_publisher_pushes_refs_then_verifies_remote_identity(tmp_path: Path) -> None:
    identity = build_staging(
        archive_bytes=_archive(),
        reviewed_sha=REVIEWED_SHA,
        output=tmp_path / "staging",
        version="0.3.0",
    )
    api = FakeGitHubApi()
    pusher = FakeRefPusher()
    publisher = GitHubStagingPublisher(
        token=SecretStr("github-secret"),
        api=api,
        pusher=pusher,
    )

    assert publisher.read("example/mercury-tools-staging", identity.tag) is None
    api.existing = ExistingStaging.from_identity(identity)
    observed = publisher.create("example/mercury-tools-staging", identity)

    assert observed == ExistingStaging.from_identity(identity)
    assert pusher.calls == [
        (
            identity.path,
            "example/mercury-tools-staging",
            identity.tag,
            "SecretStr('**********')",
        )
    ]
    assert api.reads[-1] == ("example/mercury-tools-staging", identity.tag)


def test_github_publisher_fails_when_remote_verification_differs(tmp_path: Path) -> None:
    identity = build_staging(
        archive_bytes=_archive(),
        reviewed_sha=REVIEWED_SHA,
        output=tmp_path / "staging",
        version="0.3.0",
    )
    api = FakeGitHubApi(ExistingStaging.from_identity(identity, tree_digest="0" * 64))
    publisher = GitHubStagingPublisher(
        token=SecretStr("github-secret"),
        api=api,
        pusher=FakeRefPusher(),
    )

    with pytest.raises(StagingError, match="^staging_remote_mismatch$"):
        publisher.create("example/mercury-tools-staging", identity)


class FakeHttpResponse:
    def __init__(self, payload: dict) -> None:
        self._body = json.dumps(payload).encode()

    def __enter__(self):
        return self

    def __exit__(self, *_args) -> None:
        return None

    def read(self, _limit: int) -> bytes:
        return self._body


def test_github_rest_api_treats_exact_empty_repository_conflict_as_missing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    tag = f"v0.3.0-rc.{REVIEWED_SHA[:12]}"
    payload = {
        "message": "Git Repository is empty.",
        "documentation_url": "https://docs.github.com/rest/git/refs#get-a-reference",
        "status": "409",
    }

    def fake_urlopen(request: urllib.request.Request, timeout: int):
        raise urllib.error.HTTPError(
            request.full_url,
            409,
            "Conflict",
            {},
            io.BytesIO(json.dumps(payload).encode()),
        )

    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)

    assert (
        GitHubRestApi(token=SecretStr("github-secret")).read_staging(
            "example/mercury-tools-staging", tag
        )
        is None
    )


def test_github_rest_api_rejects_other_conflict_responses(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    tag = f"v0.3.0-rc.{REVIEWED_SHA[:12]}"
    payload = {
        "message": "Repository rule conflict.",
        "documentation_url": "https://docs.github.com/rest/git/refs#get-a-reference",
        "status": "409",
    }

    def fake_urlopen(request: urllib.request.Request, timeout: int):
        raise urllib.error.HTTPError(
            request.full_url,
            409,
            "Conflict",
            {},
            io.BytesIO(json.dumps(payload).encode()),
        )

    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)

    with pytest.raises(StagingError, match="^staging_github_api_failed$"):
        GitHubRestApi(token=SecretStr("github-secret")).read_staging(
            "example/mercury-tools-staging", tag
        )


def _blob_sha(content: bytes) -> str:
    return hashlib.sha1(f"blob {len(content)}\0".encode() + content).hexdigest()


def test_github_rest_api_reconstructs_and_verifies_remote_public_tree(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    reviewed_sha = "a" * 40
    commit_sha = "b" * 40
    tag_object_sha = "c" * 40
    tree_sha = "d" * 40
    tag = f"v0.3.0-rc.{reviewed_sha[:12]}"
    tree_digest = "ca938b2aaaf87fbc8d9a92fac7e0f355070da77e8588c429742d8d5699084d7a"
    contents = {
        "README.md": b"Mercury public tree fixture\n",
        "bin/run": b"#!/bin/sh\nexit 0\n",
    }
    blobs = {_blob_sha(content): content for content in contents.values()}
    prefix = "https://api.github.com/repos/example/mercury-tools-staging"
    responses = {
        f"{prefix}/git/ref/tags/{tag}": {"object": {"sha": tag_object_sha, "type": "tag"}},
        f"{prefix}/git/tags/{tag_object_sha}": {
            "message": json.dumps(
                {
                    "reviewed_sha": reviewed_sha,
                    "schema_version": 1,
                    "tree_digest": tree_digest,
                },
                separators=(",", ":"),
                sort_keys=True,
            ),
            "object": {"sha": commit_sha, "type": "commit"},
            "sha": tag_object_sha,
            "tag": tag,
        },
        f"{prefix}/git/commits/{commit_sha}": {
            "sha": commit_sha,
            "tree": {"sha": tree_sha},
        },
        f"{prefix}/git/trees/{tree_sha}?recursive=1": {
            "tree": [
                {
                    "mode": "100644",
                    "path": "README.md",
                    "sha": _blob_sha(contents["README.md"]),
                    "type": "blob",
                },
                {
                    "mode": "040000",
                    "path": "bin",
                    "sha": "e" * 40,
                    "type": "tree",
                },
                {
                    "mode": "100755",
                    "path": "bin/run",
                    "sha": _blob_sha(contents["bin/run"]),
                    "type": "blob",
                },
            ],
            "truncated": False,
        },
    }
    for blob_sha, content in blobs.items():
        responses[f"{prefix}/git/blobs/{blob_sha}"] = {
            "content": base64.b64encode(content).decode(),
            "encoding": "base64",
        }

    def fake_urlopen(request: urllib.request.Request, timeout: int):
        assert timeout == 20
        assert request.headers["Authorization"] == "Bearer github-secret"
        return FakeHttpResponse(responses[request.full_url])

    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)

    observed = GitHubRestApi(token=SecretStr("github-secret")).read_staging(
        "example/mercury-tools-staging", tag
    )

    assert observed == ExistingStaging(
        reviewed_sha=reviewed_sha,
        staging_commit_sha=commit_sha,
        tag=tag,
        tag_object_sha=tag_object_sha,
        tree_digest=tree_digest,
    )


def test_github_rest_api_rejects_noncanonical_remote_directory_mode() -> None:
    api = GitHubRestApi(token=SecretStr("github-secret"))

    with pytest.raises(StagingError, match="^staging_remote_invalid$"):
        api._remote_snapshot(
            "example/mercury-tools-staging",
            [
                {
                    "mode": "100644",
                    "path": "bin",
                    "sha": "e" * 40,
                    "type": "tree",
                }
            ],
        )
