"""GitHub REST backend for immutable Mercury release publication."""

from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request
from datetime import UTC, datetime

from pydantic import SecretStr

from mercury_release_control.handoff import ReleaseArtifact
from mercury_release_control.publication import (
    PublicationError,
    RemoteAsset,
    RemoteRelease,
    RemoteTag,
)

_DOWNLOAD_HOSTS = frozenset(
    {
        "github-releases.githubusercontent.com",
        "objects.githubusercontent.com",
        "release-assets.githubusercontent.com",
        "github-production-release-asset-2e65be.s3.amazonaws.com",
    }
)


class GitHubPublicationBackend:
    def __init__(self, *, repository: str, token: SecretStr) -> None:
        if len(repository.split("/")) != 2 or any(
            not part or not _safe_name(part) for part in repository.split("/")
        ):
            raise PublicationError("publication_repository_invalid")
        self._repository = repository
        self._token = token

    def read_tag(self, tag: str) -> RemoteTag | None:
        encoded = urllib.parse.quote(tag, safe="")
        reference = self._json(
            "GET", f"/repos/{self._repository}/git/ref/tags/{encoded}", allow_404=True
        )
        if reference is None:
            return None
        ref_object = _mapping(reference.get("object"))
        if ref_object.get("type") != "tag":
            raise PublicationError("publication_tag_mismatch")
        tag_object = self._json(
            "GET", f"/repos/{self._repository}/git/tags/{_sha(ref_object.get('sha'))}"
        )
        target = _mapping(tag_object.get("object"))
        if target.get("type") != "commit" or tag_object.get("tag") != tag:
            raise PublicationError("publication_tag_mismatch")
        return RemoteTag(annotated=True, commit=_sha(target.get("sha")), name=tag)

    def create_tag(self, *, tag: str, commit: str, message: str) -> RemoteTag:
        tag_object = self._json(
            "POST",
            f"/repos/{self._repository}/git/tags",
            payload={
                "message": message,
                "object": commit,
                "tag": tag,
                "tagger": {
                    "date": datetime.now(UTC).isoformat(),
                    "email": "release-control@mercury.invalid",
                    "name": "Mercury Release Control",
                },
                "type": "commit",
            },
        )
        tag_sha = _sha(tag_object.get("sha"))
        self._json(
            "POST",
            f"/repos/{self._repository}/git/refs",
            payload={"ref": f"refs/tags/{tag}", "sha": tag_sha},
        )
        observed = self.read_tag(tag)
        if observed is None:
            raise PublicationError("publication_tag_mismatch")
        return observed

    def read_release(self, tag: str) -> RemoteRelease | None:
        encoded = urllib.parse.quote(tag, safe="")
        payload = self._json(
            "GET", f"/repos/{self._repository}/releases/tags/{encoded}", allow_404=True
        )
        if payload is None:
            return None
        return _remote_release(payload)

    def create_draft(self, *, tag: str, name: str, body: str) -> RemoteRelease:
        payload = self._json(
            "POST",
            f"/repos/{self._repository}/releases",
            payload={
                "body": body,
                "draft": True,
                "generate_release_notes": False,
                "name": name,
                "prerelease": False,
                "tag_name": tag,
                "target_commitish": tag,
            },
        )
        return _remote_release(payload)

    def upload_asset(self, release_id: int, asset: ReleaseArtifact, content: bytes) -> None:
        name = urllib.parse.quote(asset.name, safe="")
        self._json_url(
            "POST",
            f"https://uploads.github.com/repos/{self._repository}/releases/{release_id}/assets?name={name}",
            body=content,
            content_type="application/octet-stream",
        )

    def download_asset(self, release_id: int, name: str) -> bytes:
        release = self._json("GET", f"/repos/{self._repository}/releases/{release_id}")
        assets = release.get("assets")
        if not isinstance(assets, list):
            raise PublicationError("publication_remote_asset_invalid")
        asset_id: int | None = None
        for asset in assets:
            if isinstance(asset, dict) and asset.get("name") == name:
                observed = asset.get("id")
                if isinstance(observed, int) and not isinstance(observed, bool) and observed > 0:
                    asset_id = observed
        if asset_id is None:
            raise PublicationError("publication_remote_asset_invalid")
        return self._bytes(
            "GET",
            f"https://api.github.com/repos/{self._repository}/releases/assets/{asset_id}",
            accept="application/octet-stream",
        )

    def publish(self, release_id: int) -> None:
        payload = self._json(
            "PATCH",
            f"/repos/{self._repository}/releases/{release_id}",
            payload={"draft": False},
        )
        if payload.get("draft") is not False:
            raise PublicationError("publication_final_state_invalid")

    def immutable_enabled(self) -> bool:
        payload = self._json("GET", f"/repos/{self._repository}/immutable-releases", allow_404=True)
        return payload is not None and payload.get("enabled") is True

    def enable_immutable(self) -> None:
        status, body = self._request(
            "PUT", f"https://api.github.com/repos/{self._repository}/immutable-releases"
        )
        if status != 204 or body:
            raise PublicationError("publication_final_state_invalid")

    def _json(
        self,
        method: str,
        path: str,
        *,
        payload: dict[str, object] | None = None,
        allow_404: bool = False,
    ) -> dict[str, object] | None:
        return self._json_url(
            method,
            f"https://api.github.com{path}",
            payload=payload,
            allow_404=allow_404,
        )

    def _json_url(
        self,
        method: str,
        url: str,
        *,
        payload: dict[str, object] | None = None,
        body: bytes | None = None,
        content_type: str = "application/json",
        allow_404: bool = False,
    ) -> dict[str, object] | None:
        if payload is not None:
            body = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()
        try:
            _, raw = self._request(method, url, body=body, content_type=content_type)
        except _NotFound:
            if allow_404:
                return None
            raise PublicationError("publication_github_api_failed") from None
        try:
            decoded = json.loads(raw, object_pairs_hook=_unique_object)
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
            raise PublicationError("publication_github_response_invalid") from exc
        if not isinstance(decoded, dict):
            raise PublicationError("publication_github_response_invalid")
        return decoded

    def _bytes(
        self,
        method: str,
        url: str,
        *,
        accept: str = "application/vnd.github+json",
        body: bytes | None = None,
        content_type: str = "application/json",
    ) -> bytes:
        _, content = self._request(
            method,
            url,
            accept=accept,
            body=body,
            content_type=content_type,
        )
        return content

    def _request(
        self,
        method: str,
        url: str,
        *,
        accept: str = "application/vnd.github+json",
        body: bytes | None = None,
        content_type: str = "application/json",
    ) -> tuple[int, bytes]:
        parsed = urllib.parse.urlsplit(url)
        if parsed.scheme != "https" or parsed.hostname not in {
            "api.github.com",
            "uploads.github.com",
        }:
            raise PublicationError("publication_github_url_invalid")
        request = urllib.request.Request(
            url,
            method=method,
            data=body,
            headers={
                "Accept": accept,
                "Authorization": f"Bearer {self._token.get_secret_value()}",
                "Content-Type": content_type,
                "User-Agent": "mercury-release-control-v2",
                "X-GitHub-Api-Version": "2026-03-10",
            },
        )
        opener = urllib.request.build_opener(_SafeRedirect())
        try:
            with opener.open(request, timeout=30) as response:
                status = response.status
                content = response.read(1024 * 1024 * 1024 + 1)
        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                raise _NotFound from exc
            raise PublicationError("publication_github_api_failed") from exc
        except (urllib.error.URLError, OSError, TimeoutError) as exc:
            raise PublicationError("publication_github_api_failed") from exc
        if len(content) > 1024 * 1024 * 1024:
            raise PublicationError("publication_github_response_invalid")
        return status, content


class _SafeRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, newurl):
        redirected = super().redirect_request(request, fp, code, msg, headers, newurl)
        if redirected is None:
            return None
        parsed = urllib.parse.urlsplit(newurl)
        if parsed.scheme != "https" or parsed.hostname not in _DOWNLOAD_HOSTS:
            raise PublicationError("publication_github_redirect_invalid")
        redirected.remove_header("Authorization")
        return redirected


class _NotFound(RuntimeError):
    pass


def _remote_release(payload: dict[str, object]) -> RemoteRelease:
    assets = payload.get("assets")
    if not isinstance(assets, list) or len(assets) > 100:
        raise PublicationError("publication_remote_asset_invalid")
    observed: list[RemoteAsset] = []
    for raw in assets:
        asset = _mapping(raw)
        digest = asset.get("digest")
        if not isinstance(digest, str) or not digest.startswith("sha256:"):
            raise PublicationError("publication_remote_asset_invalid")
        size = asset.get("size")
        if not isinstance(size, int) or isinstance(size, bool) or size <= 0:
            raise PublicationError("publication_remote_asset_invalid")
        observed.append(
            RemoteAsset(
                name=_text(asset.get("name")),
                sha256=_sha256(digest.removeprefix("sha256:")),
                size=size,
            )
        )
    release_id = payload.get("id")
    if not isinstance(release_id, int) or isinstance(release_id, bool) or release_id <= 0:
        raise PublicationError("publication_github_response_invalid")
    return RemoteRelease(
        assets=tuple(sorted(observed, key=lambda item: item.name)),
        draft=payload.get("draft") is True,
        immutable=payload.get("immutable") is True,
        name=_text(payload.get("name")),
        release_id=release_id,
        tag=_text(payload.get("tag_name")),
    )


def _mapping(value: object) -> dict[str, object]:
    if not isinstance(value, dict):
        raise PublicationError("publication_github_response_invalid")
    return value


def _text(value: object) -> str:
    if not isinstance(value, str) or not value or len(value) > 4096:
        raise PublicationError("publication_github_response_invalid")
    return value


def _sha(value: object) -> str:
    if not isinstance(value, str) or len(value) != 40 or not set(value) <= set("0123456789abcdef"):
        raise PublicationError("publication_github_response_invalid")
    return value


def _sha256(value: str) -> str:
    if len(value) != 64 or not set(value) <= set("0123456789abcdef"):
        raise PublicationError("publication_github_response_invalid")
    return value


def _safe_name(value: str) -> bool:
    return all(character.isalnum() or character in "_.-" for character in value)


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    output: dict[str, object] = {}
    for key, value in pairs:
        if key in output:
            raise ValueError("duplicate JSON key")
        output[key] = value
    return output
