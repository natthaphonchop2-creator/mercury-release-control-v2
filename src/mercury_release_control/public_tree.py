"""Independent PublicTreeV1 implementation for trusted release control."""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import re
import tarfile
import unicodedata
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath

MAX_ARCHIVE_BYTES = 256 * 1024 * 1024
MAX_ARCHIVE_MEMBERS = 100_000
MAX_MEMBER_BYTES = 64 * 1024 * 1024
MAX_TOTAL_BYTES = 1024 * 1024 * 1024
MAX_PATH_BYTES = 4096
MAX_PATH_DEPTH = 64

_EXCLUDED_DIRECTORIES = frozenset(
    {
        ".git",
        ".mercury",
        ".superpowers",
        "__pycache__",
        "build",
        "dist",
        "release-evidence",
    }
)
_EXCLUDED_STATE_FILES = frozenset(
    {
        "audit-ledger.jsonl",
        "credential-store.json",
        "credentials-store.json",
        "downloaded-provider-payload.json",
        "provider-payload.json",
        "provider-response.json",
        "raw-provider-payload.json",
        "raw-provider-response.json",
        "validation-raw-traffic.json",
        "validation-traffic.json",
    }
)
_COMMIT_PATTERN = re.compile(r"^[0-9a-f]{40}(?:[0-9a-f]{24})?$")


class PublicTreeError(RuntimeError):
    """A constant-code trusted public-tree failure."""


@dataclass(frozen=True, slots=True)
class PublicTreeEntry:
    path: str
    mode: int
    sha256: str
    content: bytes = field(repr=False)

    def public_identity(self) -> dict[str, str | int]:
        return {"mode": self.mode, "path": self.path, "sha256": self.sha256}


@dataclass(frozen=True, slots=True)
class PublicTreeSnapshot:
    entries: tuple[PublicTreeEntry, ...]
    digest: str

    def public_inventory(self) -> tuple[dict[str, str | int], ...]:
        return tuple(entry.public_identity() for entry in self.entries)

    def as_dict(self) -> dict[str, object]:
        return {
            "digest": self.digest,
            "entries": list(self.public_inventory()),
            "schema_version": 1,
        }


def build_public_tree(archive_bytes: bytes) -> PublicTreeSnapshot:
    if (
        not isinstance(archive_bytes, bytes)
        or not archive_bytes
        or len(archive_bytes) > MAX_ARCHIVE_BYTES
    ):
        raise PublicTreeError("public_tree_archive_too_large")
    try:
        with tarfile.open(fileobj=io.BytesIO(archive_bytes), mode="r:") as archive:
            global_comment = _git_comment(archive.pax_headers)
            members = archive.getmembers()
            if len(members) > MAX_ARCHIVE_MEMBERS:
                raise PublicTreeError("public_tree_archive_too_large")
            entries: list[PublicTreeEntry] = []
            collision_keys: set[str] = set()
            total_bytes = 0
            for member in members:
                name = _member_name(member, global_comment)
                key = name.casefold()
                if key in collision_keys:
                    raise PublicTreeError("public_tree_archive_invalid")
                collision_keys.add(key)
                if member.isdir():
                    continue
                if not member.isfile():
                    raise PublicTreeError("public_tree_archive_invalid")
                if member.size < 0 or member.size > MAX_MEMBER_BYTES:
                    raise PublicTreeError("public_tree_archive_too_large")
                total_bytes += member.size
                if total_bytes > MAX_TOTAL_BYTES:
                    raise PublicTreeError("public_tree_archive_too_large")
                if _excluded(name):
                    continue
                stream = archive.extractfile(member)
                if stream is None:
                    raise PublicTreeError("public_tree_archive_invalid")
                content = stream.read(MAX_MEMBER_BYTES + 1)
                if len(content) != member.size or len(content) > MAX_MEMBER_BYTES:
                    raise PublicTreeError("public_tree_archive_invalid")
                entries.append(
                    PublicTreeEntry(
                        path=name,
                        mode=0o755 if member.mode & 0o111 else 0o644,
                        sha256=hashlib.sha256(content).hexdigest(),
                        content=content,
                    )
                )
    except PublicTreeError:
        raise
    except (OSError, tarfile.TarError, UnicodeError, ValueError) as exc:
        raise PublicTreeError("public_tree_archive_invalid") from exc

    ordered = tuple(sorted(entries, key=lambda entry: entry.path))
    records = b"".join(
        f"{entry.mode:o} {entry.path}\0{entry.sha256}".encode()
        for entry in ordered
    )
    return PublicTreeSnapshot(entries=ordered, digest=hashlib.sha256(records).hexdigest())


def _excluded(name: str) -> bool:
    parts = tuple(part.casefold() for part in PurePosixPath(name).parts)
    return (
        any(part in _EXCLUDED_DIRECTORIES for part in parts)
        or any(part == ".env" or part.startswith(".env.") for part in parts)
        or bool(parts and parts[-1] in _EXCLUDED_STATE_FILES)
    )


def _member_name(member: tarfile.TarInfo, global_comment: str | None) -> str:
    expected_headers = {"comment": global_comment} if global_comment is not None else {}
    if member.pax_headers != expected_headers:
        raise PublicTreeError("public_tree_archive_invalid")
    name = member.name[:-1] if member.isdir() and member.name.endswith("/") else member.name
    normalized = unicodedata.normalize("NFC", name)
    path = PurePosixPath(name)
    parts = name.split("/")
    if (
        not name
        or "\0" in name
        or "\\" in name
        or normalized != name
        or path.is_absolute()
        or path.as_posix() != name
        or any(part in {"", ".", ".."} for part in parts)
        or len(parts) > MAX_PATH_DEPTH
        or len(name.encode()) > MAX_PATH_BYTES
    ):
        raise PublicTreeError("public_tree_archive_invalid")
    return name


def _git_comment(headers: dict[str, str]) -> str | None:
    if not headers:
        return None
    comment = headers.get("comment")
    if set(headers) != {"comment"} or not isinstance(comment, str):
        raise PublicTreeError("public_tree_archive_invalid")
    if _COMMIT_PATTERN.fullmatch(comment) is None:
        raise PublicTreeError("public_tree_archive_invalid")
    return comment


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        snapshot = build_public_tree(args.archive.read_bytes())
    except (OSError, PublicTreeError) as exc:
        code = str(exc) if isinstance(exc, PublicTreeError) else "public_tree_archive_invalid"
        print(json.dumps({"error": code, "status": "error"}, sort_keys=True))
        return 1
    print(json.dumps(snapshot.as_dict(), separators=(",", ":"), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
