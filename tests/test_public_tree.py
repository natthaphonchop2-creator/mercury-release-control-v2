from __future__ import annotations

import base64
import io
import json
import tarfile
from pathlib import Path

import pytest

from mercury_release_control.public_tree import PublicTreeError, build_public_tree

FIXTURE = Path(__file__).parent / "fixtures/public-tree-v1.json"


def _archive(
    members: list[dict[str, object]],
    *,
    global_headers: dict[str, str] | None = None,
) -> bytes:
    output = io.BytesIO()
    with tarfile.open(
        fileobj=output,
        mode="w",
        format=tarfile.PAX_FORMAT,
        pax_headers=global_headers,
    ) as archive:
        for raw in members:
            member = tarfile.TarInfo(str(raw["path"]))
            member.mode = int(raw["mode"])
            content = base64.b64decode(str(raw["content_b64"]), validate=True)
            member.size = len(content)
            archive.addfile(member, io.BytesIO(content))
    return output.getvalue()


def test_public_tree_fixture_contract() -> None:
    fixture = json.loads(FIXTURE.read_text(encoding="utf-8"))

    snapshot = build_public_tree(_archive(fixture["members"]))

    assert snapshot.digest == fixture["expected_digest"]
    assert list(snapshot.public_inventory()) == fixture["entries"]


def test_public_tree_accepts_exact_git_global_comment() -> None:
    fixture = json.loads(FIXTURE.read_text(encoding="utf-8"))
    snapshot = build_public_tree(
        _archive(fixture["members"], global_headers={"comment": "a" * 40})
    )
    assert snapshot.digest == fixture["expected_digest"]


@pytest.mark.parametrize("path", ("../secret", "/secret", "a/../b", "a\\b"))
def test_public_tree_rejects_unsafe_paths(path: str) -> None:
    member = {
        "content_b64": base64.b64encode(b"x").decode(),
        "mode": 0o100644,
        "path": path,
    }
    with pytest.raises(PublicTreeError, match="^public_tree_archive_invalid$"):
        build_public_tree(_archive([member]))


def test_public_tree_rejects_casefolded_duplicates() -> None:
    members = [
        {
            "content_b64": base64.b64encode(name.encode()).decode(),
            "mode": 0o100644,
            "path": name,
        }
        for name in ("Docs/Guide.md", "docs/guide.md")
    ]
    with pytest.raises(PublicTreeError, match="^public_tree_archive_invalid$"):
        build_public_tree(_archive(members))


def test_public_tree_rejects_unapproved_global_pax() -> None:
    fixture = json.loads(FIXTURE.read_text(encoding="utf-8"))
    with pytest.raises(PublicTreeError, match="^public_tree_archive_invalid$"):
        build_public_tree(
            _archive(fixture["members"], global_headers={"comment": "not-a-commit"})
        )
