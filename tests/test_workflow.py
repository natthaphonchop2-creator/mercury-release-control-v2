from __future__ import annotations

import json
import stat
from pathlib import Path

import pytest

from mercury_release_control.workflow import WorkflowError, _load_json, _write_new


def test_workflow_output_is_exclusive_bounded_and_private(tmp_path: Path) -> None:
    output = tmp_path / "receipt.json"

    _write_new(output, {"status": "ok"})

    assert json.loads(output.read_text(encoding="utf-8")) == {"status": "ok"}
    assert stat.S_IMODE(output.stat().st_mode) == 0o600
    with pytest.raises(WorkflowError, match="^workflow_output_invalid$"):
        _write_new(output, {"status": "forged"})


def test_workflow_input_rejects_duplicate_json_keys(tmp_path: Path) -> None:
    source = tmp_path / "input.json"
    source.write_bytes(b'{"status":"ok","status":"forged"}')

    with pytest.raises(WorkflowError, match="^workflow_input_invalid$"):
        _load_json(source)
