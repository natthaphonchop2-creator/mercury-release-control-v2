from __future__ import annotations

import re
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW_PATH = ROOT / ".github/workflows/migrate-v0.3.0.yml"
ACTION_PIN = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+@[0-9a-f]{40}$")
MERCURY_REPOSITORY = "natthaphonchop2-creator/mercury-tools"
MERCURY_REPOSITORY_ID = "1290137723"
MIGRATION_PATH = "supabase/migrations/20260719120000_connector_neutral_profiles.sql"
MIGRATION_SHA256 = "2ca702823fd17a7806ead1b829af21984ea54b676700cf443cb69b7e6161c0ca"
CA_URL = "https://supabase-downloads.s3-ap-southeast-1.amazonaws.com/prod/ssl/prod-ca-2021.crt"
CA_SHA256 = "700723581420dd1ac98fd7e9ac529f0ef210eadcaf87fc868a3ad7d114c2f3b7"


def _workflow() -> dict[str, object]:
    if not WORKFLOW_PATH.is_file():
        return {}
    payload = yaml.load(WORKFLOW_PATH.read_text(encoding="utf-8"), Loader=yaml.BaseLoader)
    assert isinstance(payload, dict)
    return payload


def test_migration_workflow_is_manual_main_only_concurrent_and_environment_protected() -> None:
    workflow = _workflow()

    assert workflow["on"] == {
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
    assert workflow["permissions"] == {"contents": "read"}
    assert workflow["concurrency"] == {
        "cancel-in-progress": "false",
        "group": "mercury-v0.3.0-production-migration",
    }
    assert set(workflow["jobs"]) == {"migrate", "reject-non-main"}
    assert workflow["jobs"]["reject-non-main"]["if"] == ("${{ github.ref != 'refs/heads/main' }}")
    job = workflow["jobs"]["migrate"]
    assert job["if"] == "${{ github.ref == 'refs/heads/main' }}"
    assert job["environment"] == "production-release"
    assert job["runs-on"] == "ubuntu-24.04"
    assert job["timeout-minutes"] == "20"


def test_migration_workflow_checks_out_exact_trusted_control_main_commit() -> None:
    workflow = _workflow()
    steps = workflow["jobs"]["migrate"]["steps"]
    checkout = next(step for step in steps if step["name"] == "Checkout exact trusted control")

    assert checkout["with"] == {
        "fetch-depth": "1",
        "persist-credentials": "false",
        "ref": "${{ github.sha }}",
    }
    assert all(ACTION_PIN.fullmatch(step["uses"]) for step in steps if "uses" in step)
    bind = next(step for step in steps if step["name"] == "Bind trusted control implementation")
    assert 'test "$GITHUB_REF" = "refs/heads/main"' in bind["run"]
    assert 'test "$(git rev-parse HEAD)" = "$GITHUB_SHA"' in bind["run"]
    assert 'test -z "$(git status --porcelain)"' in bind["run"]
    assert "uv sync --frozen" in bind["run"]


def test_migration_workflow_fetches_only_exact_reviewed_mercury_migration_as_data() -> None:
    workflow = _workflow()
    step = next(
        item
        for item in workflow["jobs"]["migrate"]["steps"]
        if item["name"] == "Fetch exact reviewed migration as untrusted data"
    )
    run = step["run"]

    assert step["env"] == {
        "GH_TOKEN": "${{ secrets.MERCURY_TARGET_REPOSITORY_READ_TOKEN }}",
        "REVIEWED_SHA": "${{ inputs.reviewed_commit_sha }}",
    }
    assert MERCURY_REPOSITORY in run
    assert MERCURY_REPOSITORY_ID in run
    assert MIGRATION_PATH in run
    assert MIGRATION_SHA256 in run
    assert "git/ref/heads/main" in run
    assert 'test "$MAIN_SHA" = "$REVIEWED_SHA"' in run
    assert "application/vnd.github.raw+json" in run
    assert "sha256sum --check" in run
    for forbidden in ("git clone", "git archive", "source $", "bash $", "psql -f"):
        assert forbidden not in run


def test_migration_workflow_pins_ca_and_exports_pgsslrootcert() -> None:
    workflow = _workflow()
    steps = workflow["jobs"]["migrate"]["steps"]
    prepare = next(step for step in steps if step["name"] == "Prepare pinned Supabase root CA")
    migrate = next(step for step in steps if step["name"] == "Run trusted production migration")

    assert prepare["env"] == {
        "SUPABASE_CA_SHA256": CA_SHA256,
        "SUPABASE_CA_URL": CA_URL,
    }
    assert "curl --fail --location --proto '=https' --tlsv1.2" in prepare["run"]
    assert "sha256sum --check" in prepare["run"]
    assert migrate["env"] == {
        "REVIEWED_SHA": "${{ inputs.reviewed_commit_sha }}",
        "SUPABASE_DB_URL": "${{ secrets.SUPABASE_DB_URL }}",
    }
    assert 'PGSSLROOTCERT="$RUNNER_TEMP/mercury-migration/tls/prod-ca-2021.crt"' in migrate["run"]
    assert "export PGSSLROOTCERT" in migrate["run"]
    assert "python -m mercury_release_control.production_migration" in migrate["run"]


def test_migration_workflow_emits_no_artifact_or_secret_material() -> None:
    text = WORKFLOW_PATH.read_text(encoding="utf-8") if WORKFLOW_PATH.is_file() else ""

    assert "actions/upload-artifact" not in text
    assert "actions/download-artifact" not in text
    assert "GITHUB_OUTPUT" not in text
    assert "SUPABASE_DB_URL=" not in text
    assert "echo $SUPABASE" not in text
    assert "set -x" not in text
    assert "pull_request" not in text
