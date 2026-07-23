from __future__ import annotations

import re
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github/workflows/attest-v0.3.0.yml"
ACTION_PIN = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+@[0-9a-f]{40}$")
SUPABASE_CA_URL = (
    "https://supabase-downloads.s3-ap-southeast-1.amazonaws.com/"
    "prod/ssl/prod-ca-2021.crt"
)
SUPABASE_CA_SHA256 = "700723581420dd1ac98fd7e9ac529f0ef210eadcaf87fc868a3ad7d114c2f3b7"


def test_attestation_workflow_is_pinned_single_artifact_and_dependency_ordered() -> None:
    text = WORKFLOW.read_text(encoding="utf-8")
    workflow = yaml.load(text, Loader=yaml.BaseLoader)

    assert workflow["permissions"] == {"actions": "write", "contents": "read"}
    job = workflow["jobs"]["attest"]
    assert job["environment"] == "production-release"
    steps = job["steps"]
    names = [step["name"] for step in steps]
    assert names.index("Verify GitHub identities and protected release environment") < names.index(
        "Build and publish exact history-free staging"
    )
    assert names.index("Build and publish exact history-free staging") < names.index(
        "Inspect every hosted and repository surface"
    )
    assert names.index("Inspect every hosted and repository surface") < names.index(
        "Assemble exact sanitized TrustedAttestationV2"
    )
    assert names.index("Assemble exact sanitized TrustedAttestationV2") < names.index(
        "Dispatch secretless Mercury artifact verification"
    )
    actions = [step["uses"] for step in steps if "uses" in step]
    assert len([action for action in actions if action.startswith("actions/upload-artifact@")]) == 1
    assert all(ACTION_PIN.fullmatch(action) for action in actions)
    assert "pull_request_target" not in text
    assert "release-v0.3.0.yml/dispatches" in text


def test_attestation_workflow_never_executes_candidate_files() -> None:
    text = WORKFLOW.read_text(encoding="utf-8")

    assert "pip install ." not in text
    assert "uv run --project $RUNNER_TEMP" not in text
    assert "source $RUNNER_TEMP" not in text
    assert "bash $RUNNER_TEMP" not in text
    assert 'git -C "$MIRROR" archive' in text


def test_attestation_workflow_supplies_render_owner_id_to_surface_inspector() -> None:
    workflow = yaml.load(WORKFLOW.read_text(encoding="utf-8"), Loader=yaml.BaseLoader)
    steps = workflow["jobs"]["attest"]["steps"]
    inspect_step = next(
        step for step in steps if step["name"] == "Inspect every hosted and repository surface"
    )

    assert inspect_step["env"]["RENDER_OWNER_ID"] == "${{ vars.RENDER_OWNER_ID }}"


def test_attestation_workflows_pin_supabase_ca_and_bind_pgsslrootcert() -> None:
    for version in ("0.2.2", "0.3.0"):
        path = ROOT / f".github/workflows/attest-v{version}.yml"
        workflow = yaml.load(path.read_text(encoding="utf-8"), Loader=yaml.BaseLoader)
        steps = workflow["jobs"]["attest"]["steps"]
        names = [step["name"] for step in steps]
        prepare = next(
            step for step in steps if step["name"] == "Prepare checksum-pinned Supabase root CA"
        )
        inspect = next(
            step for step in steps if step["name"] == "Inspect every hosted and repository surface"
        )

        assert names.index(prepare["name"]) < names.index(inspect["name"])
        assert prepare["env"] == {
            "SUPABASE_CA_SHA256": SUPABASE_CA_SHA256,
            "SUPABASE_CA_URL": SUPABASE_CA_URL,
        }
        assert "curl --fail --location --proto '=https' --tlsv1.2" in prepare["run"]
        assert "sha256sum --check" in prepare["run"]
        assert 'PGSSLROOTCERT="$RUNNER_TEMP/mercury-release/tls/prod-ca-2021.crt"' in inspect[
            "run"
        ]
        assert "export PGSSLROOTCERT" in inspect["run"]
        assert 'test -r "$PGSSLROOTCERT"' in inspect["run"]


def test_attestation_dispatch_does_not_relay_caller_supplied_staging_identity() -> None:
    text = WORKFLOW.read_text(encoding="utf-8")
    dispatch = text.split(
        "- name: Dispatch secretless Mercury artifact verification", 1
    )[1]

    assert "--arg staging_ref" not in dispatch
    assert "--arg public_tree_digest" not in dispatch
    assert "staging_ref:" not in dispatch
    assert "public_tree_digest:" not in dispatch
    assert "release_control_attestation_gzip_b64" in dispatch


def test_attestation_dispatch_uses_bounded_deterministic_gzip_transport() -> None:
    text = WORKFLOW.read_text(encoding="utf-8")
    dispatch = text.split(
        "- name: Dispatch secretless Mercury artifact verification", 1
    )[1]

    assert (
        'ATTESTATION_GZIP_B64="$(gzip --no-name --best --stdout "$ATTESTATION" '
        '| base64 --wrap=0)"'
    ) in dispatch
    assert 'test "${#ATTESTATION_GZIP_B64}" -le 60000' in dispatch
    assert "--arg control_attestation_gzip_b64" in dispatch
    assert "release_control_attestation_gzip_b64: $control_attestation_gzip_b64" in dispatch
    assert "release_control_attestation_b64" not in dispatch
    assert "ATTESTATION_B64" not in dispatch
