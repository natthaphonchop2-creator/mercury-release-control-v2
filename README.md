# Mercury Release Control v2

Trusted release control plane for Mercury Tools `v0.3.0`.

This repository verifies reviewed Mercury source as untrusted bytes, creates a
history-free public staging snapshot, inspects approved hosted providers, emits
a sanitized attempt-bound attestation, and publishes the final immutable GitHub
Release only after every gate passes.

ERP credentials and raw accounting payloads must never be committed here. Live
release credentials exist only in the protected `production-release` GitHub
environment.

The manual `migrate-v0.3.0.yml` workflow is the only trusted production schema
mutation path for this release. It binds an approved Mercury main commit to one
checksum-pinned migration, reruns the protected GitHub preflight before database
access, verifies the exact pre-migration history and schema footprint, runs one
locked transaction, and validates the resulting security boundary before commit.
The trusted Guardian also pins the privileged workflow, runner, policy, import
closure, and dependency lock independently of the candidate manifest. A configured
GitHub control plane does not imply that
the provider migration or deployment has completed; hosted attestation checks
those states independently.

The repository is an independent open-source project and is not affiliated with
Mercury Technologies, Inc.
