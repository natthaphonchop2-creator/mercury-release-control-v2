# Mercury Release Control v2

Trusted release control plane for Mercury Tools `v0.2.2`.

This repository verifies reviewed Mercury source as untrusted bytes, creates a
history-free public staging snapshot, inspects approved hosted providers, emits
a sanitized attempt-bound attestation, and publishes the final immutable GitHub
Release only after every gate passes.

ERP credentials and raw accounting payloads must never be committed here. Live
release credentials exist only in the protected `production-release` GitHub
environment.

The repository is an independent open-source project and is not affiliated with
Mercury Technologies, Inc.
