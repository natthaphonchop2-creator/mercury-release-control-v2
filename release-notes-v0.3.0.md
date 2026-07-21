# Mercury Finance v0.3.0

Candidate release controls for Mercury's connector-neutral accounting and ERP platform.

## Candidate identity

- Release tag: `v0.3.0`
- Package version: `0.3.0`
- Required Supabase migration: `20260719120000`
- Hosted MCP tools: 24 exact public tools
- ERP action catalog: 254 approved actions

## Trust boundary

The controls retain exact repository IDs, reviewed commit binding, workflow run and
attempt binding, artifact digests, immutable tag rules, provider-state inspection,
and post-release verification. This candidate contains no ERP credentials or usable
secrets.

Publication, migration, deployment, tagging, and marketplace submission remain
separate release operations.

The release control plane now includes a manual, environment-approved production
migration runner. It remains unapplied by this commit; provider attestation must
continue to fail until independently reviewed migration and deployment evidence
are present.

The migration path now reruns the protected GitHub preflight before database
access. Trusted Guardian constants pin the privileged runner, workflow, policy,
runtime import closure, and locked dependencies, so a candidate cannot authorize
tampering by regenerating its own control manifest.

The v0.3 control plane declares a solo-maintainer governance profile. Pull requests
must pass both the strict `required` CI check and `verify-candidate-as-data` Trusted
Guardian check. Production operations still require a protected-environment review
by the primary repository owner, while administrator bypass remains disabled.
