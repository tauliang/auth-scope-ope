# Upstream implementation plan for AuthScope

This is the delivery sequence the AuthScope service must complete before the
OPE product can leave its Task 1 audit checkpoint. It is written for the
AuthScope maintainers, ordered so each phase unblocks the next, with concrete
endpoints, schemas, and acceptance tests. OPE will not emulate any of this
locally.

Ordering principle: identity first (nothing can be authenticated without it),
then typed contracts (nothing can be pinned without them), then exactly-once
semantics, then evidence, then scoping, then the GitHub and launch flows that
depend on all of the above.

## Phase A: workload identity and decision attestations

This is the most load-bearing phase. Every OPE business mutation depends on it.

1. Add an mTLS (or equivalent workload-signer) security scheme to the OpenAPI
   document and use it as the security requirement for every operation OPE
   calls. Static bearer credentials must not be accepted on these paths.
2. Add `POST /v1/identities/workload/register`: one-time registration of a
   workspace-bound OPE workload identity. Request: attested hardware or
   platform key material plus the workspace it binds to. Response: a stable
   identity digest and the granted roles.
3. Add a `decision_attestor` role to the identity model. Only identities
   carrying it may submit founder decisions.
4. Add `POST /v1/identities/workload/verify`: given the authenticated
   transport identity, return its workspace binding, roles, and identity
   digest. AuthScope must derive the identity from the transport, never from
   a client-selected header.
5. Add a `DecisionAttestation` schema: workspace, founder, audience, purpose,
   subject, canonical decision digest, invocation digest, fixed
   authentication-method enum, algorithm-tagged authentication-proof digest,
   nonce, issued-at, expiry, key id, and signature. The proof digest must be
   defined so it never carries a credential id, assertion, or recovery key.
6. Add `POST /v1/decision-attestations/verify`: independently verify
   signature, workspace, audience, digests, authentication context, nonce,
   freshness, and one-use replay state. Reject on any mismatch or replay.
   Every mutation that accepts a founder decision must call this and reject
   attestations from identities without `decision_attestor`.

Acceptance tests: register an identity, verify it, submit a valid attestation
and see it accepted; then replay it and see it denied; alter each field
(workspace, audience, digests, nonce, expiry, signature) one at a time and see
each denied; submit from an identity without the role and see it denied.

## Phase B: typed mutation contracts

Replace GenericJSON in and GenericObject out with exact named schemas on every
operation in the OPE manifest:

- `POST /v1/mission-proposals` and `POST /v1/mission-proposals/{id}/approve`
  (the approve request carries the signed attestation),
- `POST /v1/mission-proposals/shape` (new: dry-run shaping that returns
  canonical digests without creating a proposal),
- all expansion request, approve, and deny operations (the decide request
  carries the action-bound attestation),
- `POST /v1/executions/settle` (typed settlement including the signed
  receipt),
- `POST /v1/executions/reconcile`,
- `POST /v1/integrations/github/repositories` (typed binding request and
  response),
- `POST /v1/projections/exchange`.

Acceptance tests: for each operation, the OpenAPI document names exact request
and response schemas; a code-generated client round-trips each one; unknown
fields are rejected.

## Phase C: idempotency-key operation lookup

1. Honor a workspace-qualified `Idempotency-Key` header on every mutating
   operation in the manifest.
2. Add `GET /v1/operations/{idempotency_key}`: return the settled result of the
   earlier mutation with the same key, or 404 if none exists. Same key plus
   same canonical request digest returns the original result; same key plus a
   different digest is a conflict.

Acceptance tests: begin a mutation, drop the connection before reading the
response, look it up by key, and confirm no duplicate mutation occurred;
resubmit with a different payload under the same key and confirm a conflict.

## Phase D: receipts and signing-key publication

1. Define a `SignedReceipt` schema and return it from execution settlement and
   from a new `GET /v1/executions/{grant_id}/receipt`.
2. Publish the signing-key history at
   `GET /.well-known/auth-scope-signing-keys`: the pinned root fingerprint
   plus the authenticated key history with rotation records, so OPE can verify
   receipts locally without trusting the network at verification time.

Acceptance tests: settle an execution, fetch the receipt and the key history
from a fresh client, and verify the receipt signature offline; rotate a key
and confirm old receipts still verify against the history.

## Phase E: workspace scoping and atomic containment

1. Introduce a first-class workspace concept distinct from tenants, or document
   precisely how a tenant maps to one OPE workspace.
2. Scope `GET /v1/missions` (and event reads) to the calling workspace, and
   include missions the caller did not create locally.
3. Add `POST /v1/workspaces/{workspace_id}/contain`: atomic containment of a
   workspace, accepted only with a valid signed attestation. It must be real
   containment, not a dry run.

Acceptance tests: containment revokes or freezes all active missions in the
workspace including ones created outside OPE; listing from a second workspace
shows no cross-read.

## Phase F: GitHub flows for OPE

1. Add `POST /v1/integrations/github/bindings/begin`: starts the
   AuthScope-hosted GitHub App installation handoff. Returns only a handoff id
   and an AuthScope-origin installation URL. AuthScope owns all GitHub OAuth
   state.
2. Add `POST /v1/integrations/github/bindings/finish`: exchanges the one-use
   opaque binding code for a repository binding. Never expose GitHub OAuth
   codes or tokens to the caller.
3. Add `GET /v1/integrations/github/bindings/{binding_id}`: read a binding by
   id, with immutable installation and repository ids.
4. Add `POST /v1/integrations/github/issues/snapshot`: typed brokered issue
   snapshot with provider-derived source revision, canonical source digest,
   base ref and SHA. No GitHub credential in the response.
5. Add `POST /v1/integrations/github/workflow-posture`: inspect workflow
   files, token permissions, and environments; report whether agent-controlled
   content can reach secrets, write tokens, spending, or deployments.
6. Add `POST /v1/integrations/github/check-runs`: idempotent check-run
   publication bound to immutable repository id and head SHA.

Acceptance tests: complete a handoff with crafted callback values and confirm
no GitHub credential ever reaches the caller; snapshot an issue twice and
confirm the digest is stable; mark a repository with a `pull_request_target`
workflow and confirm posture reports unsafe; publish the same check twice and
confirm one check-run.

## Phase G: launch preparation

1. Add `GET /v1/agent-kits`: the supported coding-agent kits and their
   runtime requirements.
2. Add `POST /v1/missions/{mission_ref}/launch/prepare`: exactly-once
   preparation of a governed run, accepted only with a valid signed
   attestation. Returns isolated-launch artifacts: isolated worktree,
   clean-home execution parameters, and credential delivery by anonymous file
   descriptor (never a reusable credential the agent process can exfiltrate).
3. Document the gateway-only egress guarantee in the compiled runtime policy.

Acceptance tests: prepare a launch, confirm the agent process receives no
reusable credential on its command line or in its environment, and confirm a
second prepare with the same idempotency key returns the original artifacts.

## Phase H: immutable release

1. Cut an immutable release (tag plus build artifact) of AuthScope.
2. Publish the release's OpenAPI document and its SHA-256 digest.
3. Confirm `make contract-ready` in the OPE repository exits 0 against the
   release's document with no exceptions.

Only then does OPE Task 2 begin.

## What OPE does in the meantime

Nothing in Tasks 2 through 16 starts early. The OPE repository holds the
audit, the manifest, the vendored baseline, and the red gate. When Phase H
lands, OPE updates the vendored document and the lock, reruns the gate, and
proceeds.
