# Upstream requirements audit: AuthScope at 76fe961

Audited 2026-09-17. Baseline: `tauliang/auth-scope@76fe961`,
`openapi/auth-scope-v1.yaml` (OpenAPI 3.1, 211 operations, SHA-256
`8b9916ded625a3a56ac8a4df00bbea6446ee8a13fb5fe5e71326716345de3b7b`).

Method: every entry in `contracts/ope-required-capabilities.json` was checked
against the vendored document for exact method plus path, named request and
response schemas, a matching security scheme, and an explicit reconciliation
operation. Nothing was marked present on a guess. `scripts/verify-contract.sh`
reproduces the mechanical part of this audit; the semantic verdicts below come
from reading the schemas.

## Release status

The upstream repository has **zero releases**. Commit `76fe961` is a commit,
not an immutable release. The design declares it a design and contract-audit
baseline only. There is no release identifier or OpenAPI digest that
`make contract-ready` can pin.

## Capability verdicts

| Capability | Verdict | Evidence |
|---|---|---|
| Mission shaping, proposal create/approve, introspection, completion, revocation | Partial | Paths exist (`POST /v1/mission-proposals`, `.../{proposal_id}/approve`, `GET .../introspect`, `POST .../complete`, `POST .../revoke`) but every mutation takes GenericJSON and returns GenericObject. No shaping endpoint. No attestation parameter anywhere. |
| Workload-identity registration and verification with `decision_attestor` role | Absent | Zero hits for attestor, workload, or decision-attest in the document. No identity registration endpoint, no role model, no attestation schema (no audience, digest, nonce, freshness, or replay fields). |
| Decision-attestation verification | Absent | `POST /v1/decision-artifacts/verify` is a false friend: unauthenticated (`security: []`), untyped in and out. |
| Transport security scheme for workload identity | Absent | Global security is bearer-only. Defined schemes: bearerAuth, gatewayBearer, gatewayToken, agentID, agentNonce, agentSignature. No mTLS, no workload-identity scheme. |
| Authority levels and tenant labels | Partial | `GET`/`PUT /v1/enterprise/authority-levels` exist with the right idea, but untyped and enterprise-scoped, not workspace-scoped. |
| GitHub App handoff begin and one-use binding-code exchange | Absent | No handoff-begin endpoint, no binding-code exchange, no installation-state endpoint. The single `handoff` hit is a delegation-type enum value. |
| Repository bindings | Partial | `POST`/`GET /v1/integrations/github/repositories` exist (`createGitHubRepositoryBinding`, `listGitHubRepositoryBindings`). |
| Typed brokered GitHub issue snapshot with canonical source digest | Absent | No GitHub issue endpoints at all. No issue-snapshot schema. |
| Workflow-posture inspection | Absent | Nothing inspects workflow files for dangerous triggers. `validate-required-check` is about required status checks, a different thing. |
| Idempotent GitHub check-run publication | Absent | Only `POST /v1/integrations/github/check-runs/plan`, which returns a payload for an integration worker to publish. Planning is not publication, and it is secured by the agent-signature trio. |
| Runtime policies | Partial | `POST /v1/missions/{mission_ref}/runtime-policies` compiles a typed `RuntimePolicySnapshot` with signature and signing key id. Listing and diff endpoints exist. |
| Leases | Partial | `POST /v1/missions/{mission_ref}/leases` and `POST /v1/leases/{lease_id}/refresh` exist; refresh is agent-signature secured and untyped. |
| Agent-kit registry | Absent | Zero `kit` hits in the document. |
| Isolated launch with anonymous-FD credential delivery | Absent | `RuntimeHostFacts` worktree fields are host reporting, not provisioning. `POST /v1/projections/exchange` issues a brokered credential token (untyped, agent-signed), not an anonymous file descriptor. |
| Expansion requests with action-bound attestations | Partial shape, absent attestation | All expansion endpoints exist but take GenericJSON, return GenericObject, and the `ExpansionRequest` schema is `{}`. No attestation fields. |
| Execution grants, settlement, signed receipts | Partial | Consume, settle, and reconcile endpoints exist; settle advertises a signed receipt but returns GenericObject and no `SignedReceipt` schema exists anywhere. No grant-issuance endpoint. |
| Signed/authenticated events with resumable cursors | Partial | `GET /v1/events` supports cursor plus limit and returns a typed `EventPage` with `next_cursor`. But `GET /v1/events/stream` declares no parameters (not resumable), and `EventRecord` is hash-chained with no signature field. |
| Operation lookup by workspace-qualified idempotency key | Absent | The `Idempotency-Key` header is referenced by exactly one operation (`POST .../delegate`). No general lookup exists. `POST /v1/executions/reconcile` is execution-specific and untyped. |
| Immediate revocation checks at the gateway | Partial, unverifiable | `POST /v1/gateway/authorize` exists as a per-call enforcement hook, but the contract expresses no revocation-state semantics and no freshness bound. The ten-second requirement has no contractual basis. |
| Workspace-scoped active-mission listing | Partial | `GET /v1/missions` supports tenant plus status filters with a typed page, but the API has no workspace concept. Everything is tenant-scoped. |
| Atomic workspace containment | Absent | `POST /v1/enterprise/kill-switch` is enterprise-scoped, takes GenericJSON, and returns a dry-run impact result. Not atomic containment. |
| Published signing keys for local receipt verification | Absent | No JWKS or key-history endpoint. `/.well-known/mission-authority` returns untyped GenericObject. `RuntimePolicySnapshot` carries a signature and key id, but there is no endpoint to fetch the keys, so local verification is impossible. |

## The five load-bearing gaps

Each of these independently blocks the product. All five must be closed by an
immutable upstream release before Task 2 begins.

1. **No `decision_attestor` workload-identity mechanism.** No mTLS or workload
   scheme, no identity registration, no role model, no attestation schema.
   Every founder decision (approve, launch, revoke, expand, contain) must be
   accepted through a signed attestation. Without this, not one business
   mutation can be authenticated the way the design requires, and the whole
   "no static bearer credentials" rule cannot be honored.
2. **Nearly all mutating operations are untyped.** Proposal create and approve,
   expansion approve and deny, GitHub binding, execution settle and reconcile,
   projection exchange: GenericJSON in, GenericObject out. The compatibility
   manifest demands exact request and response schemas per operation so the
   adapter can be typed and the contract pinned. Nothing here can be pinned.
3. **No idempotency-key operation lookup.** The header exists on one endpoint.
   There is no general "resolve an ambiguous mutation by idempotency key"
   operation, so the exactly-once failure model (never retry without a lookup)
   cannot be implemented.
4. **No local receipt-verification material.** No signed-receipt schema and no
   published signing-key history. The design gates mission completion on a
   locally verified receipt. Impossible against this contract.
5. **No workspace concept and no workspace-scoped atomic containment.** The API
   is tenant-scoped only. The only containment operation is an enterprise
   kill-switch with dry-run semantics. The one-instance-one-workspace binding
   and offline-recovery containment have no upstream counterpart.

Also missing: GitHub issue snapshot, workflow-posture inspection, agent-kit
registry, check-run publication, mission shaping, and runtime-policy compile
as a standalone operation.

## What is usable

The baseline is not empty. It gives the product real fragments to lean on once
the gaps close: mission, proposal, and expansion CRUD shapes; cursor-paginated
events; runtime-policy compilation with signatures; a gateway enforcement hook;
and check-run planning. The audit confirms the design's own verdict: 76fe961 is
a design baseline, not an implementation-ready authority.

## Gate status

`make contract-ready` is RED. Task 1 remains open at this audit checkpoint.
Task 2 has no authorized start condition until an immutable AuthScope release
satisfies the full manifest in `contracts/ope-required-capabilities.json`.
