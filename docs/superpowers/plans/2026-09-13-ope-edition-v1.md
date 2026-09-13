# AuthScope OPE Edition v1 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a founder-focused product in which one GitHub issue becomes one expiring AuthScope Mission Pass, one governed coding-agent run, one pull request, and one verified receipt.

**Architecture:** Build a Go server and CLI with a React web client. The OPE application collects intent, presents authority, verifies local founder authentication, signs exact decision attestations with its workspace-bound workload identity, and renders verified results; the upstream AuthScope service remains the only authority evaluator, credential broker, execution gateway, revocation source, and execution-evidence signer. Persist only workspace-qualified presentation and correlation state in local SQLite.

**Tech Stack:** Go 1.26.6, `net/http`, `database/sql`, `modernc.org/sqlite` v1.58.0, `github.com/go-webauthn/webauthn` v0.18.1, OpenAPI 3.1, React 19.2.0, TypeScript 5.9.3, Vite 8.1.5, pnpm 10.13.1, Vitest, Testing Library, MSW, and Playwright.

**Spec:** [`../specs/2026-09-13-ope-edition-v1-design.md`](../specs/2026-09-13-ope-edition-v1-design.md)

## Global Constraints

- AuthScope commit `76fe961` is a design and contract-audit baseline only. No Task 2 work begins until an immutable AuthScope release and OpenAPI digest satisfy the complete required-operation manifest.
- The v1 template ID is exactly `github-issue-pr-v1`.
- The product has exactly three workflow screens: Connect, Authorize, and Mission.
- One OPE instance binds to one immutable AuthScope `workspace_id`, unique configured hostname and origin, per-instance `__Host-` session-cookie name, and one independently verified workspace-bound OPE workload identity. Every persisted record and every cache, cursor, idempotency, session, expansion, and receipt lookup is qualified by that `workspace_id`.
- The OPE application never evaluates authority, performs a GitHub mutation, signs an authority grant or execution receipt, or stores a provider write credential. Its only signed artifacts are the exact scoped decision attestations defined here.
- Missing upstream capabilities, stale source state, ambiguous workspace state, unverifiable revocation state, and invalid evidence fail closed.
- GitHub PATs, generic REST/GraphQL proxying, shell execution, automatic authority expansion, direct default-branch writes, merges, releases, deployments, workflow-file edits, and repository administration are prohibited in v1.
- OPE verifies WebAuthn locally and signs each exact decision attestation with its non-exportable workspace workload identity. The attestation includes a fixed authentication-method enum and an algorithm-tagged digest of the local proof record, never a credential ID, assertion, or recovery key. AuthScope accepts only a `decision_attestor` identity and independently verifies signature, workspace, audience, decision digest, invocation digest when applicable, authentication context, nonce, freshness, and replay state. The CLI uses a one-use browser handoff with PKCE and stores no refresh credential.
- Telemetry excludes repository names, issue content, source code, prompts, patches, transcripts, credentials, and receipt payloads.
- Backend tests use Go's race detector where concurrency matters; frontend coverage thresholds are 85% statements, 85% lines, 80% functions, and 80% branches.
- Each completed task ends in one independently reviewable commit and leaves `go test ./...`, frontend tests, and contract checks passing for all implemented surfaces. A blocked Task 1 remains open at its explicit audit review checkpoint and does not authorize Task 2.

---

## Planned file structure

| Path | Responsibility |
| --- | --- |
| `cmd/authscope-ope/main.go` | Compose dependencies and expose `serve`, `doctor`, `run`, `revoke`, and `recover` commands. |
| `internal/config/config.go` | Strict environment/file configuration with development and release validation. |
| `internal/coreapi/client.go` | Narrow typed HTTP client for AuthScope. No other package sends AuthScope HTTP requests. |
| `internal/coreapi/types.go` | OPE-required AuthScope request and response types. |
| `internal/coreapi/compatibility.go` | Verify discovery metadata, required routes, version, and enforcement capabilities. |
| `internal/store/store.go` | Workspace-qualified storage interfaces and transaction contracts. |
| `internal/store/sqlite.go` | SQLite implementation, migrations, compare-and-swap state, and idempotency. |
| `internal/store/instance.go` | Durable immutable instance binding for workspace, hostname, origin, RP ID, cookie namespace, and attached workload-identity digest. |
| `internal/authn/bootstrap.go` | One-use bootstrap and offline recovery reset state. |
| `internal/authn/passkey.go` | WebAuthn enrollment, login, and recent-auth decision challenges. |
| `internal/authn/session.go` | Hashed web sessions, CSRF, Origin checks, and expiry. |
| `internal/authn/pkce.go` | CLI authorization-code and PKCE flow. |
| `internal/identity/attestor.go` | Non-exportable workload signer for exact OPE decision attestations. |
| `internal/github/handoff.go` | Opaque AuthScope-hosted GitHub installation begin/callback/finish handoff. |
| `internal/github/source.go` | Typed issue snapshot brokered and executed by AuthScope without exposing a GitHub credential. |
| `internal/missionpass/model.go` | Pass state, version, source binding, digest, and transition rules. |
| `internal/missionpass/template.go` | Conservative `github-issue-pr-v1` input and editable-field limits. |
| `internal/missionpass/proposal.go` | Shape and create an AuthScope proposal before founder review. |
| `internal/missionpass/approval.go` | Passkey begin/finish approval that creates only the upstream mission. |
| `internal/missionpass/revoke.go` | Passkey begin/finish revocation and containment presentation. |
| `internal/missionpass/events.go` | Cursor-resumable event ingestion, deduplication, and state projection. |
| `internal/launch/service.go` | One-use PKCE exchange and exactly-once AuthScope `PrepareLaunch`. |
| `internal/trust/keys.go` | Pinned AuthScope signing-root and authenticated key-history validation. |
| `internal/reconcile/worker.go` | Own event cursors, resolve uncertain operations, verify receipts, and publish checks. |
| `internal/expansion/service.go` | Exact bounded expansion presentation and decision relay. |
| `internal/receipt/service.go` | Local receipt verification, privacy filtering, and automatic GitHub check publication. |
| `internal/httpapi/server.go` | Middleware, route registration, JSON limits, and static web serving. |
| `internal/httpapi/*_handlers.go` | One handler group per local API resource. |
| `internal/cli/*.go` | CLI commands and safe argument-array launch. |
| `openapi/ope-v1.yaml` | Local public API contract. |
| `contracts/authscope.lock.json` | Upstream version plus OpenAPI and signing-key-history SHA-256 values. |
| `contracts/authscope-v1.yaml` | Vendored upstream OpenAPI document whose digest is locked. |
| `contracts/ope-required-capabilities.json` | OPE release requirements that the pinned core must satisfy. |
| `contracts/authscope-signing-keys.json` | Pinned signing-root fingerprint and initial authenticated key history. |
| `web/src/features/connect` | Connect screen and passkey/GitHub flow. |
| `web/src/features/authorize` | Issue selection and Mission Pass review. |
| `web/src/features/mission` | Timeline, expansion, revoke, and receipt UI. |
| `web/src/shared/api` | Generated types and a credential-safe fetch client. |
| `test/e2e` | Fake AuthScope/GitHub services and Playwright journeys. |
| `deploy/compose.yaml` | Pinned local product stack with health checks and non-exportable signer/key-handle references. |

### Task 1: Audit and lock every upstream operation, then bootstrap a vertical shell

**Files:**
- Create: `go.mod`, `go.sum`, `.gitignore`, `LICENSE`, `Makefile`
- Create: `cmd/authscope-ope/main.go`
- Create: `internal/config/config.go`, `internal/config/config_test.go`
- Create: `internal/coreapi/compatibility.go`, `internal/coreapi/compatibility_test.go`
- Create: `internal/httpapi/server.go`, `internal/httpapi/server_test.go`
- Create: `contracts/authscope.lock.json`, `contracts/authscope-v1.yaml`, `contracts/ope-required-capabilities.json`, `openapi/ope-v1.yaml`
- Create: `scripts/verify-contract.sh`, `scripts/run-usability-spike.sh`, `docs/upstream-requirements.md`, `docs/upstream-implementation-plan.md`, `docs/usability-spike.md`
- Create: `web/package.json`, `web/pnpm-lock.yaml`, `web/tsconfig.json`, `web/vite.config.ts`, `web/vitest.config.ts`, `web/eslint.config.js`, `web/index.html`
- Create: `web/src/main.tsx`, `web/src/App.tsx`, `web/src/App.test.tsx`, `web/src/test/setup.ts`
- Create: `web/src/shared/api/client.ts`, `web/src/shared/api/client.test.ts`, `web/src/shared/api/generated.ts`
- Create: `web/src/spike/FirstRunPrototype.tsx`, `web/src/spike/FirstRunPrototype.test.tsx`
- Create: `.github/workflows/ci.yml`

**Interfaces:**
- Produces: `config.Load() (config.Config, error)` and `coreapi.CheckCompatibility(context.Context, coreapi.Discovery, coreapi.ContractLock, coreapi.CapabilityManifest) error`.
- Produces: `httpapi.New(httpapi.Dependencies) http.Handler` with `/healthz`, `/readyz`, and `GET /api/v1/bootstrap`.
- Produces: an audit lock for AuthScope commit `76fe961` and the vendored OpenAPI SHA-256, plus an operation manifest mapping every OPE requirement to method, path, schemas, security, reconciliation, and release status.
- Produces: a generated TypeScript API client, test/lint configuration, one fake-backed `/api/v1/bootstrap` route rendered through `App`, and a contract-faithful first-run click-through prototype ending at a simulated confirmed `RunID`.
- Produces: a hard `contract-ready` gate that remains red until an immutable AuthScope release satisfies the entire manifest; Task 2 has no authorized start condition before it passes.

- [ ] **Step 1: Write failing configuration and compatibility tests**

```go
func TestLoadRejectsReleaseWithoutWorkloadSignerReference(t *testing.T) {
    t.Setenv("OPE_MODE", "release")
    t.Setenv("AUTH_SCOPE_URL", "https://authority.example")
    t.Setenv("OPE_WORKLOAD_SIGNER_REF", "")
    _, err := Load()
    if !errors.Is(err, ErrMissingWorkloadSignerReference) {
        t.Fatalf("Load error = %v", err)
    }
}

func TestCheckCompatibilityRejectsMissingReceiptVerification(t *testing.T) {
    discovery := Discovery{Version: "76fe961", Capabilities: []string{"missions", "leases"}}
    err := CheckCompatibility(context.Background(), discovery, LockedContract(), RequiredManifest())
    if !errors.Is(err, ErrIncompatibleCore) {
        t.Fatalf("compatibility error = %v", err)
    }
}

func TestReleaseRejectsAuditBaseline(t *testing.T) {
    discovery := Discovery{Version: "76fe961", OpenAPISHA256: LockedContract().OpenAPISHA256}
    err := CheckReleaseCompatibility(context.Background(), discovery, LockedContract(), RequiredManifest())
    if !errors.Is(err, ErrAuditBaselineOnly) {
        t.Fatalf("release compatibility error = %v", err)
    }
}
```

- [ ] **Step 2: Run the focused tests and verify the expected failure**

Run: `go test ./internal/config ./internal/coreapi -count=1`

Expected: compilation fails because `Load`, `Discovery`, and `CheckCompatibility` do not exist.

- [ ] **Step 3: Add strict configuration and capability checking**

```go
type ContractLock struct {
    CoreVersion   string `json:"core_version"`
    OpenAPISHA256 string `json:"openapi_sha256"`
}

type RequiredOperation struct {
    Capability     string `json:"capability"`
    Method         string `json:"method"`
    Path           string `json:"path"`
    RequestSchema  string `json:"request_schema"`
    ResponseSchema string `json:"response_schema"`
    SecurityScheme string `json:"security_scheme"`
    ReconcilePath  string `json:"reconcile_path,omitempty"`
}

type CapabilityManifest struct {
    RequiredOperations []RequiredOperation `json:"required_operations"`
}

func CheckCompatibility(_ context.Context, got Discovery, lock ContractLock, manifest CapabilityManifest) error {
    if got.Version != lock.CoreVersion || got.OpenAPISHA256 != lock.OpenAPISHA256 {
        return fmt.Errorf("%w: deployed core does not match lock", ErrIncompatibleCore)
    }
    available := make(map[string]struct{}, len(got.Capabilities))
    for _, capability := range got.Capabilities { available[capability] = struct{}{} }
    for _, operation := range manifest.RequiredOperations {
        if _, ok := available[operation.Capability]; !ok {
            return fmt.Errorf("%w: missing %s", ErrIncompatibleCore, operation.Capability)
        }
    }
    return nil
}
```

The manifest must include proposal shaping/creation/approval, mission introspection/revoke/complete, `decision_attestor` identity registration and exact-attestation verification, runtime policy/lease/kit discovery, isolated launch with anonymous-FD credential delivery, GitHub handoff begin and one-use binding-code exchange, repository binding/issue snapshot/workflow posture/check publication, exact expansions, execution consume/settle/reconcile, authenticated cursor events, local receipt-verification keys, idempotency lookup, active-mission listing, workspace containment, and gateway revocation enforcement. Release configuration names only a non-exportable workload-signer or mTLS key-handle reference; static AuthScope bearer credentials and literal private keys are invalid.

- [ ] **Step 4: Verify the vendored OpenAPI operation map**

`scripts/verify-contract.sh` checks the vendored document SHA-256, parses every manifest method/path, confirms the referenced request and response schemas and security scheme exist, and confirms every mutating operation has an explicit reconciliation path. Add the `contract-ready` Make target here so Step 5 can run it independently of the later general verification target. Write actual gaps at commit `76fe961` to `docs/upstream-requirements.md` and a concrete upstream delivery sequence with tests to `docs/upstream-implementation-plan.md`; do not invent local fallbacks. The audit command may report gaps, but `make contract-ready` fails while the version is `76fe961`, while any manifest operation is absent, or while the compatible version and OpenAPI digest are not immutable release identifiers.

- [ ] **Step 5: Enforce the upstream dependency stop**

Run `make contract-ready` against the currently selected AuthScope build. If any required operation, schema, security scheme, decision-attestor behavior, reconciliation route, signing-key history, runtime isolation capability, active-mission listing, or workspace containment operation is absent, write the exact gaps and upstream delivery sequence, expose the audit-only review checkpoint below, and stop with Task 1 incomplete. Complete the recorded upstream plan, obtain an immutable compatible AuthScope release, update the vendored OpenAPI and lock, and rerun `make contract-ready`. Task 2 may begin only after this command exits zero.

Blocked audit-only review checkpoint; this is not the Task 1 commit:

```bash
git add --intent-to-add contracts/authscope.lock.json contracts/authscope-v1.yaml contracts/ope-required-capabilities.json docs/upstream-requirements.md docs/upstream-implementation-plan.md scripts/verify-contract.sh
git diff --check -- contracts docs/upstream-requirements.md docs/upstream-implementation-plan.md scripts/verify-contract.sh
git diff -- contracts docs/upstream-requirements.md docs/upstream-implementation-plan.md scripts/verify-contract.sh
```

- [ ] **Step 6: Add health/readiness routes and the initial vertical web shell**

`/healthz` returns process health. `/readyz` returns `503` until the lock and operation map are verified and live AuthScope compatibility succeeds. `/api/v1/bootstrap` returns only enrollment state, immutable workspace binding, compatibility status, and supported authority display labels. Generate `web/src/shared/api/generated.ts` from `openapi/ope-v1.yaml`; render that fake-backed response in `App.test.tsx` through the same typed client later screens use.

- [ ] **Step 7: Run the five-session contract-faithful usability spike**

Build `FirstRunPrototype` only after `make contract-ready` passes, using fixtures generated from the now-complete immutable upstream operation schemas. It covers bootstrap and recovery-method enrollment, immutable workspace/hostname presentation, GitHub handoff, repository and issue selection, proposal summary and two editable limits, exact pass approval, CLI browser authorization, token exchange, and a simulated confirmed `RunID`. Run five first-time sessions with `scripts/run-usability-spike.sh`, starting at the first product-controlled interaction and subtracting only AuthScope-hosted GitHub installation time. Record only durations, fixed outcome codes, and observations in `docs/usability-spike.md`. Median completion must be under five minutes. If it misses, revise the flow and rerun all five sessions before continuing.

- [ ] **Step 8: Add CI and deterministic developer commands**

`make verify` must run `scripts/verify-contract.sh`, assert regenerated TypeScript is clean, then run `go test -race ./...`, `go vet ./...`, `pnpm --dir web lint`, `pnpm --dir web typecheck`, `pnpm --dir web test:coverage`, and `pnpm --dir web build`. `make contract-ready` is a separate mandatory dependency for Task 2 and release work. CI installs exact Go and pnpm versions and runs both commands without long-lived credentials once a compatible upstream release exists.

- [ ] **Step 9: Run the foundation checks**

Run: `make verify && make contract-ready && scripts/run-usability-spike.sh --verify docs/usability-spike.md`

Expected: all foundation tests pass; the immutable upstream release has no required-operation gaps; the five-session median is below five minutes; `/readyz` returns `503` for version, digest, route, schema, security, reconciliation, role, or capability mismatch and `200` only for the complete locked contract.

- [ ] **Step 10: Commit**

```bash
git add .github .gitignore LICENSE Makefile go.mod go.sum cmd contracts docs internal openapi scripts web
git commit -m "chore: bootstrap OPE edition and lock core contract"
```

### Task 2: Add the workspace-qualified SQLite presentation store

**Files:**
- Create: `internal/store/store.go`
- Create: `internal/store/instance.go`, `internal/store/instance_test.go`
- Create: `internal/store/sqlite.go`, `internal/store/sqlite_test.go`
- Create: `internal/store/migrations/001_initial.sql`
- Create: `internal/store/testkit_test.go`
- Modify: `internal/config/config.go`
- Modify: `cmd/authscope-ope/main.go`

**Interfaces:**
- Produces: `store.Store` with an immutable instance binding plus workspace-qualified founder, session, connection, pass, event, expansion, and idempotency methods.
- Produces: `store.WithTx(context.Context, func(store.Tx) error) error` for compare-and-swap and idempotency operations.
- Consumes: strict data-path configuration from Task 1.

```go
type Store interface {
    WithTx(context.Context, func(Tx) error) error
    GetInstance(context.Context) (InstanceRecord, error)
    GetMissionPass(context.Context, string, string) (MissionPassRecord, error)
    ListMissionEvents(context.Context, string, string, string, int) ([]MissionEventRecord, error)
}

type MissionPassRecord struct {
    WorkspaceID             string
    PassID                  string
    StoreRevision           int64 // local compare-and-swap revision; increments on every mutation
    DraftVersion            int64 // immutable founder-visible proposal revision
    AuthScopeMissionVersion int64 // upstream authority version; changes on approval or expansion
}

type InstanceRecord struct {
    InstanceID             string
    WorkspaceID            string
    Hostname               string
    Origin                 string
    RPID                   string
    SessionCookieName      string
    WorkloadIdentityDigest string // empty until Task 4 attaches it exactly once
    CreatedAt              time.Time
}

type Tx interface {
    BindInstance(context.Context, InstanceRecord) error
    AttachWorkloadIdentity(context.Context, string /* expected empty */, string /* digest */) error
    PutConnection(context.Context, ConnectionRecord) error
    PutMissionPass(context.Context, MissionPassRecord, int64 /* expectedStoreRevision */) error
    PutEventIfAbsent(context.Context, MissionEventRecord) (bool, error)
    BeginIdempotency(context.Context, IdempotencyRecord) (IdempotencyResult, error)
    CompleteIdempotency(context.Context, string, string, []byte) error
}
```

- [ ] **Step 1: Write failing isolation, state-CAS, and idempotency tests**

Tests must prove that instance initialization before HTTP serving creates one durable instance record and that a later workspace, hostname, origin, RP ID, instance ID, or cookie-name change returns `ErrInstanceRebind`. Task 3 bootstrap must only read that record. Require a unique valid hostname and exact HTTPS or permitted loopback origin, and derive a unique name `__Host-authscope-ope-session-<instance-id>` with `Secure`, `Path=/`, and no `Domain`. Also prove that the same `pass_id` in two workspaces cannot cross-read, an outdated `expectedStoreRevision` returns `ErrConflict`, identical idempotency key plus identical canonical digest returns the first result, and identical key plus a different digest returns `ErrIdempotencyMismatch`. Updating `AuthScopeMissionVersion` must increment `StoreRevision` without changing `DraftVersion`; creating a revised proposal must increment `DraftVersion` and `StoreRevision` without copying an unrelated upstream mission version.

```go
func TestMissionPassCannotCrossWorkspace(t *testing.T) {
    db := openTestStore(t)
    savePass(t, db, "personal", "pass-1", 1)
    _, err := db.GetMissionPass(context.Background(), "business", "pass-1")
    if !errors.Is(err, ErrNotFound) { t.Fatalf("error = %v", err) }
}
```

- [ ] **Step 2: Run tests and verify failure**

Run: `go test -race ./internal/store -count=1`

Expected: compilation fails because `Store`, the migration, and SQLite adapter do not exist.

- [ ] **Step 3: Create the schema and repository methods**

The migration creates a singleton `instance` record plus `founders`, `webauthn_credentials`, `sessions`, `github_connections`, `mission_passes`, `mission_events`, `expansions`, `idempotency_records`, and `telemetry_events`. During startup and before route registration, Task 2 calls insert-once `BindInstance` with instance ID, workspace, hostname, origin, RP ID, derived cookie name, creation time, and an initially empty workload-identity digest. It never updates the binding fields; Task 4 may attach the digest exactly once only while it is empty, and no path may replace it. Every primary or unique business key begins with `workspace_id`. Mission rows have separate `store_revision`, `draft_version`, and `authscope_mission_version` columns. Local compare-and-swap updates execute `UPDATE ... SET store_revision = store_revision + 1 ... WHERE workspace_id = ? AND pass_id = ? AND store_revision = ?` and require exactly one affected row; neither draft nor upstream mission version is used as the local CAS token.

- [ ] **Step 4: Harden local persistence**

Open SQLite with WAL, foreign keys, a five-second busy timeout, and one writer connection. Create the database and parent directory with owner-only permissions. Reject symlinks and files with group or world permission bits in release mode. Store session hashes and passkey public data; add a test that searches every column for seeded GitHub and AuthScope token fixtures and finds none.

- [ ] **Step 5: Run store tests**

Run: `go test -race ./internal/store -count=1`

Expected: immutable instance binding, hostname/origin/cookie validation, isolation, optimistic concurrency, atomic event deduplication, and idempotency tests pass.

- [ ] **Step 6: Commit**

```bash
git add go.mod go.sum cmd internal/config internal/store
git commit -m "feat: add workspace-isolated OPE state store"
```

### Task 3: Enroll the founder and protect web decisions with passkeys

**Files:**
- Create: `internal/authn/bootstrap.go`, `internal/authn/bootstrap_test.go`
- Create: `internal/authn/passkey.go`, `internal/authn/passkey_test.go`
- Create: `internal/authn/session.go`, `internal/authn/session_test.go`
- Create: `internal/httpapi/auth_handlers.go`, `internal/httpapi/auth_handlers_test.go`
- Create: `web/src/features/connect/PasskeySetup.tsx`, `web/src/features/connect/PasskeySetup.test.tsx`
- Modify: `internal/httpapi/server.go`, `openapi/ope-v1.yaml`
- Modify: `web/src/main.tsx`

**Interfaces:**
- Produces: `authn.BootstrapService.Begin`, `BeginRecovery`, and `Complete`; `authn.BeginRegistration`, `authn.FinishRegistration`, `authn.BeginLogin`, `authn.FinishLogin`, `authn.BeginDecision`, and `authn.FinishDecision`.
- Produces: `POST /api/v1/bootstrap/begin`, `POST /api/v1/bootstrap/recovery/begin`, `POST /api/v1/bootstrap/complete`, `POST /api/v1/auth/register/begin`, `POST /api/v1/auth/register/finish`, `POST /api/v1/auth/login/begin`, and `POST /api/v1/auth/login/finish`.
- Produces: authenticated request context containing immutable `founder_id`, `workspace_id`, `session_id`, `auth_time`, and `csrf_token_hash`.
- Consumes: Task 2's durable immutable local instance binding, workspace-qualified transactions, and hashed-session storage. Task 3 does not call AuthScope or verify the workload identity.

```go
type Principal struct {
    FounderID  string
    WorkspaceID string
    SessionID  string
    AuthTime   time.Time
}

type DecisionChallenge struct {
    ChallengeID string
    WorkspaceID string
    SessionID   string
    SubjectID   string
    Purpose     DecisionPurpose
    Digest      [32]byte
    Nonce       [32]byte
    ExpiresAt   time.Time
    ConsumedAt  *time.Time
}
```

- [ ] **Step 1: Write failing bootstrap, recovery, replay, CSRF, and recent-auth tests**

Cover one-use bootstrap codes, configured values that disagree with the durable local instance, mandatory enrollment of a passkey plus an independent recovery method, duplicate credential rejection, reused offline recovery keys, wrong Host or Origin, wrong per-instance cookie name, missing CSRF, wrong content type, oversized body, expired sessions, copied cookies in another workspace or instance, replayed WebAuthn challenges, wrong decision purpose/digest/session, and an assertion older than five minutes.

```go
func TestDecisionRequiresAssertionBoundToServerCanonicalClaims(t *testing.T) {
    service := newAuthTestService(t)
    passA := loadProposalFixture(t, "pass-a")
    bindingA := CanonicalApprovalDecision(passA)
    challenge := service.BeginDecision(context.Background(), principal, DecisionPassApproval, bindingA)
    assertion := validAssertion(t, service, challenge)
    passB := loadProposalFixture(t, "pass-b")
    bindingB := CanonicalApprovalDecision(passB)
    err := service.FinishDecision(context.Background(), principal, challenge.ChallengeID, DecisionPassApproval, bindingB, assertion)
    if !errors.Is(err, ErrDecisionBinding) { t.Fatalf("error = %v", err) }
}
```

- [ ] **Step 2: Run tests and verify failure**

Run: `go test -race ./internal/authn ./internal/httpapi -run 'TestBootstrap|TestPasskey|TestSession|TestDecision' -count=1`

Expected: compilation fails because the authentication services and handlers do not exist.

- [ ] **Step 3: Add bootstrap, recovery, and WebAuthn services**

Load the immutable local workspace, hostname, origin, RP ID, instance ID, and cookie name created by Task 2; reject configuration drift without calling AuthScope. Generate a 128-bit one-use bootstrap code, print it only to the controlling terminal, and persist its SHA-256 hash and ten-minute expiry. `bootstrap/begin` verifies the code in constant time and creates a separate short-lived bootstrap-ceremony cookie and server record without marking the code consumed. Registration begin/finish binds the first passkey to that ceremony. `bootstrap/recovery/begin` then starts a distinct second-passkey registration or generates a 256-bit offline recovery key, displays it once, stores only its hash, and requires proof of possession. `bootstrap/complete` requires the same ceremony, verified first passkey, and confirmed independent recovery method; one transaction consumes the code and ceremony and creates the first founder session. A failure or replay creates no partial founder session. Configure WebAuthn with the exact bound RP ID and origin. Require user verification for registration, login, and decision assertions.

- [ ] **Step 4: Add secure sessions and HTTP middleware**

Create 256-bit opaque sessions, store only their SHA-256 hashes, and set the bound per-instance `__Host-authscope-ope-session-<instance-id>` cookie with `HttpOnly; Secure; SameSite=Strict; Path=/` and no `Domain`. Rotate the session after login. Established-session browser mutations require exact Host and Origin, the exact cookie name, and a session-bound CSRF token. Pre-session bootstrap, registration, and login transitions require exact Host and Origin plus their bootstrap or WebAuthn ceremony state; they cannot accept or reuse a founder session. CLI and GitHub callback exceptions follow the fixed route-security matrix in Task 13. All JSON routes enforce exact content type and body-size limits. Emit CSP `default-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'`, `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`, and a restrictive Permissions Policy. Return problem-details JSON without credential or challenge contents.

- [ ] **Step 5: Add the internal one-use decision challenge service**

`authn.BeginDecision` accepts a fixed purpose enum and server-recomputed canonical claims, creates a random WebAuthn challenge bound to workspace, session, subject, purpose, digest, nonce, and two-minute expiry, and returns only ceremony options plus `challenge_id`. It is an internal service used by each resource-specific begin route added in later tasks; there is no generic public decision-challenge route. Each corresponding finish route calls `FinishDecision` with freshly recomputed claims and atomically consumes the challenge. A challenge cannot cross purpose, session, subject, workspace, or digest.

- [ ] **Step 6: Build passkey setup and login states on the Connect screen**

The component supports `needs_bootstrap`, `needs_recovery_method`, `locked`, and `authenticated`. It never stores challenges or assertions in local storage. It offers a second passkey or a one-time offline recovery-key download and requires the founder to confirm possession before completion. Recovery reset is absent from the browser and documented as an offline CLI operation that revokes all sessions.

- [ ] **Step 7: Run authentication and web tests**

Run: `go test -race ./internal/authn ./internal/httpapi -count=1 && pnpm --dir web test -- PasskeySetup`

Expected: all authentication tests pass, and the browser tests show no authenticated workflow before a passkey and an independent recovery method exist.

- [ ] **Step 8: Commit**

```bash
git add go.mod go.sum internal/authn internal/httpapi openapi web/src
git commit -m "feat: secure founder decisions with passkeys"
```

### Task 4: Add the narrow AuthScope client and fail-closed compatibility gate

**Files:**
- Create: `internal/coreapi/client.go`, `internal/coreapi/client_test.go`
- Create: `internal/coreapi/types.go`, `internal/coreapi/testdata/*.json`
- Create: `internal/identity/attestor.go`, `internal/identity/attestor_test.go`
- Modify: `internal/store/instance.go`, `internal/store/store.go`, `internal/store/sqlite.go`
- Modify: `internal/coreapi/compatibility.go`, `internal/coreapi/compatibility_test.go`
- Create: `internal/httpapi/problem.go`, `internal/httpapi/problem_test.go`
- Modify: `cmd/authscope-ope/main.go`, `internal/httpapi/server.go`

**Interfaces:**
- Produces: a `coreapi.Authority` interface used by all later services.
- Produces: request options that set workspace, actor, trace, idempotency, and optimistic mission-version headers consistently; the authenticated transport supplies the workload identity.
- Produces: `identity.DecisionAttestor.Attest(context.Context, identity.DecisionClaims) (identity.SignedDecisionAttestation, error)` backed by the non-exportable workspace workload signer.
- Consumes: the Task 1 contract lock, Task 2 immutable instance record and attach-once digest operation, and Task 3 authenticated principal.

```go
type Authority interface {
    Discover(context.Context) (Discovery, error)
    VerifyWorkspaceIdentity(context.Context, string) (WorkspaceIdentity, error)
    BeginGitHubBinding(context.Context, GitHubBindingBeginRequest, RequestOptions) (GitHubBindingHandoff, error)
    FinishGitHubBinding(context.Context, GitHubBindingFinishRequest, RequestOptions) (RepositoryBinding, error)
    GetRepositoryBinding(context.Context, string, RequestOptions) (RepositoryBinding, error)
    ReadGitHubIssue(context.Context, GitHubIssueRequest, RequestOptions) (GitHubIssueSnapshot, error)
    InspectWorkflowPosture(context.Context, WorkflowPostureRequest, RequestOptions) (WorkflowPosture, error)
    ListAgentKits(context.Context, RequestOptions) ([]AgentKit, error)
    ShapeMission(context.Context, ShapeMissionRequest, RequestOptions) (MissionDraft, error)
    CreateProposal(context.Context, CreateProposalRequest, RequestOptions) (Proposal, error)
    ApproveProposal(context.Context, string, identity.SignedDecisionAttestation, RequestOptions) (Mission, error)
    PrepareLaunch(context.Context, string, LaunchRequest, identity.SignedDecisionAttestation, RequestOptions) (LaunchArtifacts, error)
    IntrospectMission(context.Context, string, RequestOptions) (MissionStatus, error)
    RevokeMission(context.Context, string, RevokeRequest, identity.SignedDecisionAttestation, RequestOptions) (Revocation, error)
    ListExpansions(context.Context, string, RequestOptions) ([]Expansion, error)
    DecideExpansion(context.Context, string, ExpansionDecision, identity.SignedDecisionAttestation, RequestOptions) (ExpansionResult, error)
    ReadEvents(context.Context, string, string, RequestOptions) (EventPage, error)
    GetReceipt(context.Context, string, RequestOptions) (SignedReceipt, error)
    GetSigningKeys(context.Context, RequestOptions) (SigningKeyHistory, error)
    PublishGitHubCheck(context.Context, GitHubCheckRequest, RequestOptions) (GitHubCheckResult, error)
    ReconcileOperation(context.Context, string, string, RequestOptions) (OperationResult, error)
    ListActiveMissions(context.Context, RequestOptions) ([]ActiveMission, error)
    ContainWorkspace(context.Context, WorkspaceContainmentRequest, identity.SignedDecisionAttestation, RequestOptions) (WorkspaceContainment, error)
}

type DecisionClaims struct {
    WorkspaceID      string
    FounderID        string
    Audience         string
    Purpose          string
    SubjectID        string
    DecisionDigest   string
    InvocationDigest string
    AuthenticationMethod      string
    AuthenticationProofDigest string
    Nonce            [32]byte
    IssuedAt         time.Time
    ExpiresAt        time.Time
}

type SignedDecisionAttestation struct {
    Algorithm      string
    KeyID          string
    IdentityDigest string
    Claims         DecisionClaims
    Signature      []byte
}
```

- [ ] **Step 1: Add failing client contract tests**

Use `httptest.Server` fixtures to assert exact methods, paths, JSON, content type, workspace, authenticated transport identity, idempotency key, request ID, timeout, response size cap, and non-2xx problem decoding. Cover GitHub handoff begin/finish, active-mission listing, and workspace containment. Sign a decision fixture through an injected non-exportable signer; use an identity whose AuthScope registration lacks `decision_attestor`, then independently alter workspace, audience, purpose, subject, decision digest, invocation digest, authentication method, authentication-proof digest, nonce, issued-at, expiry, key ID, or signature and require the fake AuthScope verifier to deny it. Replay the identical attestation and require denial after its first successful consumption. Include a response with an unknown enum and a response larger than 2 MiB; both must fail.

- [ ] **Step 2: Run the client tests and verify failure**

Run: `go test ./internal/coreapi -run 'TestClient|TestCompatibility' -count=1`

Expected: compilation fails because `Client` and the full `Authority` interface do not exist.

- [ ] **Step 3: Implement the typed HTTP client**

Use one injected `http.Client` with a non-exportable workspace workload signer and mTLS transport, per-operation context deadlines, `http.NewRequestWithContext`, redirects disabled, `json.Decoder.DisallowUnknownFields`, and an `io.LimitReader` capped at 2 MiB. Accept only HTTPS outside development. The transport never exposes a bearer credential or signing key to callers. `DecisionAttestor` accepts only fixed `webauthn_uv` and `offline_recovery_key` authentication methods, canonicalizes exact claims, domain-separates them with `authscope-ope/decision-attestation/v1`, and emits an algorithm-tagged signature and stable identity digest. The authentication-proof digest covers the local verified ceremony record without serializing the credential ID, assertion, or recovery key. Redact authorization, client-certificate, decision-attestation, and cookie material from all structured errors.

```go
func (c *Client) do(ctx context.Context, method, path string, in, out any, opts RequestOptions) error {
    body, err := canonicalJSON(in)
    if err != nil { return err }
    req, err := http.NewRequestWithContext(ctx, method, c.base.ResolveReference(&url.URL{Path: path}).String(), bytes.NewReader(body))
    if err != nil { return err }
    req.Header.Set("Content-Type", "application/json")
    req.Header.Set("X-AuthScope-Workspace", opts.WorkspaceID)
    req.Header.Set("X-Request-ID", opts.RequestID)
    if opts.IdempotencyKey != "" { req.Header.Set("Idempotency-Key", opts.IdempotencyKey) }
    return c.roundTrip(req, out)
}
```

- [ ] **Step 4: Wire readiness to live compatibility**

Startup loads Task 2's immutable instance record and the contract lock, calls discovery, verifies every required operation, and asks AuthScope to verify that the non-exportable workload identity authenticated by the mTLS/workload-signer transport is restricted to the exact instance workspace and carries `decision_attestor`. AuthScope derives identity from the authenticated transport and never trusts a client-selected identity header. Attach the returned stable identity digest to the instance record exactly once; later mismatch is fatal. Store the last successful check time. `/readyz` becomes unhealthy when compatibility has never succeeded or its verified state is older than thirty seconds. Shared mutation middleware and the client adapter both reject every business mutation when verification is missing or stale, including a healthy-to-stale transition after route registration.

- [ ] **Step 5: Map upstream errors without broadening authority**

Map authentication to `401`, forbidden/denied to `403`, missing workspace-qualified objects to `404`, stale version/idempotency mismatch to `409`, unavailable verified context to `412`, rate limits to `429`, and upstream uncertainty to `503`. Never translate an upstream denial into a retryable allow path.

- [ ] **Step 6: Run client, readiness, and redaction tests**

Run: `go test -race ./internal/coreapi ./internal/httpapi -count=1`

Expected: contract fixtures pass; missing methods, schemas, reconciliation paths, workspace binding, `decision_attestor` role, attestation checks, active-mission listing, containment, or healthy-to-stale compatibility return `503`; mutated or replayed decision attestations are denied; seeded credentials and attestations do not appear in errors or logs.

- [ ] **Step 7: Commit**

```bash
git add cmd internal/coreapi internal/httpapi internal/identity internal/store contracts
git commit -m "feat: add fail-closed AuthScope core adapter"
```

### Task 5: Connect an explicit GitHub repository and import a trusted issue snapshot

**Files:**
- Create: `internal/github/handoff.go`, `internal/github/handoff_test.go`
- Create: `internal/github/source.go`, `internal/github/source_test.go`
- Create: `internal/httpapi/github_handlers.go`, `internal/httpapi/github_handlers_test.go`
- Modify: `internal/httpapi/server.go`, `internal/httpapi/server_test.go`
- Create: `web/src/features/connect/GitHubConnection.tsx`, `web/src/features/connect/GitHubConnection.test.tsx`
- Create: `web/src/features/authorize/IssuePicker.tsx`, `web/src/features/authorize/IssuePicker.test.tsx`
- Modify: `web/src/App.tsx`, `web/src/App.test.tsx`
- Modify: `internal/coreapi/types.go`, `internal/store/store.go`, `internal/store/sqlite.go`
- Modify: `openapi/ope-v1.yaml`, `web/src/shared/api/generated.ts`

**Interfaces:**
- Produces: `github.Handoff.Begin`, `github.Handoff.RecordCallback`, `github.Handoff.Finish`, and `github.Source.ReadIssue`.
- Produces: `POST /api/v1/connections/github/begin`, `GET /api/v1/connections/github/callback`, and `POST /api/v1/connections/github/{handoff_id}/finish`.
- Produces: `GET /api/v1/connections/github/{id}/issues/{number}`.
- Produces: immutable `IssueSnapshot` with binding ID, installation ID, repository ID, issue number, issue revision, default branch, base SHA, objective, and acceptance criteria.
- Consumes: `coreapi.Authority.BeginGitHubBinding`, `FinishGitHubBinding`, `GetRepositoryBinding`, `ReadGitHubIssue`, `InspectWorkflowPosture`, and `ReconcileOperation`. AuthScope hosts GitHub App installation, handles GitHub OAuth material, executes provider reads, and returns no GitHub credential or OAuth code to OPE.

```go
type GitHubHandoff struct {
    ID              string
    WorkspaceID     string
    SessionID       string
    StateHash       [32]byte
    BindingCodeDigest [32]byte
    AuthScopeOrigin string
    ExpiresAt       time.Time
    CallbackAt      *time.Time
    ConsumedAt      *time.Time
}
```

```go
type IssueSnapshot struct {
    WorkspaceID        string    `json:"workspace_id"`
    RepositoryBinding string    `json:"repository_binding_id"`
    InstallationID     int64     `json:"installation_id"`
    RepositoryID       int64     `json:"repository_id"`
    RepositoryFullName string    `json:"repository_full_name"`
    IssueNumber        int64     `json:"issue_number"`
    SourceRevision     string    `json:"source_revision"`
    SourceDigest       string    `json:"source_digest"`
    DefaultBranch      string    `json:"default_branch"`
    BaseSHA            string    `json:"base_sha"`
    Objective          string    `json:"objective"`
    AcceptanceCriteria []string  `json:"acceptance_criteria"`
}
```

- [ ] **Step 1: Write failing connection and issue-snapshot tests**

Cover handoff-state and session mismatch, callback without a pending begin, non-AuthScope or changed install URL origin, missing/duplicate/expired callback, changed opaque binding code, finish without the original authenticated session or same-origin CSRF token, concurrent finish, server restart after callback, and an upstream response containing a GitHub OAuth code or token. Inject timeouts and crashes before and after `BeginGitHubBinding` and `FinishGitHubBinding`; require reconciliation by the original idempotency key, no repeated upstream mutation, and safe restart of a handoff whose in-memory binding code was lost. Also cover an installation outside the instance-bound workspace, insufficient GitHub App permissions, repository transfer, revoked binding, closed/deleted issue, stale source revision, stale base SHA, same-name repositories with different immutable IDs, and hostile pre-existing workflows using `push`, `pull_request`, `pull_request_target`, reusable workflows, secrets, write tokens, environments, or deployment actions.

- [ ] **Step 2: Run the focused tests and verify failure**

Run: `go test ./internal/github ./internal/httpapi -run 'TestGitHub|TestIssue' -count=1`

Expected: compilation fails because the GitHub source and handlers do not exist.

- [ ] **Step 3: Add the opaque AuthScope-hosted installation handoff**

`POST /api/v1/connections/github/begin` requires the founder session, Origin, CSRF, and an idempotency key. It creates 256-bit state, stores only its hash with workspace, session, and two-minute expiry, persists an operation intent, and calls `BeginGitHubBinding` once. On timeout it calls `ReconcileOperation` with the original key and never repeats the begin mutation. It returns only the settled handoff ID plus an HTTPS installation URL whose origin exactly matches configured AuthScope. AuthScope hosts the GitHub App installation and owns all GitHub OAuth state and credentials.

`GET /api/v1/connections/github/callback` accepts only handoff ID, opaque one-use AuthScope binding code, and state. It constant-time matches state, records the raw code once in a size-limited in-memory handoff cache and only its digest in durable state, and redirects immediately to a fixed same-origin completion URL. The handler and access logger redact the entire query. It does not finish the binding, create a browser session, accept a GitHub OAuth code, or render either opaque value. Expiry or process restart clears the raw code and requires a new handoff rather than an unsafe exchange.

`POST /api/v1/connections/github/{handoff_id}/finish` requires the original authenticated session, exact Origin, CSRF, and idempotency key. It verifies the cached code against the durable digest, persists an operation intent, and calls `FinishGitHubBinding` once. On timeout it calls `ReconcileOperation` with the original key and never repeats the finish mutation. It clears the raw code after a settled or reconciled outcome and persists the verified workspace, AuthScope binding ID, immutable installation and repository IDs, full name for display, permission status, and verification time. Reconnection replaces a revoked binding transactionally and never reuses its missions. Unknown callback query fields or upstream provider-credential fields fail closed.

- [ ] **Step 4: Import and pin the issue snapshot**

Call AuthScope's typed GitHub issue-snapshot operation with the explicit workspace, binding, immutable repository ID, and issue number. Require AuthScope to return a provider-derived source revision, canonical source digest, base ref/SHA, decision ID, and execution receipt. OPE never receives or handles the GitHub token. Store normalized objective and acceptance criteria only in the active pass draft; never derive the authoritative source digest from generated mission text.

- [ ] **Step 5: Require safe workflow posture**

Ask AuthScope to inspect the repository's current workflow files, rules, token permissions, environments, and mission-branch trigger behavior. Mark the connection unavailable for launch if agent-controlled branch or pull-request content can reach secrets, write tokens, spending, deployments, or `pull_request_target`. Persist only the signed posture digest, inspected head SHA, outcome, reason codes, and expiry. Recheck immediately before launch.

- [ ] **Step 6: Build the Connect and issue-selection components**

The Connect component shows the immutable instance workspace, GitHub identity, installation, repository, permission status, workflow posture, and enforcement status. The issue picker accepts an issue number or URL only after a repository is selected and disables closed, stale, unsafe-workflow, or unverified results with a concrete recovery action. Integrate both components into the real `App` route before committing.

- [ ] **Step 7: Prove no credential exposure**

Seed recognizable GitHub tokens and OAuth codes in the fake AuthScope response headers, callback query, binding response, and internal test transport. Assert they are rejected and absent from SQLite, HTTP responses, browser storage, logs, telemetry, and rendered DOM. The only callback secret OPE may retain is the opaque, one-use AuthScope binding code in the bounded in-memory handoff cache until finish, restart, or expiry; durable state contains only its digest. Assert the client rejects any upstream binding or issue response containing a provider credential field.

- [ ] **Step 8: Run backend and frontend tests**

Run: `go test -race ./internal/github ./internal/httpapi ./internal/store -count=1 && pnpm --dir web test -- GitHubConnection IssuePicker`

Expected: begin/callback/finish replay and origin tests pass, no GitHub OAuth material reaches OPE, and stale source or unsafe workflow posture prevents navigation to Authorize.

- [ ] **Step 9: Commit**

```bash
git add internal/coreapi internal/github internal/httpapi internal/store openapi web/src
git commit -m "feat: connect GitHub and pin issue context"
```

### Task 6: Shape and create the exact AuthScope proposal before review

**Files:**
- Create: `internal/missionpass/model.go`, `internal/missionpass/model_test.go`
- Create: `internal/missionpass/template.go`, `internal/missionpass/template_test.go`
- Create: `internal/missionpass/proposal.go`, `internal/missionpass/proposal_test.go`
- Create: `internal/httpapi/pass_handlers.go`, `internal/httpapi/pass_handlers_test.go`
- Modify: `internal/httpapi/server.go`, `internal/httpapi/server_test.go`
- Create: `web/src/features/authorize/MissionPassReview.tsx`, `web/src/features/authorize/MissionPassReview.test.tsx`
- Modify: `internal/coreapi/types.go`
- Modify: `internal/store/store.go`, `internal/store/sqlite.go`
- Modify: `web/src/App.tsx`, `web/src/App.test.tsx`
- Modify: `openapi/ope-v1.yaml`, `web/src/shared/api/generated.ts`

**Interfaces:**
- Produces: `missionpass.Service.CreateProposal` and `missionpass.Service.ReviseProposal`.
- Produces: `POST /api/v1/mission-passes/drafts`, `PUT /api/v1/mission-passes/{id}/draft`, and `GET /api/v1/mission-passes/{id}`.
- Produces: an immutable `ProposalRecord` whose current `ProposalDigest` and `InvocationDigest` are the exact algorithm-tagged canonical digests returned by AuthScope; `ApprovedProposalDigest` stays empty until Task 7 copies the approved value.
- Consumes: Task 5's trusted `IssueSnapshot`; `coreapi.Authority.ShapeMission`, `CreateProposal`, and `ReconcileOperation`; separate `StoreRevision`, `DraftVersion`, and `AuthScopeMissionVersion` fields from Task 2.

```go
type EditableLimits struct {
    ExpiresAt              time.Time `json:"expires_at"`
    MaxAggregateCostMicros int64     `json:"max_aggregate_cost_micros"`
}

type ProposalRecord struct {
    WorkspaceID             string
    PassID                  string
    StoreRevision           int64
    DraftVersion            int64
    AuthScopeMissionVersion int64
    ProposalID              string
    ProposalDigest          string
    ApprovedProposalDigest  string
    SourceRevision          string
    SourceDigest            string
    BaseSHA                 string
    MissionBranch           string
    AgentKitID              string
    AgentKitVersion         string
    RunnerArguments         []string
    InvocationDigest        string
    Limits                  EditableLimits
    State                   PassState
    Reconciliation          ReconciliationState
}

type PassState string

const (
    PassDraft             PassState = "draft"
    PassApproved          PassState = "approved"
    PassLaunching         PassState = "launching"
    PassRunning           PassState = "running"
    PassAwaitingExpansion PassState = "awaiting_expansion"
    PassOutcomePending    PassState = "outcome_pending"
    PassCompleted         PassState = "completed"
    PassFailed            PassState = "failed"
    PassRevoked           PassState = "revoked"
    PassExpired           PassState = "expired"
)

type ReconciliationState string

const (
    ReconciliationSettled ReconciliationState = "settled"
    ReconciliationPending ReconciliationState = "pending"
    ReconciliationDisputed ReconciliationState = "disputed"
)
```

`StoreRevision` is the only local compare-and-swap token. `DraftVersion` changes only when a founder-visible proposal is revised. `AuthScopeMissionVersion` is zero before approval and changes only when AuthScope creates or revises mission authority.

- [ ] **Step 1: Write failing shaping, proposal, edit-boundary, and state tests**

Use a fake Authority to assert this exact call order: trusted source refresh, workflow-posture refresh, `ShapeMission`, then `CreateProposal`, then persistence. Assert that OPE stores AuthScope's returned proposal ID, proposal digest, fixed agent-kit ID/version, exact runner argument array, and invocation digest byte-for-byte, leaves `ApprovedProposalDigest` empty, and never computes a substitute authority digest. Verify the proposal digest covers the invocation digest. Mutate kit ID, kit version, runner argument order/content, or invocation digest and fail closed. Cover malformed or unknown proposal fields, a widened shaped result, stale issue/base/workflow posture, timeout plus reconciliation, and every valid and invalid state transition. Send attempts to edit objective, criteria, repository, issue, branch, paths, action sets, file/tool/token ceilings, agent kit, runner arguments, invocation digest, and enforcement level; each must return `422`. Only an earlier expiry and a lower aggregate-cost ceiling are accepted.

- [ ] **Step 2: Run the focused tests and verify failure**

Run: `go test -race ./internal/missionpass ./internal/httpapi -run 'TestShape|TestCreateProposal|TestReviseProposal|TestPassState' -count=1`

Expected: compilation fails because the mission model, proposal service, and handlers do not exist.

- [ ] **Step 3: Define the local template input and complete state table**

The local template supplies immutable source identifiers, branch prefix `authscope/<pass-id>-`, fixed protected paths, the fixed supported AuthScope agent-kit ID and version, no user-command surface, maximum expiry of two hours, maximum aggregate cost of USD 20, zero delegation, and one pending expansion. AuthScope supplies the kit's exact runner argument array and an algorithm-tagged invocation digest over kit ID, version, and ordered arguments; that digest is covered by the proposal digest. The template is input validation and presentation metadata only. AuthScope shapes and evaluates authority. Terminal states never transition. A run-success or run-failure event enters `outcome_pending`; only a locally verified receipt enters `completed` or `failed`. Reconciliation status remains orthogonal to pass state.

- [ ] **Step 4: Shape and create the upstream proposal before review**

Refresh source revision, base SHA, repository binding, workflow-posture digest, and live compatibility. Call `ShapeMission`, require the response to remain inside the fixed template, then call `CreateProposal` with a workspace-qualified idempotency key. Persist the exact returned proposal ID, digest algorithm and digest, authority summary, fixed ceilings, enforcement labels, agent-kit ID/version, ordered runner arguments, invocation-digest algorithm/value, `ApprovedProposalDigest = ""`, and `DraftVersion = 1`. If creation times out, persist an intent and call `ReconcileOperation`; do not issue another proposal mutation.

- [ ] **Step 5: Implement the only two edits**

`PUT /api/v1/mission-passes/{id}/draft` accepts only `expected_store_revision`, `expected_draft_version`, `expires_at`, and `max_aggregate_cost_micros`. It rejects an expiry after the template maximum or current value and a budget above the template maximum or current value. A valid edit reruns `ShapeMission` and `CreateProposal`, writes an immutable proposal revision with `DraftVersion + 1`, and leaves `AuthScopeMissionVersion = 0`. Unknown JSON fields fail decoding.

- [ ] **Step 6: Build the compact Authorize review**

Show the shaped objective and acceptance evidence read-only, a compact “Can / Will ask / Cannot” summary, repository/issue/base/branch, fixed agent-kit ID/version, expiry, one aggregate budget, and honest enforcement labels. Put the ordered runner arguments, invocation digest, protected paths, and fixed technical ceilings in collapsed details. The only controls are expiry and aggregate budget. Display the exact AuthScope proposal and invocation digests and invalidate the visible review when either editable value changes. Integrate the Authorize route into `App`.

- [ ] **Step 7: Run the proposal slice**

Run: `go test -race ./internal/missionpass ./internal/httpapi ./internal/store -count=1 && pnpm --dir web test -- MissionPassReview App`

Expected: call-order, exact-digest, timeout reconciliation, immutable-revision, state-table, and UI edit-boundary tests pass; no local code claims to authorize an action.

- [ ] **Step 8: Commit**

```bash
git add internal/coreapi internal/missionpass internal/httpapi internal/store openapi web/src
git commit -m "feat: create exact AuthScope proposals before review"
```

### Task 7: Approve the exact proposal with a passkey and create only the mission

**Files:**
- Create: `internal/missionpass/approval.go`, `internal/missionpass/approval_test.go`
- Create: `internal/httpapi/approval_handlers.go`, `internal/httpapi/approval_handlers_test.go`
- Modify: `internal/httpapi/server.go`, `internal/httpapi/server_test.go`
- Modify: `internal/authn/passkey.go`, `internal/authn/passkey_test.go`
- Modify: `internal/coreapi/types.go`
- Modify: `internal/store/store.go`, `internal/store/sqlite.go`
- Modify: `web/src/features/authorize/MissionPassReview.tsx`, `web/src/features/authorize/MissionPassReview.test.tsx`
- Modify: `openapi/ope-v1.yaml`, `web/src/shared/api/generated.ts`

**Interfaces:**
- Produces: `missionpass.ApprovalService.Begin` and `missionpass.ApprovalService.Finish`.
- Produces: `POST /api/v1/mission-passes/{id}/approve/begin`, `POST /api/v1/mission-passes/{id}/approve/finish`.
- Consumes: the exact current AuthScope proposal and invocation digests from Task 6, Task 3 decision challenges, Task 4 `identity.DecisionAttestor`, `Authority.ApproveProposal`, and `Authority.ReconcileOperation`.

```go
type ApprovalBinding struct {
    WorkspaceID     string
    FounderID       string
    SessionID       string
    PassID          string
    DraftVersion    int64
    ProposalID      string
    ProposalDigest  string
    InvocationDigest string
    SourceDigest    string
    BaseSHA         string
    Purpose         string
    Audience        string
}

type ApprovalResult struct {
    MissionRef               string `json:"mission_ref"`
    MissionHash              string `json:"mission_hash"`
    AuthScopeMissionVersion  int64  `json:"authscope_mission_version"`
    ApprovalDecisionRef      string `json:"approval_decision_ref"`
}
```

An approval result contains no runtime policy, lease, launch descriptor, sealed credential, or `RunID`.

- [ ] **Step 1: Write failing begin/finish, replay, and reconciliation tests**

Begin approval for the current proposal and assert that the WebAuthn challenge digest covers every `ApprovalBinding` field. Independently change workspace, founder/session, pass, draft version, proposal ID/digest, invocation digest, source digest, base SHA, purpose, audience, challenge nonce, or expiry and assert failure. After local WebAuthn success, use a signing identity whose AuthScope registration lacks `decision_attestor`, then mutate the OPE decision-attestation signature, workspace, audience, exact binding digest, invocation digest, authentication method/proof digest, nonce, issued-at, expiry, or replay state and require AuthScope denial. Cover replayed finish, stale proposal, edited proposal after begin, concurrent finish, upstream timeout, process crash after upstream success, and status reconciliation. Assert one upstream mission and zero calls to `PrepareLaunch`.

- [ ] **Step 2: Run the focused tests and verify failure**

Run: `go test -race ./internal/authn ./internal/missionpass ./internal/httpapi -run 'TestApproval|TestApproveProposal' -count=1`

Expected: tests fail because approval begin/finish and reconciliation records do not exist.

- [ ] **Step 3: Begin an exact decision challenge**

Reload the current proposal, refresh source/base/workflow posture, and require `draft` state with reconciled proposal creation. Parse the algorithm-tagged AuthScope proposal and invocation digests without recomputing them. Call `authn.BeginDecision` with purpose `pass_approval`, audience `authscope:proposal-approval`, and a server-canonicalized `ApprovalBinding`. Return WebAuthn request options and `challenge_id`; never accept authority or invocation fields from the browser.

- [ ] **Step 4: Finish approval and create only the mission**

Atomically consume the challenge through `authn.FinishDecision`, then call `DecisionAttestor.Attest` over the exact approval binding, method `webauthn_uv`, an algorithm-tagged digest of the verified local ceremony record, challenge nonce, issued-at, and two-minute expiry. Create a local approval intent before the upstream mutation and call `ApproveProposal` with the exact proposal ID/digest, invocation digest, and signed decision attestation. AuthScope must require `decision_attestor` and independently verify signature, workspace, audience, decision and invocation digests, authentication context, nonce, freshness, and replay before creating the mission. Persist mission reference/hash, decision reference, attestation digest, `ApprovedProposalDigest = ProposalDigest`, and `AuthScopeMissionVersion`; increment `StoreRevision`, leave `DraftVersion` unchanged, and transition `draft -> approved`. Do not prepare a runtime, lease, run, or launcher artifact.

- [ ] **Step 5: Reconcile ambiguous approval**

Use a deterministic downstream idempotency key derived from workspace, pass ID, draft version, and `approve`. On timeout, return `202 pending_reconciliation`. The pass status route calls `ReconcileOperation` using the stored operation reference and may settle the original result; it never repeats `ApproveProposal`. A different canonical request with the same local key returns `409`.

- [ ] **Step 6: Add approval to Authorize**

The single “Approve Mission Pass” action first calls the begin route, performs WebAuthn, then calls finish. While reconciliation is pending, disable edits and launch and show “Checking the original approval” rather than a retry button. When settled, show the mission reference and a CLI launch handoff action without claiming that a run exists.

- [ ] **Step 7: Run approval tests**

Run: `go test -race ./internal/authn ./internal/missionpass ./internal/httpapi ./internal/store -count=1 && pnpm --dir web test -- MissionPassReview`

Expected: exact binding, signing-identity role plus attestation signature/claim/replay checks, one-use challenge, stale-source, concurrent approval, crash-window, and reconciliation tests pass; approved records have a mission version and an empty `RunID`.

- [ ] **Step 8: Commit**

```bash
git add internal/authn internal/coreapi internal/identity internal/missionpass internal/httpapi internal/store openapi web/src
git commit -m "feat: approve exact proposals and create missions"
```

### Task 8: Authorize the CLI through a one-use browser PKCE handoff

**Files:**
- Create: `internal/authn/pkce.go`, `internal/authn/pkce_test.go`
- Create: `internal/cli/authorize.go`, `internal/cli/authorize_test.go`
- Create: `internal/httpapi/cli_authorization_handlers.go`, `internal/httpapi/cli_authorization_handlers_test.go`
- Modify: `internal/httpapi/server.go`, `internal/httpapi/server_test.go`
- Create: `web/src/features/authorize/CLIAuthorization.tsx`, `web/src/features/authorize/CLIAuthorization.test.tsx`
- Modify: `cmd/authscope-ope/main.go`
- Modify: `internal/store/store.go`, `internal/store/sqlite.go`
- Modify: `openapi/ope-v1.yaml`, `web/src/shared/api/generated.ts`

**Interfaces:**
- Produces: `authn.CLIAuthorizationService.Create`, `BeginBrowserDecision`, and `FinishBrowserDecision`.
- Produces: a bounded in-memory `authn.PendingDecisionAttestations` cache whose entries are tied to authorization ID, attestation digest, code hash, and expiry.
- Produces: `cli.ReceiveAuthorizationCode`.
- Produces: `POST /api/v1/cli/authorizations`, `POST /api/v1/cli/authorizations/{id}/approve/begin`, and `POST /api/v1/cli/authorizations/{id}/approve/finish`.
- Consumes: an approved mission and its fixed invocation digest from Task 7, Task 3 decision challenges, Task 4 `identity.DecisionAttestor`, a loopback redirect, an RFC 7636 `S256` challenge, and an ephemeral X25519 CLI public key.

```go
type CLIAuthorizationRequest struct {
    PassID                string `json:"pass_id"`
    RedirectURI           string `json:"redirect_uri"`
    State                 string `json:"state"`
    CodeChallenge         string `json:"code_challenge"`
    CodeChallengeMethod   string `json:"code_challenge_method"`
    EphemeralPublicKey    string `json:"ephemeral_public_key"`
}

type CLIAuthorizationStart struct {
    ID                 string   `json:"authorization_id"`
    BrowserURL         string   `json:"browser_url"`
    ProposalDigest     string   `json:"proposal_digest"`
    AgentKitID         string   `json:"agent_kit_id"`
    AgentKitVersion    string   `json:"agent_kit_version"`
    RunnerArguments    []string `json:"runner_arguments"`
    InvocationDigest   string   `json:"invocation_digest"`
}

type CLIAuthorization struct {
    ID                    string
    WorkspaceID           string
    PassID                string
    MissionRef            string
    ProposalDigest        string
    AgentKitID            string
    AgentKitVersion       string
    RunnerArguments       []string
    InvocationDigest      string
    RedirectURI           string
    State                 string
    CodeChallenge         string
    EphemeralPublicKey    [32]byte
    CodeHash              [32]byte
    ExpiresAt             time.Time
    ApprovedAt            *time.Time
    ConsumedAt            *time.Time
    DecisionAttestationDigest string
}
```

- [ ] **Step 1: Write failing PKCE and browser-handoff tests**

Cover non-loopback and `localhost` redirects, fixed or privileged ports, wrong `S256` verifier, state mismatch, altered ephemeral public key, wrong pass/mission/approved-proposal digest/invocation digest, changed kit ID/version or runner argument order/content, expired or replayed browser approval, duplicate browser finish, unauthenticated browser, wrong Origin/CSRF, concurrent callbacks, and process restart after approval but before exchange. Require `Create` to return the exact approved proposal digest, agent-kit ID/version, ordered arguments, and invocation digest; the CLI must recompute and retain them only in memory. Use a signing identity whose AuthScope registration lacks `decision_attestor`, then mutate decision-attestation audience, digest, authentication method/proof digest, nonce, freshness, or signature and require the fake AuthScope launch verifier to deny it. Search the store and CLI test filesystem after success and assert that no reusable bearer, refresh credential, or signed attestation exists.

- [ ] **Step 2: Run the focused tests and verify failure**

Run: `go test -race ./internal/authn ./internal/cli ./internal/httpapi -run 'TestCLIAuth|TestPKCE|TestLoopback' -count=1`

Expected: compilation fails because the one-use authorization service and loopback receiver do not exist.

- [ ] **Step 3: Create a pending CLI authorization**

`authscope-ope run <pass-id>` binds a random callback listener to `127.0.0.1` on an unprivileged ephemeral port, creates 256-bit state and PKCE verifier values, generates an ephemeral X25519 keypair in memory, and posts pass ID, state, the `S256` challenge, and public key. The server reloads the approved proposal, requires nonempty `ApprovedProposalDigest`, and binds the authorization record and its canonical idempotency digest to that digest, the fixed agent-kit ID/version, ordered runner arguments, and exact invocation digest; it accepts no command or argument fields from the CLI. The server accepts exact `http://127.0.0.1:<port>/callback` redirects, stores state plus only hashes of secret values, applies a two-minute expiry, and returns `CLIAuthorizationStart`. The CLI canonicalizes the returned kit ID/version and ordered arguments with the pinned digest algorithm, rejects a mismatch, and retains those expected values with its ephemeral key only in memory for Task 9 envelope verification. The same canonical request returns the original pending authorization and changed content conflicts. It grants no mission or runtime authority.

- [ ] **Step 4: Approve the handoff in the browser**

The authenticated browser reloads the current approved mission and shows the pass, repository, issue, fixed agent-kit ID/version, runner arguments, and invocation digest. Begin a passkey decision with purpose `cli_launch_authorization` and audience `authscope:prepare-launch`, bound to authorization ID, pass, mission reference/version, proposal digest, invocation digest, kit ID/version, ordered arguments, callback URI, PKCE challenge, ephemeral public key, and nonce. Finish verifies WebAuthn, signs that exact binding through `DecisionAttestor`, places the short-lived one-use signed attestation only in `PendingDecisionAttestations`, stores its digest in the durable authorization, atomically creates one 256-bit authorization code, stores only its hash, marks the request approved, and redirects code plus original state to the exact loopback URI. AuthScope later rejects a signing identity without `decision_attestor`, or a wrong workspace, audience, digest, invocation digest, nonce, freshness, signature, or replay.

- [ ] **Step 5: Receive without persisting credentials**

The CLI rejects wrong state, duplicate callbacks, missing code, or callback requests from a non-loopback peer. It keeps code, verifier, state, expected proposal/kit/argument/invocation values, and ephemeral private key only in memory until Task 9 exchange. OPE retains the signed exact decision attestation only in the bounded process-memory cache until exchange settles, the authorization expires, or the process stops; durable state keeps only its digest. A restart before the upstream request invalidates that authorization and requires a new browser decision. Once an upstream request may have been sent, Task 9 reconciles the original idempotency intent and never needs to replay the attestation. Cancellation, timeout, signal, or exchange completion zeroes buffers where Go permits and closes the listener. No CLI secret reaches disk, browser storage, an environment variable, or shell history.

- [ ] **Step 6: Add the browser handoff component**

Render the browser decision as a transient state inside Authorize, not a fourth product screen. Show which pass and local CLI request will be authorized. On finish, show only “Return to the CLI”; never render the code, verifier, or sealed runtime material.

- [ ] **Step 7: Run PKCE and UI tests**

Run: `go test -race ./internal/authn ./internal/cli ./internal/httpapi ./internal/store -count=1 && pnpm --dir web test -- CLIAuthorization`

Expected: one browser decision binds one exact invocation and delivers one code to one loopback listener; attestation, replay, cross-workspace, redirect, PKCE, and persistence tests pass.

- [ ] **Step 8: Commit**

```bash
git add cmd internal/authn internal/cli internal/httpapi internal/identity internal/store openapi web/src
git commit -m "feat: authorize one CLI launch through the browser"
```

### Task 9: Exchange once, prepare exactly one governed run, and launch through an anonymous descriptor

**Files:**
- Create: `contracts/authscope-signing-keys.json`
- Create: `internal/trust/keys.go`, `internal/trust/keys_test.go`
- Create: `internal/launch/service.go`, `internal/launch/service_test.go`
- Create: `internal/launch/envelope.go`, `internal/launch/envelope_test.go`
- Create: `internal/cli/run.go`, `internal/cli/run_test.go`
- Create: `internal/cli/process_unix.go`, `internal/cli/process_unix_test.go`
- Create: `internal/httpapi/launch_handlers.go`, `internal/httpapi/launch_handlers_test.go`
- Modify: `internal/httpapi/server.go`, `internal/httpapi/server_test.go`
- Modify: `cmd/authscope-ope/main.go`
- Modify: `internal/coreapi/types.go`
- Modify: `internal/coreapi/compatibility.go`, `internal/coreapi/compatibility_test.go`
- Modify: `internal/missionpass/model.go`
- Modify: `internal/store/store.go`, `internal/store/sqlite.go`
- Modify: `openapi/ope-v1.yaml`, `web/src/shared/api/generated.ts`
- Modify: `contracts/authscope.lock.json`, `scripts/verify-contract.sh`

**Interfaces:**
- Produces: `launch.Service.ExchangeAndPrepare`.
- Produces: `cli.ProcessStarter.Start(context.Context, string, []string, []string, uintptr) (cli.ProcessResult, error)`.
- Produces: `POST /api/v1/cli/token`, whose successful response is an AuthScope-signed launch envelope sealed to Task 8's ephemeral CLI key.
- Consumes: one approved authorization code and verifier, the signed exact CLI decision attestation, `Authority.PrepareLaunch`, `Authority.ReconcileOperation`, the pinned AuthScope signing-key history, and the proposal's fixed agent kit and invocation digest.

```go
type LaunchArtifacts struct {
    RunID                    string
    MissionRef               string
    AuthScopeMissionVersion  int64
    RuntimePolicyID          string
    LeaseID                  string
    AgentKitID               string
    AgentKitVersion          string
    InvocationDigest        string
    RunnerExecutable         string
    RunnerArguments          []string
    IsolationProfile         string
    EnvelopeKeyID            string
    SealedSignedEnvelope     []byte
    ExpiresAt                time.Time
}

type ProcessResult struct {
    ExitCode int
    RunID    string
}
```

- [ ] **Step 1: Write failing exchange, idempotency, envelope, FD, and isolation tests**

Exchange once, double-submit concurrently, and retry after a lost response; assert exactly one `PrepareLaunch` call and one `RunID`, and make an identical code/verifier/canonical exchange return only the original result. Reject changed content after code consumption, expired code, a missing in-memory attestation before any upstream request after restart, altered CLI public key, stale mission version, changed source/base/workflow posture, altered proposal or invocation digest, changed kit ID/version or runner argument order/content, invalid or replayed OPE decision attestation, unsupported kit, missing `enforced` runtime isolation, bad envelope signature metadata, wrong audience, expired envelope, runner symlink, writable runner, arbitrary executable/arguments, and descriptor replay. Mutate every proposal/kit/version/argument/invocation value returned to and retained by the CLI and require envelope verification to fail. Seed provider, Git, SSH, cloud, model, proxy, dynamic-loader, Docker-socket, and shell-startup credentials; assert none reach argv or environment. Assert credential bytes travel only through the designated anonymous file descriptor.

- [ ] **Step 2: Run the focused tests and verify failure**

Run: `go test -race ./internal/launch ./internal/cli ./internal/httpapi -run 'TestExchange|TestPrepareLaunch|TestEnvelope|TestProcess' -count=1`

Expected: compilation fails because launch exchange, envelope validation, and anonymous-FD process start do not exist.

- [ ] **Step 3: Atomically exchange and prepare one run**

Canonicalize the token exchange first. If a durable completed exchange has the same code hash, verifier proof, and canonical body, return only its original sealed result from the bounded delivery cache or `ReconcileOperation`; if any field differs, reject it. For a new exchange, hash and compare the authorization code, verify PKCE in constant time, reload and compare the exact approved proposal and invocation digests, and require the matching original attestation from `PendingDecisionAttestations` before atomically reserving the code with an idempotency intent. Only one concurrent exchange owns that reservation. Refresh binding, issue revision, base SHA, workflow posture, mission version, pass expiry, contract compatibility, and agent kit. Call the single upstream `PrepareLaunch` operation with the original signed CLI decision attestation. AuthScope requires the `decision_attestor` role and independently verifies the attestation's signature, workspace, audience, exact decision and invocation digests, authentication context, nonce, freshness, and replay before it creates the runtime policy, lease, and `RunID`. If the process dies before the upstream request, expire the reservation and require a new browser authorization because the attestation is intentionally unavailable. Once the request may have been sent, persist the ambiguous intent and call `ReconcileOperation`; never repeat `PrepareLaunch`. Clear the cached attestation after a settled result or expiry. Persist only run metadata, attestation digest, and envelope digest. Keep sealed ciphertext in a bounded in-memory delivery cache, and retrieve the original envelope through `ReconcileOperation` after response loss; never write envelope, attestation, or credential bytes to SQLite or disk. Set `AuthScopeMissionVersion` from upstream, leave `DraftVersion` unchanged, increment `StoreRevision`, and transition `approved -> launching`.

- [ ] **Step 4: Require a signed envelope sealed to the ephemeral key**

AuthScope signs the launch payload and seals the signed bytes to the CLI X25519 public key. The protected payload binds run ID, mission reference/version, proposal digest, invocation digest, runtime policy, lease, agent-kit ID/version, exact runner executable and ordered arguments, isolation profile, audience `authscope-agent-run`, nonce, issued-at, and expiry. OPE treats it as opaque ciphertext. Pin the AuthScope signing-root fingerprint and initial authenticated key history in `contracts/authscope-signing-keys.json`, add its SHA-256 to `contracts/authscope.lock.json`, and make `scripts/verify-contract.sh` enforce both; `internal/trust` accepts rotation only through a statement chained to that root. The CLI opens the envelope with the in-memory private key, validates algorithm, key ID, signature, audience, nonce, expiry, recomputes the invocation digest from the envelope kit ID/version and ordered arguments, and requires equality with the proposal digest, kit ID/version, arguments, and invocation digest retained from `CLIAuthorizationStart`; it rejects unknown fields.

- [ ] **Step 5: Start only the governed runner through an anonymous FD**

Resolve `authscope-agent-run` to an absolute owner-controlled regular file and reject symlinks or group/world writes. Create an anonymous pipe, write the signed runtime envelope to the child end, expose only its numeric descriptor through the fixed `--launch-envelope-fd` argument, close both unused ends promptly, and call `exec.CommandContext` directly. Use only AuthScope-supplied runner arguments. Never accept an agent command from the user and never invoke a shell.

- [ ] **Step 6: Require upstream isolation rather than emulate it locally**

Start with an empty environment plus an explicit locale, isolated temporary home/worktree paths, and the runner's required non-secret variables. Require the signed envelope and live capability report to name an `enforced` profile that denies ambient credential helpers, SSH agents, Docker sockets, host configuration, sensitive filesystem paths, and outbound traffic except the enforcing AuthScope gateway. OPE refuses launch when isolation is `observed`, `checked`, missing, or stale. Task 16 proves the isolation with the real runtime.

- [ ] **Step 7: Run launch tests**

Run: `scripts/verify-contract.sh && go test -race ./internal/trust ./internal/launch ./internal/cli ./internal/httpapi ./internal/store -count=1`

Expected: concurrent and crash-window tests produce one run; argv, environment, files, logs, and errors contain no runtime credential; shell and isolation bypass fixtures are rejected.

- [ ] **Step 8: Commit**

```bash
git add cmd contracts scripts/verify-contract.sh internal/trust internal/coreapi internal/launch internal/cli internal/httpapi internal/missionpass internal/store openapi web/src
git commit -m "feat: prepare and start one isolated governed run"
```

### Task 10: Project fixed events, reconcile server-side, and revoke through begin/finish decisions

**Files:**
- Create: `internal/missionpass/events.go`, `internal/missionpass/events_test.go`
- Create: `internal/reconcile/worker.go`, `internal/reconcile/worker_test.go`
- Create: `internal/missionpass/revoke.go`, `internal/missionpass/revoke_test.go`
- Create: `internal/httpapi/event_handlers.go`, `internal/httpapi/event_handlers_test.go`
- Create: `internal/httpapi/revoke_handlers.go`, `internal/httpapi/revoke_handlers_test.go`
- Modify: `internal/httpapi/server.go`, `internal/httpapi/server_test.go`
- Create: `internal/cli/revoke.go`, `internal/cli/revoke_test.go`
- Create: `web/src/features/mission/Timeline.tsx`, `web/src/features/mission/Timeline.test.tsx`
- Create: `web/src/features/mission/RevokeButton.tsx`, `web/src/features/mission/RevokeButton.test.tsx`
- Modify: `cmd/authscope-ope/main.go`
- Modify: `internal/coreapi/types.go`
- Modify: `internal/store/store.go`, `internal/store/sqlite.go`
- Modify: `openapi/ope-v1.yaml`, `web/src/shared/api/generated.ts`

**Interfaces:**
- Produces: `missionpass.EventProjector.Apply`, `reconcile.Worker.Run`, `missionpass.RevocationService.Begin`, and `missionpass.RevocationService.Finish`.
- Produces: cursor-resumable `GET /api/v1/mission-passes/{id}/events`, plus `POST /api/v1/mission-passes/{id}/revoke/begin` and `POST /api/v1/mission-passes/{id}/revoke/finish`.
- Produces: `POST /api/v1/cli/revocations` and `POST /api/v1/cli/revocations/token` for a result-only loopback PKCE handoff that reuses the Mission revoke decision.
- Consumes: authenticated AuthScope events, stored operation intents, Task 3 challenges, Task 4 `identity.DecisionAttestor`, `Authority.ReadEvents`, `ReconcileOperation`, and `RevokeMission`.

```go
type SafeEvent struct {
    EventID                  string
    Cursor                   string
    Type                     string
    OccurredAt               time.Time
    AuthScopeMissionVersion  int64
    ResourceDigest           string
    ReasonCode               string
    Branch                   string
    PullRequestNumber        int64
    HeadSHA                  string
    CheckKind                string
    CheckOutcome             string
}

var allowedEventTypes = map[string]bool{
    "mission_started": true, "action_checked": true,
    "expansion_requested": true, "pull_request_created": true,
    "run_succeeded": true, "run_failed": true,
    "mission_expired": true, "mission_revoked": true,
    "receipt_ready": true,
}
```

- [ ] **Step 1: Write failing projection, worker, and revocation tests**

Feed duplicate, out-of-order, stale-cursor, wrong-workspace, bad-authentication, lower-mission-version, unknown-type, unknown-field, and oversized events. An unknown authenticated type must discard its payload, leave the cursor unchanged, mark the mission projection incompatible and stale, and make shared mutation middleware fail closed until the parser and pinned contract are upgraded. Seed prompts, patches, issue bodies, transcripts, URLs, email addresses, and credentials; assert none reach SQLite or rendered JSON. Restart the worker during pending approval, launch, expansion, check publication, and revocation reconciliation, including a terminal mission with pending publication. Begin and finish revocation from web and CLI; for the CLI cover invalid loopback redirect, state, PKCE verifier, replay, and result-reference leakage. Alter mission version, descendants flag, reason, challenge, digest, decision-attestation workspace/audience/authentication method/proof digest/nonce/freshness/signature, or replay state, or sign with an identity whose AuthScope registration lacks `decision_attestor`, and assert failure. Concurrent web/CLI finish yields one upstream revoke.

- [ ] **Step 2: Run the focused tests and verify failure**

Run: `go test -race ./internal/missionpass ./internal/reconcile ./internal/cli ./internal/httpapi -run 'TestEvent|TestWorker|TestRevok' -count=1`

Expected: compilation fails because the fixed projector, worker, and revocation flows do not exist.

- [ ] **Step 3: Store only an allowlisted event projection**

Authenticate before parsing. Decode each known event into a strict type, require fixed reason, check-kind, and outcome enums, validate the mission-branch pattern, derive safe links from the verified repository binding plus numeric PR data, and store only `SafeEvent` fields. An unknown authenticated event type has its payload discarded, records only a fixed local incompatibility reason, marks the projection incompatible and stale, blocks business mutations, and does not advance the cursor. Unknown payload fields, invalid events, and cross-workspace events are rejected and never advance the cursor. Recovery requires a parser and pinned-contract upgrade that recognizes the event, followed by replay from the unchanged cursor. Insert a known event and advance its cursor in one transaction. A run outcome moves to `outcome_pending`, never directly to `completed` or `failed`.

- [ ] **Step 4: Run reconciliation as a server-owned worker**

Start one worker with the server context. It resumes each nonterminal mission from its durable cursor, uses bounded long polling with exponential backoff capped at thirty seconds, projects events, and reconciles stored ambiguous mutation intents by their original idempotency keys. It takes a SQLite worker lease so a second process cannot own the same instance cursor. Shutdown persists cursors and releases the lease. A terminal mission stops event polling after its final receipt reconciliation, but any pending check-publication or containment intent remains worker-owned and is retried or reconciled until it becomes `settled` or `disputed`.

- [ ] **Step 5: Implement web revocation begin/finish**

`/api/v1/mission-passes/{id}/revoke/begin` reloads the mission and binds a passkey challenge to workspace, founder/session, pass, mission reference/version, descendants `true`, normalized reason code, purpose `mission_revoke`, audience `authscope:mission-revoke`, and nonce. `/api/v1/mission-passes/{id}/revoke/finish` atomically consumes the challenge, calls `DecisionAttestor.Attest` over that exact binding, writes intent first, and calls `RevokeMission` with the signed attestation. AuthScope independently enforces the attestor role, signature, workspace, audience, digest, nonce, freshness, and replay state. Record `acknowledged`, `pending`, or `partial` containment; pending outcomes are reconciled by the worker. Never claim enforcement until upstream acknowledges gateway containment.

- [ ] **Step 6: Implement CLI revocation through the browser**

`authscope-ope revoke <pass-id>` binds an unprivileged `127.0.0.1` callback, creates state and an `S256` verifier/challenge, and calls `POST /api/v1/cli/revocations` to register a two-minute request bound to the pass and exact server-canonical revocation digest. It opens the authenticated Mission revocation view with the opaque request ID. The browser uses the existing resource-specific revoke begin/finish routes and exact signed attestation; after the one upstream result settles or becomes pending reconciliation, finish creates a one-use result code and redirects it with state to the exact loopback URI. The CLI verifies state and calls `POST /api/v1/cli/revocations/token` with the code and verifier. The response contains only an opaque revocation-result reference and fixed state; no CLI credential or session is issued or stored. An identical code, verifier, and canonical token request may recover only that original reference until expiry; changed, expired, foreign-workspace, or differently bound requests fail, and an ambiguous upstream revoke is reconciled rather than repeated.

- [ ] **Step 7: Build timeline and revoke controls**

Render fixed safe events and stale/reconciliation status on the Mission route. Show trusted branch and PR links only from projected numeric identifiers. The revoke control always uses begin/finish and distinguishes requested, pending, partial, and acknowledged containment. It remains available in `approved`, `launching`, `running`, `awaiting_expansion`, and `outcome_pending`.

- [ ] **Step 8: Run projection and revocation suites**

Run: `go test -race ./internal/missionpass ./internal/reconcile ./internal/cli ./internal/httpapi ./internal/store -count=1 && pnpm --dir web test -- Timeline RevokeButton`

Expected: event replay is deterministic, sensitive payloads never enter persistence, worker restart resumes correctly, and each revocation path emits one upstream request with an honest containment state.

- [ ] **Step 9: Commit**

```bash
git add cmd internal/coreapi internal/identity internal/missionpass internal/reconcile internal/cli internal/httpapi internal/store openapi web/src
git commit -m "feat: reconcile safe events and revoke governed missions"
```

### Task 11: Decide one exact bounded expansion through passkey begin/finish

**Files:**
- Create: `internal/expansion/service.go`, `internal/expansion/service_test.go`
- Create: `internal/httpapi/expansion_handlers.go`, `internal/httpapi/expansion_handlers_test.go`
- Modify: `internal/httpapi/server.go`, `internal/httpapi/server_test.go`
- Create: `web/src/features/mission/ExpansionCard.tsx`, `web/src/features/mission/ExpansionCard.test.tsx`
- Modify: `internal/missionpass/events.go`
- Modify: `internal/reconcile/worker.go`
- Modify: `internal/coreapi/types.go`
- Modify: `internal/store/store.go`, `internal/store/sqlite.go`
- Modify: `openapi/ope-v1.yaml`, `web/src/shared/api/generated.ts`

**Interfaces:**
- Produces: `expansion.Service.ListPending`, `BeginDecision`, and `FinishDecision`.
- Produces: `GET /api/v1/mission-passes/{id}/expansions`, `POST /api/v1/expansions/{id}/decide/begin`, and `POST /api/v1/expansions/{id}/decide/finish`.
- Consumes: AuthScope's canonical expansion delta and digest, Task 3 decision challenges, Task 4 `identity.DecisionAttestor`, `Authority.DecideExpansion`, and worker reconciliation.

```go
type Decision string

const (
    ApproveOnce Decision = "approve_once"
    Deny        Decision = "deny"
)

type ExpansionBinding struct {
    WorkspaceID                 string
    PassID                      string
    MissionRef                  string
    ExpectedAuthScopeVersion    int64
    ExpansionID                 string
    ExpansionDigest             string
    Decision                    Decision
    EffectiveExpiry             time.Time
    Purpose                     string
    Audience                    string
}
```

- [ ] **Step 1: Write failing exact-delta, begin/finish, and race tests**

Approve a valid request, then independently alter operation, resource, repository, ref, path, destination, normalized arguments digest, quantity, budget, mission version, expiry, expansion digest, decision, or audience and assert failure. Mutate signed decision-attestation workspace, audience, digest, authentication method/proof digest, nonce, freshness, signature, or replay state, or sign with an identity whose AuthScope registration lacks `decision_attestor`, and require AuthScope denial. Cover challenge replay, concurrent finish, timeout reconciliation, resolved/expired/terminal/wrong-workspace requests, and a second simultaneous pending expansion. Denial must leave authority byte-identical. Approval must return the upstream mission version while leaving local `DraftVersion` unchanged.

- [ ] **Step 2: Run the focused tests and verify failure**

Run: `go test -race ./internal/expansion ./internal/httpapi -count=1`

Expected: compilation fails because expansion begin/finish and exact-delta persistence do not exist.

- [ ] **Step 3: Present only the canonical upstream delta**

Store and display expansion ID/digest, current and requested authority, blocked operation, immutable resource identifiers, normalized-arguments digest, consequence change, reason code, reversibility, and requested expiry. Agent-authored rationale is visibly labeled and is never used in the decision digest. Reject unknown fields rather than retaining raw payloads.

- [ ] **Step 4: Begin a decision bound to exact authority**

Reload pending expansion and current mission version. Compute the WebAuthn challenge over `ExpansionBinding` with purpose `expansion_decision` and audience `authscope:expansion-decision`; `approve_once` uses the lesser of requested expiry and mission expiry. The browser cannot submit or widen a delta. Only `approve_once` and `deny` decode.

- [ ] **Step 5: Finish idempotently and reconcile**

Atomically consume the challenge, call `DecisionAttestor.Attest` over the exact binding, and store intent before `DecideExpansion` with that signed attestation. AuthScope independently verifies role, signature, workspace, audience, digest, nonce, freshness, and replay. The same idempotency key and canonical binding returns the original result; a different binding conflicts. On approval, store the returned `AuthScopeMissionVersion`, increment `StoreRevision`, preserve `DraftVersion`, and return to `running`. On denial, preserve the prior authority version until AuthScope reports replanning or outcome. The worker reconciles uncertain results without repeating the mutation.

- [ ] **Step 6: Add the compact expansion card**

Show one exact authority diff with “Approve once” and “Deny.” Both actions perform begin/finish passkey ceremonies. Disable the card when stale, expired, terminal, or resolved. Append the decision reference and resulting upstream mission version to the timeline without rendering raw arguments.

- [ ] **Step 7: Run expansion suites**

Run: `go test -race ./internal/expansion ./internal/httpapi ./internal/missionpass ./internal/reconcile ./internal/store -count=1 && pnpm --dir web test -- ExpansionCard`

Expected: mutation, replay, stale-version, and reconciliation tests pass; approval never exceeds the exact request and never changes `DraftVersion`.

- [ ] **Step 8: Commit**

```bash
git add internal/expansion internal/httpapi internal/identity internal/missionpass internal/reconcile internal/coreapi internal/store openapi web/src
git commit -m "feat: decide exact one-use authority expansions"
```

### Task 12: Verify receipts locally and publish one privacy-safe GitHub check automatically

**Files:**
- Modify: `contracts/authscope-signing-keys.json`
- Modify: `internal/trust/keys.go`, `internal/trust/keys_test.go`
- Create: `internal/receipt/verify.go`, `internal/receipt/verify_test.go`
- Create: `internal/receipt/service.go`, `internal/receipt/service_test.go`
- Create: `internal/receipt/filter.go`, `internal/receipt/filter_test.go`
- Create: `internal/httpapi/receipt_handlers.go`, `internal/httpapi/receipt_handlers_test.go`
- Modify: `internal/httpapi/server.go`, `internal/httpapi/server_test.go`
- Create: `web/src/features/mission/ReceiptView.tsx`, `web/src/features/mission/ReceiptView.test.tsx`
- Modify: `internal/coreapi/compatibility.go`, `internal/coreapi/types.go`
- Modify: `internal/missionpass/events.go`
- Modify: `internal/reconcile/worker.go`, `internal/reconcile/worker_test.go`
- Modify: `internal/store/store.go`, `internal/store/sqlite.go`
- Modify: `openapi/ope-v1.yaml`, `web/src/shared/api/generated.ts`
- Modify: `scripts/verify-contract.sh`

**Interfaces:**
- Produces: `receipt.Verifier.Verify`, `receipt.Service.Get`, and the worker-only `receipt.Service.PublishVerifiedCheck` method; there is no local check-publication HTTP endpoint.
- Produces: `GET /api/v1/mission-passes/{id}/receipt` for the authenticated privacy-filtered private view.
- Produces: automatic receipt reconciliation and check publication owned by `reconcile.Worker`.
- Consumes: `Authority.GetReceipt`, `GetSigningKeys`, and `PublishGitHubCheck`; Task 9's pinned signing-root fingerprint and authenticated signing-key history through `internal/trust`.

```go
type SignedReceiptEnvelope struct {
    Algorithm string          `json:"alg"`
    KeyID     string          `json:"kid"`
    Payload   json.RawMessage `json:"payload"`
    Signature string          `json:"signature"`
}

type ReceiptView struct {
    Verification               string
    ReceiptDigest              string
    Outcome                    string
    MissionRef                 string
    AuthScopeMissionVersions   []int64
    ExpansionDecisionRefs      []string
    RepositoryID               int64
    IssueNumber                int64
    Branch                     string
    PullRequestNumber          int64
    HeadSHA                    string
    Checks                     []CheckSummary
    StartedAt                  time.Time
    FinishedAt                 time.Time
    AggregateCostMicros        int64
    HistoricalEnforcement      []EnforcementSummary
}
```

- [ ] **Step 1: Write failing cryptographic, privacy, timing, and publication tests**

Verify a valid Ed25519 fixture locally, then mutate every signed field, signature byte, algorithm, key ID, canonical payload byte, key-validity time, mission version, expansion history, repository/issue/run identifier, branch, PR, head SHA, outcome, and historical enforcement value; each alteration must fail. Test unknown, revoked, not-yet-valid, and improperly rotated keys. Seed secrets, issue bodies, acceptance evidence, test names, prompts, patches, transcripts, exception details, budgets, private URLs, and email addresses and assert they appear in neither the minimal check nor an unauthenticated response; richer evidence may appear only in the authenticated private view. Deliver duplicate `receipt_ready` events and publication timeouts; assert one check mutation and continued reconciliation after terminal mission state until publication is settled or disputed. With a fake clock, make the receipt available after upstream completion and require verified projection plus check publication within sixty seconds.

- [ ] **Step 2: Run the focused tests and verify failure**

Run: `go test -race ./internal/receipt ./internal/reconcile ./internal/httpapi -count=1`

Expected: compilation fails because the local verifier, fixed receipt projection, and automatic publication path do not exist.

- [ ] **Step 3: Pin and verify signing-key history**

Use Task 9's locked AuthScope signing-root fingerprint and initial key history. `verify-contract.sh` verifies the file digest before tests or startup. Accept only Ed25519 and exact canonical payload bytes. A refreshed history is accepted only when its rotation statement chains to the pinned root and covers the receipt signing time. Local verification checks signature, key status and validity, payload schema, mission/run/source identifiers, every mission version and expansion decision, head SHA, timestamps, and historical enforcement evidence. OPE never asks AuthScope merely to assert that its own receipt is valid.

- [ ] **Step 4: Create a fixed private receipt projection**

Construct `ReceiptView` field by field only after local verification. Never deserialize the upstream envelope directly into an API response. Keep the authenticated founder view private. Derive safe GitHub links from the verified binding plus numeric identifiers; do not expose issue body, logs, patches, transcript, or upstream private details URL.

- [ ] **Step 5: Publish the GitHub check automatically and idempotently**

When the worker observes `receipt_ready` or a run enters `outcome_pending`, fetch and verify the receipt, transition to `completed` or `failed`, and immediately call `PublishGitHubCheck`. Use an idempotency key derived from workspace, receipt digest, repository ID, PR number, and head SHA. The fixed check payload contains only outcome, signed historical enforcement status, and a receipt-digest prefix. Acceptance evidence, tests, exceptions, budgets, source details, and the full receipt remain in the authenticated private view. On timeout, reconcile the original publication; never create a second check. Private receipt rendering does not wait for publication settlement, and the worker continues the pending publication after terminal lifecycle state until it is settled or disputed.

- [ ] **Step 6: Add the receipt view**

Show pending, verified-success, verified-failure, disputed, publication-pending, and unverifiable states distinctly. There is no manual publish button and no public share route. An invalid receipt leaves the pass in `outcome_pending` and blocks completion language.

- [ ] **Step 7: Run receipt and worker suites**

Run: `go test -race ./internal/receipt ./internal/reconcile ./internal/httpapi ./internal/missionpass -count=1 && pnpm --dir web test -- ReceiptView`

Expected: tamper, key-history, privacy, duplicate-publication, timeout-reconciliation, and sixty-second fake-clock tests pass; only a locally verified receipt sets a terminal outcome.

- [ ] **Step 8: Commit**

```bash
git add contracts internal/receipt internal/reconcile internal/httpapi internal/missionpass internal/coreapi internal/store openapi scripts/verify-contract.sh web/src
git commit -m "feat: verify receipts and publish GitHub checks"
```

### Task 13: Complete the three-screen product and prove the contract with fakes

**Files:**
- Create: `web/src/features/connect/ConnectPage.tsx`, `web/src/features/connect/ConnectPage.test.tsx`
- Create: `web/src/features/authorize/AuthorizePage.tsx`, `web/src/features/authorize/AuthorizePage.test.tsx`
- Create: `web/src/features/mission/MissionPage.tsx`, `web/src/features/mission/MissionPage.test.tsx`
- Create: `web/src/shared/components/EnforcementBadge.tsx`, `web/src/shared/components/ProblemPanel.tsx`
- Create: `test/e2e/fake_authscope.go`, `test/e2e/fake_authscope_test.go`
- Create: `test/e2e/fake_gateway.go`, `test/e2e/fake_gateway_test.go`
- Create: `test/e2e/ope.spec.ts`, `test/e2e/workspace_matrix_test.go`
- Create: `test/e2e/two_instance.spec.ts`
- Create: `scripts/run-e2e.sh`
- Modify: `web/src/App.tsx`, `web/src/App.test.tsx`
- Modify: `internal/httpapi/server.go`, `internal/httpapi/server_test.go`
- Modify: `web/src/shared/api/client.ts`, `web/src/shared/api/client.test.ts`
- Modify: `openapi/ope-v1.yaml`, `web/src/shared/api/generated.ts`
- Modify: `Makefile`, `.github/workflows/ci.yml`

**Interfaces:**
- Produces: exactly three navigable product screens: Connect, Authorize, and Mission.
- Produces: fakes validated against `contracts/authscope-v1.yaml` and the exact DTO fixtures used by `coreapi.Client`.
- Consumes: all Task 1–12 browser and API slices.

- [ ] **Step 1: Write failing full-journey, cardinality, recovery, and workspace-matrix tests**

Create Playwright journeys for happy path, expansion approval, expansion denial, web revocation, CLI authorization, stale issue/base/workflow posture, incompatible AuthScope, failed run, invalid receipt, and reconnect after event loss. For one pass, make a fake governed agent attempt a second repository, second issue, second branch, second run, and second PR; require exact upstream denials and unchanged OPE state. Add direct default-branch, protected-path, workflow-file, merge, release, deployment, issue-close, and post-revocation attempts. Seed foreign-workspace connection, issue, pass, approval, CLI authorization, launch, event, expansion, revocation, and receipt identifiers and require `404` on every applicable route; caller-supplied workspace headers cannot override the instance binding. Start two instances with distinct configured HTTPS hostnames, origins, instance IDs, and `__Host-` cookie names in one browser profile; prove each login works on its own origin, neither cookie is sent or accepted by the other instance, and copying either session or CSRF value fails. For every business mutation route, replaying the same idempotency key and canonical body must return the original result, while reusing the key with changed content must return `409`. WebAuthn and bootstrap transitions, PKCE browser-approval transitions, and the GitHub callback reject replay through atomically consumed one-use state. CLI launch/revoke token exchanges return only the original result for an identical consumed code, verifier, and canonical body; changed content fails. GitHub begin and finish remain idempotent business mutations.

- [ ] **Step 2: Run e2e tests and verify failure**

Run: `scripts/run-e2e.sh`

Expected: tests fail because the final page composition and contract-faithful fake services do not exist.

- [ ] **Step 3: Build contract-faithful fakes**

Generate or validate fake request/response fixtures from the vendored upstream OpenAPI and capability manifest. The fake derives the workspace workload identity from authenticated transport, requires its registered `decision_attestor` role, and independently verifies every decision attestation's signature, workspace, audience, decision and invocation digests, nonce, freshness, and replay state. It also enforces request schemas, the opaque GitHub begin/callback/finish handoff, proposal and exact invocation binding, mission versions, one proposal/mission/run/branch/PR cardinality, idempotency and reconciliation, signed events, unknown-event incompatibility, signed launch envelopes, signed receipts, exact expansion deltas, bulk workspace containment, authoritative active-mission listing, revocation, and minimal check publication. A test fails if the fake exposes an operation or field absent from the pinned contract.

- [ ] **Step 4: Compose exactly three screens**

Connect contains bootstrap/login, immutable instance workspace, compatibility, GitHub binding, and issue selection entry. Authorize contains issue preview, compact proposal, two editable limits, exact digest approval, and CLI browser handoff. Mission contains state, remaining limits, safe timeline, one expansion, revoke, PR link, receipt, and automatic-check status. Deep links restore server state. No dashboard, policy console, task queue, chat, or fourth workflow screen is added.

- [ ] **Step 5: Add honest enforcement and recovery states**

Render only `observed`, `checked`, or `enforced` labels received in authenticated evidence. Name the blocked condition and safe recovery action for every typed error. Never suggest a PAT, direct agent launch, bypass, duplicate mutation, or retry of an ambiguous request. Mark event and operation projections stale until the worker reconciles them.

- [ ] **Step 6: Enforce the single-workspace route matrix centrally**

Derive workspace exclusively from the immutable instance record. When a founder session or one-use bootstrap, GitHub, or CLI record is present, require its stored workspace to match; caller-supplied workspace headers cannot select or override one. Route helpers always scope storage and upstream calls with the immutable workspace. Unknown and foreign identifiers return the same `404`; no response reveals whether another workspace owns an object. Generate and test an explicit route-security matrix: readiness-only public GETs; exact-Origin bootstrap/login ceremonies; founder-session plus Origin/CSRF browser mutations; state-bound GitHub callback; and loopback state/PKCE/code CLI launch and revoke exchanges. Apply it to bootstrap and authentication, GitHub handoff begin/callback/finish, connection, issue, proposal, approval begin/finish/status, CLI launch authorization/exchange, CLI revocation registration/exchange, pass, event, revocation begin/finish, expansion begin/finish, and receipt routes. Assert the route registry has no local manual check-publication endpoint.

- [ ] **Step 7: Run browser and API journeys**

Run: `make verify && scripts/run-e2e.sh`

Expected: all fake contracts validate against the pin; three-screen journeys pass; every second-resource/run/PR action is denied; the cross-workspace matrix returns uniform `404`; browser storage contains no authority or credential material.

- [ ] **Step 8: Commit**

```bash
git add .github Makefile internal/httpapi openapi scripts/run-e2e.sh test/e2e web
git commit -m "feat: complete the three-screen OPE journey"
```

### Task 14: Package the bound instance, diagnose prerequisites, and implement offline recovery

**Files:**
- Create: `internal/cli/doctor.go`, `internal/cli/doctor_test.go`
- Create: `internal/recovery/service.go`, `internal/recovery/service_test.go`
- Create: `internal/cli/recover.go`, `internal/cli/recover_test.go`
- Create: `deploy/compose.yaml`, `deploy/README.md`
- Create: `Dockerfile`, `.dockerignore`
- Create: `docs/getting-started.md`, `docs/security-model.md`
- Modify: `cmd/authscope-ope/main.go`
- Modify: `internal/authn/bootstrap.go`
- Modify: `internal/config/config.go`, `internal/config/config_test.go`
- Modify: `internal/store/store.go`, `internal/store/sqlite.go`
- Modify: `Makefile`

**Interfaces:**
- Produces: one binary with `serve`, `doctor`, `run`, `revoke`, and `recover`.
- Produces: `recovery.Service.ResetOffline`.
- Consumes: Task 2's durable immutable instance record and Task 4's attached workload-identity digest and `identity.DecisionAttestor`.
- Consumes: `coreapi.Authority.ContainWorkspace`, `coreapi.Authority.ListActiveMissions`, the contract pin, local data store, verified AuthScope workspace identity, and the installed `authscope-agent-run`.

```go
type RecoveryRequest struct {
    WorkspaceID       string
    RecoveryKey       []byte
    ConfirmWorkspace  string
}

type RecoveryResult struct {
    RecoveryEventID      string
    RevokedSessionCount  int
    ContainedMissionCount int
    BootstrapExpiresAt   time.Time
}
```

- [ ] **Step 1: Write failing packaging, doctor, and recovery tests**

Reject workspace rebinding, permissive or symlinked data/signer-reference files, incompatible contract, wrong workload workspace or identity digest, unsafe local origin, clock skew over thirty seconds, unavailable database, unsupported runner, writable/symlinked runner, missing enforced isolation, unsafe GitHub posture, and server startup during an offline reset. Test wrong/replayed recovery key, wrong typed workspace confirmation, a signing identity without `decision_attestor`, altered containment workspace/audience/digest/authentication method/proof digest/nonce/freshness/signature, replayed containment attestation, containment timeout, concurrent reset, and crashes before containment, after containment, after the empty active-list result, and during local reset. Seed an active mission known only to AuthScope and require bulk containment to cover it. Prove local session, CLI-code, passkey, bootstrap, and recovery-key state remains unchanged until `ListActiveMissions` authoritatively returns empty; then prove invalidation, bootstrap re-enable, and durable recovery-event creation.

- [ ] **Step 2: Run the focused tests and verify failure**

Run: `go test -race ./internal/cli ./internal/recovery ./internal/config ./internal/store -run 'TestDoctor|TestRecovery|TestInstanceBinding' -count=1`

Expected: compilation fails because doctor, recovery service, and packaging validation do not exist.

- [ ] **Step 3: Validate the already-bound instance**

Load the owner-only immutable instance record created in Task 2 and require the workload-identity digest attached in Task 4. Validate configured workspace, instance ID, hostname, origin, RP ID, cookie name, and the transport-authenticated identity digest against that record without changing it. Task 14 creates or attaches no instance fields. There is no workspace picker or switch operation. Moving to another workspace requires a separate OPE instance, unique hostname/origin/cookie namespace, and data directory.

- [ ] **Step 4: Implement offline recovery**

`authscope-ope recover --data-dir <absolute-path>` acquires an exclusive database lock and refuses to run while the server owns it. Read the offline recovery key from the controlling terminal with echo disabled, never from argv, environment, or configuration, and require an exact typed workspace ID. Verify the offline recovery proof, generate a fresh nonce, canonicalize the fixed workspace-wide containment decision, persist its recovery intent, and sign a short-lived one-use attestation with purpose `offline_recovery_contain`, audience `authscope:workspace-containment`, method `offline_recovery_key`, and an algorithm-tagged digest of the verified local recovery record that reveals no recovery-key material. Call `ContainWorkspace` first with a stable idempotency key so AuthScope bulk-contains every active mission in the workspace, including missions absent from the OPE database. Reconcile an ambiguous response by that key. Only after acknowledged containment, poll the authoritative `ListActiveMissions` view until it returns an authenticated empty list; any nonempty, stale, unavailable, or unverifiable result leaves authentication and recovery methods unchanged and the intent pending. After the empty result is durably recorded, revoke all web sessions, invalidate all CLI authorization codes, launch-delivery metadata, and in-memory envelope caches, delete passkey public credentials, rotate local session/CSRF seeds, record a non-secret recovery event, and issue one ten-minute bootstrap code to the controlling terminal. The original recovery key is consumed in the same local transaction; enrollment creates a replacement recovery method.

- [ ] **Step 5: Add doctor and package the local stack**

`doctor` validates the existing Task 2 instance binding and Task 4 workload-identity attachment; it never creates or rewrites either. It verifies immutable core version/OpenAPI/key-history digests, the transport-authenticated workspace-bound identity and `decision_attestor` role, live compatibility, clock skew, database ownership, configured Host/Origin/RP ID/cookie name, passkey secure-context requirements, GitHub binding and workflow posture, supported kit, runner path/ownership/version, enforced isolation, and event/check worker health. Build web assets into the Go binary. The container runs non-root with read-only root filesystem, a dedicated owner-only data volume, loopback-only port, health checks, and managed non-exportable signer references; the host CLI and governed runner remain explicit prerequisites.

- [ ] **Step 6: Document first use and containment**

The getting-started guide reaches a proposal without YAML and states that one instance binds one workspace. The security model names browser, OPE, AuthScope, runner, agent, gateway, and GitHub trust boundaries; explains anonymous-FD credential delivery and automatic checks; and states that evidence proves authorization and execution facts, not business wisdom, legality, or compliance.

- [ ] **Step 7: Run packaging and recovery suites**

Run: `make verify && go test -race ./internal/recovery ./internal/cli ./internal/config ./internal/store -count=1`

Expected: the image and embedded binary build reproducibly; doctor reports each unsafe prerequisite; recovery completes only after bulk containment and an authoritative empty active-mission list, including an upstream-only orphan case, or leaves the existing authentication state intact.

- [ ] **Step 8: Commit**

```bash
git add .dockerignore Dockerfile Makefile cmd deploy docs internal/authn internal/cli internal/config internal/recovery internal/store
git commit -m "feat: package and recover a workspace-bound OPE instance"
```

### Task 15: Add privacy-limited telemetry and credential-leak release scans

**Files:**
- Create: `internal/telemetry/events.go`, `internal/telemetry/events_test.go`
- Create: `internal/telemetry/sink.go`, `internal/telemetry/sink_test.go`
- Create: `test/security/credential_leak_test.go`
- Create: `test/security/privacy_projection_test.go`
- Create: `scripts/check-secrets.sh`, `scripts/check-runtime-leaks.sh`
- Modify: `internal/httpapi/server.go`
- Modify: `internal/reconcile/worker.go`
- Modify: `internal/cli/run.go`
- Modify: `web/src/features/connect/ConnectPage.tsx`, `web/src/features/connect/ConnectPage.test.tsx`
- Modify: `Makefile`, `.github/workflows/ci.yml`

**Interfaces:**
- Produces: `telemetry.Sink.Record(context.Context, telemetry.Event) error`.
- Produces: `make privacy-check` and `make credential-check`.
- Consumes: opaque identifiers and durations from prior tasks; seeded canary credentials and private content from security fixtures.

```go
type Event struct {
    Name             string
    DurationMillis   int64
    InstallationID   string
    PassID           string
    RunID            string
    ErrorCode        string
    EnforcementLevel string
    InterventionCount int
    OutcomeClass     string
}
```

- [ ] **Step 1: Write failing schema, consent, and leak tests**

Reflect over every telemetry field and reject repository, issue, branch, PR, objective, criteria, prompt, source, patch, transcript, token, secret, credential, email, URL, receipt payload, or free-form message fields. Assert telemetry is off by default in development and before explicit release-mode configuration. Seed distinct canaries for the workload signer/key handle, signed decision attestation, offline recovery key, opaque AuthScope GitHub binding code, passkey assertion, CLI code/verifier/private key, sealed-envelope plaintext, and runtime credential, plus private provider and issue/event/receipt content. Exercise AuthScope headers, GitHub callback queries, SQLite/WAL/SHM, HTTP errors, logs, DOM, browser storage, process listings, child environment, crash output, telemetry, and the public check payload; each secret may exist only in its explicitly bounded in-memory, terminal-input, signer, or anonymous-FD channel.

- [ ] **Step 2: Run the focused tests and verify failure**

Run: `go test -race ./internal/telemetry ./test/security -count=1`

Expected: compilation fails because the telemetry sink and full leak harness do not exist.

- [ ] **Step 3: Implement an allowlisted telemetry sink**

Accept only the fixed `Event` struct and fixed name/error/outcome enums. Pseudonymize installation ID with an instance-local telemetry salt; keep workspace, repository, issue content, and receipt data out of events. Record funnel timing for connect, issue selected, proposal ready, approved, CLI authorized, run prepared, expansion decided, receipt verified, and check published. The Connect screen visibly exposes the configured telemetry state; development default remains off.

- [ ] **Step 4: Scan every persistence and process surface**

`check-secrets.sh` scans tracked files, built assets, logs, test output, SQLite database/WAL/SHM, Compose configuration, and captured HTTP/browser artifacts. `check-runtime-leaks.sh` launches the CLI and fake runner, captures argv, environment, inherited descriptors, process errors, and crash output, and verifies that the runtime credential exists only on the designated anonymous descriptor before the runner consumes it. It also proves the configured signer remains non-exportable and no key bytes enter the OPE process. Both scripts fail on any canary outside its explicit one-time channel.

- [ ] **Step 5: Test privacy projections end to end**

Run the event and receipt projectors with unknown future fields and sensitive content, then inspect SQLite, API JSON, rendered DOM, telemetry, and GitHub check payloads. For an authenticated unknown event type, discard the payload, keep the cursor unchanged, mark the projection incompatible and stale, and prove every business mutation remains blocked until a compatible parser and pinned contract are installed. Reject unknown fields on otherwise known event types. Verify that errors use fixed reason codes and contain no upstream response body, and that the public check contains only outcome, historical enforcement, and the configured receipt-digest prefix.

- [ ] **Step 6: Run privacy and credential gates**

Run: `make verify && make privacy-check && make credential-check`

Expected: telemetry schema/consent tests pass and every seeded canary is absent outside its single authorized in-memory or anonymous-FD hop.

- [ ] **Step 7: Commit**

```bash
git add .github Makefile internal/cli internal/httpapi internal/reconcile internal/telemetry scripts test/security web/src
git commit -m "feat: enforce OPE privacy and credential boundaries"
```

### Task 16: Prove the real pinned path and run the first-use release gate

**Files:**
- Create: `test/integration/real_authscope_test.go`
- Create: `test/integration/real_gateway_test.go`
- Create: `test/integration/real_runtime_test.go`
- Create: `test/integration/real_github_test.go`
- Create: `test/integration/testdata/mission-issue.md`
- Create: `scripts/run-real-integration.sh`
- Create: `scripts/run-usability-gate.sh`
- Create: `docs/release-checklist.md`, `docs/release-evidence.md`
- Modify: `Makefile`, `.github/workflows/ci.yml`
- Modify: `README.md`

**Interfaces:**
- Produces: `make integration-real`, `make usability-gate`, and `make verify-release`.
- Produces: release evidence tied to immutable OPE, AuthScope, gateway, runtime, OpenAPI, signing-key-history, and disposable GitHub repository revisions.
- Consumes: the actual pinned AuthScope service, enforcing gateway, supported `authscope-agent-run`, coding-agent kit, and a disposable GitHub installation/repository.

- [ ] **Step 1: Write failing real-integration assertions**

Against a disposable private repository, require OPE `POST begin`, AuthScope-hosted GitHub installation, OPE `GET callback`, and same-origin authenticated `POST finish`; capture every OPE request and prove no GitHub OAuth code or token reaches it. Continue through trusted issue snapshot, shaped proposal, local WebAuthn verification, an exact signed approval attestation, one CLI exchange, one `PrepareLaunch`, governed edits, one mission branch, one PR, local receipt verification, and one automatically published minimal GitHub check. Bind the fixed agent-kit ID/version and exact proposal runner-argument array into one invocation digest and verify byte-for-byte equality through proposal, CLI create, passkey decision, token exchange, and sealed launch envelope; no interface accepts a user command. For approval, launch, revocation, expansion, and recovery containment, require AuthScope to reject an identity without `decision_attestor`, a changed workspace/audience/decision or invocation digest/authentication method or proof digest/nonce/freshness/signature, and an attestation replay. Attempt a second repository, issue, branch, run, and PR under the pass. Also attempt default-branch and pre-existing-branch writes, protected/workflow paths, force push, merge, tag, release, deployment, issue closure, unsupported GitHub operations, stale source/base/workflow posture, expired pass, altered proposal or expansion digest, and mutations after revocation. Deliver an authenticated unknown event type and require discarded payload, unchanged cursor, incompatible/stale projection, and blocked mutations until a compatible contract/parser is installed. Prove the public check contains only outcome, historical enforcement, and a receipt-digest prefix while richer evidence remains authenticated and private.

- [ ] **Step 2: Run the real suite and verify the expected pre-release failure**

Run: `scripts/run-real-integration.sh --preflight`

Expected: the script exits nonzero and names every absent or mismatched real prerequisite; it never substitutes a fake, skips a required operation, or treats commit `76fe961` as a release version.

- [ ] **Step 3: Prove non-bypassable runtime isolation**

Launch the real supported kit with seeded ambient GitHub, Git credential-helper, SSH-agent, cloud, model-provider, proxy, Docker-socket, shell-startup, home-directory, and external-network escape fixtures. Require the runner to expose none of them and to reach GitHub mutations only through the enforcing gateway. Include a hostile pre-existing `push`, `pull_request`, and `pull_request_target` workflow fixture; connection or launch must fail unless AuthScope proves agent-controlled content cannot reach secrets, write tokens, spending, environments, or deployments.

- [ ] **Step 4: Prove timing, concurrency, and isolation gates**

Run serial and concurrent launch, expansion, revoke, containment, and check-publication requests and require one result for each idempotency key. Measure acknowledged revocation to denial of the next governed mutation at no more than ten seconds. Measure upstream run completion to locally verified receipt and automatic GitHub check at no more than sixty seconds, including a terminal mission whose publication remains pending and is reconciled to settled or disputed without founder action. Seed an AuthScope-active mission with no OPE row, run offline recovery, and require `ContainWorkspace` to cover it before an authenticated `ListActiveMissions` returns empty; local authentication must remain intact for every nonempty or uncertain result. Start a second instance bound to another workspace, hostname, origin, instance ID, and `__Host-` cookie name. In one browser profile prove cookies and CSRF state do not cross hosts and either instance rejects a copied cookie, then prove that connection, mission, run, event, expansion, revocation, receipt, and idempotency identifiers cannot cross instances.

- [ ] **Step 5: Require immutable release dependencies**

`run-real-integration.sh` compares the running AuthScope version, OpenAPI digest, capability manifest, gateway build, runtime build, fixed agent-kit version, and signing-key-history digest with release inputs. It requires implemented GitHub handoff, decision-attestor verification, active-mission listing, bulk workspace containment, idempotency reconciliation, and gateway-enforced runtime operations from that exact immutable release. A development commit pin, including `76fe961`, dirty dependency, missing non-exportable workspace-bound identity or `decision_attestor` role, observed/checked isolation, or unverified key history blocks release. Record exact revisions and results in `docs/release-evidence.md`.

- [ ] **Step 6: Run the first-use usability gate**

Conduct eight first-time sessions. Start the clock at the first product-controlled interaction and stop when the UI displays the confirmed `RunID`; subtract only time on GitHub-hosted authentication pages. Include bootstrap, recovery-method enrollment, immutable workspace verification, repository/issue selection, proposal review, passkey approval, browser CLI authorization, and exchange. Release requires a median below five minutes, at most three founder decision views, eight successful governed launches, and no credential or workspace-boundary failure. Record only durations, fixed error codes, and outcome.

- [ ] **Step 7: Run the release command**

Run: `make verify-release`

Expected: contract, race, frontend, fake e2e, packaging, privacy, credential, exact-attestation, invocation-binding, GitHub-handoff, recovery-containment, two-instance browser isolation, minimal-check, real AuthScope/gateway/runtime/GitHub, timing, cardinality, cross-workspace, and usability gates all pass. The product remains labeled beta until the pinned upstream release and complete path receive independent security validation.

- [ ] **Step 8: Commit**

```bash
git add .github Makefile README.md docs scripts/run-real-integration.sh scripts/run-usability-gate.sh test/integration
git commit -m "test: prove the real OPE Mission Pass release path"
```

---

## Delivery order and release gates

| Milestone | Tasks | Exit gate |
| --- | --- | --- |
| Contract and safe foundation | 1–5 | The actual upstream operation map is locked; one instance is bound to one workspace; authentication, storage, GitHub source, workflow posture, and generated-client checks pass. |
| Exact founder intent | 6–7 | AuthScope shapes and creates the proposal before review; the founder approves its exact digest; approval creates one mission and no launch artifact. |
| One governed run | 8–10 | One-use browser PKCE authorizes the CLI; one exchange creates exactly one run; the signed sealed envelope reaches the governed runner through an anonymous FD; fixed events, reconciliation, and revocation work. |
| Bounded exception and evidence | 11–12 | Expansion begin/finish cannot exceed the exact delta; local cryptographic receipt verification drives one automatic privacy-safe GitHub check. |
| Complete beta product | 13–15 | Exactly three screens, contract-faithful fake journeys, full workspace-route isolation, offline recovery, packaging, privacy telemetry, and credential-leak gates pass. |
| Release proof | 16 | The pinned real AuthScope, gateway, runtime, agent kit, and disposable GitHub path pass denial, timing, cardinality, isolation, receipt, and first-use usability gates. |

Do not begin support, sales, marketing, finance, scheduling, team administration, billing, public receipt sharing, agent orchestration, workspace switching, agent selection, automatic merge, deployment, or custom policy editing in this plan. Open a separate design and implementation plan for each later edition after beta data shows repeat GitHub Mission Pass usage.
