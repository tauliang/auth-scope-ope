# OPE Mission Pass release checklist

This is the human checklist for cutting an OPE Edition release. Every
gate must pass in order; the release is not verified until
`make verify-release` reports PASS on every gate. The product stays
labeled beta until the pinned upstream release and the complete path
receive independent security validation.

## 1. Prerequisites (all required before any gate runs)

- [ ] The pinned immutable AuthScope release `tauliang/auth-scope@ope-v1.0.0`
      is deployed and reachable over https. A development commit pin
      (including `76fe961`, the design and contract-audit baseline) is
      never a release.
- [ ] The enforcing AuthScope gateway is deployed at `OPE_GATEWAY_URL`.
- [ ] The supported `authscope-agent-run` runtime binary is installed at
      `OPE_RUNTIME_BIN`, with its build digest recorded.
- [ ] The fixed coding-agent kit is pinned as `id@version` in
      `OPE_AGENT_KIT` (never `latest`).
- [ ] A disposable private GitHub repository exists at
      `OPE_GITHUB_REPO` (`owner/name`), with the fixture issue from
      `test/integration/testdata/mission-issue.md` applied verbatim.
- [ ] An AuthScope-hosted GitHub installation covers the disposable
      repository (`OPE_GITHUB_INSTALLATION_ID`).
- [ ] The signing-key history served at
      `/.well-known/auth-scope-signing-keys` digests to
      `OPE_SIGNING_KEYS_DIGEST`, matching the production root pin (see
      the known questions below).
- [ ] A non-exportable workload signer reference is configured as
      `OPE_WORKLOAD_SIGNER_REF` (an HSM or TEE handle, never key
      material). See the release blocker below.
- [ ] The OPE instance under test is the release build (`OPE_URL`),
      bound to one workspace, hostname, origin, and instance id.
- [ ] The operator has performed the human ceremonies once (passkey
      approval, browser CLI authorization, GitHub installation
      click-through) and recorded the artifact manifest named by
      `OPE_REAL_MANIFEST`.

## 2. Gate order

Run in this order; stop at the first red gate.

1. `make contract-ready`: the vendored release contract satisfies the
   OPE capability manifest.
2. `GOSUMDB=off go test -race ./... -count=1` and
   `GOSUMDB=off go vet ./...`: the full Go suite under the race
   detector, then vet.
3. `node scripts/generate-web-client.mjs --check`: the generated web
   client matches `openapi/ope-v1.yaml`.
4. Frontend: `pnpm --dir web lint`, `typecheck`, `test:coverage`
   (thresholds), `build`.
5. `make e2e`: the fake-based journeys and the two-instance browser
   specs (UI specs skip cleanly without a browser; API specs run).
6. Packaging: the release binary builds with `-tags embedweb` and the
   web bundle embedded.
7. `make privacy-check` and `make credential-check`: no seeded secret
   canary on any durable surface; runtime credentials reach the runner
   only on the anonymous file descriptor.
8. `scripts/run-real-integration.sh --preflight`, then the full run:
   the pinned real AuthScope, gateway, runtime, kit, and disposable
   GitHub path pass the denial, timing, cardinality, isolation,
   receipt, and check gates. The preflight fails closed and names each
   absent prerequisite; it never substitutes a fake.
9. `scripts/run-usability-gate.sh --results <csv>`: eight first-time
   sessions: median under five minutes, at most three decision views,
   eight successful governed launches, no credential or
   workspace-boundary failure.
10. `make verify-release`: the aggregator. Every gate above must PASS;
    BLOCKED is not a pass.

## 3. Known contract questions for the upstream

These are open with the AuthScope maintainers and must be resolved or
explicitly accepted before release.

### Receipt envelope field names: `alg`/`kid` vs `algorithm`/`key_id`

The vendored contract (`contracts/authscope-v1.yaml`) names signing
material the JWK way: the discovery document's `artifact_signing`
object and `DiscoveryVerificationKey` use `alg` and `kid`, and the
`SignedReceipt` schema uses `key_id` for the signing key reference.
OPE's local `coreapi.SignedReceiptEnvelope` uses the JSON names
`algorithm` and `key_id`.

The mapping OPE assumes today:

- local `algorithm` (accepted value `"Ed25519"`) maps to the upstream
  JWK `alg` for the receipt signing key;
- local envelope and payload `key_id` map to the upstream `kid`.

The pinned release must confirm the exact wire names of the receipt
envelope before release. If the release serves `alg`/`kid` on the
envelope itself, OPE's verifier must translate before checking the
signature, and `internal/receipt` plus `internal/coreapi` need the
translation in one place with a test. Until the upstream confirms, this
is a release question, not a silent assumption.

### `resolveWorkloadSigner` release-mode gap: release blocker

`cmd/authscope-ope/main.go` resolves the workload signer for the
AuthScope transport and decision attestations. In release mode it fails
closed today: HSM/TEE-backed reference resolution is not implemented,
so any configured `OPE_WORKLOAD_SIGNER_REF` is unresolvable by this
build (`identity.ErrUnresolvableSigner`). Development with no reference
falls back to an ephemeral in-memory signer that is clearly marked
dev-only and must never reach release.

Do not release until HSM/TEE-backed reference resolution lands and
`OPE_WORKLOAD_SIGNER_REF` resolves to a non-exportable signer in
release mode. The real-integration preflight accepts the reference
only as a handle; it rejects anything that looks like literal key
material.

### `OPE_BIND_ADDR` compose concern

Inside the container the server should bind `0.0.0.0:8080` so the
published port is reachable. The compose or container runtime must
publish host-loopback-only (for example `127.0.0.1:8080:8080`), never
a public interface. Binding `0.0.0.0` inside the container is not
permission to expose the instance publicly; the loopback-only
publication is what keeps the browser origin and `__Host-` cookie
assumptions intact.

## 4. Sign-off

- [ ] `make verify-release` reports PASS on every gate.
- [ ] `docs/release-evidence.md` records the exact pinned revisions and
      the observed gate results.
- [ ] The three known questions above are resolved or explicitly
      accepted in writing by the release owner.
- [ ] The product is labeled beta everywhere it is named (README, UI
      footer, release notes): no production assurance is claimed until
      the pinned upstream release and the complete OPE path receive
      independent security validation.
- [ ] Release owner sign-off: name and date.
