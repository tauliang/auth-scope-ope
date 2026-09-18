# Release evidence

Recorded 2026-09-18 for the OPE Mission Pass release path (Task 16).
This document ties the release gates to the immutable revisions they
ran against. The Task 16 commit SHA is reported in the push report
delivered with this task; the product code it adds to is the Task 15
head below (Task 16 adds only tests, scripts, and docs, no product
code changes).

## Pinned revisions

| Artifact | Pinned revision |
|---|---|
| OPE | `tauliang/auth-scope-ope@feat/ope`, Task 15 head `ee7676b39b79f2d835b155857e724253cc6a2b2f` plus the Task 16 commit (`test: prove the real OPE Mission Pass release path`) |
| AuthScope | `tauliang/auth-scope@ope-v1.0.0` (immutable release; GitHub release 391187606) |
| OpenAPI | `tauliang/auth-scope@ope-v1.0.0` `openapi/auth-scope-v1.yaml`, SHA-256 `9516e098c5ee9196b6bc73f3633123d173d4249fbc0a5063843924d53b43af76` |
| Capability manifest | `contracts/ope-required-capabilities.json`, 36 required operations, satisfied by the pinned release per `make contract-ready` |
| Signing-key history | SHA-256 `82ad34a6edd7223336b1ed15982a37bd1cb39c2f6f4776f1cb8e65007b08cb09` |
| Gateway / runtime / agent kit | pinned at release time by the operator; `scripts/run-real-integration.sh` records the runtime build digest and the fixed `id@version` kit in the run report |

Caveat, recorded honestly: the vendored signing-key history is still
the locally generated test root (`contracts/authscope.lock.json`:
"TEST PIN ONLY"). The production AuthScope root pin must replace
`contracts/authscope-signing-keys.json` before release, and
`OPE_SIGNING_KEYS_DIGEST` must then be the production digest. The
preflight compares the served key history against the operator's
`OPE_SIGNING_KEYS_DIGEST`, so a test pin can never silently pass as
production.

Commit `76fe961` is the design and contract-audit baseline only. It is
not an immutable release, and the preflight rejects it (and any raw
commit pin) explicitly.

## Gate results observed in this environment

The sandbox where this evidence was recorded has no real AuthScope
service, gateway, runtime, agent kit, or disposable GitHub
repository. The gates below report what was actually observed here.

| Gate | Result | Evidence |
|---|---|---|
| contract (`make contract-ready`) | PASS | `scripts/verify-contract.sh` exits 0 against the vendored release contract |
| go tests (`go test -race ./... -count=1`) | PASS | full module green under the race detector, including the new `test/integration` package (all real tests skip with named prerequisites) |
| go vet | PASS | clean |
| web client check | PASS | `node scripts/generate-web-client.mjs --check` |
| frontend (lint, typecheck, test:coverage, build) | PASS | pnpm gates green, coverage thresholds met |
| e2e (`make e2e`) | PASS | fake-based journeys and two-instance specs; browser specs skip cleanly without a browser executable |
| packaging | PASS | release binary builds with `-tags embedweb` |
| privacy (`make privacy-check`) | PASS | no seeded canary on any durable surface |
| credential (`make credential-check`) | PASS | runtime credentials reach the runner only on the anonymous FD |
| real integration (`scripts/run-real-integration.sh --preflight`) | BLOCKED | exits nonzero and names every absent prerequisite: `AUTH_SCOPE_URL`, `OPE_GATEWAY_URL`, `OPE_RUNTIME_BIN`, `OPE_AGENT_KIT`, `OPE_GITHUB_REPO`, `OPE_GITHUB_INSTALLATION_ID`, `OPE_SIGNING_KEYS_DIGEST`, `OPE_AUTHSCOPE_VERSION`, `OPE_WORKSPACE_ID`, `OPE_HOSTNAME`, `OPE_ORIGIN`, `OPE_WORKLOAD_SIGNER_REF`, `OPE_URL`, `OPE_REAL_MANIFEST`. No fake substituted, no operation skipped, no dev pin accepted. |
| usability (`scripts/run-usability-gate.sh`) | BLOCKED | fails closed: eight real first-time sessions need a real browser and the real backend; `--plan` prints the procedure and `--results` verifies recorded sessions |
| `make verify-release` | BLOCKED (not failed) | all runnable gates PASS; the two real gates report BLOCKED with the prerequisites named |

## What BLOCKED means

BLOCKED is not a pass and not a failure. It means the gate is wired,
fails closed, and is waiting on the real prerequisites listed in
`docs/release-checklist.md`. The release is not verified until
`make verify-release` reports PASS on every gate in an environment
where the pinned real backend is present.
