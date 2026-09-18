# AuthScope OPE Edition (beta)

AuthScope OPE Edition is a founder-focused product layer for governing AI agents with the AuthScope mission-authority service. It helps a one-person company define a bounded mission once, let an agent act inside that boundary, resolve only meaningful exceptions, and receive verifiable evidence of the outcome.

The first release is deliberately narrow: one GitHub issue becomes one expiring Mission Pass, one governed coding-agent run, one pull request, and one verified receipt. AuthScope remains the authority and enforcement engine; this repository owns local founder authentication, exact signed decision attestations, onboarding, presentation, and workflow.

This product is labeled beta. It must not claim production assurance until the pinned upstream release and the complete OPE path receive independent security validation. See the release checklist for what that requires.

## The three screens

The whole product is three screens, and every path resolves to one of them:

- **Connect.** Bind the instance to one AuthScope workspace, connect a GitHub repository through the AuthScope-hosted installation, and pick the mission issue. The GitHub handoff never exposes OAuth codes or tokens to OPE.
- **Authorize.** Review the shaped proposal: the trusted issue snapshot, the exact plan, and the invocation digest that binds the fixed agent kit and runner arguments. Approve with a passkey, which mints an exact signed decision attestation. Approval creates the mission and nothing else.
- **Mission.** Watch the governed run, resolve expansion requests (each one an exact signed decision), revoke when needed, and receive the locally verified receipt. The automatically published GitHub check carries only the outcome, the historical enforcement status, and a receipt-digest prefix; the full evidence stays in the private founder view.

## Planning documents

- [OPE Edition v1 design](docs/superpowers/specs/2026-09-13-ope-edition-v1-design.md)
- [OPE Edition v1 implementation plan](docs/superpowers/plans/2026-09-13-ope-edition-v1.md)
- [Getting started](docs/getting-started.md)
- [Security model](docs/security-model.md)

## Release gates

A release is verified only when `make verify-release` reports PASS on every gate:

| Gate | Command |
|---|---|
| Contract | `make contract-ready` |
| Go tests (race) and vet | `go test -race ./...`, `go vet ./...` |
| Web client and frontend | generated-client check, `pnpm --dir web lint`, `typecheck`, `test:coverage`, `build` |
| Fake e2e | `make e2e` |
| Packaging | release binary with `-tags embedweb` |
| Privacy and credential | `make privacy-check`, `make credential-check` |
| Real integration | `make integration-real` (preflights first and fails closed) |
| Usability | `make usability-gate` |

The real-integration gate (`scripts/run-real-integration.sh`) drives the pinned real AuthScope release `tauliang/auth-scope@ope-v1.0.0`, the enforcing gateway, the supported runtime, the fixed agent kit, and a disposable GitHub repository. Its preflight names every absent prerequisite, never substitutes a fake, and never treats the audit baseline commit `76fe961` as a release. The usability gate needs eight real first-time sessions; it fails closed rather than simulating them. While the real prerequisites are absent, both gates report BLOCKED (not failed), and the release is not verified.

Release procedure, known upstream contract questions, and sign-off live in [docs/release-checklist.md](docs/release-checklist.md). The pinned revisions and observed gate results live in [docs/release-evidence.md](docs/release-evidence.md).

## Development

AuthScope commit `76fe961` is a design and contract-audit baseline only. Implementation is pinned to the immutable release in `contracts/authscope.lock.json`; `make contract-ready` enforces the pin.

```sh
export GOSUMDB=off   # the sandbox proxy blocks the Go module sum database
go test ./...        # Go toolchain: /home/hatch/workspace/tools/go/bin/go
make verify          # contract gate, Go suite, vet, frontend, e2e checks
```
