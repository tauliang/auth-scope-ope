# OPE security model

OPE exists to make one claim auditable: that a specific founder
authorized a specific piece of work, and that the work ran the way it
was approved. Everything in this document follows from that claim.
Evidence in OPE proves authorization and execution facts. It does not
prove business wisdom, legality, or compliance. A signed receipt shows
the founder approved the launch and the runner executed these steps;
it says nothing about whether the launch was a good idea.

## Trust boundaries

Seven parties meet in an OPE deployment. Each boundary names what one
side may assume about the other and what it must verify.

### Browser

The founder's browser holds the passkey private key and the session
cookie. The browser is trusted exactly as far as the founder's device
is trusted: a compromised browser can act as the founder, and no
server-side check can distinguish that from the founder acting
directly. This is why enrollment binds a passkey (something the device
holds) rather than a password (something the founder knows and can be
phished). The session cookie is `__Host-` prefixed, host-only,
HttpOnly, SameSite strict, and bound to the instance that issued it.

### OPE

The local OPE server holds the instance binding, ceremony state, and
the session store. It trusts nothing it has not verified: every start
re-checks the contract pins and live compatibility with AuthScope,
every founder request re-validates host, origin, session, and CSRF,
and the data directory is locked exclusively so two processes can never
serve or recover the same state at once. OPE never stores key material:
passkey private keys stay in the browser, the workload signer is a
non-exportable reference, and one-time codes are stored as hashes.

### AuthScope

AuthScope core is the authority for every business fact: workspaces,
proposals, missions, receipts, and the GitHub broker. OPE treats it as
authoritative but not as implicitly trustworthy. The vendored contract
digest is pinned; the server refuses to start when the core's version,
OpenAPI hash, or capabilities do not match the pins. The workload
identity is derived from the transport (mTLS or the workload signer),
never from a client-selected header, and decision attestations require
the `decision_attestor` role. If AuthScope says the workspace is
contained and its mission list is empty, offline recovery believes it
only after authenticating that response as workspace-scoped.

### Runner

The governed runner is the only process that executes agent work. OPE
trusts the runner binary, not the agent it runs. Before every launch
OPE re-validates the runner path: it must be an absolute path to a
regular file, owned by the operator or root, with no group or world
writability, and it must report a sane version. The runner receives the
launch credential and nothing else; it cannot read the OPE database or
mint founder sessions.

### Agent

The agent kit (the coding agent and its tools) is untrusted code. It
runs under the runner's supervision with the least privilege the kit
declares, and its outputs are treated as claims to be checked, not as
facts. Signed receipts record what the runner observed the agent do;
they do not vouch for the agent's judgment. A malicious or mistaken
agent can waste the approved budget or produce bad code, but it cannot
escape the runner, approve its own proposals, or touch another
workspace.

### Gateway

The gateway is the network edge in front of OPE: a TLS-terminating
reverse proxy or an SSH tunnel. OPE itself listens on loopback only
and never on a public interface; the gateway is what makes the UI
reachable beyond the machine. The gateway is trusted with transport
confidentiality and with forwarding the browser's Host header
unchanged, because OPE pins the request host to the configured origin
and rejects anything else. The gateway sees encrypted traffic only if
it terminates TLS, and in that case it must be operated with the same
care as OPE itself. It never holds OPE credentials.

### GitHub

GitHub is an external party reached only through AuthScope's broker.
OPE never holds a GitHub token and never talks to the GitHub API
directly: the binding flow, issue snapshots, and check publications all
go through AuthScope, which scopes every operation to the bound
repository. OPE independently inspects workflow posture before launch,
because a repository's workflows execute with the repository's
privileges and a risky workflow is a supply-chain risk no signature can
fix.

## Anonymous-FD credential delivery

When the founder approves a launch in the browser, the CLI exchanges
the one-use decision for a launch credential and hands it to the
runner. The handoff uses an anonymous file descriptor: the CLI creates
a pipe, writes the credential into it, and passes the read end to the
runner as an inherited descriptor. The credential never appears in an
argument list, an environment variable, a log line, or a proc table.
After the runner reads it, both ends are closed and the memory is
zeroed. A credential that never exists in a nameable place cannot be
scraped from one.

## Automatic checks

OPE does not rely on the operator remembering to verify things. These
checks run on their own:

- **Startup gate.** Contract digest pins, live core compatibility, and
  workload-identity attachment run before any route is registered. A
  mismatch fails the start.
- **Per-request guards.** Host and origin pinning, session and CSRF
  validation, rate limits, and idempotency run on every request without
  operator action.
- **Workflow posture.** Every connected repository's workflows are
  inspected before launch; risky findings block the launch.
- **Signing-key history.** The local pin file is checked against the
  upstream key history; unknown keys fail closed until the pins are
  updated deliberately.
- **Clock skew.** Decisions and attestations are short-lived. Skew
  beyond thirty seconds against AuthScope's clock fails the relevant
  check rather than silently accepting stale attestations.
- **Recovery verification.** Offline recovery contains the workspace at
  AuthScope, then polls the authoritative mission list until it is
  verifiably empty before touching local authentication state. No local
  reset happens on the basis of an unverified claim.

## What recovery guarantees

Offline recovery is for the day the founder's credentials are gone. It
guarantees that after it completes, no session, CLI handoff, or passkey
from before recovery can authenticate, the workspace has no active
missions anywhere (verified against AuthScope, not assumed), and
exactly one fresh bootstrap code exists for re-enrollment. It does not
guarantee that AuthScope is telling the truth about the mission list;
it guarantees that OPE verified the list was authenticated and
workspace-scoped before acting on it. The recovery event record is
non-secret and auditable: who recovered, when, how many missions were
contained, and the digests of the attestation and proof.

## What OPE does not do

OPE does not judge proposals, does not review code for correctness,
and does not decide whether work complies with law or policy. Those are
the founder's decisions, and the evidence exists so the founder's
decisions can be audited, not so OPE can make them. An approval signed
by the founder's passkey is authorization, nothing more.
