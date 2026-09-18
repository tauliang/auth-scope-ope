# Getting started with OPE

OPE (the operator environment) is the local side of AuthScope: it holds
your workspace binding, your founder identity, and the governed runner
that executes approved work. This guide takes you from an empty machine
to your first proposal without writing any YAML.

One instance binds one workspace. The first time the server starts, it
writes an immutable binding record into its data directory tying that
instance to exactly one AuthScope workspace. From then on it refuses to
serve any other workspace's state, and a second instance needs its own
data directory.

## What you need

Three things, all explicit. OPE fails closed when any of them is
missing.

1. **AuthScope.** A reachable AuthScope core and the workspace ID it
   gave you. Every business fact (proposals, missions, receipts) lives
   there; OPE keeps only presentation and ceremony state.
2. **The governed runner.** The `ope-runner` binary that actually
   executes agent work. Set `OPE_RUNNER_PATH` to its absolute path. It
   must be a regular file, owned by you or root, and not writable by
   group or world.
3. **A workload signer.** In release mode this is a managed,
   non-exportable reference such as an HSM or TEE handle, passed as
   `OPE_WORKLOAD_SIGNER_REF`. Never key material. In development you can
   omit it and OPE uses an ephemeral in-memory signer that is clearly
   marked dev-only and must never reach release.

## Configure

OPE reads its configuration from the environment:

```sh
export OPE_MODE=development
export AUTH_SCOPE_URL=https://authscope.example
export OPE_WORKSPACE_ID=ws_123
export OPE_HOSTNAME=localhost
export OPE_ORIGIN=http://localhost:8080
export OPE_RP_ID=localhost
export OPE_BIND_ADDR=127.0.0.1:8080
export OPE_DATA_DIR=$HOME/.ope
export OPE_RUNNER_PATH=/usr/local/bin/ope-runner
```

In development the origin may be loopback `http`; release requires
`https` origins and an `https` AuthScope URL.

## Start the server

```sh
authscope-ope serve
```

The first start binds the instance: it verifies the AuthScope contract
pins, checks live compatibility, attaches your workload identity, and
writes the binding record. Watch the log for the compatibility gate;
if the core version or contract digest does not match the pins, the
server refuses to start rather than serve against an unknown core.

Open the printed origin in your browser. Because nothing is enrolled
yet, the UI starts the bootstrap ceremony.

## Enroll as founder

The bootstrap ceremony creates your founder identity and registers a
passkey for it:

1. The server prints a one-time bootstrap code. Enter it in the browser.
2. Register a passkey when prompted. The credential's public key stays
   local; the private key never leaves your device.
3. During the ceremony, write down the offline recovery key and store it
   somewhere safe, ideally offline. It is shown exactly once and there
   is no way to recover it later. If you lose both your passkey and this
   key, the workspace cannot be recovered.

After the ceremony you are signed in with a session cookie scoped to
this instance (`__Host-` prefixed, host-only, HttpOnly, SameSite
strict).

## Connect GitHub

In the UI, connect the GitHub repository you want to work in. OPE
starts a brokered binding flow with AuthScope: you authorize the
GitHub App, AuthScope records the repository binding, and OPE stores a
reference to it. OPE inspects the repository's workflow posture before
anything runs; risky workflows block launches until they are fixed.

## Reach your first proposal without YAML

You never write a mission file. In the UI, open an issue from the
connected repository and choose to shape it into a proposal. OPE asks
AuthScope to draft the mission from the issue: title, plan, and budget
come back as a structured proposal. Review it in the browser, adjust in
plain language if you want, and approve with your passkey. No YAML, no
config files, no CLI flags for the happy path.

Approving a proposal creates a mission pass. Launch it from the UI or
from your terminal:

```sh
authscope-ope run <pass-id>
```

The CLI opens your browser for the launch decision, then hands the
approved launch to the governed runner through an anonymous file
descriptor, so the credential that authorizes the run never appears in
an argument list, an environment variable, or a log. The runner
executes the agent kit, streams evidence back, and OPE records signed
receipts you can audit later.

## Check health

`authscope-ope doctor` runs read-only diagnostics against the data
directory: binding, identity, contract pins, clock skew, database
permissions, runner, and more. It never writes, so it is safe to run
anytime something looks off.

## If everything breaks

If you lose your passkey, stop the server and run offline recovery:

```sh
authscope-ope recover --data-dir /absolute/path/to/data
```

Type the workspace ID exactly when asked, then type the offline
recovery key. Recovery contains the workspace at AuthScope, verifies
every mission is gone, wipes local authentication state, and prints one
fresh ten-minute bootstrap code for re-enrollment. See the security
model for what recovery guarantees and what it does not.
