# Deploying OPE with Docker Compose

This deploys one workspace-bound OPE instance as a container. One
instance binds one workspace: to serve another workspace, run another
service with its own data volume and its own `OPE_WORKSPACE_ID`.

## Prerequisites

All three are explicit and checked at startup; the server fails closed
when any is missing.

1. **Host CLI.** The `authscope-ope` CLI on the operator machine for the
   `run`, `revoke`, `doctor`, and `recover` flows. Build it from this
   repository or copy it out of the image:
   `docker create --name ope-bin authscope-ope:latest` then
   `docker cp ope-bin:/usr/local/bin/authscope-ope ./authscope-ope`.
2. **Governed runner.** The `ope-runner` binary on the host, mounted
   read-only into the container at `/usr/local/bin/ope-runner`. Set
   `OPE_RUNNER_PATH_HOST` to its host path. The binary must be an
   owner-writable regular file; the server validates the path before
   every launch.
3. **Workload signer.** A managed, non-exportable signer reference
   (HSM/TEE handle, never key material) passed as
   `OPE_WORKLOAD_SIGNER_REF`. Release mode refuses to start without it.
   Development builds may omit it and use an ephemeral in-memory signer
   that is clearly marked dev-only.

## Configuration

Copy the required values into the environment before starting:

```sh
export AUTH_SCOPE_URL=https://authscope.example
export OPE_WORKSPACE_ID=ws_123
export OPE_HOSTNAME=ope.example
export OPE_ORIGIN=https://ope.example
export OPE_RP_ID=ope.example
export OPE_WORKLOAD_SIGNER_REF=hsm:slot/ope-workload
export OPE_RUNNER_PATH_HOST=/usr/local/bin/ope-runner
docker compose -f deploy/compose.yaml up -d --build
```

The published port is loopback-only (`127.0.0.1:8080`). Reach the UI
through an SSH tunnel or place a TLS-terminating reverse proxy in
front; the container itself never listens on a public interface.

## Data and backups

All instance state lives in the `ope-data` volume (`/data` in the
container): `ope.db`, the instance lock, and nothing else. Back up the
volume; it is the instance. The root filesystem is read-only.

## Health and diagnostics

- `GET /healthz` is the container health check (liveness).
- `GET /readyz` reports contract and upstream compatibility (readiness).
- `authscope-ope doctor` runs read-only preflight diagnostics against a
  stopped instance's data directory.

## Offline recovery

Recovery runs against a stopped instance with exclusive access to the
data directory:

```sh
docker compose -f deploy/compose.yaml stop ope
authscope-ope recover --data-dir /var/lib/docker/volumes/deploy_ope-data/_data
```

The recovery key is read from the controlling terminal with echo
disabled, never from argv, the environment, or configuration. The
command prints one ten-minute bootstrap code exactly once for
re-enrollment.
