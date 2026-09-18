# Mission pass: add a request timeout flag

<!-- This is the fixture issue body for the real-integration suite
     (test/integration). The operator applies it verbatim to the
     disposable private repository; the suite asserts the trusted issue
     snapshot digest against these exact bytes. -->

## Summary

Add a `--timeout` flag to the `serve` command so operators can bound how
long the server waits for a graceful shutdown. The flag accepts a Go
duration string (for example `30s`) and defaults to `10s` when omitted.

## Acceptance criteria

- `serve --timeout 30s` waits up to thirty seconds for in-flight
  requests before exiting.
- `serve --timeout 0s` exits immediately without waiting.
- An invalid duration value fails closed with a usage error before the
  server binds any port.
- The default remains `10s` when the flag is omitted.
- No new network listeners, no new credentials, no changes to the
  authentication or attestation paths.

## Out of scope

- Per-request timeouts, readiness probes, and deployment manifests.
- Anything outside the `serve` command implementation and its flag
  parsing.
