import { useCallback, useState } from 'react';
import {
  ApiError,
  beginRevoke,
  finishRevoke,
  isRevokePending,
  newIdempotencyKey,
} from '../../shared/api/client';
import { getPasskey } from '../../shared/webauthn';

// revokeReasons are the fixed normalized revocation reason codes the
// server accepts. The browser sends one; everything else about the
// revocation is bound server-side.
const revokeReasons = [
  { code: 'founder_requested', label: 'Founder requested' },
  { code: 'safety_concern', label: 'Safety concern' },
  { code: 'mission_superseded', label: 'Mission superseded' },
] as const;

type RevokeState =
  | { kind: 'idle' }
  | { kind: 'choosing' }
  | { kind: 'signing' }
  | { kind: 'finishing' }
  | { kind: 'done'; containment: string }
  | { kind: 'pending' }
  | { kind: 'handedOff' }
  | { kind: 'error'; message: string; recoverable: boolean };

// containmentMessage renders the fixed containment state in plain
// language. Enforcement is never claimed until the gateway containment
// is acknowledged.
function containmentMessage(containment: string): string {
  switch (containment) {
    case 'acknowledged':
      return 'Mission revoked. Gateway containment acknowledged.';
    case 'partial':
      return 'Mission revoked. Containment is partial; some resources may still be winding down.';
    case 'pending':
      return 'Mission revoked. Containment is pending; the gateway has not acknowledged it yet.';
    default:
      return `Mission revoked (containment ${containment}).`;
  }
}

function revokeErrorMessage(err: unknown): { message: string; recoverable: boolean } {
  if (err instanceof ApiError) {
    switch (err.status) {
      case 400:
        return { message: err.title || 'The revocation request was invalid.', recoverable: false };
      case 404:
        return {
          message: 'The mission pass or revocation challenge was not found. Start over.',
          recoverable: false,
        };
      case 409:
        return {
          message:
            err.title ||
            'This mission cannot be revoked from its current state, or the revocation details changed. Start over.',
          recoverable: false,
        };
      default:
        return {
          message: err.title || `The revocation failed (${err.status}).`,
          recoverable: err.status >= 500,
        };
    }
  }
  return { message: 'The revocation could not be completed.', recoverable: false };
}

// RevokeButton runs the founder's passkey revocation ceremony for one
// mission pass. The founder picks a fixed reason, signs the
// server-bound revocation with their passkey, and the mission is
// revoked upstream exactly once. When the upstream outcome is ambiguous
// the UI reports the pending state and the timeline reconciles it.
// When cliRevocationId is set, the finish hands the one-use result code
// to the waiting CLI through the loopback callback and the UI shows
// only "Return to the CLI."
export function RevokeButton({
  passId,
  onRevoked,
  cliRevocationId,
}: {
  passId: string;
  onRevoked: () => void;
  cliRevocationId?: string;
}) {
  const [state, setState] = useState<RevokeState>({ kind: 'idle' });
  const [reason, setReason] = useState<string>(revokeReasons[0].code);

  const start = useCallback(() => {
    setState({ kind: 'choosing' });
  }, []);

  const confirm = useCallback(async () => {
    setState({ kind: 'signing' });
    try {
      const begun = await beginRevoke(passId, reason, newIdempotencyKey());
      const assertion = await getPasskey(begun.options);
      setState({ kind: 'finishing' });
      const result = await finishRevoke(
        passId,
        begun.challenge_id,
        assertion,
        newIdempotencyKey(),
        cliRevocationId,
      );
      if ('handedToCli' in result) {
        setState({ kind: 'handedOff' });
      } else if (isRevokePending(result)) {
        setState({ kind: 'pending' });
      } else {
        setState({ kind: 'done', containment: result.containment });
      }
      onRevoked();
    } catch (err: unknown) {
      const { message, recoverable } = revokeErrorMessage(err);
      setState({ kind: 'error', message, recoverable });
    }
  }, [passId, reason, cliRevocationId, onRevoked]);

  const reset = useCallback(() => {
    setState({ kind: 'idle' });
  }, []);

  switch (state.kind) {
    case 'choosing':
      return (
        <section aria-label="revoke mission">
          <h3>Revoke mission</h3>
          <p>This revokes the mission upstream. The revocation is signed with your passkey.</p>
          <label>
            Reason
            <select value={reason} onChange={(e) => setReason(e.target.value)}>
              {revokeReasons.map((r) => (
                <option key={r.code} value={r.code}>
                  {r.label}
                </option>
              ))}
            </select>
          </label>
          <button type="button" onClick={confirm}>
            Revoke with passkey
          </button>
          <button type="button" onClick={reset}>
            Cancel
          </button>
        </section>
      );
    case 'signing':
      return (
        <section aria-label="revoke mission">
          <p>Waiting for your passkey…</p>
        </section>
      );
    case 'finishing':
      return (
        <section aria-label="revoke mission">
          <p>Revoking the mission…</p>
        </section>
      );
    case 'done':
      return (
        <section aria-label="revoke mission">
          <p role="status">{containmentMessage(state.containment)}</p>
        </section>
      );
    case 'pending':
      return (
        <section aria-label="revoke mission">
          <p role="status">
            The revocation outcome is uncertain. The request is saved and the timeline will
            reconcile it; check back shortly.
          </p>
        </section>
      );
    case 'handedOff':
      return (
        <section aria-label="revoke mission">
          <p role="status">Return to the CLI.</p>
        </section>
      );
    case 'error':
      return (
        <section aria-label="revoke mission">
          <p role="alert">{state.message}</p>
          {state.recoverable && (
            <button type="button" onClick={confirm}>
              Retry
            </button>
          )}
          <button type="button" onClick={reset}>
            Back
          </button>
        </section>
      );
    case 'idle':
    default:
      return (
        <button type="button" onClick={start}>
          Revoke mission
        </button>
      );
  }
}
