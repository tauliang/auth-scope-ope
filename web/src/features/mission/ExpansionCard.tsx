import { useCallback, useState } from 'react';
import {
  ApiError,
  beginExpansionDecision,
  finishExpansionDecision,
  newIdempotencyKey,
} from '../../shared/api/client';
import { getPasskey } from '../../shared/webauthn';
import type {
  ExpansionDecisionResult,
  PendingExpansion,
} from '../../shared/api/generated';

type ExpansionCardState =
  | { kind: 'idle' }
  | { kind: 'signing' }
  | { kind: 'finishing' }
  | { kind: 'done'; decision: 'approve_once' | 'deny' }
  | { kind: 'pending' }
  | { kind: 'error'; message: string };

function expansionErrorMessage(err: unknown): string {
  if (err instanceof ApiError) {
    switch (err.status) {
      case 400:
        return err.title || 'The expansion decision request was invalid.';
      case 404:
        return 'The expansion or decision challenge was not found. Refresh and try again.';
      case 409:
        return (
          err.title ||
          'The expansion changed or a conflicting decision is in progress. Refresh to see the current state.'
        );
      default:
        return err.title || 'The expansion decision failed. Try again.';
    }
  }
  return 'The expansion decision failed. Try again.';
}

// ExpansionCard shows one pending expansion delta and runs the founder's
// passkey decision ceremony. The card displays the exact canonical
// fields; the browser never submits or widens the authority delta.
// The card is disabled when the delta is stale, expired, or already
// decided.
export function ExpansionCard({
  expansion,
  onDecided,
}: {
  passId: string;
  expansion: PendingExpansion;
  onDecided: (result: ExpansionDecisionResult) => void;
}) {
  const [state, setState] = useState<ExpansionCardState>({ kind: 'idle' });

  const disabled =
    expansion.stale ||
    expansion.expired ||
    state.kind === 'signing' ||
    state.kind === 'finishing' ||
    state.kind === 'done' ||
    state.kind === 'pending';

  const decide = useCallback(
    async (decision: 'approve_once' | 'deny') => {
      const key = newIdempotencyKey();
      setState({ kind: 'signing' });
      try {
        const begin = await beginExpansionDecision(
          expansion.expansion_id,
          decision,
          key,
        );
        const assertion = await getPasskey(begin.options);
        setState({ kind: 'finishing' });
        const result = await finishExpansionDecision(
          expansion.expansion_id,
          begin.challenge_id,
          assertion,
          key,
        );
        if ('reconciliation' in result) {
          setState({ kind: 'pending' });
          return;
        }
        setState({ kind: 'done', decision });
        onDecided(result);
      } catch (err) {
        setState({ kind: 'error', message: expansionErrorMessage(err) });
      }
    },
    [expansion.expansion_id, onDecided],
  );

  return (
    <section aria-label={`Expansion ${expansion.expansion_id}`}>
      <dl>
        <dt>Blocked operation</dt>
        <dd>{expansion.blocked_operation}</dd>
        <dt>Resource</dt>
        <dd>{expansion.resource}</dd>
        <dt>Current authority</dt>
        <dd>{expansion.current_authority}</dd>
        <dt>Requested authority</dt>
        <dd>{expansion.requested_authority}</dd>
        <dt>Consequence</dt>
        <dd>{expansion.consequence_change}</dd>
        <dt>Reason</dt>
        <dd>{expansion.reason_code}</dd>
        <dt>Reversibility</dt>
        <dd>{expansion.reversibility}</dd>
        <dt>Path</dt>
        <dd>{expansion.destination}</dd>
        <dt>Normalized arguments digest</dt>
        <dd>{expansion.normalized_arguments_digest}</dd>
        <dt>Expansion digest</dt>
        <dd>{expansion.expansion_digest}</dd>
        {expansion.agent_rationale && (
          <>
            <dt>Agent-authored rationale</dt>
            <dd>{expansion.agent_rationale}</dd>
          </>
        )}
      </dl>
      <p>
        Approval grants exactly one use of the requested authority,
        bounded by the effective expiry. The grant never widens beyond
        the canonical delta shown above.
      </p>
      {expansion.stale && <p>Stale: the expansion is no longer pending upstream or the mission moved.</p>}
      {expansion.expired && <p>Expired: the requested expiry has passed.</p>}
      <button
        type="button"
        disabled={disabled}
        onClick={() => void decide('approve_once')}
      >
        Approve once
      </button>
      <button
        type="button"
        disabled={disabled}
        onClick={() => void decide('deny')}
      >
        Deny
      </button>
      {state.kind === 'done' && state.decision === 'approve_once' && (
        <p role="status">Approved for exactly one use.</p>
      )}
      {state.kind === 'done' && state.decision === 'deny' && (
        <p role="status">Denied. The prior authority is unchanged.</p>
      )}
      {state.kind === 'pending' && (
        <p role="status">
          The upstream outcome is ambiguous. The decision is pending reconciliation.
        </p>
      )}
      {state.kind === 'error' && <p role="alert">{state.message}</p>}
    </section>
  );
}
