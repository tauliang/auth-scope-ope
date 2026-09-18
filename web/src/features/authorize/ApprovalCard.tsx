import { useCallback, useState } from 'react';
import {
  ApiError,
  beginMissionPassApproval,
  fetchMissionPass,
  finishMissionPassApproval,
  isApprovalResult,
  newIdempotencyKey,
} from '../../shared/api/client';
import type {
  ApprovalResult,
  MissionPassReview as MissionPassReviewPayload,
} from '../../shared/api/generated';
import { getPasskey } from '../../shared/webauthn';

type ApprovalState =
  | { kind: 'idle' }
  | { kind: 'starting' }
  | { kind: 'waiting' }
  | { kind: 'finishing' }
  | { kind: 'approved'; result: ApprovalResult }
  | { kind: 'pending' }
  | { kind: 'error'; message: string; recoverable: boolean };

function approvalErrorMessage(err: unknown): { message: string; recoverable: boolean } {
  if (err instanceof ApiError) {
    switch (err.status) {
      case 404:
        return {
          message: 'The approval challenge expired before it was used. Start a new approval.',
          recoverable: true,
        };
      case 409:
        return {
          message: err.title || 'The proposal changed while you were reviewing it. Look at the new revision, then approve again if it still matches your intent.',
          recoverable: true,
        };
      default:
        return {
          message: err.title || `The approval failed (${err.status}).`,
          recoverable: err.status >= 500,
        };
    }
  }
  return { message: 'The approval could not be completed.', recoverable: false };
}

// ApprovalCard approves the exact proposal shown in the review with a
// passkey. Approval creates only the mission: no runtime policy, no
// lease, no launch, and no run.
export function ApprovalCard({
  review,
  onChanged,
}: {
  review: MissionPassReviewPayload;
  onChanged: (next: MissionPassReviewPayload) => void;
}) {
  const [state, setState] = useState<ApprovalState>({ kind: 'idle' });

  const refresh = useCallback(async () => {
    const next = await fetchMissionPass(review.pass_id);
    onChanged(next);
  }, [review.pass_id, onChanged]);

  const approve = useCallback(async () => {
    setState({ kind: 'starting' });
    try {
      const begun = await beginMissionPassApproval(review.pass_id, newIdempotencyKey());
      setState({ kind: 'waiting' });
      const assertion = await getPasskey(begun.options);
      setState({ kind: 'finishing' });
      const outcome = await finishMissionPassApproval(
        review.pass_id,
        begun.challenge_id,
        assertion,
        newIdempotencyKey(),
      );
      if (isApprovalResult(outcome)) {
        setState({ kind: 'approved', result: outcome });
      } else {
        setState({ kind: 'pending' });
      }
      await refresh();
    } catch (err: unknown) {
      const { message, recoverable } = approvalErrorMessage(err);
      setState({ kind: 'error', message, recoverable });
    }
  }, [review.pass_id, refresh]);

  // An ambiguous approval stays on screen with a way to check it again;
  // reading the pass reconciles the recorded upstream operation.
  if (review.reconciliation === 'pending') {
    return (
      <section aria-label="Approval status">
        <h3>Approval</h3>
        <p>Checking the original approval. This can take a moment.</p>
        <button
          type="button"
          onClick={() => {
            setState({ kind: 'idle' });
            void refresh().catch(() => {
              setState({ kind: 'error', message: 'Could not check the approval. Try again.', recoverable: true });
            });
          }}
        >
          Check now
        </button>
        {state.kind === 'error' && <p role="alert">{state.message}</p>}
      </section>
    );
  }

  if (review.state === 'approved') {
    return (
      <section aria-label="Approval status">
        <h3>Approval</h3>
        <p>
          Approved. The exact proposal created mission{' '}
          <code>{review.mission_ref || 'mission'}</code>; nothing was launched and no run started.
        </p>
      </section>
    );
  }

  // Past approval (a later lifecycle stage) has nothing to approve.
  if (review.state !== 'draft') {
    return null;
  }

  return (
    <section aria-label="Approval">
      <h3>Approval</h3>
      <p>
        Approving with your passkey signs the exact proposal above and creates only the
        mission. It does not set a runtime policy, take a lease, prepare a launch, or
        start a run.
      </p>
      {(state.kind === 'idle' || state.kind === 'error') && (
        <button type="button" onClick={() => void approve()}>
          Approve with passkey
        </button>
      )}
      {state.kind === 'starting' && <p>Starting the approval…</p>}
      {state.kind === 'waiting' && <p>Waiting for your passkey…</p>}
      {state.kind === 'finishing' && <p>Verifying and approving the exact proposal…</p>}
      {state.kind === 'approved' && (
        <p role="status">
          Approved. Mission <code>{state.result.mission_ref}</code> was created and nothing else.
        </p>
      )}
      {state.kind === 'pending' && (
        <p role="status">The approval reached AuthScope but the outcome is uncertain. Checking it now.</p>
      )}
      {state.kind === 'error' && (
        <div>
          <p role="alert">{state.message}</p>
          {state.recoverable && (
            <button type="button" onClick={() => void approve()}>
              Try again
            </button>
          )}
        </div>
      )}
    </section>
  );
}

export default ApprovalCard;
