import { ApiError } from '../api/client';

// A safe recovery action for a typed failure. The panel names the
// blocked condition and the safe recovery action. It never suggests a
// personal access token, a direct agent launch, a bypass, a duplicate
// mutation, or a retry of an ambiguous request.
interface RecoveryGuidance {
  condition: string;
  action: string;
  retryable: boolean;
}

function guidanceForStatus(status: number): RecoveryGuidance | null {
  switch (status) {
    case 400:
      return {
        condition: 'The request was malformed.',
        action: 'Check the entered values and try once with corrected input.',
        retryable: true,
      };
    case 401:
      return {
        condition: 'The session is missing or expired.',
        action: 'Unlock again with your passkey to continue.',
        retryable: false,
      };
    case 403:
      return {
        condition: 'The action is not permitted for this session.',
        action: 'Review what the pass allows; if the action should be allowed, start the decision over from the pass page.',
        retryable: false,
      };
    case 404:
      return {
        condition: 'The item was not found in this workspace.',
        action: 'Go back and pick the item again from the current list.',
        retryable: false,
      };
    case 409:
      return {
        condition: 'A conflicting record already exists.',
        action: 'Open the pass to see the recorded result. Do not send the request again with changed content.',
        retryable: false,
      };
    case 412:
      return {
        condition: 'The underlying data changed since it was read.',
        action: 'Refresh the issue or proposal and review the new state before deciding.',
        retryable: false,
      };
    case 422:
      return {
        condition: 'The decision could not be verified upstream.',
        action: 'Start the decision over with a fresh challenge; expired or replayed challenges are rejected.',
        retryable: false,
      };
    case 429:
      return {
        condition: 'Too many requests.',
        action: 'Wait a minute, then try once.',
        retryable: true,
      };
    default:
      if (status >= 500) {
        return {
          condition: 'The service hit an unexpected error.',
          action: 'Wait a moment and try once. If it persists, check the local service logs.',
          retryable: true,
        };
      }
      return null;
  }
}

// ProblemPanel renders a typed failure with its blocked condition and
// safe recovery action. Unknown errors render the server's title plus a
// conservative default; the panel never invents recovery steps that
// touch credentials, bypass checks, or repeat an ambiguous mutation.
export function ProblemPanel({
  title,
  detail,
  onRetry,
  onDismiss,
}: {
  title: string;
  detail?: string;
  onRetry?: () => void;
  onDismiss?: () => void;
}) {
  return (
    <div role="alert" className="problem-panel">
      <p>
        <strong>{title}</strong>
      </p>
      {detail && <p>{detail}</p>}
      <div>
        {onRetry && (
          <button type="button" onClick={onRetry}>
            Try again
          </button>
        )}{' '}
        {onDismiss && (
          <button type="button" onClick={onDismiss}>
            Dismiss
          </button>
        )}
      </div>
    </div>
  );
}

// problemPanelForError maps an unknown throw into ProblemPanel props.
// Recovery actions marked retryable are safe to retry once; ambiguous
// mutations (409 and up) are never retried automatically.
export function problemPanelForError(err: unknown): {
  title: string;
  detail?: string;
  retryable: boolean;
} {
  if (err instanceof ApiError) {
    const guidance = guidanceForStatus(err.status);
    return {
      title: err.title || `The request failed (${err.status}).`,
      detail: guidance ? `${guidance.condition} ${guidance.action}` : undefined,
      retryable: guidance?.retryable ?? false,
    };
  }
  return {
    title: 'The request could not be completed.',
    detail: 'Check that the local service is running, then try once.',
    retryable: true,
  };
}

export default ProblemPanel;
