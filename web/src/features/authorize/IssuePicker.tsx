import { useState } from 'react';
import { ApiError, githubIssue } from '../../shared/api/client';
import type {
  GitHubConnection,
  GitHubIssueResponse,
  GitHubIssueSnapshot,
  GitHubPosture,
} from '../../shared/api/generated';

// parseIssueInput accepts a bare issue number or a GitHub issue URL.
// A URL whose owner/name does not match the selected repository is
// rejected so the snapshot always belongs to the connected repo.
export function parseIssueInput(
  input: string,
  connection: GitHubConnection | null,
): { number: number } | { error: string } {
  const trimmed = input.trim();
  if (/^\d{1,10}$/.test(trimmed)) {
    return { number: Number.parseInt(trimmed, 10) };
  }
  try {
    const url = new URL(trimmed);
    const match = /^\/([^/]+)\/([^/]+)\/issues\/(\d{1,10})(?:\/|$)/.exec(url.pathname);
    if (match) {
      const repo = `${match[1]}/${match[2]}`;
      if (connection && repo.toLowerCase() !== connection.repository_name.toLowerCase()) {
        return {
          error: `That URL points at ${repo}, but ${connection.repository_name} is connected.`,
        };
      }
      return { number: Number.parseInt(match[3], 10) };
    }
  } catch {
    // fall through to the generic error
  }
  return { error: 'Enter an issue number, or a GitHub issue URL.' };
}

type Eligibility =
  | { ok: true }
  | { ok: false; reason: string; recoverable: boolean };

// checkEligibility gates Authorize on the trusted posture check. Risky or
// unverifiable posture disables Authorize; the recovery action re-checks.
export function checkEligibility(posture: GitHubPosture): Eligibility {
  if (posture.outcome === 'risky') {
    const reasons = posture.reason_codes.length > 0 ? posture.reason_codes.join(', ') : 'risky workflows';
    return {
      ok: false,
      reason: `Unsafe workflow posture: ${reasons}. Authorize is blocked until the workflows are fixed.`,
      recoverable: true,
    };
  }
  if (Number.isNaN(Date.parse(posture.expires_at)) || Date.parse(posture.expires_at) <= Date.now()) {
    return {
      ok: false,
      reason: 'The posture check is missing or expired, so this issue is unverified. Check again to re-verify.',
      recoverable: true,
    };
  }
  return { ok: true };
}

type PickerState =
  | { kind: 'idle' }
  | { kind: 'loading' }
  | { kind: 'result'; response: GitHubIssueResponse }
  | { kind: 'error'; message: string; recoverable: boolean };

// IssuePicker imports a trusted issue snapshot for the connected
// repository and gates launch on workflow posture. Closed, stale, unsafe,
// or unverified issues never navigate to Authorize: the button is
// disabled and a recovery action is offered instead. Only the snapshot
// and posture metadata are rendered; nothing secret is shown or stored.
export default function IssuePicker({
  connection,
  onAuthorize,
}: {
  connection: GitHubConnection | null;
  onAuthorize: (snapshot: GitHubIssueSnapshot) => void;
}) {
  const [input, setInput] = useState('');
  const [inputError, setInputError] = useState<string | null>(null);
  const [state, setState] = useState<PickerState>({ kind: 'idle' });

  async function lookup(issueNumber: number) {
    if (!connection) return;
    setState({ kind: 'loading' });
    try {
      const response = await githubIssue(connection.connection_id, issueNumber);
      setState({ kind: 'result', response });
    } catch (err) {
      const recoverable = err instanceof ApiError && (err.status === 409 || err.status >= 500);
      const message =
        err instanceof ApiError
          ? err.title
          : 'Could not import the issue.';
      setState({ kind: 'error', message, recoverable });
    }
  }

  function submit() {
    setInputError(null);
    const parsed = parseIssueInput(input, connection);
    if ('error' in parsed) {
      setInputError(parsed.error);
      return;
    }
    void lookup(parsed.number);
  }

  function reset() {
    setInput('');
    setInputError(null);
    setState({ kind: 'idle' });
  }

  if (!connection) {
    return (
      <section aria-label="Issue picker">
        <h2>Pick an issue</h2>
        <p>Connect a repository first, then pick an issue to authorize.</p>
        <label>
          Issue number or URL
          <input type="text" disabled placeholder="e.g. 42" aria-label="Issue number or URL" />
        </label>
        <button type="button" disabled>
          Look up issue
        </button>
      </section>
    );
  }

  return (
    <section aria-label="Issue picker">
      <h2>Pick an issue</h2>
      <p>Repository: {connection.repository_name}</p>
      <form
        onSubmit={(e) => {
          e.preventDefault();
          submit();
        }}
      >
        <label>
          Issue number or URL
          <input
            type="text"
            value={input}
            onChange={(e) => setInput(e.target.value)}
            placeholder="42 or https://github.com/owner/repo/issues/42"
            autoComplete="off"
            spellCheck={false}
            disabled={state.kind === 'loading'}
          />
        </label>
        {inputError && <p role="alert">{inputError}</p>}
        <button type="submit" disabled={state.kind === 'loading'}>
          {state.kind === 'loading' ? 'Looking up…' : 'Look up issue'}
        </button>
      </form>

      {state.kind === 'error' && (
        <div>
          <p role="alert">{state.message}</p>
          {state.recoverable && (
            <button
              type="button"
              onClick={() => {
                const parsed = parseIssueInput(input, connection);
                if (!('error' in parsed)) void lookup(parsed.number);
              }}
            >
              Check again
            </button>
          )}{' '}
          <button type="button" onClick={reset}>
            Try another issue
          </button>
        </div>
      )}

      {state.kind === 'result' && (
        <ResultCard
          response={state.response}
          onAuthorize={onAuthorize}
          onRecheck={() => {
            const parsed = parseIssueInput(input, connection);
            if (!('error' in parsed)) void lookup(parsed.number);
          }}
          onReset={reset}
        />
      )}
    </section>
  );
}

function ResultCard({
  response,
  onAuthorize,
  onRecheck,
  onReset,
}: {
  response: GitHubIssueResponse;
  onAuthorize: (snapshot: GitHubIssueSnapshot) => void;
  onRecheck: () => void;
  onReset: () => void;
}) {
  const { snapshot, posture } = response;
  const eligibility = checkEligibility(posture);

  return (
    <article aria-label="Issue snapshot">
      <h3>
        #{snapshot.issue_number} in {snapshot.repository_full_name}
      </h3>
      <p>{snapshot.objective}</p>
      {snapshot.acceptance_criteria.length > 0 && (
        <>
          <h4>Acceptance criteria</h4>
          <ul>
            {snapshot.acceptance_criteria.map((criterion, index) => (
              <li key={index}>{criterion}</li>
            ))}
          </ul>
        </>
      )}
      <dl>
        <dt>Source revision</dt>
        <dd>
          <code>{snapshot.source_revision.slice(0, 16)}</code>
        </dd>
        <dt>Workflow posture</dt>
        <dd>
          {posture.outcome === 'clean'
            ? 'clean'
            : `risky (${posture.reason_codes.join(', ') || 'see details'})`}
        </dd>
      </dl>
      {!eligibility.ok && <p role="alert">{eligibility.reason}</p>}
      <button
        type="button"
        disabled={!eligibility.ok}
        onClick={() => onAuthorize(snapshot)}
      >
        Continue to Authorize
      </button>{' '}
      {!eligibility.ok && eligibility.recoverable && (
        <button type="button" onClick={onRecheck}>
          Check again
        </button>
      )}{' '}
      <button type="button" onClick={onReset}>
        Pick another issue
      </button>
    </article>
  );
}
