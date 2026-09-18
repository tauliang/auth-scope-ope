import { useCallback, useEffect, useState } from 'react';
import {
  ApiError,
  beginCliAuthorization,
  finishCliAuthorization,
  newIdempotencyKey,
} from '../../shared/api/client';
import type { CLIAuthorizationApproveBeginResponse } from '../../shared/api/generated';
import { getPasskey } from '../../shared/webauthn';

// cliAuthorizationPathPrefix is the transient browser route the CLI prints
// for the founder. The authorization id follows the prefix. Nothing about
// the authorization is persisted in browser storage; the page is
// throwaway.
export const cliAuthorizationPathPrefix = '/authorize/cli/';

// cliAuthorizationIdFromPath extracts the authorization id from the
// transient CLI route, or null when the pathname is not a CLI
// authorization route.
export function cliAuthorizationIdFromPath(pathname: string): string | null {
  if (!pathname.startsWith(cliAuthorizationPathPrefix)) {
    return null;
  }
  const id = pathname.slice(cliAuthorizationPathPrefix.length).split('/')[0];
  return id === '' ? null : id;
}

type AuthorizationState =
  | { kind: 'loading' }
  | { kind: 'ready'; begun: CLIAuthorizationApproveBeginResponse }
  | { kind: 'waiting'; begun: CLIAuthorizationApproveBeginResponse }
  | { kind: 'finishing' }
  | { kind: 'done' }
  | { kind: 'error'; message: string; recoverable: boolean };

function authorizationErrorMessage(err: unknown): { message: string; recoverable: boolean } {
  if (err instanceof ApiError) {
    switch (err.status) {
      case 404:
        return {
          message: 'The launch authorization was not found or already expired. Ask the CLI to start over.',
          recoverable: false,
        };
      case 409:
        return {
          message:
            err.title ||
            'The launch authorization expired, was already used, or the launch details changed. Ask the CLI to start over.',
          recoverable: false,
        };
      default:
        return {
          message: err.title || `The launch authorization failed (${err.status}).`,
          recoverable: err.status >= 500,
        };
    }
  }
  return { message: 'The launch authorization could not be completed.', recoverable: false };
}

// CLIAuthorization approves one CLI launch through the browser. It shows
// the exact launch bindings pinned by the CLI (pass, repository, issue,
// agent kit, ordered runner arguments, invocation digest) and signs them
// with the founder passkey. After a successful finish the page shows only
// "Return to the CLI." The authorization code, the PKCE verifier, and any
// sealed runtime material never touch this page.
export function CLIAuthorization({ authorizationId }: { authorizationId: string }) {
  const [state, setState] = useState<AuthorizationState>({ kind: 'loading' });
  const [attempt, setAttempt] = useState(0);

  useEffect(() => {
    let cancelled = false;
    setState({ kind: 'loading' });
    beginCliAuthorization(authorizationId, newIdempotencyKey())
      .then((begun) => {
        if (!cancelled) {
          setState({ kind: 'ready', begun });
        }
      })
      .catch((err: unknown) => {
        if (!cancelled) {
          const { message, recoverable } = authorizationErrorMessage(err);
          setState({ kind: 'error', message, recoverable });
        }
      });
    return () => {
      cancelled = true;
    };
  }, [authorizationId, attempt]);

  const approve = useCallback(
    async (begun: CLIAuthorizationApproveBeginResponse) => {
      setState({ kind: 'waiting', begun });
      try {
        const assertion = await getPasskey(begun.assertion_options);
        setState({ kind: 'finishing' });
        await finishCliAuthorization(authorizationId, begun.challenge_id, assertion, newIdempotencyKey());
        setState({ kind: 'done' });
      } catch (err: unknown) {
        const { message, recoverable } = authorizationErrorMessage(err);
        setState({ kind: 'error', message, recoverable });
      }
    },
    [authorizationId],
  );

  if (state.kind === 'loading') {
    return (
      <main>
        <h1>AuthScope OPE</h1>
        <p>Loading the CLI launch request…</p>
      </main>
    );
  }

  if (state.kind === 'done') {
    return (
      <main>
        <h1>AuthScope OPE</h1>
        <p role="status">Return to the CLI.</p>
      </main>
    );
  }

  if (state.kind === 'error') {
    return (
      <main>
        <h1>AuthScope OPE</h1>
        <p role="alert">{state.message}</p>
        {state.recoverable && (
          <button type="button" onClick={() => setAttempt((n) => n + 1)}>
            Try again
          </button>
        )}
      </main>
    );
  }

  if (state.kind === 'finishing') {
    return (
      <main>
        <h1>AuthScope OPE</h1>
        <p>Verifying your passkey and handing the launch back to the CLI…</p>
      </main>
    );
  }

  const { begun } = state;
  const waiting = state.kind === 'waiting';
  return (
    <main>
      <h1>AuthScope OPE</h1>
      <section aria-label="CLI launch request">
        <h2>CLI launch request</h2>
        <p>
          The CLI asked the browser to authorize one launch of an approved pass. Approving with
          your passkey signs exactly the launch details below and hands a one-use authorization
          back to the CLI. Nothing is launched from this page.
        </p>
        <dl>
          <dt>Pass</dt>
          <dd><code>{begun.pass_id}</code></dd>
          <dt>Repository</dt>
          <dd>{begun.repository_name}</dd>
          <dt>Issue</dt>
          <dd>#{begun.issue_number}</dd>
          <dt>Agent kit</dt>
          <dd>
            <code>{begun.agent_kit_id}</code> <code>{begun.agent_kit_version}</code>
          </dd>
          <dt>Runner arguments</dt>
          <dd>
            <code>{begun.runner_arguments.join(' ')}</code>
          </dd>
          <dt>Invocation digest</dt>
          <dd><code>{begun.invocation_digest}</code></dd>
          <dt>Proposal digest</dt>
          <dd><code>{begun.proposal_digest}</code></dd>
        </dl>
      </section>
      <button type="button" onClick={() => void approve(begun)} disabled={waiting}>
        {waiting ? 'Waiting for your passkey…' : 'Authorize launch with passkey'}
      </button>
    </main>
  );
}

export default CLIAuthorization;
