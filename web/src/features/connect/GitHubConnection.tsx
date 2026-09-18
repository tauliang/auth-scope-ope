import { useEffect, useRef, useState } from 'react';
import { ApiError, githubBegin, githubFinish } from '../../shared/api/client';
import type { GitHubConnection as Connection } from '../../shared/api/generated';
import PasskeySetup from '../../auth/PasskeySetup';

// pendingStorageKey holds the in-flight handoff across the AuthScope
// redirect round-trip. It carries only the opaque handoff ID and the
// repository name: no codes, states, or digests ever touch the browser.
const pendingStorageKey = 'ope.github.pendingHandoff';

// connectionStorageKey holds the last connected repository for this tab.
// It carries only server-verified identity metadata, never secrets.
const connectionStorageKey = 'ope.github.connection';

// readStoredConnection returns the server-verified repository connection
// stored for this tab, or null when none was stored. Only identity and
// status metadata ever passes through here; no secret material.
export function readStoredConnection(): Connection | null {
  try {
    const raw = sessionStorage.getItem(connectionStorageKey);
    if (!raw) return null;
    const parsed = JSON.parse(raw) as Connection;
    if (parsed && typeof parsed.connection_id === 'string') return parsed;
    return null;
  } catch {
    return null;
  }
}

export const githubCompletionPath = '/connect/github/done';

type PendingHandoff = {
  handoff_id: string;
  repository: string;
};

function readPending(): PendingHandoff | null {
  try {
    const raw = sessionStorage.getItem(pendingStorageKey);
    if (!raw) return null;
    const parsed = JSON.parse(raw) as Partial<PendingHandoff>;
    if (typeof parsed.handoff_id === 'string' && typeof parsed.repository === 'string') {
      return { handoff_id: parsed.handoff_id, repository: parsed.repository };
    }
    return null;
  } catch {
    return null;
  }
}

function clearPending(): void {
  sessionStorage.removeItem(pendingStorageKey);
}

// repositoryPattern mirrors the server's owner/name shape. The server is
// authoritative; this only avoids a wasted round-trip.
const repositoryPattern = /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/;

type StartState =
  | { kind: 'idle' }
  | { kind: 'starting' }
  | { kind: 'error'; message: string };

// GitHubConnectionStart renders the connect form. On submit it opens the
// handoff, stashes the opaque handoff ID in session storage, and hands
// the browser to the fixed-origin AuthScope installation URL. AuthScope
// redirects back to the completion path, which GitHubConnectionComplete
// serves.
export function GitHubConnectionStart({ onConnected }: { onConnected: (c: Connection | null) => void }) {
  const [repository, setRepository] = useState('');
  const [state, setState] = useState<StartState>({ kind: 'idle' });
  const [validation, setValidation] = useState<string | null>(null);
  const [stored, setStored] = useState<Connection | null>(null);

  useEffect(() => {
    const raw = sessionStorage.getItem(connectionStorageKey);
    if (!raw) return;
    try {
      const parsed = JSON.parse(raw) as Connection;
      if (parsed && typeof parsed.connection_id === 'string') {
        setStored(parsed);
        onConnected(parsed);
      }
    } catch {
      sessionStorage.removeItem(connectionStorageKey);
    }
  }, [onConnected]);

  function disconnect() {
    sessionStorage.removeItem(connectionStorageKey);
    setStored(null);
    onConnected(null);
  }

  async function start() {
    const trimmed = repository.trim();
    if (!repositoryPattern.test(trimmed) || trimmed.length > 128) {
      setValidation('Enter a repository as owner/name.');
      return;
    }
    setValidation(null);
    setState({ kind: 'starting' });
    try {
      const begin = await githubBegin(trimmed);
      sessionStorage.setItem(
        pendingStorageKey,
        JSON.stringify({ handoff_id: begin.handoff_id, repository: trimmed } satisfies PendingHandoff),
      );
      // A full navigation: the installation happens on AuthScope's origin.
      window.location.assign(begin.installation_url);
    } catch (err) {
      const message = err instanceof ApiError ? err.title : 'Could not start the connection.';
      setState({ kind: 'error', message });
    }
  }

  if (stored) {
    return (
      <section aria-label="GitHub connection">
        <h2>GitHub connection</h2>
        <ConnectionView connection={stored} />
        <button type="button" onClick={disconnect}>
          Connect a different repository
        </button>
      </section>
    );
  }

  return (
    <section aria-label="GitHub connection">
      <h2>GitHub connection</h2>
      {state.kind === 'error' && (
        <p role="alert">
          {state.message}{' '}
          <button type="button" onClick={() => setState({ kind: 'idle' })}>
            Try again
          </button>
        </p>
      )}
      <form
        onSubmit={(e) => {
          e.preventDefault();
          void start();
        }}
      >
        <label>
          Repository (owner/name)
          <input
            type="text"
            value={repository}
            onChange={(e) => setRepository(e.target.value)}
            placeholder="octo-org/my-repo"
            autoComplete="off"
            spellCheck={false}
            disabled={state.kind === 'starting'}
          />
        </label>
        {validation && (
          <p role="alert">{validation}</p>
        )}
        <button type="submit" disabled={state.kind === 'starting'}>
          {state.kind === 'starting' ? 'Starting…' : 'Connect repository'}
        </button>
      </form>
      <p>
        Connecting opens AuthScope, which hosts the GitHub App installation.
        OPE never sees your GitHub credentials.
      </p>
    </section>
  );
}

type CompleteState =
  | { kind: 'finishing' }
  | { kind: 'connected'; connection: Connection }
  | { kind: 'error'; message: string; canRetry: boolean };

// GitHubConnectionComplete serves the fixed completion path after the
// AuthScope redirect. It finishes the pending handoff with the original
// founder session and renders the persisted connection: immutable
// workspace and repository identity, installation, permission status, and
// the enforcement posture for issue import. When this page load holds no
// CSRF token (the redirect round-trip drops in-memory state), it asks for
// a fresh passkey sign-in first; the token is never written to storage.
export function GitHubConnectionComplete({
  csrfToken,
  workspaceId,
  hostname,
  onAuthenticated,
  onConnected,
}: {
  csrfToken: string | null;
  workspaceId: string;
  hostname: string;
  onAuthenticated: (token: string) => void;
  onConnected: (c: Connection) => void;
}) {
  const [state, setState] = useState<CompleteState>({ kind: 'finishing' });
  const attempted = useRef(false);

  function finish() {
    const pending = readPending();
    if (!pending) {
      setState({
        kind: 'error',
        message: 'No pending GitHub connection found. Start a new connection.',
        canRetry: false,
      });
      return;
    }
    setState({ kind: 'finishing' });
    githubFinish(pending.handoff_id)
      .then((connection) => {
        clearPending();
        sessionStorage.setItem(connectionStorageKey, JSON.stringify(connection));
        setState({ kind: 'connected', connection });
        onConnected(connection);
      })
      .catch((err: unknown) => {
        const message = err instanceof ApiError ? err.title : 'Could not finish the connection.';
        // Keep the pending handoff for retry unless it is gone server-side.
        const gone = err instanceof ApiError && (err.status === 404 || err.status === 400);
        if (gone) clearPending();
        setState({ kind: 'error', message, canRetry: !gone });
      });
  }

  useEffect(() => {
    if (!csrfToken || attempted.current) return;
    attempted.current = true;
    finish();
  }, [csrfToken]);

  function retry() {
    attempted.current = true;
    finish();
  }

  function startOver() {
    clearPending();
    window.location.assign('/');
  }

  if (!csrfToken) {
    return (
      <main>
        <h1>Finish connecting GitHub</h1>
        <p>
          The installation round-trip cleared this page&apos;s sign-in. Sign in
          again to finish connecting the repository.
        </p>
        <PasskeySetup
          initialPhase="login"
          workspaceId={workspaceId}
          hostname={hostname}
          onAuthenticated={onAuthenticated}
        />
      </main>
    );
  }

  if (state.kind === 'finishing') {
    return (
      <main>
        <h1>Finish connecting GitHub</h1>
        <p>Finishing the installation…</p>
      </main>
    );
  }

  if (state.kind === 'error') {
    return (
      <main>
        <h1>Finish connecting GitHub</h1>
        <p role="alert">{state.message}</p>
        {state.canRetry && (
          <button type="button" onClick={retry}>
            Retry
          </button>
        )}{' '}
        <button type="button" onClick={startOver}>
          Start over
        </button>
      </main>
    );
  }

  const c = state.connection;
  return (
    <main>
      <h1>GitHub connected</h1>
      <ConnectionView connection={c} />
      <button type="button" onClick={startOver}>
        Back to workspace
      </button>
    </main>
  );
}

// ConnectionView renders the persisted connection. Every value shown is
// server-verified identity or status metadata; no credential material is
// ever rendered.
export function ConnectionView({ connection }: { connection: Connection }) {
  return (
    <section aria-label="GitHub connection details">
      <dl>
        <dt>Workspace</dt>
        <dd>{connection.workspace_id}</dd>
        <dt>Repository</dt>
        <dd>{connection.repository_name}</dd>
        <dt>Repository ID</dt>
        <dd>{connection.repository_id}</dd>
        <dt>Installation ID</dt>
        <dd>{connection.installation_id}</dd>
        <dt>Permission status</dt>
        <dd>{connection.permission_status}</dd>
        <dt>Verified at</dt>
        <dd>{connection.verified_at}</dd>
      </dl>
      <p>
        Enforcement: every issue import re-verifies the repository binding
        against its immutable ID and checks workflow posture. A risky
        posture blocks Authorize until the workflows are fixed.
      </p>
    </section>
  );
}
