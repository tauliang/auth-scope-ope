import { useEffect, useState } from 'react';
import { fetchBootstrap, ApiError, setCsrfToken as setClientCsrfToken } from './shared/api/client';
import type { BootstrapResponse, GitHubConnection, GitHubIssueSnapshot } from './shared/api/generated';
import PasskeySetup, { type SetupInitialPhase } from './auth/PasskeySetup';
import {
  GitHubConnectionComplete,
  GitHubConnectionStart,
  githubCompletionPath,
} from './features/connect/GitHubConnection';
import IssuePicker from './features/authorize/IssuePicker';
import { MissionPassAuthorize } from './features/authorize/MissionPassReview';

type LoadState =
  | { kind: 'loading' }
  | { kind: 'error'; message: string }
  | { kind: 'ready'; bootstrap: BootstrapResponse };

// AuthenticatedApp renders the product once the founder holds a live
// session. The CSRF token is published to the API client in memory so
// state-changing requests attach it as X-CSRF-Token; it is never written
// to browser storage.
function AuthenticatedApp({ bootstrap, csrfToken }: { bootstrap: BootstrapResponse; csrfToken: string }) {
  const [connection, setConnection] = useState<GitHubConnection | null>(null);
  const [authorized, setAuthorized] = useState<GitHubIssueSnapshot | null>(null);

  useEffect(() => {
    setClientCsrfToken(csrfToken);
    return () => setClientCsrfToken(null);
  }, [csrfToken]);

  return (
    <main>
      <h1>AuthScope OPE</h1>
      <section aria-label="enrollment">
        <h2>Enrollment</h2>
        <p>Founder enrolled.</p>
      </section>
      <section aria-label="workspace">
        <h2>Workspace</h2>
        {bootstrap.workspace ? (
          <dl>
            <dt>Workspace ID</dt>
            <dd>{bootstrap.workspace.workspace_id}</dd>
            <dt>Hostname</dt>
            <dd>{bootstrap.workspace.hostname}</dd>
          </dl>
        ) : (
          <p>No workspace bound yet.</p>
        )}
      </section>
      <section aria-label="compatibility">
        <h2>Authority compatibility</h2>
        <p>
          {bootstrap.compatibility.status === 'ready' ? 'Compatible' : 'Not compatible'} with core{' '}
          {bootstrap.compatibility.core_version}.
        </p>
        {bootstrap.compatibility.problems?.map((problem) => (
          <p key={problem} role="alert">
            {problem}
          </p>
        ))}
      </section>
      <section aria-label="authority">
        <h2>Authority</h2>
        <ul>
          {bootstrap.authority_labels.map((label) => (
            <li key={label}>{label}</li>
          ))}
        </ul>
      </section>
      <GitHubConnectionStart onConnected={setConnection} />
      <IssuePicker connection={connection} onAuthorize={setAuthorized} />
      {authorized && connection && (
        <MissionPassAuthorize
          connectionId={connection.connection_id}
          issueNumber={authorized.issue_number}
          onBack={() => setAuthorized(null)}
        />
      )}
    </main>
  );
}

// App is the product shell. It loads the first-paint bootstrap state and
// routes to founder enrollment, passkey unlock, or the authenticated
// product. The session CSRF token is held in memory for the lifetime of
// the page and never written to browser storage.
export default function App() {
  const [state, setState] = useState<LoadState>({ kind: 'loading' });
  const [csrfToken, setCsrfToken] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    fetchBootstrap()
      .then((bootstrap) => {
        if (!cancelled) setState({ kind: 'ready', bootstrap });
      })
      .catch((err: unknown) => {
        if (!cancelled) {
          const message = err instanceof ApiError ? `upstream ${err.status}` : 'unreachable';
          setState({ kind: 'error', message });
        }
      });
    return () => {
      cancelled = true;
    };
  }, []);

  function refreshAfterAuth(token: string) {
    setCsrfToken(token);
    // Re-read first paint: the session cookie is now set, so the server
    // reports the authenticated state.
    fetchBootstrap()
      .then((next) => setState({ kind: 'ready', bootstrap: next }))
      .catch((err: unknown) => {
        const message = err instanceof ApiError ? `upstream ${err.status}` : 'unreachable';
        setState({ kind: 'error', message });
      });
  }

  if (state.kind === 'loading') return <main><h1>AuthScope OPE</h1><p>Connecting…</p></main>;
  if (state.kind === 'error')
    return (
      <main>
        <h1>AuthScope OPE</h1>
        <p role="alert">Could not reach the local service ({state.message}).</p>
      </main>
    );

  const { bootstrap } = state;

  function setupPhase(): SetupInitialPhase | null {
    switch (bootstrap.enrollment_state) {
      case 'needs_bootstrap':
        return 'code';
      case 'needs_recovery_method':
        return 'choose-recovery';
      case 'locked':
        return 'login';
      case 'authenticated':
        return null;
    }
  }

  const setup = (phase: SetupInitialPhase) => (
    <PasskeySetup
      initialPhase={phase}
      workspaceId={bootstrap.workspace?.workspace_id ?? 'unknown'}
      hostname={bootstrap.workspace?.hostname ?? 'unknown'}
      onAuthenticated={refreshAfterAuth}
    />
  );

  // The AuthScope installation redirect lands here. It needs the same
  // authenticated session plus the in-memory CSRF token to finish the
  // handoff; without them the login flow below runs first and returns
  // here afterwards.
  const onCompletionPath =
    typeof window !== 'undefined' && window.location.pathname === githubCompletionPath;
  if (onCompletionPath && bootstrap.enrollment_state === 'authenticated' && csrfToken) {
    return (
      <GitHubConnectionComplete
        csrfToken={csrfToken}
        workspaceId={bootstrap.workspace?.workspace_id ?? 'unknown'}
        hostname={bootstrap.workspace?.hostname ?? 'unknown'}
        onAuthenticated={refreshAfterAuth}
        onConnected={() => {}}
      />
    );
  }

  // An authenticated bootstrap plus a remembered CSRF token means this
  // page holds a live founder session.
  if (bootstrap.enrollment_state === 'authenticated' && csrfToken) {
    return <AuthenticatedApp bootstrap={bootstrap} csrfToken={csrfToken} />;
  }

  const phase = setupPhase();
  if (phase) {
    return setup(phase);
  }

  // The server reports an authenticated session but this page load holds
  // no CSRF token in memory (for example after a refresh): start a fresh
  // passkey login so the token is re-issued to memory.
  return setup('login');
}
