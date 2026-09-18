import { useEffect, useState } from 'react';
import { fetchBootstrap, ApiError } from './shared/api/client';
import type { BootstrapResponse } from './shared/api/generated';
import PasskeySetup, { type SetupInitialPhase } from './auth/PasskeySetup';

type LoadState =
  | { kind: 'loading' }
  | { kind: 'error'; message: string }
  | { kind: 'ready'; bootstrap: BootstrapResponse };

// AuthenticatedApp renders the product once the founder holds a live
// session. The CSRF token is accepted here so the type system keeps it in
// memory, attached to the session it belongs to; later tasks thread it
// into state-changing requests via the X-CSRF-Token header.
function AuthenticatedApp({ bootstrap, csrfToken }: { bootstrap: BootstrapResponse; csrfToken: string }) {
  void csrfToken;
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
