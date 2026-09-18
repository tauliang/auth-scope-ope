import { useEffect, useState } from 'react';
import { fetchBootstrap, ApiError } from './shared/api/client';
import type { BootstrapResponse } from './shared/api/generated';
import PasskeySetup, { type SetupInitialPhase } from './auth/PasskeySetup';
import { ConnectPage } from './features/connect/ConnectPage';
import { AuthorizePage } from './features/authorize/AuthorizePage';
import {
  MissionPage,
  cliRevocationIdFromSearch,
  missionPassIdFromLocation,
} from './features/mission/MissionPage';
import { ProblemPanel } from './shared/components/ProblemPanel';

// Screen is the three-screen OPE journey: Connect, Authorize, Mission.
// Every navigable path resolves to exactly one of these three screens.
export type Screen = 'connect' | 'authorize' | 'mission';

// routeForPath maps a pathname to its screen. The GitHub installation
// completion path (/connect/github/done) belongs to the Connect screen;
// the transient CLI authorization path (/authorize/cli/<id>) belongs to
// the Authorize screen; the mission pass path (/mission/<id>) belongs to
// the Mission screen. Unknown paths fall back to Connect.
export function routeForPath(pathname: string): Screen {
  if (pathname === '/authorize' || pathname.startsWith('/authorize/')) {
    return 'authorize';
  }
  if (pathname === '/mission' || pathname.startsWith('/mission/')) {
    return 'mission';
  }
  return 'connect';
}

type LoadState =
  | { kind: 'loading' }
  | { kind: 'error'; message: string }
  | { kind: 'ready'; bootstrap: BootstrapResponse };

// App is the product shell. It loads the first-paint bootstrap state,
// gates on founder enrollment and passkey unlock, then renders exactly
// one of the three journey screens. The session CSRF token is held in
// memory for the lifetime of the page and never written to browser
// storage.
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

  if (state.kind === 'loading')
    return (
      <main>
        <h1>AuthScope OPE</h1>
        <p>Connecting…</p>
      </main>
    );
  if (state.kind === 'error')
    return (
      <main>
        <h1>AuthScope OPE</h1>
        <ProblemPanel
          title="Could not reach the local service."
          detail={`The service reported ${state.message}. Check that the local service is running, then try once.`}
        />
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
    const screen = routeForPath(window.location.pathname);
    if (screen === 'connect') {
      return (
        <ConnectPage bootstrap={bootstrap} csrfToken={csrfToken} onAuthenticated={refreshAfterAuth} />
      );
    }
    if (screen === 'authorize') {
      return <AuthorizePage />;
    }
    const passId = missionPassIdFromLocation(window.location.pathname, window.location.search);
    if (passId) {
      const cliRevocationId = cliRevocationIdFromSearch(window.location.search);
      return <MissionPage passId={passId} cliRevocationId={cliRevocationId} />;
    }
    return (
      <main>
        <h1>AuthScope OPE</h1>
        <ProblemPanel
          title="No mission pass selected."
          detail="The mission screen needs a pass id. Go back to the Authorize screen and approve a proposal first."
        />
      </main>
    );
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
