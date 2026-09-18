import { useCallback, useEffect, useState } from 'react';
import { setCsrfToken as setClientCsrfToken } from '../../shared/api/client';
import type { BootstrapResponse, GitHubConnection as Connection } from '../../shared/api/generated';
import {
  GitHubConnectionComplete,
  GitHubConnectionStart,
  githubCompletionPath,
} from './GitHubConnection';
import { ProblemPanel, problemPanelForError } from '../../shared/components/ProblemPanel';

// ConnectPage is the Connect screen: enrollment state, the immutable
// instance workspace binding, AuthScope compatibility, the GitHub
// repository binding, and the entry to issue selection. It owns the
// GitHub installation completion path (/connect/github/done): the
// AuthScope redirect lands there and the completion step finishes the
// handoff with the founder session and CSRF token.
export function ConnectPage({
  bootstrap,
  csrfToken,
  onAuthenticated,
}: {
  bootstrap: BootstrapResponse;
  csrfToken: string;
  onAuthenticated: (token: string) => void;
}) {
  const [, setConnection] = useState<Connection | null>(null);
  const onCompletionPath =
    typeof window !== 'undefined' && window.location.pathname === githubCompletionPath;

  useEffect(() => {
    setClientCsrfToken(csrfToken);
    return () => setClientCsrfToken(null);
  }, [csrfToken]);

  const handleConnected = useCallback((c: Connection | null) => {
    setConnection(c);
  }, []);

  if (onCompletionPath) {
    return (
      <GitHubConnectionComplete
        csrfToken={csrfToken}
        workspaceId={bootstrap.workspace?.workspace_id ?? 'unknown'}
        hostname={bootstrap.workspace?.hostname ?? 'unknown'}
        onAuthenticated={onAuthenticated}
        onConnected={handleConnected}
      />
    );
  }

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
        <p>
          This instance is bound to exactly one workspace. There is no
          workspace switcher; a different workspace needs a separate
          instance.
        </p>
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
      <GitHubConnectionStart onConnected={handleConnected} />
      <section aria-label="next step">
        <h2>Next step</h2>
        <p>
          <a href="/authorize">Select an issue to authorize</a>
        </p>
      </section>
    </main>
  );
}

// ConnectErrorPage renders a typed bootstrap failure with its blocked
// condition and safe recovery action.
export function ConnectErrorPage({ error }: { error: unknown }) {
  const panel = problemPanelForError(error);
  return (
    <main>
      <h1>AuthScope OPE</h1>
      <ProblemPanel title={panel.title} detail={panel.detail} />
    </main>
  );
}

export default ConnectPage;
