import { useEffect, useState } from 'react';
import { fetchBootstrap, ApiError } from './shared/api/client';
import type { BootstrapResponse } from './shared/api/generated';

type LoadState =
  | { kind: 'loading' }
  | { kind: 'error'; message: string }
  | { kind: 'ready'; bootstrap: BootstrapResponse };

// App is the Task 1 vertical shell: it renders the fake-backed bootstrap
// document through the same typed client the later screens use.
export default function App() {
  const [state, setState] = useState<LoadState>({ kind: 'loading' });

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

  if (state.kind === 'loading') return <main><h1>AuthScope OPE</h1><p>Loading…</p></main>;
  if (state.kind === 'error')
    return (
      <main>
        <h1>AuthScope OPE</h1>
        <p role="alert">Could not reach the local service ({state.message}).</p>
      </main>
    );

  const { bootstrap } = state;
  return (
    <main>
      <h1>AuthScope OPE</h1>
      <section aria-label="enrollment">
        <h2>Enrollment</h2>
        <p>{bootstrap.enrolled ? 'Founder enrolled.' : 'No founder enrolled yet.'}</p>
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
