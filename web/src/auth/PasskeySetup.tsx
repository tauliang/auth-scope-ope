import { useState } from 'react';
import {
  ApiError,
  authBootstrapBegin,
  authBootstrapComplete,
  authBootstrapRecoveryBegin,
  authBootstrapRegisterBegin,
  authBootstrapRegisterFinish,
  authLoginBegin,
  authLoginFinish,
} from '../shared/api/client';
import { createPasskey, getPasskey } from '../shared/webauthn';

// PasskeySetup enrolls the founder or unlocks the product with a passkey.
// It mirrors the server enrollment states: a fresh instance starts at the
// terminal-code step, a ceremony that already registered its first passkey
// resumes at recovery choice, and an enrolled instance starts at login.
// Passkey material, challenges, and the CSRF token live only in memory;
// this component never writes to browser storage.
export type SetupInitialPhase = 'code' | 'choose-recovery' | 'login';

interface PasskeySetupProps {
  initialPhase: SetupInitialPhase;
  workspaceId: string;
  hostname: string;
  onAuthenticated: (csrfToken: string) => void;
}

type Phase =
  | { kind: 'code' }
  | { kind: 'register-passkey' }
  | { kind: 'choose-recovery' }
  | { kind: 'register-recovery-passkey' }
  | { kind: 'offline-key'; key: string }
  | { kind: 'login' };

function friendlyError(err: unknown): string {
  if (err instanceof ApiError) return err.title;
  if (err instanceof Error) return err.message;
  return 'Something went wrong.';
}

export default function PasskeySetup({ initialPhase, workspaceId, hostname, onAuthenticated }: PasskeySetupProps) {
  const [phase, setPhase] = useState<Phase>(
    initialPhase === 'login'
      ? { kind: 'login' }
      : initialPhase === 'choose-recovery'
        ? { kind: 'choose-recovery' }
        : { kind: 'code' },
  );
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [code, setCode] = useState('');
  const [displayName, setDisplayName] = useState('');
  const [keySaved, setKeySaved] = useState(false);

  async function run(fn: () => Promise<void>) {
    if (busy) return;
    setBusy(true);
    setError(null);
    try {
      await fn();
    } catch (err) {
      setError(friendlyError(err));
    } finally {
      setBusy(false);
    }
  }

  function submitCode() {
    void run(async () => {
      await authBootstrapBegin(code.trim());
      setPhase({ kind: 'register-passkey' });
    });
  }

  function registerFirstPasskey() {
    void run(async () => {
      const begin = await authBootstrapRegisterBegin(displayName.trim() || undefined);
      const response = await createPasskey(begin.options);
      await authBootstrapRegisterFinish(begin.ceremony_id, response);
      setPhase({ kind: 'choose-recovery' });
    });
  }

  function recoverWithPasskey() {
    void run(async () => {
      setPhase({ kind: 'register-recovery-passkey' });
      const begin = await authBootstrapRecoveryBegin('passkey');
      if (!begin.ceremony_id) {
        throw new Error('The server did not issue a recovery ceremony.');
      }
      const response = await createPasskey(begin.options);
      await authBootstrapRegisterFinish(begin.ceremony_id, response);
      const done = await authBootstrapComplete();
      onAuthenticated(done.csrf_token);
    });
  }

  function recoverWithOfflineKey() {
    void run(async () => {
      const begin = await authBootstrapRecoveryBegin('offline_key');
      if (!begin.recovery_key) {
        throw new Error('The server did not issue a recovery key.');
      }
      setKeySaved(false);
      setPhase({ kind: 'offline-key', key: begin.recovery_key });
    });
  }

  function completeWithOfflineKey(key: string) {
    void run(async () => {
      const done = await authBootstrapComplete(key);
      onAuthenticated(done.csrf_token);
    });
  }

  function login() {
    void run(async () => {
      const begin = await authLoginBegin();
      const response = await getPasskey(begin.options);
      const done = await authLoginFinish(begin.ceremony_id, response);
      onAuthenticated(done.csrf_token);
    });
  }

  function downloadKey(key: string) {
    const blob = new Blob([`AuthScope OPE offline recovery key\nWorkspace: ${workspaceId}\n\n${key}\n`], {
      type: 'text/plain',
    });
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement('a');
    anchor.href = url;
    anchor.download = 'authscope-ope-recovery-key.txt';
    document.body.appendChild(anchor);
    anchor.click();
    anchor.remove();
    URL.revokeObjectURL(url);
  }

  return (
    <main>
      <h1>AuthScope OPE</h1>
      <p>
        Workspace <code>{workspaceId}</code> on <code>{hostname}</code>
      </p>
      {error && <p role="alert">{error}</p>}

      {phase.kind === 'code' && (
        <section aria-label="enrollment code">
          <h2>Enroll this instance</h2>
          <p>Enter the one-time code printed on the server terminal to begin founder enrollment.</p>
          <label>
            Terminal code
            <input
              type="text"
              value={code}
              onChange={(e) => setCode(e.target.value)}
              autoComplete="off"
              spellCheck={false}
            />
          </label>
          <button type="button" disabled={busy || code.trim() === ''} onClick={submitCode}>
            Begin enrollment
          </button>
        </section>
      )}

      {phase.kind === 'register-passkey' && (
        <section aria-label="register passkey">
          <h2>Register your passkey</h2>
          <p>Your device will ask you to create a passkey for this instance.</p>
          <label>
            Display name (optional)
            <input
              type="text"
              value={displayName}
              onChange={(e) => setDisplayName(e.target.value)}
              placeholder="Founder"
              autoComplete="off"
            />
          </label>
          <button type="button" disabled={busy} onClick={registerFirstPasskey}>
            Register passkey
          </button>
        </section>
      )}

      {phase.kind === 'choose-recovery' && (
        <section aria-label="choose recovery method">
          <h2>Choose a recovery method</h2>
          <p>
            Enrollment requires an independent recovery method in addition to your passkey. Pick
            one:
          </p>
          <button type="button" disabled={busy} onClick={recoverWithPasskey}>
            Use a second passkey
          </button>
          <button type="button" disabled={busy} onClick={recoverWithOfflineKey}>
            Use an offline recovery key
          </button>
        </section>
      )}

      {phase.kind === 'register-recovery-passkey' && (
        <section aria-label="register recovery passkey">
          <h2>Register your recovery passkey</h2>
          <p>Use a different passkey than your first one, for example on another device.</p>
          <p>Waiting for your device…</p>
        </section>
      )}

      {phase.kind === 'offline-key' && (
        <section aria-label="offline recovery key">
          <h2>Save your offline recovery key</h2>
          <p>
            This key is shown exactly once. Store it somewhere safe, separate from your devices.
            There is no way to view it again after enrollment completes.
          </p>
          <p>
            <code>{phase.key}</code>
          </p>
          <button type="button" disabled={busy} onClick={() => downloadKey(phase.key)}>
            Download recovery key
          </button>
          <label>
            <input
              type="checkbox"
              checked={keySaved}
              onChange={(e) => setKeySaved(e.target.checked)}
            />
            I have stored this key securely
          </label>
          <button type="button" disabled={busy || !keySaved} onClick={() => completeWithOfflineKey(phase.key)}>
            Complete enrollment
          </button>
        </section>
      )}

      {phase.kind === 'login' && (
        <section aria-label="unlock">
          <h2>Unlock</h2>
          <p>Authenticate with your passkey to continue.</p>
          <button type="button" disabled={busy} onClick={login}>
            Authenticate with passkey
          </button>
        </section>
      )}
    </main>
  );
}
