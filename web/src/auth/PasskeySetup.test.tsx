import { describe, expect, it, vi, beforeEach, afterEach } from 'vitest';
import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import PasskeySetup from './PasskeySetup';
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

vi.mock('../shared/api/client', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../shared/api/client')>();
  return {
    ...actual,
    authBootstrapBegin: vi.fn(),
    authBootstrapRegisterBegin: vi.fn(),
    authBootstrapRegisterFinish: vi.fn(),
    authBootstrapRecoveryBegin: vi.fn(),
    authBootstrapComplete: vi.fn(),
    authLoginBegin: vi.fn(),
    authLoginFinish: vi.fn(),
  };
});

vi.mock('../shared/webauthn', () => ({
  createPasskey: vi.fn(),
  getPasskey: vi.fn(),
}));

const props = {
  workspaceId: 'ws-test',
  hostname: 'ope.example.com',
  onAuthenticated: vi.fn(),
};

describe('PasskeySetup', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it('starts at the terminal code step for a fresh instance', async () => {
    const user = userEvent.setup();
    vi.mocked(authBootstrapBegin).mockResolvedValue({ expires_at: 'x' });
    render(<PasskeySetup {...props} initialPhase="code" onAuthenticated={vi.fn()} />);

    expect(screen.getByLabelText(/terminal code/i)).toBeInTheDocument();
    await user.type(screen.getByLabelText(/terminal code/i), '  abc123  ');
    await user.click(screen.getByRole('button', { name: /begin enrollment/i }));

    expect(authBootstrapBegin).toHaveBeenCalledWith('abc123');
    expect(await screen.findByRole('button', { name: /register passkey/i })).toBeInTheDocument();
  });

  it('shows the server problem title when the code is wrong', async () => {
    const user = userEvent.setup();
    vi.mocked(authBootstrapBegin).mockRejectedValue(new ApiError(401, 'x', 'invalid bootstrap code'));
    render(<PasskeySetup {...props} initialPhase="code" onAuthenticated={vi.fn()} />);

    await user.type(screen.getByLabelText(/terminal code/i), 'wrong');
    await user.click(screen.getByRole('button', { name: /begin enrollment/i }));
    expect(await screen.findByRole('alert')).toHaveTextContent('invalid bootstrap code');
  });

  it('registers the first passkey then offers recovery choices', async () => {
    const user = userEvent.setup();
    const onAuthenticated = vi.fn();
    vi.mocked(authBootstrapBegin).mockResolvedValue({ expires_at: 'x' });
    vi.mocked(authBootstrapRegisterBegin).mockResolvedValue({ ceremony_id: 'c1', options: { publicKey: {} } });
    vi.mocked(createPasskey).mockResolvedValue({ id: 'cred-1' });
    vi.mocked(authBootstrapRegisterFinish).mockResolvedValue({ credential_id: 'cred-1' });

    render(<PasskeySetup {...props} initialPhase="code" onAuthenticated={onAuthenticated} />);
    await user.type(screen.getByLabelText(/terminal code/i), 'code');
    await user.click(screen.getByRole('button', { name: /begin enrollment/i }));
    await user.type(screen.getByLabelText(/display name/i), 'Shengquan');
    await user.click(await screen.findByRole('button', { name: /register passkey/i }));

    expect(authBootstrapRegisterBegin).toHaveBeenCalledWith('Shengquan');
    expect(createPasskey).toHaveBeenCalledWith({ publicKey: {} });
    expect(authBootstrapRegisterFinish).toHaveBeenCalledWith('c1', { id: 'cred-1' });
    expect(await screen.findByRole('button', { name: /use a second passkey/i })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /use an offline recovery key/i })).toBeInTheDocument();
  });

  it('completes enrollment with a second passkey', async () => {
    const user = userEvent.setup();
    const onAuthenticated = vi.fn();
    vi.mocked(authBootstrapRecoveryBegin).mockResolvedValue({
      method: 'passkey',
      ceremony_id: 'c2',
      options: { publicKey: {} },
    });
    vi.mocked(createPasskey).mockResolvedValue({ id: 'cred-2' });
    vi.mocked(authBootstrapRegisterFinish).mockResolvedValue({ credential_id: 'cred-2' });
    vi.mocked(authBootstrapComplete).mockResolvedValue({ csrf_token: 'csrf-1' });

    render(<PasskeySetup {...props} initialPhase="choose-recovery" onAuthenticated={onAuthenticated} />);
    await user.click(screen.getByRole('button', { name: /use a second passkey/i }));

    expect(authBootstrapRecoveryBegin).toHaveBeenCalledWith('passkey');
    expect(authBootstrapRegisterFinish).toHaveBeenCalledWith('c2', { id: 'cred-2' });
    expect(authBootstrapComplete).toHaveBeenCalledWith();
    await vi.waitFor(() => expect(onAuthenticated).toHaveBeenCalledWith('csrf-1'));
  });

  it('completes enrollment with an offline recovery key after confirmation', async () => {
    const user = userEvent.setup();
    const onAuthenticated = vi.fn();
    vi.mocked(authBootstrapRecoveryBegin).mockResolvedValue({
      method: 'offline_key',
      recovery_key: 'rk-abc-123',
    });
    vi.mocked(authBootstrapComplete).mockResolvedValue({ csrf_token: 'csrf-2' });

    // URL.createObjectURL is not implemented in jsdom; stub it for download.
    const createObjectURL = vi.fn().mockReturnValue('blob:fake');
    const revokeObjectURL = vi.fn();
    vi.stubGlobal('URL', { createObjectURL, revokeObjectURL });

    render(<PasskeySetup {...props} initialPhase="choose-recovery" onAuthenticated={onAuthenticated} />);
    await user.click(screen.getByRole('button', { name: /use an offline recovery key/i }));

    expect(await screen.findByText('rk-abc-123')).toBeInTheDocument();
    const complete = screen.getByRole('button', { name: /complete enrollment/i });
    expect(complete).toBeDisabled();

    await user.click(screen.getByRole('button', { name: /download recovery key/i }));
    expect(createObjectURL).toHaveBeenCalled();

    await user.click(screen.getByLabelText(/i have stored this key securely/i));
    expect(complete).toBeEnabled();
    await user.click(complete);

    expect(authBootstrapComplete).toHaveBeenCalledWith('rk-abc-123');
    await vi.waitFor(() => expect(onAuthenticated).toHaveBeenCalledWith('csrf-2'));
  });

  it('resumes at recovery choice for a ceremony with a registered passkey', () => {
    render(<PasskeySetup {...props} initialPhase="choose-recovery" onAuthenticated={vi.fn()} />);
    expect(screen.getByRole('button', { name: /use a second passkey/i })).toBeInTheDocument();
  });

  it('unlocks with a passkey in the locked state', async () => {
    const user = userEvent.setup();
    const onAuthenticated = vi.fn();
    vi.mocked(authLoginBegin).mockResolvedValue({ ceremony_id: 'lc1', options: { publicKey: {} } });
    vi.mocked(getPasskey).mockResolvedValue({ id: 'cred-1' });
    vi.mocked(authLoginFinish).mockResolvedValue({ csrf_token: 'csrf-3' });

    render(<PasskeySetup {...props} initialPhase="login" onAuthenticated={onAuthenticated} />);
    await user.click(screen.getByRole('button', { name: /authenticate with passkey/i }));

    expect(getPasskey).toHaveBeenCalledWith({ publicKey: {} });
    expect(authLoginFinish).toHaveBeenCalledWith('lc1', { id: 'cred-1' });
    await vi.waitFor(() => expect(onAuthenticated).toHaveBeenCalledWith('csrf-3'));
  });

  it('shows a friendly message when the browser lacks passkey support', async () => {
    const user = userEvent.setup();
    vi.mocked(authLoginBegin).mockResolvedValue({ ceremony_id: 'lc1', options: {} });
    vi.mocked(getPasskey).mockRejectedValue(new Error('this browser does not support passkeys'));

    render(<PasskeySetup {...props} initialPhase="login" onAuthenticated={vi.fn()} />);
    await user.click(screen.getByRole('button', { name: /authenticate with passkey/i }));
    expect(await screen.findByRole('alert')).toHaveTextContent('this browser does not support passkeys');
  });
});
