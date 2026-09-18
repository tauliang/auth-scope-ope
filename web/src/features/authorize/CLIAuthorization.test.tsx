import { describe, expect, it, vi, beforeEach } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { CLIAuthorization, cliAuthorizationIdFromPath } from './CLIAuthorization';
import { ApiError } from '../../shared/api/client';
import * as client from '../../shared/api/client';
import { getPasskey } from '../../shared/webauthn';
import type { CLIAuthorizationApproveBeginResponse } from '../../shared/api/generated';

vi.mock('../../shared/api/client', async (importOriginal) => {
  const original = await importOriginal<typeof import('../../shared/api/client')>();
  return {
    ...original,
    beginCliAuthorization: vi.fn(),
    finishCliAuthorization: vi.fn(),
    newIdempotencyKey: () => 'test-key-1',
  };
});

vi.mock('../../shared/webauthn', () => ({
  getPasskey: vi.fn(),
}));

function beginPayload(): CLIAuthorizationApproveBeginResponse {
  return {
    challenge_id: 'challenge-1',
    assertion_options: { publicKey: { challenge: 'abc' } },
    pass_id: 'pass-1',
    repository_name: 'octo-org/host',
    issue_number: 42,
    proposal_digest: `sha256:${'f'.repeat(64)}`,
    invocation_digest: `sha256:${'d'.repeat(64)}`,
    agent_kit_id: 'authscope-agent-kit',
    agent_kit_version: '1.0.0',
    runner_arguments: ['authscope-agent-run', '--mission'],
  };
}

beforeEach(() => {
  vi.mocked(client.beginCliAuthorization).mockReset();
  vi.mocked(client.finishCliAuthorization).mockReset();
  vi.mocked(getPasskey).mockReset();
});

describe('cliAuthorizationIdFromPath', () => {
  it('extracts the id from the transient route', () => {
    expect(cliAuthorizationIdFromPath('/authorize/cli/authz-1')).toBe('authz-1');
  });

  it('returns null for other paths', () => {
    expect(cliAuthorizationIdFromPath('/')).toBeNull();
    expect(cliAuthorizationIdFromPath('/authorize/cli/')).toBeNull();
    expect(cliAuthorizationIdFromPath('/connect/github/done')).toBeNull();
  });
});

describe('CLIAuthorization', () => {
  it('shows the exact launch bindings and hands back to the CLI after finish', async () => {
    const user = userEvent.setup();
    const begun = beginPayload();
    vi.mocked(client.beginCliAuthorization).mockResolvedValue(begun);
    vi.mocked(getPasskey).mockResolvedValue({ id: 'cred-1' });
    vi.mocked(client.finishCliAuthorization).mockResolvedValue(undefined);

    render(<CLIAuthorization authorizationId="authz-1" />);

    await waitFor(() => {
      expect(screen.getByText('octo-org/host')).toBeInTheDocument();
    });
    // Task 8: the page shows the exact pinned launch bindings.
    expect(screen.getByText('#42')).toBeInTheDocument();
    expect(screen.getByText('authscope-agent-kit')).toBeInTheDocument();
    expect(screen.getByText('authscope-agent-run --mission')).toBeInTheDocument();
    expect(screen.getByText(`sha256:${'d'.repeat(64)}`)).toBeInTheDocument();

    await user.click(screen.getByRole('button', { name: 'Authorize launch with passkey' }));

    await waitFor(() => {
      expect(getPasskey).toHaveBeenCalledWith(begun.assertion_options);
    });
    await waitFor(() => {
      expect(client.finishCliAuthorization).toHaveBeenCalledWith(
        'authz-1',
        'challenge-1',
        { id: 'cred-1' },
        'test-key-1',
      );
    });
    // Task 8: after finish the page shows only "Return to the CLI."
    await waitFor(() => {
      expect(screen.getByRole('status')).toHaveTextContent('Return to the CLI.');
    });
    expect(screen.queryByText('octo-org/host')).not.toBeInTheDocument();
  });

  it('reports an expired authorization without retry', async () => {
    vi.mocked(client.beginCliAuthorization).mockRejectedValue(new ApiError(404, 'not found', 'Not found'));

    render(<CLIAuthorization authorizationId="authz-stale" />);

    await waitFor(() => {
      expect(screen.getByRole('alert')).toHaveTextContent('already expired');
    });
    expect(screen.queryByRole('button', { name: 'Try again' })).not.toBeInTheDocument();
  });

  it('reports a conflict with the server title when present', async () => {
    vi.mocked(client.beginCliAuthorization).mockRejectedValue(
      new ApiError(409, 'conflict', 'The launch details changed.'),
    );

    render(<CLIAuthorization authorizationId="authz-changed" />);

    await waitFor(() => {
      expect(screen.getByRole('alert')).toHaveTextContent('The launch details changed.');
    });
  });

  it('reports a conflict with a fallback message when the server has no title', async () => {
    vi.mocked(client.beginCliAuthorization).mockRejectedValue(new ApiError(409, 'conflict', ''));

    render(<CLIAuthorization authorizationId="authz-changed" />);

    await waitFor(() => {
      expect(screen.getByRole('alert')).toHaveTextContent('already used');
    });
  });

  it('offers retry on a server error and retries the begin', async () => {
    const user = userEvent.setup();
    vi.mocked(client.beginCliAuthorization)
      .mockRejectedValueOnce(new ApiError(503, 'unavailable', ''))
      .mockResolvedValueOnce(beginPayload());

    render(<CLIAuthorization authorizationId="authz-1" />);

    await waitFor(() => {
      expect(screen.getByRole('alert')).toHaveTextContent('(503)');
    });
    await user.click(screen.getByRole('button', { name: 'Try again' }));

    await waitFor(() => {
      expect(screen.getByText('octo-org/host')).toBeInTheDocument();
    });
    expect(client.beginCliAuthorization).toHaveBeenCalledTimes(2);
  });

  it('reports a non-API failure with a generic message', async () => {
    vi.mocked(client.beginCliAuthorization).mockRejectedValue(new Error('network down'));

    render(<CLIAuthorization authorizationId="authz-1" />);

    await waitFor(() => {
      expect(screen.getByRole('alert')).toHaveTextContent('could not be completed');
    });
    expect(screen.queryByRole('button', { name: 'Try again' })).not.toBeInTheDocument();
  });

  it('shows a verifying state while the finish is in flight', async () => {
    const user = userEvent.setup();
    let resolveFinish!: () => void;
    vi.mocked(client.beginCliAuthorization).mockResolvedValue(beginPayload());
    vi.mocked(getPasskey).mockResolvedValue({ id: 'cred-1' });
    vi.mocked(client.finishCliAuthorization).mockImplementation(
      () => new Promise<void>((resolve) => { resolveFinish = resolve; }),
    );

    render(<CLIAuthorization authorizationId="authz-1" />);
    await waitFor(() => {
      expect(screen.getByText('octo-org/host')).toBeInTheDocument();
    });
    await user.click(screen.getByRole('button', { name: 'Authorize launch with passkey' }));

    await waitFor(() => {
      expect(screen.getByText(/handing the launch back to the CLI/)).toBeInTheDocument();
    });
    resolveFinish();
    await waitFor(() => {
      expect(screen.getByRole('status')).toHaveTextContent('Return to the CLI.');
    });
  });

  it('ignores a late begin after unmount', async () => {
    let resolveBegin!: (value: CLIAuthorizationApproveBeginResponse) => void;
    vi.mocked(client.beginCliAuthorization).mockImplementation(
      () => new Promise<CLIAuthorizationApproveBeginResponse>((resolve) => { resolveBegin = resolve; }),
    );

    const { unmount } = render(<CLIAuthorization authorizationId="authz-1" />);
    unmount();
    resolveBegin(beginPayload());
    // Flushing the late resolution must not throw or warn about a state
    // update on an unmounted component.
    await Promise.resolve();
    expect(client.beginCliAuthorization).toHaveBeenCalledTimes(1);
  });

  it('never renders secret material', async () => {
    const user = userEvent.setup();
    vi.mocked(client.beginCliAuthorization).mockResolvedValue(beginPayload());
    vi.mocked(getPasskey).mockResolvedValue({ id: 'cred-1' });
    vi.mocked(client.finishCliAuthorization).mockResolvedValue(undefined);

    const { container } = render(<CLIAuthorization authorizationId="authz-1" />);
    await waitFor(() => {
      expect(screen.getByText('octo-org/host')).toBeInTheDocument();
    });
    await user.click(screen.getByRole('button', { name: 'Authorize launch with passkey' }));
    await waitFor(() => {
      expect(screen.getByRole('status')).toHaveTextContent('Return to the CLI.');
    });
    const text = (container.textContent ?? '').toLowerCase();
    expect(text).not.toContain('verifier');
    expect(text).not.toContain('sealed');
    expect(text).not.toMatch(/code_challenge/);
  });
});
