import { describe, expect, it, vi, beforeEach } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { RevokeButton } from './RevokeButton';
import { ApiError } from '../../shared/api/client';
import * as client from '../../shared/api/client';
import { getPasskey } from '../../shared/webauthn';
import type { RevocationResult, RevokeBeginResponse } from '../../shared/api/generated';

vi.mock('../../shared/api/client', async (importOriginal) => {
  const original = await importOriginal<typeof import('../../shared/api/client')>();
  return {
    ...original,
    beginRevoke: vi.fn(),
    finishRevoke: vi.fn(),
    newIdempotencyKey: () => 'test-key-1',
  };
});

vi.mock('../../shared/webauthn', () => ({
  getPasskey: vi.fn(),
}));

function beginPayload(): RevokeBeginResponse {
  return {
    challenge_id: 'challenge-1',
    options: { publicKey: { challenge: 'abc' } },
  };
}

function resultPayload(): RevocationResult {
  return {
    pass_id: 'pass-1',
    mission_ref: 'mission-1',
    revoked: true,
    containment: 'acknowledged',
    reason_code: 'founder_requested',
    revoked_at: '2026-09-18T10:00:00Z',
  };
}

beforeEach(() => {
  vi.mocked(client.beginRevoke).mockReset();
  vi.mocked(client.finishRevoke).mockReset();
  vi.mocked(getPasskey).mockReset();
});

describe('RevokeButton', () => {
  it('runs the passkey revocation ceremony and reports the result', async () => {
    const user = userEvent.setup();
    const onRevoked = vi.fn();
    vi.mocked(client.beginRevoke).mockResolvedValue(beginPayload());
    vi.mocked(getPasskey).mockResolvedValue({ id: 'cred-1' });
    vi.mocked(client.finishRevoke).mockResolvedValue(resultPayload());

    render(<RevokeButton passId="pass-1" onRevoked={onRevoked} />);

    await user.click(screen.getByRole('button', { name: 'Revoke mission' }));
    await user.selectOptions(screen.getByLabelText('Reason'), 'safety_concern');
    await user.click(screen.getByRole('button', { name: 'Revoke with passkey' }));

    await waitFor(() => {
      expect(client.beginRevoke).toHaveBeenCalledWith('pass-1', 'safety_concern', 'test-key-1');
    });
    await waitFor(() => {
      expect(getPasskey).toHaveBeenCalledWith({ publicKey: { challenge: 'abc' } });
    });
    await waitFor(() => {
      expect(client.finishRevoke).toHaveBeenCalledWith(
        'pass-1',
        'challenge-1',
        { id: 'cred-1' },
        'test-key-1',
        undefined,
      );
    });
    await waitFor(() => {
      expect(screen.getByRole('status')).toHaveTextContent(
        'Mission revoked. Gateway containment acknowledged.',
      );
    });
    expect(onRevoked).toHaveBeenCalled();
  });

  it('distinguishes partial and pending containment', async () => {
    const user = userEvent.setup();
    vi.mocked(client.beginRevoke).mockResolvedValue(beginPayload());
    vi.mocked(getPasskey).mockResolvedValue({ id: 'cred-1' });

    vi.mocked(client.finishRevoke).mockResolvedValue({ ...resultPayload(), containment: 'partial' });
    const first = render(<RevokeButton passId="pass-1" onRevoked={() => {}} />);
    await user.click(screen.getByRole('button', { name: 'Revoke mission' }));
    await user.click(screen.getByRole('button', { name: 'Revoke with passkey' }));
    await waitFor(() => {
      expect(screen.getByRole('status')).toHaveTextContent('Containment is partial');
    });
    first.unmount();

    vi.mocked(client.finishRevoke).mockResolvedValue({ ...resultPayload(), containment: 'pending' });
    render(<RevokeButton passId="pass-1" onRevoked={() => {}} />);
    await user.click(screen.getByRole('button', { name: 'Revoke mission' }));
    await user.click(screen.getByRole('button', { name: 'Revoke with passkey' }));
    await waitFor(() => {
      expect(screen.getByRole('status')).toHaveTextContent('Containment is pending');
    });
  });

  it('hands the result to the CLI without rendering it', async () => {
    const user = userEvent.setup();
    vi.mocked(client.beginRevoke).mockResolvedValue(beginPayload());
    vi.mocked(getPasskey).mockResolvedValue({ id: 'cred-1' });
    vi.mocked(client.finishRevoke).mockResolvedValue({ handedToCli: true });
    const onRevoked = vi.fn();

    render(<RevokeButton passId="pass-1" onRevoked={onRevoked} cliRevocationId="req-1" />);
    await user.click(screen.getByRole('button', { name: 'Revoke mission' }));
    await user.click(screen.getByRole('button', { name: 'Revoke with passkey' }));

    await waitFor(() => {
      expect(client.finishRevoke).toHaveBeenCalledWith(
        'pass-1',
        'challenge-1',
        { id: 'cred-1' },
        'test-key-1',
        'req-1',
      );
    });
    await waitFor(() => {
      expect(screen.getByRole('status')).toHaveTextContent('Return to the CLI.');
    });
    expect(onRevoked).toHaveBeenCalled();
  });

  it('reports the pending state when the upstream outcome is ambiguous', async () => {
    const user = userEvent.setup();
    vi.mocked(client.beginRevoke).mockResolvedValue(beginPayload());
    vi.mocked(getPasskey).mockResolvedValue({ id: 'cred-1' });
    vi.mocked(client.finishRevoke).mockResolvedValue({
      pass_id: 'pass-1',
      reconciliation: 'pending',
    });

    render(<RevokeButton passId="pass-1" onRevoked={() => {}} />);

    await user.click(screen.getByRole('button', { name: 'Revoke mission' }));
    await user.click(screen.getByRole('button', { name: 'Revoke with passkey' }));

    await waitFor(() => {
      expect(screen.getByRole('status')).toHaveTextContent('uncertain');
    });
  });

  it('reports a non-revocable pass without retry', async () => {
    const user = userEvent.setup();
    vi.mocked(client.beginRevoke).mockRejectedValue(
      new ApiError(409, 'conflict', 'This mission cannot be revoked from its current state.'),
    );

    render(<RevokeButton passId="pass-1" onRevoked={() => {}} />);

    await user.click(screen.getByRole('button', { name: 'Revoke mission' }));
    await user.click(screen.getByRole('button', { name: 'Revoke with passkey' }));

    await waitFor(() => {
      expect(screen.getByRole('alert')).toHaveTextContent('cannot be revoked');
    });
    expect(screen.queryByRole('button', { name: 'Retry' })).not.toBeInTheDocument();
  });

  it('cancelling returns to the idle button', async () => {
    const user = userEvent.setup();
    render(<RevokeButton passId="pass-1" onRevoked={() => {}} />);

    await user.click(screen.getByRole('button', { name: 'Revoke mission' }));
    expect(screen.getByRole('button', { name: 'Revoke with passkey' })).toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'Cancel' }));

    expect(screen.getByRole('button', { name: 'Revoke mission' })).toBeInTheDocument();
    expect(client.beginRevoke).not.toHaveBeenCalled();
  });
});

describe('RevokeButton edge cases', () => {
  it('reports an invalid reason without retry', async () => {
    const user = userEvent.setup();
    vi.mocked(client.beginRevoke).mockRejectedValue(new ApiError(400, 'bad request', 'Invalid reason.'));

    render(<RevokeButton passId="pass-1" onRevoked={() => {}} />);

    await user.click(screen.getByRole('button', { name: 'Revoke mission' }));
    await user.click(screen.getByRole('button', { name: 'Revoke with passkey' }));

    await waitFor(() => {
      expect(screen.getByRole('alert')).toHaveTextContent('Invalid reason.');
    });
    expect(screen.queryByRole('button', { name: 'Retry' })).not.toBeInTheDocument();
  });

  it('retries after a recoverable upstream failure', async () => {
    const user = userEvent.setup();
    const onRevoked = vi.fn();
    vi.mocked(client.beginRevoke)
      .mockRejectedValueOnce(new ApiError(503, 'upstream'))
      .mockResolvedValue({ challenge_id: 'challenge-1', options: {} });
    vi.mocked(getPasskey).mockResolvedValue({ id: 'cred-1' });
    vi.mocked(client.finishRevoke).mockResolvedValue({
      pass_id: 'pass-1',
      mission_ref: 'mission-1',
      revoked: true,
      containment: 'acknowledged',
      reason_code: 'founder_requested',
      revoked_at: '2026-09-18T10:00:00Z',
    });

    render(<RevokeButton passId="pass-1" onRevoked={onRevoked} />);

    await user.click(screen.getByRole('button', { name: 'Revoke mission' }));
    await user.click(screen.getByRole('button', { name: 'Revoke with passkey' }));

    await waitFor(() => {
      expect(screen.getByRole('button', { name: 'Retry' })).toBeInTheDocument();
    });
    await user.click(screen.getByRole('button', { name: 'Retry' }));

    await waitFor(() => {
      expect(screen.getByRole('status')).toHaveTextContent('Mission revoked');
    });
    expect(onRevoked).toHaveBeenCalledTimes(1);
  });

  it('reports a cancelled passkey without retry', async () => {
    const user = userEvent.setup();
    vi.mocked(client.beginRevoke).mockResolvedValue({ challenge_id: 'challenge-1', options: {} });
    vi.mocked(getPasskey).mockRejectedValue(new Error('passkey authentication was cancelled'));

    render(<RevokeButton passId="pass-1" onRevoked={() => {}} />);

    await user.click(screen.getByRole('button', { name: 'Revoke mission' }));
    await user.click(screen.getByRole('button', { name: 'Revoke with passkey' }));

    await waitFor(() => {
      expect(screen.getByRole('alert')).toHaveTextContent('could not be completed');
    });
    expect(screen.getByRole('button', { name: 'Back' })).toBeInTheDocument();
  });

  it('goes back to idle from an error', async () => {
    const user = userEvent.setup();
    vi.mocked(client.beginRevoke).mockRejectedValue(new ApiError(404, 'not found'));

    render(<RevokeButton passId="pass-1" onRevoked={() => {}} />);

    await user.click(screen.getByRole('button', { name: 'Revoke mission' }));
    await user.click(screen.getByRole('button', { name: 'Revoke with passkey' }));

    await waitFor(() => {
      expect(screen.getByRole('alert')).toBeInTheDocument();
    });
    await user.click(screen.getByRole('button', { name: 'Back' }));

    expect(screen.getByRole('button', { name: 'Revoke mission' })).toBeInTheDocument();
  });
});
