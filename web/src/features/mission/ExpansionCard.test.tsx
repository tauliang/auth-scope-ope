import { describe, expect, it, vi, beforeEach } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { ExpansionCard } from './ExpansionCard';
import * as client from '../../shared/api/client';
import { getPasskey } from '../../shared/webauthn';
import type {
  ExpansionDecisionResult,
  ExpansionBeginResponse,
  PendingExpansion,
} from '../../shared/api/generated';

vi.mock('../../shared/api/client', async (importOriginal) => {
  const original = await importOriginal<typeof import('../../shared/api/client')>();
  return {
    ...original,
    beginExpansionDecision: vi.fn(),
    finishExpansionDecision: vi.fn(),
    newIdempotencyKey: () => 'test-key-1',
  };
});

vi.mock('../../shared/webauthn', () => ({
  getPasskey: vi.fn(),
}));

function pendingExpansion(overrides: Partial<PendingExpansion> = {}): PendingExpansion {
  return {
    expansion_id: 'exp-1',
    expansion_digest: 'sha256:' + 'a'.repeat(64),
    blocked_operation: 'files.write',
    resource: 'github:octo-org/host',
    repository: 'octo-org/host',
    ref: 'refs/heads/mission-1',
    path: 'config/flags.yaml',
    destination: 'config/flags.yaml',
    normalized_arguments_digest: 'sha256:' + 'b'.repeat(64),
    quantity: 1,
    budget_micros: 50000,
    current_authority: 'read-only',
    requested_authority: 'write:config/flags.yaml',
    consequence_change: 'agent may write config/flags.yaml once',
    reason_code: 'config_update_required',
    reversibility: 'reversible',
    requested_expiry: '2026-09-18T14:00:00Z',
    agent_rationale: 'The agent asked to flip the feature flag.',
    stale: false,
    expired: false,
    ...overrides,
  };
}

function beginPayload(): ExpansionBeginResponse {
  return {
    challenge_id: 'challenge-1',
    options: { publicKey: { challenge: 'abc' } },
    expansion_id: 'exp-1',
    decision: 'approve_once',
    effective_expiry: '2026-09-18T14:00:00Z',
  };
}

function resultPayload(): ExpansionDecisionResult {
  return {
    expansion_id: 'exp-1',
    pass_id: 'pass-1',
    decision: 'approve_once',
    decision_ref: 'expansion-decision:ws-test:exp-1:approve_once',
    authscope_mission_version: 4,
    state: 'running',
  };
}

beforeEach(() => {
  vi.mocked(client.beginExpansionDecision).mockReset();
  vi.mocked(client.finishExpansionDecision).mockReset();
  vi.mocked(getPasskey).mockReset();
});

describe('ExpansionCard', () => {
  it('renders the exact canonical delta, never raw arguments', () => {
    render(
      <ExpansionCard
        passId="pass-1"
        expansion={pendingExpansion()}
        onDecided={() => {}}
      />,
    );

    expect(screen.getByText('files.write')).toBeInTheDocument();
    expect(screen.getByText('github:octo-org/host')).toBeInTheDocument();
    expect(screen.getByText('read-only')).toBeInTheDocument();
    expect(screen.getByText('write:config/flags.yaml')).toBeInTheDocument();
    expect(
      screen.getByText('agent may write config/flags.yaml once'),
    ).toBeInTheDocument();
    expect(screen.getByText('config_update_required')).toBeInTheDocument();
    expect(screen.getByText('reversible')).toBeInTheDocument();
    expect(screen.getByText('config/flags.yaml')).toBeInTheDocument();
    expect(screen.getByText('sha256:' + 'b'.repeat(64))).toBeInTheDocument();
    expect(screen.getByText('sha256:' + 'a'.repeat(64))).toBeInTheDocument();
    // The agent-authored rationale is shown labeled, not as authority.
    expect(
      screen.getByText('The agent asked to flip the feature flag.'),
    ).toBeInTheDocument();
    expect(screen.getByText(/agent-authored/i)).toBeInTheDocument();
    // The card states the exact bound of the grant.
    expect(screen.getByText(/exactly one use/i)).toBeInTheDocument();
  });

  it('disables decisions when the delta is stale', () => {
    render(
      <ExpansionCard
        passId="pass-1"
        expansion={pendingExpansion({ stale: true })}
        onDecided={() => {}}
      />,
    );

    expect(screen.getByText(/stale/i)).toBeInTheDocument();
    expect(
      screen.getByRole('button', { name: /approve once/i }),
    ).toBeDisabled();
    expect(screen.getByRole('button', { name: /deny/i })).toBeDisabled();
  });

  it('disables decisions when the expansion expired', () => {
    render(
      <ExpansionCard
        passId="pass-1"
        expansion={pendingExpansion({ expired: true })}
        onDecided={() => {}}
      />,
    );

    expect(screen.getByText(/expired/i)).toBeInTheDocument();
    expect(
      screen.getByRole('button', { name: /approve once/i }),
    ).toBeDisabled();
    expect(screen.getByRole('button', { name: /deny/i })).toBeDisabled();
  });

  it('runs the passkey approve-once ceremony and reports the result', async () => {
    const user = userEvent.setup();
    const onDecided = vi.fn();
    vi.mocked(client.beginExpansionDecision).mockResolvedValue(beginPayload());
    vi.mocked(getPasskey).mockResolvedValue({ id: 'cred-1' });
    vi.mocked(client.finishExpansionDecision).mockResolvedValue(resultPayload());

    render(
      <ExpansionCard
        passId="pass-1"
        expansion={pendingExpansion()}
        onDecided={onDecided}
      />,
    );

    await user.click(screen.getByRole('button', { name: /approve once/i }));

    await waitFor(() => {
      expect(client.beginExpansionDecision).toHaveBeenCalledWith(
        'exp-1',
        'approve_once',
        'test-key-1',
      );
    });
    await waitFor(() => {
      expect(getPasskey).toHaveBeenCalledWith({
        publicKey: { challenge: 'abc' },
      });
    });
    await waitFor(() => {
      expect(client.finishExpansionDecision).toHaveBeenCalledWith(
        'exp-1',
        'challenge-1',
        { id: 'cred-1' },
        'test-key-1',
      );
    });
    await waitFor(() => {
      expect(onDecided).toHaveBeenCalledWith(resultPayload());
    });
    await waitFor(() => {
      expect(screen.getByRole('status')).toHaveTextContent(/approved for exactly one use/i);
    });
  });

  it('runs the deny ceremony', async () => {
    const user = userEvent.setup();
    const onDecided = vi.fn();
    vi.mocked(client.beginExpansionDecision).mockResolvedValue({
      ...beginPayload(),
      decision: 'deny',
    });
    vi.mocked(getPasskey).mockResolvedValue({ id: 'cred-1' });
    vi.mocked(client.finishExpansionDecision).mockResolvedValue({
      ...resultPayload(),
      decision: 'deny',
    });

    render(
      <ExpansionCard
        passId="pass-1"
        expansion={pendingExpansion()}
        onDecided={onDecided}
      />,
    );

    await user.click(screen.getByRole('button', { name: /deny/i }));

    await waitFor(() => {
      expect(client.beginExpansionDecision).toHaveBeenCalledWith(
        'exp-1',
        'deny',
        'test-key-1',
      );
    });
    await waitFor(() => {
      expect(onDecided).toHaveBeenCalled();
    });
    await waitFor(() => {
      expect(screen.getByRole('status')).toHaveTextContent(/denied/i);
    });
  });

  it('shows a clear error when the ceremony fails', async () => {
    const user = userEvent.setup();
    vi.mocked(client.beginExpansionDecision).mockRejectedValue(
      new Error('request failed'),
    );

    render(
      <ExpansionCard
        passId="pass-1"
        expansion={pendingExpansion()}
        onDecided={() => {}}
      />,
    );

    await user.click(screen.getByRole('button', { name: /approve once/i }));

    await waitFor(() => {
      expect(screen.getByRole('alert')).toBeInTheDocument();
    });
  });
});
