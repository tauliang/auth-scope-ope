import { describe, expect, it, vi, beforeEach } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { ApprovalCard } from './ApprovalCard';
import { ApiError } from '../../shared/api/client';
import * as client from '../../shared/api/client';
import { getPasskey } from '../../shared/webauthn';
import type { MissionPassReview as MissionPassReviewPayload } from '../../shared/api/generated';

vi.mock('../../shared/api/client', async (importOriginal) => {
  const original = await importOriginal<typeof import('../../shared/api/client')>();
  return {
    ...original,
    beginMissionPassApproval: vi.fn(),
    finishMissionPassApproval: vi.fn(),
    fetchMissionPass: vi.fn(),
    newIdempotencyKey: () => 'test-key-1',
  };
});

vi.mock('../../shared/webauthn', () => ({
  getPasskey: vi.fn(),
}));

function reviewPayload(overrides: Partial<MissionPassReviewPayload> = {}): MissionPassReviewPayload {
  return {
    acceptance_criteria: ['retry with backoff'],
    agent_kit_id: 'authscope-agent-kit',
    agent_kit_version: '1.0.0',
    authscope_mission_version: 0,
    base_sha: 'a'.repeat(40),
    connection_id: 'conn-1',
    draft_version: 1,
    invocation_digest: `sha256:${'d'.repeat(64)}`,
    issue_number: 42,
    limits: {
      expires_at: new Date(Date.now() + 60 * 60 * 1000).toISOString(),
      max_aggregate_cost_micros: 10_000_000,
    },
    mission_branch: 'authscope/pass-1-42',
    objective: 'Add retries',
    pass_id: 'pass-1',
    proposal_digest: `sha256:${'f'.repeat(64)}`,
    proposal_id: 'prop-1',
    reconciliation: 'settled',
    repository_name: 'octo-org/host',
    runner_arguments: ['authscope-agent-run', '--mission'],
    source_revision: 'rev-1',
    state: 'draft',
    store_revision: 1,
    workspace_id: 'ws-test',
    ...overrides,
  };
}

const beginResponse = { challenge_id: 'challenge-1', options: { publicKey: { challenge: 'abc' } } };
const approvalResult = {
  workspace_id: 'ws-test',
  mission_ref: 'mission-1',
  mission_hash: `sha256:${'e'.repeat(64)}`,
  authscope_mission_version: 3,
  approval_decision_ref: 'approval-decision:ws-test:pass-1:1',
};

beforeEach(() => {
  vi.mocked(client.beginMissionPassApproval).mockReset();
  vi.mocked(client.finishMissionPassApproval).mockReset();
  vi.mocked(client.fetchMissionPass).mockReset();
  vi.mocked(getPasskey).mockReset();
});

async function clickApprove(user: ReturnType<typeof userEvent.setup>) {
  await user.click(screen.getByRole('button', { name: 'Approve with passkey' }));
}

describe('ApprovalCard', () => {
  it('walks begin, passkey, finish and shows the created mission', async () => {
    const user = userEvent.setup();
    vi.mocked(client.beginMissionPassApproval).mockResolvedValue(beginResponse);
    vi.mocked(getPasskey).mockResolvedValue({ id: 'cred-1' });
    vi.mocked(client.finishMissionPassApproval).mockResolvedValue(approvalResult);
    vi.mocked(client.fetchMissionPass).mockResolvedValue(
      reviewPayload({ state: 'approved', mission_ref: 'mission-1' }),
    );
    const onChanged = vi.fn();

    render(<ApprovalCard review={reviewPayload()} onChanged={onChanged} />);
    await clickApprove(user);

    await waitFor(() => {
      expect(client.beginMissionPassApproval).toHaveBeenCalledWith('pass-1', 'test-key-1');
    });
    expect(getPasskey).toHaveBeenCalledWith(beginResponse.options);
    expect(client.finishMissionPassApproval).toHaveBeenCalledWith(
      'pass-1',
      'challenge-1',
      { id: 'cred-1' },
      'test-key-1',
    );
    await waitFor(() => {
      const status = screen.getByRole('status');
      expect(status).toHaveTextContent('Approved');
      expect(status).toHaveTextContent('mission-1');
      expect(status).toHaveTextContent('was created and nothing else');
    });
    expect(onChanged).toHaveBeenCalled();
  });

  it('shows the reconciliation state on an ambiguous 202 finish', async () => {
    const user = userEvent.setup();
    vi.mocked(client.beginMissionPassApproval).mockResolvedValue(beginResponse);
    vi.mocked(getPasskey).mockResolvedValue({ id: 'cred-1' });
    const pending = reviewPayload({ reconciliation: 'pending' });
    vi.mocked(client.finishMissionPassApproval).mockResolvedValue(pending);
    vi.mocked(client.fetchMissionPass).mockResolvedValue(pending);

    render(<ApprovalCard review={reviewPayload()} onChanged={() => {}} />);
    await clickApprove(user);

    await waitFor(() => {
      expect(screen.getByText(/the outcome is uncertain/)).toBeInTheDocument();
    });
    await waitFor(() => {
      expect(client.fetchMissionPass).toHaveBeenCalledWith('pass-1');
    });
  });

  it('explains a stale proposal conflict without touching upstream', async () => {
    const user = userEvent.setup();
    vi.mocked(client.beginMissionPassApproval).mockResolvedValue(beginResponse);
    vi.mocked(getPasskey).mockResolvedValue({ id: 'cred-1' });
    vi.mocked(client.finishMissionPassApproval).mockRejectedValue(
      new ApiError(409, 'conflict', 'The proposal changed since the approval began.'),
    );

    render(<ApprovalCard review={reviewPayload()} onChanged={() => {}} />);
    await clickApprove(user);

    await waitFor(() => {
      expect(screen.getByText(/The proposal changed since the approval began/)).toBeInTheDocument();
    });
    expect(screen.getByRole('button', { name: 'Try again' })).toBeInTheDocument();
    expect(client.fetchMissionPass).not.toHaveBeenCalled();
  });

  it('offers a fresh start when the challenge is gone', async () => {
    const user = userEvent.setup();
    vi.mocked(client.beginMissionPassApproval).mockResolvedValue(beginResponse);
    vi.mocked(getPasskey).mockResolvedValue({ id: 'cred-1' });
    vi.mocked(client.finishMissionPassApproval).mockRejectedValue(
      new ApiError(404, 'not found', 'gone'),
    );

    render(<ApprovalCard review={reviewPayload()} onChanged={() => {}} />);
    await clickApprove(user);

    await waitFor(() => {
      expect(screen.getByText(/The approval challenge expired/)).toBeInTheDocument();
    });
  });

  it('renders the pending reconciliation copy with a check button', async () => {
    const user = userEvent.setup();
    const refreshed = reviewPayload({ state: 'approved', mission_ref: 'mission-1', reconciliation: 'settled' });
    vi.mocked(client.fetchMissionPass).mockResolvedValue(refreshed);
    const onChanged = vi.fn();

    render(<ApprovalCard review={reviewPayload({ reconciliation: 'pending' })} onChanged={onChanged} />);
    expect(screen.getByText(/Checking the original approval/)).toBeInTheDocument();

    await user.click(screen.getByRole('button', { name: 'Check now' }));
    await waitFor(() => {
      expect(onChanged).toHaveBeenCalledWith(refreshed);
    });
  });
});
