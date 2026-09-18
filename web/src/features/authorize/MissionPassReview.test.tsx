import { describe, expect, it, vi, beforeEach } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MissionPassAuthorize, MissionPassReview } from './MissionPassReview';
import { ApiError } from '../../shared/api/client';
import * as client from '../../shared/api/client';
import type { MissionPassReview as MissionPassReviewPayload } from '../../shared/api/generated';

vi.mock('../../shared/api/client', async (importOriginal) => {
  const original = await importOriginal<typeof import('../../shared/api/client')>();
  return {
    ...original,
    createMissionPassDraft: vi.fn(),
    reviseMissionPassDraft: vi.fn(),
    fetchMissionPass: vi.fn(),
    newIdempotencyKey: () => 'test-key-1',
  };
});

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

beforeEach(() => {
  vi.mocked(client.createMissionPassDraft).mockReset();
  vi.mocked(client.reviseMissionPassDraft).mockReset();
  vi.mocked(client.fetchMissionPass).mockReset();
});

describe('MissionPassReview', () => {
  it('renders the read-only proposal facts and digests', () => {
    render(<MissionPassReview review={reviewPayload()} onRevised={() => {}} />);
    expect(screen.getByText('Add retries')).toBeInTheDocument();
    expect(screen.getByText('retry with backoff')).toBeInTheDocument();
    expect(screen.getByText(`sha256:${'f'.repeat(64)}`)).toBeInTheDocument();
    expect(screen.getByText('octo-org/host')).toBeInTheDocument();
    expect(screen.getByText('#42')).toBeInTheDocument();
    expect(screen.getByText('a'.repeat(40))).toBeInTheDocument();
    expect(screen.getByText('authscope/pass-1-42')).toBeInTheDocument();
    expect(screen.getByText(/authscope-agent-kit 1\.0\.0/)).toBeInTheDocument();
    // Compact capability summary.
    expect(screen.getByText('Work on the generated mission branch')).toBeInTheDocument();
    expect(
      screen.getByText('Any operation outside the approved grant needs a one-time founder-approved expansion'),
    ).toBeInTheDocument();
    expect(screen.getByText('Touch the default branch')).toBeInTheDocument();
    // Honest enforcement labels.
    expect(
      screen.getByText('GitHub actions are brokered and enforced by AuthScope'),
    ).toBeInTheDocument();
    expect(
      screen.getByText('Agent runtime actions are compiled and enforced by AuthScope'),
    ).toBeInTheDocument();
    // Invocation digest lives in the collapsed details.
    expect(screen.getByText(`sha256:${'d'.repeat(64)}`)).toBeInTheDocument();
    expect(screen.getByText('authscope-agent-run')).toBeInTheDocument();
  });

  it('marks the review stale when a limit changes and revises with narrowed values', async () => {
    const user = userEvent.setup();
    const next = reviewPayload({ draft_version: 2, store_revision: 2 });
    vi.mocked(client.reviseMissionPassDraft).mockResolvedValue(next);
    const onRevised = vi.fn();
    render(<MissionPassReview review={reviewPayload()} onRevised={onRevised} />);

    const reviseButton = screen.getByRole('button', { name: 'Revise draft' });
    expect(reviseButton).toBeDisabled();

    // Narrow the budget from $10.00 to $5.00.
    await user.clear(screen.getByLabelText('Aggregate budget (USD)'));
    await user.type(screen.getByLabelText('Aggregate budget (USD)'), '5.00');
    expect(
      screen.getByText(/This review no longer matches the draft/),
    ).toBeInTheDocument();
    expect(reviseButton).toBeEnabled();

    await user.click(reviseButton);
    await waitFor(() => expect(onRevised).toHaveBeenCalledWith(next));
    expect(vi.mocked(client.reviseMissionPassDraft)).toHaveBeenCalledTimes(1);
    const [passId, body] = vi.mocked(client.reviseMissionPassDraft).mock.calls[0];
    expect(passId).toBe('pass-1');
    expect(body).toMatchObject({
      expected_store_revision: 1,
      expected_draft_version: 1,
      max_aggregate_cost_micros: 5_000_000,
    });
  });

  it('rejects widening edits client-side', async () => {
    const user = userEvent.setup();
    render(<MissionPassReview review={reviewPayload()} onRevised={() => {}} />);
    await user.clear(screen.getByLabelText('Aggregate budget (USD)'));
    await user.type(screen.getByLabelText('Aggregate budget (USD)'), '15.00');
    expect(screen.getByText(/can only move lower/)).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Revise draft' })).toBeDisabled();
    expect(vi.mocked(client.reviseMissionPassDraft)).not.toHaveBeenCalled();
  });

  it('shows the pending-reconciliation banner with a refresh action', async () => {
    const user = userEvent.setup();
    const settled = reviewPayload({ reconciliation: 'settled' });
    vi.mocked(client.fetchMissionPass).mockResolvedValue(settled);
    const onRevised = vi.fn();
    render(
      <MissionPassReview
        review={reviewPayload({ reconciliation: 'pending' })}
        onRevised={onRevised}
      />,
    );
    expect(screen.getByText(/upstream outcome is still uncertain/)).toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'Check again' }));
    await waitFor(() => expect(onRevised).toHaveBeenCalledWith(settled));
  });

  it('surfaces revision conflicts as errors', async () => {
    const user = userEvent.setup();
    vi.mocked(client.reviseMissionPassDraft).mockRejectedValue(new ApiError(409, 'conflict', 'revision conflict'));
    render(<MissionPassReview review={reviewPayload()} onRevised={() => {}} />);
    await user.clear(screen.getByLabelText('Aggregate budget (USD)'));
    await user.type(screen.getByLabelText('Aggregate budget (USD)'), '5.00');
    await user.click(screen.getByRole('button', { name: 'Revise draft' }));
    await waitFor(() => expect(screen.getByText(/revision conflict/)).toBeInTheDocument());
  });
});

describe('MissionPassAuthorize', () => {
  it('creates exactly one draft on mount and shows its review', async () => {
    const payload = reviewPayload();
    vi.mocked(client.createMissionPassDraft).mockResolvedValue(payload);
    render(<MissionPassAuthorize connectionId="conn-1" issueNumber={42} onBack={() => {}} />);
    expect(screen.getByText(/Creating the exact AuthScope proposal/)).toBeInTheDocument();
    await waitFor(() => expect(screen.getByText('Proposal review')).toBeInTheDocument());
    expect(vi.mocked(client.createMissionPassDraft)).toHaveBeenCalledTimes(1);
    expect(vi.mocked(client.createMissionPassDraft)).toHaveBeenCalledWith(
      expect.objectContaining({ connection_id: 'conn-1', issue_number: 42 }),
      'test-key-1',
    );
  });

  it('shows the pending draft when creation returns 202', async () => {
    vi.mocked(client.createMissionPassDraft).mockResolvedValue(
      reviewPayload({ reconciliation: 'pending', proposal_id: '' }),
    );
    render(<MissionPassAuthorize connectionId="conn-1" issueNumber={42} onBack={() => {}} />);
    await waitFor(() =>
      expect(screen.getByText(/upstream outcome is still uncertain/)).toBeInTheDocument(),
    );
  });

  it('offers a retry on recoverable creation errors', async () => {
    const user = userEvent.setup();
    const payload = reviewPayload();
    vi.mocked(client.createMissionPassDraft)
      .mockRejectedValueOnce(new ApiError(503, 'unavailable', 'upstream unavailable'))
      .mockResolvedValueOnce(payload);
    render(<MissionPassAuthorize connectionId="conn-1" issueNumber={42} onBack={() => {}} />);
    await waitFor(() => expect(screen.getByText(/upstream unavailable/)).toBeInTheDocument());
    await user.click(screen.getByRole('button', { name: 'Try again' }));
    await waitFor(() => expect(screen.getByText('Proposal review')).toBeInTheDocument());
    // The retry reuses the same idempotency key.
    expect(vi.mocked(client.createMissionPassDraft)).toHaveBeenNthCalledWith(
      2,
      expect.anything(),
      'test-key-1',
    );
  });
});
