import { describe, expect, it, vi, beforeEach } from 'vitest';
import { render, screen } from '@testing-library/react';
import {
  MissionPage,
  cliRevocationIdFromSearch,
  missionPassIdFromLocation,
  missionPassIdFromPath,
} from './MissionPage';
import * as client from '../../shared/api/client';
import type { MissionPassReview, ReceiptStatus, TimelineResponse } from '../../shared/api/generated';

vi.mock('../../shared/api/client', async (importOriginal) => {
  const original = await importOriginal<typeof import('../../shared/api/client')>();
  return {
    ...original,
    fetchTimeline: vi.fn(),
    fetchMissionReceipt: vi.fn(),
    fetchMissionPass: vi.fn(),
    listPendingExpansions: vi.fn(),
  };
});

function timeline(): TimelineResponse {
  return {
    pass_id: 'pass-1',
    state: 'approved',
    reconciliation: 'idle',
    events: [],
    cursor: '',
    compatible: true,
    stale: false,
    containment: '',
  };
}

function missionPass(): MissionPassReview {
  return {
    acceptance_criteria: ['done'],
    agent_kit_id: 'authscope-agent-kit',
    agent_kit_version: '1.0.0',
    authscope_mission_version: 1,
    connection_id: 'conn-1',
    draft_version: 1,
    invocation_digest: 'sha256:d',
    issue_number: 7,
    limits: { max_aggregate_cost_micros: 5000000, expires_at: '2026-09-19T00:00:00Z' },
    objective: 'fix it',
    pass_id: 'pass-1',
    proposal_digest: 'sha256:p',
    proposal_id: 'prop-1',
    reconciliation: 'settled',
    repository_name: 'octo-org/my-repo',
    runner_arguments: ['run'],
    state: 'approved',
    store_revision: 1,
    workspace_id: 'ws-test',
  };
}

beforeEach(() => {
  vi.mocked(client.fetchTimeline).mockReset();
  vi.mocked(client.fetchTimeline).mockResolvedValue(timeline());
  vi.mocked(client.fetchMissionPass).mockReset();
  vi.mocked(client.fetchMissionPass).mockResolvedValue(missionPass());
  vi.mocked(client.fetchMissionReceipt).mockReset();
  const pending: ReceiptStatus = { pass_id: 'pass-1', verification: 'pending' };
  vi.mocked(client.fetchMissionReceipt).mockResolvedValue(pending);
  vi.mocked(client.listPendingExpansions).mockReset();
  vi.mocked(client.listPendingExpansions).mockResolvedValue([]);
});

describe('missionPassIdFromPath', () => {
  it('extracts the pass id from the mission route', () => {
    expect(missionPassIdFromPath('/mission/pass-1')).toBe('pass-1');
  });

  it('returns null for other paths', () => {
    expect(missionPassIdFromPath('/')).toBeNull();
    expect(missionPassIdFromPath('/mission/')).toBeNull();
    expect(missionPassIdFromPath('/authorize/cli/authz-1')).toBeNull();
  });
});

describe('cliRevocationIdFromSearch', () => {
  it('extracts the CLI revocation request id', () => {
    expect(cliRevocationIdFromSearch('?cli_revocation=req-1')).toBe('req-1');
  });

  it('returns null when absent', () => {
    expect(cliRevocationIdFromSearch('')).toBeNull();
    expect(cliRevocationIdFromSearch('?other=1')).toBeNull();
  });
});

describe('missionPassIdFromLocation', () => {
  it('prefers the path over the query parameter', () => {
    expect(missionPassIdFromLocation('/mission/pass-1', '?pass=pass-2')).toBe('pass-1');
  });

  it('falls back to the query parameter', () => {
    expect(missionPassIdFromLocation('/mission', '?pass=pass-2')).toBe('pass-2');
    expect(missionPassIdFromLocation('/mission', '')).toBeNull();
  });
});

describe('MissionPage', () => {
  it('renders the state, timeline and the revoke control for a pass', async () => {
    render(<MissionPage passId="pass-1" cliRevocationId={null} />);

    expect(await screen.findByLabelText('mission state')).toBeInTheDocument();
    expect(screen.getByText('approved')).toBeInTheDocument();
    expect(screen.getByLabelText('mission timeline')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Revoke mission' })).toBeInTheDocument();
  });

  it('marks the projection stale while reconciliation is pending', async () => {
    const pending = missionPass();
    pending.reconciliation = 'pending';
    vi.mocked(client.fetchMissionPass).mockResolvedValue(pending);
    render(<MissionPage passId="pass-1" cliRevocationId={null} />);

    expect(await screen.findByText(/stale/i)).toBeInTheDocument();
  });
});

describe('MissionPage CLI handoff', () => {
  it('shows the requested banner and the normal revoke control for the handoff', async () => {
    render(<MissionPage passId="pass-1" cliRevocationId="req-1" />);

    expect(await screen.findByLabelText('mission timeline')).toBeInTheDocument();
    expect(screen.getByText(/The CLI requested this revocation/)).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Revoke mission' })).toBeInTheDocument();
  });

  it('shows no banner without a handoff', async () => {
    render(<MissionPage passId="pass-1" cliRevocationId={null} />);

    expect(await screen.findByLabelText('mission timeline')).toBeInTheDocument();
    expect(screen.queryByText(/The CLI requested this revocation/)).not.toBeInTheDocument();
  });

  it('shows the private receipt view on the mission page', async () => {
    render(<MissionPage passId="pass-1" cliRevocationId={null} />);

    expect(await screen.findByLabelText('receipt')).toBeInTheDocument();
    expect(await screen.findByText(/Receipt pending/)).toBeInTheDocument();
  });
});
