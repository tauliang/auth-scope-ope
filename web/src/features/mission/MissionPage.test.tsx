import { describe, expect, it, vi, beforeEach } from 'vitest';
import { render, screen } from '@testing-library/react';
import {
  MissionPage,
  cliRevocationIdFromSearch,
  missionPassIdFromPath,
} from './MissionPage';
import * as client from '../../shared/api/client';
import type { TimelineResponse } from '../../shared/api/generated';

vi.mock('../../shared/api/client', async (importOriginal) => {
  const original = await importOriginal<typeof import('../../shared/api/client')>();
  return {
    ...original,
    fetchTimeline: vi.fn(),
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

beforeEach(() => {
  vi.mocked(client.fetchTimeline).mockReset();
  vi.mocked(client.fetchTimeline).mockResolvedValue(timeline());
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

describe('MissionPage', () => {
  it('renders the timeline and the revoke control for a pass', async () => {
    render(<MissionPage passId="pass-1" cliRevocationId={null} />);

    expect(await screen.findByLabelText('mission timeline')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Revoke mission' })).toBeInTheDocument();
  });
});

describe('MissionPage CLI handoff', () => {
  it('shows the requested banner and the normal revoke control for the handoff', async () => {
    render(<MissionPage passId="pass-1" cliRevocationId="req-1" />);

    expect(await screen.findByLabelText('mission timeline')).toBeInTheDocument();
    expect(screen.getByRole('status')).toHaveTextContent(
      'The CLI requested this revocation.',
    );
    expect(screen.getByRole('button', { name: 'Revoke mission' })).toBeInTheDocument();
  });

  it('shows no banner without a handoff', async () => {
    render(<MissionPage passId="pass-1" cliRevocationId={null} />);

    expect(await screen.findByLabelText('mission timeline')).toBeInTheDocument();
    expect(screen.queryByText(/The CLI requested this revocation/)).not.toBeInTheDocument();
  });
});
