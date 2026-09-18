import { describe, expect, it, vi, beforeEach } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { Timeline } from './Timeline';
import { ApiError } from '../../shared/api/client';
import * as client from '../../shared/api/client';
import type { TimelineResponse } from '../../shared/api/generated';

vi.mock('../../shared/api/client', async (importOriginal) => {
  const original = await importOriginal<typeof import('../../shared/api/client')>();
  return {
    ...original,
    fetchTimeline: vi.fn(),
  };
});

function timeline(overrides: Partial<TimelineResponse> = {}): TimelineResponse {
  return {
    pass_id: 'pass-1',
    state: 'approved',
    reconciliation: 'idle',
    events: [],
    cursor: '',
    compatible: true,
    stale: false,
    containment: '',
    ...overrides,
  };
}

beforeEach(() => {
  vi.mocked(client.fetchTimeline).mockReset();
});

describe('Timeline', () => {
  it('renders projected events with plain-language labels', async () => {
    vi.mocked(client.fetchTimeline).mockResolvedValue(
      timeline({
        events: [
          {
            event_id: 'e1',
            cursor: 'c1',
            type: 'mission_started',
            occurred_at: '2026-09-18T10:00:00Z',
            authscope_mission_version: 3,
            resource_digest: 'sha256:abc',
          },
          {
            event_id: 'e2',
            cursor: 'c2',
            type: 'action_checked',
            occurred_at: '2026-09-18T10:01:00Z',
            authscope_mission_version: 3,
            resource_digest: 'sha256:abc',
            check_kind: 'test',
            check_outcome: 'passed',
          },
          {
            event_id: 'e3',
            cursor: 'c3',
            type: 'mission_revoked',
            occurred_at: '2026-09-18T10:02:00Z',
            authscope_mission_version: 3,
            resource_digest: 'sha256:abc',
          },
        ],
        cursor: 'c3',
      }),
    );

    render(<Timeline passId="pass-1" />);

    await waitFor(() => {
      expect(screen.getByText('Mission started')).toBeInTheDocument();
    });
    expect(screen.getByText('Check test passed')).toBeInTheDocument();
    expect(screen.getByText('Mission revoked')).toBeInTheDocument();
    expect(
      vi.mocked(client.fetchTimeline),
    ).toHaveBeenCalledWith('pass-1', undefined, 100);
  });

  it('shows the containment banner for a revoked pass', async () => {
    vi.mocked(client.fetchTimeline).mockResolvedValue(
      timeline({ state: 'revoked', containment: 'acknowledged' }),
    );

    render(<Timeline passId="pass-1" />);

    await waitFor(() => {
      expect(screen.getByRole('alert')).toHaveTextContent('Containment: acknowledged');
    });
  });

  it('shows the incompatibility banner when the projection is paused', async () => {
    vi.mocked(client.fetchTimeline).mockResolvedValue(
      timeline({ compatible: false, incompatibility_reason: 'unknown event type' }),
    );

    render(<Timeline passId="pass-1" />);

    await waitFor(() => {
      expect(screen.getByRole('alert')).toHaveTextContent('incompatible and paused');
    });
  });

  it('pages through events by cursor', async () => {
    const first = timeline({
      events: [
        {
          event_id: 'e1',
          cursor: 'c1',
          type: 'mission_started',
          occurred_at: '2026-09-18T10:00:00Z',
          authscope_mission_version: 3,
          resource_digest: 'sha256:abc',
        },
      ],
      cursor: 'c1',
    });
    const second = timeline({
      events: [
        {
          event_id: 'e2',
          cursor: 'c2',
          type: 'run_succeeded',
          occurred_at: '2026-09-18T10:01:00Z',
          authscope_mission_version: 3,
          resource_digest: 'sha256:abc',
        },
      ],
      cursor: '',
    });
    vi.mocked(client.fetchTimeline)
      .mockResolvedValueOnce(first)
      .mockResolvedValueOnce(second);

    const user = userEvent.setup();
    render(<Timeline passId="pass-1" />);

    await waitFor(() => {
      expect(screen.getByText('Mission started')).toBeInTheDocument();
    });
    await user.click(screen.getByRole('button', { name: 'Load more' }));

    await waitFor(() => {
      expect(screen.getByText('Run succeeded')).toBeInTheDocument();
    });
    expect(screen.getByText('Mission started')).toBeInTheDocument();
    expect(vi.mocked(client.fetchTimeline)).toHaveBeenNthCalledWith(2, 'pass-1', 'c1', 100);
  });

  it('reports a missing pass', async () => {
    vi.mocked(client.fetchTimeline).mockRejectedValue(new ApiError(404, 'not found'));

    render(<Timeline passId="pass-1" />);

    await waitFor(() => {
      expect(screen.getByRole('alert')).toHaveTextContent('not found');
    });
  });
});

describe('Timeline edge cases', () => {
  it('labels expansion and pull request events with optional fields', async () => {
    vi.mocked(client.fetchTimeline).mockResolvedValue(
      timeline({
        events: [
          {
            event_id: 'e1',
            cursor: 'c1',
            type: 'expansion_requested',
            occurred_at: '2026-09-18T10:00:00Z',
            authscope_mission_version: 3,
            resource_digest: 'sha256:abc',
            reason_code: 'scope_grew',
          },
          {
            event_id: 'e2',
            cursor: 'c2',
            type: 'expansion_requested',
            occurred_at: '2026-09-18T10:01:00Z',
            authscope_mission_version: 3,
            resource_digest: 'sha256:abc',
          },
          {
            event_id: 'e3',
            cursor: 'c3',
            type: 'pull_request_created',
            occurred_at: '2026-09-18T10:02:00Z',
            authscope_mission_version: 3,
            resource_digest: 'sha256:abc',
            pull_request_number: 7,
            branch: 'authscope/exp-7',
          },
          {
            event_id: 'e4',
            cursor: 'c4',
            type: 'pull_request_created',
            occurred_at: '2026-09-18T10:03:00Z',
            authscope_mission_version: 3,
            resource_digest: 'sha256:abc',
          },
          {
            event_id: 'e5',
            cursor: 'c5',
            type: 'receipt_ready',
            occurred_at: '2026-09-18T10:04:00Z',
            authscope_mission_version: 3,
            resource_digest: 'sha256:abc',
          },
        ],
        cursor: '',
      }),
    );

    render(<Timeline passId="pass-1" />);

    await waitFor(() => {
      expect(screen.getByText('Expansion requested: scope_grew')).toBeInTheDocument();
    });
    expect(screen.getByText('Expansion requested')).toBeInTheDocument();
    // Without a verified repository binding, the PR event renders as
    // plain text with no links.
    expect(screen.getAllByText('Pull request opened')).toHaveLength(2);
    expect(screen.getByText('Receipt ready')).toBeInTheDocument();
    expect(screen.queryByRole('link')).not.toBeInTheDocument();
  });

  it('renders trusted PR and branch links from the verified repository binding', async () => {
    vi.mocked(client.fetchTimeline).mockResolvedValue(
      timeline({
        repository_name: 'owner/repo',
        events: [
          {
            event_id: 'e3',
            cursor: 'c3',
            type: 'pull_request_created',
            occurred_at: '2026-09-18T10:02:00Z',
            authscope_mission_version: 3,
            resource_digest: 'sha256:abc',
            pull_request_number: 7,
            branch: 'authscope/exp-7',
          },
        ],
        cursor: '',
      }),
    );

    render(<Timeline passId="pass-1" />);

    await waitFor(() => {
      expect(screen.getByText('Pull request opened')).toBeInTheDocument();
    });
    const prLink = screen.getByRole('link', { name: 'PR #7' });
    expect(prLink).toHaveAttribute('href', 'https://github.com/owner/repo/pull/7');
    const branchLink = screen.getByRole('link', { name: 'authscope/exp-7' });
    expect(branchLink).toHaveAttribute(
      'href',
      'https://github.com/owner/repo/tree/authscope%2Fexp-7',
    );
  });

  it('renders no links when the repository binding is not a valid owner/repo', async () => {
    vi.mocked(client.fetchTimeline).mockResolvedValue(
      timeline({
        repository_name: 'not a repo',
        events: [
          {
            event_id: 'e3',
            cursor: 'c3',
            type: 'pull_request_created',
            occurred_at: '2026-09-18T10:02:00Z',
            authscope_mission_version: 3,
            resource_digest: 'sha256:abc',
            pull_request_number: 7,
            branch: 'authscope/exp-7',
          },
        ],
        cursor: '',
      }),
    );

    render(<Timeline passId="pass-1" />);

    await waitFor(() => {
      expect(screen.getByText('Pull request opened')).toBeInTheDocument();
    });
    expect(screen.queryByRole('link')).not.toBeInTheDocument();
  });

  it('shows the stale banner without a compatibility reason', async () => {
    vi.mocked(client.fetchTimeline).mockResolvedValue(
      timeline({ stale: true, compatible: false }),
    );

    render(<Timeline passId="pass-1" />);

    await waitFor(() => {
      expect(screen.getByText(/stale/)).toBeInTheDocument();
    });
    expect(screen.getByText(/incompatible and paused\./)).toBeInTheDocument();
  });

  it('reports a failed page load as an error', async () => {
    const first = timeline({
      events: [
        {
          event_id: 'e1',
          cursor: 'c1',
          type: 'mission_started',
          occurred_at: '2026-09-18T10:00:00Z',
          authscope_mission_version: 3,
          resource_digest: 'sha256:abc',
        },
      ],
      cursor: 'c1',
    });
    vi.mocked(client.fetchTimeline)
      .mockResolvedValueOnce(first)
      .mockRejectedValueOnce(new ApiError(500, 'upstream'));

    const user = userEvent.setup();
    render(<Timeline passId="pass-1" />);

    await waitFor(() => {
      expect(screen.getByText('Mission started')).toBeInTheDocument();
    });
    await user.click(screen.getByRole('button', { name: 'Load more' }));

    await waitFor(() => {
      expect(screen.getByRole('alert')).toBeInTheDocument();
    });
  });

  it('shows an empty timeline', async () => {
    vi.mocked(client.fetchTimeline).mockResolvedValue(timeline());

    render(<Timeline passId="pass-1" />);

    await waitFor(() => {
      expect(screen.getByText('No events yet.')).toBeInTheDocument();
    });
  });

  it('polls while reconciliation is pending and settles', async () => {
    const pending = timeline({ reconciliation: 'pending' });
    const settled = timeline({ reconciliation: 'idle', state: 'revoked' });
    vi.mocked(client.fetchTimeline)
      .mockResolvedValueOnce(pending)
      .mockResolvedValueOnce(settled);

    render(<Timeline passId="pass-1" pollIntervalMs={10} />);

    await waitFor(() => {
      expect(screen.getByText(/Reconciliation: pending/)).toBeInTheDocument();
    });

    await waitFor(() => {
      expect(screen.getByText(/Reconciliation: idle/)).toBeInTheDocument();
    });
    expect(vi.mocked(client.fetchTimeline)).toHaveBeenCalledTimes(2);
  });

  it('keeps the last good page when a poll fails', async () => {
    const pending = timeline({ reconciliation: 'pending' });
    const settled = timeline({ reconciliation: 'idle', state: 'revoked' });
    vi.mocked(client.fetchTimeline)
      .mockResolvedValueOnce(pending)
      .mockRejectedValueOnce(new Error('boom'))
      .mockResolvedValueOnce(settled);

    render(<Timeline passId="pass-1" pollIntervalMs={10} />);

    await waitFor(() => {
      expect(screen.getByText(/Reconciliation: pending/)).toBeInTheDocument();
    });

    // The failed poll retries on the next tick and the settled page wins.
    await waitFor(() => {
      expect(screen.getByText(/Reconciliation: idle/)).toBeInTheDocument();
    });
    expect(vi.mocked(client.fetchTimeline).mock.calls.length).toBeGreaterThanOrEqual(3);
  });
});
