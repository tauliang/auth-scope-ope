import { describe, expect, it, vi, beforeEach } from 'vitest';
import { act, render, screen, waitFor } from '@testing-library/react';
import { ReceiptView } from './ReceiptView';
import { ApiError } from '../../shared/api/client';
import * as client from '../../shared/api/client';
import type { ReceiptStatus, ReceiptView as ReceiptViewData } from '../../shared/api/generated';

vi.mock('../../shared/api/client', async (importOriginal) => {
  const original = await importOriginal<typeof import('../../shared/api/client')>();
  return {
    ...original,
    fetchMissionReceipt: vi.fn(),
  };
});

function verifiedView(overrides: Partial<ReceiptViewData> = {}): ReceiptViewData {
  return {
    verification: 'verified',
    receipt_id: 'rcpt-1',
    grant_id: 'run-1',
    mission_ref: 'mission-1',
    workspace_id: 'ws-test',
    key_id: 'receipt-key-1',
    signed_at: 1758260000,
    receipt_digest: 'ab'.repeat(32),
    settlement_digest: `sha256:${'b'.repeat(64)}`,
    outcome: 'success',
    mission_versions: [3],
    expansion_decision_refs: [],
    repository_id: 111,
    issue_number: 42,
    branch: 'authscope/mission-1',
    pull_request_number: 7,
    head_sha: 'a'.repeat(40),
    checks: [{ kind: 'unit_tests', outcome: 'passed' }],
    started_at: 1758256000,
    finished_at: 1758259000,
    aggregate_cost_micros: 100,
    budget_micros: 100,
    historical_enforcement: [{ scope: 'github', level: 'enforced' }],
    ...overrides,
  };
}

function status(overrides: Partial<ReceiptStatus> = {}): ReceiptStatus {
  return {
    pass_id: 'pass-1',
    verification: 'pending',
    ...overrides,
  };
}

beforeEach(() => {
  vi.mocked(client.fetchMissionReceipt).mockReset();
});

describe('ReceiptView', () => {
  it('renders the pending state without completion language', async () => {
    vi.mocked(client.fetchMissionReceipt).mockResolvedValue(status({ verification: 'pending' }));

    render(<ReceiptView passId="pass-1" pollIntervalMs={10} />);

    await waitFor(() => {
      expect(screen.getByText(/Receipt pending/)).toBeInTheDocument();
    });
    expect(screen.queryByText(/succeeded|completed|failed/)).not.toBeInTheDocument();
  });

  it('renders a verified success with the fixed projection', async () => {
    vi.mocked(client.fetchMissionReceipt).mockResolvedValue(
      status({
        verification: 'verified',
        view: verifiedView(),
        publication: {
          state: 'settled',
          check_run_id: 'chk-1',
          idempotency_key: 'key-1',
          repository_id: 111,
          pull_request_number: 7,
          head_sha: 'a'.repeat(40),
          updated_at: '2026-09-18T10:00:00Z',
        },
      }),
    );

    render(<ReceiptView passId="pass-1" pollIntervalMs={10} />);

    await waitFor(() => {
      expect(screen.getByText('Verified receipt: run succeeded.')).toBeInTheDocument();
    });
    expect(screen.getByText('GitHub check published.')).toBeInTheDocument();
    expect(screen.getByText(/sha256:abababababab/)).toBeInTheDocument();
    expect(screen.getByText('github: enforced')).toBeInTheDocument();
    expect(screen.queryByRole('button')).not.toBeInTheDocument();
  });

  it('renders a verified failure distinctly', async () => {
    vi.mocked(client.fetchMissionReceipt).mockResolvedValue(
      status({
        verification: 'verified',
        view: verifiedView({ outcome: 'failure' }),
      }),
    );

    render(<ReceiptView passId="pass-1" pollIntervalMs={10} />);

    await waitFor(() => {
      expect(screen.getByText('Verified receipt: run failed.')).toBeInTheDocument();
    });
    expect(screen.getByText('Check publication pending.')).toBeInTheDocument();
  });

  it('renders an unverifiable receipt with the reason and no completion language', async () => {
    vi.mocked(client.fetchMissionReceipt).mockResolvedValue(
      status({ verification: 'unverifiable', reason_code: 'bad_signature' }),
    );

    render(<ReceiptView passId="pass-1" pollIntervalMs={10} />);

    await waitFor(() => {
      expect(screen.getByText(/Receipt unverifiable: the signature did not verify/)).toBeInTheDocument();
    });
    expect(screen.getByText(/stays pending until a receipt verifies locally/)).toBeInTheDocument();
    expect(screen.queryByText(/succeeded|completed/)).not.toBeInTheDocument();
  });

  it('renders a disputed publication distinctly', async () => {
    vi.mocked(client.fetchMissionReceipt).mockResolvedValue(
      status({
        verification: 'verified',
        view: verifiedView(),
        publication: {
          state: 'disputed',
          check_run_id: '',
          idempotency_key: 'key-1',
          repository_id: 111,
          pull_request_number: 7,
          head_sha: 'a'.repeat(40),
          updated_at: '2026-09-18T10:00:00Z',
        },
      }),
    );

    render(<ReceiptView passId="pass-1" pollIntervalMs={10} />);

    await waitFor(() => {
      expect(screen.getByText('Check publication disputed.')).toBeInTheDocument();
    });
  });

  it('renders a publication-pending state while the check is in flight', async () => {
    vi.mocked(client.fetchMissionReceipt).mockResolvedValue(
      status({
        verification: 'verified',
        view: verifiedView(),
        publication: {
          state: 'in_flight',
          check_run_id: '',
          idempotency_key: 'key-1',
          repository_id: 111,
          pull_request_number: 7,
          head_sha: 'a'.repeat(40),
          updated_at: '2026-09-18T10:00:00Z',
        },
      }),
    );

    render(<ReceiptView passId="pass-1" pollIntervalMs={10} />);

    await waitFor(() => {
      expect(screen.getByText('Check publication pending.')).toBeInTheDocument();
    });
  });

  it('renders a not-found error for an unknown pass', async () => {
    vi.mocked(client.fetchMissionReceipt).mockRejectedValue(new ApiError(404, 'not found'));

    render(<ReceiptView passId="nope" pollIntervalMs={10} />);

    await waitFor(() => {
      expect(screen.getByText('This mission pass was not found.')).toBeInTheDocument();
    });
  });

  it('surfaces the problem title on server errors', async () => {
    vi.mocked(client.fetchMissionReceipt).mockRejectedValue(
      new ApiError(500, 'request failed', 'the authority is down'),
    );

    render(<ReceiptView passId="pass-1" pollIntervalMs={10} />);

    await waitFor(() => {
      expect(screen.getByText('the authority is down')).toBeInTheDocument();
    });
  });

  it('falls back to a status message when the problem title is empty', async () => {
    vi.mocked(client.fetchMissionReceipt).mockRejectedValue(new ApiError(500, '', ''));

    render(<ReceiptView passId="pass-1" pollIntervalMs={10} />);

    await waitFor(() => {
      expect(screen.getByText('The receipt failed to load (500).')).toBeInTheDocument();
    });
  });

  it('falls back to a generic message for non-API failures', async () => {
    vi.mocked(client.fetchMissionReceipt).mockRejectedValue(new Error('boom'));

    render(<ReceiptView passId="pass-1" pollIntervalMs={10} />);

    await waitFor(() => {
      expect(screen.getByText('The receipt could not be loaded.')).toBeInTheDocument();
    });
  });

  it('treats a verified status without a view as pending', async () => {
    vi.mocked(client.fetchMissionReceipt).mockResolvedValue(status({ verification: 'verified' }));

    render(<ReceiptView passId="pass-1" pollIntervalMs={10} />);

    await waitFor(() => {
      expect(screen.getByText(/Receipt pending/)).toBeInTheDocument();
    });
  });

  it('polls while pending and shows the verified view when it arrives', async () => {
    const pending = status({ verification: 'pending' });
    const verified = status({ verification: 'verified', view: verifiedView() });
    vi.mocked(client.fetchMissionReceipt)
      .mockResolvedValueOnce(pending)
      .mockRejectedValueOnce(new Error('poll hiccup'))
      .mockResolvedValue(verified);

    render(<ReceiptView passId="pass-1" pollIntervalMs={20} />);

    // The first poll fails and the retry timer is re-armed; the next
    // poll returns the verified view.
    await waitFor(
      () => {
        expect(screen.getByText('Verified receipt: run succeeded.')).toBeInTheDocument();
      },
      { timeout: 5000 },
    );
    expect(vi.mocked(client.fetchMissionReceipt).mock.calls.length).toBeGreaterThanOrEqual(3);
  }, 10000);

  it.each([
    ['bad_key', 'the signing key was unknown or invalid when the receipt was signed'],
    ['bad_payload', 'the receipt payload was malformed'],
    ['bad_binding', 'the receipt did not match this pass'],
    ['something_else', 'something_else'],
  ])('renders the unverifiable reason %s in plain language', async (code, label) => {
    // The unknown-code case exercises the default label branch with a
    // code outside the generated union.
    const st: ReceiptStatus = {
      ...status({ verification: 'unverifiable' }),
      reason_code: code as ReceiptStatus['reason_code'],
    };
    vi.mocked(client.fetchMissionReceipt).mockResolvedValue(st);

    render(<ReceiptView passId="pass-1" pollIntervalMs={10} />);

    await waitFor(() => {
      expect(screen.getByText(`Receipt unverifiable: ${label}.`)).toBeInTheDocument();
    });
  });

  it('falls back to a generic label for an empty reason code', async () => {
    const st: ReceiptStatus = {
      ...status({ verification: 'unverifiable' }),
      reason_code: '' as ReceiptStatus['reason_code'],
    };
    vi.mocked(client.fetchMissionReceipt).mockResolvedValue(st);

    render(<ReceiptView passId="pass-1" pollIntervalMs={10} />);

    await waitFor(() => {
      expect(screen.getByText(/the receipt could not be verified/)).toBeInTheDocument();
    });
  });

  it('renders a short receipt digest without slicing', async () => {
    vi.mocked(client.fetchMissionReceipt).mockResolvedValue(
      status({
        verification: 'verified',
        view: verifiedView({ receipt_digest: 'abc', settlement_digest: undefined }),
      }),
    );

    render(<ReceiptView passId="pass-1" pollIntervalMs={10} />);

    await waitFor(() => {
      expect(screen.getByText('sha256:abc')).toBeInTheDocument();
    });
    expect(screen.queryByText(/Settlement digest/)).not.toBeInTheDocument();
  });

  it('stops polling once the check publication settles', async () => {
    const pending = status({ verification: 'pending' });
    const settled = status({
      verification: 'verified',
      view: verifiedView(),
      publication: {
        state: 'settled',
        check_run_id: 'chk-1',
        idempotency_key: 'key-1',
        repository_id: 111,
        pull_request_number: 7,
        head_sha: 'a'.repeat(40),
        updated_at: '2026-09-18T10:00:00Z',
      },
    });
    vi.mocked(client.fetchMissionReceipt).mockResolvedValueOnce(pending).mockResolvedValue(settled);

    render(<ReceiptView passId="pass-1" pollIntervalMs={20} />);

    await waitFor(() => {
      expect(screen.getByText('GitHub check published.')).toBeInTheDocument();
    });
    const calls = vi.mocked(client.fetchMissionReceipt).mock.calls.length;
    await new Promise((r) => setTimeout(r, 100));
    expect(vi.mocked(client.fetchMissionReceipt).mock.calls.length).toBe(calls);
  }, 10000);

  it('ignores a late initial load after unmount', async () => {
    let resolve!: (value: ReceiptStatus) => void;
    const gate = new Promise<ReceiptStatus>((res) => {
      resolve = res;
    });
    vi.mocked(client.fetchMissionReceipt).mockReturnValue(gate);

    const { unmount } = render(<ReceiptView passId="pass-1" pollIntervalMs={10} />);
    unmount();
    resolve(status({ verification: 'pending' }));
    await act(async () => {
      await gate;
    });
    expect(screen.queryByLabelText('receipt')).not.toBeInTheDocument();
  });

  it('ignores a late poll after unmount', async () => {
    const pending = status({ verification: 'pending' });
    let resolvePoll!: (value: ReceiptStatus) => void;
    const pollGate = new Promise<ReceiptStatus>((res) => {
      resolvePoll = res;
    });
    vi.mocked(client.fetchMissionReceipt).mockResolvedValueOnce(pending).mockReturnValueOnce(pollGate);

    const { unmount } = render(<ReceiptView passId="pass-1" pollIntervalMs={20} />);
    await waitFor(() => {
      expect(screen.getByText(/Receipt pending/)).toBeInTheDocument();
    });
    await waitFor(() => {
      expect(vi.mocked(client.fetchMissionReceipt).mock.calls.length).toBe(2);
    });
    unmount();
    resolvePoll(status({ verification: 'verified', view: verifiedView() }));
    await act(async () => {
      await pollGate;
    });
    expect(screen.queryByLabelText('receipt')).not.toBeInTheDocument();
  });

  it('does not re-arm the timer when a failed poll lands after unmount', async () => {
    const pending = status({ verification: 'pending' });
    let rejectPoll!: (err: unknown) => void;
    const pollGate = new Promise<ReceiptStatus>((_, rej) => {
      rejectPoll = rej;
    });
    // Suppress the unhandled rejection warning: the component
    // attaches its catch after unmount.
    pollGate.catch(() => {});
    vi.mocked(client.fetchMissionReceipt).mockResolvedValueOnce(pending).mockReturnValueOnce(pollGate);

    const { unmount } = render(<ReceiptView passId="pass-1" pollIntervalMs={20} />);
    await waitFor(() => {
      expect(screen.getByText(/Receipt pending/)).toBeInTheDocument();
    });
    await waitFor(() => {
      expect(vi.mocked(client.fetchMissionReceipt).mock.calls.length).toBe(2);
    });
    unmount();
    rejectPoll(new Error('late poll failure'));
    await act(async () => {
      await new Promise((r) => setTimeout(r, 50));
    });
    expect(vi.mocked(client.fetchMissionReceipt).mock.calls.length).toBe(2);
  });
});
