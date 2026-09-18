import { describe, expect, it, vi, beforeEach, afterEach } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import IssuePicker, { checkEligibility, parseIssueInput } from './IssuePicker';
import type {
  GitHubConnection,
  GitHubIssueResponse,
  GitHubPosture,
} from '../../shared/api/generated';

const connection: GitHubConnection = {
  connection_id: 'conn-1',
  workspace_id: 'ws-test',
  installation_id: 12345,
  repository_binding_id: 'bind-1',
  repository_id: 67890,
  repository_name: 'octo-org/my-repo',
  permission_status: 'ok',
  verified_at: '2026-09-18T00:00:00Z',
};

function posture(overrides: Partial<GitHubPosture> = {}): GitHubPosture {
  return {
    checked_at: new Date().toISOString(),
    expires_at: new Date(Date.now() + 60_000).toISOString(),
    head_sha: 'abc123',
    outcome: 'clean',
    reason_codes: [],
    ...overrides,
  };
}

function issueResponse(overrides: Partial<GitHubIssueResponse> = {}): GitHubIssueResponse {
  return {
    snapshot: {
      acceptance_criteria: ['criterion one', 'criterion two'],
      base_sha: 'base-sha',
      default_branch: 'main',
      installation_id: 12345,
      issue_number: 42,
      objective: 'Ship the thing.',
      repository_binding_id: 'bind-1',
      repository_full_name: 'octo-org/my-repo',
      repository_id: 67890,
      source_digest: 'digest-0123456789abcdef',
      source_revision: 'revision-0123456789abcdef',
      workspace_id: 'ws-test',
    },
    posture: posture(),
    ...overrides,
  };
}

function jsonResponse(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}

describe('parseIssueInput', () => {
  it('accepts a bare issue number', () => {
    expect(parseIssueInput('42', connection)).toEqual({ number: 42 });
  });

  it('accepts a matching issue URL', () => {
    expect(parseIssueInput('https://github.com/octo-org/my-repo/issues/42', connection)).toEqual({
      number: 42,
    });
  });

  it('rejects a URL for a different repository', () => {
    const result = parseIssueInput('https://github.com/other/repo/issues/7', connection);
    expect(result).toEqual({
      error: 'That URL points at other/repo, but octo-org/my-repo is connected.',
    });
  });

  it('rejects garbage input', () => {
    expect(parseIssueInput('hello', connection)).toEqual({
      error: 'Enter an issue number, or a GitHub issue URL.',
    });
  });
});

describe('checkEligibility', () => {
  it('allows a clean, fresh posture', () => {
    expect(checkEligibility(posture())).toEqual({ ok: true });
  });

  it('blocks a risky posture with a recovery path', () => {
    const result = checkEligibility(posture({ outcome: 'risky', reason_codes: ['unsafe_workflow'] }));
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.reason).toContain('unsafe_workflow');
      expect(result.recoverable).toBe(true);
    }
  });

  it('blocks an expired posture', () => {
    const result = checkEligibility(
      posture({ expires_at: new Date(Date.now() - 1000).toISOString() }),
    );
    expect(result).toEqual({
      ok: false,
      reason: expect.stringContaining('unverified'),
      recoverable: true,
    });
  });
});

describe('IssuePicker', () => {
  beforeEach(() => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(jsonResponse(issueResponse())));
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it('disables lookup until a repository is connected', () => {
    render(<IssuePicker connection={null} onAuthorize={vi.fn()} />);
    expect(screen.getByText(/connect a repository first/i)).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /look up issue/i })).toBeDisabled();
    expect(fetch).not.toHaveBeenCalled();
  });

  it('imports a clean issue and continues to Authorize', async () => {
    const user = userEvent.setup();
    const onAuthorize = vi.fn();
    render(<IssuePicker connection={connection} onAuthorize={onAuthorize} />);

    await user.type(screen.getByLabelText(/issue number or url/i), '42');
    await user.click(screen.getByRole('button', { name: /look up issue/i }));

    expect(await screen.findByText('Ship the thing.')).toBeInTheDocument();
    expect(screen.getByText('criterion one')).toBeInTheDocument();

    const [url] = vi.mocked(fetch).mock.calls[0] as [string, RequestInit?];
    expect(url).toBe('/api/v1/connections/github/conn-1/issues/42');

    const authorize = screen.getByRole('button', { name: /continue to authorize/i });
    expect(authorize).toBeEnabled();
    await user.click(authorize);
    expect(onAuthorize).toHaveBeenCalledWith(
      expect.objectContaining({ issue_number: 42 }),
    );
  });

  it('accepts an issue URL for the connected repository', async () => {
    const user = userEvent.setup();
    render(<IssuePicker connection={connection} onAuthorize={vi.fn()} />);

    await user.type(
      screen.getByLabelText(/issue number or url/i),
      'https://github.com/octo-org/my-repo/issues/42',
    );
    await user.click(screen.getByRole('button', { name: /look up issue/i }));

    expect(await screen.findByText('Ship the thing.')).toBeInTheDocument();
  });

  it('rejects a URL for another repository without calling the API', async () => {
    const user = userEvent.setup();
    render(<IssuePicker connection={connection} onAuthorize={vi.fn()} />);

    await user.type(
      screen.getByLabelText(/issue number or url/i),
      'https://github.com/other/repo/issues/7',
    );
    await user.click(screen.getByRole('button', { name: /look up issue/i }));

    expect(await screen.findByRole('alert')).toHaveTextContent(/other\/repo/);
    expect(fetch).not.toHaveBeenCalled();
  });

  it('blocks Authorize on risky posture without navigating', async () => {
    const user = userEvent.setup();
    const onAuthorize = vi.fn();
    vi.mocked(fetch).mockResolvedValue(
      jsonResponse(issueResponse({ posture: posture({ outcome: 'risky', reason_codes: ['unsafe_workflow'] }) })),
    );
    render(<IssuePicker connection={connection} onAuthorize={onAuthorize} />);

    await user.type(screen.getByLabelText(/issue number or url/i), '42');
    await user.click(screen.getByRole('button', { name: /look up issue/i }));

    expect(await screen.findByRole('alert')).toHaveTextContent(/unsafe_workflow/);
    const authorize = screen.getByRole('button', { name: /continue to authorize/i });
    expect(authorize).toBeDisabled();
    expect(onAuthorize).not.toHaveBeenCalled();

    // Recovery re-checks.
    await user.click(screen.getByRole('button', { name: /check again/i }));
    await waitFor(() => expect(vi.mocked(fetch)).toHaveBeenCalledTimes(2));
  });

  it('blocks Authorize on expired posture', async () => {
    const user = userEvent.setup();
    vi.mocked(fetch).mockResolvedValue(
      jsonResponse(
        issueResponse({ posture: posture({ expires_at: new Date(Date.now() - 1000).toISOString() }) }),
      ),
    );
    render(<IssuePicker connection={connection} onAuthorize={vi.fn()} />);

    await user.type(screen.getByLabelText(/issue number or url/i), '42');
    await user.click(screen.getByRole('button', { name: /look up issue/i }));

    expect(await screen.findByRole('alert')).toHaveTextContent(/unverified/i);
    expect(screen.getByRole('button', { name: /continue to authorize/i })).toBeDisabled();
  });

  it('reports a closed issue with a recovery path', async () => {
    const user = userEvent.setup();
    vi.mocked(fetch).mockResolvedValue(
      jsonResponse({ title: 'Issue is closed.', status: 404 }, 404),
    );
    render(<IssuePicker connection={connection} onAuthorize={vi.fn()} />);

    await user.type(screen.getByLabelText(/issue number or url/i), '42');
    await user.click(screen.getByRole('button', { name: /look up issue/i }));

    expect(await screen.findByRole('alert')).toHaveTextContent('Issue is closed.');
    expect(screen.queryByRole('button', { name: /continue to authorize/i })).not.toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: /try another issue/i }));
    expect(screen.getByLabelText(/issue number or url/i)).toHaveValue('');
  });

  it('offers a re-check on a stale revision', async () => {
    const user = userEvent.setup();
    vi.mocked(fetch).mockResolvedValue(
      jsonResponse({ title: 'Issue changed since the snapshot.', status: 409 }, 409),
    );
    render(<IssuePicker connection={connection} onAuthorize={vi.fn()} />);

    await user.type(screen.getByLabelText(/issue number or url/i), '42');
    await user.click(screen.getByRole('button', { name: /look up issue/i }));

    expect(await screen.findByRole('alert')).toHaveTextContent(/changed since the snapshot/i);
    await user.click(screen.getByRole('button', { name: /check again/i }));
    await waitFor(() => expect(vi.mocked(fetch)).toHaveBeenCalledTimes(2));
  });
});
