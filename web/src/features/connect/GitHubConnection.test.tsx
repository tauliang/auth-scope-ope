import { describe, expect, it, vi, beforeEach, afterEach } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import {
  GitHubConnectionComplete,
  GitHubConnectionStart,
} from './GitHubConnection';
import { setCsrfToken } from '../../shared/api/client';
import type { GitHubConnection } from '../../shared/api/generated';

vi.mock('../../auth/PasskeySetup', () => ({
  default: () => <div data-testid="passkey-login">sign in</div>,
}));

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

function stubLocation(pathname: string) {
  const assign = vi.fn();
  vi.stubGlobal('location', { pathname, assign, href: `http://localhost${pathname}` });
  return assign;
}

function jsonResponse(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}

describe('GitHubConnectionStart', () => {
  beforeEach(() => {
    sessionStorage.clear();
    stubLocation('/');
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue(
        jsonResponse({
          handoff_id: 'hand-1',
          installation_url: 'https://authscope.local/install?h=h',
          expires_at: '2026-09-18T01:00:00Z',
        }),
      ),
    );
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it('rejects a malformed repository without calling the API', async () => {
    const user = userEvent.setup();
    const onConnected = vi.fn();
    render(<GitHubConnectionStart onConnected={onConnected} />);

    await user.type(screen.getByLabelText(/repository/i), 'not a repo');
    await user.click(screen.getByRole('button', { name: /connect repository/i }));

    expect(await screen.findByRole('alert')).toHaveTextContent(/owner\/name/i);
    expect(fetch).not.toHaveBeenCalled();
  });

  it('begins the handoff, stashes only the handoff ID, and redirects', async () => {
    const user = userEvent.setup();
    const onConnected = vi.fn();
    const assign = stubLocation('/');
    render(<GitHubConnectionStart onConnected={onConnected} />);

    await user.type(screen.getByLabelText(/repository/i), 'octo-org/my-repo');
    await user.click(screen.getByRole('button', { name: /connect repository/i }));

    await waitFor(() => expect(assign).toHaveBeenCalledWith('https://authscope.local/install?h=h'));

    const [url, init] = vi.mocked(fetch).mock.calls[0] as [string, RequestInit];
    expect(url).toBe('/api/v1/connections/github/begin');
    expect(init.method).toBe('POST');
    const headers = new Headers(init.headers);
    expect(headers.get('Content-Type')).toBe('application/json');
    expect(headers.get('Idempotency-Key')).toBeTruthy();

    const pending = JSON.parse(sessionStorage.getItem('ope.github.pendingHandoff') ?? '{}');
    expect(Object.keys(pending).sort()).toEqual(['handoff_id', 'repository']);
    expect(pending.handoff_id).toBe('hand-1');
    expect(sessionStorage.getItem('ope.github.pendingHandoff')).not.toContain('code');
  });

  it('shows the server problem and recovers', async () => {
    const user = userEvent.setup();
    vi.mocked(fetch).mockResolvedValue(
      jsonResponse({ title: 'Repository not found.', status: 404 }, 404),
    );
    render(<GitHubConnectionStart onConnected={vi.fn()} />);

    await user.type(screen.getByLabelText(/repository/i), 'octo-org/missing');
    await user.click(screen.getByRole('button', { name: /connect repository/i }));

    expect(await screen.findByRole('alert')).toHaveTextContent('Repository not found.');
    await user.click(screen.getByRole('button', { name: /try again/i }));
    expect(screen.queryByRole('alert')).not.toBeInTheDocument();
  });

  it('renders a stored connection and notifies the parent', async () => {
    sessionStorage.setItem('ope.github.connection', JSON.stringify(connection));
    const onConnected = vi.fn();
    render(<GitHubConnectionStart onConnected={onConnected} />);

    expect(await screen.findByText('octo-org/my-repo')).toBeInTheDocument();
    expect(screen.getByText('67890')).toBeInTheDocument();
    expect(onConnected).toHaveBeenCalledWith(connection);
    expect(fetch).not.toHaveBeenCalled();
  });

  it('clears the stored connection to connect a different repository', async () => {
    sessionStorage.setItem('ope.github.connection', JSON.stringify(connection));
    const user = userEvent.setup();
    const onConnected = vi.fn();
    render(<GitHubConnectionStart onConnected={onConnected} />);

    await user.click(await screen.findByRole('button', { name: /different repository/i }));
    expect(sessionStorage.getItem('ope.github.connection')).toBeNull();
    expect(onConnected).toHaveBeenLastCalledWith(null);
    expect(screen.getByLabelText(/repository/i)).toBeInTheDocument();
  });
});

describe('GitHubConnectionComplete', () => {
  const completeProps = {
    workspaceId: 'ws-test',
    hostname: 'ope.example.com',
    onAuthenticated: vi.fn(),
    onConnected: vi.fn(),
  };

  beforeEach(() => {
    sessionStorage.clear();
    stubLocation('/connect/github/done');
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(jsonResponse(connection)));
    // Mirrors App: the CSRF token lives in the client module in memory.
    setCsrfToken('csrf-1');
  });

  afterEach(() => {
    setCsrfToken(null);
    vi.unstubAllGlobals();
    vi.clearAllMocks();
  });

  it('asks for a fresh sign-in when the page holds no CSRF token', () => {
    render(<GitHubConnectionComplete {...completeProps} csrfToken={null} />);
    expect(screen.getByTestId('passkey-login')).toBeInTheDocument();
    expect(fetch).not.toHaveBeenCalled();
  });

  it('finishes the pending handoff and shows the connection', async () => {
    sessionStorage.setItem(
      'ope.github.pendingHandoff',
      JSON.stringify({ handoff_id: 'hand-1', repository: 'octo-org/my-repo' }),
    );
    const onConnected = vi.fn();
    render(<GitHubConnectionComplete {...completeProps} onConnected={onConnected} csrfToken="csrf-1" />);

    expect(await screen.findByRole('heading', { name: /github connected/i })).toBeInTheDocument();
    expect(screen.getByText('octo-org/my-repo')).toBeInTheDocument();
    expect(screen.getByText('12345')).toBeInTheDocument();

    const [url, init] = vi.mocked(fetch).mock.calls[0] as [string, RequestInit];
    expect(url).toBe('/api/v1/connections/github/hand-1/finish');
    expect(init.method).toBe('POST');
    const headers = new Headers(init.headers);
    expect(headers.get('X-CSRF-Token')).toBe('csrf-1');
    expect(headers.get('Idempotency-Key')).toBeTruthy();

    expect(onConnected).toHaveBeenCalledWith(connection);
    expect(sessionStorage.getItem('ope.github.pendingHandoff')).toBeNull();
    expect(JSON.parse(sessionStorage.getItem('ope.github.connection') ?? '{}').connection_id).toBe('conn-1');
  });

  it('reports a missing pending handoff with a start-over path', async () => {
    const assign = stubLocation('/connect/github/done');
    const user = userEvent.setup();
    render(<GitHubConnectionComplete {...completeProps} csrfToken="csrf-1" />);

    expect(await screen.findByRole('alert')).toHaveTextContent(/no pending github connection/i);
    expect(screen.queryByRole('button', { name: /retry/i })).not.toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: /start over/i }));
    expect(assign).toHaveBeenCalledWith('/');
  });

  it('retries a failed finish and keeps the pending handoff', async () => {
    sessionStorage.setItem(
      'ope.github.pendingHandoff',
      JSON.stringify({ handoff_id: 'hand-1', repository: 'octo-org/my-repo' }),
    );
    vi.mocked(fetch)
      .mockResolvedValueOnce(jsonResponse({ title: 'AuthScope is unreachable.', status: 502 }, 502))
      .mockResolvedValue(jsonResponse(connection));
    const user = userEvent.setup();
    render(<GitHubConnectionComplete {...completeProps} csrfToken="csrf-1" />);

    expect(await screen.findByRole('alert')).toHaveTextContent('AuthScope is unreachable.');
    expect(sessionStorage.getItem('ope.github.pendingHandoff')).not.toBeNull();

    await user.click(screen.getByRole('button', { name: /retry/i }));
    expect(await screen.findByRole('heading', { name: /github connected/i })).toBeInTheDocument();
    expect(vi.mocked(fetch)).toHaveBeenCalledTimes(2);
  });

  it('clears a gone handoff and offers start over', async () => {
    sessionStorage.setItem(
      'ope.github.pendingHandoff',
      JSON.stringify({ handoff_id: 'hand-1', repository: 'octo-org/my-repo' }),
    );
    vi.mocked(fetch).mockResolvedValue(
      jsonResponse({ title: 'Handoff expired.', status: 404 }, 404),
    );
    const user = userEvent.setup();
    const assign = stubLocation('/connect/github/done');
    render(<GitHubConnectionComplete {...completeProps} csrfToken="csrf-1" />);

    expect(await screen.findByRole('alert')).toHaveTextContent('Handoff expired.');
    expect(sessionStorage.getItem('ope.github.pendingHandoff')).toBeNull();
    await user.click(screen.getByRole('button', { name: /start over/i }));
    expect(assign).toHaveBeenCalledWith('/');
  });
});
