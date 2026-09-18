import { describe, expect, it, vi, beforeEach, afterEach } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import App, { routeForPath } from './App';
import type { BootstrapResponse } from './shared/api/generated';

vi.mock('./shared/webauthn', () => ({
  createPasskey: vi.fn().mockResolvedValue({ id: 'cred-1' }),
  getPasskey: vi.fn().mockResolvedValue({ id: 'cred-1' }),
}));

const baseBootstrap: BootstrapResponse = {
  enrolled: false,
  enrollment_state: 'needs_bootstrap',
  compatibility: { status: 'ready', core_version: 'ope-v1.0.0' },
  authority_labels: ['AuthScope mission authority'],
  workspace: { workspace_id: 'ws-test', hostname: 'ope.example.com' },
};

function bootstrapResponse(overrides: Partial<BootstrapResponse>): BootstrapResponse {
  return { ...baseBootstrap, ...overrides };
}

describe('App', () => {
  beforeEach(() => {
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue(new Response(JSON.stringify(baseBootstrap), { status: 200 })),
    );
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it('routes a fresh instance to founder enrollment', async () => {
    render(<App />);
    expect(await screen.findByLabelText(/terminal code/i)).toBeInTheDocument();
  });

  it('resumes a ceremony with a registered passkey at recovery choice', async () => {
    vi.mocked(fetch).mockResolvedValue(
      new Response(
        JSON.stringify(bootstrapResponse({ enrollment_state: 'needs_recovery_method' })),
        { status: 200 },
      ),
    );
    render(<App />);
    expect(await screen.findByRole('button', { name: /use a second passkey/i })).toBeInTheDocument();
  });

  it('routes an enrolled instance to passkey unlock', async () => {
    vi.mocked(fetch).mockResolvedValue(
      new Response(JSON.stringify(bootstrapResponse({ enrolled: true, enrollment_state: 'locked' })), {
        status: 200,
      }),
    );
    render(<App />);
    expect(await screen.findByRole('button', { name: /authenticate with passkey/i })).toBeInTheDocument();
  });

  it('runs enrollment end to end and lands on the authenticated product', async () => {
    const user = userEvent.setup();
    const states = [
      bootstrapResponse({}),
      bootstrapResponse({ enrolled: true, enrollment_state: 'authenticated' }),
    ];
    let bootstrapCalls = 0;
    vi.mocked(fetch).mockImplementation(async (input: RequestInfo | URL) => {
      const url = String(input);
      if (url === '/api/v1/bootstrap') {
        const body = states[Math.min(bootstrapCalls, states.length - 1)];
        bootstrapCalls += 1;
        return new Response(JSON.stringify(body), { status: 200 });
      }
      if (url === '/api/v1/bootstrap/begin') return new Response('{}', { status: 200 });
      if (url === '/api/v1/auth/register/begin') {
        return new Response(JSON.stringify({ ceremony_id: 'c1', options: {} }), { status: 200 });
      }
      if (url === '/api/v1/auth/register/finish') {
        return new Response(JSON.stringify({ credential_id: 'cred-1' }), { status: 200 });
      }
      if (url === '/api/v1/bootstrap/recovery/begin') {
        return new Response(JSON.stringify({ method: 'offline_key', recovery_key: 'rk-1' }), {
          status: 200,
        });
      }
      if (url === '/api/v1/bootstrap/complete') {
        return new Response(JSON.stringify({ csrf_token: 'csrf-1' }), { status: 200 });
      }
      return new Response('not found', { status: 404 });
    });

    render(<App />);
    await user.type(await screen.findByLabelText(/terminal code/i), 'code-1');
    await user.click(screen.getByRole('button', { name: /begin enrollment/i }));
    await user.click(await screen.findByRole('button', { name: /register passkey/i }));
    await user.click(await screen.findByRole('button', { name: /use an offline recovery key/i }));
    expect(await screen.findByText('rk-1')).toBeInTheDocument();
    await user.click(screen.getByLabelText(/i have stored this key securely/i));
    await user.click(screen.getByRole('button', { name: /complete enrollment/i }));

    expect(await screen.findByText('Founder enrolled.')).toBeInTheDocument();
    expect(screen.getByText('ws-test')).toBeInTheDocument();
  });

  it('renders an error when the service is unreachable', async () => {
    vi.mocked(fetch).mockRejectedValue(new Error('down'));
    render(<App />);
    expect(await screen.findByRole('alert')).toHaveTextContent('unreachable');
  });

  it('renders the upstream status on ApiError', async () => {
    const { ApiError } = await import('./shared/api/client');
    vi.mocked(fetch).mockRejectedValue(new ApiError(503, 'not ready'));
    render(<App />);
    expect(await screen.findByRole('alert')).toHaveTextContent('upstream 503');
  });

  it('threads the CSRF token into GitHub requests after login', async () => {
    sessionStorage.clear();
    const user = userEvent.setup();
    const states = [
      bootstrapResponse({ enrolled: true, enrollment_state: 'locked' }),
      bootstrapResponse({ enrolled: true, enrollment_state: 'authenticated' }),
    ];
    let bootstrapCalls = 0;
    vi.mocked(fetch).mockImplementation(async (input: RequestInfo | URL) => {
      const url = String(input);
      if (url === '/api/v1/bootstrap') {
        const body = states[Math.min(bootstrapCalls, states.length - 1)];
        bootstrapCalls += 1;
        return new Response(JSON.stringify(body), { status: 200 });
      }
      if (url === '/api/v1/auth/login/begin') {
        return new Response(JSON.stringify({ ceremony_id: 'c1', options: {} }), { status: 200 });
      }
      if (url === '/api/v1/auth/login/finish') {
        return new Response(JSON.stringify({ csrf_token: 'csrf-1' }), { status: 200 });
      }
      if (url === '/api/v1/connections/github/begin') {
        return new Response(
          JSON.stringify({
            handoff_id: 'hand-1',
            installation_url: 'https://authscope.local/install?h=h',
            expires_at: '2026-09-18T01:00:00Z',
          }),
          { status: 200 },
        );
      }
      return new Response('not found', { status: 404 });
    });

    const assign = vi.fn();
    vi.stubGlobal('location', { pathname: '/', assign, href: 'http://localhost/' });

    render(<App />);
    await user.click(await screen.findByRole('button', { name: /authenticate with passkey/i }));
    expect(await screen.findByText('Founder enrolled.')).toBeInTheDocument();

    // The GitHub connect form is on the connect screen; the issue
    // selection entry links to the authorize screen.
    expect(screen.getByRole('heading', { name: /github connection/i })).toBeInTheDocument();
    expect(screen.getByRole('link', { name: /select an issue/i })).toHaveAttribute(
      'href',
      '/authorize',
    );

    await user.type(screen.getByLabelText(/repository \(owner\/name\)/i), 'octo-org/my-repo');
    await user.click(screen.getByRole('button', { name: /connect repository/i }));

    await waitFor(() => expect(assign).toHaveBeenCalled());
    const beginCall = vi
      .mocked(fetch)
      .mock.calls.find(([u]) => String(u) === '/api/v1/connections/github/begin');
    expect(beginCall).toBeDefined();
    const headers = new Headers((beginCall as [string, RequestInit])[1].headers);
    expect(headers.get('X-CSRF-Token')).toBe('csrf-1');
    expect(headers.get('Idempotency-Key')).toBeTruthy();
  });

  it('finishes the GitHub connection on the callback path after login', async () => {
    sessionStorage.clear();
    sessionStorage.setItem(
      'ope.github.pendingHandoff',
      JSON.stringify({ handoff_id: 'hand-1', repository: 'octo-org/my-repo' }),
    );
    const user = userEvent.setup();
    const connection = {
      connection_id: 'conn-1',
      workspace_id: 'ws-test',
      installation_id: 12345,
      repository_binding_id: 'bind-1',
      repository_id: 67890,
      repository_name: 'octo-org/my-repo',
      permission_status: 'ok',
      verified_at: '2026-09-18T00:00:00Z',
    };
    const states = [
      bootstrapResponse({ enrolled: true, enrollment_state: 'locked' }),
      bootstrapResponse({ enrolled: true, enrollment_state: 'authenticated' }),
    ];
    let bootstrapCalls = 0;
    vi.mocked(fetch).mockImplementation(async (input: RequestInfo | URL) => {
      const url = String(input);
      if (url === '/api/v1/bootstrap') {
        const body = states[Math.min(bootstrapCalls, states.length - 1)];
        bootstrapCalls += 1;
        return new Response(JSON.stringify(body), { status: 200 });
      }
      if (url === '/api/v1/auth/login/begin') {
        return new Response(JSON.stringify({ ceremony_id: 'c1', options: {} }), { status: 200 });
      }
      if (url === '/api/v1/auth/login/finish') {
        return new Response(JSON.stringify({ csrf_token: 'csrf-1' }), { status: 200 });
      }
      if (url === '/api/v1/connections/github/hand-1/finish') {
        return new Response(JSON.stringify(connection), { status: 200 });
      }
      return new Response('not found', { status: 404 });
    });

    vi.stubGlobal('location', {
      pathname: '/connect/github/done',
      assign: vi.fn(),
      href: 'http://localhost/connect/github/done',
    });

    render(<App />);
    // The round-trip drops in-memory state, so a fresh passkey login runs first.
    await user.click(await screen.findByRole('button', { name: /authenticate with passkey/i }));
    expect(await screen.findByRole('heading', { name: /github connected/i })).toBeInTheDocument();
    expect(screen.getByText('octo-org/my-repo')).toBeInTheDocument();
    expect(sessionStorage.getItem('ope.github.pendingHandoff')).toBeNull();
  });

  it('routes the transient CLI authorization path after login', async () => {
    sessionStorage.clear();
    const user = userEvent.setup();
    const begun = {
      challenge_id: 'challenge-9',
      assertion_options: { publicKey: { challenge: 'abc' } },
      pass_id: 'pass-1',
      repository_name: 'octo-org/host',
      issue_number: 7,
      proposal_digest: `sha256:${'f'.repeat(64)}`,
      invocation_digest: `sha256:${'d'.repeat(64)}`,
      agent_kit_id: 'authscope-agent-kit',
      agent_kit_version: '1.0.0',
      runner_arguments: ['authscope-agent-run', '--mission'],
    };
    vi.mocked(fetch).mockImplementation(async (input: RequestInfo | URL) => {
      const url = String(input);
      if (url === '/api/v1/bootstrap') {
        return new Response(
          JSON.stringify(bootstrapResponse({ enrolled: true, enrollment_state: 'authenticated' })),
          { status: 200 },
        );
      }
      if (url === '/api/v1/auth/login/begin') {
        return new Response(JSON.stringify({ ceremony_id: 'c1', options: {} }), { status: 200 });
      }
      if (url === '/api/v1/auth/login/finish') {
        return new Response(JSON.stringify({ csrf_token: 'csrf-1' }), { status: 200 });
      }
      if (url === '/api/v1/cli/authorizations/authz-9/approve/begin') {
        return new Response(JSON.stringify(begun), { status: 201 });
      }
      return new Response('not found', { status: 404 });
    });
    vi.stubGlobal('location', {
      pathname: '/authorize/cli/authz-9',
      href: 'http://localhost/authorize/cli/authz-9',
      assign: vi.fn(),
    });

    render(<App />);
    await user.click(await screen.findByRole('button', { name: /authenticate with passkey/i }));

    // The transient route renders the CLI authorization page with the
    // pinned launch bindings, not the regular product.
    expect(await screen.findByText('octo-org/host')).toBeInTheDocument();
    expect(screen.getByText('#7')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Authorize launch with passkey' })).toBeInTheDocument();
    expect(screen.queryByRole('heading', { name: /github connection/i })).not.toBeInTheDocument();
  });

  it('starts a fresh passkey login when the page holds no CSRF token', async () => {
    const full = bootstrapResponse({
      enrolled: true,
      enrollment_state: 'authenticated',
      workspace: { workspace_id: 'personal', hostname: 'ope.example' },
      compatibility: {
        status: 'not_ready',
        core_version: 'ope-v1.0.0',
        problems: ['vendored OpenAPI digest mismatch'],
      },
    });
    // First paint reports an authenticated session but this page holds no
    // CSRF token in memory, so the App starts a fresh passkey login.
    vi.mocked(fetch).mockImplementation(async (input: RequestInfo | URL) => {
      if (String(input) === '/api/v1/bootstrap') {
        return new Response(JSON.stringify(full), { status: 200 });
      }
      return new Response('not found', { status: 404 });
    });
    render(<App />);
    expect(await screen.findByRole('button', { name: /authenticate with passkey/i })).toBeInTheDocument();
  });
});

describe('routeForPath', () => {
  it('maps every known path to exactly one of the three screens', () => {
    expect(routeForPath('/')).toBe('connect');
    expect(routeForPath('/connect/github/done')).toBe('connect');
    expect(routeForPath('/authorize')).toBe('authorize');
    expect(routeForPath('/authorize/cli/abc123')).toBe('authorize');
    expect(routeForPath('/mission')).toBe('mission');
    expect(routeForPath('/mission/pass-1')).toBe('mission');
  });

  it('falls back to connect for unknown paths', () => {
    expect(routeForPath('/nope')).toBe('connect');
    expect(routeForPath('/api/v1/foo')).toBe('connect');
  });

  it('exposes exactly three screens', () => {
    const screens = new Set([
      routeForPath('/'),
      routeForPath('/authorize'),
      routeForPath('/mission/pass-1'),
    ]);
    expect([...screens].sort()).toEqual(['authorize', 'connect', 'mission']);
  });
});
