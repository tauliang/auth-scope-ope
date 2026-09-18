import { describe, expect, it, vi, beforeEach, afterEach } from 'vitest';
import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import App from './App';
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
