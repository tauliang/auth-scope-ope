import { describe, expect, it, vi, afterEach } from 'vitest';
import { render, screen } from '@testing-library/react';
import { ConnectPage } from './ConnectPage';
import type { BootstrapResponse } from '../../shared/api/generated';

vi.mock('./GitHubConnection', () => ({
  GitHubConnectionComplete: () => <div data-testid="github-complete" />,
  GitHubConnectionStart: () => <div data-testid="github-start" />,
  githubCompletionPath: '/connect/github/done',
}));

function bootstrap(telemetry_state: 'enabled' | 'disabled'): BootstrapResponse {
  return {
    enrolled: true,
    enrollment_state: 'authenticated',
    workspace: { workspace_id: 'ws-test', hostname: 'ope.example.test' },
    compatibility: { status: 'ready', core_version: 'v1' },
    authority_labels: ['AuthScope mission authority'],
    telemetry_state,
  };
}

function stubLocation(pathname: string) {
  vi.stubGlobal('location', {
    pathname,
    href: `http://localhost${pathname}`,
    assign: vi.fn(),
  });
}

describe('ConnectPage telemetry disclosure', () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it('shows telemetry as off when the server reports disabled', () => {
    stubLocation('/');
    render(
      <ConnectPage bootstrap={bootstrap('disabled')} csrfToken="csrf-1" onAuthenticated={() => {}} />,
    );
    const section = screen.getByLabelText('telemetry');
    expect(section.textContent).toMatch(/off/);
    expect(section.textContent).not.toMatch(/on\b.*off|off.*\bon\b/);
  });

  it('shows telemetry as on when the server reports enabled', () => {
    stubLocation('/');
    render(
      <ConnectPage bootstrap={bootstrap('enabled')} csrfToken="csrf-1" onAuthenticated={() => {}} />,
    );
    expect(screen.getByLabelText('telemetry').textContent).toMatch(/on/);
  });

  it('explains what telemetry never contains', () => {
    stubLocation('/');
    render(
      <ConnectPage bootstrap={bootstrap('disabled')} csrfToken="csrf-1" onAuthenticated={() => {}} />,
    );
    const text = screen.getByLabelText('telemetry').textContent ?? '';
    expect(text).toMatch(/never contains/);
    expect(text).toMatch(/credentials/);
  });

  it('renders no secret material in the DOM', () => {
    stubLocation('/');
    const { container } = render(
      <ConnectPage bootstrap={bootstrap('disabled')} csrfToken="csrf-1" onAuthenticated={() => {}} />,
    );
    const html = container.innerHTML;
    // The bootstrap carries only opaque identifiers and the telemetry
    // state; no token, secret, or credential may reach the DOM.
    for (const token of ['ghp_', 'gho_', 'sk-', 'bearer ', 'BEGIN PRIVATE KEY']) {
      expect(html.toLowerCase()).not.toContain(token);
    }
  });
});
