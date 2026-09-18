import { describe, expect, it, vi, beforeEach, afterEach } from 'vitest';
import { render, screen } from '@testing-library/react';
import App from './App';
import type { BootstrapResponse } from './shared/api/generated';

const fakeBootstrap: BootstrapResponse = {
  enrolled: false,
  compatibility: { status: 'ready', core_version: 'ope-v1.0.0' },
  authority_labels: ['AuthScope mission authority'],
};

describe('App', () => {
  beforeEach(() => {
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue(new Response(JSON.stringify(fakeBootstrap), { status: 200 })),
    );
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it('renders the fake-backed bootstrap through the typed client', async () => {
    render(<App />);
    expect(await screen.findByText('No founder enrolled yet.')).toBeInTheDocument();
    expect(screen.getByText('No workspace bound yet.')).toBeInTheDocument();
    expect(screen.getByText(/Compatible.*ope-v1\.0\.0/)).toBeInTheDocument();
    expect(screen.getByText('AuthScope mission authority')).toBeInTheDocument();
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

  it('renders workspace binding and compatibility problems', async () => {
    const full: BootstrapResponse = {
      enrolled: true,
      workspace: { workspace_id: 'personal', hostname: 'ope.example' },
      compatibility: {
        status: 'not_ready',
        core_version: 'ope-v1.0.0',
        problems: ['vendored OpenAPI digest mismatch'],
      },
      authority_labels: ['AuthScope mission authority'],
    };
    vi.mocked(fetch).mockResolvedValue(new Response(JSON.stringify(full), { status: 200 }));
    render(<App />);
    expect(await screen.findByText('Founder enrolled.')).toBeInTheDocument();
    expect(screen.getByText('personal')).toBeInTheDocument();
    expect(screen.getByText('ope.example')).toBeInTheDocument();
    expect(screen.getByText('vendored OpenAPI digest mismatch')).toBeInTheDocument();
  });
});
