import { describe, expect, it, vi, beforeEach, afterEach } from 'vitest';
import { ApiError, fetchBootstrap, fetchHealth } from './client';

describe('api client', () => {
  beforeEach(() => {
    vi.stubGlobal('fetch', vi.fn());
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it('fetches the bootstrap document same-origin', async () => {
    const fake = {
      enrolled: false,
      compatibility: { status: 'ready', core_version: 'ope-v1.0.0' },
      authority_labels: ['AuthScope mission authority'],
    };
    vi.mocked(fetch).mockResolvedValue(new Response(JSON.stringify(fake), { status: 200 }));

    const got = await fetchBootstrap();
    expect(got.enrolled).toBe(false);
    expect(got.compatibility.core_version).toBe('ope-v1.0.0');

    const [, init] = vi.mocked(fetch).mock.calls[0] as [string, RequestInit];
    expect(init.credentials).toBe('same-origin');
  });

  it('raises ApiError on non-2xx', async () => {
    vi.mocked(fetch).mockResolvedValue(new Response('oops', { status: 503 }));
    await expect(fetchBootstrap()).rejects.toMatchObject({ status: 503 });
    await expect(fetchBootstrap()).rejects.toBeInstanceOf(ApiError);
  });

  it('fetches health from the local path', async () => {
    vi.mocked(fetch).mockResolvedValue(new Response(JSON.stringify({ status: 'ok' }), { status: 200 }));
    const health = await fetchHealth();
    expect(health.status).toBe('ok');
    const [path] = vi.mocked(fetch).mock.calls[0] as [string, RequestInit];
    expect(path).toBe('/healthz');
  });
});
