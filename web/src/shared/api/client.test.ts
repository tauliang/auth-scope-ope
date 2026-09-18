import { describe, expect, it, vi, beforeEach, afterEach } from 'vitest';
import {
  ApiError,
  authBootstrapBegin,
  authBootstrapComplete,
  authBootstrapRecoveryBegin,
  authBootstrapRegisterBegin,
  authBootstrapRegisterFinish,
  authLoginBegin,
  authLoginFinish,
  fetchBootstrap,
  fetchHealth,
} from './client';

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

describe('auth client', () => {
  beforeEach(() => {
    vi.stubGlobal('fetch', vi.fn());
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  function ok(body: unknown) {
    vi.mocked(fetch).mockResolvedValue(new Response(JSON.stringify(body), { status: 200 }));
  }

  function lastCall(): [string, RequestInit] {
    const calls = vi.mocked(fetch).mock.calls;
    return calls[calls.length - 1] as [string, RequestInit];
  }

  it('posts the bootstrap code to /api/v1/bootstrap/begin', async () => {
    ok({ expires_at: 't' });
    const res = await authBootstrapBegin('code-1');
    expect(res.expires_at).toBe('t');
    const [path, init] = lastCall();
    expect(path).toBe('/api/v1/bootstrap/begin');
    expect(init.method).toBe('POST');
    expect(JSON.parse(init.body as string)).toEqual({ code: 'code-1' });
  });

  it('omits display_name when not provided', async () => {
    ok({ ceremony_id: 'c', options: {} });
    await authBootstrapRegisterBegin();
    const [path, init] = lastCall();
    expect(path).toBe('/api/v1/auth/register/begin');
    expect(JSON.parse(init.body as string)).toEqual({});
    ok({ ceremony_id: 'c', options: {} });
    await authBootstrapRegisterBegin('Shengquan');
    expect(JSON.parse((lastCall()[1].body as string))).toEqual({ display_name: 'Shengquan' });
  });

  it('finishes registration with the ceremony id and attestation', async () => {
    ok({ credential_id: 'k' });
    await authBootstrapRegisterFinish('c1', { id: 'att' });
    const [path, init] = lastCall();
    expect(path).toBe('/api/v1/auth/register/finish');
    expect(JSON.parse(init.body as string)).toEqual({ ceremony_id: 'c1', response: { id: 'att' } });
  });

  it('begins recovery with the chosen method', async () => {
    ok({ method: 'offline_key', recovery_key: 'rk' });
    const res = await authBootstrapRecoveryBegin('offline_key');
    expect(res.recovery_key).toBe('rk');
    const [path, init] = lastCall();
    expect(path).toBe('/api/v1/bootstrap/recovery/begin');
    expect(JSON.parse(init.body as string)).toEqual({ method: 'offline_key' });
  });

  it('completes bootstrap with or without a recovery confirmation', async () => {
    ok({ csrf_token: 'csrf' });
    await authBootstrapComplete('rk-1');
    let [path, init] = lastCall();
    expect(path).toBe('/api/v1/bootstrap/complete');
    expect(JSON.parse(init.body as string)).toEqual({ recovery_confirmation: 'rk-1' });
    ok({ csrf_token: 'csrf' });
    await authBootstrapComplete();
    [path, init] = lastCall();
    expect(JSON.parse(init.body as string)).toEqual({});
  });

  it('runs the login ceremony', async () => {
    ok({ ceremony_id: 'lc', options: {} });
    await authLoginBegin();
    expect(lastCall()[0]).toBe('/api/v1/auth/login/begin');
    ok({ csrf_token: 'csrf' });
    const done = await authLoginFinish('lc', { id: 'assert' });
    expect(done.csrf_token).toBe('csrf');
    const [path, init] = lastCall();
    expect(path).toBe('/api/v1/auth/login/finish');
    expect(JSON.parse(init.body as string)).toEqual({ ceremony_id: 'lc', response: { id: 'assert' } });
  });

  it('surfaces the problem title from auth failures', async () => {
    vi.mocked(fetch).mockResolvedValue(
      new Response(JSON.stringify({ title: 'invalid bootstrap code' }), { status: 401 }),
    );
    await expect(authBootstrapBegin('bad')).rejects.toMatchObject({
      status: 401,
      title: 'invalid bootstrap code',
    });
  });

  it('falls back to the status message when the problem body is unreadable', async () => {
    vi.mocked(fetch).mockResolvedValue(new Response('not json', { status: 500 }));
    const err: unknown = await authLoginBegin().catch((e: unknown) => e);
    expect(err).toBeInstanceOf(ApiError);
    expect((err as ApiError).title).toContain('500');
  });
});
