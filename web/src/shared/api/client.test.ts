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
  beginCliAuthorization,
  beginRevoke,
  fetchBootstrap,
  fetchHealth,
  fetchTimeline,
  finishCliAuthorization,
  finishRevoke,
  isRevokePending,
  setCsrfToken,
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

  it('begins a CLI authorization with an idempotency key', async () => {
    const begun = { challenge_id: 'challenge-1', options: {} };
    vi.mocked(fetch).mockResolvedValue(new Response(JSON.stringify(begun), { status: 201 }));
    const got = await beginCliAuthorization('authz-1', 'key-1');
    expect(got.challenge_id).toBe('challenge-1');
    const [path, init] = vi.mocked(fetch).mock.calls[0] as [string, RequestInit];
    expect(path).toBe('/api/v1/cli/authorizations/authz-1/approve/begin');
    expect((init.headers as Record<string, string>)['Idempotency-Key']).toBe('key-1');
  });

  it('finishes a CLI authorization following the loopback redirect', async () => {
    vi.mocked(fetch).mockResolvedValue(new Response('Return to the CLI.', { status: 200 }));
    await finishCliAuthorization('authz-1', 'challenge-1', { id: 'cred-1' }, 'key-2');
    const [path, init] = vi.mocked(fetch).mock.calls[0] as [string, RequestInit];
    expect(path).toBe('/api/v1/cli/authorizations/authz-1/approve/finish');
    expect(init.method).toBe('POST');
    expect(init.redirect).toBe('follow');
    expect(init.credentials).toBe('same-origin');
    expect(JSON.parse(init.body as string)).toMatchObject({ challenge_id: 'challenge-1' });
  });

  it('raises ApiError when the CLI finish fails', async () => {
    vi.mocked(fetch).mockResolvedValue(
      new Response(JSON.stringify({ title: 'gone' }), {
        status: 409,
        headers: { 'Content-Type': 'application/problem+json' },
      }),
    );
    await expect(finishCliAuthorization('authz-1', 'challenge-1', {})).rejects.toMatchObject({ status: 409 });
  });

  it('mints an idempotency key when the CLI begin omits one', async () => {
    vi.mocked(fetch).mockResolvedValue(new Response(JSON.stringify({ challenge_id: 'c1' }), { status: 201 }));
    await beginCliAuthorization('authz-1');
    const [, init] = vi.mocked(fetch).mock.calls[0] as [string, RequestInit];
    expect((init.headers as Record<string, string>)['Idempotency-Key']).toBeTruthy();
  });

  it('omits the CSRF header on CLI finish without a session token', async () => {
    setCsrfToken(null);
    vi.mocked(fetch).mockResolvedValue(new Response('Return to the CLI.', { status: 200 }));
    await finishCliAuthorization('authz-1', 'challenge-1', { id: 'cred-1' });
    const [, init] = vi.mocked(fetch).mock.calls[0] as [string, RequestInit];
    expect((init.headers as Record<string, string>)['X-CSRF-Token']).toBeUndefined();
    expect((init.headers as Record<string, string>)['Idempotency-Key']).toBeTruthy();
  });

  it('sends the CSRF token on CLI finish after login', async () => {
    setCsrfToken('csrf-9');
    vi.mocked(fetch).mockResolvedValue(new Response('Return to the CLI.', { status: 200 }));
    await finishCliAuthorization('authz-1', 'challenge-1', { id: 'cred-1' });
    const [, init] = vi.mocked(fetch).mock.calls[0] as [string, RequestInit];
    expect((init.headers as Record<string, string>)['X-CSRF-Token']).toBe('csrf-9');
    setCsrfToken(null);
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

describe('revocation client', () => {
  beforeEach(() => {
    vi.stubGlobal('fetch', vi.fn());
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it('fetches the mission timeline with cursor and limit', async () => {
    const page = { pass_id: 'pass-1', events: [], cursor: 'c1' };
    vi.mocked(fetch).mockResolvedValue(new Response(JSON.stringify(page), { status: 200 }));
    const got = await fetchTimeline('pass-1', 'c0', 100);
    expect(got.cursor).toBe('c1');
    const [path, init] = vi.mocked(fetch).mock.calls[0] as [string, RequestInit];
    expect(path).toBe('/api/v1/mission-passes/pass-1/events?after=c0&limit=100');
    expect(init.credentials).toBe('same-origin');
  });

  it('fetches the timeline without pagination', async () => {
    vi.mocked(fetch).mockResolvedValue(new Response(JSON.stringify({ events: [] }), { status: 200 }));
    await fetchTimeline('pass-1');
    const [path] = vi.mocked(fetch).mock.calls[0] as [string, RequestInit];
    expect(path).toBe('/api/v1/mission-passes/pass-1/events');
  });

  it('begins a revocation with the reason and an idempotency key', async () => {
    const begun = { challenge_id: 'challenge-1', options: {} };
    vi.mocked(fetch).mockResolvedValue(new Response(JSON.stringify(begun), { status: 200 }));
    const got = await beginRevoke('pass-1', 'safety_concern', 'key-1');
    expect(got.challenge_id).toBe('challenge-1');
    const [path, init] = vi.mocked(fetch).mock.calls[0] as [string, RequestInit];
    expect(path).toBe('/api/v1/mission-passes/pass-1/revoke/begin');
    expect(JSON.parse(init.body as string)).toMatchObject({ reason: 'safety_concern' });
    expect((init.headers as Record<string, string>)['Idempotency-Key']).toBe('key-1');
  });

  it('finishes a revocation and returns the result', async () => {
    const result = { pass_id: 'pass-1', revoked: true, containment: 'acknowledged' };
    vi.mocked(fetch).mockResolvedValue(new Response(JSON.stringify(result), { status: 200 }));
    const got = await finishRevoke('pass-1', 'challenge-1', { id: 'cred-1' }, 'key-2');
    expect(isRevokePending(got)).toBe(false);
    const [path, init] = vi.mocked(fetch).mock.calls[0] as [string, RequestInit];
    expect(path).toBe('/api/v1/mission-passes/pass-1/revoke/finish');
    expect(JSON.parse(init.body as string)).toMatchObject({ challenge_id: 'challenge-1' });
  });

  it('returns the pending reconciliation on a 202 revocation finish', async () => {
    const pending = { pass_id: 'pass-1', reconciliation: 'pending' };
    vi.mocked(fetch).mockResolvedValue(new Response(JSON.stringify(pending), { status: 202 }));
    const got = await finishRevoke('pass-1', 'challenge-1', { id: 'cred-1' });
    expect(isRevokePending(got)).toBe(true);
  });

  it('raises ApiError when the revocation begin fails', async () => {
    vi.mocked(fetch).mockResolvedValue(
      new Response(JSON.stringify({ title: 'not revocable' }), {
        status: 409,
        headers: { 'Content-Type': 'application/problem+json' },
      }),
    );
    await expect(beginRevoke('pass-1', 'founder_requested')).rejects.toMatchObject({ status: 409 });
  });

  it('finishes a CLI revocation handoff through the normal finish route', async () => {
    vi.mocked(fetch).mockResolvedValue(new Response('Return to the CLI.', { status: 200 }));
    const got = await finishRevoke('pass-1', 'challenge-1', { id: 'cred-1' }, 'key-4', 'req-1');
    expect(got).toEqual({ handedToCli: true });
    const [path, init] = vi.mocked(fetch).mock.calls[0] as [string, RequestInit];
    expect(path).toBe('/api/v1/mission-passes/pass-1/revoke/finish');
    expect(JSON.parse(init.body as string)).toMatchObject({
      challenge_id: 'challenge-1',
      cli_revocation_id: 'req-1',
    });
  });
});

describe('revocation client edge cases', () => {
  beforeEach(() => {
    vi.stubGlobal('fetch', vi.fn());
    setCsrfToken(null);
  });

  afterEach(() => {
    vi.unstubAllGlobals();
    setCsrfToken(null);
  });

  it('attaches the CSRF token on revocation finish after login', async () => {
    setCsrfToken('csrf-7');
    vi.mocked(fetch).mockResolvedValue(
      new Response(JSON.stringify({ pass_id: 'pass-1' }), { status: 200 }),
    );
    await finishRevoke('pass-1', 'challenge-1', { id: 'cred-1' });
    const [, init] = vi.mocked(fetch).mock.calls[0] as [string, RequestInit];
    expect((init.headers as Record<string, string>)['X-CSRF-Token']).toBe('csrf-7');
  });

  it('attaches the CSRF token on CLI revocation handoff finish', async () => {
    setCsrfToken('csrf-8');
    vi.mocked(fetch).mockResolvedValue(new Response('Return to the CLI.', { status: 200 }));
    await finishRevoke('pass-1', 'challenge-1', { id: 'cred-1' }, 'key-5', 'req-1');
    const [, init] = vi.mocked(fetch).mock.calls[0] as [string, RequestInit];
    expect((init.headers as Record<string, string>)['X-CSRF-Token']).toBe('csrf-8');
  });

  it('raises ApiError when the CLI revocation finish fails', async () => {
    vi.mocked(fetch).mockResolvedValue(
      new Response(JSON.stringify({ title: 'gone' }), {
        status: 410,
        headers: { 'Content-Type': 'application/problem+json' },
      }),
    );
    await expect(
      finishRevoke('pass-1', 'challenge-1', {}, 'key-6', 'req-1'),
    ).rejects.toMatchObject({
      status: 410,
    });
  });

  it('raises ApiError when the timeline fetch fails', async () => {
    vi.mocked(fetch).mockResolvedValue(new Response('oops', { status: 500 }));
    await expect(fetchTimeline('pass-1')).rejects.toBeInstanceOf(ApiError);
  });

  it('mints an idempotency key when the revocation finish omits one', async () => {
    vi.mocked(fetch).mockResolvedValue(new Response(JSON.stringify({ pass_id: 'pass-1' }), { status: 200 }));
    await finishRevoke('pass-1', 'challenge-1', {});
    const [, init] = vi.mocked(fetch).mock.calls[0] as [string, RequestInit];
    expect((init.headers as Record<string, string>)['Idempotency-Key']).toBeTruthy();
  });
});
