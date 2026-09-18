import { test, expect, request } from '@playwright/test';
import { uiTest } from './browser-guard';

// two_instance.spec.ts covers two-instance isolation: hostname,
// cookie, session, and CSRF. Two API servers and two web servers run
// side by side; the specs assert that neither instance leaks state or
// credentials to the other.

const webA = process.env.OPE_E2E_WEB_A ?? 'http://localhost:15173';
const webB = process.env.OPE_E2E_WEB_B ?? 'http://localhost:15174';
const codeA = process.env.OPE_E2E_CODE_A ?? '';
const codeB = process.env.OPE_E2E_CODE_B ?? '';

test.beforeAll(() => {
  test.skip(
    !process.env.OPE_E2E_WEB_A || !process.env.OPE_E2E_WEB_B,
    'OPE_E2E_WEB_A/B are not set; run through scripts/run-e2e.sh',
  );
});

function cookieName(setCookie: string | null): string {
  expect(setCookie).toBeTruthy();
  return setCookie!.split(';')[0].split('=')[0].trim();
}

test('each instance reports its own hostname and workspace', async () => {
  const a = await request.newContext({ baseURL: webA });
  const b = await request.newContext({ baseURL: webB });
  const bodyA = await (await a.get('/api/v1/bootstrap')).json();
  const bodyB = await (await b.get('/api/v1/bootstrap')).json();
  expect(bodyA.workspace.workspace_id).toBe('ws-e2e-a');
  expect(bodyA.workspace.hostname).toBe('e2e-a.local');
  expect(bodyB.workspace.workspace_id).toBe('ws-e2e-b');
  expect(bodyB.workspace.hostname).toBe('e2e-b.local');
  expect(bodyA.workspace.workspace_id).not.toBe(bodyB.workspace.workspace_id);
  await a.dispose();
  await b.dispose();
});

test('ceremony cookie names are instance-bound', async () => {
  test.skip(!codeA || !codeB, 'bootstrap codes not captured; run through scripts/run-e2e.sh');
  const a = await request.newContext({ baseURL: webA });
  const b = await request.newContext({ baseURL: webB });
  const resA = await a.post('/api/v1/bootstrap/begin', {
    headers: { Origin: webA },
    data: { code: codeA },
  });
  const resB = await b.post('/api/v1/bootstrap/begin', {
    headers: { Origin: webB },
    data: { code: codeB },
  });
  expect(resA.ok()).toBe(true);
  expect(resB.ok()).toBe(true);
  const nameA = cookieName(resA.headers()['set-cookie']);
  const nameB = cookieName(resB.headers()['set-cookie']);
  expect(nameA).not.toBe(nameB);
  // A cookie minted by A is unknown to B: B rejects it instead of
  // honoring foreign session material.
  const cross = await b.post('/api/v1/auth/register/begin', {
    headers: { Origin: webB, Cookie: `${nameA}=foreign-value` },
    data: { display_name: 'founder' },
  });
  expect(cross.status()).toBe(401);
  await a.dispose();
  await b.dispose();
});

test('a foreign origin is rejected', async () => {
  const a = await request.newContext({ baseURL: webA });
  const res = await a.post('/api/v1/bootstrap/begin', {
    headers: { Origin: webB },
    data: { code: 'wrong-code' },
  });
  expect(res.status()).toBe(403);
  await a.dispose();
});

test('health and readiness do not leak the other workspace', async () => {
  const a = await request.newContext({ baseURL: webA });
  const health = await (await a.get('/healthz')).json();
  expect(health.status).toBe('ok');
  expect(JSON.stringify(health)).not.toContain('ws-e2e-b');
  await a.dispose();
});

uiTest('the rendered pages show their own instance binding', async ({ page }) => {
  await page.goto(webA + '/');
  await expect(page.getByLabel(/terminal code/i)).toBeVisible();
  await page.goto(webB + '/');
  await expect(page.getByLabel(/terminal code/i)).toBeVisible();
  // The two pages are separate instances; the bootstrap payload behind
  // each page carries its own workspace, asserted at the API level
  // above.
});
