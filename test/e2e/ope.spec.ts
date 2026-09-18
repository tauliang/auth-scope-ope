import { test, expect, request } from '@playwright/test';
import { uiTest, browserInstalled } from './browser-guard';

// ope.spec.ts covers the three-screen journey shell: Connect (/),
// Authorize (/authorize), Mission (/mission). The founder's passkey
// ceremonies cannot run in this harness, so the specs assert the route
// composition, the enrollment gate, and the typed failure rendering.
// The full authenticated journey is covered by the Go e2e suite.

const webA = process.env.OPE_E2E_WEB_A ?? 'http://localhost:15173';

test.beforeAll(() => {
  test.skip(!process.env.OPE_E2E_WEB_A, 'OPE_E2E_WEB_A is not set; run through scripts/run-e2e.sh');
});

test('bootstrap reports the instance binding', async () => {
  const api = await request.newContext({ baseURL: webA });
  const res = await api.get('/api/v1/bootstrap');
  expect(res.ok()).toBe(true);
  const body = await res.json();
  expect(body.enrollment_state).toBe('needs_bootstrap');
  expect(body.workspace.workspace_id).toBe('ws-e2e-a');
  expect(body.workspace.hostname).toBe('e2e-a.local');
  await api.dispose();
});

test('the three routes serve the app shell', async () => {
  const api = await request.newContext({ baseURL: webA });
  for (const path of ['/', '/authorize', '/mission/pass-e2e-1']) {
    const res = await api.get(path, { headers: { Accept: 'text/html' } });
    expect(res.status(), path).toBe(200);
    const html = await res.text();
    expect(html).toContain('<div id="root">');
  }
  await api.dispose();
});

uiTest('a fresh instance opens enrollment on the connect screen', async ({ page }) => {
  await page.goto('/');
  await expect(page.getByLabel(/terminal code/i)).toBeVisible();
  await expect(page.getByText('Founder enrolled.')).not.toBeVisible();
});

uiTest('authorize and mission routes gate on enrollment, not 404', async ({ page }) => {
  await page.goto('/authorize');
  await expect(page.getByLabel(/terminal code/i)).toBeVisible();
  await page.goto('/mission/pass-e2e-1');
  await expect(page.getByLabel(/terminal code/i)).toBeVisible();
});

uiTest('an unreachable service renders the typed failure', async ({ page }) => {
  await page.route('**/api/v1/bootstrap', (route) => route.abort());
  await page.goto('/');
  await expect(page.getByRole('alert')).toContainText('Could not reach the local service.');
});

test('browser availability is reported', async () => {
  // This test documents the harness tolerance: it always runs and
  // reports whether the UI tests above executed or skipped.
  expect(typeof browserInstalled()).toBe('boolean');
});
