import { defineConfig } from '@playwright/test';

// Browser e2e for the three-screen OPE journey. The harness
// (scripts/run-e2e.sh) boots two API servers and two web servers and
// exports the base URLs:
//
//   OPE_E2E_WEB_A / OPE_E2E_WEB_B   the two web origins
//   OPE_E2E_API_A / OPE_E2E_API_B   the two API servers (behind the proxy)
//   OPE_E2E_CODE_A / OPE_E2E_CODE_B the one-time bootstrap codes
//
// The UI tests skip cleanly when no browser executable is installed;
// the API-level tests in the same files run unconditionally through
// the request fixture, which needs no browser.
export default defineConfig({
  testDir: './test/e2e',
  testMatch: ['*.spec.ts'],
  timeout: 30_000,
  retries: 0,
  reporter: [['list']],
  use: {
    baseURL: process.env.OPE_E2E_WEB_A ?? 'http://localhost:15173',
  },
});
