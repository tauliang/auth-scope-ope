import { test as baseTest, chromium } from '@playwright/test';
import fs from 'node:fs';

// browserInstalled reports whether a Playwright browser executable is
// present. The e2e harness is tolerant: UI tests skip with a clear
// message when no browser is installed instead of failing.
export function browserInstalled(): boolean {
  try {
    return fs.existsSync(chromium.executablePath());
  } catch {
    return false;
  }
}

// uiTest declares a test that needs a real browser. When no browser
// executable is installed the test is skipped; the API-level tests in
// the same files keep running through the request fixture.
export const uiTest = browserInstalled() ? baseTest : baseTest.skip;
