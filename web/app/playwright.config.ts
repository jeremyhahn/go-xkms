// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
//
// This file is part of go-xkms.
//
// go-xkms is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

import { defineConfig, devices } from '@playwright/test';

/**
 * Mock-API E2E tier for the xKMS web console.
 *
 * This tier is hermetic: it drives the SPA against a plain `vite` dev server
 * with NO backend xkmsd running. Every REST call the SPA makes is intercepted
 * with page.route() (see e2e/support/) — nothing here dials a real server.
 * That is what makes it runnable by anyone, anywhere, in `make test-web-e2e`.
 *
 * The real-server / real-WebAuthn tier lives at test/integration/web and runs
 * separately under `make integration-test-web` (devcontainer only).
 *
 * Override the target with BASE_URL (e.g. to point at an already-running
 * dev server) the same way xkey/frontend/playwright.config.ts does.
 */
const baseURL = process.env.BASE_URL || 'http://localhost:5180';

export default defineConfig({
  testDir: './e2e',
  fullyParallel: true,
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 2 : 0,
  // CI uses 1 worker for determinism; local defaults to 4.
  workers: process.env.CI ? 1 : (process.env.PW_WORKERS ? parseInt(process.env.PW_WORKERS) : 4),
  reporter: [
    ['html', { open: 'never' }],
    ['list'],
  ],
  use: {
    baseURL,
    trace: 'on-first-retry',
    screenshot: 'only-on-failure',
    video: 'retain-on-failure',
    actionTimeout: 10_000,
    navigationTimeout: 30_000,
  },
  timeout: 30_000,
  expect: {
    timeout: 5_000,
  },
  projects: [
    {
      name: 'chromium',
      use: { ...devices['Desktop Chrome'] },
    },
  ],
  // Auto-start the Vite dev server when no explicit BASE_URL is given. Dev
  // mode (not `vite preview`) is used deliberately: this tier must not
  // require a production build step to run. reuseExistingServer skips
  // startup if the port is already in use (e.g. a developer already has
  // `npm run dev` open).
  ...(!process.env.BASE_URL ? {
    webServer: {
      command: 'npx vite --port 5180 --strictPort',
      port: 5180,
      reuseExistingServer: true,
      timeout: 60_000,
    },
  } : {}),
});
