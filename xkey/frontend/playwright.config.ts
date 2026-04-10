import { defineConfig, devices } from '@playwright/test';

/**
 * Playwright E2E configuration for xKey Wails v2 desktop GUI.
 *
 * Supports two target environments:
 *   - Wails dev server: set BASE_URL=http://localhost:34115
 *   - Vite dev server (UI-only, default): auto-started on port 5199
 *
 * Override via the BASE_URL environment variable.
 */
const baseURL = process.env.BASE_URL || 'http://localhost:5199';

export default defineConfig({
  testDir: './tests/e2e',
  fullyParallel: true,
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 2 : 0,
  /* Limit workers to avoid overwhelming the Vite dev server.
     CI uses 1 worker for determinism; local defaults to 4. */
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
  timeout: 45_000,
  expect: {
    timeout: 10_000,
  },
  projects: [
    {
      name: 'chromium',
      use: { ...devices['Desktop Chrome'] },
    },
  ],
  /* Auto-start the Vite dev server when no explicit BASE_URL is given.
     Uses port 5199 to avoid conflicts with other local dev servers.
     reuseExistingServer skips startup if the port is already in use. */
  ...(!process.env.BASE_URL ? {
    webServer: {
      command: 'npx vite --port 5199',
      port: 5199,
      reuseExistingServer: true,
      timeout: 60_000,
    },
  } : {}),
});
