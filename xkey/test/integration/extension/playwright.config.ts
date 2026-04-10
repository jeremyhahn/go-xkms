import { defineConfig } from '@playwright/test';

export default defineConfig({
  testDir: './tests',
  timeout: 30_000,
  expect: {
    timeout: 5_000,
  },
  fullyParallel: false,
  workers: 1,
  retries: process.env.CI ? 1 : 0,
  reporter: process.env.CI ? [['github'], ['list']] : 'list',
  // Run IPC tests first (reliable), pairing tests second, browser tests last (best-effort).
  testMatch: ['ipc-autofill.spec.ts', 'ipc-pairing.spec.ts', 'autofill.spec.ts'],
});
