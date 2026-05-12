import { defineConfig } from '@playwright/test';

const serverPort = Number(process.env.E2E_SERVER_PORT || 9443);

export default defineConfig({
  testDir: './tests',
  timeout: 30000,
  retries: 1,
  workers: 1, // Sequential - lifecycle tests depend on order
  fullyParallel: false,
  use: {
    baseURL: process.env.ADMIN_BASE_URL || `https://localhost:${serverPort}`,
    ignoreHTTPSErrors: true,
    launchOptions: {
      args: ['--ignore-certificate-errors'],
    },
  },
  projects: [
    { name: 'chromium', use: { browserName: 'chromium' } },
  ],
  webServer: {
    command: './start-server.sh',
    port: serverPort,
    timeout: 120000,
    reuseExistingServer: !process.env.CI,
    env: {
      E2E_SERVER_PORT: String(serverPort),
    },
    ignoreHTTPSErrors: true,
  },
  reporter: [
    ['list'],
    ['html', { open: 'never' }],
  ],
});
