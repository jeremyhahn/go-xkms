import { defineConfig } from '@playwright/test';

// serverPort is the xkmsd ACME HTTPS listener (config key acme.https_addr,
// see start-server.sh), not an admin/SPA port -- xkmsd exposes no admin REST
// API or admin SPA on this or any other listener. See the ACME migration
// report for what that means for the specs in ./tests.
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
