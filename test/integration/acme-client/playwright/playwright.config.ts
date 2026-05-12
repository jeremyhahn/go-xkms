import { defineConfig, devices } from '@playwright/test';

const CLIENT_PORT = parseInt(process.env.CLIENT_PORT || '18443', 10);
const CLIENT_BASE_URL = process.env.CLIENT_BASE_URL || `http://localhost:${CLIENT_PORT}`;

export default defineConfig({
  testDir: './tests',
  timeout: 30000,
  retries: process.env.CI ? 1 : 0,
  workers: 1,
  fullyParallel: false,
  reporter: [['list'], ['html', { open: 'never' }]],
  use: {
    baseURL: CLIENT_BASE_URL,
  },
  projects: [
    {
      name: 'chromium',
      use: { ...devices['Desktop Chrome'] },
    },
  ],
  webServer: {
    command: './start-server.sh',
    port: CLIENT_PORT,
    reuseExistingServer: !process.env.CI,
    timeout: 120000,
  },
});
