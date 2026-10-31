// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
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

import { defineConfig } from '@playwright/test';

// Drives Chrome's CDP virtual authenticator against a REAL running xkmsd
// server's WebAuthn Relying Party (/api/v1/webauthn/*). The webServer hook
// boots xkmsd on https://localhost:18443 and waits for /health.
export default defineConfig({
  testDir: './tests',
  timeout: 60_000,
  retries: 0,
  workers: 1,
  outputDir: 'test-results',
  reporter: [
    ['list'],
    ['html', { open: 'never', outputFolder: 'playwright-report' }],
  ],
  use: {
    browserName: 'chromium',
    headless: true,
    baseURL: 'https://localhost:18443',
    screenshot: 'only-on-failure',
    trace: 'on-first-retry',
    // xkmsd serves its self-signed bootstrap certificate (TLS-only transports).
    ignoreHTTPSErrors: true,
    // --no-sandbox: required for the CDP virtual authenticator in CI containers.
    // The disabled Private/Local Network Access features are a TEST-ONLY
    // concession: both the page (localhost:18444) and the RP (localhost:18443)
    // live in the loopback address space, which Chrome gates behind PNA
    // independently of the Origin-based CORS policy under test. A real
    // cross-origin consumer is a public web app calling a public RP and is not
    // subject to this loopback gate, so disabling it here keeps the test
    // focused on the application's CORS headers without altering production.
    launchOptions: {
      args: [
        '--no-sandbox',
        '--disable-features=PrivateNetworkAccessSendPreflights,PrivateNetworkAccessRespectPreflightResults,LocalNetworkAccessChecks,BlockInsecurePrivateNetworkRequests',
      ],
    },
  },
  webServer: {
    command: 'bash ./run-server.sh',
    url: 'https://localhost:18443/health',
    ignoreHTTPSErrors: true,
    reuseExistingServer: false,
    timeout: 120_000,
    stdout: 'pipe',
    stderr: 'pipe',
  },
});
