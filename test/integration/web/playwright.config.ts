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

import { defineConfig } from '@playwright/test';

/**
 * Live-server E2E tier for the xKMS web console: drives Chrome's CDP virtual
 * WebAuthn authenticator (see tests/support/virtualAuthenticator.ts, lifted
 * from test/integration/webauthn-browser/tests/rp-ceremony.spec.ts) against
 * the SPA served BY a real running xkmsd at /ui/ — no REST calls are
 * intercepted here; everything hits the live server. The webServer hook
 * boots xkmsd via run-server.sh and waits for the REST port to accept
 * connections.
 *
 * ONLY run this in the devcontainer (`make integration-test-web`) — see
 * test/integration/CLAUDE.md. Never run against the host OS.
 */
export default defineConfig({
  testDir: './tests',
  timeout: 60_000,
  retries: 0,
  // The registration/login specs share one operator identity created on
  // first boot; running them out of process order would race that state.
  workers: 1,
  outputDir: 'test-results',
  reporter: [
    ['list'],
    ['html', { open: 'never', outputFolder: 'playwright-report' }],
  ],
  use: {
    browserName: 'chromium',
    headless: true,
    baseURL: 'https://localhost:18463',
    // The daemon's TLS cert is self-issued by its embedded CA (ensureTLSServerCert)
    // for this test's throwaway CA — not in any system trust store.
    ignoreHTTPSErrors: true,
    screenshot: 'only-on-failure',
    trace: 'on-first-retry',
    launchOptions: {
      // --no-sandbox: required for the CDP virtual authenticator in CI containers.
      args: ['--no-sandbox'],
    },
  },
  webServer: {
    command: 'bash ./run-server.sh',
    // TCP-only readiness check: an HTTP(S) `url` probe would itself need to
    // negotiate the self-signed TLS handshake, which is an extra failure mode
    // this only needs to rule out "is anything listening yet".
    port: 18463,
    reuseExistingServer: false,
    timeout: 180_000,
    stdout: 'pipe',
    stderr: 'pipe',
  },
});
