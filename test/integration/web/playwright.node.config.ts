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
import base from './playwright.config.ts';

/**
 * passkey-node.spec.ts against its own xkmsd (config-node.yaml, port 18464,
 * state under .runtime-node): passkey register and login on a server that
 * already has users, over its auth-enforcing embedded node (ruling 973).
 *
 *   npx playwright test -c playwright.node.config.ts
 *
 * ONLY run this in the devcontainer, as playwright.config.ts.
 */
export default defineConfig({
  ...base,
  testMatch: 'passkey-node.spec.ts',
  testIgnore: [],
  outputDir: 'test-results-node',
  reporter: [
    ['list'],
    ['html', { open: 'never', outputFolder: 'playwright-report-node' }],
  ],
  use: {
    ...base.use,
    baseURL: 'https://localhost:18464',
  },
  webServer: {
    command: 'XKMS_E2E_CONFIG=config-node.yaml XKMS_E2E_PORT=18464 XKMS_E2E_RUNTIME=.runtime-node bash ./run-server.sh',
    url: 'https://localhost:18464/health',
    ignoreHTTPSErrors: true,
    reuseExistingServer: false,
    timeout: 180_000,
    stdout: 'pipe',
    stderr: 'pipe',
  },
});
