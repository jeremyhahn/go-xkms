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

// Ruling 973 on a live xkmsd (playwright.node.config.ts, config-node.yaml):
// the public WebAuthn routes looked users up through the qrdb client with the
// request's anonymous context, and the auth-enforcing embedded node refused
// them, so registration/begin and login/begin answered 500 once the server
// had users. The node refuses anonymous sign-up (403 registration_refused), so
// each operator is provisioned through an administrator-issued invitation and
// redeemed with a passkey (support/passkeyAccount.ts, given this suite's origin
// and state directory); the server is user-ful from `xkmsd init` on. This spec
// then signs an operator out and back in with the same passkey.

import { test, expect } from '@playwright/test';
import { installVirtualAuthenticator } from './support/virtualAuthenticator.ts';
import { loginOperator, uniqueOperator } from './support/operator.ts';
import { provisionOperator, type PasskeyServer } from './support/passkeyAccount.ts';

/** The daemon playwright.node.config.ts boots: config-node.yaml, .runtime-node. */
const NODE_SERVER: PasskeyServer = { origin: 'https://localhost:18464', runtimeDir: '.runtime-node' };

test.describe.serial('Passkeys over an auth-enforcing embedded node', () => {
  const first = uniqueOperator('node-first');
  const second = uniqueOperator('node-second');

  test('the first operator redeems an administrator-issued invitation and signs in', async ({ page }) => {
    await installVirtualAuthenticator(page);
    await provisionOperator(page, first, NODE_SERVER);
  });

  test('another operator redeems its invitation and signs back in with the same passkey', async ({ page }) => {
    await installVirtualAuthenticator(page);

    const registrationBegins: number[] = [];
    const loginBegins: number[] = [];
    page.on('response', (res) => {
      const path = new URL(res.url()).pathname;
      if (path.endsWith('/api/v1/webauthn/registration/begin')) registrationBegins.push(res.status());
      if (path.endsWith('/api/v1/webauthn/login/begin')) loginBegins.push(res.status());
    });

    await provisionOperator(page, second, NODE_SERVER);

    await page.getByRole('button', { name: 'Sign out' }).click();
    await expect(page.getByRole('button', { name: 'Sign in with passkey' })).toBeVisible();
    await expect(page.locator('aside')).toHaveCount(0);

    await loginOperator(page, second);
    await expect(page.getByText(second.displayName)).toBeVisible({ timeout: 10_000 });

    // On a user-ful server the public begin routes answer, never 500:
    // anonymous sign-up is refused and both sign-ins begin.
    expect(registrationBegins).toEqual([403]);
    expect(loginBegins).toEqual([200, 200]);
  });
});
