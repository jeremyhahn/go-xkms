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
// had users. The enforcing node refuses anonymous user creation (the WebAuthn
// service principal has no users:create), so each operator is provisioned by
// the administrator and redeems its invitation (provisionOperator). This spec
// makes the server user-ful first, then provisions another operator and signs
// it out and back in with the same passkey on the populated node.

import { test, expect } from '@playwright/test';
import { installVirtualAuthenticator } from './support/virtualAuthenticator.ts';
import { loginOperator, uniqueOperator } from './support/operator.ts';
import { provisionOperator } from './support/passkeyAccount.ts';

test.describe.serial('Passkeys over an auth-enforcing embedded node', () => {
  const first = uniqueOperator('node-first');
  const second = uniqueOperator('node-second');

  test('the first operator is provisioned, so the server has users', async ({ page }) => {
    await installVirtualAuthenticator(page);
    await provisionOperator(page, first);
  });

  test('another operator is provisioned and signs back in with the same passkey', async ({ page }) => {
    await installVirtualAuthenticator(page);
    await provisionOperator(page, second);

    const begins: number[] = [];
    page.on('response', (res) => {
      if (/\/api\/v1\/webauthn\/login\/begin$/.test(new URL(res.url()).pathname)) {
        begins.push(res.status());
      }
    });

    await page.getByRole('button', { name: 'Sign out' }).click();
    await expect(page.getByRole('button', { name: 'Sign in with passkey' })).toBeVisible();
    await expect(page.locator('aside')).toHaveCount(0);

    await loginOperator(page, second);
    await expect(page.getByText(second.displayName)).toBeVisible({ timeout: 10_000 });

    // The sign-in began on the populated node, not as a 500.
    expect(begins).toEqual([200]);
  });
});
