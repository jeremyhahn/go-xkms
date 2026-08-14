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

/**
 * Real passkey registration and login end-to-end through the browser,
 * against a real running xkmsd. No REST call is intercepted anywhere in this
 * tier — this proves the SPA, @go-xkms/svelte-auth, the SDK's WebAuthn wire
 * bridge, and xkmsd's Relying Party all agree on the wire format, which the
 * mock tier (web/app/e2e) cannot: that tier fabricates every response.
 */

import { test, expect } from '@playwright/test';
import { installVirtualAuthenticator } from './support/virtualAuthenticator.ts';
import { loginOperator, registerOperator, uniqueOperator } from './support/operator.ts';

test.describe('Passkey registration and login', () => {
  test('registers a passkey, then signs out and back in via the same credential', async ({ page }) => {
    await installVirtualAuthenticator(page);
    const op = uniqueOperator('auth');

    await registerOperator(page, op);

    // Sign out — back to the login chooser, shell gone.
    await page.getByRole('button', { name: 'Sign out' }).click();
    await expect(page.getByRole('button', { name: 'Sign in with passkey' })).toBeVisible();
    await expect(page.locator('aside')).toHaveCount(0);

    // Sign back in with the SAME resident credential the registration
    // ceremony created on the virtual authenticator.
    await loginOperator(page, op);

    // The header's display name comes from a follow-up GET /api/v1/auth/me
    // triggered by an $effect once authStore flips — give it room to land.
    await expect(page.getByText(op.displayName)).toBeVisible({ timeout: 10_000 });
  });

  test('rejects a login for an unregistered email without revealing account existence', async ({ page }) => {
    await installVirtualAuthenticator(page);

    await page.goto('/ui/#/login');
    await page.getByRole('button', { name: 'Sign in with passkey' }).click();
    await page.getByLabel('Email').fill(`nobody-${Date.now()}@example.com`);
    await page.getByRole('button', { name: 'Authenticate with passkey' }).click();

    await expect(page.getByText('Sign-in failed. Check your details and try again.')).toBeVisible();
    // Still on the signed-out screen — no dashboard, no shell.
    await expect(page.locator('aside')).toHaveCount(0);
  });
});
