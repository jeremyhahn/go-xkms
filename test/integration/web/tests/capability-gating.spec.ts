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
 * Ruling 972 (1): no console control may lead to a 501 or "not configured"
 * state. Against a real xkmsd booted with webauthn.enabled: false
 * (config-webauthn-off.yaml, the second webServer in playwright.config.ts),
 * the passkey controls show their disabled state naming the setting, and no
 * request the console makes answers 501. No REST call is intercepted.
 */

import { test, expect, type Response } from '@playwright/test';

test.use({ baseURL: 'https://localhost:18464' });

test.describe('Console with passkeys off', () => {
  test('Create account shows the disabled state and nothing answers 501', async ({ page, request }) => {
    const caps = await request.get('/api/v1/capabilities');
    expect(caps.status()).toBe(200);
    expect((await caps.json()).webauthn_enabled).toBe(false);

    const notImplemented: string[] = [];
    page.on('response', (res: Response) => {
      if (res.status() === 501) notImplemented.push(`${res.request().method()} ${res.url()}`);
    });

    await page.goto('/ui/#/login');
    const signInOff = page.getByTestId('svelte-auth-login-disabled-passkey');
    await expect(signInOff).toBeVisible();
    await expect(signInOff).toContainText('webauthn.enabled: true');

    await page.getByRole('button', { name: 'No passkey yet? Enroll one' }).click();
    const signUpOff = page.getByTestId('svelte-auth-register-disabled');
    await expect(signUpOff).toBeVisible();
    await expect(signUpOff).toContainText('webauthn.enabled: true');
    await expect(page.getByRole('button', { name: 'Create account with passkey' })).toHaveCount(0);

    await page.waitForLoadState('networkidle');
    expect(notImplemented).toEqual([]);
  });
});
