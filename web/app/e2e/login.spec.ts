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
 * Signed-out screen: the login chooser renders and its two credential
 * methods (passkey / certificate) are gated on GET /api/v1/capabilities
 * (webauthn_enabled -> passkey, piv_login_enabled -> certificate). This is
 * BrowserCredentialProvider.methods() (always offers both) intersected with
 * the deployment's capability flags — see sdk/ts/svelte-auth LoginPanel.
 */

import { test, expect } from '@playwright/test';
import { mockLoginCapabilities } from './support/mockAuth.ts';

test.describe('Login screen', () => {
  test('renders the passkey chooser with both methods when both capabilities are on', async ({ page }) => {
    await mockLoginCapabilities(page, { webauthn_enabled: true, piv_login_enabled: true });

    await page.goto('/#/login');

    await expect(page.getByText('xKMS Console')).toBeVisible();
    await expect(page.getByRole('button', { name: 'Sign in with passkey' })).toBeVisible();
    await expect(page.getByRole('button', { name: 'Sign in with certificate' })).toBeVisible();
  });

  test('hides the certificate method when the server has piv_login_enabled=false', async ({ page }) => {
    await mockLoginCapabilities(page, { webauthn_enabled: true, piv_login_enabled: false });

    await page.goto('/#/login');

    await expect(page.getByRole('button', { name: 'Sign in with passkey' })).toBeVisible();
    await expect(page.getByRole('button', { name: 'Sign in with certificate' })).toHaveCount(0);
  });

  test('hides the passkey method when the server has webauthn_enabled=false', async ({ page }) => {
    await mockLoginCapabilities(page, { webauthn_enabled: false, piv_login_enabled: true });

    await page.goto('/#/login');

    await expect(page.getByRole('button', { name: 'Sign in with passkey' })).toHaveCount(0);
    await expect(page.getByRole('button', { name: 'Sign in with certificate' })).toBeVisible();
  });

  test('navigates to the enrollment screen from the login chooser', async ({ page }) => {
    await mockLoginCapabilities(page);

    await page.goto('/#/login');
    await page.getByRole('button', { name: 'No passkey yet? Enroll one' }).click();

    await expect(page.getByRole('button', { name: 'Create account with passkey' })).toBeVisible();
    await expect(page).toHaveURL(/#\/register$/);
  });
});
