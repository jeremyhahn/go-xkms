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
 * Error rendering. Every view's load() catches the SDK error and renders it
 * in a plain `.alert-error` — there is no separate 403-specific UI anywhere
 * in src/views (grepped: no view branches on e.status), so "the 403/denied
 * path" and "a 500" exercise the SAME rendering mechanism with different
 * server answers. Both cases must still show the screen's own PageHeader —
 * an error must never blank the shell down to nothing.
 */

import { test, expect } from '@playwright/test';
import { installDefaultApiMocks, mockError } from './support/mockApi.ts';
import { defaultAuthMe, seedAuthenticated } from './support/mockAuth.ts';

test.describe('Error rendering', () => {
  test('a 500 from the server renders the alert with the server message, header intact', async ({ page }) => {
    await installDefaultApiMocks(page);
    await seedAuthenticated(page, defaultAuthMe());
    await mockError(page, 'GET', '/api/v1/keys', 500, 'backend unavailable');

    await page.goto('/#/keys');

    await expect(page.getByRole('heading', { name: 'Keys' })).toBeVisible();
    await expect(page.locator('.alert-error')).toContainText('backend unavailable');
    // The loading spinner must not still be showing once the error resolved.
    await expect(page.locator('.loading-spinner')).toHaveCount(0);
  });

  test('a 403 (denied) response renders the same alert path, header intact', async ({ page }) => {
    await installDefaultApiMocks(page);
    // Authenticated, but this identity is denied the certs:list permission —
    // the nav item would be hidden client-side, but a direct route visit
    // still reaches the view and must show what the server actually answers.
    await seedAuthenticated(page, defaultAuthMe());
    await mockError(page, 'GET', '/api/v1/certs', 403, 'certs:list denied for this principal');

    await page.goto('/#/certs');

    await expect(page.getByRole('heading', { name: 'Certificates' })).toBeVisible();
    await expect(page.locator('.alert-error')).toContainText('certs:list denied for this principal');
  });

  test('a rejected mutation surfaces the server message without closing the dialog', async ({ page }) => {
    await installDefaultApiMocks(page);
    await seedAuthenticated(page, defaultAuthMe());
    await mockError(page, 'POST', '/api/v1/keys', 409, 'key_id "dup-key" already exists');

    await page.goto('/#/keys');
    await page.getByRole('button', { name: '+ Generate' }).click();
    await page.getByLabel('Key ID').fill('dup-key');
    await page.getByRole('button', { name: 'Generate', exact: true }).click();

    // The dialog stays open with the failure shown, not silently dismissed.
    await expect(page.getByText('key_id "dup-key" already exists')).toBeVisible();
    await expect(page.getByRole('button', { name: 'Generate', exact: true })).toBeVisible();
  });
});
