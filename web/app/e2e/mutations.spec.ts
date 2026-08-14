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
 * One representative mutation per major screen: fill the dialog, submit, and
 * assert the EXACT request body the SPA sent (not just "a POST happened") —
 * this is the shape the server's DTO decoder actually depends on — plus the
 * success toast that confirms the view's own completion handling ran.
 */

import { test, expect } from '@playwright/test';
import { installDefaultApiMocks, mockOnce } from './support/mockApi.ts';
import { defaultAuthMe, seedAuthenticated } from './support/mockAuth.ts';

test.describe('Mutations — request shape and success feedback', () => {
  test('Keys: generate sends the ECDSA request shape and toasts success', async ({ page }) => {
    await installDefaultApiMocks(page);
    await seedAuthenticated(page, defaultAuthMe());

    let captured: unknown;
    await page.route('**/api/v1/keys', async (route) => {
      if (route.request().method() !== 'POST') {
        await route.fallback();
        return;
      }
      captured = route.request().postDataJSON();
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({ key_id: 'e2e-test-key', key_type: 'ecdsa', backend: 'software' }),
      });
    });

    await page.goto('/#/keys');
    await page.getByRole('button', { name: '+ Generate' }).click();
    await page.getByLabel('Key ID').fill('e2e-test-key');
    // key_type defaults to "ecdsa" with curve "P-256" — leave the selects as-is
    // to pin the default request shape.
    await page.getByRole('button', { name: 'Generate', exact: true }).click();

    await expect(page.getByText('Key "e2e-test-key" generated.')).toBeVisible();
    expect(captured).toEqual({
      key_id: 'e2e-test-key',
      key_type: 'ecdsa',
      exportable: false,
      curve: 'P-256',
    });
  });

  test('Users: create sends the username/role/tenant shape and toasts success', async ({ page }) => {
    await installDefaultApiMocks(page);
    await seedAuthenticated(page, defaultAuthMe());

    let captured: unknown;
    await page.route('**/api/v1/users/', async (route) => {
      if (route.request().method() !== 'POST') {
        await route.fallback();
        return;
      }
      captured = route.request().postDataJSON();
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({ username: 'e2e-user', enabled: true }),
      });
    });

    await page.goto('/#/users');
    await page.getByRole('button', { name: '+ Create' }).click();
    await page.getByPlaceholder('Username').fill('e2e-user');
    await page.getByPlaceholder('Display name').fill('E2E User');
    await page.getByPlaceholder('Role').fill('operator');
    await page.getByPlaceholder('Tenant ID').fill('system');
    await page.getByRole('button', { name: 'Create', exact: true }).click();

    await expect(page.getByText('User "e2e-user" created.')).toBeVisible();
    expect(captured).toEqual({
      username: 'e2e-user',
      display_name: 'E2E User',
      role: 'operator',
      tenant_id: 'system',
    });
  });

  test('Barrier: unseal sends the passphrase as `secret` and toasts success', async ({ page }) => {
    await installDefaultApiMocks(page);
    await seedAuthenticated(page, defaultAuthMe());
    // Sealed, so the unseal form is offered (BarrierView gates it on status.sealed).
    await mockOnce(page, 'GET', '/api/v1/barrier/status', { sealed: true, strategy: 'passphrase', hardware_backed: false });

    let captured: unknown;
    await page.route('**/api/v1/barrier/unseal', async (route) => {
      captured = route.request().postDataJSON();
      await route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify({ sealed: false }) });
    });

    await page.goto('/#/barrier');
    await expect(page.getByText('sealed', { exact: true })).toBeVisible();
    await page.getByLabel('Passphrase').fill('correct-horse-battery-staple');
    await page.getByRole('button', { name: 'Unseal' }).click();

    await expect(page.getByText('Barrier unsealed.')).toBeVisible();
    expect(captured).toEqual({ secret: 'correct-horse-battery-staple' });
  });
});
