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
 * The personal password vault in the console, against the mock API: the
 * exact request each vault verb sends, on the /api/v1/password-vault paths.
 */

import { test, expect, type Page } from '@playwright/test';
import { installDefaultApiMocks, mockOnce } from './support/mockApi.ts';
import { defaultAuthMe, seedAuthenticated } from './support/mockAuth.ts';

const locked = { available: true, is_locked: true, barrier_sealed: false, password_count: 0, message: '' };
const unlocked = { available: true, is_locked: false, barrier_sealed: false, password_count: 0, message: '' };

/** capture answers METHOD path with body and records the request bodies. */
async function capture(page: Page, method: string, path: string, body: unknown): Promise<unknown[]> {
  const seen: unknown[] = [];
  await page.route(`**${path}`, async (route) => {
    if (route.request().method() !== method) {
      await route.fallback();
      return;
    }
    seen.push(route.request().postDataJSON());
    await route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(body) });
  });
  return seen;
}

test.describe('Password vault', () => {
  test('recovers a locked vault with the recovery code and shows the new code once', async ({ page }) => {
    await installDefaultApiMocks(page);
    await seedAuthenticated(page, defaultAuthMe());
    let sessionCalls = 0;
    await page.route('**/api/v1/password-vault/session', async (route) => {
      sessionCalls++;
      await route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(sessionCalls === 1 ? locked : unlocked) });
    });
    await mockOnce(page, 'GET', '/api/v1/password-vault', { initialized: true, unlocked: false, factors: [] });
    const recovered = await capture(page, 'POST', '/api/v1/password-vault/recover', {
      factor: { id: 'f9', factor: 'passphrase', created_at: '2026-09-30T00:00:00Z' },
      recovery_code: 'WXYZ-2345-ABCD-EFGH-IJKL-MNOP-QRST-UVWX',
    });

    await page.goto('/#/passwords');
    await page.getByRole('button', { name: 'Use recovery code' }).click();
    await page.getByLabel('Recovery code').fill('ABCD-EFGH-IJKL-MNOP-QRST-UVWX-YZ23-4567');
    await page.getByLabel('New passphrase', { exact: true }).fill('fresh passphrase');
    await page.getByLabel('Confirm new passphrase').fill('fresh passphrase');
    await page.getByRole('button', { name: 'Recover vault' }).click();

    await expect(page.getByText('WXYZ-2345-ABCD-EFGH-IJKL-MNOP-QRST-UVWX')).toBeVisible();
    expect(recovered).toEqual([{
      recovery_code: 'ABCD-EFGH-IJKL-MNOP-QRST-UVWX-YZ23-4567',
      factor: 'passphrase',
      passphrase: 'fresh passphrase',
      label: 'web console',
    }]);
  });

  test('adds and removes a passphrase factor while the session is open', async ({ page }) => {
    await installDefaultApiMocks(page);
    await seedAuthenticated(page, defaultAuthMe());
    await mockOnce(page, 'GET', '/api/v1/password-vault', {
      initialized: true,
      unlocked: true,
      factors: [
        { id: 'f1', factor: 'passphrase', label: 'web console', created_at: '2026-09-30T00:00:00Z' },
        { id: 'f2', factor: 'passphrase', label: 'laptop', created_at: '2026-09-30T00:00:00Z' },
        { id: 'rc', factor: 'recovery', created_at: '2026-09-30T00:00:00Z' },
      ],
    });
    const enrolled = await capture(page, 'POST', '/api/v1/password-vault/factors', {
      factor: { id: 'f3', factor: 'passphrase', created_at: '2026-09-30T00:00:00Z' },
    });
    let removed = '';
    await page.route('**/api/v1/password-vault/factors/*', async (route) => {
      if (route.request().method() !== 'DELETE') {
        await route.fallback();
        return;
      }
      removed = new URL(route.request().url()).pathname;
      await route.fulfill({ status: 204 });
    });

    await page.goto('/#/passwords');
    await page.getByRole('button', { name: 'Vault factors' }).click();
    const dialog = page.getByRole('dialog');
    await expect(dialog.getByText('laptop')).toBeVisible();
    await expect(dialog.getByRole('button', { name: /Remove/ })).toHaveCount(2);

    await dialog.getByLabel('New passphrase', { exact: true }).fill('second passphrase');
    await dialog.getByLabel('Confirm new passphrase').fill('second passphrase');
    await dialog.getByLabel('Label').fill('phone');
    await dialog.getByRole('button', { name: 'Add passphrase' }).click();
    await expect(page.getByText('Passphrase added.')).toBeVisible();
    expect(enrolled).toEqual([{ factor: 'passphrase', passphrase: 'second passphrase', label: 'phone' }]);

    await dialog.getByRole('button', { name: 'Remove laptop' }).click();
    await expect(page.getByText('Factor removed.')).toBeVisible();
    expect(removed).toBe('/api/v1/password-vault/factors/f2');
  });
});
