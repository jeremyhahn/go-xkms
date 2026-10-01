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
 * Unlocking with a PIV / certificate / TPM key factor through the xKey
 * browser extension. The extension's content script is emulated in the page
 * with the same window.postMessage protocol (xkey/extension/src/content.ts);
 * the extension-to-xKey half is covered by the Go bridge test that drives
 * the real native host. What runs here is the console's real code path.
 */

import { test, expect, type Page } from '@playwright/test';
import { installDefaultApiMocks } from './support/mockApi.ts';
import { defaultAuthMe, seedAuthenticated } from './support/mockAuth.ts';

const FP = 'a'.repeat(64);
const locked = { available: true, is_locked: true, barrier_sealed: false, password_count: 0, message: '' };
const unlocked = { available: true, is_locked: false, barrier_sealed: false, password_count: 0, message: '' };

/** emulateExtension installs the content script's message protocol. */
async function emulateExtension(page: Page, answer: { unlocked: boolean; error?: string }): Promise<void> {
  await page.addInitScript((reply) => {
    (window as unknown as { __xkeyRequests: unknown[] }).__xkeyRequests = [];
    window.addEventListener('message', (event) => {
      const d = event.data as { source?: string; type?: string; requestId?: string; fingerprints?: string[] };
      if (event.source !== window || d?.source !== 'xkms-console') return;
      (window as unknown as { __xkeyRequests: unknown[] }).__xkeyRequests.push(d);
      if (d.type === 'xkey-ping') {
        window.postMessage({ source: 'xkey-extension', type: 'xkey-pong', requestId: d.requestId }, location.origin);
      } else if (d.type === 'xkey-vault-unlock') {
        window.postMessage({ source: 'xkey-extension', type: 'xkey-vault-unlock-result', requestId: d.requestId, ...reply }, location.origin);
      }
    });
  }, answer);
}

async function mockLockedKeyVault(page: Page): Promise<{ unlocked: boolean }> {
  const state = { unlocked: false };
  await page.route('**/api/v1/password-vault/session', (r) =>
    r.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(state.unlocked ? unlocked : locked) }));
  await page.route('**/api/v1/password-vault', (r) =>
    r.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({ initialized: true, unlocked: state.unlocked, factors: [{ id: 'k1', factor: 'piv', label: 'desk card', created_at: '2026-10-01T00:00:00Z', key_fingerprint: FP }] }),
    }));
  return state;
}

test.describe('Password vault key factors via the xKey extension', () => {
  test('the page asks the extension with the factor fingerprints and never posts a credential', async ({ page }) => {
    await installDefaultApiMocks(page);
    await seedAuthenticated(page, defaultAuthMe());
    const state = await mockLockedKeyVault(page);
    let unlockPosted = false;
    await page.route('**/api/v1/password-vault/unlock', (r) => {
      unlockPosted = true;
      return r.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(unlocked) });
    });
    await emulateExtension(page, { unlocked: true });
    await page.goto('/#/passwords');
    state.unlocked = true;
    await page.getByRole('button', { name: 'Unlock with xKey' }).click();

    await expect(page.getByText('Vault unlocked by xKey.')).toBeVisible();
    const requests = await page.evaluate(() => (window as unknown as { __xkeyRequests: { type: string; fingerprints?: string[] }[] }).__xkeyRequests);
    expect(requests.map((r) => r.type)).toEqual(['xkey-ping', 'xkey-vault-unlock']);
    expect(requests[1]!.fingerprints).toEqual([FP]);
    expect(unlockPosted).toBe(false);
  });

  test('without the extension the page says the factor needs it', async ({ page }) => {
    await installDefaultApiMocks(page);
    await seedAuthenticated(page, defaultAuthMe());
    await mockLockedKeyVault(page);

    await page.goto('/#/passwords');
    await page.getByRole('button', { name: 'Unlock with xKey' }).click();
    await expect(page.getByText(/needs the xKey browser extension/)).toBeVisible();
  });

  test("xKey's refusal is shown", async ({ page }) => {
    await installDefaultApiMocks(page);
    await seedAuthenticated(page, defaultAuthMe());
    await mockLockedKeyVault(page);
    await emulateExtension(page, { unlocked: false, error: 'this page is not the console of the server xKey is connected to' });

    await page.goto('/#/passwords');
    await page.getByRole('button', { name: 'Unlock with xKey' }).click();
    await expect(page.getByText(/not the console of the server/)).toBeVisible();
  });
});
