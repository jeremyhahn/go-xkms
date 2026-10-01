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
 * Vault passkeys through Chrome's real WebAuthn stack: a CDP virtual
 * authenticator (CTAP 2.1, user verification, and the PRF / hmac-secret
 * extension) stands in for the security key, so the console's
 * navigator.credentials calls, the browser's PRF salt transform and the
 * authenticator's hmac-secret all run for real. Only the REST API is mocked.
 */

import { test, expect, type CDPSession, type Page } from '@playwright/test';
import { installDefaultApiMocks } from './support/mockApi.ts';
import { defaultAuthMe, seedAuthenticated } from './support/mockAuth.ts';

// The console is served from localhost, so that is the relying party the
// server advertises and a browser may use.
const RP = 'localhost';

const locked = { available: true, is_locked: true, barrier_sealed: false, password_count: 0, message: '' };
const unlocked = { available: true, is_locked: false, barrier_sealed: false, password_count: 0, message: '' };

async function addAuthenticator(page: Page, hasPrf: boolean): Promise<CDPSession> {
  const cdp = await page.context().newCDPSession(page);
  await cdp.send('WebAuthn.enable');
  await cdp.send('WebAuthn.addVirtualAuthenticator', {
    options: {
      protocol: 'ctap2',
      ctap2Version: 'ctap2_1',
      transport: 'usb',
      hasResidentKey: true,
      hasUserVerification: true,
      isUserVerified: true,
      automaticPresenceSimulation: true,
      hasPrf,
    },
  });
  return cdp;
}

interface VaultMock {
  vault: { initialized: boolean; unlocked: boolean; factors: unknown[]; passkey_rp_id?: string };
  locked: boolean;
  enrolled: Record<string, string>[];
  unlocks: Record<string, string>[];
}

/** mockVault answers the vault and session routes from a mutable state. */
async function mockVault(page: Page, state: VaultMock): Promise<void> {
  const json = (body: unknown) => ({ status: 200, contentType: 'application/json', body: JSON.stringify(body) });
  await page.route('**/api/v1/password-vault/session', (r) => r.fulfill(json(state.locked ? locked : unlocked)));
  await page.route('**/api/v1/password-vault', (r) => r.fulfill(json(state.vault)));
  await page.route('**/api/v1/password-vault/factors', async (r) => {
    const body = r.request().postDataJSON() as Record<string, string>;
    state.enrolled.push(body);
    state.locked = false;
    await r.fulfill(json({ factor: { id: 'f1', factor: 'passkey', created_at: '2026-10-01T00:00:00Z' }, recovery_code: 'AAAA-BBBB' }));
  });
  await page.route('**/api/v1/password-vault/unlock', async (r) => {
    state.unlocks.push(r.request().postDataJSON() as Record<string, string>);
    state.locked = false;
    await r.fulfill(json(unlocked));
  });
}

function bytes(b64: string): number {
  return Buffer.from(b64, 'base64').length;
}

test.describe('Password vault passkeys (Chrome virtual authenticator)', () => {
  test('a passkey created in the browser unlocks the vault: same credential, same PRF secret', async ({ page }) => {
    await installDefaultApiMocks(page);
    await seedAuthenticated(page, defaultAuthMe());
    const state: VaultMock = { vault: { initialized: false, unlocked: false, factors: [], passkey_rp_id: RP }, locked: true, enrolled: [], unlocks: [] };
    await mockVault(page, state);
    await addAuthenticator(page, true);

    await page.goto('/#/passwords');
    await page.getByRole('button', { name: 'Create with a passkey' }).click();
    await expect(page.getByText('AAAA-BBBB')).toBeVisible();

    const enrolled = state.enrolled[0]!;
    expect(enrolled.factor).toBe('passkey');
    expect(enrolled.rp_id).toBe(RP);
    expect(bytes(enrolled.prf_salt!)).toBe(32);
    expect(bytes(enrolled.secret!)).toBe(32);

    // The server now lists the factor; lock and unlock with the same key.
    state.locked = true;
    state.vault = {
      initialized: true,
      unlocked: false,
      passkey_rp_id: RP,
      factors: [{ id: 'f1', factor: 'passkey', created_at: '2026-10-01T00:00:00Z', credential_id: enrolled.credential_id, prf_salt: enrolled.prf_salt, rp_id: RP }],
    };
    await page.getByRole('button', { name: 'I have stored it' }).click();
    await page.reload();
    await page.getByRole('button', { name: 'Unlock with passkey' }).click();
    await expect(page.getByText('Vault unlocked.')).toBeVisible();

    const unlock = state.unlocks[0]!;
    expect(unlock.credential_id).toBe(enrolled.credential_id);
    expect(unlock.secret).toBe(enrolled.secret);
  });

  test('an authenticator without PRF is refused with the typed error, and nothing is enrolled', async ({ page }) => {
    await installDefaultApiMocks(page);
    await seedAuthenticated(page, defaultAuthMe());
    const state: VaultMock = { vault: { initialized: false, unlocked: false, factors: [], passkey_rp_id: RP }, locked: true, enrolled: [], unlocks: [] };
    await mockVault(page, state);
    await addAuthenticator(page, false);

    await page.goto('/#/passwords');
    await page.getByRole('button', { name: 'Create with a passkey' }).click();
    await expect(page.getByText(/does not support the WebAuthn PRF extension/)).toBeVisible();
    expect(state.enrolled).toHaveLength(0);
  });
});
