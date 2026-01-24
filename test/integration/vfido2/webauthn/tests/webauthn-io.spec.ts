// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-keychain.
//
// go-keychain is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

import { test, expect, type CDPSession } from '@playwright/test';

/**
 * Creates a CDP virtual authenticator that mimics vfido2 behavior:
 * - CTAP2 protocol
 * - USB transport (UHID)
 * - Resident key support
 * - User verification support
 * - ES256 (P-256) signatures in ASN.1/DER format
 */
async function addVirtualAuthenticator(cdp: CDPSession): Promise<string> {
  await cdp.send('WebAuthn.enable', { enableUI: false });

  const result = await cdp.send('WebAuthn.addVirtualAuthenticator', {
    options: {
      protocol: 'ctap2',
      transport: 'usb',
      hasResidentKey: true,
      hasUserVerification: true,
      isUserVerified: true,
      automaticPresenceSimulation: true,
    },
  });

  return result.authenticatorId;
}

async function removeVirtualAuthenticator(cdp: CDPSession, authId: string): Promise<void> {
  await cdp.send('WebAuthn.removeVirtualAuthenticator', {
    authenticatorId: authId,
  });
  await cdp.send('WebAuthn.disable');
}

/**
 * Generates a unique username for each test run to avoid conflicts
 * with previously registered credentials on webauthn.io.
 */
function generateUsername(): string {
  const ts = Date.now();
  const rand = Math.random().toString(36).substring(2, 8);
  return `vfido2-test-${ts}-${rand}`;
}

test.describe('webauthn.io integration', () => {
  let cdp: CDPSession;
  let authId: string;

  test.beforeEach(async ({ page }) => {
    cdp = await page.context().newCDPSession(page);
    authId = await addVirtualAuthenticator(cdp);
  });

  test.afterEach(async () => {
    if (cdp && authId) {
      await removeVirtualAuthenticator(cdp, authId);
    }
  });

  test('register and authenticate with webauthn.io', async ({ page }) => {
    const username = generateUsername();

    // Navigate to webauthn.io
    await page.goto('https://webauthn.io/', { waitUntil: 'networkidle' });
    await expect(page).toHaveTitle(/webauthn/i);

    // Step 1: Registration
    const usernameInput = page.locator('#input-email');
    await expect(usernameInput).toBeVisible({ timeout: 10_000 });
    await usernameInput.fill(username);

    const registerButton = page.getByRole('button', { name: 'Register' });
    await expect(registerButton).toBeVisible();
    await registerButton.click();

    // Wait for registration success (Alpine.js alert with class "alert-success")
    const regSuccess = page.locator('.alert-success');
    await expect(regSuccess).toBeVisible({ timeout: 15_000 });

    console.log(`Registration successful for user: ${username}`);

    // Step 2: Authentication
    const authButton = page.getByRole('button', { name: 'Authenticate' });
    await expect(authButton).toBeVisible();
    await authButton.click();

    // Successful authentication redirects to /profile showing "You're logged in!"
    await page.waitForURL('**/profile', { timeout: 15_000 });
    await expect(page.getByText("You're logged in")).toBeVisible({ timeout: 5_000 });

    console.log(`Authentication successful for user: ${username}`);
  });

  test('registration creates discoverable credential', async ({ page }) => {
    const username = generateUsername();

    await page.goto('https://webauthn.io/', { waitUntil: 'networkidle' });

    const usernameInput = page.locator('#input-email');
    await expect(usernameInput).toBeVisible({ timeout: 10_000 });
    await usernameInput.fill(username);

    const registerButton = page.getByRole('button', { name: 'Register' });
    await registerButton.click();

    const regSuccess = page.locator('.alert-success');
    await expect(regSuccess).toBeVisible({ timeout: 15_000 });

    // Verify credential was stored in the virtual authenticator
    const creds = await cdp.send('WebAuthn.getCredentials', {
      authenticatorId: authId,
    });

    expect(creds.credentials.length).toBeGreaterThanOrEqual(1);

    const cred = creds.credentials[0];
    expect(cred.rpId).toBe('webauthn.io');

    console.log(`Discoverable credential created: rpId=${cred.rpId}, signCount=${cred.signCount}`);
  });

  test('authentication increments sign counter', async ({ page }) => {
    const username = generateUsername();

    await page.goto('https://webauthn.io/', { waitUntil: 'networkidle' });

    // Register first
    const usernameInput = page.locator('#input-email');
    await expect(usernameInput).toBeVisible({ timeout: 10_000 });
    await usernameInput.fill(username);

    const registerButton = page.getByRole('button', { name: 'Register' });
    await registerButton.click();

    const regSuccess = page.locator('.alert-success');
    await expect(regSuccess).toBeVisible({ timeout: 15_000 });

    // Record sign count after registration
    let creds = await cdp.send('WebAuthn.getCredentials', {
      authenticatorId: authId,
    });
    const initialSignCount = creds.credentials[0].signCount;

    // Authenticate
    const authButton = page.getByRole('button', { name: 'Authenticate' });
    await expect(authButton).toBeVisible();
    await authButton.click();

    // Successful authentication redirects to /profile
    await page.waitForURL('**/profile', { timeout: 15_000 });
    await expect(page.getByText("You're logged in")).toBeVisible({ timeout: 5_000 });

    // Check sign count incremented after authentication
    creds = await cdp.send('WebAuthn.getCredentials', {
      authenticatorId: authId,
    });
    expect(creds.credentials[0].signCount).toBeGreaterThan(initialSignCount);

    console.log(`Sign counter incremented: ${initialSignCount} -> ${creds.credentials[0].signCount}`);
  });

  test('rejects authentication with wrong credential', async ({ page }) => {
    const username = generateUsername();

    await page.goto('https://webauthn.io/', { waitUntil: 'networkidle' });

    // Register with one user
    const usernameInput = page.locator('#input-email');
    await expect(usernameInput).toBeVisible({ timeout: 10_000 });
    await usernameInput.fill(username);

    const registerButton = page.getByRole('button', { name: 'Register' });
    await registerButton.click();

    const regSuccess = page.locator('.alert-success');
    await expect(regSuccess).toBeVisible({ timeout: 15_000 });

    // Clear the existing credential from the virtual authenticator
    const creds = await cdp.send('WebAuthn.getCredentials', {
      authenticatorId: authId,
    });
    for (const cred of creds.credentials) {
      await cdp.send('WebAuthn.removeCredential', {
        authenticatorId: authId,
        credentialId: cred.credentialId,
      });
    }

    // Try to authenticate - should fail because credential was removed
    const authButton = page.getByRole('button', { name: 'Authenticate' });
    await expect(authButton).toBeVisible();
    await authButton.click();

    // Should show an error (Alpine.js alert with class "alert-danger")
    const errorIndicator = page.locator('.alert-danger');
    await expect(errorIndicator).toBeVisible({ timeout: 15_000 });

    console.log('Authentication correctly rejected with missing credential');
  });
});
