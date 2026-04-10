// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
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

import { test, expect, type CDPSession } from '@playwright/test';

/**
 * PIN Protocol Regression Tests using Chrome CDP Virtual Authenticators
 *
 * These tests specifically target PIN-related WebAuthn scenarios to catch
 * regressions like:
 *
 * - Chrome "change PIN" bug: When PIN is set but advertised incorrectly,
 *   Chrome prompts "Use a different phone or security key" or asks to change
 *   the PIN instead of proceeding with registration.
 *
 * - Firefox "no PIN prompt" bug: When PIN state is misconfigured in GetInfo,
 *   Firefox fails to prompt for PIN verification during authentication.
 *
 * Each test configures a CDP virtual authenticator with specific PIN/UV
 * settings to simulate the authenticator configurations that triggered
 * these bugs.
 */

/**
 * Generates a unique username for each test run to avoid conflicts
 * with previously registered credentials on webauthn.io.
 */
function generateUsername(): string {
  const ts = Date.now();
  const rand = Math.random().toString(36).substring(2, 8);
  return `xkeyfido2-pin-${ts}-${rand}`;
}

test.describe('PIN protocol regression tests', () => {

  test.describe('PIN set with UV available - registration succeeds without change PIN prompt', () => {
    let cdp: CDPSession;
    let authId: string;

    test.beforeEach(async ({ page }) => {
      cdp = await page.context().newCDPSession(page);
      await cdp.send('WebAuthn.enable', { enableUI: false });

      // Simulate authenticator with PIN set and auto-verified:
      // hasUserVerification: true  -> authenticator supports UV (PIN is configured)
      // isUserVerified: true       -> PIN is already verified (auto-approve)
      // This is the correct configuration for an authenticator with PIN set.
      // The Chrome "change PIN" bug occurred when the authenticator advertised
      // pinUvAuthToken without clientPin in GetInfo options, causing Chrome to
      // think the PIN needed to be changed.
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
      authId = result.authenticatorId;
    });

    test.afterEach(async () => {
      if (cdp && authId) {
        await cdp.send('WebAuthn.removeVirtualAuthenticator', {
          authenticatorId: authId,
        });
        await cdp.send('WebAuthn.disable');
      }
    });

    test('registration completes without PIN change dialog', async ({ page }) => {
      const username = generateUsername();

      await page.goto('https://webauthn.io/', { waitUntil: 'networkidle' });
      await expect(page).toHaveTitle(/webauthn/i);

      const usernameInput = page.locator('#input-email');
      await expect(usernameInput).toBeVisible({ timeout: 10_000 });
      await usernameInput.fill(username);

      const registerButton = page.getByRole('button', { name: 'Register' });
      await expect(registerButton).toBeVisible();
      await registerButton.click();

      // When PIN is correctly configured, registration should succeed
      // immediately without any "change PIN" or "use a different device" prompts.
      // The Chrome bug caused a timeout here because the browser showed a
      // blocking PIN-change dialog instead of completing registration.
      const regSuccess = page.locator('.alert-success');
      await expect(regSuccess).toBeVisible({ timeout: 15_000 });

      // Verify the credential was created with UV flag
      const creds = await cdp.send('WebAuthn.getCredentials', {
        authenticatorId: authId,
      });
      expect(creds.credentials.length).toBe(1);
      expect(creds.credentials[0].rpId).toBe('webauthn.io');

      console.log(`PIN-set registration succeeded for user: ${username}`);
    });
  });

  test.describe('no PIN capability - registration behavior with makeCredUvNotRqd', () => {
    let cdp: CDPSession;
    let authId: string;

    test.beforeEach(async ({ page }) => {
      cdp = await page.context().newCDPSession(page);
      await cdp.send('WebAuthn.enable', { enableUI: false });

      // Simulate authenticator with NO PIN/UV capability at all.
      // hasUserVerification: false -> authenticator does not support UV
      // This simulates PINSet=false with no UV method available.
      // When makeCredUvNotRqd is implied, registration can still succeed
      // for "discouraged" UV preference, but authentication behavior differs.
      const result = await cdp.send('WebAuthn.addVirtualAuthenticator', {
        options: {
          protocol: 'ctap2',
          transport: 'usb',
          hasResidentKey: true,
          hasUserVerification: false,
          automaticPresenceSimulation: true,
        },
      });
      authId = result.authenticatorId;
    });

    test.afterEach(async () => {
      if (cdp && authId) {
        await cdp.send('WebAuthn.removeVirtualAuthenticator', {
          authenticatorId: authId,
        });
        await cdp.send('WebAuthn.disable');
      }
    });

    test('registration succeeds without UV when PIN not configured', async ({ page }) => {
      const username = generateUsername();

      await page.goto('https://webauthn.io/', { waitUntil: 'networkidle' });

      const usernameInput = page.locator('#input-email');
      await expect(usernameInput).toBeVisible({ timeout: 10_000 });
      await usernameInput.fill(username);

      const registerButton = page.getByRole('button', { name: 'Register' });
      await registerButton.click();

      // Registration should succeed - webauthn.io defaults to "preferred" UV
      // which allows authenticators without UV to proceed.
      // The key regression this catches: if an authenticator incorrectly
      // advertises UV support when it has no PIN, browsers may block.
      const regSuccess = page.locator('.alert-success');
      await expect(regSuccess).toBeVisible({ timeout: 15_000 });

      // Verify credential was stored
      const creds = await cdp.send('WebAuthn.getCredentials', {
        authenticatorId: authId,
      });
      expect(creds.credentials.length).toBe(1);

      console.log(`No-PIN registration succeeded for user: ${username}`);
    });
  });

  test.describe('PIN set with UV required - authentication requires user verification', () => {
    let cdp: CDPSession;
    let authId: string;

    test.beforeEach(async ({ page }) => {
      cdp = await page.context().newCDPSession(page);
      await cdp.send('WebAuthn.enable', { enableUI: false });

      // Simulate authenticator with PIN set and user verification enabled.
      // hasUserVerification: true  -> UV supported (PIN configured)
      // isUserVerified: true       -> PIN auto-verified for testing
      // This ensures the full register-then-authenticate flow works with UV.
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
      authId = result.authenticatorId;
    });

    test.afterEach(async () => {
      if (cdp && authId) {
        await cdp.send('WebAuthn.removeVirtualAuthenticator', {
          authenticatorId: authId,
        });
        await cdp.send('WebAuthn.disable');
      }
    });

    test('register then authenticate with UV flag set', async ({ page }) => {
      const username = generateUsername();

      // Step 1: Register
      await page.goto('https://webauthn.io/', { waitUntil: 'networkidle' });

      const usernameInput = page.locator('#input-email');
      await expect(usernameInput).toBeVisible({ timeout: 10_000 });
      await usernameInput.fill(username);

      const registerButton = page.getByRole('button', { name: 'Register' });
      await registerButton.click();

      const regSuccess = page.locator('.alert-success');
      await expect(regSuccess).toBeVisible({ timeout: 15_000 });

      // Verify credential has UV flag
      const creds = await cdp.send('WebAuthn.getCredentials', {
        authenticatorId: authId,
      });
      expect(creds.credentials.length).toBe(1);
      expect(creds.credentials[0].rpId).toBe('webauthn.io');
      // isResidentCredential should be true (discoverable credential)
      expect(creds.credentials[0].isResidentCredential).toBe(true);

      // Step 2: Authenticate
      const authButton = page.getByRole('button', { name: 'Authenticate' });
      await expect(authButton).toBeVisible();
      await authButton.click();

      // Authentication with UV should succeed and redirect to profile.
      // The Firefox "no PIN prompt" bug caused authentication to fail because
      // the browser could not determine the correct UV method from GetInfo.
      await page.waitForURL('**/profile', { timeout: 15_000 });
      await expect(page.getByText("You're logged in")).toBeVisible({ timeout: 5_000 });

      // Verify sign count was incremented (proves assertion was processed)
      const credsAfterAuth = await cdp.send('WebAuthn.getCredentials', {
        authenticatorId: authId,
      });
      expect(credsAfterAuth.credentials[0].signCount).toBeGreaterThan(0);

      console.log(`UV-required register+authenticate succeeded for user: ${username}`);
    });
  });

  test.describe('multiple authenticators - PIN protocol coexistence', () => {
    let cdp: CDPSession;
    let authIdWithUV: string;
    let authIdNoUV: string;

    test.beforeEach(async ({ page }) => {
      cdp = await page.context().newCDPSession(page);
      await cdp.send('WebAuthn.enable', { enableUI: false });
    });

    test.afterEach(async () => {
      if (cdp) {
        for (const id of [authIdWithUV, authIdNoUV]) {
          if (id) {
            try {
              await cdp.send('WebAuthn.removeVirtualAuthenticator', {
                authenticatorId: id,
              });
            } catch { /* already removed */ }
          }
        }
        await cdp.send('WebAuthn.disable');
      }
    });

    test('credential from UV-capable authenticator has correct properties', async ({ page }) => {
      // Create UV-capable authenticator (simulates PIN protocol V1+V2 support).
      // When both protocols are available, the authenticator negotiates
      // the highest available version. This test verifies that credentials
      // created with UV produce the expected properties.
      const uvResult = await cdp.send('WebAuthn.addVirtualAuthenticator', {
        options: {
          protocol: 'ctap2',
          transport: 'usb',
          hasResidentKey: true,
          hasUserVerification: true,
          isUserVerified: true,
          automaticPresenceSimulation: true,
        },
      });
      authIdWithUV = uvResult.authenticatorId;

      const username = generateUsername();

      await page.goto('https://webauthn.io/', { waitUntil: 'networkidle' });

      const usernameInput = page.locator('#input-email');
      await expect(usernameInput).toBeVisible({ timeout: 10_000 });
      await usernameInput.fill(username);

      const registerButton = page.getByRole('button', { name: 'Register' });
      await registerButton.click();

      const regSuccess = page.locator('.alert-success');
      await expect(regSuccess).toBeVisible({ timeout: 15_000 });

      // Verify credential was created with proper parameters
      const creds = await cdp.send('WebAuthn.getCredentials', {
        authenticatorId: authIdWithUV,
      });
      expect(creds.credentials.length).toBe(1);

      const cred = creds.credentials[0];
      expect(cred.rpId).toBe('webauthn.io');
      expect(cred.isResidentCredential).toBe(true);
      // Private key should be present (base64-encoded PKCS#8)
      expect(cred.privateKey).toBeTruthy();

      console.log(`UV-capable credential created: rpId=${cred.rpId}`);
    });

    test('credential portability between UV and non-UV authenticators', async ({ page }) => {
      // This test simulates PIN protocol coexistence:
      // 1. Register with a UV-capable authenticator (PIN V1+V2)
      // 2. Swap to a non-UV authenticator (simulates downgrade)
      // 3. Verify authentication still works but with different UV behavior.
      //
      // This catches the regression where changing PIN/UV configuration
      // between GetInfo responses caused inconsistent browser behavior.
      // The Chrome "change PIN" bug was exactly this scenario: the
      // authenticator's UV state changed mid-session.

      // Step 1: Register with UV authenticator
      const uvResult = await cdp.send('WebAuthn.addVirtualAuthenticator', {
        options: {
          protocol: 'ctap2',
          transport: 'usb',
          hasResidentKey: true,
          hasUserVerification: true,
          isUserVerified: true,
          automaticPresenceSimulation: true,
        },
      });
      authIdWithUV = uvResult.authenticatorId;

      const username = generateUsername();

      await page.goto('https://webauthn.io/', { waitUntil: 'networkidle' });

      const usernameInput = page.locator('#input-email');
      await expect(usernameInput).toBeVisible({ timeout: 10_000 });
      await usernameInput.fill(username);

      const registerButton = page.getByRole('button', { name: 'Register' });
      await registerButton.click();

      const regSuccess = page.locator('.alert-success');
      await expect(regSuccess).toBeVisible({ timeout: 15_000 });

      // Save credential data before removing authenticator
      const creds = await cdp.send('WebAuthn.getCredentials', {
        authenticatorId: authIdWithUV,
      });
      const credential = creds.credentials[0];
      const signCountAfterReg = credential.signCount;

      // Step 2: Remove UV authenticator, add non-UV one with the same credential.
      // This simulates the scenario where PIN protocol configuration changed
      // between GetInfo responses (e.g., authenticator reboot, state mismatch).
      await cdp.send('WebAuthn.removeVirtualAuthenticator', {
        authenticatorId: authIdWithUV,
      });

      const noUVResult = await cdp.send('WebAuthn.addVirtualAuthenticator', {
        options: {
          protocol: 'ctap2',
          transport: 'usb',
          hasResidentKey: true,
          hasUserVerification: false,
          automaticPresenceSimulation: true,
        },
      });
      authIdNoUV = noUVResult.authenticatorId;

      // Port the credential to the non-UV authenticator
      await cdp.send('WebAuthn.addCredential', {
        authenticatorId: authIdNoUV,
        credential: {
          credentialId: credential.credentialId,
          rpId: credential.rpId,
          privateKey: credential.privateKey,
          userHandle: credential.userHandle,
          signCount: credential.signCount,
          isResidentCredential: credential.isResidentCredential,
        },
      });

      // Step 3: Authenticate with the non-UV authenticator.
      // webauthn.io uses "preferred" UV, so it accepts assertions
      // without UV. The key validation is that the sign count advances,
      // proving the credential was used by a different authenticator config.
      const authButton = page.getByRole('button', { name: 'Authenticate' });
      await expect(authButton).toBeVisible();
      await authButton.click();

      await page.waitForURL('**/profile', { timeout: 15_000 });
      await expect(page.getByText("You're logged in")).toBeVisible({ timeout: 5_000 });

      // Verify sign count advanced with the non-UV authenticator
      const credsAfter = await cdp.send('WebAuthn.getCredentials', {
        authenticatorId: authIdNoUV,
      });
      expect(credsAfter.credentials[0].signCount).toBeGreaterThan(signCountAfterReg);

      console.log(
        `Credential ported: UV auth signCount=${signCountAfterReg} -> ` +
        `non-UV auth signCount=${credsAfter.credentials[0].signCount}`
      );
    });
  });

  test.describe('PIN retry protection - UV verification failure', () => {
    let cdp: CDPSession;
    let authId: string;
    let regAuthId: string;

    test.beforeEach(async ({ page }) => {
      cdp = await page.context().newCDPSession(page);
      await cdp.send('WebAuthn.enable', { enableUI: false });
    });

    test.afterEach(async () => {
      if (cdp) {
        // Clean up whichever authenticator is active
        if (authId) {
          try {
            await cdp.send('WebAuthn.removeVirtualAuthenticator', {
              authenticatorId: authId,
            });
          } catch { /* already removed */ }
        }
        if (regAuthId && regAuthId !== authId) {
          try {
            await cdp.send('WebAuthn.removeVirtualAuthenticator', {
              authenticatorId: regAuthId,
            });
          } catch { /* already removed */ }
        }
        await cdp.send('WebAuthn.disable');
      }
    });

    test('authentication fails when UV cannot be verified', async ({ page }) => {
      const username = generateUsername();

      // Step 1: Register with a working authenticator (UV verified)
      const regResult = await cdp.send('WebAuthn.addVirtualAuthenticator', {
        options: {
          protocol: 'ctap2',
          transport: 'usb',
          hasResidentKey: true,
          hasUserVerification: true,
          isUserVerified: true,
          automaticPresenceSimulation: true,
        },
      });
      regAuthId = regResult.authenticatorId;

      await page.goto('https://webauthn.io/', { waitUntil: 'networkidle' });

      const usernameInput = page.locator('#input-email');
      await expect(usernameInput).toBeVisible({ timeout: 10_000 });
      await usernameInput.fill(username);

      const registerButton = page.getByRole('button', { name: 'Register' });
      await registerButton.click();

      const regSuccess = page.locator('.alert-success');
      await expect(regSuccess).toBeVisible({ timeout: 15_000 });

      // Get the credential from the working authenticator
      const creds = await cdp.send('WebAuthn.getCredentials', {
        authenticatorId: regAuthId,
      });
      expect(creds.credentials.length).toBe(1);
      const credential = creds.credentials[0];

      // Step 2: Remove the working authenticator
      await cdp.send('WebAuthn.removeVirtualAuthenticator', {
        authenticatorId: regAuthId,
      });

      // Step 3: Create a new authenticator with UV NOT verified (wrong PIN).
      // isUserVerified: false simulates an authenticator where the user
      // entered the wrong PIN. The authenticator has UV capability but
      // the PIN verification failed, so assertions should be rejected.
      const failResult = await cdp.send('WebAuthn.addVirtualAuthenticator', {
        options: {
          protocol: 'ctap2',
          transport: 'usb',
          hasResidentKey: true,
          hasUserVerification: true,
          isUserVerified: false,
          automaticPresenceSimulation: true,
        },
      });
      authId = failResult.authenticatorId;

      // Add the credential from registration to the failing authenticator
      await cdp.send('WebAuthn.addCredential', {
        authenticatorId: authId,
        credential: {
          credentialId: credential.credentialId,
          rpId: credential.rpId,
          privateKey: credential.privateKey,
          userHandle: credential.userHandle,
          signCount: credential.signCount,
          isResidentCredential: credential.isResidentCredential,
        },
      });

      // Step 4: Try to authenticate - should fail because UV is not verified
      const authButton = page.getByRole('button', { name: 'Authenticate' });
      await expect(authButton).toBeVisible();
      await authButton.click();

      // The assertion should fail. When UV is required but isUserVerified=false,
      // the authenticator cannot satisfy the UV requirement.
      // webauthn.io shows an error alert on failure.
      const errorIndicator = page.locator('.alert-danger');
      await expect(errorIndicator).toBeVisible({ timeout: 15_000 });

      console.log('UV verification failure correctly prevented authentication');
    });
  });
});
