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
 * registerOperator drives the REAL RegisterView UI (RegisterPanel from
 * @go-xkms/svelte-auth) through a real passkey attestation ceremony against
 * the virtual authenticator installed on `page`, and waits for the resulting
 * authenticated dashboard.
 *
 * Each spec calls this with its OWN unique email rather than sharing one
 * operator across specs/tests: webauthn.allow_public_registration stays open
 * regardless of the adaptive authenticator's bootstrap-vs-required state, so
 * self-registration keeps working after the first operator exists, and a
 * fresh identity per test avoids any dependency on a virtual authenticator's
 * credential store surviving across Playwright test-scoped browser contexts
 * (it does not).
 */

import { expect, type Page } from '@playwright/test';

export interface Operator {
  email: string;
  displayName: string;
}

let counter = 0;

/** uniqueOperator returns a fresh, collision-free identity for one test. */
export function uniqueOperator(label: string): Operator {
  counter += 1;
  return {
    email: `e2e-${label}-${Date.now()}-${counter}@example.com`,
    displayName: `E2E ${label}`,
  };
}

/**
 * registerOperator navigates to /ui/#/register, completes the ceremony, and
 * asserts the SPA lands on the authenticated dashboard. The virtual
 * authenticator must already be installed on `page` (see
 * support/virtualAuthenticator.ts) before calling this.
 */
export async function registerOperator(page: Page, op: Operator): Promise<void> {
  await page.goto('/ui/#/register');
  await page.getByLabel('Email').fill(op.email);
  await page.getByLabel('Display name').fill(op.displayName);
  await page.getByRole('button', { name: 'Create account with passkey' }).click();

  await expect(page.getByRole('heading', { level: 1, name: 'Dashboard' })).toBeVisible({ timeout: 20_000 });
  await expect(page.locator('aside')).toBeVisible();
}

/**
 * loginOperator navigates to /ui/#/login and completes the passkey assertion
 * ceremony for an already-registered identity (same page/context as the
 * registration, so the virtual authenticator still holds the credential).
 */
export async function loginOperator(page: Page, op: Operator): Promise<void> {
  await page.goto('/ui/#/login');
  await page.getByRole('button', { name: 'Sign in with passkey' }).click();
  await page.getByLabel('Email').fill(op.email);
  await page.getByRole('button', { name: 'Authenticate with passkey' }).click();

  await expect(page.getByRole('heading', { level: 1, name: 'Dashboard' })).toBeVisible({ timeout: 20_000 });
  await expect(page.locator('aside')).toBeVisible();
}
