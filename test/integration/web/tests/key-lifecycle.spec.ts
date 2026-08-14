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
 * A real key lifecycle (generate -> list -> sign -> delete) driven entirely
 * through the browser against the live server — the software backend does
 * real ECDSA P-256 key generation and signing, not a stub.
 *
 * NOTE: this assumes a freshly self-registered operator (see
 * support/operator.ts) holds keys:create / keys:sign / keys:delete. That is
 * the expected default for the first-boot-adjacent RBAC role, but has not
 * been verified against a running daemon from this sandbox (which cannot
 * bind listening ports) — if the operator's default role turns out to be
 * read-only, the "Generate" / "Sign" / "Delete" controls this spec clicks
 * simply will not be in the DOM (they are can()-gated in KeysView.svelte /
 * KeyDetail.svelte) and this spec fails fast at the first missing control
 * rather than hanging.
 */

import { test, expect } from '@playwright/test';
import { installVirtualAuthenticator } from './support/virtualAuthenticator.ts';
import { registerOperator, uniqueOperator } from './support/operator.ts';

test('generates, signs, and deletes a key through the console', async ({ page }) => {
  await installVirtualAuthenticator(page);
  await registerOperator(page, uniqueOperator('keys'));

  const keyId = `e2e-key-${Date.now()}`;

  await page.getByRole('navigation', { name: 'Primary' }).getByRole('button', { name: 'Keys' }).click();
  await expect(page.getByRole('heading', { level: 1, name: 'Keys' })).toBeVisible();

  // Generate — default ECDSA P-256, matches the mock tier's request-shape
  // assertion in web/app/e2e/mutations.spec.ts for the same form.
  await page.getByRole('button', { name: '+ Generate' }).click();
  await page.getByLabel('Key ID').fill(keyId);
  await page.getByRole('button', { name: 'Generate', exact: true }).click();
  await expect(page.getByText(`Key "${keyId}" generated.`)).toBeVisible({ timeout: 15_000 });

  // List — the new key is a real row now, not a mock.
  await expect(page.getByRole('cell', { name: keyId, exact: true })).toBeVisible();

  // Sign — opens the key detail drawer and runs a real signature over the
  // software backend.
  await page.getByRole('cell', { name: keyId, exact: true }).click();
  await page.getByRole('tab', { name: 'Sign' }).click();
  await page.getByLabel('Message').fill('e2e sign payload');
  await page.getByRole('button', { name: 'Sign', exact: true }).click();
  await expect(page.getByText('Signature (base64)')).toBeVisible({ timeout: 15_000 });
  const signaturePre = page.locator('pre').last();
  await expect(signaturePre).not.toBeEmpty();

  // Delete — back to Overview, delete, confirm the toast and the row is gone.
  await page.getByRole('tab', { name: 'Overview' }).click();
  await page.getByRole('button', { name: 'Delete' }).click();
  await expect(page.getByText(`Key "${keyId}" deleted.`)).toBeVisible({ timeout: 15_000 });
  await expect(page.getByRole('cell', { name: keyId, exact: true })).toHaveCount(0);
});
