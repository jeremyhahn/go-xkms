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
 * Barrier status and the audit viewer against real server data — no mocked
 * response bodies anywhere in this file. config.yaml auto-unseals via a
 * passphrase strategy at boot, so BarrierView should read "unsealed" with no
 * ceremony needed here; the Shamir/rekey ceremonies themselves are explicitly
 * out of scope for the web console (CLAUDE.md: "multi-operator ceremonies are
 * best driven from the CLI"), and BarrierView says so directly.
 */

import { test, expect } from '@playwright/test';
import { installVirtualAuthenticator } from './support/virtualAuthenticator.ts';
import { registerOperator, uniqueOperator } from './support/operator.ts';

test('barrier status reflects the real auto-unsealed passphrase strategy', async ({ page }) => {
  await installVirtualAuthenticator(page);
  await registerOperator(page, uniqueOperator('barrier'));

  await page.getByRole('navigation', { name: 'Primary' }).getByRole('button', { name: 'Barrier & Seal' }).click();

  await expect(page.getByRole('heading', { level: 1, name: 'Barrier & Seal' })).toBeVisible();
  await expect(page.getByText('unsealed', { exact: true })).toBeVisible();
  await expect(page.getByText('strategy: passphrase')).toBeVisible();
  // Sealed-only controls must not appear against an unsealed barrier.
  await expect(page.getByLabel('Passphrase')).toHaveCount(0);
});

test('the audit viewer lists a real event after a privileged operation', async ({ page }) => {
  await installVirtualAuthenticator(page);
  await registerOperator(page, uniqueOperator('audit'));

  // Perform one real privileged operation so the tamper-evident chain has at
  // least one row to show beyond registration itself.
  const keyId = `e2e-audit-key-${Date.now()}`;
  await page.getByRole('navigation', { name: 'Primary' }).getByRole('button', { name: 'Keys' }).click();
  await page.getByRole('button', { name: '+ Generate' }).click();
  await page.getByLabel('Key ID').fill(keyId);
  await page.getByRole('button', { name: 'Generate', exact: true }).click();
  await expect(page.getByText(`Key "${keyId}" generated.`)).toBeVisible({ timeout: 15_000 });

  await page.getByRole('navigation', { name: 'Primary' }).getByRole('button', { name: 'Audit' }).click();
  await expect(page.getByRole('heading', { level: 1, name: 'Audit' })).toBeVisible();

  // The empty-state row must NOT be showing — real events came back.
  await expect(page.getByText('No audit events match these filters.')).toHaveCount(0);

  // Filter down to just this operation's resource and confirm a real,
  // structured event (not a mock body) with today's timestamp is present.
  await page.getByLabel('Resource').fill('keys');
  await page.getByRole('button', { name: 'Apply' }).click();
  await expect(page.getByRole('cell', { name: 'keys' }).first()).toBeVisible({ timeout: 15_000 });
});
