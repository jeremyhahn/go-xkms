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
 * Authenticated shell: the nav renders once auth flips to 'authenticated'
 * (via the seeded desktop-bridge bootstrap, see support/mockAuth.ts), and
 * Sidebar.svelte hides an item when EITHER its RBAC gate (`can(resource,
 * action)`, sourced from auth/me `permissions`) or its capability gate
 * (`hasCapability`, sourced from auth/me `capabilities`) fails — see
 * src/lib/nav.ts and src/components/Sidebar.svelte. This is security-visible
 * behaviour: a nav item missing here means the server disabled or denied it.
 */

import { test, expect } from '@playwright/test';
import { installDefaultApiMocks } from './support/mockApi.ts';
import { ALL_CAPABILITIES, ALL_PERMISSIONS, defaultAuthMe, seedAuthenticated } from './support/mockAuth.ts';

test.describe('Authenticated shell', () => {
  test('renders the nav and the dashboard once authenticated', async ({ page }) => {
    await installDefaultApiMocks(page);
    await seedAuthenticated(page);

    await page.goto('/#/dashboard');

    await expect(page.locator('aside')).toBeVisible();
    await expect(page.getByRole('heading', { name: 'Dashboard' })).toBeVisible();
    await expect(page.getByText('Test Operator')).toBeVisible();
  });

  test('shows every RBAC- and capability-gated item when everything is granted', async ({ page }) => {
    await installDefaultApiMocks(page);
    await seedAuthenticated(page, defaultAuthMe());

    await page.goto('/#/dashboard');

    const nav = page.getByRole('navigation', { name: 'Primary' });
    for (const label of ['Keys', 'FROST', 'Certificates', 'Certificate Authority', 'Users', 'Tenants', 'Cluster']) {
      await expect(nav.getByRole('button', { name: label })).toBeVisible();
    }
  });

  test('hides an RBAC-gated item when its permission is denied', async ({ page }) => {
    await installDefaultApiMocks(page);
    // Every permission granted EXCEPT users:list, which gates the "Users" item.
    const permissions = { ...ALL_PERMISSIONS, 'users:list': false };
    await seedAuthenticated(page, defaultAuthMe({ permissions }));

    await page.goto('/#/dashboard');

    const nav = page.getByRole('navigation', { name: 'Primary' });
    await expect(nav.getByRole('button', { name: 'Users' })).toHaveCount(0);
    // A sibling item in the same section with a different gate stays visible —
    // proves the whole "Identity & Access" section isn't blanket-hidden.
    await expect(nav.getByRole('button', { name: 'Tenants' })).toBeVisible();
  });

  test('hides a capability-gated item when the server has not wired that subsystem', async ({ page }) => {
    await installDefaultApiMocks(page);
    // Every capability wired EXCEPT cluster.
    const capabilities = { ...ALL_CAPABILITIES, cluster: false };
    await seedAuthenticated(page, defaultAuthMe({ capabilities }));

    await page.goto('/#/dashboard');

    const nav = page.getByRole('navigation', { name: 'Primary' });
    await expect(nav.getByRole('button', { name: 'Cluster' })).toHaveCount(0);
    // The whole "Cluster" section heading disappears with its only item.
    await expect(page.locator('#nav-group-cluster')).toHaveCount(0);
  });

  test('hides an item gated on BOTH capability and permission when only the permission is granted', async ({ page }) => {
    await installDefaultApiMocks(page);
    // "SSH" requires capability:"ssh" AND permission "ssh:read". Deny only the
    // capability — the item must still disappear (both gates are AND'd).
    const capabilities = { ...ALL_CAPABILITIES, ssh: false };
    await seedAuthenticated(page, defaultAuthMe({ capabilities }));

    await page.goto('/#/dashboard');

    const nav = page.getByRole('navigation', { name: 'Primary' });
    await expect(nav.getByRole('button', { name: 'SSH' })).toHaveCount(0);
  });

  test('reduces to only ungated items for an identity with no grants', async ({ page }) => {
    await installDefaultApiMocks(page);
    await seedAuthenticated(page, defaultAuthMe({ permissions: {}, capabilities: {} }));

    await page.goto('/#/dashboard');

    const nav = page.getByRole('navigation', { name: 'Primary' });
    // Dashboard and Settings have no gate at all, so they always survive.
    await expect(nav.getByRole('button', { name: 'Dashboard' })).toBeVisible();
    await expect(nav.getByRole('button', { name: 'Settings' })).toBeVisible();
    // Everything gated is gone.
    await expect(nav.getByRole('button', { name: 'Keys' })).toHaveCount(0);
    await expect(nav.getByRole('button', { name: 'Users' })).toHaveCount(0);
    await expect(nav.getByRole('button', { name: 'Cluster' })).toHaveCount(0);
  });

  test('signs out back to the login screen and clears the shell', async ({ page }) => {
    await installDefaultApiMocks(page);
    await seedAuthenticated(page);

    await page.goto('/#/dashboard');
    await expect(page.locator('aside')).toBeVisible();

    await page.getByRole('button', { name: /Sign out/ }).click();

    await expect(page.getByRole('button', { name: 'Sign in with passkey' })).toBeVisible();
    await expect(page.locator('aside')).toHaveCount(0);
  });
});
