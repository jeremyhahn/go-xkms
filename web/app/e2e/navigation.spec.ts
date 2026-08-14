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
 * Route dispatch across every authenticated screen. Mirrors the marker table
 * in web/app/test/app_routing.test.ts (the vitest equivalent), but exercised
 * through a real hash navigation + a real mounted browser page instead of
 * @testing-library/svelte, and against the DEFAULT_RESPONSES mock table
 * instead of rejecting every SDK call.
 *
 * Every view puts its <PageHeader title=...> OUTSIDE the loading/error
 * conditional (see e.g. KeysView.svelte, DashboardView.svelte), so this
 * asserts the header text renders per route — the thing this repo's ship
 * history shows breaks most often: a route wired to the wrong view (every
 * screen still renders, just the wrong one), or the signed-out guard leaking
 * through.
 */

import { test, expect } from '@playwright/test';
import { installDefaultApiMocks } from './support/mockApi.ts';
import { defaultAuthMe, seedAuthenticated } from './support/mockAuth.ts';

// The exact <PageHeader title=...> string each view passes (grepped from
// web/app/src/views/*.svelte), one route per main screen.
const ROUTES: Array<[string, string]> = [
  ['/dashboard', 'Dashboard'],
  ['/backends', 'Backends'],
  ['/keys', 'Keys'],
  ['/certs', 'Certificates'],
  ['/ca', 'Certificate Authority'],
  ['/barrier', 'Barrier & Seal'],
  ['/pin', 'PIN'],
  ['/piv', 'PIV'],
  ['/ssh', 'SSH'],
  ['/policies', 'PCR Policies'],
  ['/users', 'Users'],
  ['/factors', 'Auth Factors'],
  ['/frost', 'FROST'],
  ['/audit', 'Audit'],
  ['/tenants', 'Tenants'],
  ['/custodians', 'Custodians'],
  ['/shares', 'Shares'],
  ['/passwords', 'Passwords'],
  ['/platform', 'Platform Secrets'],
  ['/ceremony', 'Init & Ceremony'],
  ['/cluster', 'Cluster'],
  ['/settings', 'Settings'],
];

test.describe('Route navigation', () => {
  for (const [path, marker] of ROUTES) {
    test(`renders its own header at ${path}`, async ({ page }) => {
      await installDefaultApiMocks(page);
      await seedAuthenticated(page, defaultAuthMe());

      await page.goto(`/#${path}`);

      // Scoped to level 1: PageHeader's <h1> is the only heading unique to
      // the screen — several views also render <h2> card titles that share a
      // word with the page title (e.g. PinView's "Change SO PIN").
      await expect(page.getByRole('heading', { level: 1, name: marker })).toBeVisible();
      // The shell (sidebar) is present — this is not the signed-out screen.
      await expect(page.locator('aside')).toBeVisible();
    });
  }

  test('renders the not-found placeholder for an unknown route', async ({ page }) => {
    await installDefaultApiMocks(page);
    await seedAuthenticated(page, defaultAuthMe());

    await page.goto('/#/this-route-does-not-exist');

    await expect(page.getByText('Not found')).toBeVisible();
  });

  test('clicking a nav item navigates and updates the active hash', async ({ page }) => {
    await installDefaultApiMocks(page);
    await seedAuthenticated(page, defaultAuthMe());

    await page.goto('/#/dashboard');
    await page.getByRole('navigation', { name: 'Primary' }).getByRole('button', { name: 'Keys' }).click();

    await expect(page).toHaveURL(/#\/keys$/);
    await expect(page.getByRole('heading', { name: 'Keys' })).toBeVisible();
  });
});
