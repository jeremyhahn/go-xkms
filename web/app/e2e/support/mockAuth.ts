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
 * Auth seeding for the mock-API E2E tier.
 *
 * The SPA's auth store (@go-xkms/svelte-auth) only flips to 'authenticated'
 * two ways: a real login/register ceremony completing (setAuthenticated), or
 * the Wails desktop bootstrap (src/lib/desktop.ts) detecting a `window.go`
 * bridge and installing a loopback token. A page reload with a token merely
 * sitting in localStorage does NOT flip the store — nothing calls
 * validateSession() on boot — so seeding localStorage alone cannot reach the
 * authenticated shell.
 *
 * bootstrapDesktop() is the intended "skip the login ceremony" seam (it
 * exists for exactly this purpose in the real desktop shell), so this tier
 * reuses it: injecting a fake `window.go.main.bridge` before the page's own
 * scripts run makes main.ts's `bootstrapDesktop()` call the REAL
 * `setAuthenticated()`, through production code, with no source changes.
 */

import type { Page } from '@playwright/test';

/** The full shape returned by GET /api/v1/auth/me. */
export interface MockAuthMe {
  subject: string;
  tenant_id?: string;
  username?: string;
  display_name?: string;
  auth_method?: string;
  roles?: string[];
  permissions: Record<string, boolean>;
  capabilities: Record<string, boolean>;
}

/** A permission map that grants every resource:action the nav model checks. */
export const ALL_PERMISSIONS: Record<string, boolean> = {
  'backends:list': true,
  'keys:list': true,
  'keys:create': true,
  'keys:import': true,
  'certs:list': true,
  'seal:status': true,
  'seal:unseal': true,
  'seal:seal': true,
  'pin:read': true,
  'piv:read': true,
  'ssh:read': true,
  'passwords:read': true,
  'users:list': true,
  'users:read': true,
  'users:create': true,
  'users:update': true,
  'users:enable': true,
  'users:disable': true,
  'users:delete': true,
  'audit:read': true,
  'tenants:list': true,
  'oidc_credentials:list': true,
};

/** Every capability flag nav.ts gates on, all wired. */
export const ALL_CAPABILITIES: Record<string, boolean> = {
  frost: true,
  tpm_policies: true,
  ca: true,
  ssh: true,
  passwords: true,
  oidc_credentials: true,
  platform: true,
  ceremony: true,
  factors: true,
  audit: true,
  tenants: true,
  custodians: true,
  shares: true,
  cluster: true,
};

/** A signed-in operator identity with every permission/capability granted. */
export function defaultAuthMe(overrides: Partial<MockAuthMe> = {}): MockAuthMe {
  return {
    subject: 'op-1',
    username: 'operator',
    display_name: 'Test Operator',
    roles: ['admin'],
    permissions: { ...ALL_PERMISSIONS },
    capabilities: { ...ALL_CAPABILITIES },
    ...overrides,
  };
}

/**
 * seedAuthenticated installs the fake Wails bridge (flips the real auth store
 * to 'authenticated' via bootstrapDesktop on load) and mocks GET
 * /api/v1/auth/me with the given identity. Call BEFORE page.goto().
 */
export async function seedAuthenticated(
  page: Page,
  me: MockAuthMe = defaultAuthMe(),
): Promise<void> {
  await page.addInitScript(() => {
    (window as unknown as { go: unknown }).go = {
      main: {
        bridge: {
          GetConnection: () =>
            JSON.stringify({ mode: 'standalone', base_url: '', token: 'mock-loopback-token' }),
        },
      },
    };
  });
  await page.route('**/api/v1/auth/me', async (route) => {
    await route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(me) });
  });
}

/**
 * mockLoginCapabilities stubs GET /api/v1/capabilities — the deployment
 * capability probe LoginPanel intersects with its own provider methods to
 * decide which sign-in buttons to offer (webauthn_enabled -> passkey,
 * piv_login_enabled -> certificate). Only relevant on the signed-out screens.
 */
export async function mockLoginCapabilities(
  page: Page,
  flags: Record<string, boolean> = { webauthn_enabled: true, piv_login_enabled: true },
): Promise<void> {
  await page.route('**/api/v1/capabilities', async (route) => {
    await route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(flags) });
  });
}
