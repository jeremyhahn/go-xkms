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
 * Default REST response table for the mock-API E2E tier.
 *
 * Every view's onMount load() call needs SOME 200 response or it renders its
 * own error alert instead of data — the PageHeader above it still renders
 * either way (see navigation.spec.ts), but the mutation/detail specs need
 * real-shaped bodies to exercise past the loading state. This table gives
 * every list/status endpoint the main nav reaches an empty-but-correctly-
 * shaped body, keyed by exact pathname + method, mirroring the field names in
 * sdk/ts/src/types/*.ts (NOT guesses — each key was checked against the
 * corresponding SDK type before being added here).
 *
 * installDefaultApiMocks registers ONE route per api prefix and answers from
 * this table; installApiMock lets a spec override a single path for a
 * negative-path or mutation-echo assertion. Routes registered later win over
 * earlier ones for the same URL, so overrides must be installed AFTER
 * installDefaultApiMocks.
 */

import type { Page, Route } from '@playwright/test';

type Method = 'GET' | 'POST' | 'PUT' | 'DELETE' | 'PATCH';
type RouteKey = `${Method} ${string}`;

/** Keyed by "METHOD pathname" (query string ignored). */
export const DEFAULT_RESPONSES: Record<RouteKey, unknown> = {
  'GET /health': { status: 'ok', version: 'mock' },
  'GET /api/v1/algorithms': { algorithms: [] },

  'GET /api/v1/backends': { backends: [], pagination: { total: 0 } },
  'GET /api/v1/barrier/status': { sealed: false, strategy: 'passphrase', hardware_backed: false },
  'GET /api/v1/cluster/status': { status: { clustered: false, has_leader: false } },
  'GET /api/v1/cluster/members': { members: [] },

  'GET /api/v1/keys': { keys: [], pagination: { total: 0 } },
  'GET /api/v1/certs': { certificates: [], pagination: { total: 0 } },
  'GET /api/v1/ca/bundle': { certificates: [] },
  'GET /api/v1/frost/keys': { keys: [], pagination: { total: 0 } },

  'GET /api/v1/audit/': { events: [], next: '', total: 0 },
  'GET /api/v1/users/': { users: [], page: 1, page_size: 20, total: 0 },
  'GET /api/v1/tenants/': { tenants: [], pagination: { total: 0 } },
  'GET /api/v1/policies/': { policies: [], total: 0 },
  'GET /api/v1/factors/': { factors: [], total: 0 },
  'GET /api/v1/shares/': { shares: [], pagination: { total: 0 } },
  'GET /api/v1/custodian/groups/': { groups: [], pagination: { total: 0 } },

  'GET /api/v1/passwords/': { passwords: [], total: 0 },
  'GET /api/v1/passwords/status': {
    available: true,
    is_locked: false,
    barrier_sealed: false,
    password_count: 0,
    message: '',
  },
  'GET /api/v1/platform/status': { available: true },
  'GET /api/v1/platform/secrets': { secrets: [] },
  'GET /api/v1/piv/slots': { slots: [] },
  'GET /api/v1/pin/lockout': {
    failed_attempts: 0,
    max_attempts: 5,
    is_locked: false,
    recovery_seconds: 0,
  },
  'GET /xkms/v1/ssh/keys': { items: [] },
  'GET /xkms/v1/ssh/known-hosts': { items: [] },
  'GET /xkms/v1/ssh/authorized-keys': { items: [] },
  'GET /api/v1/init/status': { state: 'initialized' },
  'GET /api/v1/seal/capability': { available: false },
  'GET /api/v1/credentials/strategy': { strategies: [] },
};

// Path prefixes the mock router owns. Anything outside these (Vite's own
// dev-server assets, HMR websocket, etc.) is left to route.continue() so the
// SPA bundle itself still loads.
const API_GLOBS = ['**/api/v1/**', '**/xkms/v1/**', '**/health', '**/health/**'];

function routeKey(method: string, pathname: string): string {
  return `${method} ${pathname}`;
}

async function respond(route: Route, body: unknown, status = 200): Promise<void> {
  await route.fulfill({ status, contentType: 'application/json', body: JSON.stringify(body) });
}

/**
 * installDefaultApiMocks wires the whole DEFAULT_RESPONSES table. Call this
 * first, before any per-test override route and before seedAuthenticated /
 * page.goto, so every view's mount-time load() gets a 200 instead of hanging
 * on an unmocked request (Playwright would otherwise let it fall through to
 * a real network call that has nowhere to go).
 */
export async function installDefaultApiMocks(page: Page): Promise<void> {
  for (const glob of API_GLOBS) {
    await page.route(glob, async (route) => {
      const req = route.request();
      const url = new URL(req.url());
      const key = routeKey(req.method(), url.pathname);
      const body = DEFAULT_RESPONSES[key as RouteKey];
      if (body !== undefined) {
        await respond(route, body);
        return;
      }
      // Unmapped GET under an owned prefix: an empty object is harmless for
      // every view here because PageHeader renders unconditionally above the
      // load()'s try/catch — see navigation.spec.ts. Unmapped mutations
      // (POST/PUT/DELETE) are a real gap a spec must mock explicitly, so
      // those fail loudly (404) instead of silently no-op succeeding.
      if (req.method() === 'GET') {
        await respond(route, {});
        return;
      }
      await route.fulfill({ status: 404, contentType: 'application/json', body: '{"error":"unmocked in e2e"}' });
    });
  }
}

/**
 * mockOnce overrides a single "METHOD pathname" for the rest of the test.
 * Must be called AFTER installDefaultApiMocks (Playwright matches the most
 * recently registered route first).
 */
export async function mockOnce(
  page: Page,
  method: Method,
  pathname: string,
  body: unknown,
  status = 200,
): Promise<void> {
  await page.route(`**${pathname}`, async (route) => {
    if (route.request().method() !== method) {
      await route.fallback();
      return;
    }
    await respond(route, body, status);
  });
}

/** mockError makes a single "METHOD pathname" answer with an error status. */
export async function mockError(
  page: Page,
  method: Method,
  pathname: string,
  status: number,
  message = 'mock error',
): Promise<void> {
  await page.route(`**${pathname}`, async (route) => {
    if (route.request().method() !== method) {
      await route.fallback();
      return;
    }
    await route.fulfill({
      status,
      contentType: 'application/json',
      body: JSON.stringify({ error: message, message }),
    });
  });
}
