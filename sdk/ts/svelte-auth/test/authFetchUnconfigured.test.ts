// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
//
// This file is part of go-xkms.
//
// go-xkms is dual-licensed:
//
//  1. GNU Affero General Public License v3.0 (AGPL-3.0)
//     See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
//  2. Commercial License
//     Contact licensing@automatethethings.com for commercial licensing options.

/**
 * authFetch behaviour BEFORE the auth store has been configured.
 *
 * Deliberately its own test file (see authStoreUnconfigured.test.ts for why):
 * isRenewable()'s very first check is `!isAuthStoreConfigured()`, and every
 * other authFetch suite configures the store in a beforeEach. A fresh,
 * never-configured module instance is the only way to exercise the
 * "package not wired up yet" passthrough.
 */

import { describe, it, expect, afterEach, vi } from 'vitest';

import { installAuthFetch, uninstallAuthFetch } from '../src/authFetch.ts';

function jsonResponse(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}

describe('authFetch before the auth store is configured', () => {
  afterEach(() => {
    uninstallAuthFetch();
    vi.unstubAllGlobals();
  });

  it('passes a 401 straight through — there is no store to renew against', async () => {
    const base = vi.fn(async () => jsonResponse(401, { error: 'unauthenticated' }));
    vi.stubGlobal('fetch', base);
    installAuthFetch();

    const resp = await window.fetch('/api/v1/keys', {
      headers: { Authorization: 'Bearer stale' },
    });

    expect(resp.status).toBe(401);
    expect(base).toHaveBeenCalledTimes(1);
  });
});
